"""Bounded, read-only discovery of installed games from local launcher records."""
from __future__ import annotations

import hashlib
from itertools import islice
import json
import os
from pathlib import Path
import re

MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_LAUNCHER_RECORDS = 5000
DISCOVERY_LIMITS = [
    "Discovery covers registered Steam libraries, Epic manifests and explicit GOG game keys; it is not a whole-disk search.",
    "Microsoft Store/Xbox, portable games and unregistered installations may require manual folder selection.",
    "Engine identification uses bounded file evidence, not runtime execution or a claim that every format can be decompiled.",
]


def _read(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(data) > MAX_MANIFEST_BYTES:
        raise ValueError("Launcher record exceeds safety limit")
    return data.decode("utf-8-sig")


def parse_vdf(text):
    """Parse ordinary quoted/unquoted Valve records; never evaluate directives."""
    pattern = re.compile(r'\s+|//[^\r\n]*|"(?:\\.|[^"\\])*"|[{}]|[^\s{}"]+')
    tokens = []
    position = 0
    for match in pattern.finditer(text):
        if match.start() != position:
            raise ValueError("Malformed Valve record")
        position = match.end()
        token = match.group()
        if token.isspace() or token.startswith("//"):
            continue
        if token.startswith('"'):
            token = re.sub(r'\\(["\\])', r'\1', token[1:-1])
        tokens.append(token)
        if len(tokens) > 100000:
            raise ValueError("Too many Valve record tokens")
    if position != len(text):
        raise ValueError("Malformed Valve record")
    index = 0
    def object_at(depth=0, nested=False):
        nonlocal index
        if depth > 32:
            raise ValueError("Valve record nesting exceeds limit")
        result = {}
        while index < len(tokens):
            key = tokens[index]
            index += 1
            if key == "}":
                if not nested:
                    raise ValueError("Unexpected closing brace")
                return result
            if key == "{" or index == len(tokens):
                raise ValueError("Missing Valve record value")
            value = tokens[index]
            index += 1
            if value == "{":
                value = object_at(depth + 1, True)
            elif value == "}":
                raise ValueError("Missing Valve record value")
            result[key] = value
        if nested:
            raise ValueError("Unclosed Valve record object")
        return result
    return object_at()


def _children(path, limit=512):
    try:
        return sorted(islice(path.iterdir(), limit), key=lambda node: node.name.casefold())
    except OSError:
        return []


def inspect_game(path, title=None, launcher="manual"):
    path = Path(path).expanduser().resolve()
    present = path.is_dir()
    engine, evidence = "unknown", []
    entries = _children(path) if present else []
    runtime_roots = [path, *[entry for entry in entries[:128] if entry.is_dir()]]
    runtime_entries = {runtime: entries if runtime == path else _children(runtime) for runtime in runtime_roots}
    data_dirs = [(runtime, entry) for runtime, children in runtime_entries.items() for entry in children
                 if entry.name.lower().endswith("_data") and entry.is_dir()]
    for runtime, data in data_dirs:
        metadata = data / "il2cpp_data/Metadata/global-metadata.dat"
        native = runtime / "GameAssembly.dll"
        managed = _children(data / "Managed", 32)
        if native.is_file() and metadata.is_file():
            engine, evidence = "unity-il2cpp", [native, metadata]
            break
        dlls = [item for item in managed if item.is_file() and item.suffix.lower() == ".dll"]
        if dlls:
            engine, evidence = "unity-mono", dlls[:4]
    if engine == "unknown":
        unreal_source = path / "Development/Src/Core/Classes/Object.uc"
        if unreal_source.is_file() and (path / "Binaries").is_dir():
            engine, evidence = "unreal", [unreal_source, path / "Binaries"]
    if engine == "unknown":
        for project in runtime_roots:
            packages = [entry for entry in _children(project / "Content/Paks", 64)
                        if entry.is_file() and entry.suffix.lower() in {".pak", ".utoc", ".ucas"}]
            binaries = project / "Binaries"
            legacy = [entry for folder in ["CookedPC", "CookedPCConsole", "CookedPCServer"]
                      for entry in _children(project / folder, 32)
                      if entry.is_file() and entry.suffix.lower() in {".upk", ".udk", ".u"}]
            if packages and binaries.is_dir():
                engine, evidence = "unreal", [*packages[:4], binaries]
                break
            if legacy:
                engine, evidence = "unreal", legacy[:4]
                break
    if engine == "unknown":
        for item in [entry for children in runtime_entries.values() for entry in children]:
            if item.is_file() and item.suffix.lower() == ".pck":
                try:
                    with item.open("rb") as stream:
                        if stream.read(4) == b"GDPC":
                            engine, evidence = "godot", [item]
                            break
                except OSError:
                    pass
    if engine == "unknown":
        executables = [entry for children in runtime_entries.values() for entry in children
                       if entry.is_file() and entry.suffix.lower() == ".exe"]
        if executables:
            engine, evidence = "native", executables[:4]
    return {"id": hashlib.sha256(str(path).casefold().encode()).hexdigest()[:16],
            "title": title or path.name, "path": str(path), "launcher": launcher,
            "installed": present, "installation_status": "present" if present else "missing",
            "engine": engine, "engine_evidence": [str(item.relative_to(path)) for item in evidence],
            "engine_status": "file_evidence" if engine not in {"unknown", "native"} else "unresolved",
            "limits": list(DISCOVERY_LIMITS)}


def _registry_values(hive, key, fields, access=0):
    try:
        import winreg
        with winreg.OpenKey(hive, key, 0, winreg.KEY_READ | access) as handle:
            result = {}
            for field in fields:
                try:
                    value, kind = winreg.QueryValueEx(handle, field)
                    if isinstance(value, str):
                        result[field] = value
                except OSError:
                    pass
            return result
    except (ImportError, OSError):
        return {}


def _steam_roots():
    roots = [Path("F:/SteamLibrary"), Path("G:/SteamLibrary"),
             Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Steam",
             Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Steam"]
    try:
        import winreg
        for hive, key, access in [(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", 0),
                                  (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam", winreg.KEY_WOW64_32KEY),
                                  (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam", winreg.KEY_WOW64_64KEY)]:
            values = _registry_values(hive, key, ["SteamPath", "InstallPath"], access)
            roots.extend(Path(value) for value in values.values())
    except ImportError:
        pass
    libraries = list(roots)
    for root in roots:
        for config in [root / "steamapps/libraryfolders.vdf", root / "config/libraryfolders.vdf"]:
            try:
                values = parse_vdf(_read(config)).get("libraryfolders", {})
                for key, value in values.items():
                    if key.isdigit():
                        location = value.get("path") if isinstance(value, dict) else value
                        if location:
                            libraries.append(Path(location))
            except (OSError, ValueError, UnicodeError, AttributeError):
                pass
    return list({str(path.resolve()).casefold(): path.resolve() for path in libraries}.values())


def steam_games(libraries):
    games = []
    for library in libraries:
        records = islice((Path(library) / "steamapps").glob("appmanifest_*.acf"), MAX_LAUNCHER_RECORDS)
        for record in records:
            try:
                state = parse_vdf(_read(record))["AppState"]
                if str(state.get("appid")) == "228980":
                    continue  # Steamworks shared redistributables are infrastructure, not a game.
                install = state["installdir"]
                if not install or install in {".", ".."} or any(char in install for char in '/\\:'):
                    continue
                game = inspect_game(Path(library) / "steamapps/common" / install, state.get("name", install), "Steam")
                flags = int(state.get("StateFlags", 0))
                updating = bool(flags & (256 | 512 | 1024 | 131072 | 262144 | 524288 | 1048576 | 2097152 | 4194304))
                ready = bool(flags & 4) and not bool(flags & (1 | 32 | 128 | 2048)) and not updating
                game.update({"launcher_id": state.get("appid", record.stem.removeprefix("appmanifest_")),
                             "build_id": state.get("buildid"), "state_flags": flags,
                             "installed": game["installed"] and ready,
                             "installation_status": "updating" if updating else "installed" if ready and game["installed"] else "incomplete" if game["installed"] else "missing"})
                games.append(game)
            except (OSError, ValueError, UnicodeError, KeyError, TypeError, AttributeError):
                continue
    return games


def epic_games(manifests):
    games = []
    for record in islice(Path(manifests).glob("*.item"), MAX_LAUNCHER_RECORDS):
        try:
            state = json.loads(_read(record))
            if not state.get("InstallLocation") or state.get("bIsDLC") or state.get("bIsApplication") is False:
                continue
            game = inspect_game(state["InstallLocation"], state.get("DisplayName") or state.get("AppName"), "Epic")
            incomplete = bool(state.get("bIsIncompleteInstall", False))
            game.update({"launcher_id": state.get("AppName"), "build_id": state.get("AppVersionString"),
                         "installed": game["installed"] and not incomplete,
                         "installation_status": "incomplete" if incomplete else "installed" if game["installed"] else "missing"})
            games.append(game)
        except (OSError, ValueError, UnicodeError, TypeError, AttributeError):
            continue
    return games


def _gog_games():
    games = []
    try:
        import winreg
        for access in [winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY]:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\GOG.com\Games", 0, winreg.KEY_READ | access) as root:
                    keys = []
                    for index in range(min(winreg.QueryInfoKey(root)[0], MAX_LAUNCHER_RECORDS)):
                        keys.append(winreg.EnumKey(root, index))
                for key in keys:
                    state = _registry_values(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\GOG.com\\Games\\" + key, ["path", "gameName"], access)
                    if state.get("path") and state.get("gameName"):
                        game = inspect_game(state["path"], state["gameName"], "GOG")
                        game["launcher_id"] = key
                        game["installation_status"] = "installed" if game["installed"] else "missing"
                        games.append(game)
            except OSError:
                continue
    except ImportError:
        pass
    return games


def discover_games():
    epic_root = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "Epic/EpicGamesLauncher/Data/Manifests"
    candidates = steam_games(_steam_roots()) + epic_games(epic_root) + _gog_games()
    unique = {}
    for game in candidates:
        previous = unique.get(game["id"])
        if previous is None or (game["installed"] and not previous["installed"]):
            unique[game["id"]] = game
    return sorted(unique.values(), key=lambda game: (game["title"].casefold(), game["path"].casefold()))
