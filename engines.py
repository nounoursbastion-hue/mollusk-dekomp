"""Dispatch installed, local analysis tools without executing a game."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import subprocess
import time
import urllib.parse
import urllib.request

import native
from settings import configured_path

TOOLS = {
    'ilspy': Path(str(Path(__file__).resolve().parent/'tools/ilspy/ilspycmd.exe')),
    'il2cpp': Path(str(Path(__file__).resolve().parent/'tools/il2cpp/Il2CppDumper.exe')),
    'assetripper': Path(str(Path(__file__).resolve().parent/'tools/assetripper/AssetRipper.GUI.Free.exe')),
    'repak': Path(str(Path(__file__).resolve().parent/'tools/repak/repak.exe')),
    'cue4parse': Path(str(Path(__file__).resolve().parent/'tools/cue4parse/cue4parse.exe')),
}
TOOLS={key:configured_path(key,path) for key,path in TOOLS.items()}


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _run(args, out, label, timeout, env):
    log = out / (label + '.log')
    started = time.monotonic()
    with log.open('w', encoding='utf-8') as stream:
        try:
            process = subprocess.run([str(x) for x in args], cwd=out, env=env, stdin=subprocess.DEVNULL,
                                     stdout=stream, stderr=subprocess.STDOUT, timeout=timeout,
                                     creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            code, status = process.returncode, 'ok' if process.returncode == 0 else 'failed'
        except subprocess.TimeoutExpired:
            code, status = 124, 'timeout'
        except OSError as error:
            stream.write(str(error))
            code, status = None, 'failed'
    return dict(stage=label, status=status, exit_code=code, log=str(log), seconds=round(time.monotonic()-started, 2))


def _files(root):
    return sum(1 for p in root.rglob('*') if p.is_file() and not p.is_symlink()) if root.exists() else 0


def _unity_data(source):
    fallback = None
    for base in [source] + [p for p in source.iterdir() if p.is_dir() and not p.is_symlink()]:
        for p in base.glob('*_Data'):
            if p.is_dir() and not p.is_symlink():
                if (p/'il2cpp_data/Metadata/global-metadata.dat').is_file() and (base/'GameAssembly.dll').is_file():
                    return p
                if (p/'Managed').is_dir() and any((p/'Managed').glob('*.dll')):
                    fallback = p
    return fallback


def _archive_paths(text):
    paths = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith('../../../'):
            line = line[9:]
        p = PurePosixPath(line)
        reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}
        if (not line or not p.parts or '\\' in line or p.is_absolute() or '..' in p.parts or ':' in line
                or any(part.split('.')[0].upper() in reserved for part in p.parts)
                or any(part.rstrip(' .') != part or any(c in part for c in '<>"|?*\x00') for part in p.parts)):
            raise ValueError('Unsafe archive member path')
        normalized = p.as_posix().casefold()
        if normalized in seen:
            raise ValueError('Archive has conflicting member paths')
        seen.add(normalized)
        paths.append(p.as_posix())
    if not paths:
        raise ValueError('Archive has no readable member paths')
    return paths


def _assetripper(source, out, tool, timeout, env, progress):
    stage = out / 'unity-assets'
    stage.mkdir(exist_ok=True)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    started = time.monotonic()
    def post(route, fields):
        request = urllib.request.Request(f'http://127.0.0.1:{port}' + route,
                                         data=urllib.parse.urlencode(fields).encode())
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise TimeoutError('AssetRipper time budget exhausted')
        with urllib.request.urlopen(request, timeout=remaining) as response:
            response.read()
    with (out / 'assetripper-console.log').open('w', encoding='utf-8') as log:
        process = subprocess.Popen([str(tool), '--headless', '--port', str(port), '--log-path', str(out/'assetripper.log')],
                                   cwd=out, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        try:
            for _ in range(min(90, timeout)):
                if process.poll() is not None:
                    raise RuntimeError('AssetRipper exited during startup')
                try:
                    with urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=1) as response:
                        if b'AssetRipper' in response.read(1024*1024):
                            break
                except (OSError, TimeoutError):
                    pass
                time.sleep(1)
            else:
                raise TimeoutError('AssetRipper startup timeout')
            post('/Settings/Update', {'ScriptContentLevel': 'Level2', 'ScriptExportMode': 'Hybrid',
                                     'BundledAssetsExportMode': 'DirectExport', 'ExportUnreadableAssets': 'on'})
            progress('AssetRipper : lecture des assets Unity...')
            post('/LoadFolder', {'Path': str(source)})
            post('/Export/UnityProject', {'Path': str(stage)})
            count = _files(stage / 'ExportedProject')
            return dict(stage='unity-assets', status='partial' if count else 'failed', files=count, output=str(stage),
                        compiled=False, limits=['Reader diagnostics remain in assetripper.log; exported scenes and materials are not runtime-validated.'])
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def analyze_game(game, out, *, progress=print, run_tools=True, timeout=1800,
                 export_assets=True, ue_profile=None, tools=None, run_native=True,
                 analysis_timeout=600, function_timeout=15, max_functions=0, source_fingerprint=None):
    if timeout <= 0:
        raise ValueError('Tool timeout must be positive')
    source = Path(game['path'] if isinstance(game, dict) else game).resolve()
    out = Path(out).resolve()
    if not source.is_dir() or out == source or out.is_relative_to(source) or source.is_relative_to(out):
        raise ValueError('Game installation and output must be separate directories')
    if source_fingerprint is not None and not re.fullmatch(r'[0-9a-f]{64}', source_fingerprint):
        raise ValueError('source_fingerprint must be a verified SHA256 tree fingerprint')
    available = {name: Path(path).resolve() for name, path in (tools or TOOLS).items()}
    request = dict(source=str(source), source_fingerprint=source_fingerprint, run_tools=run_tools,
                   engine_hint=game.get('engine') if isinstance(game, dict) else None,
                   title_hint=game.get('title') if isinstance(game, dict) else None,
                   timeout=timeout, export_assets=export_assets, ue_profile=ue_profile, run_native=run_native,
                   analysis_timeout=analysis_timeout, function_timeout=function_timeout, max_functions=max_functions,
                   tools={key: [str(path), path.stat().st_size, path.stat().st_mtime_ns] if path.is_file() else [str(path), None, None]
                          for key, path in available.items()})
    previous_path = out/'engine-report.json'
    if previous_path.exists():
        previous = json.loads(previous_path.read_text(encoding='utf-8'))
        valid = bool(source_fingerprint) and previous.get('request') == request and previous.get('tracked_inputs_unchanged')
        for item in previous.get('toolruns', []):
            if item.get('output') and item.get('files'):
                target = Path(item['output']).resolve()
                valid = valid and target.is_relative_to(out) and target.is_dir() and _files(target) == item['files']
        for item in previous.get('native', []):
            if item.get('output_directory'):
                target = Path(item['output_directory']).resolve()
                valid = valid and target.is_relative_to(out) and (target/'native-report.json').is_file()
                if item.get('ghidra', {}).get('pseudocode_functions'):
                    valid = valid and len(list((target/'pseudocode').glob('*.c'))) == item['ghidra']['pseudocode_functions']
        if valid:
            progress('Analyse précédente réutilisée : identité complète des fichiers source vérifiée.')
            previous['cache_reused'] = True
            return previous
        raise FileExistsError('Analysis output differs from the verified input/options or contains missing outputs; choose a fresh directory')
    out.mkdir(parents=True, exist_ok=True)
    for name in ('temp', 'dotnet-home', 'cache'):
        (out / name).mkdir(exist_ok=True)
    env = dict(os.environ, DOTNET_ROLL_FORWARD='LatestMajor',
               DOTNET_CLI_HOME=str(out/'dotnet-home'), NUGET_PACKAGES=str(out/'cache'),
               TEMP=str(out/'temp'), TMP=str(out/'temp'), DOTNET_BUNDLE_EXTRACT_BASE_DIR=str(out/'cache'),
               DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1')
    dotnet=configured_path('dotnet',Path(__file__).resolve().parent/'tools/dotnet')
    if dotnet.is_dir():env['DOTNET_ROOT']=str(dotnet)
    data = _unity_data(source)
    paks = sorted(source.rglob('*.pak'))
    iostore = sorted(source.rglob('*.utoc'))
    packs = sorted(source.rglob('*.pck'))
    engine = game.get('engine') if isinstance(game, dict) else None
    if not engine or engine == 'unknown':
        engine = ('unity-il2cpp' if data and (data/'il2cpp_data/Metadata/global-metadata.dat').is_file() and (data.parent/'GameAssembly.dll').is_file() else 'unity-mono' if data else
                  'unreal' if paks or iostore else 'godot' if packs else 'native')
    report = dict(engine=engine, status='inventory_only', toolruns=[], resources=[], native=[],
                  supported_actions=[], limits=[], original_source_recovered=False, standalone=False, request=request)
    tracked = {}
    def track(path):
        tracked[Path(path)] = digest(path)
    def action(name, tool, args, target, expected=None):
        report['supported_actions'].append(name)
        if not run_tools:
            row = dict(stage=name, status='pending', reason='Tool execution disabled')
        elif tool not in available or not available[tool].is_file():
            row = dict(stage=name, status='tool_unavailable', reason=f'Local {tool} executable missing')
        else:
            if not target.resolve().is_relative_to(out) or (target.exists() and any(target.iterdir())):
                raise ValueError('Tool output directory must be empty and contained in this analysis')
            target.mkdir(parents=True, exist_ok=True)
            progress(name)
            row = _run([available[tool], *args], out, name, timeout, env)
            row['files'] = _files(target)
            row['output'] = str(target)
            if row['status'] == 'ok' and (not row['files'] or (expected and not expected.is_file())):
                row.update(status='failed', reason='Tool returned success without expected output')
            elif row['status'] == 'ok':
                row['status'] = 'partial'
        report['toolruns'].append(row)
        return row
    def native_binary(path):
        report['supported_actions'].append('native-pseudocode')
        track(path)
        try:
            relative = path.relative_to(source).as_posix()
            target = out/'native'/hashlib.sha256(relative.encode()).hexdigest()[:16]
            result = native.analyze_native(path, target,
                                           run_ghidra=run_tools and run_native, analysis_timeout=analysis_timeout,
                                           function_timeout=function_timeout, max_functions=max_functions)
            result['input_relative'], result['output_directory'] = relative, str(target)
            report['native'].append(result)
        except Exception as error:
            report['native'].append(dict(status='failed', reason=f'{type(error).__name__}: {error}'))
    try:
        if engine in ('unity-mono', 'unity-il2cpp'):
            if data is None:
                raise ValueError('Unity data directory not found')
            if engine == 'unity-mono':
                managed = data/'Managed'
                dlls = sorted(managed.glob('*.dll'))
                if not dlls:
                    report['limits'].append('No managed assemblies were found.')
                for dll in dlls:
                    track(dll)
                    key = hashlib.sha256(dll.name.encode()).hexdigest()[:16]
                    target = out/'managed'/key
                    row = action('managed-'+key, 'ilspy', ['--disable-updatecheck', '-p', '--nested-directories',
                                  '-r', str(managed), '-o', str(target), str(dll)], target)
                    row['csharp_files'] = sum(1 for _ in target.rglob('*.cs')) if target.exists() else 0
                    if row['status'] == 'partial' and not row['csharp_files']:
                        row.update(status='failed', reason='No reconstructed C# files')
                report['limits'].append('C# is reconstructed, includes engine/framework assemblies, and has not been recompiled.')
            else:
                binary, metadata = data.parent/'GameAssembly.dll', data/'il2cpp_data/Metadata/global-metadata.dat'
                if not binary.is_file() or not metadata.is_file():
                    raise ValueError('IL2CPP requires GameAssembly.dll and global-metadata.dat')
                track(binary); track(metadata)
                target = out/'il2cpp'
                row = action('il2cpp-signatures', 'il2cpp', [str(binary), str(metadata), str(target)], target, target/'dump.cs')
                row['method_bodies_recovered'] = False
                report['limits'].append('Il2CppDumper recovers declarations and addresses, not original C# method bodies; unsupported metadata versions remain explicit failures.')
                native_binary(binary)
            if export_assets:
                report['supported_actions'].append('unity-assets')
                if run_tools and available.get('assetripper', Path('missing')).is_file():
                    try:
                        row = _assetripper(data.parent, out, available['assetripper'], timeout, env, progress)
                    except Exception as error:
                        row = dict(stage='unity-assets', status='failed', reason=f'{type(error).__name__}: {error}')
                else:
                    row = dict(stage='unity-assets', status='pending' if not run_tools else 'tool_unavailable')
                report['toolruns'].append(row)
                if row.get('files'):
                    report['resources'].append(row)
        elif engine == 'unreal':
            if ue_profile and not re.fullmatch(r'GAME_UE[45]_[0-9]+', ue_profile):
                raise ValueError('Provide an explicit version profile, for example GAME_UE4_25 or GAME_UE5_6')
            for pak in paks:
                track(pak)
                key = hashlib.sha256(pak.relative_to(source).as_posix().encode()).hexdigest()[:16]
                target = out/'packages'/key
                if not run_tools or not available.get('repak', Path('missing')).is_file():
                    action('pak-'+key, 'repak', [], target)
                    continue
                listing = _run([available['repak'], 'list', pak], out, 'pak-list-'+key, timeout, env)
                report['toolruns'].append(listing)
                if listing['status'] != 'ok':
                    listing['limits'] = ['Unreadable or encrypted archive; no keys or bypass attempted.']
                    continue
                entries = _archive_paths(Path(listing['log']).read_text(encoding='utf-8', errors='replace'))
                row = action('pak-'+key, 'repak', ['unpack', str(pak), '-o', str(target)], target)
                row['expected_entries'] = len(entries)
                row['missing_entries'] = sum(1 for item in entries if not (target/item).is_file()) if target.exists() else len(entries)
                if row['missing_entries']:
                    row['status'] = 'partial' if row.get('files') else 'failed'
                if row.get('files'):
                    report['resources'].append(row)
                if export_assets and ue_profile:
                    probe = out/'probe'/key
                    probe_entries = [item for item in entries if item.endswith('.uasset')][:3]
                    if probe_entries:
                        args = ['--pak', str(pak), '-g', ue_profile, '-o', str(probe), '--mesh-format', 'Gltf2']
                        for item in probe_entries:
                            args += ['-p', item]
                        probe_row = action('ue-probe-'+key, 'cue4parse', args, probe)
                        if probe_row['status'] == 'partial' and probe_row.get('files'):
                            converted = out/'converted'/key
                            full = action('ue-assets-'+key, 'cue4parse', ['--pak', str(pak), '-g', ue_profile, '-o', str(converted), '--mesh-format', 'Gltf2'], converted)
                            if full.get('files'):
                                report['resources'].append(full)
            if iostore:
                report['limits'].append('IoStore .utoc/.ucas detected. This adapter does not yet validate their extraction; retained in the installation inventory.')
            if not paks and not iostore:
                report['limits'].append('No UE4/UE5 archive found. UE3 .upk/.udk resources require a separate package reader; only inventory and native executable analysis are available.')
            if export_assets and not ue_profile:
                report['limits'].append('Unreal asset conversion requires an explicit compatible ue_profile; engine version is never guessed.')
            report['limits'].append('Raw Unreal packages retain dependencies. Kismet/editor graph reconstruction is not provided by archive extraction.')
            binaries = sorted(source.rglob('*-Shipping.exe')) or sorted(source.rglob('*.exe'))
            if binaries:
                native_binary(binaries[0])
        elif engine == 'godot':
            report['supported_actions'].append('godot-pack-inventory')
            report['limits'].append('Godot packs are inventoried; no local GDRE script/resource decompiler is installed. Native export does not reconstruct GDScript.')
            binaries = sorted(source.rglob('*.exe'))
            if binaries:
                native_binary(binaries[0])
        else:
            binaries = sorted(source.rglob('*.exe'))
            if not binaries:
                report['limits'].append('No supported top-level native executable found; unknown/custom engines remain inventoried.')
            else:
                title = str(game.get('title', '')).lower() if isinstance(game, dict) else ''
                binaries.sort(key=lambda p: (p.stem.lower() not in title, len(p.relative_to(source).parts), -p.stat().st_size))
                report['limits'].append('The main native executable is selected by title, path depth and size; launcher/helper identification remains heuristic.')
                native_binary(binaries[0])
        statuses = [r['status'] for r in report['toolruns'] + report['native']]
        if not run_tools:
            report['status'] = 'inventory_only'
        elif any(s in ('partial', 'pseudocode_partial') for s in statuses):
            report['status'] = 'partial'
        elif statuses and all(s == 'metadata_only' for s in statuses):
            report['status'] = 'metadata_only'
        else:
            report['status'] = 'unavailable' if not statuses else 'failed'
    except Exception as error:
        report.update(status='partial' if report['resources'] or report['native'] else 'failed')
        report['limits'].append(f'{type(error).__name__}: {error}')
    report['tracked_inputs_unchanged'] = all(p.is_file() and digest(p) == sha for p, sha in tracked.items())
    if not report['tracked_inputs_unchanged']:
        report['status'] = 'input_changed_during_analysis'
    report['limits'].append('Only selected binaries/archives are hashed here; the installation inventory describes the remaining files. No game executable is launched.')
    report['limits'].append('Cached exports are checked by presence and file counts; exported content is not fully rehashed or runtime-validated.')
    (out/'engine-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    return report
