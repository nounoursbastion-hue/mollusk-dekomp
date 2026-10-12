"""Lightweight, read-only PC game inventory; inspect at most 64 bytes per file."""
from collections import Counter
import json
import os
from pathlib import Path

from resources import classify


PC_SIGNATURES = (
    (b"UnityFS\0", "UnityFS", "unity-container"),
    (b"UnityRaw\0", "UnityRaw", "unity-container"),
    (b"UnityWeb\0", "UnityWeb", "unity-container"),
    (b"UnityArchive\0", "UnityArchive", "unity-container"),
    (b"GDPC", "Godot PCK", "godot-container"),
    (b"\xc1\x83\x2a\x9e", "Unreal package", "unreal-package"),
    (b"MZ", "DOS MZ executable header", "executable-candidate"),
    (b"FSB5", "FSB5", "audio-bank"),
    (b"BKHD", "Wwise BNK", "audio-bank"),
)
PC_HINTS = {
    ".assets": "unity-serialized-file", ".bundle": "asset-container",
    ".resource": "asset-resource", ".ress": "asset-resource",
    ".pck": "godot-container", ".gd": "godot-script", ".gdc": "godot-script-bytecode",
    ".pak": "asset-container", ".utoc": "unreal-iostore-index",
    ".ucas": "unreal-iostore-container", ".uasset": "unreal-package",
    ".umap": "unreal-map", ".uexp": "unreal-export-data",
    ".exe": "executable", ".dll": "library", ".so": "library",
    ".lua": "script", ".py": "script", ".js": "script",
    ".cs": "source", ".cpp": "source", ".h": "source",
    ".png": "image", ".jpg": "image", ".dds": "texture",
    ".fbx": "model", ".obj": "model", ".glb": "model",
    ".wav": "audio", ".ogg": "audio", ".bank": "audio-bank",
    ".json": "configuration", ".xml": "configuration", ".ini": "configuration",
}


def unsafe_entry(path, root, errors):
    try:
        if not (path.is_symlink() or path.is_junction() or not path.resolve().is_relative_to(root)):
            return False
        error = "Link or escaped entry skipped"
    except OSError as exc:
        error = str(exc)
    errors.append({"path": path.relative_to(root).as_posix(), "error": error})
    return True


def inventory_game(root, out, *, source_area="game"):
    if source_area not in {"game", "exported"}:
        raise ValueError("Unsupported inventory source area")
    root, out = Path(root).resolve(), Path(out).resolve()
    if not root.is_dir():
        raise ValueError("Game root must be an existing directory")
    if out == root or out.is_relative_to(root):
        raise ValueError("Inventory output must be outside the game directory")
    out.mkdir(parents=True, exist_ok=True)
    inventory = out / "pc-resources-private.jsonl"
    partial = inventory.with_suffix(".jsonl.partial")
    errors, extensions, formats, statuses = [], Counter(), Counter(), Counter()
    files = total_bytes = inspected_bytes = 0

    def walk_error(exc):
        errors.append({"path": str(exc.filename), "error": str(exc)})

    with partial.open("w", encoding="utf-8") as target:
        for folder, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
            for name in list(dirs):
                child = Path(folder) / name
                if unsafe_entry(child, root, errors):
                    dirs.remove(name)
            dirs.sort()
            for name in sorted(names):
                path = Path(folder) / name
                relative = path.relative_to(root).as_posix()
                if unsafe_entry(path, root, errors):
                    continue
                row = {"path": relative, "bytes": None, "source_area": source_area,
                       "sha256": None, "content_hash_status": "not_requested",
                       "lexical_hints": {}, "semantic_function_verified": False,
                       "assets_decoded": False, "observed_formats": []}
                try:
                    before = path.stat()
                    if not path.is_file():
                        continue
                    row["bytes"] = before.st_size
                    with path.open("rb") as source:
                        head = source.read(64)
                    after = path.stat()
                    inspected_bytes += len(head)
                    observed, hint = classify(head, path.suffix, before.st_size)
                    for magic, label, category in PC_SIGNATURES:
                        if head.startswith(magic):
                            observed.append({"format": label, "category": category,
                                             "evidence": "header_signature", "decoded": False})
                    row.update({"extension": path.suffix.lower(), "header_hex": head.hex(),
                                "inspected_bytes": len(head), "observed_formats": observed,
                                "extension_category_hint": PC_HINTS.get(path.suffix.lower(), hint),
                                "classification_status": "signature_observed" if observed else "opaque"})
                    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                        row["classification_status"] = "changed_during_inventory"
                        errors.append({"path": relative, "error": "File changed during inventory"})
                    extensions[path.suffix.lower() or "(none)"] += 1
                    formats.update(item["format"] for item in observed)
                    total_bytes += before.st_size
                except OSError as exc:
                    row["classification_status"] = "read_error"
                    row["error"] = str(exc)
                    errors.append({"path": relative, "error": str(exc)})
                statuses[row["classification_status"]] += 1
                files += 1
                target.write(json.dumps(row, ensure_ascii=False) + "\n")
    partial.replace(inventory)
    report = {"source_root": str(root), "source_area": source_area, "files": files, "bytes": total_bytes,
              "inspected_bytes": inspected_bytes, "max_header_bytes_per_file": 64,
              "classification": dict(statuses), "extensions": dict(extensions),
              "observed_formats": dict(formats), "errors": errors,
              "inventory": str(inventory), "all_files_hashed": False, "assets_decoded": 0,
              "status": "complete_inventory" if not errors else "partial_inventory",
              "limits": ["Only file metadata and at most 64 header bytes were read; no full content hashes.",
                         "Header signatures and extension hints do not verify gameplay semantics or engine version.",
                         "Containers were not unpacked and original source was not reconstructed.",
                         "Symbolic links and Windows junctions are skipped; source paths remain private."]}
    (out / "pc-resource-summary.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report
