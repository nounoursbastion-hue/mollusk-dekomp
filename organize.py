"""Organize private job outputs into physical files without altering game installs."""
from collections import Counter
import codecs
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct


FOLDERS = ("Models", "Audio", "Textures", "Maps", "Animations", "Shaders",
           "Scripts", "Materials", "Containers", "Binaries", "Configurations", "Non_decodes")
SKIP_DIRS = {".git", ".cache", "__pycache__", "cache", "settings", "temp", "tmp", "logs", "tools"}
OPAQUE = {".uasset": "asset", ".umap": "Maps", ".uexp": "asset", ".ubulk": "asset",
          ".upk": "asset", ".udk": "Maps", ".utoc": "Containers", ".ucas": "Containers",
          ".bank": "Audio", ".wem": "Audio", ".fsb": "Audio", ".bnk": "Audio",
          ".tm2": "Textures", ".mic": "Audio", ".anm": "Animations", ".sam": "Animations",
          ".psq": "Models", ".psw": "Models", ".bns": "Animations", ".mph": "Models"}
SOURCE = {".cs", ".c", ".cpp", ".h", ".hpp", ".java", ".py", ".lua", ".js", ".uc", ".uci", ".gd", ".asm"}
SHADERS = {".shader", ".hlsl", ".glsl", ".cg", ".cginc", ".shadergraph", ".shadersubgraph"}


def classify_export(path):
    """Classify representations conservatively; extensions alone never prove decoding."""
    suffix, size = path.suffix.lower(), path.stat().st_size
    with path.open("rb") as source:
        head = source.read(4096)
    row = {"category": "Non_decodes", "status": "opaque", "format": None,
           "category_hint": OPAQUE.get(suffix), "runtime_validated": False,
           "original_source_recovered": False}
    if suffix in OPAQUE:
        return row
    signatures = (
        (b"\x89PNG\r\n\x1a\n", "PNG", "Textures"), (b"\xff\xd8\xff", "JPEG", "Textures"),
        (b"DDS ", "DDS", "Textures"), (b"OggS", "Ogg", "Audio"),
        (b"fLaC", "FLAC", "Audio"), (b"ID3", "MP3 ID3", "Audio"),
        (b"Kaydara FBX Binary  \x00\x1a\x00", "FBX binary", "Models"),
        (b"ACTRHEAD", "ActorX mesh", "Models"),
        (b"ANIMHEAD", "ActorX animation", "Animations"),
        (b"\x7fELF", "ELF", "Binaries"), (b"MZ", "MZ executable", "Binaries"),
        (b"PK\x03\x04", "ZIP", "Containers"), (b"\x1f\x8b\x08", "gzip", "Containers"),
        (b"7z\xbc\xaf\x27\x1c", "7z", "Containers"), (b"PAK1", "PAK1", "Containers"),
    )
    for magic, label, category in signatures:
        if head.startswith(magic):
            row.update(category=category, format=label, status="format_signature_observed")
            return row
    if suffix == ".glb" and len(head) >= 20 and head[:4] == b"glTF":
        version, declared_size, json_size, kind = struct.unpack_from("<IIII", head, 4)
        if version == 2 and declared_size == size and kind == 0x4E4F534A and json_size % 4 == 0 and 0 < json_size <= min(size - 20, 16 * 1024 * 1024):
            try:
                with path.open("rb") as source:
                    source.seek(20)
                    document = json.loads(source.read(json_size))
                asset = document.get("asset") if isinstance(document, dict) else None
                if isinstance(asset, dict) and asset.get("version") == "2.0":
                    row.update(category="Models", format="GLB 2", status="container_structure_observed")
                    return row
            except (ValueError, RecursionError):
                return row
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        if int.from_bytes(head[4:8], "little") + 8 == size:
            row.update(category="Audio", format="RIFF WAVE", status="container_structure_observed")
            return row
    try:
        text = codecs.getincrementaldecoder("utf-8-sig")("strict").decode(head, final=False)
    except UnicodeDecodeError:
        return row
    if "\0" in text:
        return row
    yaml = text.startswith("%YAML") or "--- !u!" in text
    if suffix == ".unity" and yaml:
        row.update(category="Maps", format="Unity scene YAML", status="serialized_source_unvalidated")
    elif suffix == ".anim" and yaml:
        row.update(category="Animations", format="Unity animation YAML", status="serialized_source_unvalidated")
    elif suffix == ".mat" and yaml:
        row.update(category="Materials", format="Unity material YAML", status="serialized_source_unvalidated")
    elif suffix == ".mtl" and re.search(r"(?m)^newmtl\s+\S", text):
        row.update(category="Materials", format="Wavefront MTL", status="text_records_observed")
    elif suffix == ".obj" and re.search(r"(?m)^v\s+[-+\d.]", text):
        row.update(category="Models", format="Wavefront OBJ", status="text_records_observed")
    elif suffix == ".bvh" and text.lstrip().startswith("HIERARCHY"):
        row.update(category="Animations", format="BVH", status="text_records_observed")
    elif suffix == ".fbx" and "; FBX" in text[:100]:
        row.update(category="Models", format="FBX text", status="text_records_observed")
    elif suffix in SOURCE:
        row.update(category="Scripts", format="source text", status="source_syntax_unvalidated")
    elif suffix in SHADERS:
        row.update(category="Shaders", format="shader source or graph text", status="source_syntax_unvalidated")
    elif suffix in {".json", ".xml", ".ini", ".txt", ".csv", ".tsv", ".md", ".meta"}:
        row.update(category="Configurations", format="text", status="text_encoding_observed")
    return row


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def organize_exports(roots, out):
    out = Path(out).resolve()
    job = out.parent
    roots = [Path(root).resolve() for root in roots]
    if not roots:
        raise ValueError("At least one private output root is required")
    for root in roots:
        if not root.is_dir() or root == job or not root.is_relative_to(job) or root == out or root.is_relative_to(out) or out.is_relative_to(root):
            raise ValueError("Only private exports inside the same job may be organized")
    out.mkdir(parents=True, exist_ok=True)
    for name in FOLDERS:
        folder = out / name
        if folder.is_symlink() or folder.is_junction() or not folder.resolve().is_relative_to(out):
            raise ValueError("Organized category cannot be a link")
        folder.mkdir(exist_ok=True)
    manifest = out / "organized-manifest-private.jsonl"
    partial = manifest.with_suffix(".jsonl.partial")
    counts, methods, statuses, errors, seen = Counter(), Counter(), Counter(), [], set()
    total_bytes = skipped = 0
    with partial.open("w", encoding="utf-8") as report:
        for source_index, root in enumerate(roots):
            def walk_error(exc):
                errors.append({"source_index": source_index, "path": str(exc.filename), "error": str(exc)})
            for folder, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
                for name in list(dirs):
                    child = Path(folder) / name
                    try:
                        excluded = name.lower() in SKIP_DIRS or name.lower().endswith(".rep")
                        unsafe = child.is_symlink() or child.is_junction() or not child.resolve().is_relative_to(root)
                    except OSError as exc:
                        excluded, unsafe = False, True
                        errors.append({"source_index": source_index, "path": str(child), "error": str(exc)})
                    if excluded or unsafe:
                        dirs.remove(name)
                        skipped += 1
                        if unsafe:
                            errors.append({"source_index": source_index, "path": str(child), "error": "Link directory skipped"})
                dirs.sort()
                for name in sorted(files):
                    source = Path(folder) / name
                    relative = source.relative_to(root).as_posix()
                    if source.suffix.lower() in {".log", ".gpr", ".lock", ".lck", ".partial"}:
                        skipped += 1
                        continue
                    try:
                        resolved = source.resolve()
                        if source.is_symlink() or source.is_junction() or not resolved.is_relative_to(root):
                            raise ValueError("Link file skipped")
                        if resolved in seen:
                            skipped += 1
                            continue
                        if not source.is_file():
                            skipped += 1
                            continue
                        seen.add(resolved)
                        before = source.stat()
                        row = classify_export(source)
                        sha256 = digest(source)
                        identifier = hashlib.sha256(f"{source_index}:{relative}".encode("utf-8")).hexdigest()[:24]
                        display = name if len(name) <= 100 else source.stem[:80] + source.suffix[:16]
                        target = out / row["category"] / (identifier + "-" + display)
                        if target.is_symlink() or target.is_junction() or not target.resolve().is_relative_to(out):
                            raise ValueError("Organized output cannot be a link or escape its directory")
                        if target.exists():
                            if target.stat().st_size != before.st_size or digest(target) != sha256:
                                raise ValueError("Existing organized file differs; not overwritten")
                            method = "existing_verified"
                        else:
                            temporary = target.with_name(target.name + ".partial")
                            if temporary.exists():
                                raise FileExistsError(temporary)
                            try:
                                os.link(source, temporary)
                                method = "hardlink_private_export"
                            except OSError:
                                with source.open("rb") as original, temporary.open("xb") as copied:
                                    shutil.copyfileobj(original, copied, length=1024 * 1024)
                                if temporary.stat().st_size != before.st_size or digest(temporary) != sha256:
                                    raise ValueError("Organized copy verification failed")
                                method = "copy_verified"
                            if target.exists():
                                raise FileExistsError("Organized target appeared during creation")
                            temporary.rename(target)
                        after = source.stat()
                        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                            raise RuntimeError("Private export changed during organization")
                        row.update(source_index=source_index, source_path=relative,
                                   organized_path=target.relative_to(out).as_posix(),
                                   bytes=before.st_size, sha256=sha256, storage_method=method)
                        report.write(json.dumps(row, ensure_ascii=False) + "\n")
                        counts[row["category"]] += 1
                        statuses[row["status"]] += 1
                        methods[method] += 1
                        total_bytes += before.st_size
                    except (OSError, ValueError, RuntimeError) as exc:
                        errors.append({"source_index": source_index, "path": relative, "error": str(exc)})
    partial.replace(manifest)
    summary = {"files": sum(counts.values()), "bytes": total_bytes, "categories": dict(counts),
               "classification": dict(statuses), "storage_methods": dict(methods),
               "source_roots_private": [str(root) for root in roots], "output": str(out),
               "manifest": str(manifest), "skipped": skipped, "errors": errors,
               "status": "complete" if not errors else "partial",
               "limits": ["Folders classify exported representations; no claim of original source or runtime correctness.",
                          "Opaque engine packages and banks are retained under Non_decodes with category hints.",
                          "Hardlinks share bytes with private exports: copy a file before modifying it.",
                          "Original installed game paths are rejected; source provenance remains private."]}
    (out / "organized-summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "README.txt").write_text(
        "Fichiers organises depuis les copies privees de ce job.\n"
        "Les liens physiques partagent les octets avec les exports : copiez un fichier avant de le modifier.\n"
        "Non_decodes contient les formats opaques ; une extension ne garantit pas un asset utilisable.\n"
        "Les signatures et structures observees ne prouvent ni la fidelite en jeu ni la compilation du code.\n"
        "Le manifeste prive indique SHA-256, classement, origine locale et methode de stockage.\n", encoding="utf-8")
    return summary
