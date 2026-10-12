"""Verified copies of one selected local installation; source files stay read-only."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import uuid

CHUNK = 4 * 1024 * 1024


def _linked(path):
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _signature(stat):
    return stat.st_size, stat.st_mtime_ns, stat.st_dev, stat.st_ino


def _inventory(root):
    files, errors = {}, []
    def failed(error):
        errors.append({"path": str(error.filename), "error": str(error)})
    for folder, directories, names in os.walk(root, followlinks=False, onerror=failed):
        for name in list(directories):
            node = Path(folder) / name
            if _linked(node) or not node.resolve().is_relative_to(root):
                directories.remove(name)
                errors.append({"path": node.relative_to(root).as_posix(), "error": "Link directory skipped"})
        directories.sort()
        for name in sorted(names):
            node = Path(folder) / name
            relative = node.relative_to(root).as_posix()
            try:
                if _linked(node) or not node.resolve().is_relative_to(root) or not node.is_file():
                    raise ValueError("Link, special file or escaped path skipped")
                files[relative] = _signature(node.stat())
            except (OSError, ValueError) as error:
                errors.append({"path": relative, "error": str(error)})
    return files, errors


def _destination(root, relative):
    path = root / relative
    if not path.resolve().is_relative_to(root):
        raise ValueError("Destination leaves output root")
    for node in [path, *path.parents]:
        if _linked(node):
            raise ValueError("Destination traverses a symbolic link or junction")
    return path


def _hash(path, size):
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        remaining = size
        while remaining:
            data = stream.read(min(CHUNK, remaining))
            if not data:
                raise ValueError("File truncated while hashing")
            sha.update(data)
            remaining -= len(data)
        if stream.read(1):
            raise ValueError("File grew while hashing")
    return sha.hexdigest()


def copy_game(source, out):
    """Copy into the RAW folder itself, preserving relative paths and original bytes."""
    source, out = Path(source).absolute(), Path(out).absolute()
    for node in [source, *source.parents, out, *out.parents]:
        if _linked(node):
            raise ValueError("Source/output root traverses a link or junction")
    source, out = source.resolve(), out.resolve()
    if not source.is_dir() or out == source or out.is_relative_to(source) or source.is_relative_to(out):
        raise ValueError("Source and output must be separate, nonoverlapping directories")
    if out.drive.upper() == "C:":
        raise ValueError("Large RAW copies must be written to F: or G:, not C:")
    files, errors = _inventory(source)
    out.mkdir(parents=True, exist_ok=True)
    destinations = {}
    required = 0
    for relative, signature in files.items():
        try:
            target = _destination(out, relative)
            destinations[relative] = target
            if not target.exists():
                required += signature[0]
        except (OSError, ValueError) as error:
            errors.append({"path": relative, "error": str(error)})
    free = shutil.disk_usage(out).free
    if required + 16 * 1024 * 1024 > free:
        raise OSError(f"Insufficient output space: {required} payload bytes required, {free} bytes free")
    manifest = out.parent / (out.name + "-copy-manifest-private.jsonl")
    temporary_manifest = manifest.with_name(manifest.name + "." + uuid.uuid4().hex + ".part")
    copied = reused = verified_bytes = 0
    verified_records = []
    try:
        with temporary_manifest.open("x", encoding="utf-8") as inventory:
            for relative, signature in files.items():
                path = source / relative
                target = destinations.get(relative)
                if target is None:
                    continue
                temporary = None
                row = {"path": relative, "bytes": signature[0]}
                try:
                    if _linked(path) or _signature(path.stat()) != signature:
                        raise ValueError("Source changed since inventory")
                    target = _destination(out, relative)
                    if target.exists():
                        if not target.is_file() or target.stat().st_size != signature[0]:
                            raise FileExistsError("Existing RAW file has a different size or type")
                        digest = _hash(path, signature[0])
                        if _hash(target, signature[0]) != digest:
                            raise FileExistsError("Existing RAW file has different bytes")
                        action = "reused"
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        temporary = target.with_name(target.name + "." + uuid.uuid4().hex + ".part")
                        digest_state = hashlib.sha256()
                        remaining = signature[0]
                        with path.open("rb") as original, temporary.open("xb") as output:
                            while remaining:
                                data = original.read(min(CHUNK, remaining))
                                if not data:
                                    raise ValueError("Source truncated during copy")
                                output.write(data)
                                digest_state.update(data)
                                remaining -= len(data)
                            if original.read(1):
                                raise ValueError("Source grew during copy")
                        digest = digest_state.hexdigest()
                        if _hash(temporary, signature[0]) != digest:
                            raise ValueError("Written RAW file SHA-256 mismatch")
                        if target.exists():
                            raise FileExistsError("RAW target appeared during copy")
                        temporary.rename(target)
                        action = "copied"
                    if _signature(path.stat()) != signature:
                        raise ValueError("Source changed during verification")
                    copied += action == "copied"
                    reused += action == "reused"
                    verified_bytes += signature[0]
                    row.update(status="sha256_verified", action=action, sha256=digest)
                    verified_records.append((relative, signature[0], digest))
                except (OSError, ValueError) as error:
                    row.update(status="failed", error=str(error))
                    errors.append({"path": relative, "error": str(error)})
                finally:
                    if temporary is not None and temporary.exists():
                        temporary.unlink()
                inventory.write(json.dumps(row, ensure_ascii=False) + "\n")
        temporary_manifest.replace(manifest)
    finally:
        if temporary_manifest.exists():
            temporary_manifest.unlink()
    final_files, final_errors = _inventory(source)
    errors.extend(final_errors)
    if final_files != files:
        errors.append({"path": "", "error": "Source tree changed during copy; result is partial"})
    existing, output_errors = _inventory(out)
    errors.extend(output_errors)
    for extra in existing.keys() - files.keys():
        errors.append({"path": extra, "error": "Unexpected existing RAW file; not removed"})
    all_verified = not errors and copied + reused == len(files)
    tree_digest = hashlib.sha256(b"MolluskDekomP source tree v1\x00")
    for entry in sorted(verified_records):
        tree_digest.update((json.dumps(entry, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8"))
    report = {"status": "complete" if all_verified else "partial",
              "source_files_scanned": len(files), "source_bytes": sum(item[0] for item in files.values()),
              "files_copied": copied, "files_reused": reused, "files_verified": copied + reused,
              "bytes": verified_bytes, "all_files_verified": all_verified,
              "source_tree_sha256": tree_digest.hexdigest() if all_verified else None,
              "source_unchanged": final_files == files and not final_errors,
              "source_executed": False, "manifest": str(manifest), "errors": errors,
              "limits": ["RAW files preserve source bytes and dependencies; copying is not format decoding or source recovery.",
                         "Links, junctions and inaccessible files are skipped and make the copy partial.",
                         "Source changes are checked by file identity, size and modification time before/after copying."]}
    summary = manifest.with_name(out.name + "-copy-summary.json")
    summary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report
