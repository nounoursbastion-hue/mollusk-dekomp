"""Validated PAK1 layout observed on the supplied PS2 disc, not generic PAK."""
import hashlib
import json
from pathlib import Path, PureWindowsPath
import struct


def pak_entries(path):
    path = Path(path)
    size = path.stat().st_size
    with path.open("rb") as stream:
        header = stream.read(16)
        if len(header) != 16:
            raise ValueError("Truncated PAK1 header")
        magic, chars, count, alignment = struct.unpack("<4sIII", header)
        if magic != b"PAK1" or alignment != 2048 or not 0 < count <= 1000000:
            raise ValueError("Unsupported PAK1 layout")
        data_start = 16 + chars * 2 + count * 4
        if data_start > size or data_start % alignment or chars * 2 > 64 * 1024 * 1024:
            raise ValueError("Invalid PAK1 table bounds")
        names_blob = stream.read(chars * 2)
        names = names_blob.decode("utf-16le").split("\0")
        if len(names) < count + 1 or any(names[count:]):
            raise ValueError("Invalid PAK1 names or nonzero table padding")
        names = names[:count]
        offsets_blob = stream.read(count * 4)
        if len(offsets_blob) != count * 4:
            raise ValueError("Truncated PAK1 offset table")
        ends = struct.unpack("<" + str(count) + "I", offsets_blob)
        rows, previous_end, known = [], data_start, set()
        for index, (name, end) in enumerate(zip(names, ends)):
            windows = PureWindowsPath(name)
            if not name or windows.is_absolute() or windows.drive or ".." in windows.parts:
                raise ValueError("Unsafe PAK1 path")
            parts = windows.parts
            if not parts:
                raise ValueError("Empty normalized PAK1 output name")
            if any(part.endswith((".", " ")) or ":" in part for part in parts):
                raise ValueError("Unsafe PAK1 path component")
            reserved = {"CON", "PRN", "AUX", "NUL"} | {prefix + str(i) for prefix in ("COM", "LPT") for i in range(1, 10)}
            if any(part.split(".")[0].upper() in reserved for part in parts):
                raise ValueError("Reserved Windows PAK1 path component")
            normal = "/".join(parts)
            if normal.casefold() in known:
                raise ValueError("Duplicate PAK1 output name")
            known.add(normal.casefold())
            start = (previous_end + alignment - 1) // alignment * alignment
            if end < start or end > size:
                raise ValueError("PAK1 payload outside archive")
            stream.seek(previous_end)
            padding = stream.read(start - previous_end)
            if any(padding):
                raise ValueError("Nonzero PAK1 alignment padding")
            rows.append({"index": index, "path": normal, "offset": start,
                         "size": end - start, "padding_before": start - previous_end})
            previous_end = end
        if previous_end != size:
            raise ValueError("PAK1 trailing bytes not described by table")
    return rows


def extract_paks(root, out):
    root, out = Path(root).resolve(), Path(out).resolve()
    if not root.is_dir() or out == root or out.is_relative_to(root):
        raise ValueError("Output must be outside extracted disc directory")
    out.mkdir(parents=True, exist_ok=True)
    archives, files, total_bytes = [], 0, 0
    manifest = out / "pak-manifest-private.jsonl"
    with manifest.with_suffix(".partial").open("w", encoding="utf-8") as report:
        for path in sorted(root.rglob("*.PAK")):
            if path.is_symlink() or path.is_junction() or not path.resolve().is_relative_to(root):
                raise ValueError("PAK path escapes input root")
            before = path.stat()
            rows = pak_entries(path)
            relative = path.relative_to(root).as_posix()
            archive_id = "archive-" + hashlib.sha256(relative.encode()).hexdigest()[:20]
            destination = out / "files" / archive_id
            with path.open("rb") as source:
                for row in rows:
                    target = destination / row["path"]
                    if not target.resolve().is_relative_to(out):
                        raise ValueError("PAK target escapes output root")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    partial = target.with_name(target.name + ".partial")
                    if partial.exists():
                        raise FileExistsError(partial)
                    sha = hashlib.sha256()
                    source.seek(row["offset"])
                    remaining = row["size"]
                    if target.exists():
                        if target.is_symlink() or target.stat().st_size != remaining:
                            raise ValueError("Existing PAK output is incompatible")
                        with target.open("rb") as existing:
                            while remaining:
                                block = source.read(min(1024 * 1024, remaining))
                                if not block or block != existing.read(len(block)):
                                    raise ValueError("Existing PAK output differs")
                                sha.update(block)
                                remaining -= len(block)
                    else:
                        with partial.open("xb") as output:
                            while remaining:
                                block = source.read(min(1024 * 1024, remaining))
                                if not block:
                                    raise ValueError("Truncated PAK payload")
                                sha.update(block)
                                output.write(block)
                                remaining -= len(block)
                        partial.replace(target)
                        with target.open("rb") as verified:
                            verify = hashlib.file_digest(verified, "sha256").hexdigest()
                        if verify != sha.hexdigest():
                            raise ValueError("PAK payload hash mismatch")
                    row.update({"archive": relative, "archive_id": archive_id,
                                "sha256": sha.hexdigest(),
                                "extracted_path": target.relative_to(out).as_posix(),
                                "status": "payload_bytes_verified"})
                    report.write(json.dumps(row, ensure_ascii=False) + "\n")
                    files += 1
                    total_bytes += row["size"]
            after = path.stat()
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                raise RuntimeError("PAK source changed during extraction")
            archives.append({"path": relative, "entries": len(rows), "status": "complete"})
    manifest.with_suffix(".partial").replace(manifest)
    summary = {"archives": len(archives), "entries": files, "bytes": total_bytes,
               "all_payloads_verified": True, "details": archives,
               "files_root": str(out / "files"), "manifest": str(manifest),
               "limits": ["Only observed PAK1 layout with 2048-byte alignment is supported.",
                          "Extracted payloads are unchanged; extraction does not decode their formats."]}
    (out / "pak-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary
