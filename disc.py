"""Read-only ISO9660 inventory and bounded, verified extraction (standard library)."""
from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import re
import uuid

SECTOR = 2048
CHUNK = 4 * 1024 * 1024


def _both(data: bytes, offset: int, width: int) -> int:
    little = int.from_bytes(data[offset:offset + width], "little")
    big = int.from_bytes(data[offset + width:offset + width * 2], "big")
    if little != big:
        raise ValueError("ISO9660 endian copies disagree")
    return little


def _read(stream, offset: int, size: int, limit: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > limit:
        raise ValueError("Extent outside image")
    stream.seek(offset)
    result = stream.read(size)
    if len(result) != size:
        raise ValueError("Truncated image")
    return result


def _digest(stream, offset: int, size: int) -> str:
    stream.seek(offset)
    digest = hashlib.sha256()
    while size:
        data = stream.read(min(CHUNK, size))
        if not data:
            raise ValueError("Truncated file while hashing")
        digest.update(data)
        size -= len(data)
    return digest.hexdigest()


def _component(name: str) -> str:
    # Windows path rules also apply when running the reader on another platform.
    if (not name or name in {".", ".."} or any(c in name for c in '/\\:<>"|?*')
            or any(ord(c) < 32 for c in name) or name.endswith((" ", "."))
            or re.match(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", name, re.I)):
        raise ValueError(f"Unsafe ISO path component: {name!r}")
    return name


def _record(data: bytes) -> dict:
    if len(data) < 34 or data[0] != len(data) or 33 + data[32] > len(data):
        raise ValueError("Malformed ISO9660 directory record")
    if data[1] or data[26] or data[27] or data[25] & 0x80:
        raise ValueError("Extended attributes, interleaved or multi-extent files unsupported")
    if _both(data, 28, 2) != 1:
        raise ValueError("Multi-volume ISO unsupported")
    identifier = data[33:33 + data[32]]
    name = "" if identifier in {b"\x00", b"\x01"} else identifier.decode("ascii")
    if name:
        name = _component(re.sub(r";[0-9]+$", "", name).rstrip("."))
    return {"name": name, "offset": _both(data, 2, 4) * SECTOR,
            "size": _both(data, 10, 4), "directory": bool(data[25] & 2)}


def analyze(image: str | Path, hash_files: bool = True) -> dict:
    """Inventory the primary ISO9660 namespace. Raw/cooked sectors other than 2048 fail."""
    image = Path(image).resolve(strict=True)
    size = image.stat().st_size
    with image.open("rb") as stream:
        primary = None
        for sector in range(16, min(size // SECTOR, 256)):
            descriptor = _read(stream, sector * SECTOR, SECTOR, size)
            if descriptor[1:6] != b"CD001" or descriptor[6] != 1:
                raise ValueError("Not a supported 2048-byte ISO9660 image")
            if descriptor[0] == 1:
                primary = descriptor
            if descriptor[0] == 255:
                break
        else:
            raise ValueError("Missing volume descriptor terminator")
        if primary is None or _both(primary, 128, 2) != SECTOR:
            raise ValueError("Missing primary volume or unsupported block size")
        volume_bytes = _both(primary, 80, 4) * SECTOR
        if volume_bytes > size:
            raise ValueError("Volume exceeds image size")
        root = _record(primary[156:156 + primary[156]])
        pending = [("", root)]
        seen_directories = set()
        seen_paths = set()
        files = []
        directories = []
        while pending:
            prefix, directory = pending.pop()
            key = (directory["offset"], directory["size"])
            if key in seen_directories:
                raise ValueError("Directory cycle or alias")
            seen_directories.add(key)
            if directory["size"] > 64 * 1024 * 1024:
                raise ValueError("Directory exceeds safety limit")
            raw = _read(stream, directory["offset"], directory["size"], volume_bytes)
            pos = 0
            while pos < len(raw):
                length = raw[pos]
                if not length:
                    pos = ((pos // SECTOR) + 1) * SECTOR
                    continue
                if pos % SECTOR + length > SECTOR or pos + length > len(raw):
                    raise ValueError("Directory record crosses a sector or directory boundary")
                entry = _record(raw[pos:pos + length])
                pos += length
                if not entry["name"]:
                    continue
                relative = prefix + entry.pop("name")
                if relative.casefold() in seen_paths:
                    raise ValueError("Duplicate or case-insensitive colliding ISO paths")
                seen_paths.add(relative.casefold())
                if len(seen_paths) > 1_000_000 or relative.count("/") > 128:
                    raise ValueError("ISO inventory exceeds safety limits")
                if entry["offset"] + entry["size"] > volume_bytes:
                    raise ValueError("Extent exceeds declared volume")
                if entry.pop("directory"):
                    directories.append(relative)
                    pending.append((relative + "/", entry))
                else:
                    entry["path"] = relative
                    if hash_files:
                        entry["sha256"] = _digest(stream, entry["offset"], entry["size"])
                    entry["header_hex"] = _read(stream, entry["offset"], min(entry["size"], 32), volume_bytes).hex()
                    files.append(entry)
        files.sort(key=lambda row: row["path"])
        system_id = primary[8:40].decode("ascii").strip()
        boot = None
        config = next((entry for entry in files if entry["path"].upper() == "SYSTEM.CNF"), None)
        if config:
            text = _read(stream, config["offset"], min(config["size"], 65536), volume_bytes).decode("ascii", "replace")
            match = re.search(r"(?im)^\s*(BOOT2|BOOT)\s*=\s*cdrom[0-9]*:\\?([^\r\n;]+)", text)
            if match:
                boot = match.group(2).replace("\\", "/").strip().lstrip("/")
                platform = "PlayStation 2" if match.group(1).upper() == "BOOT2" else "PlayStation"
            else:
                platform = "PlayStation family (boot unresolved)"
        else:
            platform = "unknown"
        return {"format": "ISO9660", "sector_bytes": SECTOR, "image_bytes": size,
                "image_sha256": _digest(stream, 0, size), "volume_bytes": volume_bytes,
                "system_id": system_id, "platform": platform, "boot_executable": boot,
                "files": files, "directories": sorted(directories),
                "file_count": len(files), "file_bytes": sum(row["size"] for row in files),
                "limits": ["Primary ISO9660 namespace only; Joliet and Rock Ridge metadata are not decoded.",
                           "Unrecognized contents remain opaque files; extraction is not source reconstruction."]}


def _target(root: Path, relative: str) -> Path:
    parts = PurePosixPath(relative).parts
    if not parts or PurePosixPath(relative).is_absolute():
        raise ValueError("Unsafe extraction path")
    for part in parts:
        _component(part)
    target = root.joinpath(*parts)
    if not target.resolve().is_relative_to(root):
        raise ValueError("Extraction path leaves destination")
    for node in [root, *target.parents, target]:
        if node.is_symlink() or (hasattr(node, "is_junction") and node.is_junction()):
            raise ValueError("Symlinks and junctions are forbidden in extraction paths")
    return target


def extract(image: str | Path, destination: str | Path, manifest: dict | None = None) -> dict:
    """Extract exactly the verified files; existing nonidentical targets are never overwritten."""
    image = Path(image).resolve(strict=True)
    manifest = manifest or analyze(image)
    destination = Path(destination).absolute()
    if destination.is_symlink() or (hasattr(destination, "is_junction") and destination.is_junction()):
        raise ValueError("Destination cannot be a link")
    destination = destination.resolve()
    size = image.stat().st_size
    with image.open("rb") as stream:
        if size != manifest["image_bytes"] or _digest(stream, 0, size) != manifest["image_sha256"]:
            raise ValueError("Source image differs from inventory")
        seen = set()
        written = reused = 0
        for entry in manifest["files"]:
            relative, offset, length = entry["path"], entry["offset"], entry["size"]
            if relative.casefold() in seen or not isinstance(offset, int) or not isinstance(length, int) or offset < 0 or length < 0 or offset + length > size:
                raise ValueError("Invalid or duplicate manifest extent")
            seen.add(relative.casefold())
            expected = entry.get("sha256")
            if not expected:
                expected = _digest(stream, offset, length)
            target = _target(destination, relative)
            if target.exists():
                with target.open("rb") as existing:
                    if target.stat().st_size != length or _digest(existing, 0, length) != expected:
                        raise FileExistsError(f"Nonidentical extraction target: {target}")
                reused += 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(target.name + "." + uuid.uuid4().hex + ".part")
            try:
                stream.seek(offset)
                remaining = length
                with temporary.open("xb") as output:
                    digest = hashlib.sha256()
                    while remaining:
                        data = stream.read(min(CHUNK, remaining))
                        if not data:
                            raise ValueError("Source truncated during extraction")
                        output.write(data)
                        digest.update(data)
                        remaining -= len(data)
                if digest.hexdigest() != expected:
                    raise ValueError("Extracted file hash mismatch")
                with temporary.open("rb") as check:
                    if _digest(check, 0, length) != expected:
                        raise ValueError("Written file hash mismatch")
                temporary.rename(target)
                written += 1
            finally:
                if temporary.exists():
                    temporary.unlink()
        if _digest(stream, 0, size) != manifest["image_sha256"]:
            raise ValueError("Source image changed during extraction")
    return {"files_written": written, "files_reused": reused,
            "files_verified": written + reused, "bytes": manifest["file_bytes"],
            "image_sha256": manifest["image_sha256"], "source_unchanged": True,
            "all_written_files_sha256_verified": True}
