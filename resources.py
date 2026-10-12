"""Read-only resource inventory. Signatures and lexical hints are not decoding."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re


SIGNATURES = (
    (b"\x7fELF", "ELF", "executable"),
    (b"\x89PNG\r\n\x1a\n", "PNG", "image"),
    (b"\xff\xd8\xff", "JPEG", "image"),
    (b"DDS ", "DDS", "texture"),
    (b"TIM2", "TIM2", "texture"),
    (b"PAK1", "PAK1", "container"),
    (b"VAGp", "VAG", "audio"),
    (b"SShd", "SSHD", "audio"),
    (b"OggS", "Ogg", "audio"),
    (b"fLaC", "FLAC", "audio"),
    (b"\x00\x00\x01\xba", "MPEG program stream", "video"),
    (b"PK\x03\x04", "ZIP", "container"),
    (b"\x1f\x8b\x08", "gzip", "container"),
)
HINTS = {
    ".pss": "video", ".mpg": "video", ".m2v": "video",
    ".vag": "audio", ".ads": "audio", ".ss2": "audio",
    ".bnk": "audio-bank", ".wav": "audio", ".mib": "audio",
    ".tm2": "texture", ".tim2": "texture", ".tex": "texture",
    ".irx": "console-module", ".elf": "executable", ".cnf": "configuration",
    ".pak": "container", ".arc": "container", ".bin": "opaque-binary",
    ".wad": "container", ".dat": "opaque-binary",
    ".anm": "animation", ".sam": "animation", ".bns": "skeleton",
    ".psq": "model", ".psw": "model", ".mph": "model",
    ".mic": "audio", ".msb": "audio-bank", ".cmh": "audio-bank",
    ".hmp": "terrain", ".col": "collision", ".ent": "entities",
}
TOKENS = {
    "texture": re.compile(r"texture|\.tm2\b|\.tim2\b|\.dds\b", re.I),
    "animation": re.compile(r"anim(?:ation)?|skeleton|bone", re.I),
    "model": re.compile(r"mesh|vertex|model", re.I),
    "audio": re.compile(r"sound|audio|music|\.vag\b", re.I),
    "script": re.compile(r"script|\.lua\b", re.I),
}


def classify(head, extension, size):
    observed = []
    for magic, name, category in SIGNATURES:
        if head.startswith(magic):
            observed.append({"format": name, "category": category,
                             "evidence": "header_signature", "decoded": False})
    if len(head) >= 12 and head[:4] == b"RIFF":
        subtype = head[8:12].decode("ascii", "replace")
        observed.append({"format": "RIFF", "subtype": subtype,
                         "category": "audio" if subtype == "WAVE" else "container",
                         "declared_bytes": int.from_bytes(head[4:8], "little") + 8,
                         "declared_size_matches": int.from_bytes(head[4:8], "little") + 8 == size,
                         "evidence": "header_signature", "decoded": False})
    return observed, HINTS.get(extension.lower())


def scan_file(path, root):
    """Hash every byte; collect at most 128 printable strings and signature offsets."""
    sha = hashlib.sha256()
    before = path.stat()
    samples, string_count, hints = [], 0, Counter()
    signatures = {name: {"count": 0, "first_offsets": []}
                  for magic, name, category in SIGNATURES}
    # shortcut: bounded samples do not identify an asset's exact appearance or purpose.
    carry, text_carry, offset, head = b"", b"", 0, b""
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            if not head:
                head = block[:4096]
            sha.update(block)
            joined = carry + block
            base = offset - len(carry)
            for magic, name, category in SIGNATURES:
                start = 0
                while (pos := joined.find(magic, start)) >= 0:
                    absolute = base + pos
                    if absolute + len(magic) > offset:
                        entry = signatures[name]
                        entry["count"] += 1
                        if len(entry["first_offsets"]) < 16:
                            entry["first_offsets"].append(absolute)
                    start = pos + 1
            carry = joined[-16:]
            text = text_carry + block
            matches = list(re.finditer(rb"[\x20-\x7e]{6,}", text))
            text_carry = b""
            for match in matches:
                if match.end() == len(text):
                    text_carry = match.group()[-512:]
                    continue
                value = match.group()[:512].decode("ascii")
                string_count += 1
                if len(samples) < 128:
                    samples.append({"offset": offset - (len(text) - len(block)) + match.start(),
                                    "value": value})
                for name, pattern in TOKENS.items():
                    if pattern.search(value):
                        hints[name] += 1
            offset += len(block)
    if len(text_carry) >= 6:
        string_count += 1
        value = text_carry.decode("ascii")
        if len(samples) < 128:
            samples.append({"offset": offset - len(text_carry), "value": value})
        for name, pattern in TOKENS.items():
            if pattern.search(value):
                hints[name] += 1
    after = path.stat()
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise RuntimeError(f"File changed during read: {path}")
    observed, extension_hint = classify(head, path.suffix, offset)
    return {"path": path.relative_to(root).as_posix(), "bytes": offset,
            "sha256": sha.hexdigest(), "extension": path.suffix.lower(),
            "header_hex": head[:32].hex(), "observed_formats": observed,
            "extension_category_hint": extension_hint,
            "classification_status": "signature_observed" if observed else "opaque",
            "embedded_signature_candidates": {k: v for k, v in signatures.items() if v["count"]},
            "printable_ascii_runs": string_count, "string_samples_private": samples,
            "lexical_hints": dict(hints), "semantic_function_verified": False,
            "assets_decoded": False,
            "limits": ["Embedded signatures can occur by chance; no embedded objects carved.",
                       "Strings and extensions are hints, not verified gameplay semantics.",
                       "Strings longer than 512 bytes are sampled; no original source recovered."]}


def run_resources(root, out):
    root, out = Path(root).resolve(), Path(out).resolve()
    if not root.is_dir():
        raise ValueError("Extracted resource root must be a directory")
    if out == root or out.is_relative_to(root):
        raise ValueError("Output must be outside extracted resources")
    out.mkdir(parents=True, exist_ok=True)
    counts, extensions, hints, errors = Counter(), Counter(), Counter(), []
    total = total_bytes = 0
    from pak import extract_paks
    archives = extract_paks(root, out / "archives") if any(root.rglob("*.PAK")) else None
    inventory = out / "resources-private.jsonl"
    temporary = inventory.with_suffix(".jsonl.partial")
    with temporary.open("w", encoding="utf-8") as target:
        roots = [("disc", root)]
        if archives:
            roots.append(("pak", Path(archives["files_root"])))
        for area, source_root in roots:
            for path in iter_resource_files(source_root, errors):
                if path.is_symlink() or path.is_junction() or not path.resolve().is_relative_to(source_root):
                    errors.append({"path": path.relative_to(source_root).as_posix(), "error": "Link or escaped path skipped"})
                    continue
                if not path.is_file():
                    continue
                try:
                    row = scan_file(path, source_root)
                    row["source_area"] = area
                    target.write(json.dumps(row, ensure_ascii=False) + "\n")
                    total += 1
                    total_bytes += row["bytes"]
                    extensions[row["extension"] or "(none)"] += 1
                    counts[row["classification_status"]] += 1
                    hints.update(row["lexical_hints"])
                except (OSError, RuntimeError) as exc:
                    errors.append({"path": path.relative_to(source_root).as_posix(), "error": str(exc)})
    temporary.replace(inventory)
    previews = None
    if archives:
        from textures import run_texture_previews
        previews = run_texture_previews(Path(archives["files_root"]), out / "previews")
    report = {"files": total, "bytes": total_bytes, "archives": archives, "classification": dict(counts),
              "extensions": dict(extensions), "lexical_hints": dict(hints), "errors": errors,
              "all_files_hashed": not errors, "assets_decoded": previews["converted_entries"] if previews else 0,
              "texture_previews": previews,
              "status": "complete_inventory" if not errors else "partial_inventory",
              "limits": ["Inventory classification does not verify an asset's exact meaning.",
                         "Unknown resource formats remain opaque.",
                         "Private inventory retains source paths and printable samples."]}
    (out / "resource-summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def iter_resource_files(root, errors):
    """Avoid following Windows junctions as well as normal symbolic links."""
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in list(dirs):
            path = Path(folder) / name
            if path.is_symlink() or path.is_junction() or not path.resolve().is_relative_to(root):
                dirs.remove(name)
                errors.append({"path": path.relative_to(root).as_posix(), "error": "Link directory skipped"})
        dirs.sort()
        for name in sorted(files):
            yield Path(folder) / name
