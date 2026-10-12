"""Strict TIM2 base-level previews, with no guessed GS pixel unswizzling.

Header/color layout reference: https://github.com/polymood/tim2dump
CSM1 palette order reference: https://github.com/leeao/PS2Textures
"""
import hashlib
import json
from pathlib import Path
import struct


def colors(data, kind):
    if kind == 1:
        output = []
        for (value,) in struct.iter_unpack("<H", data):
            rgb = [(value >> shift) & 31 for shift in (0, 5, 10)]
            output.append(tuple((v << 3) | (v >> 2) for v in rgb) + (255 if value & 32768 else 0,))
        return output
    if kind == 3:
        return [(r, g, b, min(255, (a * 255 + 64) // 128))
                for r, g, b, a in struct.iter_unpack("4B", data)]
    raise ValueError("Unsupported TIM2 color format")


def decode_tim2(data):
    from PIL import Image
    if len(data) < 64 or data[:4] != b"TIM2":
        raise ValueError("Not a complete TIM2 header")
    if data[4] != 4 or data[5] != 0 or struct.unpack_from("<H", data, 6)[0] != 1:
        raise ValueError("Only TIM2 v4, 16-byte alignment, single-picture layout is supported")
    total, clut_size, image_size, header_size, clut_colors, picture_format, mipmaps, clut_type, image_type, width, height = struct.unpack_from("<IIIHH4BHH", data, 16)
    if picture_format != 0 or mipmaps != 1 or header_size != 48:
        raise ValueError("Extended, compound or mipmapped TIM2 is preserved without preview")
    if not (0 < width <= 2048 and 0 < height <= 2048):
        raise ValueError("TIM2 dimensions outside preview bounds")
    if total != header_size + image_size + clut_size or 16 + total != len(data):
        raise ValueError("TIM2 picture sizes do not match file bounds")
    gs_tex0 = struct.unpack_from("<Q", data, 40)[0]
    psm, csm, csa = (gs_tex0 >> 20) & 63, (gs_tex0 >> 55) & 1, (gs_tex0 >> 56) & 31
    if image_type not in (3, 4, 5) or psm != {3: 0, 4: 20, 5: 19}[image_type]:
        raise ValueError("Unsupported GS pixel storage; no guessed unswizzling")
    pixels = width * height
    raw = data[64:64 + image_size]
    if image_type == 3:
        if clut_size or image_size != pixels * 4:
            raise ValueError("Invalid RGBA32 TIM2 data size")
        rgba = colors(raw, 3)
    else:
        required_colors = 16 if image_type == 4 else 256
        if clut_type not in (1, 3) or csm != 0 or csa != 0 or clut_colors != required_colors:
            raise ValueError("Unsupported TIM2 CLUT layout")
        expected_size = (pixels + 1) // 2 if image_type == 4 else pixels
        if image_size != expected_size:
            raise ValueError("TIM2 index data size mismatch")
        color_bytes = {1: 2, 3: 4}[clut_type]
        if clut_size != required_colors * color_bytes:
            raise ValueError("TIM2 CLUT data size mismatch")
        palette = colors(data[64 + image_size:], clut_type)
        if image_type == 5:
            # Standard CSM1 interchanges bits 3 and 4 within each 32-color block.
            palette = [palette[(i & 231) | ((i & 8) << 1) | ((i & 16) >> 1)] for i in range(256)]
            indices = raw
        else:
            indices = [index for value in raw for index in (value & 15, value >> 4)][:pixels]
        rgba = [palette[index] for index in indices]
    image = Image.new("RGBA", (width, height))
    image.putdata(rgba)
    return image, {"width": width, "height": height, "image_type": image_type,
                   "clut_type": clut_type, "mipmap": 0, "gs_psm": psm,
                   "runtime_fidelity_verified": False}


def run_texture_previews(root, out):
    from PIL import Image
    root, out = Path(root).resolve(), Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    converted = unsupported = 0
    cache = {}
    mapping = out / "preview-map-private.jsonl"
    with mapping.with_suffix(".partial").open("w", encoding="utf-8") as report:
        for path in sorted(root.rglob("*.TM2")):
            if path.is_symlink() or path.is_junction() or not path.resolve().is_relative_to(root):
                raise ValueError("Texture path escapes resource root")
            row = {"path": path.relative_to(root).as_posix()}
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest not in cache:
                try:
                    image, metadata = decode_tim2(data)
                    target = out / ("texture-" + digest + ".png")
                    if target.exists():
                        with Image.open(target) as existing:
                            if existing.convert("RGBA").tobytes() != image.tobytes():
                                raise ValueError("Existing PNG differs from decoded pixels")
                    else:
                        image.save(target)
                    with Image.open(target) as verify:
                        verify.load()
                        if verify.size != image.size or verify.convert("RGBA").tobytes() != image.tobytes():
                            raise ValueError("PNG roundtrip verification failed")
                    cache[digest] = {"status": "preview_pixels_roundtrip_verified",
                                     "preview": target.name, **metadata}
                except (ValueError, OSError) as exc:
                    cache[digest] = {"status": "unsupported_preserved", "reason": str(exc)}
            row.update(cache[digest])
            row["source_sha256"] = digest
            converted += row["status"] == "preview_pixels_roundtrip_verified"
            unsupported += row["status"] == "unsupported_preserved"
            report.write(json.dumps(row) + "\n")
    mapping.with_suffix(".partial").replace(mapping)
    summary = {"textures": converted + unsupported, "converted_entries": converted,
               "unsupported_entries": unsupported,
               "unique_pngs": sum(row["status"] == "preview_pixels_roundtrip_verified" for row in cache.values()),
               "mapping": str(mapping), "runtime_fidelity_verified": False,
               "limits": ["Single picture, base mip only, no guessed GS pixel unswizzling.",
                          "Palette color/alpha is a standard preview interpretation; in-game appearance is not compared.",
                          "Mipmapped, extended or other GS storage layouts remain untouched."]}
    (out / "texture-preview-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary
