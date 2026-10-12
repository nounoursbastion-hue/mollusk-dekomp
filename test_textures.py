import struct
import unittest

from textures import decode_tim2


def tim2(raw, palette, kind, clut_type, colors, width, height):
    file = struct.pack("<4sBBH8x", b"TIM2", 4, 0, 1)
    psm = {3: 0, 4: 20, 5: 19}[kind]
    header = struct.pack("<IIIHH4BHHQQII", 48 + len(raw) + len(palette), len(palette), len(raw), 48,
                         colors, 0, 1, clut_type, kind, width, height, psm << 20, 0, 0, 0)
    return file + header + raw + palette


class TextureTests(unittest.TestCase):
    def test_rgba32_alpha(self):
        image, metadata = decode_tim2(tim2(bytes((1, 2, 3, 128)), b"", 3, 0, 0, 1, 1))
        self.assertEqual(image.getpixel((0, 0)), (1, 2, 3, 255))
        self.assertFalse(metadata["runtime_fidelity_verified"])

    def test_index4_16bit_palette(self):
        palette = struct.pack("<16H", 0x801f, 0x83e0, *([0] * 14))
        image, _ = decode_tim2(tim2(bytes((0x10,)), palette, 4, 1, 16, 2, 1))
        self.assertEqual(image.getpixel((0, 0)), (255, 0, 0, 255))
        self.assertEqual(image.getpixel((1, 0)), (0, 255, 0, 255))

    def test_index8_palette_order(self):
        palette = bytes(value for index in range(256) for value in (index, 0, 0, 128))
        image, _ = decode_tim2(tim2(bytes((8, 16)), palette, 5, 3, 256, 2, 1))
        self.assertEqual(image.getpixel((0, 0))[0], 16)
        self.assertEqual(image.getpixel((1, 0))[0], 8)

    def test_rejects_mipmaps_and_truncation(self):
        data = bytearray(tim2(bytes((1, 2, 3, 128)), b"", 3, 0, 0, 1, 1))
        data[33] = 4
        with self.assertRaises(ValueError):
            decode_tim2(data)
        data[33] = 1
        with self.assertRaises(ValueError):
            decode_tim2(data[:-1])


if __name__ == "__main__":
    unittest.main()
