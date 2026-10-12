from pathlib import Path
import struct
import tempfile
import unittest

from pak import pak_entries, extract_paks


def fixture(names=("DATA\\FIRST.TXT", "DATA\\SECOND.TM2")):
    name_bytes = ("\0".join(names) + "\0").encode("utf-16le")
    names_size = 2048 - 16 - len(names) * 4
    table = struct.pack("<4sIII", b"PAK1", names_size // 2, len(names), 2048)
    table += name_bytes + bytes(names_size - len(name_bytes))
    table += struct.pack("<2I", 2051, 4100)
    return table + b"one" + bytes(2048 - 3) + b"TIM2"


class PakTests(unittest.TestCase):
    def test_extract_alignment_and_resume(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root = Path(folder) / "input"
            root.mkdir()
            source = root / "A.PAK"
            source.write_bytes(fixture())
            rows = pak_entries(source)
            self.assertEqual([r["offset"] for r in rows], [2048, 4096])
            self.assertEqual([r["size"] for r in rows], [3, 4])
            out = Path(folder) / "out"
            report = extract_paks(root, out)
            self.assertEqual(report["entries"], 2)
            self.assertEqual(next((out / "files").rglob("SECOND.TM2")).read_bytes(), b"TIM2")
            self.assertEqual(extract_paks(root, out)["bytes"], 7)
            next((out / "files").rglob("FIRST.TXT")).write_bytes(b"bad")
            with self.assertRaises(ValueError):
                extract_paks(root, out)

    def test_rejects_traversal_and_nonzero_padding(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            source = Path(folder) / "A.PAK"
            source.write_bytes(fixture(("..\\FIRST.TXT", "DATA\\SECOND.TM2")))
            with self.assertRaises(ValueError):
                pak_entries(source)
            data = bytearray(fixture())
            data[3000] = 1
            source.write_bytes(data)
            with self.assertRaises(ValueError):
                pak_entries(source)


if __name__ == "__main__":
    unittest.main()
