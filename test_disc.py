import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("disc", Path(__file__).with_name("disc.py"))
disc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(disc)


def both(value, width):
    return value.to_bytes(width, "little") + value.to_bytes(width, "big")


def record(name, sector, size, directory=False):
    name = name if isinstance(name, bytes) else name.encode("ascii")
    data = bytearray(33 + len(name) + (len(name) % 2 == 0))
    data[0] = len(data)
    data[2:10] = both(sector, 4)
    data[10:18] = both(size, 4)
    data[25] = 2 if directory else 0
    data[28:32] = both(1, 2)
    data[32] = len(name)
    data[33:33 + len(name)] = name
    return data


def fixture():
    image = bytearray(24 * 2048)
    pvd = memoryview(image)[16 * 2048:17 * 2048]
    pvd[:7] = b"\x01CD001\x01"
    pvd[8:40] = b"PLAYSTATION".ljust(32)
    pvd[80:88] = both(24, 4)
    pvd[128:132] = both(2048, 2)
    root = record(b"\x00", 20, 2048, True)
    pvd[156:156 + len(root)] = root
    image[17 * 2048:17 * 2048 + 7] = b"\xffCD001\x01"
    config = b"BOOT2 = cdrom0:\\SLES_000.00;1\r\n"
    executable = b"\x7fELF" + bytes(range(64))
    listing = root + record(b"\x01", 20, 2048, True)
    listing += record("SYSTEM.CNF;1", 21, len(config))
    listing += record("SLES_000.00;1", 22, len(executable))
    image[20 * 2048:20 * 2048 + len(listing)] = listing
    image[21 * 2048:21 * 2048 + len(config)] = config
    image[22 * 2048:22 * 2048 + len(executable)] = executable
    return image


class DiscTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name)
        self.image = self.root / "disc.iso"
        self.image.write_bytes(fixture())

    def tearDown(self):
        self.temp.cleanup()

    def test_inventory_extract_and_idempotence(self):
        manifest = disc.analyze(self.image)
        self.assertEqual(manifest["file_count"], 2)
        self.assertEqual(manifest["platform"], "PlayStation 2")
        self.assertEqual(manifest["boot_executable"], "SLES_000.00")
        result = disc.extract(self.image, self.root / "out", manifest)
        self.assertEqual(result["files_written"], 2)
        self.assertTrue(result["source_unchanged"])
        self.assertEqual(disc.extract(self.image, self.root / "out", manifest)["files_reused"], 2)
        (self.root / "out/SYSTEM.CNF").write_bytes(b"wrong")
        with self.assertRaises(FileExistsError):
            disc.extract(self.image, self.root / "out", manifest)

    def test_traversal_rejected(self):
        manifest = disc.analyze(self.image)
        manifest["files"][0]["path"] = "../escape"
        with self.assertRaises(ValueError):
            disc.extract(self.image, self.root / "out", manifest)
        self.assertFalse((self.root / "escape").exists())

    def test_source_change_and_invalid_extent_rejected(self):
        manifest = disc.analyze(self.image)
        manifest["files"][0]["offset"] = manifest["image_bytes"]
        with self.assertRaises(ValueError):
            disc.extract(self.image, self.root / "out", manifest)
        manifest = disc.analyze(self.image)
        self.image.write_bytes(self.image.read_bytes()[:-1])
        with self.assertRaises(ValueError):
            disc.extract(self.image, self.root / "out", manifest)

    def test_bad_endian_and_directory_cycles_rejected(self):
        raw = fixture()
        raw[16 * 2048 + 80] ^= 1
        self.image.write_bytes(raw)
        with self.assertRaises(ValueError):
            disc.analyze(self.image)
        raw = fixture()
        cycle = record("LOOP", 20, 2048, True)
        raw[20 * 2048 + 400:20 * 2048 + 400 + len(cycle)] = cycle
        # Replace the unused bytes directly after the original directory records.
        pos = 20 * 2048
        while raw[pos]:
            pos += raw[pos]
        raw[pos:pos + len(cycle)] = cycle
        self.image.write_bytes(raw)
        with self.assertRaises(ValueError):
            disc.analyze(self.image)


if __name__ == "__main__":
    unittest.main()
