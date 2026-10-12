import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import extract_pc


class PcCopyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name)
        self.source = self.root / "game"
        self.source.mkdir()
        (self.source / "nested").mkdir()
        (self.source / "game.exe").write_bytes(b"MZ-fixture")
        (self.source / "nested/data.bin").write_bytes(bytes(range(256)) * 100)
        (self.source / "empty.dat").write_bytes(b"")
        self.out = self.root / "job/raw"

    def tearDown(self):
        self.temp.cleanup()

    def test_complete_hashes_and_resume(self):
        initial = {p.relative_to(self.source): p.read_bytes() for p in self.source.rglob("*") if p.is_file()}
        result = extract_pc.copy_game(self.source, self.out)
        self.assertEqual(result["files_copied"], 3)
        self.assertTrue(result["all_files_verified"])
        self.assertTrue(result["source_unchanged"])
        for row in map(json.loads, Path(result["manifest"]).read_text(encoding="utf8").splitlines()):
            data = (self.out / row["path"]).read_bytes()
            self.assertEqual(row["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(data, initial[Path(row["path"])])
        replay = extract_pc.copy_game(self.source, self.out)
        self.assertEqual(replay["files_reused"], 3)
        self.assertEqual(replay["files_copied"], 0)
        self.assertTrue(replay["all_files_verified"])
        self.assertEqual(result["source_tree_sha256"], replay["source_tree_sha256"])

    def test_collision_is_preserved_and_other_files_continue(self):
        self.out.mkdir(parents=True)
        target = self.out / "game.exe"
        target.write_bytes(b"wrong-but-same-size")
        result = extract_pc.copy_game(self.source, self.out)
        self.assertEqual(result["status"], "partial")
        self.assertIsNone(result["source_tree_sha256"])
        self.assertFalse(result["all_files_verified"])
        self.assertEqual(result["files_copied"], 2)
        self.assertEqual(target.read_bytes(), b"wrong-but-same-size")

    def test_nonoverlapping_paths_required(self):
        for output in [self.source, self.source / "output", self.root]:
            with self.assertRaises(ValueError):
                extract_pc.copy_game(self.source, output)

    def test_insufficient_space_prevents_payload_writes(self):
        with patch.object(extract_pc.shutil, "disk_usage", return_value=type("Usage", (), {"free": 0})()):
            with self.assertRaises(OSError):
                extract_pc.copy_game(self.source, self.out)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_source_mutation_is_reported_and_partials_cleaned(self):
        original_hash = extract_pc._hash
        changed = False
        def changing_hash(path, size):
            nonlocal changed
            result = original_hash(path, size)
            if not changed and ".part" in path.name:
                victim = self.source / "game.exe"
                victim.write_bytes(b"changed")
                stamp = victim.stat().st_mtime_ns + 1000000000
                os.utime(victim, ns=(stamp, stamp))
                changed = True
            return result
        with patch.object(extract_pc, "_hash", side_effect=changing_hash):
            result = extract_pc.copy_game(self.source, self.out)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["source_unchanged"])
        self.assertFalse(list(self.root.rglob("*.part")))

    def test_skipped_link_directory_and_unexpected_raw_files_make_copy_partial(self):
        original = extract_pc._linked
        with patch.object(extract_pc, "_linked", side_effect=lambda node: node.name == "nested" or original(node)):
            result = extract_pc.copy_game(self.source, self.out)
        self.assertFalse(result["all_files_verified"])
        self.assertFalse((self.out / "nested/data.bin").exists())
        (self.out / "obsolete.bin").write_bytes(b"old")
        result = extract_pc.copy_game(self.source, self.out)
        self.assertTrue(any("Unexpected existing RAW" in row["error"] for row in result["errors"]))
        self.assertEqual((self.out / "obsolete.bin").read_bytes(), b"old")


if __name__ == "__main__":
    unittest.main()
