import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pc_inventory import inventory_game


class PcInventoryTests(unittest.TestCase):
    def test_bounded_headers_and_observed_vs_hinted(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root, out = Path(folder) / "game", Path(folder) / "out"
            root.mkdir()
            (root / "bundle.dat").write_bytes(b"UnityFS\0" + bytes(4096))
            (root / "guessed.pck").write_bytes(b"unknown")
            (root / "library.dll").write_bytes(b"MZ" + bytes(1024))
            report = inventory_game(root, out)
            self.assertEqual(report["files"], 3)
            self.assertEqual(report["inspected_bytes"], 64 + 7 + 64)
            self.assertFalse(report["all_files_hashed"])
            rows = {r["path"]: r for r in map(json.loads, (out / "pc-resources-private.jsonl").read_text().splitlines())}
            self.assertEqual(rows["bundle.dat"]["observed_formats"][0]["format"], "UnityFS")
            self.assertEqual(rows["guessed.pck"]["classification_status"], "opaque")
            self.assertEqual(rows["guessed.pck"]["extension_category_hint"], "godot-container")
            self.assertTrue(all(row["sha256"] is None for row in rows.values()))

    def test_read_error_and_junction_are_reported(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root, out = Path(folder) / "game", Path(folder) / "out"
            root.mkdir()
            (root / "blocked.bin").write_bytes(b"restricted")
            (root / "linked").mkdir()
            (root / "linked/hidden.bin").write_bytes(b"outside")
            original = Path.open

            def guarded(path, *args, **kwargs):
                if path.name == "blocked.bin":
                    raise PermissionError("Fixture denies reading")
                return original(path, *args, **kwargs)

            with patch.object(Path, "is_junction", lambda path: path.name == "linked"), patch.object(Path, "open", guarded):
                report = inventory_game(root, out)
            self.assertEqual(report["files"], 1)
            self.assertEqual(report["classification"], {"read_error": 1})
            self.assertEqual(report["status"], "partial_inventory")
            self.assertEqual(len(report["errors"]), 2)

    def test_rejects_output_inside_game(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            with self.assertRaises(ValueError):
                inventory_game(folder, Path(folder) / "output")

    def test_exported_area_and_invalid_area(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root, out = Path(folder) / "analysis", Path(folder) / "out"
            root.mkdir()
            (root / "class.cs").write_text("class Example {}")
            report = inventory_game(root, out, source_area="exported")
            row = json.loads((out / "pc-resources-private.jsonl").read_text())
            self.assertEqual(row["source_area"], "exported")
            self.assertEqual(report["source_area"], "exported")
            with self.assertRaises(ValueError):
                inventory_game(root, out, source_area="unknown")


if __name__ == "__main__":
    unittest.main()
