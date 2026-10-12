import json
import os
from pathlib import Path
import tempfile
import struct
import unittest
from unittest.mock import patch

from organize import organize_exports, classify_export


class OrganizeTests(unittest.TestCase):
    def test_physical_categories_resume_and_opaque_formats(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            job = Path(folder)
            root = job / "analysis"
            root.mkdir()
            (root / "scene.unity").write_text("%YAML 1.1\n--- !u!1 &1\nGameObject: {}")
            (root / "main.cs").write_text("class Example {}")
            (root / "world.umap").write_bytes(b"\xc1\x83\x2a\x9eopaque")
            (root / "sound.wem").write_bytes(b"RIFF\x04\0\0\0WAVE")
            (root / "noise.log").write_text("log")
            out = job / "organized"
            report = organize_exports([root], out)
            self.assertEqual(report["files"], 4)
            self.assertEqual(report["categories"], {"Scripts": 1, "Maps": 1, "Non_decodes": 2})
            self.assertEqual(report["status"], "complete")
            rows = list(map(json.loads, (out / "organized-manifest-private.jsonl").read_text().splitlines()))
            self.assertTrue(all((out / r["organized_path"]).is_file() for r in rows))
            self.assertTrue(all(not r["runtime_validated"] for r in rows))
            self.assertEqual(organize_exports([root], out)["storage_methods"], {"existing_verified": 4})

    def test_copy_fallback_collision_and_mismatch(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            job = Path(folder)
            first, second = job / "one", job / "two"
            first.mkdir()
            second.mkdir()
            (first / "same.cs").write_text("first")
            (second / "same.cs").write_text("second")
            out = job / "organized"
            with patch.object(os, "link", side_effect=OSError("Fixture denies hardlinks")):
                report = organize_exports([first, second], out)
            self.assertEqual(report["files"], 2)
            self.assertEqual(report["storage_methods"], {"copy_verified": 2})
            rows = list(map(json.loads, (out / "organized-manifest-private.jsonl").read_text().splitlines()))
            self.assertNotEqual(rows[0]["organized_path"], rows[1]["organized_path"])
            target = out / rows[0]["organized_path"]
            target.write_text("changed")
            report = organize_exports([first, second], out)
            self.assertEqual(report["status"], "partial")
            self.assertEqual(target.read_text(), "changed")
            self.assertEqual((first / "same.cs").read_text(), "first")

    def test_rejects_external_install_and_skips_junction(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            job = Path(folder) / "job"
            job.mkdir()
            external = Path(folder) / "installed-game"
            external.mkdir()
            with self.assertRaises(ValueError):
                organize_exports([external], job / "organized")
            root = job / "analysis"
            root.mkdir()
            (root / "linked").mkdir()
            (root / "linked/hidden.cs").write_text("outside")
            with patch.object(Path, "is_junction", lambda path: path.name == "linked"):
                report = organize_exports([root], job / "organized")
            self.assertEqual(report["files"], 0)
            self.assertEqual(report["status"], "partial")

    def test_glb_structure_and_utf8_sample_boundary(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root = Path(folder)
            document = json.dumps({"asset": {"version": "2.0"}}).encode()
            document += b" " * (-len(document) % 4)
            path = root / "mesh.glb"
            path.write_bytes(struct.pack("<4sIIII", b"glTF", 2, 20 + len(document), len(document), 0x4E4F534A) + document)
            self.assertEqual(classify_export(path)["category"], "Models")
            path.write_bytes(struct.pack("<4sIIII", b"glTF", 2, 21, 1, 0x4E4F534A) + b"{")
            self.assertEqual(classify_export(path)["category"], "Non_decodes")
            text = root / "script.cs"
            text.write_bytes(b"x" * 4095 + "é".encode())
            self.assertEqual(classify_export(text)["category"], "Scripts")


if __name__ == "__main__":
    unittest.main()
