import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from resources import classify, run_resources, scan_file, iter_resource_files


class ResourceTests(unittest.TestCase):
    def test_signatures_do_not_claim_decoding(self):
        rows, hint = classify(b"TIM2" + bytes(20), ".dat", 24)
        self.assertEqual(rows[0]["format"], "TIM2")
        self.assertFalse(rows[0]["decoded"])
        self.assertEqual(hint, "opaque-binary")
        self.assertEqual(classify(b"no header", ".vag", 9)[0], [])

    def test_stream_boundary_and_hash(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root = Path(folder)
            data = bytes(1024 * 1024 - 2) + b"TIM2\x00test_texture.dds\x00"
            path = root / "a.dat"
            path.write_bytes(data)
            row = scan_file(path, root)
            self.assertEqual(row["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(row["embedded_signature_candidates"]["TIM2"]["first_offsets"], [1024 * 1024 - 2])
            self.assertEqual(row["embedded_signature_candidates"]["TIM2"]["count"], 1)
            self.assertEqual(row["classification_status"], "opaque")
            self.assertEqual(row["lexical_hints"]["texture"], 1)

    def test_inventory_outputs_and_rejects_nested_output(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root = Path(folder) / "input"
            root.mkdir()
            (root / "sound.vag").write_bytes(b"unknown")
            report = run_resources(root, Path(folder) / "out")
            self.assertEqual(report["files"], 1)
            self.assertEqual(report["assets_decoded"], 0)
            self.assertEqual(report["classification"], {"opaque": 1})
            row = json.loads((Path(folder) / "out/resources-private.jsonl").read_text())
            self.assertEqual(row["extension_category_hint"], "audio")
            with self.assertRaises(ValueError):
                run_resources(root, root / "out")

    def test_junction_directory_is_pruned(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root = Path(folder).resolve()
            (root / "linked").mkdir()
            (root / "linked/hidden.bin").write_bytes(b"outside")
            (root / "safe.bin").write_bytes(b"inside")
            errors = []
            with patch.object(Path, "is_junction", lambda path: path.name == "linked"):
                rows = list(iter_resource_files(root, errors))
            self.assertEqual([p.name for p in rows], ["safe.bin"])
            self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
