"""Small pipeline regression checks; native analysis is mocked, never executed."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import struct
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import mollusk_dekomp as app
from test_disc import fixture, record


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name)
        self.image = self.root / "disc.iso"
        self.image.write_bytes(fixture())
        self.out = self.root / "results"
        self.calls = []
        self.fake_native = types.SimpleNamespace(analyze_native=self.native)
        self.fake_resources = types.SimpleNamespace(run_resources=lambda root, out: {"files": 2, "assets_decoded": 0, "errors": []})
        self.fake_report = types.SimpleNamespace(render=lambda out, state: (out / "MolluskDekomP.html").write_text("<html>test</html>", encoding="utf8"))
        self.modules = patch.dict(sys.modules, native=self.fake_native, resources=self.fake_resources, report=self.fake_report)
        self.modules.start()

    def tearDown(self):
        self.modules.stop()
        self.temp.cleanup()

    def native(self, executable, out, **options):
        self.calls.append(str(executable))
        out.mkdir(parents=True, exist_ok=True)
        report = out / "native-report.json"
        if report.exists():
            raise FileExistsError("Existing native report")
        data = {"status": "metadata_only", "reason": "Ghidra execution disabled by caller",
                "input_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                "input_unchanged": True, "analysis_timeout_seconds": options["analysis_timeout"],
                "function_timeout_seconds": options["function_timeout"], "export_timeout_seconds": 1800,
                "original_source_recovered": False, "standalone": False}
        report.write_text(json.dumps(data), encoding="utf8")
        return data

    def test_source_inside_output_rejected(self):
        with self.assertRaises(ValueError):
            app.destination(self.image, self.root)

    def test_output_assigned_to_another_source_rejected(self):
        self.out.mkdir()
        (self.out / "run-private.json").write_text(json.dumps({"source": "another.iso"}), encoding="utf8")
        with self.assertRaises(ValueError):
            app.run(self.image, self.out, run_ghidra=False, progress=lambda _: None)

    def test_inspect_does_not_extract_or_analyze_native(self):
        result = app.run(self.image, self.out, inspect_only=True, progress=lambda _: None)
        self.assertEqual(result["disc"]["file_count"], 2)
        self.assertFalse((self.out / "extracted").exists())
        self.assertEqual(self.calls, [])

    def test_completed_output_can_be_run_again(self):
        raw = fixture()
        executable = bytearray(68)
        executable[:16] = b"\x7fELF\x01\x01\x01" + bytes(9)
        struct.pack_into("<HHIIIIIHHHHHH", executable, 16,
                         2, 8, 1, 0x100000, 0, 0, 0x20924000, 52, 0, 0, 0, 0, 0)
        raw[22 * 2048:22 * 2048 + 68] = executable
        self.image.write_bytes(raw)
        spec = importlib.util.spec_from_file_location("mollusk_native_real", Path(__file__).with_name("native.py"))
        real_native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(real_native)
        with patch.dict(sys.modules, native=real_native):
            first = app.run(self.image, self.out, run_ghidra=False, progress=lambda _: None)
            second = app.run(self.image, self.out, run_ghidra=False, progress=lambda _: None)
        self.assertEqual(first["disc"]["image_sha256"], second["disc"]["image_sha256"])
        self.assertEqual(second["extraction"]["files_reused"], 2)
        self.assertEqual(first["native"][0]["status"], "metadata_only")
        self.assertEqual(second["native"][0]["status"], "metadata_only")
        self.assertTrue(second["native"][0]["input_unchanged"])

    def test_native_failure_keeps_processing_other_executables(self):
        raw = fixture()
        pos = 20 * 2048
        while raw[pos]:
            pos += raw[pos]
        extra = record("SECOND.ELF;1", 23, 68)
        raw[pos:pos + len(extra)] = extra
        raw[23 * 2048:23 * 2048 + 68] = b"\x7fELF" + bytes(range(64))
        self.image.write_bytes(raw)
        def mixed(executable, out, **options):
            if executable.name == "SLES_000.00":
                self.calls.append(str(executable))
                raise ValueError("Unsupported executable detail")
            return self.native(executable, out, **options)
        self.fake_native.analyze_native = mixed
        result = app.run(self.image, self.out, run_ghidra=False, progress=lambda _: None)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(result["native"]), 2)
        self.assertTrue(any(row["status"] not in {"metadata_only", "completed"} for row in result["native"]))
        self.assertTrue((self.out / "MolluskDekomP.html").is_file())

    def test_report_escapes_resource_names_and_rejects_external_code_link(self):
        spec = importlib.util.spec_from_file_location("mollusk_report_real", Path(__file__).with_name("report.py"))
        report = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(report)
        (self.out / "resources").mkdir(parents=True)
        hostile = "</script><script>alert('unsafe')</script>"
        (self.out / "resources/resources-private.jsonl").write_text(json.dumps({
            "path": hostile, "bytes": 4, "classification_status": "signature_observed",
            "observed_formats": [{"format": "PNG", "category": "image"}]}) + "\n", encoding="utf8")
        (self.out / "native/module").mkdir(parents=True)
        outside = self.root / "outside.c"
        outside.write_text("outside", encoding="utf8")
        (self.out / "native/module/functions.tsv").write_text(
            "address\tname\tsignature\tbody_bytes\tstatus\tpseudocode\tdiagnostic\n"
            "1000\tunsafe\tvoid unsafe()\t4\tinferred_unvalidated\t../../../outside.c\t\n", encoding="utf8")
        report.render(self.out, {"status": hostile})
        page = (self.out / "MolluskDekomP.html").read_text(encoding="utf8")
        self.assertNotIn(hostile, page)
        self.assertEqual(page.count("<script>"), 1)
        payload = re.search(r"const data=(.*?);let page=", page).group(1)
        rows = json.loads(payload)
        self.assertTrue(any(row["name"] == hostile for row in rows))
        self.assertFalse(any(row.get("uri") == outside.as_uri() for row in rows))


if __name__ == "__main__":
    unittest.main()
