import json
from pathlib import Path
import struct
import tempfile
import unittest
from native import inspect_elf, inspect_pe, analyze_native


def elf():
    data = bytearray(88)
    data[:16] = b'\x7fELF\x01\x01\x01' + b'\0' * 9
    struct.pack_into('<HHIIIIIHHHHHH', data, 16, 2, 8, 1, 0x100000, 52, 0, 0, 52, 32, 1, 40, 0, 0)
    struct.pack_into('<IIIIIIII', data, 52, 1, 84, 0x100000, 0x100000, 4, 4, 5, 4)
    struct.pack_into('<I', data, 84, 28 << 26)
    return data


class NativeTests(unittest.TestCase):
    def test_pe_metadata_and_bounds(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'game.exe'
            data = bytearray(512)
            data[:2] = b'MZ'
            struct.pack_into('<I', data, 60, 64)
            data[64:68] = b'PE\0\0'
            struct.pack_into('<HHIIIHH', data, 68, 0x8664, 1, 0, 0, 0, 112, 0)
            struct.pack_into('<H', data, 88, 0x20b)
            struct.pack_into('<I', data, 104, 0x1000)
            struct.pack_into('<Q', data, 112, 0x140000000)
            struct.pack_into('<8sIIIIIIHHI', data, 200, b'.text\0\0\0', 4, 0x1000, 4, 508, 0, 0, 0, 0, 0x60000020)
            source.write_bytes(data)
            self.assertEqual(inspect_pe(source)['ghidra_language'], 'x86:LE:64:default')
            self.assertEqual(analyze_native(source, Path(folder) / 'out', run_ghidra=False)['metadata'], 'pe-metadata.json')
            struct.pack_into('<I', data, 220, 1000)
            source.write_bytes(data)
            with self.assertRaises(ValueError):
                inspect_pe(source)

    def test_metadata_and_no_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'main.elf'
            source.write_bytes(elf())
            info = inspect_elf(source)
            self.assertEqual(info['ps2_extension_opcode_candidates']['MMI'], 1)
            self.assertEqual(info['ghidra_language'], 'MIPS:LE:64:64-32addr')
            report = analyze_native(source, Path(folder) / 'out', run_ghidra=False)
            self.assertEqual(report['status'], 'metadata_only')
            self.assertTrue(report['input_unchanged'])
            self.assertFalse(report['original_source_recovered'])
            self.assertEqual(analyze_native(source, Path(folder) / 'out', run_ghidra=False)['status'], 'metadata_only')

    def test_iop_and_r5900_distinction(self):
        with tempfile.TemporaryDirectory() as folder:
            data = elf()
            struct.pack_into('<I', data, 36, 0x20924000)
            source = Path(folder) / 'boot.elf'
            source.write_bytes(data)
            self.assertEqual(inspect_elf(source)['ghidra_language'], 'r5900:LE:32:default')
            iop = Path(folder) / 'sound.irx'
            iop.write_bytes(data)
            self.assertEqual(inspect_elf(iop)['ghidra_language'], 'MIPS:LE:32:default')

    def test_cache_requires_existing_pseudocode(self):
        with tempfile.TemporaryDirectory() as folder:
            source, out = Path(folder) / 'boot.elf', Path(folder) / 'out'
            source.write_bytes(elf())
            report = analyze_native(source, out, run_ghidra=False)
            report.update(status='pseudocode_partial', ghidra={'all_recognized_functions_processed': True, 'processed_functions': 1})
            (out / 'native-report.json').write_text(json.dumps(report), encoding='utf-8')
            (out / 'ghidra-summary.json').write_text('{}', encoding='utf-8')
            (out / 'functions.tsv').write_text('address\tpseudocode\n100000\tf_100000.c\n', encoding='utf-8')
            (out / 'f_100000.c').write_text('void f(void) {}', encoding='utf-8')
            self.assertEqual(analyze_native(source, out, run_ghidra=False)['status'], 'pseudocode_partial')
            (out / 'f_100000.c').unlink()
            with self.assertRaises(FileExistsError):
                analyze_native(source, out, run_ghidra=False)

    def test_reject_bad_segment(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'bad.elf'
            data = elf()
            struct.pack_into('<I', data, 52 + 4, 1000)
            source.write_bytes(data)
            with self.assertRaises(ValueError):
                inspect_elf(source)


if __name__ == '__main__':
    unittest.main()
