import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import engines


class EngineTests(unittest.TestCase):
    def test_mono_dispatch_arguments_and_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            game, out = Path(folder)/'game', Path(folder)/'out'
            managed = game/'Demo_Data/Managed'
            managed.mkdir(parents=True)
            dll = managed/'Assembly-CSharp.dll'
            dll.write_bytes(b'not-executed')
            tool = Path(folder)/'ilspy.exe'; tool.write_bytes(b'tool')
            calls = []
            def run(args, destination, label, timeout, env):
                calls.append(args)
                target = Path(args[args.index('-o')+1])
                (target/'Recovered.cs').write_text('class Recovered {}')
                return dict(stage=label, status='ok', exit_code=0)
            with patch.object(engines, '_run', side_effect=run):
                result = engines.analyze_game(game, out, tools={'ilspy': tool}, export_assets=False, progress=lambda _: None)
            self.assertEqual(result['engine'], 'unity-mono')
            self.assertEqual(result['status'], 'partial')
            self.assertIn('--disable-updatecheck', calls[0])
            self.assertEqual(calls[0][0], tool.resolve())
            self.assertEqual(calls[0][-1], str(dll.resolve()))
            self.assertTrue(result['tracked_inputs_unchanged'])
            self.assertFalse(result['original_source_recovered'])

    def test_il2cpp_failure_not_reported_as_source(self):
        with tempfile.TemporaryDirectory() as folder:
            game, out = Path(folder)/'game', Path(folder)/'out'
            metadata = game/'Demo_Data/il2cpp_data/Metadata/global-metadata.dat'
            metadata.parent.mkdir(parents=True); metadata.write_bytes(b'metadata')
            (game/'GameAssembly.dll').write_bytes(b'binary')
            tool = Path(folder)/'dumper.exe'; tool.write_bytes(b'tool')
            with patch.object(engines, '_run', return_value=dict(stage='il2cpp-signatures', status='failed', exit_code=1)), \
                 patch.object(engines.native, 'analyze_native', return_value=dict(status='metadata_only')):
                result = engines.analyze_game(game, out, tools={'il2cpp': tool}, export_assets=False, progress=lambda _: None)
            self.assertEqual(result['engine'], 'unity-il2cpp')
            self.assertEqual(result['status'], 'failed')
            self.assertFalse(result['toolruns'][0]['method_bodies_recovered'])

    def test_unreal_rejects_traversal_before_unpack(self):
        with tempfile.TemporaryDirectory() as folder:
            game, out = Path(folder)/'game', Path(folder)/'out'
            game.mkdir(); (game/'content.pak').write_bytes(b'pak')
            tool = Path(folder)/'repak.exe'; tool.write_bytes(b'tool')
            calls = []
            def run(args, destination, label, timeout, env):
                calls.append(args)
                log = destination/(label+'.log'); log.write_text('../../escape')
                return dict(stage=label, status='ok', exit_code=0, log=str(log))
            with patch.object(engines, '_run', side_effect=run):
                result = engines.analyze_game(game, out, tools={'repak': tool}, export_assets=False, progress=lambda _: None)
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][1], 'list')

    def test_raw_unreal_missing_member_is_partial(self):
        with tempfile.TemporaryDirectory() as folder:
            game, out = Path(folder)/'game', Path(folder)/'out'
            game.mkdir(); (game/'content.pak').write_bytes(b'pak')
            tool = Path(folder)/'repak.exe'; tool.write_bytes(b'tool')
            def run(args, destination, label, timeout, env):
                log = destination/(label+'.log')
                if args[1] == 'list':
                    log.write_text('Content/one.uasset\nContent/two.uasset\n')
                else:
                    target = Path(args[args.index('-o')+1])/'Content'
                    target.mkdir(); (target/'one.uasset').write_bytes(b'asset')
                    log.write_text('')
                return dict(stage=label, status='ok', exit_code=0, log=str(log))
            with patch.object(engines, '_run', side_effect=run):
                result = engines.analyze_game(game, out, tools={'repak': tool}, export_assets=False, progress=lambda _: None)
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['resources'][0]['missing_entries'], 1)

    def test_inventory_only_never_starts_tools_and_output_boundary(self):
        with tempfile.TemporaryDirectory() as folder:
            game, out = Path(folder)/'game', Path(folder)/'out'
            managed = game/'Demo_Data/Managed'; managed.mkdir(parents=True)
            (managed/'Assembly-CSharp.dll').write_bytes(b'dll')
            with patch.object(engines, '_run') as run, patch.object(engines.subprocess, 'Popen') as start:
                result = engines.analyze_game(game, out, run_tools=False, progress=lambda _: None)
                run.assert_not_called(); start.assert_not_called()
            self.assertEqual(result['status'], 'inventory_only')
            with self.assertRaises(ValueError):
                engines.analyze_game(game, game/'output', run_tools=False)

    def test_archive_member_validation(self):
        self.assertEqual(engines._archive_paths('../../../Content/test.uasset\n'), ['Content/test.uasset'])
        for member in ('../evil', 'C:/evil', 'Content\\evil', 'same\nSAME\n', '../../../../../../evil', 'NUL.txt', '.'):
            with self.assertRaises(ValueError):
                engines._archive_paths(member)

    def test_cache_requires_tree_identity_options_and_exports(self):
        with tempfile.TemporaryDirectory() as folder:
            game, out = Path(folder)/'game', Path(folder)/'out'
            managed = game/'Demo_Data/Managed'; managed.mkdir(parents=True)
            (managed/'Assembly-CSharp.dll').write_bytes(b'dll')
            tool = Path(folder)/'ilspy.exe'; tool.write_bytes(b'tool')
            def run(args, destination, label, timeout, env):
                target = Path(args[args.index('-o')+1])
                (target/'Recovered.cs').write_text('class Recovered {}')
                return dict(stage=label, status='ok', exit_code=0)
            options = dict(tools={'ilspy': tool}, export_assets=False, progress=lambda _: None, source_fingerprint='a'*64)
            with patch.object(engines, '_run', side_effect=run):
                first = engines.analyze_game(game, out, **options)
            with patch.object(engines, '_run') as run:
                self.assertTrue(engines.analyze_game(game, out, **options)['cache_reused'])
                run.assert_not_called()
            with self.assertRaises(FileExistsError):
                engines.analyze_game(game, out, **dict(options, source_fingerprint='b'*64))
            (Path(first['toolruns'][0]['output'])/'Recovered.cs').unlink()
            with self.assertRaises(FileExistsError):
                engines.analyze_game(game, out, **options)


if __name__ == '__main__':
    unittest.main()
