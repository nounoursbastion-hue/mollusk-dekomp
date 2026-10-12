import json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import games,mollusk_dekomp

class PcPipelineTests(unittest.TestCase):
 def test_inventory_then_full_and_replay_keep_source_unchanged(self):
  with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
   root=Path(tmp);source=root/'Demo';source.mkdir();(source/'opaque.bin').write_bytes(b'opaque payload');out=root/'job';game=games.inspect_game(source)
   with patch('engines.analyze_game') as analyze:
    state=mollusk_dekomp.run_game(game,out,run_tools=False,progress=lambda _:None)
    analyze.assert_not_called();self.assertEqual(state['engine_analysis']['status'],'inventory_only');self.assertFalse((out/'raw').exists())
   fingerprints=[]
   def fake_engine(g,target,**kwargs):
    self.assertEqual(Path(g['path']),out/'raw');fingerprints.append(kwargs['source_fingerprint'])
    target.mkdir(exist_ok=True);(target/'function.cs').write_text('class Reconstructed {}',encoding='utf8')
    return {'engine':g['engine'],'status':'partial','native':[]}
   with patch('engines.analyze_game',side_effect=fake_engine):
    state=mollusk_dekomp.run_game(game,out,progress=lambda _:None)
    replay=mollusk_dekomp.run_game(game,out,progress=lambda _:None)
   self.assertEqual(len(fingerprints[0]),64);self.assertEqual(fingerprints[0],fingerprints[1])
   self.assertTrue(state['raw_extraction']['all_files_verified']);self.assertEqual(replay['raw_extraction']['files_reused'],1)
   self.assertEqual((source/'opaque.bin').read_bytes(),b'opaque payload');self.assertEqual(state['organization']['errors'],[])
   self.assertTrue(any((out/'sorted/Scripts').rglob('*.cs')));self.assertTrue(any((out/'sorted/Non_decodes').rglob('*.bin')))
   self.assertTrue((out/'MolluskDekomP.html').is_file())
 def test_partial_raw_copy_blocks_decompiler(self):
  with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
   root=Path(tmp);source=root/'game';source.mkdir();(source/'data').write_bytes(b'x')
   with patch('extract_pc.copy_game',return_value={'status':'partial','errors':['unreadable']}),patch('engines.analyze_game') as analyze:
    with self.assertRaises(RuntimeError):mollusk_dekomp.run_game(source,root/'job',progress=lambda _:None)
    analyze.assert_not_called()
   state=json.loads((root/'job/run-private.json').read_text(encoding='utf8'));self.assertEqual(state['status'],'failed')

if __name__=='__main__':unittest.main()
