import json,tempfile,unittest
from pathlib import Path
from report import render

class ReportTests(unittest.TestCase):
 def test_untrusted_strings_and_local_links(self):
  with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
   root=Path(tmp);folder=root/'resources';folder.mkdir();(root/'extracted').mkdir()
   (root/'extracted'/'safe.tm2').write_bytes(b'TIM2')
   row={'path':'safe.tm2','source_area':'disc','bytes':4,'observed_formats':[{'format':'TIM2'}],'lexical_hints':{'untrusted':'</script><img src=x onerror=alert(1)>'},'classification_status':'signature_observed'}
   (folder/'resources-private.jsonl').write_text(json.dumps(row)+'\n',encoding='utf8')
   render(root,{'source':'<script>alert(2)</script> const data=DATA;','status':'completed'})
   text=(root/'MolluskDekomP.html').read_text(encoding='utf8')
   self.assertNotIn('<img src=x',text);self.assertNotIn('<script>alert(2)',text)
   dataset=json.loads(text.split('<script>const data=',1)[1].split(';let page=',1)[0])
   self.assertEqual(dataset[0]['description'],'TIM2');self.assertEqual(dataset[0]['uri'],(root/'extracted/safe.tm2').as_uri())
 def test_native_path_outside_output_not_linked(self):
  with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
   root=Path(tmp);native=root/'native/job';native.mkdir(parents=True)
   (native/'functions.tsv').write_text('address\tname\tstatus\tpseudocode\n1000\tunsafe\tpartial\t../../../test_report.py\n',encoding='utf8')
   render(root,{})
   text=(root/'MolluskDekomP.html').read_text(encoding='utf8');dataset=json.loads(text.split('const data=',1)[1].split(';let page=',1)[0])
   self.assertEqual(dataset[0]['uri'],'')

if __name__=='__main__':unittest.main()
