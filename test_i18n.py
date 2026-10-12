import ast,json,string,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import i18n,settings,report,mollusk_dekomp

class LanguageTests(unittest.TestCase):
 def test_catalogues_complete_and_placeholders_preserved(self):
  formatter=string.Formatter()
  fields=lambda text:{key for _,key,_,_ in formatter.parse(text) if key is not None}
  for source,translations in i18n.MESSAGES.items():
   self.assertEqual(len(translations),4,source)
   for lang in i18n.LANGUAGES:
    translated=i18n.translate(source,lang);self.assertTrue(translated);self.assertEqual(fields(source),fields(translated),(source,lang))
  self.assertEqual(i18n.normalize('de_DE'),'de');self.assertEqual(i18n.normalize('unsupported'),'en')
 def test_all_literal_gui_labels_are_in_catalogue(self):
  tree=ast.parse(Path(__file__).with_name('gui.py').read_text(encoding='utf8'))
  for node in ast.walk(tree):
   if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id=='ttk':
    for keyword in node.keywords:
     if keyword.arg=='text' and isinstance(keyword.value,ast.Constant):self.assertIn(keyword.value.value,i18n.MESSAGES)
 def test_all_reports_have_stable_filter_values_and_safe_catalogues(self):
  with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
   root=Path(tmp)
   for lang in i18n.LANGUAGES:
    report.render(root,{'language':lang})
    text=(root/'MolluskDekomP.html').read_text(encoding='utf8')
    self.assertIn('<html lang="'+lang+'">',text)
    self.assertIn('value="Fonction" data-i18n="Fonction"',text)
    self.assertIn(i18n.translate('Rapport technique complet et limites',lang),text)
    self.assertNotIn('=TRANSLATIONS',text);self.assertNotIn('=INITIAL_LANGUAGE',text)
    catalog=json.loads(text.split('const translations=',1)[1].split(';let language=',1)[0])
    self.assertEqual(set(catalog),set(i18n.LANGUAGES))
 def test_settings_preserve_paths_and_resolve_relative_to_config(self):
  with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
   config=Path(tmp)/'settings.json';config.write_text(json.dumps({'ilspy':'tools/ilspy.exe'}),encoding='utf8')
   with patch.object(settings,'CONFIG',config):
    settings.save_language('en');self.assertEqual(settings.load()['ilspy'],'tools/ilspy.exe')
    self.assertEqual(settings.configured_path('ilspy','unused'),config.parent/'tools/ilspy.exe')
    self.assertEqual(i18n.preferred(),'en')
    self.assertTrue(settings.protected_drive('c:'));self.assertFalse(settings.protected_drive('F:'))
    config.write_text('{"protected_drives":[]}',encoding='utf8');self.assertFalse(settings.protected_drive('C:'))
    config.write_text('{"protected_drives":"C:"}',encoding='utf8')
    with self.assertRaises(ValueError):settings.protected_drive('C:')
    config.write_text('[]',encoding='utf8')
    with self.assertRaises(ValueError):settings.load()
 def test_cli_language_reaches_gui(self):
  with patch.object(mollusk_dekomp,'gui') as gui:
   self.assertEqual(mollusk_dekomp.main(['--language','en','--gui']),0);gui.assert_called_once_with('en')

if __name__=='__main__':unittest.main()
