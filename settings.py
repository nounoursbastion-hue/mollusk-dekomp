"""Optional local settings; relative tool paths are resolved beside the app."""
import json,os
from pathlib import Path

ROOT=Path(__file__).resolve().parent
CONFIG=Path(os.environ.get('MOLLUSK_CONFIG',ROOT/'settings.json'))

def load():
 if not CONFIG.exists():return {}
 data=json.loads(CONFIG.read_text(encoding='utf8'))
 if not isinstance(data,dict):raise ValueError('settings.json must contain a JSON object')
 return data

def save_language(language):
 data=load();data['language']=language
 temporary=CONFIG.with_suffix('.json.part');temporary.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf8');temporary.replace(CONFIG)

def configured_path(key,default):
 value=load().get(key)
 if value is None or value=='':return Path(default)
 if not isinstance(value,str):raise ValueError('Invalid path setting: '+key)
 path=Path(os.path.expandvars(value)).expanduser()
 return path if path.is_absolute() else CONFIG.resolve().parent/path

def protected_drive(drive):
 drives=load().get('protected_drives',['C:'])
 if not isinstance(drives,list) or any(not isinstance(item,str) or len(item)!=2 or item[1]!=':' or not item[0].isalpha() for item in drives):raise ValueError('protected_drives must be a list of drive letters, e.g. ["C:"]')
 return drive.upper() in {item.upper() for item in drives}
