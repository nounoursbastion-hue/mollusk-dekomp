"""MolluskDékomp: verified disc extraction, resource inventory and native analysis."""
from pathlib import Path
import argparse,hashlib,json,sys,time,traceback
import disc
from i18n import translate,preferred,LANGUAGES,normalize
from settings import configured_path,protected_drive

NAME='MolluskDékomp'
DEFAULT_OUTPUT=configured_path('output',Path(__file__).resolve().parent/'results')

def save(path,data):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 temporary=path.with_suffix(path.suffix+'.part')
 temporary.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf8');temporary.replace(path)

def destination(image,out,language='fr'):
 t=lambda source,**values:translate(source,language,**values)
 image=Path(image).resolve(strict=True);out=Path(out).absolute()
 for node in [out,*out.parents]:
  if node.is_symlink() or (hasattr(node,'is_junction') and node.is_junction()):raise ValueError(t('Le dossier de sortie traverse un lien symbolique ou une jonction.'))
 out=out.resolve()
 if protected_drive(out.drive):raise ValueError(t('Disque de sortie protégé : {drive}. Choisir un autre disque.',drive=out.drive))
 if image.is_relative_to(out):raise ValueError(t("L’ISO source ne doit pas se trouver dans le dossier de sortie."))
 if image.is_dir() and out.is_relative_to(image):raise ValueError(t('Les résultats doivent être enregistrés hors du dossier du jeu.'))
 return image,out

def run(image,out,*,inspect_only=False,run_ghidra=True,analysis_timeout=600,function_timeout=15,max_functions=0,progress=print,language='fr'):
 t=lambda source,**values:translate(source,language,**values)
 image,out=destination(image,out,language);out.mkdir(parents=True,exist_ok=True)
 state_path=out/'run-private.json'
 if state_path.exists():
  previous=json.loads(state_path.read_text(encoding='utf8'))
  if previous.get('source')!=str(image):raise ValueError(t('Ce dossier appartient à une autre image. Choisir un nouveau dossier.'))
 state={'tool':NAME,'version':'1.2','source':str(image),'status':'running','stage':'inventory','started':time.strftime('%Y-%m-%dT%H:%M:%S%z'),'source_executed':False,'original_source_recovered':False,'limits':[t('Le pseudocode est une reconstruction, pas le code source original.'),t('Les contenus non décodés restent explicitement opaques.')]}
 save(state_path,state)
 state['language']=normalize(language)
 try:
  progress(t('1/4 — Inventaire ISO9660 et empreintes SHA-256…'))
  manifest=disc.analyze(image,hash_files=True)
  prior=out/'disc-manifest-private.json'
  if prior.exists() and json.loads(prior.read_text(encoding='utf8'))['image_sha256']!=manifest['image_sha256']:raise ValueError(t('L’image ne correspond pas au précédent inventaire.'))
  save(prior,manifest);state['disc']={k:v for k,v in manifest.items() if k not in {'files','directories'}};save(state_path,state)
  if not inspect_only:
   state['stage']='extraction';save(state_path,state);progress(t('2/4 — Extraction vérifiée de {count} fichiers…',count=manifest['file_count']))
   extraction=disc.extract(image,out/'extracted',manifest);save(out/'disc-extraction-report.json',extraction);state['extraction']=extraction
   state['stage']='resources';save(state_path,state);progress(t('3/4 — Archives, signatures et classement des ressources…'))
   import resources
   state['resources']=resources.run_resources(out/'extracted',out/'resources');save(state_path,state)
   state['stage']='native';save(state_path,state);progress(t('4/4 — Analyse native et pseudocode Ghidra…'))
   import native
   boot=manifest.get('boot_executable');candidates=[]
   if boot:
    match=next((r for r in manifest['files'] if r['path'].casefold()==boot.casefold()),None)
    if match:candidates.append(match)
   candidates.extend(r for r in manifest['files'] if r not in candidates and r.get('header_hex','').startswith('7f454c46'))
   state['native']=[];save(state_path,state)
   for i,entry in enumerate(candidates,1):
    relative=entry['path'];exe=out/'extracted'/relative
    with exe.open('rb') as f:magic=f.read(4)
    if magic!=b'\x7fELF':
     state['native'].append({'input':relative,'status':'unsupported','reason':'Format exécutable non pris en charge.'});continue
    progress(t('Exécutable {index}/{count} : {path}',index=i,count=len(candidates),path=relative))
    target=out/'native'/hashlib.sha256(relative.encode()).hexdigest()[:16]
    try:
     result=native.analyze_native(exe,target,run_ghidra=run_ghidra,analysis_timeout=analysis_timeout,function_timeout=function_timeout,max_functions=max_functions)
    except Exception as error:
     result={'status':'analysis_failed','reason':f'{type(error).__name__}: {error}','original_source_recovered':False}
    result['input_relative']=relative;result['output_directory']=str(target);state['native'].append(result);save(state_path,state)
   state['native_executable_count']=len(candidates)
  if not inspect_only:
   from organize import organize_exports
   progress(t('Classement des fichiers extraits et des exports…'))
   roots=[p for p in [out/'extracted',out/'resources/archives/files',out/'resources/previews',out/'native'] if p.is_dir()]
   state['organization']=organize_exports(roots,out/'sorted')
  state['status']='completed';state['result_quality']='partial_reconstruction';state['stage']='report';save(state_path,state)
  from report import render
  render(out,state);state['stage']='finished';state['report']=str(out/'MolluskDekomP.html');save(state_path,state)
  progress(t('Terminé — {path}',path=str(out/'MolluskDekomP.html')));return state
 except Exception as error:
  state.update(status='failed',error=f'{type(error).__name__}: {error}');save(state_path,state)
  (out/'failure-private.txt').write_text(traceback.format_exc(),encoding='utf8')
  raise

def run_game(game,out,*,run_tools=True,export_assets=True,timeout=1800,ue_profile=None,progress=print,language='fr'):
 t=lambda source,**values:translate(source,language,**values)
 import games,engines,pc_inventory
 if not isinstance(game,dict):game=games.inspect_game(game)
 if not game.get('installed'):raise ValueError(t('Installation absente ou encore en téléchargement ; terminer son installation avant analyse.'))
 source,out=destination(game['path'],out,language);out.mkdir(parents=True,exist_ok=True);state_path=out/'run-private.json'
 if state_path.exists() and json.loads(state_path.read_text(encoding='utf8')).get('source')!=str(source):raise ValueError(t('Ce dossier de résultats appartient à un autre jeu.'))
 state={'tool':NAME,'version':'1.2','source_type':'installed-game','source':str(source),'game':game,'status':'running','stage':'inventory','source_executed':False,'original_source_recovered':False,'limits':[t('La détection est rapide ; extraction et décompilation dépendent de la taille et du moteur.'),t('Le pseudocode et les assets exportés ne constituent pas le projet source original.')]}
 save(state_path,state)
 state['language']=normalize(language)
 try:
  progress(t('1/3 — Inventaire local du jeu : {title}',title=game['title']))
  state['resources']=pc_inventory.inventory_game(source,out/'resources');save(state_path,state)
  analysis_game=dict(game)
  if run_tools:
   from extract_pc import copy_game
   progress(t('Copie brute vérifiée des fichiers du jeu sélectionné…'));state['raw_extraction']=copy_game(source,out/'raw');save(state_path,state)
   if state['raw_extraction']['status']!='complete':raise RuntimeError(t('Copie brute partielle : consulter les erreurs avant de décompiler cette copie.'))
   analysis_game['path']=str(out/'raw')
  state['stage']='engine';save(state_path,state);progress(t('2/3 — Traitement du moteur : {engine}',engine=game['engine']))
  result=engines.analyze_game(analysis_game,out/'analysis',progress=lambda message:progress(t(message)),timeout=timeout,export_assets=export_assets,ue_profile=ue_profile,source_fingerprint=state['raw_extraction']['source_tree_sha256']) if run_tools else {'engine':game['engine'],'status':'inventory_only','native':[],'limits':[t('Inventaire rapide uniquement ; aucune extraction ou décompilation exécutée.')]}
  if (out/'analysis').is_dir():state['export_inventory']=pc_inventory.inventory_game(out/'analysis',out/'resources/exports',source_area='exported')
  if run_tools:
   from organize import organize_exports
   progress(t('Classement : modèles, sons, textures, maps, scripts et formats non décodés…'))
   state['organization']=organize_exports([p for p in [out/'raw',out/'analysis'] if p.is_dir()],out/'sorted')
  state['engine_analysis']=result;state['native']=result.get('native',[]);state['result_quality']='partial_reconstruction'
  state['status']='completed';state['stage']='report';save(state_path,state);progress(t('3/3 — Rapport et accès aux fichiers…'))
  from report import render
  render(out,state);state['stage']='finished';state['report']=str(out/'MolluskDekomP.html');save(state_path,state);progress(t('Terminé — {path}',path=state['report']));return state
 except Exception as error:
  state.update(status='failed',error=f'{type(error).__name__}: {error}');save(state_path,state);(out/'failure-private.txt').write_text(traceback.format_exc(),encoding='utf8');raise

def gui(language=None):
 from gui import start
 start(run,run_game,DEFAULT_OUTPUT,NAME,language=language)

def main(argv=None):
 parser=argparse.ArgumentParser(prog=NAME,description='Jeux installés et ISO : extraction, classement et décompilation selon les formats pris en charge.')
 parser.add_argument('--language',choices=LANGUAGES,default=preferred(),help='Interface/report language: fr, en, es, de, it')
 parser.add_argument('--gui',action='store_true');sub=parser.add_subparsers(dest='command');sub.add_parser('games',help='Détecter les jeux installés sans les modifier.')
 p=sub.add_parser('decompile-game',help='Analyser un jeu installé par identifiant ou dossier.')
 p.add_argument('game');p.add_argument('--output',type=Path,required=True);p.add_argument('--inventory-only',action='store_true');p.add_argument('--no-assets',action='store_true');p.add_argument('--timeout',type=int,default=1800);p.add_argument('--ue-profile')
 for verb in ['inspect','decompile']:
  p=sub.add_parser(verb);p.add_argument('image',type=Path);p.add_argument('--output',type=Path,required=True)
  p.add_argument('--no-ghidra',action='store_true');p.add_argument('--analysis-timeout',type=int,default=600);p.add_argument('--function-timeout',type=int,default=15);p.add_argument('--max-functions',type=int,default=0)
 args=parser.parse_args(argv)
 if args.gui or not args.command:gui(args.language);return 0
 if args.command=='games':
  import games
  print(json.dumps(games.discover_games(),ensure_ascii=False,indent=2));return 0
 if args.command=='decompile-game':
  if args.timeout<=0:parser.error('Le délai doit être positif.')
  import games
  try:
   selected=games.inspect_game(args.game) if Path(args.game).is_dir() else next((g for g in games.discover_games() if g['id']==args.game),None)
   if not selected:raise ValueError('Jeu introuvable ; utiliser la commande games ou fournir son dossier.')
   run_game(selected,args.output,run_tools=not args.inventory_only,export_assets=not args.no_assets,timeout=args.timeout,ue_profile=args.ue_profile,progress=lambda message:print(message,flush=True),language=args.language);return 0
  except Exception as error:print(f'{NAME} — {type(error).__name__}: {error}',file=sys.stderr);return 1
 if args.analysis_timeout<=0 or args.function_timeout<=0 or args.max_functions<0:parser.error('Délais positifs et nombre de fonctions positif ou nul requis.')
 try:run(args.image,args.output,inspect_only=args.command=='inspect',run_ghidra=not args.no_ghidra,analysis_timeout=args.analysis_timeout,function_timeout=args.function_timeout,max_functions=args.max_functions,progress=lambda message:print(message,flush=True),language=args.language);return 0
 except Exception as error:print(f'{NAME} — {type(error).__name__}: {error}',file=sys.stderr);return 1

if __name__=='__main__':raise SystemExit(main())
