"""Offline review page; source filenames and strings are always escaped."""
from pathlib import Path
import csv,html,json,re
from i18n import translate,normalize,LANGUAGES,MESSAGES,catalogue

def render(out,state):
 language=normalize(state.get('language','fr'));t=lambda source,**values:translate(source,language,**values)
 out=Path(out).resolve();rows=[]
 for inventory in sorted((out/'resources').rglob('*resources*.jsonl')):
  with inventory.open(encoding='utf8') as stream:
   for line in stream:
    item=json.loads(line);path=item.get('path',item.get('relative',''))
    description=' ; '.join(f.get('format','') for f in item.get('observed_formats',[]))
    if item.get('extension_category_hint'):description+=' ; '+t('indice extension : {hint}',hint=str(item['extension_category_hint']))
    game_root=out/'raw' if (out/'raw').is_dir() else Path(state.get('source',''))
    area=game_root if item.get('source_area')=='game' and state.get('source_type')=='installed-game' else out/'analysis' if item.get('source_area')=='exported' else out/'extracted' if item.get('source_area')=='disc' else out/'resources/archives/files'
    area=area.resolve();target=(area/path).resolve();uri=target.as_uri() if target.is_relative_to(area) and target.is_file() else ''
    rows.append({'type':'Ressource','name':path,'bytes':item.get('bytes',0),'status':item.get('classification_status','inventoried'),'description':description,'hints':item.get('lexical_hints',{}),'uri':uri})
 preview_map=out/'resources/previews/preview-map-private.jsonl'
 if preview_map.is_file():
  with preview_map.open(encoding='utf8') as stream:
   for line in stream:
    item=json.loads(line)
    if not item.get('preview'):continue
    target=(preview_map.parent/item['preview']).resolve()
    if not target.is_relative_to(out) or not target.is_file():continue
    rows.append({'type':'Texture','name':item['path'],'bytes':target.stat().st_size,'status':item['status'],'description':t('TIM2 → PNG {width} × {height} ; fidélité en jeu non vérifiée',width=item['width'],height=item['height']),'hints':{},'uri':target.as_uri()})
 tables=list((out/'native').rglob('functions.tsv'))+list((out/'analysis').rglob('functions.tsv'))
 for table in sorted(tables):
  with table.open(encoding='utf-8-sig',newline='') as stream:
   for item in csv.DictReader(stream,delimiter='\t'):
    code=item.get('pseudocode','');path=(table.parent/code).resolve() if code else None
    uri=path.as_uri() if path and path.is_relative_to(out) and path.is_file() else ''
    rows.append({'type':'Fonction','name':item.get('name','')+' @ '+item.get('address',''),'bytes':item.get('body_bytes',0),'status':item.get('status','unknown'),'description':item.get('signature',''),'hints':item.get('diagnostic',''),'uri':uri})
 data=json.dumps(rows,ensure_ascii=False).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
 summary=html.escape(json.dumps(state,ensure_ascii=False,indent=2))
 native=[r.get('ghidra',{}) for r in state.get('native',[])]
 metrics=[('Fichiers disque',state.get('disc',{}).get('file_count',0)),('Entrées PAK1',(state.get('resources',{}).get('archives') or {}).get('entries',0)),('Fonctions en pseudocode',sum(r.get('pseudocode_functions',0) for r in native)),('PNG uniques',(state.get('resources',{}).get('texture_previews') or {}).get('unique_pngs',0)),('Diagnostics d’analyse',sum(r.get('analysis_error_bookmarks',0) for r in native))]
 if state.get('source_type')=='installed-game':
  metrics=[('Fichiers inventoriés',state.get('resources',{}).get('files',0)),('Fichiers bruts vérifiés',state.get('raw_extraction',{}).get('files_verified',0)),('Fichiers rangés',state.get('organization',{}).get('files',0)),('Fonctions en pseudocode',sum(r.get('pseudocode_functions',0) for r in native)),('Erreurs d’inventaire',len(state.get('resources',{}).get('errors',[])))]
 def span(label):return '<span data-i18n="'+html.escape(label,quote=True)+'">'+html.escape(t(label))+'</span>'
 cards=''.join('<div style="background:#182a3d;border-radius:8px;padding:16px;min-width:170px"><strong style="display:block;font-size:28px">'+format(n,',').replace(',',' ')+'</strong>'+span(label)+'</div>' for label,n in metrics)
 links=''.join('<a href="'+html.escape(p.as_uri(),quote=True)+'">'+span(label)+'</a>' for p,label in [(out/'sorted','Fichiers rangés par catégorie'),(out/'raw','Copie brute du jeu'),(out/'extracted','Fichiers du disque'),(out/'resources','Ressources et archives'),(out/'analysis','Exports du moteur'),(out/'native','Pseudocode et projets Ghidra'),(out/'run-private.json','Rapport JSON')] if p.exists())
 page='''<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MolluskDékomp</title>
<style>:root{color-scheme:dark}body{margin:0;background:#0a1420;color:#dfebf5;font:15px system-ui}main{max-width:1400px;margin:auto;padding:32px}h1{font-size:36px;margin:0;color:#75e6c5}p{line-height:1.6}.muted{color:#9cb3c8}nav{display:flex;gap:14px;flex-wrap:wrap;margin:20px 0}a{color:#75e6c5}input,select,button{background:#182a3d;color:#eef7ff;border:1px solid #49677e;border-radius:6px;padding:10px}input{flex:1;min-width:240px}.filters{display:flex;gap:10px;flex-wrap:wrap;margin:24px 0}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #263b4d;padding:12px;vertical-align:top;overflow-wrap:anywhere}th{color:#a9c4db}td:nth-child(2){max-width:500px}code,pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px Consolas,monospace}details{margin-top:24px;background:#122233;padding:16px;border-radius:8px}.notice{padding:16px;border-left:3px solid #e7ba73;background:#241f18}.paging{display:flex;align-items:center;gap:16px;padding:20px 0}button{cursor:pointer}</style>
<main><h1>MolluskDékomp</h1><p class="muted">Extraction vérifiée · Archives · Ressources · Analyse native</p>
<label><span data-i18n="Langue">Langue</span> <select id="language" aria-label="Language">LANGUAGE_OPTIONS</select></label>
<p class="notice">Le pseudocode contient des types et noms inférés. Il ne constitue pas le code source original ni un projet prêt à compiler. Les formats opaques, erreurs et limites restent dans les rapports. Aucun jeu extrait n'a été exécuté.</p>
<section style="display:flex;gap:14px;flex-wrap:wrap">CARDS</section><nav>LINKS</nav><div class="filters"><input id="query" aria-label="Rechercher" placeholder="Nom, format, adresse, indice lexical…"><select id="type" aria-label="Type"><option value="">Tous les éléments</option><option>Ressource</option><option>Fonction</option><option>Texture</option></select><select id="status" aria-label="État"><option value="">Tous les états</option></select></div>
<p id="count" aria-live="polite"></p><table><thead><tr><th>Type</th><th>Élément</th><th>État</th><th>Observation</th></tr></thead><tbody id="rows"></tbody></table><div class="paging"><button id="previous">Précédent</button><span id="page"></span><button id="next">Suivant</button></div>
<details><summary>Rapport technique complet et limites</summary><pre>SUMMARY</pre></details></main>
<p class="muted" style="text-align:center">Les diagnostics techniques restent dans leur langue d’origine.</p>
<script>const data=DATA;let page=0;const size=80,q=document.querySelector('#query'),type=document.querySelector('#type'),status=document.querySelector('#status');for(const s of [...new Set(data.map(x=>x.status))].sort()){const o=document.createElement('option');o.textContent=s;status.append(o)}
const translations=TRANSLATIONS;let language=INITIAL_LANGUAGE;
function tr(key){return translations[language]?.[key]||key}
function setLanguage(code){language=translations[code]?code:'en';document.documentElement.lang=language;document.querySelector('#language').value=language;for(const node of document.querySelectorAll('[data-i18n]'))node.textContent=tr(node.dataset.i18n);q.placeholder=tr('Nom, format, adresse, indice lexical…');q.setAttribute('aria-label',tr('Rechercher'));type.setAttribute('aria-label',tr('Type'));status.setAttribute('aria-label',tr('État'));document.querySelector('#language').setAttribute('aria-label',tr('Langue'));draw()}
function draw(){
 const terms=q.value.toLocaleLowerCase().split(/\\s+/).filter(Boolean);
 const selected=data.filter(x=>(!type.value||x.type===type.value)&&(!status.value||x.status===status.value)&&terms.every(t=>[x.name,x.description,x.status,JSON.stringify(x.hints)].join(' ').toLocaleLowerCase().includes(t)));
 const pages=Math.max(1,Math.ceil(selected.length/size));page=Math.min(page,pages-1);
 document.querySelector('#count').textContent=tr('{count} éléments trouvés sur {total}').replace('{count}',selected.length.toLocaleString(language)).replace('{total}',data.length.toLocaleString(language));
 const body=document.querySelector('#rows');body.replaceChildren();
 for(const x of selected.slice(page*size,(page+1)*size)){
  const tr=document.createElement('tr');
  for(const [i,v] of [x.type,x.name,x.status,x.description].entries()){
   const td=document.createElement('td');
   if(i===1&&x.uri){
    const a=document.createElement('a');a.href=x.uri;a.textContent=v;td.append(a);
    if(x.type==='Texture'){const im=document.createElement('img');im.src=x.uri;im.alt=x.name;im.loading='lazy';im.width=96;im.style.display='block';im.style.marginTop='8px';td.append(im)}
   }else td.textContent=i===0?tr(v):typeof v==='string'?v:JSON.stringify(v);
   tr.append(td);
  }
  body.append(tr);
 }
 document.querySelector('#page').textContent=(page+1)+' / '+pages;document.querySelector('#previous').disabled=page===0;document.querySelector('#next').disabled=page===pages-1;
}
for(const control of [q,type,status])control.addEventListener('input',()=>{page=0;draw()});document.querySelector('#previous').onclick=()=>{page--;draw()};document.querySelector('#next').onclick=()=>{page++;draw()};document.querySelector('#language').onchange=event=>setLanguage(event.target.value);setLanguage(language);</script></html>'''
 def mark(match):
  tag,attributes,label=match.group(1,2,3)
  if label not in MESSAGES:return match.group(0)
  if tag=='option' and label in ('Ressource','Fonction','Texture'):attributes+=' value="'+label+'"'
  return '<'+tag+attributes+' data-i18n="'+html.escape(label,quote=True)+'">'+html.escape(t(label))+'</'+tag+'>'
 page=re.sub(r'<(p|th|button|summary|option)([^>]*)>([^<>]+)</\1>',mark,page)
 page=page.replace('<html lang="fr">','<html lang="'+language+'">',1).replace('LANGUAGE_OPTIONS',''.join('<option value="'+code+'">'+label+'</option>' for code,label in LANGUAGES.items()))
 # Replace data last: extracted strings cannot inject HTML or alter template tokens.
 before,after=page.split('const data=DATA;',1)
 after=after.replace('const translations=TRANSLATIONS;','const translations='+json.dumps(catalogue(),ensure_ascii=False).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')+';').replace('INITIAL_LANGUAGE',json.dumps(language))
 page=before.replace('CARDS',cards).replace('LINKS',links).replace('SUMMARY',summary)+'const data='+data+';'+after
 temporary=out/'MolluskDekomP.html.part';temporary.write_text(page,encoding='utf8');temporary.replace(out/'MolluskDekomP.html')
 return {'rows':len(rows),'file':str(out/'MolluskDekomP.html')}
