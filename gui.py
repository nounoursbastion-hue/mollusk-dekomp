"""Installed-game library and ISO workflow, with background discovery and analysis."""
from pathlib import Path
import queue,threading,webbrowser
from i18n import translate,preferred,normalize,LANGUAGES
from settings import save_language

def start(run_iso,run_game,default_output,name,language=None):
 import tkinter as tk
 from tkinter import ttk,filedialog,messagebox
 import games
 language=normalize(language or preferred());texts=[]
 def t(source,**values):return translate(source,language,**values)
 def localize(widget,source):
  texts.append((widget,source));widget.config(text=t(source));return widget
 window=tk.Tk();window.title(name+' 1.2');window.geometry('1120x840');window.minsize(850,650)
 frame=ttk.Frame(window,padding=16);frame.pack(fill='both',expand=True)
 header=ttk.Frame(frame);header.pack(fill='x');ttk.Label(header,text=name,font=('Segoe UI',23,'bold')).pack(side='left')
 language_var=tk.StringVar(value=LANGUAGES[language]);language_picker=ttk.Combobox(header,textvariable=language_var,values=list(LANGUAGES.values()),state='readonly',width=14);language_picker.pack(side='right');localize(ttk.Label(header),'Langue').pack(side='right',padx=8)
 localize(ttk.Label(frame,text='Jeux installés · extraction · code · modèles · textures · sons · maps'),'Jeux installés · extraction · code · modèles · textures · sons · maps').pack(anchor='w',pady=(0,12))
 events=queue.Queue();catalog={};manual_catalog={};running=False;completed_report=None;selected_game_id=None
 tabs=ttk.Notebook(frame);tabs.pack(fill='x');library_tab=ttk.Frame(tabs,padding=10);iso_tab=ttk.Frame(tabs,padding=10);tabs.add(library_tab,text=t('Jeux installés'));tabs.add(iso_tab,text=t('Image ISO'))
 query=tk.StringVar();detected=tk.StringVar(value=t('Recherche des jeux installés…'));output=tk.StringVar(value=str(default_output/'new-analysis'));iso=tk.StringVar()
 searchrow=ttk.Frame(library_tab);searchrow.pack(fill='x',pady=(0,8));localize(ttk.Label(searchrow,text='Rechercher'),'Rechercher').pack(side='left',padx=(0,8));ttk.Entry(searchrow,textvariable=query).pack(side='left',fill='x',expand=True)
 def fill():
  selected=tree.selection();tree.delete(*tree.get_children());terms=query.get().casefold().split()
  for id,g in catalog.items():
   if all(term in ' '.join([g['title'],g['engine'],g['launcher'],g['path']]).casefold() for term in terms):tree.insert('', 'end', iid=id,values=(g['title'],g['engine'],g['launcher'],t('Prêt' if g['installed'] else 'Absent / incomplet')))
  if selected and tree.exists(selected[0]):tree.selection_set(selected[0])
 def refresh():
  refresh_button.config(state='disabled');detected.set(t('Recherche des manifestes locaux…'))
  def worker():
   try:events.put(('discovery',games.discover_games()))
   except Exception as e:events.put(('discovery_error',str(e)))
  threading.Thread(target=worker,daemon=True).start()
 refresh_button=localize(ttk.Button(searchrow,text='Actualiser',command=refresh),'Actualiser');refresh_button.pack(side='right',padx=8)
 tree_frame=ttk.Frame(library_tab);tree_frame.pack(fill='x')
 tree=ttk.Treeview(tree_frame,columns=('title','engine','launcher','state'),show='headings',height=8,selectmode='browse')
 headings=[('title','Jeu',470),('engine','Moteur',150),('launcher','Bibliothèque',100),('state','Installation',130)]
 for key,label,width in headings:tree.heading(key,text=t(label));tree.column(key,width=width,minwidth=80)
 tree.pack(side='left',fill='x',expand=True);scroll=ttk.Scrollbar(tree_frame,orient='vertical',command=tree.yview);scroll.pack(side='right',fill='y');tree.config(yscrollcommand=scroll.set);ttk.Label(library_tab,textvariable=detected).pack(anchor='w',pady=5)
 details=tk.StringVar(value=t('Sélectionner un jeu ; seuls les fichiers du jeu choisi seront traités.'))
 ttk.Label(library_tab,textvariable=details,wraplength=1030).pack(anchor='w')
 def select(event=None):
  nonlocal selected_game_id
  if not tree.selection():return
  g=catalog[tree.selection()[0]];details.set(g['path']+'\n'+(' · '.join(g.get('engine_evidence',[])) or t('Format à examiner.')))
  if not running and selected_game_id!=g['id']:output.set(str(default_output/g['id']));selected_game_id=g['id']
 tree.bind('<<TreeviewSelect>>',select);query.trace_add('write',lambda *_:fill())
 def manual():
  path=filedialog.askdirectory(title=t('Choisir le dossier d’un jeu portable ou non détecté'))
  if not path:return
  try:
   g=games.inspect_game(path);manual_catalog[g['id']]=g;catalog[g['id']]=g;query.set('');fill();tree.selection_set(g['id']);tree.see(g['id']);select()
  except Exception as e:messagebox.showerror(name,str(e))
 localize(ttk.Button(library_tab,text='Ajouter le dossier d’un jeu',command=manual),'Ajouter le dossier d’un jeu').pack(anchor='w',pady=6)
 localize(ttk.Label(library_tab,text='Détection par bibliothèques Steam, Epic et GOG. Pour un jeu portable, Xbox ou non enregistré, ajouter son dossier.',wraplength=1030),'Détection par bibliothèques Steam, Epic et GOG. Pour un jeu portable, Xbox ou non enregistré, ajouter son dossier.').pack(anchor='w')
 row=ttk.Frame(iso_tab);row.pack(fill='x',pady=14);localize(ttk.Label(row,text='Image ISO',width=20),'Image ISO').pack(side='left');ttk.Entry(row,textvariable=iso).pack(side='left',fill='x',expand=True)
 def choose_iso():
  path=filedialog.askopenfilename(title=t('Choisir une image ISO'),filetypes=[(t('Image ISO'),'*.iso'),(t('Tous'),'*.*')])
  if path:iso.set(path);output.set(str(default_output/(Path(path).stem[:50]+'-iso')))
 localize(ttk.Button(row,text='Parcourir',command=choose_iso),'Parcourir').pack(side='right',padx=8)
 localize(ttk.Label(iso_tab,text='ISO9660 / PS2 : archives PAK1, exécutables Emotion Engine et IOP, prévisualisations TIM2. Les autres formats restent signalés.',wraplength=1000),'ISO9660 / PS2 : archives PAK1, exécutables Emotion Engine et IOP, prévisualisations TIM2. Les autres formats restent signalés.').pack(anchor='w',pady=10)
 row=ttk.Frame(frame);row.pack(fill='x',pady=10);localize(ttk.Label(row,text='Dossier des résultats',width=22),'Dossier des résultats').pack(side='left');ttk.Entry(row,textvariable=output).pack(side='left',fill='x',expand=True)
 def choose_output():
  selected=filedialog.askdirectory(title=t('Dossier de résultats, hors du jeu'))
  if selected:output.set(selected)
 localize(ttk.Button(row,text='Parcourir',command=choose_output),'Parcourir').pack(side='right',padx=8)
 full=tk.BooleanVar(value=True);assets=tk.BooleanVar(value=True)
 localize(ttk.Checkbutton(frame,text='Extraire et décompiler (désactiver pour un inventaire rapide)',variable=full),'Extraire et décompiler (désactiver pour un inventaire rapide)').pack(anchor='w')
 localize(ttk.Checkbutton(frame,text='Convertir les assets quand le décodeur est disponible',variable=assets),'Convertir les assets quand le décodeur est disponible').pack(anchor='w')
 ue_profile=tk.StringVar();profile_row=ttk.Frame(frame);profile_row.pack(fill='x',pady=4)
 localize(ttk.Label(profile_row,text='Profil Unreal si connu (ex. GAME_UE4_25)'),'Profil Unreal si connu (ex. GAME_UE4_25)').pack(side='left');ttk.Entry(profile_row,textvariable=ue_profile,width=24).pack(side='left',padx=8)
 localize(ttk.Label(frame,text='La détection est rapide. L’extraction complète peut prendre plusieurs minutes et plusieurs Go ; les formats non décodés sont conservés.',wraplength=1050),'La détection est rapide. L’extraction complète peut prendre plusieurs minutes et plusieurs Go ; les formats non décodés sont conservés.').pack(anchor='w',pady=5)
 bar=ttk.Progressbar(frame,mode='indeterminate');bar.pack(fill='x',pady=6)
 log=tk.Text(frame,height=5,wrap='word',state='disabled',font=('Consolas',10));log.pack(fill='both',expand=True)
 controls=ttk.Frame(frame);controls.pack(fill='x',pady=(10,0))
 def launch():
  nonlocal running
  if running:return
  game=None;selected_iso=iso.get();selected_out=output.get();is_iso=tabs.index(tabs.select())==1;selected_full=full.get();selected_assets=assets.get();selected_profile=ue_profile.get().strip() or None;selected_language=language
  if is_iso and not selected_iso:messagebox.showerror(name,t('Choisir une image ISO.'));return
  if not is_iso:
   if not tree.selection():messagebox.showerror(name,t('Sélectionner un jeu installé.'));return
   game=dict(catalog[tree.selection()[0]])
   if not game['installed']:messagebox.showerror(name,t('Cette installation est absente ou incomplète. Terminer son installation.'));return
  running=True;start_button.config(state='disabled');language_picker.config(state='disabled');bar.start();log.config(state='normal');log.delete('1.0','end');log.config(state='disabled')
  def worker():
   try:
    progress=lambda text:events.put(('log',t(text)))
    result=run_iso(selected_iso,selected_out,inspect_only=not selected_full,run_ghidra=selected_full,progress=progress,language=selected_language) if is_iso else run_game(game,selected_out,run_tools=selected_full,export_assets=selected_assets,ue_profile=selected_profile,progress=progress,language=selected_language)
    events.put(('done',result['report']))
   except Exception as e:events.put(('error',str(e)))
  threading.Thread(target=worker,daemon=False).start()
 def show_report():
  path=Path(completed_report) if completed_report else Path(output.get())/'MolluskDekomP.html'
  if path.is_file():webbrowser.open(path.resolve().as_uri())
  else:messagebox.showinfo(name,t('Le rapport sera disponible après l’analyse.'))
 start_button=localize(ttk.Button(controls,text='Analyser la sélection',command=launch),'Analyser la sélection');start_button.pack(side='left');localize(ttk.Button(controls,text='Ouvrir le rapport',command=show_report),'Ouvrir le rapport').pack(side='left',padx=8)
 def poll():
  nonlocal running,completed_report
  while not events.empty():
   kind,value=events.get_nowait()
   if kind=='discovery':
    catalog.clear();catalog.update({id:games.inspect_game(g['path']) for id,g in manual_catalog.items()});catalog.update({g['id']:g for g in value});fill();detected.set(t('{entries} entrées détectées · {ready} installations prêtes',entries=len(catalog),ready=sum(g['installed'] for g in catalog.values())));refresh_button.config(state='normal')
   elif kind=='discovery_error':detected.set(t('Détection : {error}',error=value));refresh_button.config(state='normal')
   elif kind=='log':log.config(state='normal');log.insert('end',value+'\n');log.see('end');log.config(state='disabled')
   else:
    running=False;bar.stop();start_button.config(state='normal');language_picker.config(state='readonly')
    if kind=='error':messagebox.showerror(name,value)
    else:completed_report=value;show_report()
  window.after(200,poll)
 def close():
  if running:messagebox.showinfo(name,t('Une analyse est en cours. Attendre sa fin pour fermer cette fenêtre.'));return
  window.destroy()
 def change_language(event=None):
  nonlocal language
  chosen=next(code for code,label in LANGUAGES.items() if label==language_var.get())
  try:save_language(chosen)
  except (OSError,ValueError) as error:language_var.set(LANGUAGES[language]);messagebox.showerror(name,str(error));return
  language=chosen
  for widget,source in texts:widget.config(text=t(source))
  tabs.tab(library_tab,text=t('Jeux installés'));tabs.tab(iso_tab,text=t('Image ISO'))
  for key,label,_ in headings:tree.heading(key,text=t(label))
  fill();detected.set(t('{entries} entrées détectées · {ready} installations prêtes',entries=len(catalog),ready=sum(g['installed'] for g in catalog.values())))
  if tree.selection():select()
  else:details.set(t('Sélectionner un jeu ; seuls les fichiers du jeu choisi seront traités.'))
 language_picker.bind('<<ComboboxSelected>>',change_language)
 window.protocol('WM_DELETE_WINDOW',close);poll();window.after(50,refresh);window.mainloop()
