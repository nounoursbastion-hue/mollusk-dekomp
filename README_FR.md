# MolluskDékomp — version multilingue à partager

L’interface et les rapports proposent **français, anglais, espagnol, allemand et italien**. Le sélecteur en haut à droite change la langue immédiatement ; le choix de l’application est enregistré. L’archive démarre en anglais.

1. Extraire l’archive dans un dossier accessible en écriture, hors d’un jeu, sur un disque disposant de beaucoup d’espace libre.
2. Installer **Python 3.12 ou plus avec Tk**, avec le lanceur Python ou l’option PATH. Python n’est pas inclus.
3. Pour les aperçus de textures PS2, installer Pillow avec `py -3 -m pip install -r requirements.txt`.
4. Lancer **MolluskDékomp.cmd**, puis choisir « Français » dans « Language ».
5. Choisir un jeu détecté, ou « Ajouter le dossier d’un jeu », puis un dossier de sortie hors du jeu. Désactiver « Extraire et décompiler » pour commencer par un inventaire rapide.

**Les outils tiers ne sont pas inclus.** Pour décompiler ou convertir, installer les outils adaptés et modifier leurs chemins dans `settings.json`. Les chemins relatifs partent du dossier de ce fichier. Le [guide anglais détaillé](README_EN.md) indique tous les chemins et versions vérifiés. Redémarrer après modification des chemins. `MOLLUSK_PY` permet d’utiliser un Python précis ; `MOLLUSK_CONFIG` permet de choisir un autre fichier de configuration.

Unity Mono utilise ILSpy et AssetRipper ; Unity IL2CPP utilise AssetRipper, Il2CppDumper et Ghidra. Unreal utilise repak et, pour les conversions compatibles, CUE4Parse avec un profil de version explicite. Ghidra nécessite Java et, pour PS2 R5900, une extension Emotion Engine compatible. Copier l’ensemble des fichiers de chaque outil, pas seulement son EXE, et conserver ses licences.

`raw/` contient les copies vérifiées, `analysis/` les exports, `sorted/` les fichiers par catégorie : modèles, sons, textures, maps, animations, shaders, scripts, matériaux, conteneurs, exécutables, configurations et fichiers non décodés. `MolluskDekomP.html` propose recherche, filtres, langues et liens locaux. Les identifiants techniques, symboles de code et diagnostics restent dans leur forme d’origine.

**L’archive ne contient aucun fichier de jeu, résultat de décompilation ou rapport privé.** Une fois lancée, l’application ne recherche ni ne télécharge d’outils sur Internet. L’inventaire fonctionne sans décompilateur ; les autres traitements dépendent des outils installés et des formats compatibles.

Le jeu installé n’est jamais exécuté ou modifié. Les fichiers rangés peuvent partager leurs octets avec les exports privés du même traitement : copier ailleurs avant de modifier. Les formats opaques restent dans `Non_decodes` et les catégories peuvent être vides. Le pseudocode ne garantit ni le code source original, ni un jeu recompilable, ni des composants autonomes. Aucune récupération universelle à 100 % n’est promise.

La configuration partagée autorise tous les disques ; `protected_drives` permet d’en bloquer certains, par exemple `["C:"]`. La copie de développement conserve sa protection de C: par défaut. Changer les paramètres d’analyse ou la version d’un jeu nécessite un nouveau dossier de résultats.
