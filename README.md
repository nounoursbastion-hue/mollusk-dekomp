# MolluskDékomp — multilingual Windows edition

Detect installed games, select one, create a verified raw copy, run compatible local extraction/decompilation tools and organize the results. **This is a Python application, not a self-contained EXE or a universal original-source recovery tool.**

## Quick start

1. Extract the ZIP to a writable folder on a drive with plenty of free space. Do not put the application or its results inside a game installation. The shared package permits any drive; `protected_drives` in `settings.json` can block drives you want to keep free. The original development copy protects C: by default.
2. Install **Python 3.12 or newer with Tk**, including the Python launcher or PATH option. Python is not included in this archive. If needed, set `MOLLUSK_PY` to the full path to your Python executable, or create a `.venv` beside the app.
3. For PS2 texture previews, install Pillow: `py -3 -m pip install -r requirements.txt`. Detection and quick inventory do not require Pillow.
4. Double-click **MolluskDékomp.cmd**. Choose your language at the top right: **English, Français, Español, Deutsch, Italiano**. Changes apply immediately and are saved in `settings.json`.
5. Select a detected game or use **Add game folder**. Choose an output folder outside the game. Uncheck **Extract and decompile** for a quick inventory. Otherwise, enable asset conversion and start **Analyze selection**.

Steam, Epic and GOG libraries are detected where their local manifests are available. Portable, Xbox and unregistered games can be added manually. Missing or incomplete installations cannot be processed. ISO9660/PS2 inputs have a separate tab.

## External tools: configure once

**Game files, decompiled content, Python, Java and third-party tools are not bundled.** Obtain/install the tools separately and keep their own licenses. Detection and inventory work without the decompilers. Full extraction uses whichever compatible tools you have installed; missing tools remain explicit in the report.

The shared ZIP includes `settings.json` with relative example paths. You can change these to absolute paths, using forward slashes in JSON. For an existing installation, copy `settings.example.json` to `settings.json`. Restart after editing tool paths. Optional `MOLLUSK_CONFIG` selects another settings file.

| Setting | Expected executable or directory | Used for |
|---|---|---|
| `ilspy` | `tools/ilspy/ilspycmd.exe` | Unity Mono / .NET C# reconstruction |
| `il2cpp` | `tools/il2cpp/Il2CppDumper.exe` | IL2CPP declarations and addresses |
| `assetripper` | `tools/assetripper/AssetRipper.GUI.Free.exe` | Compatible Unity assets/scenes |
| `repak` | `tools/repak/repak.exe` | Compatible Unreal PAK archives |
| `cue4parse` | `tools/cue4parse/cue4parse.exe` | Compatible Unreal asset conversions |
| `ghidra` | Directory containing `support/analyzeHeadless.bat` | Native pseudocode/disassembly |
| `java` | JDK root containing `bin/java.exe` | Ghidra runtime |
| `emotionengine` | Extracted PS2 extension root with `extension.properties` | PS2 R5900 analysis |
| `dotnet` | Optional runtime directory containing `dotnet.exe` | .NET analysis tools; installed runtime otherwise |
| `output` | Output directory, relative or absolute | Default results location |
| `protected_drives` | List such as `["C:"]`, or `[]` | Drives where exports are blocked |

Versions checked on the development PC: ILSpy 9.1, Il2CppDumper 6.7.46, AssetRipper 2.0, repak 0.2.3, CUE4Parse CLI 0.2.0, Ghidra 12.1.4, JDK 25, Emotion Engine Reloaded 2.1.38 matching that Ghidra version. Compatibility with other versions is not guaranteed. Preserve each tool’s supporting files; copying its EXE alone may not be enough.

For Unreal conversions, enter an explicit compatible version profile, such as `GAME_UE4_25`. The program does not guess that version. IoStore `.utoc/.ucas`, UE3 packages, complete Blueprint graphs and Godot scripts are not currently reconstructed by these adapters.

## Output and limits

`raw/` contains verified copies of accessible regular files. A partial copy blocks subsequent decompilation. `analysis/` contains tool exports; ISO jobs use `extracted/`, `resources/` and `native/`. `sorted/` groups physical files into Models, Audio, Textures, Maps, Animations, Shaders, Scripts, Materials, Containers, Binaries, Configurations and Non_decodes. **An empty category means no supported representation was produced.** Undecoded proprietary files are retained, not presented as usable models or audio.

`MolluskDekomP.html` is an offline searchable report with its own five-language selector. Generated filenames, code symbols, status identifiers and technical diagnostics retain their original form. Translation does not alter extracted data. Reports contain private local paths; the distribution ZIP does not contain your reports or game exports.

The game is never executed or modified. Sorted files can be hardlinks to the job’s private exports, never to the installed game. Copy them elsewhere before editing if you want to preserve those exports. An identical run can reuse compatible analysis results after verifying the raw source fingerprint; changing options or game versions requires a fresh output folder. Cache checks cover export presence and counts, not a full rehash of all exported content.

Pseudocode has inferred types and names. IL2CPP signatures do not recover original C# bodies. Extraction does not produce a complete original project, a recompiled game or autonomous reusable components. Encrypted/incompatible formats and analysis timeouts remain reported.

## Command line

```text
py -3 mollusk_dekomp.py --language en --gui
py -3 mollusk_dekomp.py games
py -3 mollusk_dekomp.py --language en decompile-game "D:/Games/Example" --output "D:/Exports/Example" --inventory-only
py -3 mollusk_dekomp.py --language en decompile "D:/Images/example.iso" --output "D:/Exports/Disc"
py -3 -m unittest discover -s . -p "test_*.py" -v
```

The `--language` option goes before the subcommand. Supported codes: `fr`, `en`, `es`, `de`, `it`. Without a saved preference, the source version follows the operating-system language, falling back to English. The shared package starts in English.
