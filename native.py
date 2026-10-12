"""Bounded local PE/ELF analysis; decompiler output is inferred pseudocode."""
from __future__ import annotations

import hashlib
import csv
import json
import os
import shutil
from pathlib import Path
import struct
import subprocess
import time
from settings import configured_path

DEFAULT_GHIDRA = configured_path('ghidra',Path(__file__).resolve().parent/'tools/ghidra')
DEFAULT_JAVA = configured_path('java',Path(__file__).resolve().parent/'tools/java')
DEFAULT_EE = configured_path('emotionengine',Path(__file__).resolve().parent/'tools/emotionengine')


def inspect_pe(executable):
    path = Path(executable)
    if path.stat().st_size > 512 * 1024 * 1024:
        raise ValueError('Native executable exceeds the 512 MiB analysis limit')
    data = path.read_bytes()
    if len(data) < 64 or data[:2] != b'MZ':
        raise ValueError('A complete PE DOS header is required')
    start = struct.unpack_from('<I', data, 60)[0]
    if start < 64 or start + 24 > len(data) or data[start:start + 4] != b'PE\0\0':
        raise ValueError('Invalid or truncated PE signature')
    machine, count, timestamp, symoff, symbols, optional_size, flags = struct.unpack_from('<HHIIIHH', data, start + 4)
    optional = start + 24
    if not 1 <= count <= 96 or optional + optional_size + count * 40 > len(data):
        raise ValueError('Invalid PE section table bounds')
    if optional_size < 2:
        raise ValueError('Missing PE optional header')
    magic = struct.unpack_from('<H', data, optional)[0]
    if magic not in (0x10b, 0x20b) or optional_size < (96 if magic == 0x10b else 112):
        raise ValueError('Unsupported or truncated PE optional header')
    entry = struct.unpack_from('<I', data, optional + 16)[0]
    base = struct.unpack_from('<I' if magic == 0x10b else '<Q', data, optional + (28 if magic == 0x10b else 24))[0]
    sections = []
    for i in range(count):
        off = optional + optional_size + i * 40
        name, virtual_size, rva, size, raw, reloc, lineno, nrel, nline, characteristics = struct.unpack_from('<8sIIIIIIHHI', data, off)
        if size and raw + size > len(data):
            raise ValueError('PE section exceeds executable bounds')
        sections.append(dict(name=name.rstrip(b'\0').decode('ascii', 'replace'), address=base+rva,
                             memory_bytes=virtual_size, offset=raw, file_bytes=size, flags=characteristics))
    language = {0x8664: 'x86:LE:64:default', 0x14c: 'x86:LE:32:default'}.get(machine)
    if (machine == 0x8664 and magic != 0x20b) or (machine == 0x14c and magic != 0x10b):
        raise ValueError('PE architecture and optional-header bitness disagree')
    return dict(format='PE32+' if magic == 0x20b else 'PE32', architecture={0x8664: 'x86-64', 0x14c: 'x86'}.get(machine, f'PE machine {machine}'),
                endian='little', machine=machine, image_base=base, entry=base+entry, bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest(), sections=sections, executable_class='windows_native',
                ghidra_language=language, ghidra_compiler='windows', original_source_recovered=False)


def inspect_binary(executable):
    with Path(executable).open('rb') as stream:
        magic = stream.read(4)
    if magic == b'\x7fELF':
        return inspect_elf(executable)
    if magic[:2] == b'MZ':
        return inspect_pe(executable)
    raise ValueError('Unsupported native executable: expected ELF32 or PE')


def inspect_elf(executable):
    path = Path(executable)
    if path.stat().st_size > 512 * 1024 * 1024:
        raise ValueError('Native ELF exceeds the 512 MiB analysis limit')
    data = path.read_bytes()
    if len(data) < 52 or data[:4] != b'\x7fELF':
        raise ValueError('Unsupported native format: a complete ELF header is required')
    if data[4] != 1 or data[5] not in (1, 2) or data[6] != 1:
        raise ValueError('Only ELF32 version 1 is supported')
    endian = '<' if data[5] == 1 else '>'
    fields = struct.unpack_from(endian + 'HHIIIIIHHHHHH', data, 16)
    kind, machine, version, entry, phoff, shoff, flags, hsize, phsize, phnum, shsize, shnum, shstr = fields
    if hsize < 52 or version != 1:
        raise ValueError('Invalid ELF header')
    if phnum and (phsize < 32 or phoff + phnum * phsize > len(data)):
        raise ValueError('Program header table exceeds executable bounds')
    if shnum and (shsize < 40 or shoff + shnum * shsize > len(data)):
        raise ValueError('Section header table exceeds executable bounds')
    segments, special = [], {'MMI': 0, 'LQ': 0, 'SQ': 0, 'COP2_VU': 0}
    for i in range(phnum):
        ptype, off, va, pa, filesz, memsz, pflags, align = struct.unpack_from(endian + 'IIIIIIII', data, phoff + i * phsize)
        if off + filesz > len(data) or (ptype == 1 and memsz < filesz):
            raise ValueError('Program segment exceeds executable bounds')
        segments.append(dict(type=ptype, offset=off, address=va, file_bytes=filesz, memory_bytes=memsz, flags=pflags))
        if ptype == 1 and pflags & 1 and machine == 8:
            for pos in range(off, off + filesz - 3, 4):
                op = struct.unpack_from(endian + 'I', data, pos)[0] >> 26
                label = {28: 'MMI', 30: 'LQ', 31: 'SQ', 18: 'COP2_VU'}.get(op)
                if label:
                    special[label] += 1
    sections = []
    for i in range(shnum):
        name, typ, sflags, va, off, size, link, info, align, entsize = struct.unpack_from(endian + 'IIIIIIIIII', data, shoff + i * shsize)
        if typ != 8 and off + size > len(data):
            raise ValueError('Section exceeds executable bounds')
        sections.append(dict(name_offset=name, type=typ, flags=sflags, address=va, offset=off, bytes=size, link=link, entry_bytes=entsize))
    symbols = []
    for section in sections:
        if section['type'] not in (2, 11):
            continue
        step = section['entry_bytes']
        if step < 16 or section['bytes'] % step or section['link'] >= len(sections):
            raise ValueError('Invalid ELF symbol table')
        strings = sections[section['link']]
        if strings['type'] != 3:
            raise ValueError('ELF symbol names require a string table')
        string_data = data[strings['offset']:strings['offset'] + strings['bytes']]
        for off in range(section['offset'], section['offset'] + section['bytes'], step):
            name, value, size, info, other, index = struct.unpack_from(endian + 'IIIBBH', data, off)
            if name >= len(string_data):
                raise ValueError('Symbol name exceeds string table')
            stop = string_data.find(b'\x00', name)
            if stop < 0:
                raise ValueError('Unterminated ELF symbol name')
            text = string_data[name:stop].decode('utf-8', 'replace')
            if text:
                symbols.append(dict(name=text, address=value, bytes=size, type=info & 15, binding=info >> 4, section=index))
    language = None
    compiler = 'default'
    executable_class = 'generic'
    if machine == 8:
        if path.suffix.lower() == '.irx' or kind == 0xff80:
            executable_class = 'ps2_iop'
            language = 'MIPS:' + ('LE' if endian == '<' else 'BE') + ':32:default'
        elif flags & 0x00ff0000 == 0x00920000:
            executable_class = 'ps2_emotion_engine'
            language = 'r5900:LE:32:default' if endian == '<' else None
        else:
            language = 'MIPS:' + ('LE' if endian == '<' else 'BE') + ':64:64-32addr'
            compiler = 'o32'
    elif machine == 20:
        language = 'PowerPC:' + ('LE' if endian == '<' else 'BE') + ':32:default'
    return dict(format='ELF32', architecture={8: 'MIPS', 20: 'PowerPC'}.get(machine, f'ELF machine {machine}'),
                endian='little' if endian == '<' else 'big', machine=machine, entry=entry, flags=flags,
                bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), segments=segments, sections=sections,
                symbols=symbols, executable_class=executable_class, ghidra_language=language, ghidra_compiler=compiler,
                ps2_extension_opcode_candidates=special,
                opcode_scan_limit='Aligned words in executable LOAD segments can include embedded data; counts are candidates, not validated instructions.')


def analyze_native(executable, out, *, run_ghidra=True, analysis_timeout=300,
                   function_timeout=15, max_functions=0, export_timeout=1800,
                   ghidra_home=None, java_home=None, ghidra_path=None, java_path=None, emotionengine_home=None):
    if min(analysis_timeout, function_timeout, export_timeout) <= 0 or max_functions < 0:
        raise ValueError('Timeouts must be positive and max_functions nonnegative')
    executable, out = Path(executable).resolve(), Path(out).resolve()
    if executable == out or executable.is_relative_to(out):
        raise ValueError('Native output must not contain or overwrite the input executable')
    metadata = inspect_binary(executable)
    metadata_name = 'pe-metadata.json' if metadata['format'].startswith('PE') else 'elf-metadata.json'
    request = dict(run_ghidra=run_ghidra, analysis_timeout=analysis_timeout, function_timeout=function_timeout,
                   max_functions=max_functions, export_timeout=export_timeout,
                   processor=metadata['ghidra_language'], compiler=metadata['ghidra_compiler'])
    if (out / 'native-report.json').exists():
        previous = json.loads((out / 'native-report.json').read_text(encoding='utf-8'))
        if (not run_ghidra and previous.get('status') == 'metadata_only'
                and previous.get('input_sha256') == metadata['sha256'] and previous.get('request') == request
                and (out / metadata_name).is_file()):
            return previous
        if (previous.get('input_sha256') == metadata['sha256'] and previous.get('request') == request
                and previous.get('status') == 'pseudocode_partial'
                and previous.get('ghidra', {}).get('all_recognized_functions_processed')):
            index = out / 'functions.tsv'
            if index.is_file() and (out / 'ghidra-summary.json').is_file():
                with index.open(encoding='utf-8', newline='') as stream:
                    rows = list(csv.DictReader(stream, delimiter='\t'))
                complete = len(rows) == previous['ghidra']['processed_functions']
                for row in rows:
                    if row['pseudocode']:
                        target = (out / row['pseudocode']).resolve()
                        complete = complete and target.is_relative_to(out) and target.is_file() and target.stat().st_size > 0
                if complete:
                    return previous
        raise FileExistsError('Output contains a different or incomplete run; choose a fresh directory')
    if (out / 'ghidra-summary.json').exists():
        raise FileExistsError('Native output contains an unverified report; choose a fresh directory')
    out.mkdir(parents=True, exist_ok=True)
    (out / metadata_name).write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding='utf-8')
    report = dict(status='metadata_only', metadata=metadata_name, original_source_recovered=False,
                  standalone=False, semantic_validation=False,
                  limits=['Pseudocode has inferred types, names and control flow; it is not original source or a buildable project.',
                          'Processor extensions and inferred calling conventions are not a proof of runtime equivalence. Results require manual validation.',
                          'Only functions recognized by the selected Ghidra analysis are exported; missing functions remain unknown.'],
                  input_sha256=metadata['sha256'], analysis_timeout_seconds=analysis_timeout,
                  function_timeout_seconds=function_timeout, export_timeout_seconds=export_timeout,
                  request=request)
    ghidra = Path(ghidra_home or ghidra_path or DEFAULT_GHIDRA).resolve()
    java = Path(java_home or java_path or DEFAULT_JAVA).resolve()
    launcher = ghidra / 'support' / ('analyzeHeadless.bat' if os.name == 'nt' else 'analyzeHeadless')
    ee = Path(emotionengine_home or DEFAULT_EE).resolve()
    if not run_ghidra:
        report['reason'] = 'Ghidra execution disabled by caller'
    elif not metadata['ghidra_language']:
        report.update(status='unsupported_architecture', reason='No tested architecture adapter for this ELF machine')
    elif not launcher.is_file() or not (java / 'bin' / ('java.exe' if os.name == 'nt' else 'java')).is_file():
        report.update(status='tool_unavailable', reason='Local Ghidra launcher or Java runtime missing')
    elif metadata['executable_class'] == 'ps2_emotion_engine' and not (ee / 'data/languages/EmotionEngine.ldefs').is_file():
        report.update(status='tool_unavailable', reason='Dedicated R5900 extension is required; generic MIPS is not silently substituted')
    else:
        for folder in ('project', 'settings', 'cache', 'temp', 'pseudocode'):
            (out / folder).mkdir(exist_ok=True)
        env = os.environ.copy()
        if metadata['executable_class'] == 'ps2_emotion_engine':
            settings = out / 'settings' / (env.get('USERNAME', 'user') + '-ghidra') / 'ghidra_12.1.4_PUBLIC' / 'Extensions' / ee.name
            shutil.copytree(ee, settings, dirs_exist_ok=True)
            report['processor_extension'] = 'Ghidra Emotion Engine Reloaded v2.1.38 for Ghidra 12.1.4'
        env['JAVA_HOME'] = str(java)
        env['JAVA_TOOL_OPTIONS'] = ' '.join(f'-D{k}="{out / v}"' for k, v in (
            ('application.settingsdir', 'settings'), ('application.cachedir', 'cache'), ('java.io.tmpdir', 'temp')))
        args = [str(launcher), str(out / 'project'), 'MolluskNative', '-import', str(executable),
                '-processor', metadata['ghidra_language'], '-cspec', metadata['ghidra_compiler'],
                '-analysisTimeoutPerFile', str(analysis_timeout), '-max-cpu', '2',
                '-scriptPath', str(Path(__file__).parent.resolve()), '-postScript', 'MolluskNativeExport.java',
                str(out), str(function_timeout), str(max_functions), str(export_timeout),
                '-log', str(out / 'ghidra.log')]
        if os.name == 'nt' and any(any(char in arg for char in '<>&|^%!\r\n"') for arg in args):
            raise ValueError('Windows batch launcher does not accept shell metacharacters in paths')
        started = time.monotonic()
        with (out / 'ghidra-console.log').open('w', encoding='utf-8') as log:
            process = subprocess.Popen(args, env=env, stdout=log, stderr=subprocess.STDOUT,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            try:
                code = process.wait(timeout=analysis_timeout + export_timeout + 180)
                report['exit_code'] = code
            except subprocess.TimeoutExpired:
                if os.name == 'nt':
                    subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True, check=False)
                else:
                    process.kill()
                process.wait()
                report.update(status='timeout_partial', reason='Owned Ghidra process exceeded configured total time limit')
        report['seconds'] = round(time.monotonic() - started, 2)
        summary_path = out / 'ghidra-summary.json'
        if summary_path.exists():
            report['ghidra'] = json.loads(summary_path.read_text(encoding='utf-8'))
            report['status'] = 'pseudocode_partial' if report.get('exit_code') == 0 else 'process_failed_partial'
        elif report['status'] != 'timeout_partial':
            report.update(status='process_failed', reason='No completed Ghidra export summary; inspect console log')
    report['input_unchanged'] = hashlib.sha256(executable.read_bytes()).hexdigest() == metadata['sha256']
    if not report['input_unchanged']:
        report['status'] = 'input_changed_during_analysis'
    (out / 'native-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    return report
