"""Allowlisted tools Claude may run through run_tool.

Only names in TOOLS can be executed, always without a shell, with the case work
directory as cwd. Interactive tools (shells, curses UIs) are excluded because
nothing can answer their prompts. Each hint is what Claude reads before choosing
arguments; keep them short and concrete.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

EXTRA_PATH = ["/opt/forensics/bin", "/usr/local/bin", "/usr/bin", "/bin"]

TOOLS: dict[str, dict[str, str]] = {
    # ---- disk and filesystem (The Sleuth Kit, libewf)
    "mmls": {"cat": "disk", "hint": "Partition table and offsets: mmls <image>"},
    "fsstat": {"cat": "disk", "hint": "Filesystem details: fsstat -o <sector_offset> <image>"},
    "fls": {"cat": "disk", "hint": "File listing incl. deleted; bodyfile: fls -r -m C: -o <off> <image> > ../work/body.txt (use output_name instead of >)"},
    "icat": {"cat": "disk", "hint": "Extract by inode/MFT entry: icat -o <off> <image> <inode> (use output_name to save)"},
    "istat": {"cat": "disk", "hint": "Metadata for one inode/MFT entry: istat -o <off> <image> <inode>"},
    "ils": {"cat": "disk", "hint": "List inodes: ils -o <off> <image>"},
    "blkls": {"cat": "disk", "hint": "Unallocated space: blkls -o <off> <image> (use output_name)"},
    "img_stat": {"cat": "disk", "hint": "Image format details: img_stat <image>"},
    "mactime": {"cat": "timeline", "hint": "Bodyfile to timeline: mactime -b body.txt -d -z UTC"},
    "tsk_recover": {"cat": "disk", "hint": "Recover files: tsk_recover -o <off> <image> <outdir under work/>"},
    "ewfinfo": {"cat": "disk", "hint": "E01 acquisition metadata and stored hashes: ewfinfo <file.E01>"},
    "ewfverify": {"cat": "disk", "hint": "Verify E01 internal hashes: ewfverify <file.E01>"},
    # ---- memory
    "vol": {"cat": "memory", "hint": "Volatility 3: vol -f <mem> windows.info | windows.pslist | windows.pstree | windows.netscan | windows.cmdline | windows.malfind | windows.dlllist; add -r csv for CSV. Symbols download from Microsoft on first use."},
    # ---- Windows artifacts (Eric Zimmerman tools on .NET)
    "MFTECmd": {"cat": "windows", "hint": "$MFT/$J/$LogFile: MFTECmd -f <$MFT> --csv <work dir>"},
    "EvtxECmd": {"cat": "windows", "hint": "Event logs with maps: EvtxECmd -d <dir of evtx> --csv <work dir>"},
    "RECmd": {"cat": "windows", "hint": "Registry with batch file: RECmd -d <dir of hives> --bn /opt/forensics/eztools/RECmd/BatchExamples/Kroll_Batch.reb --csv <work dir>"},
    "PECmd": {"cat": "windows", "hint": "Prefetch: PECmd -d <Prefetch dir> --csv <work dir>"},
    "LECmd": {"cat": "windows", "hint": "LNK files: LECmd -d <dir> --csv <work dir>"},
    "JLECmd": {"cat": "windows", "hint": "Jump lists: JLECmd -d <dir> --csv <work dir>"},
    "SBECmd": {"cat": "windows", "hint": "Shellbags from hives: SBECmd -d <dir of NTUSER/UsrClass> --csv <work dir>"},
    "AmcacheParser": {"cat": "windows", "hint": "AmcacheParser -f <Amcache.hve> --csv <work dir>"},
    "AppCompatCacheParser": {"cat": "windows", "hint": "Shimcache: AppCompatCacheParser -f <SYSTEM> --csv <work dir>"},
    "SrumECmd": {"cat": "windows", "hint": "SRUM: SrumECmd -f <SRUDB.dat> -r <SOFTWARE> --csv <work dir>"},
    "SQLECmd": {"cat": "windows", "hint": "SQLite artifacts with maps: SQLECmd -d <dir> --csv <work dir>"},
    "RBCmd": {"cat": "windows", "hint": "Recycle bin $I files: RBCmd -d <dir> --csv <work dir>"},
    "WxTCmd": {"cat": "windows", "hint": "Windows Timeline: WxTCmd -f <ActivitiesCache.db> --csv <work dir>"},
    "bstrings": {"cat": "windows", "hint": "Strings with regex presets: bstrings -f <file> --lr ipv4"},
    "evtx_dump": {"cat": "windows", "hint": "Fast EVTX to JSON lines: evtx_dump -o jsonl <file.evtx>"},
    "regipy-dump": {"cat": "windows", "hint": "Dump a hive: regipy-dump <hive>"},
    "regipy-plugins-run": {"cat": "windows", "hint": "Run regipy plugins: regipy-plugins-run <hive> -o <work/out.json>"},
    # ---- detection over logs
    "chainsaw": {"cat": "detection", "hint": "Sigma hunt over EVTX: chainsaw hunt <evtx dir> -s /opt/forensics/rules/sigma/rules -m /opt/forensics/chainsaw/mappings/sigma-event-logs-all.yml --csv -o <work dir>; keyword search: chainsaw search <term> <dir>"},
    "hayabusa": {"cat": "detection", "hint": "Timeline with detections: hayabusa csv-timeline -d <evtx dir> -o <work/hayabusa.csv> -w -q (add -r /opt/forensics/hayabusa/rules if rules are not found)"},
    # ---- super timelines and live-system parsing
    "log2timeline.py": {"cat": "timeline", "hint": "Plaso: log2timeline.py --storage-file <work/case.plaso> <image or dir> (long running; raise timeout_sec)"},
    "psort.py": {"cat": "timeline", "hint": "psort.py -o dynamic -w <work/timeline.csv> <work/case.plaso>"},
    "pinfo.py": {"cat": "timeline", "hint": "pinfo.py <work/case.plaso>"},
    "target-query": {"cat": "timeline", "hint": "Dissect: target-query -f <function> <image or mount>; list functions with target-query -l <target>. Useful: runkeys, services, users, prefetch, evtx, mft, amcache, shimcache"},
    "target-info": {"cat": "timeline", "hint": "Dissect host summary: target-info <image>"},
    "rdump": {"cat": "timeline", "hint": "Dissect record output to CSV/JSON: rdump -w csv://<work/out.csv> <records file>"},
    # ---- malware and file triage
    "yara": {"cat": "malware", "hint": "yara -r /opt/forensics/rules/signature-base/yara <dir or file> (use -s for matched strings)"},
    "capa": {"cat": "malware", "hint": "Capabilities of a PE/ELF: capa <file> (-v for detail, -j for JSON)"},
    "floss": {"cat": "malware", "hint": "Obfuscated strings: floss <file> (-j for JSON)"},
    "olevba": {"cat": "malware", "hint": "Office macros: olevba <doc>"},
    "oleid": {"cat": "malware", "hint": "Office doc risk indicators: oleid <doc>"},
    "rtfobj": {"cat": "malware", "hint": "Embedded RTF objects: rtfobj <file>"},
    "exiftool": {"cat": "files", "hint": "Metadata: exiftool <file>"},
    "binwalk": {"cat": "files", "hint": "Embedded files: binwalk <file>"},
    "file": {"cat": "files", "hint": "file <path>"},
    "strings": {"cat": "files", "hint": "strings -a -n 8 <file>; UTF-16: strings -a -el <file>"},
    "sha256sum": {"cat": "files", "hint": "sha256sum <file>"},
    "md5sum": {"cat": "files", "hint": "md5sum <file>"},
    "hashdeep": {"cat": "files", "hint": "Recursive hashes: hashdeep -r -c sha256 <dir>"},
    "ssdeep": {"cat": "files", "hint": "Fuzzy hashes: ssdeep -r <dir>"},
    "7z": {"cat": "files", "hint": "Extract triage collections into work/: 7z x <zip> -o<work/subdir>"},
    "unzip": {"cat": "files", "hint": "unzip -d <work/subdir> <zip>"},
    "bulk_extractor": {"cat": "files", "hint": "Features (emails, URLs, CCNs): bulk_extractor -o <new work dir> <image>"},
    "foremost": {"cat": "files", "hint": "Carving: foremost -i <image> -o <new work dir>"},
    "sqlite3": {"cat": "files", "hint": "Query a copied database (copy it to work/ first): sqlite3 -readonly <db> '<sql>'"},
    "hindsight.py": {"cat": "files", "hint": "Chrome/Edge history: hindsight.py -i <profile dir> -o <work/hindsight> -f jsonl"},
    # ---- network
    "tshark": {"cat": "network", "hint": "tshark -r <pcap> -q -z conv,tcp ; filters: -Y 'dns' -T fields -e dns.qry.name"},
    # ---- text processing over outputs
    "rg": {"cat": "text", "hint": "ripgrep over outputs: rg -i <pattern> <path>"},
    "jq": {"cat": "text", "hint": "jq '<filter>' <file.json>"},
    "head": {"cat": "text", "hint": "head -n 50 <file>"},
    "wc": {"cat": "text", "hint": "wc -l <file>"},
    "sort": {"cat": "text", "hint": "sort <file>"},
    "ls": {"cat": "text", "hint": "ls -la <path>"},
    "find": {"cat": "text", "hint": "find <path> -type f -name '<glob>' (no -exec/-delete)"},
    # ---- Velociraptor offline collections
    "velociraptor": {"cat": "collection", "hint": "Inspect an offline collection or run artifacts on an image: velociraptor artifacts list ; velociraptor query \"SELECT ...\""},
}

# Arguments that would let an allowlisted tool execute or destroy things.
FORBIDDEN_ARGS = {
    "find": {"-exec", "-execdir", "-delete", "-ok", "-okdir", "-fprint", "-fprintf", "-fls"},
    "sqlite3": {".shell", ".system", ".output", ".once", ".save", ".backup"},
    "7z": {"d", "a", "u", "rn"},
}


def resolve(name: str) -> str | None:
    if name not in TOOLS:
        return None
    return shutil.which(name, path=os.pathsep.join(EXTRA_PATH))


def available() -> list[dict[str, str]]:
    rows = []
    for name, meta in TOOLS.items():
        rows.append({"tool": name, "category": meta["cat"], "installed": bool(resolve(name)), "usage": meta["hint"]})
    return rows
