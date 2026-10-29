#!/bin/bash
# Prints which allowlisted tools are installed and their versions where cheap to get.
export PATH=/opt/forensics/bin:/usr/local/bin:$PATH
echo "Forensic workstation tool inventory ($(date -u +%FT%TZ))"
/opt/forensics/mcp-venv/bin/python -I -c '
import sys; sys.path.insert(0, "/opt/forensics/mcp")
from fw_forensics import catalog
rows = catalog.available()
missing = [r["tool"] for r in rows if not r["installed"]]
for r in rows:
    print(("  ok      " if r["installed"] else "  MISSING ") + r["category"].ljust(11) + r["tool"])
print(f"\n{len(rows)-len(missing)} of {len(rows)} tools installed")
'
echo
echo "Versions:"
for c in "vol -h | head -1" "log2timeline.py --version" "chainsaw --version" "hayabusa help | head -3" "capa --version" "yara --version" "claude --version" "dotnet --list-runtimes"; do
  printf '  %-28s %s\n' "${c%% *}" "$(bash -c "$c" 2>&1 | head -1)"
done
