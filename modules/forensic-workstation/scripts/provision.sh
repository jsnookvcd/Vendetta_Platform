#!/bin/bash
# Vendetta forensic workstation provisioner (Ubuntu 24.04 x86_64).
#
# Installs a free DFIR toolset, the analyst account, the read-only evidence
# model, Claude Code (on Amazon Bedrock by default) and the forensic MCP server.
# Safe to re-run: every step checks before it installs. A single tool failing
# to install is logged and reported in the login banner; it does not stop the
# rest of the build.
#
# Inputs (env): SSM_PREFIX, AWS_REGION, ENABLE_DESKTOP
set -uo pipefail

MODULE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SSM_PREFIX="${SSM_PREFIX:-/vendetta/forensic-workstation}"
AWS_REGION="${AWS_REGION:-us-east-1}"
ENABLE_DESKTOP="${ENABLE_DESKTOP:-true}"
FOR=/opt/forensics
BIN=$FOR/bin
FAILS=/var/log/forensic-provision-failures.log
export DEBIAN_FRONTEND=noninteractive
export PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin PIPX_MAN_DIR=/usr/local/share/man

: > "$FAILS"
log()  { echo "[$(date -u +%H:%M:%S)] $*"; }
try()  { local name="$1"; shift; log "install: $name"; if ! "$@"; then echo "$name" >> "$FAILS"; log "FAILED: $name"; fi; }
mkdir -p "$BIN" $FOR/rules $FOR/eztools

# ------------------------------------------------------------------ config
ssm() { aws ssm get-parameter --region "$AWS_REGION" --name "$SSM_PREFIX/$1" --query Parameter.Value --output text 2>/dev/null || echo "${2:-}"; }
EVIDENCE_BUCKET="$(ssm EVIDENCE_BUCKET)"
AUDIT_LOG_GROUP="$(ssm AUDIT_LOG_GROUP /forensic-workstation/audit)"
CLAUDE_BACKEND="$(ssm CLAUDE_BACKEND bedrock)"
CLAUDE_MODEL="$(ssm CLAUDE_MODEL default)"
BEDROCK_REGION="$(ssm BEDROCK_REGION "$AWS_REGION")"
[ "$CLAUDE_MODEL" = "default" ] && CLAUDE_MODEL=""
cat > /etc/forensic-workstation.env <<EOF
EVIDENCE_BUCKET=$EVIDENCE_BUCKET
AUDIT_LOG_GROUP=$AUDIT_LOG_GROUP
CLAUDE_BACKEND=$CLAUDE_BACKEND
CLAUDE_MODEL=$CLAUDE_MODEL
BEDROCK_REGION=$BEDROCK_REGION
SSM_PREFIX=$SSM_PREFIX
AWS_REGION=$AWS_REGION
EOF
chmod 644 /etc/forensic-workstation.env

# ------------------------------------------------------------------ accounts
getent group forensics >/dev/null || groupadd forensics
id analyst >/dev/null 2>&1 || useradd -m -s /bin/bash -G forensics analyst
usermod -aG forensics analyst
usermod -aG forensics ssm-user 2>/dev/null || true

# ------------------------------------------------------------------ /cases volume
# The second EBS volume shows up as an NVMe disk with no partitions or mounts.
mount_cases() {
  mountpoint -q /cases && return 0
  local dev=""
  for _ in $(seq 1 60); do
    dev=$(lsblk -dpno NAME,TYPE | awk '$2=="disk"{print $1}' | while read -r d; do
      [ -z "$(lsblk -no MOUNTPOINT "$d" | tr -d '[:space:]')" ] && [ "$(lsblk -no NAME "$d" | wc -l)" -eq 1 ] && echo "$d"
    done | head -1)
    [ -n "$dev" ] && break
    sleep 10
  done
  [ -z "$dev" ] && { log "no case volume found"; return 1; }
  blkid "$dev" >/dev/null 2>&1 || mkfs.xfs -L cases "$dev"
  mkdir -p /cases
  grep -q 'LABEL=cases' /etc/fstab || echo "LABEL=cases /cases xfs defaults,nofail,noatime 0 2" >> /etc/fstab
  mount /cases
}
try "cases volume" mount_cases
mkdir -p /cases
chown root:forensics /cases && chmod 2775 /cases
mkdir -p /mnt/fw && chmod 755 /mnt/fw

# ------------------------------------------------------------------ OS packages
apt-get update -y
APT_PKGS=(
  build-essential python3-dev python3-venv python3-pip pipx git curl wget unzip p7zip-full jq ripgrep file xxd
  sleuthkit ewf-tools afflib-tools libewf-dev dc3dd dcfldd gddrescue testdisk foremost scalpel
  qemu-utils ntfs-3g exfatprogs dislocker cryptsetup lvm2 mdadm xfsprogs fuse3 parted
  yara binwalk libimage-exiftool-perl sqlite3 hashdeep ssdeep radare2 tshark
  libparse-win32registry-perl libdate-manip-perl
)
for p in "${APT_PKGS[@]}"; do
  dpkg -s "$p" >/dev/null 2>&1 || try "apt:$p" apt-get install -y "$p"
done
dpkg -s bulk-extractor >/dev/null 2>&1 || apt-get install -y bulk-extractor >/dev/null 2>&1 || log "bulk-extractor not packaged for this release; skipped"
grep -q '^user_allow_other' /etc/fuse.conf || echo user_allow_other >> /etc/fuse.conf

# ------------------------------------------------------------------ Python tools (isolated with pipx)
pipx_tool() { pipx list --short 2>/dev/null | grep -q "^$1 " || pipx install "${@:2}" "$1"; }
try "volatility3" pipx_tool volatility3
try "dissect"     pipx_tool dissect --include-deps
try "oletools"    pipx_tool oletools
try "regipy"      pipx_tool "regipy[cli]"
try "pyhindsight" pipx_tool pyhindsight
# Plaso: GIFT PPA packages first, pipx as the fallback.
install_plaso() {
  command -v log2timeline.py >/dev/null && return 0
  if add-apt-repository -y ppa:gift/stable && apt-get update -y && apt-get install -y plaso-tools; then return 0; fi
  pipx install plaso
}
try "plaso" install_plaso

# ------------------------------------------------------------------ release binaries from GitHub
# gh_asset owner/repo regex -> download URL of the newest release asset matching regex
gh_asset() {
  curl -fsSL "https://api.github.com/repos/$1/releases/latest" | jq -r --arg re "$2" '.assets[] | select(.name|test($re)) | .browser_download_url' | head -1
}
fetch() { local url; url=$(gh_asset "$1" "$2"); [ -n "$url" ] && curl -fsSL "$url" -o "$3"; }

install_chainsaw() {
  [ -x $BIN/chainsaw ] && return 0
  local t; t=$(mktemp -d)
  fetch WithSecureLabs/chainsaw 'x86_64-unknown-linux-gnu\.tar\.gz$' "$t/c.tgz" && tar -xzf "$t/c.tgz" -C "$t" || return 1
  install -m 755 "$(find "$t" -type f -name 'chainsaw*' -perm -u+x | head -1)" $BIN/chainsaw
  [ -d $FOR/chainsaw ] || git clone --depth 1 https://github.com/WithSecureLabs/chainsaw $FOR/chainsaw
}
install_hayabusa() {
  [ -x $BIN/hayabusa ] && return 0
  local t; t=$(mktemp -d)
  fetch Yamato-Security/hayabusa 'lin-x64-gnu\.zip$' "$t/h.zip" || return 1
  rm -rf $FOR/hayabusa && mkdir -p $FOR/hayabusa && unzip -q "$t/h.zip" -d $FOR/hayabusa
  local b; b=$(find $FOR/hayabusa -maxdepth 1 -type f -name 'hayabusa*lin*' | head -1)
  chmod 755 "$b" && ln -sfn "$b" $BIN/hayabusa
}
install_zip_bin() { # repo regex binary-name
  [ -x "$BIN/$3" ] && return 0
  local t; t=$(mktemp -d)
  fetch "$1" "$2" "$t/a.zip" && unzip -q "$t/a.zip" -d "$t" || return 1
  install -m 755 "$(find "$t" -type f -name "$3" | head -1)" "$BIN/$3"
}
install_raw_bin() { # repo regex binary-name
  [ -x "$BIN/$3" ] && return 0
  fetch "$1" "$2" "$BIN/$3" && chmod 755 "$BIN/$3"
}
try "chainsaw"     install_chainsaw
try "hayabusa"     install_hayabusa
try "capa"         install_zip_bin mandiant/capa '^capa-v[0-9.]+-linux\.zip$' capa
try "floss"        install_zip_bin mandiant/flare-floss '^floss-v[0-9.]+-linux\.zip$' floss
try "evtx_dump"    install_raw_bin omerbenamram/evtx '^evtx_dump-v[0-9.]+-x86_64-unknown-linux-gnu$' evtx_dump
try "velociraptor" install_raw_bin Velocidex/velociraptor 'linux-amd64$' velociraptor

# ------------------------------------------------------------------ Eric Zimmerman tools on .NET
install_dotnet() {
  [ -x /usr/share/dotnet/dotnet ] && return 0
  curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh &&
    bash /tmp/dotnet-install.sh --channel 9.0 --runtime dotnet --install-dir /usr/share/dotnet &&
    ln -sfn /usr/share/dotnet/dotnet /usr/local/bin/dotnet
}
EZ_TOOLS=(MFTECmd EvtxECmd RECmd PECmd LECmd JLECmd SBECmd AmcacheParser AppCompatCacheParser SrumECmd SQLECmd RBCmd WxTCmd bstrings)
install_ez() {
  local tool="$1" t dll
  [ -x "$BIN/$tool" ] && return 0
  t=$(mktemp -d)
  for net in net9 net6; do
    curl -fsSL "https://download.ericzimmerman.net/$net/$tool.zip" -o "$t/$tool.zip" && break
  done
  [ -s "$t/$tool.zip" ] || return 1
  unzip -qo "$t/$tool.zip" -d $FOR/eztools/ || return 1
  dll=$(find $FOR/eztools -name "$tool.dll" | head -1)
  [ -n "$dll" ] || return 1
  printf '#!/bin/sh\nexport DOTNET_ROLL_FORWARD=Major DOTNET_CLI_TELEMETRY_OPTOUT=1\nexec /usr/share/dotnet/dotnet "%s" "$@"\n' "$dll" > "$BIN/$tool"
  chmod 755 "$BIN/$tool"
}
try "dotnet runtime" install_dotnet
for t in "${EZ_TOOLS[@]}"; do try "eztools:$t" install_ez "$t"; done

# ------------------------------------------------------------------ detection content
clone_or_pull() { if [ -d "$2/.git" ]; then git -C "$2" pull -q --ff-only; else git clone -q --depth 1 "$1" "$2"; fi; }
try "sigma rules"          clone_or_pull https://github.com/SigmaHQ/sigma $FOR/rules/sigma
try "signature-base yara"  clone_or_pull https://github.com/Neo23x0/signature-base $FOR/rules/signature-base

# ------------------------------------------------------------------ Node and Claude Code
install_node() {
  command -v node >/dev/null && [ "$(node -v | cut -d. -f1 | tr -d v)" -ge 20 ] && return 0
  local base=https://nodejs.org/dist/latest-v22.x f
  f=$(curl -fsSL $base/SHASUMS256.txt | awk '/linux-x64\.tar\.xz$/{print $2}' | head -1)
  [ -n "$f" ] || return 1
  curl -fsSL "$base/$f" -o /tmp/node.tar.xz && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1
}
try "node 22" install_node
try "claude code" npm install -g @anthropic-ai/claude-code

# ------------------------------------------------------------------ forensic MCP server and helper
install_mcp() {
  rm -rf $FOR/mcp && cp -r "$MODULE_DIR/mcp" $FOR/mcp
  chown -R root:root $FOR/mcp && chmod -R go-w $FOR/mcp
  [ -d $FOR/mcp-venv ] || python3 -m venv $FOR/mcp-venv
  $FOR/mcp-venv/bin/pip install -q --upgrade pip
  $FOR/mcp-venv/bin/pip install -q $FOR/mcp
  install -m 755 -o root -g root $FOR/mcp/fw-helper /usr/local/sbin/fw-helper
  install -m 755 -o root -g root "$MODULE_DIR/scripts/fw-audit-hook" /usr/local/bin/fw-audit-hook
  install -m 755 -o root -g root "$MODULE_DIR/scripts/fw-anthropic-key" /usr/local/bin/fw-anthropic-key
  install -m 440 -o root -g root "$MODULE_DIR/config/sudoers-forensics" /etc/sudoers.d/forensics
  visudo -cf /etc/sudoers.d/forensics
}
try "forensic mcp server" install_mcp
mkdir -p /var/log/forensic-audit /run/fw/mounts
touch /var/log/forensic-audit/audit.jsonl
chown -R root:forensics /var/log/forensic-audit && chmod 2770 /var/log/forensic-audit && chmod 660 /var/log/forensic-audit/audit.jsonl
echo 'd /run/fw/mounts 0755 root root -' > /etc/tmpfiles.d/fw.conf

# ------------------------------------------------------------------ Claude Code configuration
configure_claude() {
  mkdir -p /etc/claude-code
  local env_json
  if [ "$CLAUDE_BACKEND" = "bedrock" ]; then
    env_json=$(jq -n --arg r "$BEDROCK_REGION" --arg m "$CLAUDE_MODEL" \
      '{CLAUDE_CODE_USE_BEDROCK:"1", AWS_REGION:$r, DISABLE_AUTOUPDATER:"1", DISABLE_TELEMETRY:"1"} + (if $m=="" then {} else {ANTHROPIC_MODEL:$m} end)')
  else
    env_json=$(jq -n --arg m "$CLAUDE_MODEL" '{DISABLE_AUTOUPDATER:"1", DISABLE_TELEMETRY:"1"} + (if $m=="" then {} else {ANTHROPIC_MODEL:$m} end)')
  fi
  jq --argjson env "$env_json" --arg backend "$CLAUDE_BACKEND" \
    '.env = $env | if $backend=="anthropic" then .apiKeyHelper="/usr/local/bin/fw-anthropic-key" else . end' \
    "$MODULE_DIR/config/claude/managed-settings.json" > /etc/claude-code/managed-settings.json
  chmod 644 /etc/claude-code/managed-settings.json

  local home=/home/analyst
  install -d -m 700 -o analyst -g analyst $home/.claude
  install -m 644 -o analyst -g analyst "$MODULE_DIR/config/claude/CLAUDE.md" $home/.claude/CLAUDE.md
  sudo -u analyst -H bash -lc 'claude mcp remove --scope user forensics >/dev/null 2>&1; claude mcp add --scope user forensics -- /opt/forensics/mcp-venv/bin/fw-forensics-mcp' ||
    sudo -u analyst -H bash -c 'f=$HOME/.claude.json; [ -s "$f" ] || echo "{}" > "$f"; jq ".mcpServers.forensics={type:\"stdio\",command:\"/opt/forensics/mcp-venv/bin/fw-forensics-mcp\",args:[]}" "$f" > "$f.tmp" && mv "$f.tmp" "$f"'
  cat > /etc/profile.d/forensics.sh <<'EOF'
export PATH=/opt/forensics/bin:$PATH
export TZ=UTC
[ "$(id -un)" = analyst ] && [ -d /cases ] && [ "$PWD" = "$HOME" ] && cd /cases
EOF
  # Weekly: update Claude Code and detection content.
  cat > /etc/cron.d/forensics-update <<'EOF'
17 6 * * 0 root npm install -g @anthropic-ai/claude-code@latest >/var/log/forensics-update.log 2>&1; git -C /opt/forensics/rules/sigma pull -q; git -C /opt/forensics/rules/signature-base pull -q
EOF
}
try "claude configuration" configure_claude

# ------------------------------------------------------------------ ship audit log to CloudWatch
install_cwagent() {
  dpkg -s amazon-cloudwatch-agent >/dev/null 2>&1 || {
    curl -fsSL https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb -o /tmp/cwa.deb && dpkg -i /tmp/cwa.deb; } || return 1
  cat > /opt/aws/amazon-cloudwatch-agent/etc/forensics.json <<EOF
{"logs":{"logs_collected":{"files":{"collect_list":[
  {"file_path":"/var/log/forensic-audit/audit.jsonl","log_group_name":"$AUDIT_LOG_GROUP","log_stream_name":"{instance_id}/audit"},
  {"file_path":"/var/log/forensic-provision.log","log_group_name":"$AUDIT_LOG_GROUP","log_stream_name":"{instance_id}/provision"}
]}}}}
EOF
  /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/forensics.json
}
try "cloudwatch agent" install_cwagent

# ------------------------------------------------------------------ optional desktop (RDP over SSM port forwarding)
install_desktop() {
  apt-get install -y xfce4 xfce4-goodies xrdp dbus-x11 wireshark || return 1
  echo xfce4-session > /home/analyst/.xsession && chown analyst:analyst /home/analyst/.xsession
  adduser xrdp ssl-cert >/dev/null
  # Listen on localhost only; SSM port forwarding reaches it, nothing else can.
  sed -i 's/^port=3389$/port=tcp:\/\/127.0.0.1:3389/' /etc/xrdp/xrdp.ini
  systemctl enable --now xrdp
}
[ "$ENABLE_DESKTOP" = "true" ] && try "desktop" install_desktop

# ------------------------------------------------------------------ verify and report
bash "$MODULE_DIR/scripts/verify-tools.sh" > $FOR/INVENTORY.txt 2>&1
{
  echo "Vendetta forensic workstation (provisioned $(date -u +%FT%TZ))"
  echo "Start Claude: claude    Cases: /cases    Tools: /opt/forensics/INVENTORY.txt"
  if [ -s "$FAILS" ]; then echo "Components that failed to install:"; sed 's/^/  - /' "$FAILS"; fi
} > /etc/motd
log "provisioning complete"
