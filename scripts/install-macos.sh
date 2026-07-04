#!/usr/bin/env bash
# Rootmote macOS agent installer.
#
# Installs the agent as a per-user launchd LaunchAgent. Do not run this script
# with sudo: Claude, Codex, GitHub CLI auth, transcripts, and installed skills
# should live under the same macOS account that Rootmote reaches over SSH.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/rockclaver/rootmote-agent/main/scripts/install-macos.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/rockclaver/rootmote-agent/main/scripts/install-macos.sh | bash -s -- --version 0.1.2

set -euo pipefail

VERSION="${VERSION:-latest}"
RELEASE_BASE="${RELEASE_BASE:-https://github.com/rockclaver/rootmote-agent/releases/download}"
RELEASES_LATEST_URL="${RELEASES_LATEST_URL:-https://github.com/rockclaver/rootmote-agent/releases/latest}"
LABEL="${LABEL:-com.rockclaver.rootmote-agent}"
ADDR="${ADDR:-127.0.0.1:7676}"
DATA_DIR="${DATA_DIR:-$HOME/Library/Application Support/RootmoteAgent}"
BIN_DIR="$DATA_DIR/bin"
BIN_DST="$BIN_DIR/rootmote-agent"
FRAGMENTS_DIR="$DATA_DIR/caddy-fragments"
LOG_DIR="$HOME/Library/Logs/RootmoteAgent"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_DST="$PLIST_DIR/$LABEL.plist"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --release-base) RELEASE_BASE="$2"; shift 2 ;;
    --addr) ADDR="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

BIN_DIR="$DATA_DIR/bin"
BIN_DST="$BIN_DIR/rootmote-agent"
FRAGMENTS_DIR="$DATA_DIR/caddy-fragments"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "install-macos.sh only supports macOS. Use scripts/install.sh on Linux." >&2
  exit 1
fi

if [[ "$(id -u)" -eq 0 ]]; then
  echo "install-macos.sh must run as the target macOS user, not root." >&2
  echo "Do not use sudo; this installer creates a per-user LaunchAgent." >&2
  exit 1
fi

if [[ "$ADDR" != 127.0.0.1:* && "$ADDR" != localhost:* && "$ADDR" != "[::1]:"* && "$ADDR" != "::1:"* ]]; then
  echo "refusing non-loopback --addr $ADDR" >&2
  exit 1
fi

if [[ "$VERSION" == "latest" ]]; then
  echo "resolving latest rootmote-agent release" >&2
  resolved="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$RELEASES_LATEST_URL" || true)"
  VERSION="${resolved##*/tag/v}"
  if [[ -z "$VERSION" || "$VERSION" == "$resolved" ]]; then
    echo "failed to resolve latest release from $RELEASES_LATEST_URL" >&2
    echo "pass --version X.Y.Z to pin a specific release" >&2
    exit 1
  fi
  echo "latest release: v${VERSION}" >&2
fi

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "unsupported macOS arch: $arch" >&2; exit 1 ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

url="${RELEASE_BASE}/v${VERSION}/rootmote-agent-darwin-${arch}"
echo "downloading $url" >&2
if ! curl -fsSL "$url" -o "$tmp/rootmote-agent"; then
  echo "failed to download rootmote-agent ${VERSION} for darwin-${arch}" >&2
  echo "expected release asset: $url" >&2
  exit 1
fi
chmod 0755 "$tmp/rootmote-agent"

install -d -m 0700 "$DATA_DIR" "$BIN_DIR" "$FRAGMENTS_DIR" "$LOG_DIR" "$PLIST_DIR"
install -m 0755 "$tmp/rootmote-agent" "$BIN_DST"

xml_escape() {
  local value="$1"
  value="${value//&/&amp;}"
  value="${value//</&lt;}"
  value="${value//>/&gt;}"
  printf '%s' "$value"
}

bin_xml="$(xml_escape "$BIN_DST")"
addr_xml="$(xml_escape "$ADDR")"
data_xml="$(xml_escape "$DATA_DIR")"
fragments_xml="$(xml_escape "$FRAGMENTS_DIR")"
home_xml="$(xml_escape "$HOME")"
path_xml="$(xml_escape "$BIN_DIR:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")"
stdout_xml="$(xml_escape "$LOG_DIR/agent.log")"
stderr_xml="$(xml_escape "$LOG_DIR/agent.err.log")"

cat > "$PLIST_DST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$bin_xml</string>
    <string>--addr</string>
    <string>$addr_xml</string>
    <string>--data-dir</string>
    <string>$data_xml</string>
    <string>--caddy-fragments-dir</string>
    <string>$fragments_xml</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>$home_xml</string>
    <key>PATH</key>
    <string>$path_xml</string>
  </dict>
  <key>WorkingDirectory</key>
  <string>$data_xml</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$stdout_xml</string>
  <key>StandardErrorPath</key>
  <string>$stderr_xml</string>
</dict>
</plist>
EOF
chmod 0644 "$PLIST_DST"
if command -v plutil >/dev/null 2>&1; then
  plutil -lint "$PLIST_DST" >/dev/null
fi

uid="$(id -u)"
domain="gui/$uid"
if ! launchctl print "$domain" >/dev/null 2>&1; then
  domain="user/$uid"
fi

# --- Legacy cutover ---------------------------------------------------------
# Old installs used the claver-agent label; a survivor holding the loopback
# port would leave the new agent unable to bind. Retire it, then clear any
# remaining listener on the agent port.
LEGACY_LABEL="com.rockclaver.claver-agent"
LEGACY_PLIST="$PLIST_DIR/$LEGACY_LABEL.plist"
if [[ -f "$LEGACY_PLIST" ]]; then
  echo "retiring legacy $LEGACY_LABEL LaunchAgent" >&2
  launchctl bootout "$domain" "$LEGACY_PLIST" >/dev/null 2>&1 || true
  rm -f "$LEGACY_PLIST"
fi
if [[ -d "$HOME/Library/Application Support/ClaverAgent" ]]; then
  echo "note: legacy agent state in ~/Library/Application Support/ClaverAgent was" >&2
  echo "      left untouched; see 'Migrating from claver-agent' in the README." >&2
fi
agent_port="${ADDR##*:}"
listeners="$(lsof -nP -tiTCP:"$agent_port" -sTCP:LISTEN 2>/dev/null || true)"
if [[ -n "$listeners" ]]; then
  echo "killing processes holding 127.0.0.1:$agent_port: $listeners" >&2
  kill $listeners 2>/dev/null || true
  sleep 2
  still="$(lsof -nP -tiTCP:"$agent_port" -sTCP:LISTEN 2>/dev/null || true)"
  if [[ -n "$still" ]]; then
    kill -9 $still 2>/dev/null || true
  fi
fi

launchctl bootout "$domain" "$PLIST_DST" >/dev/null 2>&1 || true
launchctl bootstrap "$domain" "$PLIST_DST"
launchctl enable "$domain/$LABEL" >/dev/null 2>&1 || true
launchctl kickstart -k "$domain/$LABEL" >/dev/null 2>&1 || true

echo "installed rootmote-agent:"
"$BIN_DST" --version
echo "launchd service: $domain/$LABEL"
echo "data dir: $DATA_DIR"
echo "logs: $LOG_DIR"

local_name="$(scutil --get LocalHostName 2>/dev/null || true)"
if [[ -n "$local_name" ]]; then
  echo "Rootmote local host: ${local_name}.local"
fi
for iface in en0 en1; do
  if ip="$(ipconfig getifaddr "$iface" 2>/dev/null)"; then
    echo "Rootmote LAN IP ($iface): $ip"
  fi
done
echo "Use SSH port 22 and your macOS username. Remote Login must be enabled."
