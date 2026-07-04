#!/usr/bin/env bash
# Build the agent from the current working tree and install it into the local
# per-user macOS LaunchAgent. This is the macOS equivalent of deploy-dev.sh:
# use it to validate unreleased changes on a MacBook before cutting a tag.
#
# Usage:
#   scripts/deploy-macos-local.sh
#   scripts/deploy-macos-local.sh --addr 127.0.0.1:7677 --data-dir /tmp/rootmote-agent-dev
#   scripts/deploy-macos-local.sh --skip-probe

set -euo pipefail

LABEL="${LABEL:-com.rockclaver.rootmote-agent}"
ADDR="${ADDR:-127.0.0.1:7676}"
DATA_DIR="${DATA_DIR:-$HOME/Library/Application Support/RootmoteAgent}"
SKIP_PROBE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --addr) ADDR="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    --skip-probe) SKIP_PROBE=1; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "deploy-macos-local.sh only supports macOS." >&2
  exit 1
fi

if [[ "$(id -u)" -eq 0 ]]; then
  echo "deploy-macos-local.sh must run as the target macOS user, not root." >&2
  exit 1
fi

if [[ "$ADDR" != 127.0.0.1:* && "$ADDR" != localhost:* && "$ADDR" != "[::1]:"* && "$ADDR" != "::1:"* ]]; then
  echo "refusing non-loopback --addr $ADDR" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$DATA_DIR/bin"
BIN_DST="$BIN_DIR/rootmote-agent"
FRAGMENTS_DIR="$DATA_DIR/caddy-fragments"
LOG_DIR="$HOME/Library/Logs/RootmoteAgent"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_DST="$PLIST_DIR/$LABEL.plist"

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "unsupported macOS arch: $arch" >&2; exit 1 ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "[deploy] building darwin/$arch from $ROOT"
short_sha="$(cd "$ROOT" && git rev-parse --short HEAD 2>/dev/null || echo local)"
dirty=""
if [[ -n "$(cd "$ROOT" && git status --porcelain 2>/dev/null)" ]]; then
  dirty="-dirty"
fi
version="dev-${short_sha}${dirty}"
(cd "$ROOT" && GOOS=darwin GOARCH="$arch" CGO_ENABLED=0 go build \
  -ldflags "-X github.com/rockclaver/rootmote-agent/internal/version.Version=${version}" \
  -o "$tmp/rootmote-agent" ./cmd/rootmote-agent)

echo "[deploy] installing binary to $BIN_DST"
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

echo "[deploy] restarting launchd service $domain/$LABEL"
launchctl bootout "$domain" "$PLIST_DST" >/dev/null 2>&1 || true
launchctl bootstrap "$domain" "$PLIST_DST"
launchctl enable "$domain/$LABEL" >/dev/null 2>&1 || true
launchctl kickstart -k "$domain/$LABEL" >/dev/null 2>&1 || true

echo "[deploy] installed version:"
"$BIN_DST" --version

if [[ "$SKIP_PROBE" -eq 0 && -x "$(command -v node || true)" ]]; then
  echo "[deploy] probing agent websocket on $ADDR"
  ADDR="$ADDR" node <<'JS'
const addr = process.env.ADDR;
const requests = [
  ["server.health", {}],
  ["infra.service.list", {}],
  ["infra.webserver.list", {}],
  ["infra.firewall.status", {}],
  ["infra.process.list", { sort: "cpu", limit: 5 }],
];
let idx = 0;
let start = 0;
const ws = new WebSocket(`ws://${addr}/ws`);
const timeout = setTimeout(() => {
  console.error("[probe] timeout");
  process.exit(2);
}, 45000);

ws.addEventListener("open", sendNext);
ws.addEventListener("message", (event) => {
  const data = JSON.parse(String(event.data));
  if (!data.id || !data.id.startsWith("deploy-probe-")) return;
  const ms = Date.now() - start;
  if (data.kind.startsWith("error.")) {
    console.log(`[probe] ${data.id} ${ms}ms ${data.kind} ${JSON.stringify(data.payload)}`);
  } else if (data.kind === "server.health") {
    console.log(`[probe] health ${ms}ms version=${data.payload?.version ?? "unknown"}`);
  } else if (data.kind === "infra.service.list") {
    console.log(`[probe] services ${ms}ms available=${data.payload?.available} count=${(data.payload?.units ?? []).length}`);
  } else if (data.kind === "infra.webserver.list") {
    console.log(`[probe] webservers ${ms}ms available=${data.payload?.available} count=${(data.payload?.webservers ?? []).length}`);
  } else if (data.kind === "infra.firewall.status") {
    console.log(`[probe] firewall ${ms}ms backend=${data.payload?.backend} sockets=${(data.payload?.sockets ?? []).length}`);
  } else if (data.kind === "infra.process.list") {
    console.log(`[probe] processes ${ms}ms count=${(data.payload?.processes ?? []).length}`);
  }
  sendNext();
});
ws.addEventListener("error", (err) => {
  clearTimeout(timeout);
  console.error("[probe] websocket error", err.message || err);
  process.exit(1);
});

function sendNext() {
  if (idx >= requests.length) {
    clearTimeout(timeout);
    ws.close();
    return;
  }
  const [kind, payload] = requests[idx++];
  start = Date.now();
  ws.send(JSON.stringify({
    id: `deploy-probe-${idx}-${Date.now()}`,
    kind,
    payload,
  }));
}
JS
fi

echo "[deploy] ok"
