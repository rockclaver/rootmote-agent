#!/usr/bin/env bash
# Claver VPS agent installer.
#
# Idempotent. Designed to be invoked over SSH by the mobile app as:
#     curl -fsSL https://.../install.sh | sudo bash -s -- --version 0.1.0
#
# Steps:
#   1. Ensure a `claver` system user exists.
#   2. Download the agent binary for the host arch.
#   3. Install the systemd unit.
#   4. Enable + start the service.
#   5. Print the installed version to stdout (Phase 1 acceptance criterion).

set -euo pipefail

VERSION="${VERSION:-0.1.0}"
RELEASE_BASE="${RELEASE_BASE:-https://github.com/rockclaver/claver/releases/download}"
BIN_DST="/usr/local/bin/claver-agent"
UNIT_DST="/etc/systemd/system/claver-agent.service"
STATE_DIR="/var/lib/claver"
CADDYFILE="/etc/caddy/Caddyfile"
CADDY_FRAGMENTS_DIR="/etc/caddy/claver"
CADDY_IMPORT_LINE="import ${CADDY_FRAGMENTS_DIR}/*.caddy"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --release-base) RELEASE_BASE="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "install.sh must run as root (use sudo)" >&2
  exit 1
fi

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

if ! id claver >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE_DIR" --create-home --shell /usr/sbin/nologin claver
fi
install -d -o claver -g claver -m 0750 "$STATE_DIR"

if ! command -v gh >/dev/null 2>&1; then
  echo "installing GitHub CLI" >&2
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    if ! apt-get install -y gh; then
      apt-get install -y curl gpg
      install -d -m 0755 /etc/apt/keyrings
      curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        -o /etc/apt/keyrings/githubcli-archive-keyring.gpg
      chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list
      apt-get update
      apt-get install -y gh
    fi
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y 'dnf-command(config-manager)' || true
    dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo || true
    dnf install -y gh
  else
    echo "warning: no supported package manager found; install GitHub CLI manually" >&2
  fi
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

url="${RELEASE_BASE}/v${VERSION}/claver-agent-linux-${arch}"
echo "downloading $url" >&2
if ! curl -fsSL "$url" -o "$tmp/claver-agent"; then
  echo "failed to download claver-agent ${VERSION} for linux-${arch}" >&2
  echo "expected release asset: $url" >&2
  exit 1
fi
chmod 0755 "$tmp/claver-agent"
install -m 0755 "$tmp/claver-agent" "$BIN_DST"

# Install systemd unit. The unit file is expected next to this script when
# invoked locally during development, or fetched from the release otherwise.
if [[ -f "$(dirname "$0")/../systemd/claver-agent.service" ]]; then
  install -m 0644 "$(dirname "$0")/../systemd/claver-agent.service" "$UNIT_DST"
else
  unit_url="${RELEASE_BASE}/v${VERSION}/claver-agent.service"
  if ! curl -fsSL "$unit_url" -o "$UNIT_DST"; then
    echo "failed to download claver-agent systemd unit" >&2
    echo "expected release asset: $unit_url" >&2
    exit 1
  fi
  chmod 0644 "$UNIT_DST"
fi

systemctl daemon-reload
systemctl enable claver-agent.service
# `enable --now` only starts inactive units; on re-install we have just
# overwritten the binary, so restart unconditionally to pick it up.
systemctl restart claver-agent.service

# --- Phase 7: Caddy for live previews -------------------------------------
# Install Caddy if absent. The agent writes per-preview fragments into
# /etc/caddy/claver/*.caddy; the main Caddyfile must `import` that glob.
if ! command -v caddy >/dev/null 2>&1; then
  echo "installing caddy" >&2
  if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg
    curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
      | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
      > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update
    apt-get install -y caddy
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y 'dnf-command(copr)'
    dnf copr enable -y @caddy/caddy
    dnf install -y caddy
  else
    echo "warning: no supported package manager found; install caddy manually" >&2
  fi
fi

# Owned by the agent user so the agent can write per-preview fragments, with
# the caddy group + setgid bit so new files inherit group=caddy and the caddy
# daemon can read them. Falls back gracefully if either user is missing.
if id claver >/dev/null 2>&1 && getent group caddy >/dev/null 2>&1; then
  install -d -o claver -g caddy -m 2750 "$CADDY_FRAGMENTS_DIR"
elif id claver >/dev/null 2>&1; then
  install -d -o claver -g claver -m 0755 "$CADDY_FRAGMENTS_DIR"
else
  install -d -m 0755 "$CADDY_FRAGMENTS_DIR"
fi

# Ensure the main Caddyfile exists and imports our fragments glob. The check
# is intentionally a literal grep so re-runs of the installer are idempotent.
if [[ ! -f "$CADDYFILE" ]]; then
  mkdir -p "$(dirname "$CADDYFILE")"
  cat > "$CADDYFILE" <<EOF
# Managed by claver-agent installer.
# Per-preview reverse-proxy site blocks live in $CADDY_FRAGMENTS_DIR.
$CADDY_IMPORT_LINE
EOF
elif ! grep -Fq "$CADDY_IMPORT_LINE" "$CADDYFILE"; then
  printf '\n# Added by claver-agent installer.\n%s\n' "$CADDY_IMPORT_LINE" >> "$CADDYFILE"
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now caddy 2>/dev/null || true
  systemctl reload caddy 2>/dev/null || systemctl restart caddy 2>/dev/null || true
fi

# Phase 1 AC: print installed version to stdout.
"$BIN_DST" --version
