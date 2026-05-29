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

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

url="${RELEASE_BASE}/v${VERSION}/claver-agent-linux-${arch}"
echo "downloading $url" >&2
curl -fsSL "$url" -o "$tmp/claver-agent"
chmod 0755 "$tmp/claver-agent"
install -m 0755 "$tmp/claver-agent" "$BIN_DST"

# Install systemd unit. The unit file is expected next to this script when
# invoked locally during development, or fetched from the release otherwise.
if [[ -f "$(dirname "$0")/../systemd/claver-agent.service" ]]; then
  install -m 0644 "$(dirname "$0")/../systemd/claver-agent.service" "$UNIT_DST"
else
  curl -fsSL "${RELEASE_BASE}/v${VERSION}/claver-agent.service" -o "$UNIT_DST"
  chmod 0644 "$UNIT_DST"
fi

systemctl daemon-reload
systemctl enable claver-agent.service
# `enable --now` only starts inactive units; on re-install we have just
# overwritten the binary, so restart unconditionally to pick it up.
systemctl restart claver-agent.service

# Phase 1 AC: print installed version to stdout.
"$BIN_DST" --version
