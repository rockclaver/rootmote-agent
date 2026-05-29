#!/usr/bin/env bash
# Build the agent from the current working tree and install it on a remote
# VPS over SSH. Used during development to roll out unreleased changes
# without waiting for a tagged release.
#
# Usage:
#   agent/scripts/deploy-dev.sh <ssh-target> [--arch amd64|arm64] [--sudo]
#
# Examples:
#   agent/scripts/deploy-dev.sh root@vps.example.com
#   agent/scripts/deploy-dev.sh me@vps.example.com --sudo
#   agent/scripts/deploy-dev.sh me@vps.example.com --arch arm64 --sudo
#
# --arch is auto-detected from `uname -m` on the target when omitted.
# --sudo prefixes the remote install/restart commands with `sudo` (needed
# when the SSH user is not root).

set -euo pipefail

if [[ $# -lt 1 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '2,18p' "$0"
  [[ $# -lt 1 ]] && exit 2 || exit 0
fi

TARGET="$1"
shift
ARCH=""
SUDO=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch) ARCH="$2"; shift 2 ;;
    --sudo) SUDO="sudo"; shift ;;
    -h|--help)
      sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -z "$ARCH" ]]; then
  echo "[deploy] probing remote arch on $TARGET"
  remote_uname="$(ssh "$TARGET" uname -m)"
  case "$remote_uname" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)
      echo "unsupported remote arch: $remote_uname" >&2
      echo "pass --arch amd64|arm64 explicitly" >&2
      exit 1 ;;
  esac
fi

case "$ARCH" in
  amd64|arm64) ;;
  *) echo "--arch must be amd64 or arm64, got: $ARCH" >&2; exit 2 ;;
esac

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
BIN="$OUT/claver-agent"

echo "[deploy] building linux/$ARCH from $ROOT"
(cd "$ROOT" && GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -o "$BIN" ./cmd/claver-agent)

echo "[deploy] copying binary to $TARGET:/tmp/claver-agent"
scp -q "$BIN" "$TARGET:/tmp/claver-agent"

echo "[deploy] installing + restarting claver-agent on $TARGET"
ssh "$TARGET" "$SUDO install -m 0755 /tmp/claver-agent /usr/local/bin/claver-agent \
  && $SUDO systemctl restart claver-agent \
  && rm -f /tmp/claver-agent"

echo "[deploy] installed version on $TARGET:"
ssh "$TARGET" "/usr/local/bin/claver-agent --version"

echo "[deploy] ok"
