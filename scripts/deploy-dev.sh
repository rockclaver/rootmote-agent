#!/usr/bin/env bash
# Build the agent from the current working tree and install it on a remote
# VPS over SSH. Used during development to roll out unreleased changes
# without waiting for a tagged release — the binary AND the systemd unit /
# sudoers / tmpfiles fragments under systemd/, since a code change that
# needs a matching config change (e.g. a new sudoers rule) is silently
# incomplete if only the binary gets pushed.
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
BIN="$OUT/rootmote-agent"

echo "[deploy] building linux/$ARCH from $ROOT"
(cd "$ROOT" && GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -o "$BIN" ./cmd/rootmote-agent)

SERVICE_SRC="$ROOT/systemd/rootmote-agent.service"
SUDOERS_SRC="$ROOT/systemd/rootmote-agent.sudoers"
TMPFILES_SRC="$ROOT/systemd/rootmote-agent-sudo.tmpfiles.conf"

# Stage the files in a private directory (mktemp -d is mode 0700 and owned by
# the SSH user) so no other local user can swap a file before the root-run
# `install` copies it.
STAGE="$(ssh "$TARGET" 'mktemp -d')"
case "$STAGE" in
  /*) ;;
  *) echo "could not create a staging directory on $TARGET" >&2; exit 1 ;;
esac

echo "[deploy] copying binary + systemd/sudoers/tmpfiles fragments to $TARGET:$STAGE"
scp -q "$BIN" "$SERVICE_SRC" "$SUDOERS_SRC" "$TMPFILES_SRC" "$TARGET:$STAGE/"

echo "[deploy] installing binary + config fragments on $TARGET"
ssh "$TARGET" "
  set -euo pipefail
  trap 'rm -rf \"$STAGE\"' EXIT
  # Check the sudo rule first. If it is broken, change nothing.
  $SUDO install -m 0440 \"$STAGE/rootmote-agent.sudoers\" /etc/sudoers.d/rootmote-agent.new
  if ! $SUDO visudo -c -f /etc/sudoers.d/rootmote-agent.new >/dev/null; then
    $SUDO rm -f /etc/sudoers.d/rootmote-agent.new
    echo 'rootmote-agent sudoers rule failed visudo check; nothing was installed' >&2
    exit 1
  fi
  $SUDO install -m 0755 \"$STAGE/rootmote-agent\" /usr/local/bin/rootmote-agent
  $SUDO install -m 0644 \"$STAGE/rootmote-agent.service\" /etc/systemd/system/rootmote-agent.service
  $SUDO install -m 0644 \"$STAGE/rootmote-agent-sudo.tmpfiles.conf\" /etc/tmpfiles.d/rootmote-agent-sudo.conf
  $SUDO systemd-tmpfiles --create /etc/tmpfiles.d/rootmote-agent-sudo.conf
  $SUDO mv /etc/sudoers.d/rootmote-agent.new /etc/sudoers.d/rootmote-agent
  $SUDO rm -f /etc/sudoers.d/rootmote-agent-firewall
  $SUDO systemctl daemon-reload
  $SUDO systemctl restart rootmote-agent
"

echo "[deploy] installed version on $TARGET:"
ssh "$TARGET" "/usr/local/bin/rootmote-agent --version"

echo "[deploy] ok"
