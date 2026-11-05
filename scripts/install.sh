#!/bin/sh
# Rootmote VPS agent installer.
#
# Idempotent. The mobile app runs it over SSH, pinned to one release:
#     curl -fsSL https://raw.githubusercontent.com/rockclaver/rootmote-agent/<tag>/scripts/install.sh \
#       | sudo ROOTMOTE_AGENT_VERSION=<tag> sh
#
# ROOTMOTE_AGENT_VERSION is required and must be a release tag such as v0.2.0.
# Every file is downloaded from that release and checked against the release's
# SHA256SUMS before it is installed. A mismatch stops the install.
#
# ROOTMOTE_AGENT_BASE_URL replaces the download directory (default
# https://github.com/rockclaver/rootmote-agent/releases/download/<tag>). It is
# meant for local testing: it must serve the release files and SHA256SUMS.
#
# Steps:
#   1. Check the version tag, then download and verify the release files.
#   2. Ensure a `rootmote` system user exists.
#   3. Install the binary and the systemd unit.
#   4. Retire any legacy claver-agent unit and kill whatever still holds the
#      agent port (7676), so the new service can bind.
#   5. Enable + start the service.
#   6. Print the installed version to stdout.

set -eu

BIN_DST="/usr/local/bin/rootmote-agent"
UNIT_DST="/etc/systemd/system/rootmote-agent.service"
STATE_DIR="/var/lib/rootmote"

die() {
  echo "$*" >&2
  exit 1
}

VERSION="${ROOTMOTE_AGENT_VERSION:-}"
# The value must be exactly one tag like v0.2.0. The checks below look at the
# whole string (not line by line), so a value with a newline cannot slip by.
case "$VERSION" in
  v*.*.*) ;;
  *) die "ROOTMOTE_AGENT_VERSION must be a release tag like v0.2.0." ;;
esac
case "${VERSION#v}" in
  ""|*[!0-9.]*|.*|*.|*..*|*.*.*.*) die "ROOTMOTE_AGENT_VERSION must be a release tag like v0.2.0." ;;
esac

BASE_URL="${ROOTMOTE_AGENT_BASE_URL:-https://github.com/rockclaver/rootmote-agent/releases/download/${VERSION}}"
BASE_URL="${BASE_URL%/}"

# sha256_of prints the SHA-256 of a file using whichever tool the host has.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "Cannot check downloads: neither sha256sum nor shasum is installed."
  fi
}

# verify_file NAME PATH checks PATH against the SHA256SUMS entry for NAME.
# A missing entry or a different hash stops the whole install.
verify_file() {
  name="$1"
  path="$2"
  expected="$(awk -v f="$name" '$2 == f || $2 == "*" f { print $1; exit }' "$TMP/SHA256SUMS")"
  if [ -z "$expected" ]; then
    die "Checksum mismatch for ${name}: refusing to install."
  fi
  actual="$(sha256_of "$path")"
  if [ "$actual" != "$expected" ]; then
    die "Checksum mismatch for ${name}: refusing to install."
  fi
}

# fetch NAME DEST downloads NAME from the release into DEST and verifies it.
# Returns 1 when the download itself fails; a checksum mismatch exits.
fetch() {
  name="$1"
  dest="$2"
  if ! curl -fsSL "${BASE_URL}/${name}" -o "$dest"; then
    return 1
  fi
  verify_file "$name" "$dest"
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; [ -z "${SUDOERS_DST:-}" ] || rm -f "$SUDOERS_DST.new"' EXIT

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported arch: $arch" ;;
esac

echo "downloading ${BASE_URL}/SHA256SUMS" >&2
if ! curl -fsSL "${BASE_URL}/SHA256SUMS" -o "$TMP/SHA256SUMS"; then
  die "failed to download SHA256SUMS for rootmote-agent ${VERSION}; refusing to install."
fi

BIN_NAME="rootmote-agent-linux-${arch}"
echo "downloading ${BASE_URL}/${BIN_NAME}" >&2
if ! fetch "$BIN_NAME" "$TMP/rootmote-agent"; then
  die "failed to download rootmote-agent ${VERSION} for linux-${arch} (${BASE_URL}/${BIN_NAME})"
fi
chmod 0755 "$TMP/rootmote-agent"

if ! fetch rootmote-agent.service "$TMP/rootmote-agent.service"; then
  die "failed to download the rootmote-agent systemd unit (${BASE_URL}/rootmote-agent.service)"
fi

if [ "$(id -u)" -ne 0 ]; then
  die "install.sh must run as root (use sudo)"
fi

# Install the sudoers rule so the agent (running as `rootmote`) can call the
# privilege helper through `sudo -n`. Check it before anything else changes:
# a broken or missing rule stops the install and leaves the running agent
# alone. visudo --check also makes sure we never lay down a file that could
# lock out sudo entirely.
SUDOERS_DST="/etc/sudoers.d/rootmote-agent"
if ! fetch rootmote-agent.sudoers "$TMP/rootmote-agent.sudoers"; then
  die "failed to download the rootmote-agent sudo rule (${BASE_URL}/rootmote-agent.sudoers). Nothing was installed and the current agent was left running."
fi
install -m 0440 "$TMP/rootmote-agent.sudoers" "$SUDOERS_DST.new"
if ! visudo -c -f "$SUDOERS_DST.new" >/dev/null 2>&1; then
  rm -f "$SUDOERS_DST.new"
  die "The rootmote-agent sudo rule did not pass visudo, so nothing was installed. The current agent was left running."
fi

if ! id rootmote >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE_DIR" --create-home --shell /usr/sbin/nologin rootmote
fi

# The agent reads and restarts Docker containers through the Docker socket
# (monitoring, discovery, container.restart, disk.docker_prune), which only
# root and the `docker` group may open. Add `rootmote` to that group when it
# exists. Docker group access is equal to root on the host; this is the one
# deliberate widening besides the sudoers rule, and only on servers that run
# Docker. Re-running the installer after Docker is installed adds it then.
if getent group docker >/dev/null 2>&1; then
  usermod -aG docker rootmote
fi
# Earlier versions also put `rootmote` in the `adm` group (it can read
# /var/log/auth.log) and created .claude and .codex skill folders. Neither is
# used any more: take the group away again and remove those folders when they
# hold nothing (rmdir never deletes a folder that has files in it).
if id -nG rootmote 2>/dev/null | tr ' ' '\n' | grep -qx adm; then
  gpasswd -d rootmote adm >/dev/null
fi
rmdir "$STATE_DIR/.claude/skills" "$STATE_DIR/.claude" \
  "$STATE_DIR/.codex/skills" "$STATE_DIR/.codex" 2>/dev/null || true
install -d -o rootmote -g rootmote -m 0750 "$STATE_DIR"

install -m 0755 "$TMP/rootmote-agent" "$BIN_DST"
install -m 0644 "$TMP/rootmote-agent.service" "$UNIT_DST"

# The sudoers rule was checked and staged above, before anything else was
# changed. The file holds exactly one rule:
#   rootmote ALL=(root) NOPASSWD: /usr/local/bin/rootmote-agent priv *
# The helper validates every argument itself, as root.
mv "$SUDOERS_DST.new" "$SUDOERS_DST"
# Older versions installed broad sudo rules (ufw, firewall-cmd, kill, reboot,
# storage-rm, ...). Remove them: the single rule above replaces all of them.
rm -f /etc/sudoers.d/rootmote-agent-firewall

# Install the /run/sudo tmpfiles fragment: sudo needs to create its own
# timestamp directory there on every call (even with NOPASSWD), and
# ProtectSystem=strict in the unit above makes /run read-only unless this
# path is pre-created and listed in ReadWritePaths=. Apply it immediately
# (not just at next boot) so an existing deployment doesn't need a reboot
# for fixes that need root to start working.
TMPFILES_DST="/etc/tmpfiles.d/rootmote-agent-sudo.conf"
if fetch rootmote-agent-sudo.tmpfiles.conf "$TMP/rootmote-agent-sudo.tmpfiles.conf"; then
  install -m 0644 "$TMP/rootmote-agent-sudo.tmpfiles.conf" "$TMPFILES_DST"
else
  echo "warning: rootmote-agent-sudo tmpfiles fragment not found; fixes that need root may fail until /run/sudo is created" >&2
fi
if [ -f "$TMPFILES_DST" ] && command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --create "$TMPFILES_DST"
fi

# --- Legacy cutover ---------------------------------------------------------
# Old installs ran `claver-agent` on the same loopback port; any process still
# holding it leaves the new unit crash-looping on bind (the exact "Agent not
# installed" loop the app shows). Retire the legacy unit for good, then clear
# any remaining listener on the agent port before starting ours.
AGENT_PORT="${AGENT_PORT:-7676}"
if [ -f /etc/systemd/system/claver-agent.service ] || \
   systemctl cat claver-agent.service >/dev/null 2>&1; then
  echo "retiring legacy claver-agent.service" >&2
  systemctl disable --now claver-agent.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/claver-agent.service
fi
if [ -d /var/lib/claver ] && [ ! -L /var/lib/claver ]; then
  echo "note: legacy agent state found at /var/lib/claver (pairing key and" >&2
  echo "      projects). It was left untouched; to carry it over see" >&2
  echo "      'Migrating from claver-agent' in the rootmote-agent README." >&2
fi

# Stop our own unit first so only foreign processes can be holding the port.
systemctl stop rootmote-agent.service >/dev/null 2>&1 || true

list_port_pids() {
  if command -v ss >/dev/null 2>&1; then
    ss -tlnpH "sport = :$1" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u
  elif command -v fuser >/dev/null 2>&1; then
    fuser "$1/tcp" 2>/dev/null | tr -s ' ' '\n'
  fi
}

pids="$(list_port_pids "$AGENT_PORT" || true)"
if [ -n "$pids" ]; then
  for pid in $pids; do
    comm="$(ps -o comm= -p "$pid" 2>/dev/null || echo '?')"
    echo "killing process $pid ($comm) holding 127.0.0.1:$AGENT_PORT" >&2
    kill "$pid" 2>/dev/null || true
  done
  for _ in 1 2 3 4 5; do
    sleep 1
    pids="$(list_port_pids "$AGENT_PORT" || true)"
    [ -z "$pids" ] && break
  done
  if [ -n "$pids" ]; then
    echo "escalating to SIGKILL for: $pids" >&2
    for pid in $pids; do kill -9 "$pid" 2>/dev/null || true; done
  fi
fi

systemctl daemon-reload
systemctl enable rootmote-agent.service
# `enable --now` only starts inactive units; on re-install we have just
# overwritten the binary, so restart unconditionally to pick it up.
systemctl restart rootmote-agent.service

# A just-killed listener can leave sockets lingering briefly; the unit's
# Restart= policy retries the bind. Wait until the agent is actually up and
# listening so the installer's verdict is definitive.
agent_up=""
tries=0
while [ "$tries" -lt 20 ]; do
  if [ "$(systemctl is-active rootmote-agent.service 2>/dev/null)" = "active" ] && \
     [ -n "$(list_port_pids "$AGENT_PORT")" ]; then
    agent_up=1
    break
  fi
  tries=$((tries + 1))
  sleep 1
done
if [ -z "$agent_up" ]; then
  echo "error: rootmote-agent did not reach active+listening within 20s" >&2
  journalctl -u rootmote-agent -n 10 --no-pager >&2 || true
  exit 1
fi

# Print the installed version to stdout.
"$BIN_DST" --version
