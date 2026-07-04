#!/usr/bin/env bash
# Rootmote VPS agent installer.
#
# Idempotent. Designed to be invoked over SSH by the mobile app as:
#     curl -fsSL https://.../install.sh | sudo bash
# or pin to a specific version:
#     curl -fsSL https://.../install.sh | sudo bash -s -- --version 0.1.2
#
# Steps:
#   1. Ensure a `rootmote` system user exists.
#   2. Download the agent binary for the host arch.
#   3. Install the systemd unit.
#   4. Enable + start the service.
#   5. Print the installed version to stdout (Phase 1 acceptance criterion).

set -euo pipefail

VERSION="${VERSION:-latest}"
RELEASE_BASE="${RELEASE_BASE:-https://github.com/rockclaver/rootmote-agent/releases/download}"
RELEASES_LATEST_URL="${RELEASES_LATEST_URL:-https://github.com/rockclaver/rootmote-agent/releases/latest}"
BIN_DST="/usr/local/bin/rootmote-agent"
UNIT_DST="/etc/systemd/system/rootmote-agent.service"
STATE_DIR="/var/lib/rootmote"
CADDYFILE="/etc/caddy/Caddyfile"
CADDY_FRAGMENTS_DIR="/etc/caddy/rootmote"
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

if [[ "$VERSION" == "latest" ]]; then
  echo "resolving latest rootmote-agent release" >&2
  # Follow the /releases/latest redirect to find the current tag without
  # hitting the rate-limited GitHub API.
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
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

if ! id rootmote >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE_DIR" --create-home --shell /usr/sbin/nologin rootmote
fi
install -d -o rootmote -g rootmote -m 0750 "$STATE_DIR"
install -d -o rootmote -g rootmote -m 0700 \
  "$STATE_DIR/.claude" \
  "$STATE_DIR/.claude/skills" \
  "$STATE_DIR/.codex" \
  "$STATE_DIR/.codex/skills"

if ! command -v bwrap >/dev/null 2>&1; then
  echo "installing bubblewrap" >&2
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y bubblewrap
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y bubblewrap
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache bubblewrap
  else
    echo "warning: no supported package manager found; install bubblewrap manually" >&2
  fi
fi

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

url="${RELEASE_BASE}/v${VERSION}/rootmote-agent-linux-${arch}"
echo "downloading $url" >&2
if ! curl -fsSL "$url" -o "$tmp/rootmote-agent"; then
  echo "failed to download rootmote-agent ${VERSION} for linux-${arch}" >&2
  echo "expected release asset: $url" >&2
  exit 1
fi
chmod 0755 "$tmp/rootmote-agent"
install -m 0755 "$tmp/rootmote-agent" "$BIN_DST"

# Install systemd unit. The unit file is expected next to this script when
# invoked locally during development, or fetched from the release otherwise.
if [[ -f "$(dirname "$0")/../systemd/rootmote-agent.service" ]]; then
  install -m 0644 "$(dirname "$0")/../systemd/rootmote-agent.service" "$UNIT_DST"
else
  unit_url="${RELEASE_BASE}/v${VERSION}/rootmote-agent.service"
  if ! curl -fsSL "$unit_url" -o "$UNIT_DST"; then
    echo "failed to download rootmote-agent systemd unit" >&2
    echo "expected release asset: $unit_url" >&2
    exit 1
  fi
  chmod 0644 "$UNIT_DST"
fi

# Install the firewall sudoers fragment so the agent (running as `rootmote`)
# can call ufw / firewall-cmd through `sudo -n`. visudo --check ensures we
# do not lay down a broken file that could lock out sudo entirely.
SUDOERS_SRC="$(dirname "$0")/../systemd/rootmote-agent-firewall.sudoers"
SUDOERS_DST="/etc/sudoers.d/rootmote-agent-firewall"
if [[ -f "$SUDOERS_SRC" ]]; then
  install -m 0440 "$SUDOERS_SRC" "$SUDOERS_DST.new"
  if visudo -c -f "$SUDOERS_DST.new" >/dev/null; then
    mv "$SUDOERS_DST.new" "$SUDOERS_DST"
  else
    rm -f "$SUDOERS_DST.new"
    echo "warning: rootmote-agent-firewall sudoers fragment failed visudo check; firewall management will be read-only" >&2
  fi
else
  sudoers_url="${RELEASE_BASE}/v${VERSION}/rootmote-agent-firewall.sudoers"
  if curl -fsSL "$sudoers_url" -o "$SUDOERS_DST.new"; then
    chmod 0440 "$SUDOERS_DST.new"
    if visudo -c -f "$SUDOERS_DST.new" >/dev/null; then
      mv "$SUDOERS_DST.new" "$SUDOERS_DST"
    else
      rm -f "$SUDOERS_DST.new"
      echo "warning: rootmote-agent-firewall sudoers fragment failed visudo check; firewall management will be read-only" >&2
    fi
  else
    echo "warning: rootmote-agent-firewall sudoers fragment not found; firewall management will be read-only" >&2
  fi
fi

# Install the /run/sudo tmpfiles fragment: sudo needs to create its own
# timestamp directory there on every call (even with NOPASSWD), and
# ProtectSystem=strict in the unit above makes /run read-only unless this
# path is pre-created and listed in ReadWritePaths=. Apply it immediately
# (not just at next boot) so an existing deployment doesn't need a reboot
# for sudo-gated actions (firewall, reboot, storage cleanup) to start working.
TMPFILES_SRC="$(dirname "$0")/../systemd/rootmote-agent-sudo.tmpfiles.conf"
TMPFILES_DST="/etc/tmpfiles.d/rootmote-agent-sudo.conf"
if [[ -f "$TMPFILES_SRC" ]]; then
  install -m 0644 "$TMPFILES_SRC" "$TMPFILES_DST"
else
  tmpfiles_url="${RELEASE_BASE}/v${VERSION}/rootmote-agent-sudo.tmpfiles.conf"
  if ! curl -fsSL "$tmpfiles_url" -o "$TMPFILES_DST"; then
    echo "warning: rootmote-agent-sudo tmpfiles fragment not found; sudo-gated actions (firewall, reboot, storage cleanup) may fail until /run/sudo is created" >&2
  fi
fi
if [[ -f "$TMPFILES_DST" ]] && command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --create "$TMPFILES_DST"
fi

systemctl daemon-reload
systemctl enable rootmote-agent.service
# `enable --now` only starts inactive units; on re-install we have just
# overwritten the binary, so restart unconditionally to pick it up.
systemctl restart rootmote-agent.service

# --- Phase 7: Caddy for live previews -------------------------------------
# Install Caddy if absent. The agent writes per-preview fragments into
# /etc/caddy/rootmote/*.caddy; the main Caddyfile must `import` that glob.
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
if id rootmote >/dev/null 2>&1 && getent group caddy >/dev/null 2>&1; then
  install -d -o rootmote -g caddy -m 2750 "$CADDY_FRAGMENTS_DIR"
elif id rootmote >/dev/null 2>&1; then
  install -d -o rootmote -g rootmote -m 0755 "$CADDY_FRAGMENTS_DIR"
else
  install -d -m 0755 "$CADDY_FRAGMENTS_DIR"
fi

# Ensure the main Caddyfile exists and imports our fragments glob. The check
# is intentionally a literal grep so re-runs of the installer are idempotent.
if [[ ! -f "$CADDYFILE" ]]; then
  mkdir -p "$(dirname "$CADDYFILE")"
  cat > "$CADDYFILE" <<EOF
# Managed by rootmote-agent installer.
# Per-preview reverse-proxy site blocks live in $CADDY_FRAGMENTS_DIR.
$CADDY_IMPORT_LINE
EOF
elif ! grep -Fq "$CADDY_IMPORT_LINE" "$CADDYFILE"; then
  printf '\n# Added by rootmote-agent installer.\n%s\n' "$CADDY_IMPORT_LINE" >> "$CADDYFILE"
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now caddy 2>/dev/null || true
  systemctl reload caddy 2>/dev/null || systemctl restart caddy 2>/dev/null || true
fi

# Phase 1 AC: print installed version to stdout.
"$BIN_DST" --version
