# rootmote-agent

The VPS-side companion for [Rootmote](https://github.com/rockclaver/rootmote). A single Go binary, supervised by
`systemd`, that binds only to `127.0.0.1` and speaks a JSON-over-WebSocket
protocol to the mobile app over an SSH-forwarded port.

## Sessions

Structured agent sessions are the default transport. Claude Code and Codex are
driven over their native machine protocols — `claude` stream-json over stdio and
`codex app-server` JSON-RPC — translated into one normalized event/command schema
(messages, tool calls, diffs, plans, approvals, usage, turn boundaries) that the
mobile app renders as a typed transcript. Each session is a per-session child
process; start/interrupt/stop/resume/fork and replay are owned by the session
Manager, and approvals/plan-mode are answered by a single protocol message rather
than by scraping a TUI.

A **raw-terminal transport** remains as an explicit fallback for flows the
structured protocols do not cover (CLI auth / device-code prompts, experimental
modes): the CLI runs in a tmux pane and its bytes stream to the app's terminal
view. Each session selects its transport at start
(`session.start { transport: "structured" | "terminal" }`, default `structured`).

## Build

```sh
go build ./...
```

## Run locally

```sh
go run ./cmd/rootmote-agent --addr 127.0.0.1:7676
```

The agent refuses to start if `--addr` is anything other than a loopback IP.
Interactive Claude and Codex sessions run with a stable agent HOME. On the
systemd install that HOME is `/var/lib/rootmote`, so CLI auth, transcripts, and
skills installed by the agents live under `/var/lib/rootmote/.claude` and
`/var/lib/rootmote/.codex` instead of the project workspace. The agent also adds
the relevant `skills` directory to each CLI's writable roots, so skill installs
persist across sessions, logins, and binary upgrades.

### Startup options

| Flag | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `--addr` | | `127.0.0.1:7676` | Loopback bind address for the WebSocket control plane. |
| `--data-dir` | | `$HOME/rootmote` | Directory for `state.db`, project workspaces, tool installs, and token vault files. |
| `--caddy-fragments-dir` | `ROOTMOTE_CADDY_FRAGMENTS_DIR` | `/etc/caddy/rootmote` | Directory where preview site-block fragments are written. |
| `--preview-expected-ip` | `ROOTMOTE_PREVIEW_EXPECTED_IP` | unset | Optional DNS guard; preview setup requires wildcard DNS to resolve to this IP. |
| `--version` | | `false` | Print the installed agent version and exit. |

Examples:

```sh
# Local development
go run ./cmd/rootmote-agent \
  --addr 127.0.0.1:7676 \
  --data-dir ./rootmote-data
```

## Network Access

The agent control plane must stay private. It binds to loopback and the mobile
app reaches it by opening an SSH tunnel to `127.0.0.1:7676` on the managed
host. Do not expose port `7676` on a public interface.

For a VPS with a public SSH address, add the server normally in Rootmote.

For a MacBook on the same Wi-Fi/LAN as the phone, use direct SSH:

1. Enable **System Settings → General → Sharing → Remote Login** on the Mac.
2. Install and start `rootmote-agent` with the macOS installer below.
3. Add the Mac in Rootmote using either:
   - the Mac's Bonjour name, for example `Peters-MacBook-Pro.local`; or
   - the Mac's LAN IP, for example `192.168.1.145`.
4. Use SSH port `22`, the macOS username, and the public key Rootmote shows in
   the app.

The direct MacBook path does not require Tailscale on the phone. It does require
the iOS Local Network permission because the app opens an SSH socket to a
private LAN or `.local` address.

If the phone is away from the Mac's local network, direct LAN SSH will not work.
Do not make public router port-forwarded SSH the default. For remote access,
prefer a private overlay network such as Tailscale:

1. Install Tailscale on the host.
   - Linux: `curl -fsSL https://tailscale.com/install.sh | sh`, then run
     `sudo tailscale up`.
   - macOS: install Tailscale's standalone macOS app, then sign in.
2. Confirm the host appears in your tailnet and copy its Tailscale IP or
   MagicDNS name.
3. Enable SSH on the host. On macOS this is **System Settings → General →
   Sharing → Remote Login**.
4. Add the host in Rootmote using the Tailscale IP or MagicDNS name, port `22`,
   your SSH username, and the SSH key you authorized on that host.

For unattended Linux servers, Tailscale supports auth keys:

```sh
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --auth-key=tskey-...
```

Use a short-lived, pre-approved, tagged auth key for server provisioning. Do not
enable exit-node, subnet-router, or Tailscale SSH modes unless you have reviewed
the tailnet ACL and the operational tradeoffs.

For a systemd install, prefer an override instead of editing the packaged unit:

```sh
sudo systemctl edit rootmote-agent
```

```ini
[Service]
Environment=ROOTMOTE_PREVIEW_EXPECTED_IP=203.0.113.10
```

Then reload and restart:

```sh
sudo systemctl daemon-reload
sudo systemctl restart rootmote-agent
```

### GitHub setup

GitHub imports use GitHub CLI authentication. No custom OAuth app, callback URL,
or Client ID is required.

Install `gh` on the VPS, then sign in as the same user that runs
`rootmote-agent`:

```sh
sudo -u rootmote -H gh auth login \
  --hostname github.com \
  --git-protocol https \
  --scopes repo,read:org,workflow \
  --web
```

The mobile app can also start the same browser sign-in flow from **Import from
GitHub**. Repository listing, imports, pushes, and PR creation read the active
token with `gh auth token --hostname github.com`.

## Test

```sh
go test ./...
```

## Install on a VPS

```sh
curl -fsSL https://raw.githubusercontent.com/rockclaver/rootmote-agent/main/scripts/install.sh \
  | sudo bash
```

By default the installer resolves the latest GitHub release. To pin a specific
version, pass `--version`:

```sh
curl -fsSL https://raw.githubusercontent.com/rockclaver/rootmote-agent/main/scripts/install.sh \
  | sudo bash -s -- --version 0.1.2
```

The installer creates a `rootmote` system user, drops the binary at
`/usr/local/bin/rootmote-agent`, installs the systemd unit, enables and starts
the service, and prints the installed version on stdout. It also installs the
OS-level Bubblewrap package so Codex CLI can find `bwrap` on PATH, and creates
the persistent Claude/Codex skill roots under `/var/lib/rootmote`.

## Install on macOS

Enable Remote Login first, then install the agent as the macOS user that
Rootmote will SSH into. Use the Mac's `.local` name or LAN IP when the phone is
on the same network:

```sh
curl -fsSL https://raw.githubusercontent.com/rockclaver/rootmote-agent/main/scripts/install-macos.sh \
  | bash
```

To pin a specific release:

```sh
curl -fsSL https://raw.githubusercontent.com/rockclaver/rootmote-agent/main/scripts/install-macos.sh \
  | bash -s -- --version 0.1.2
```

The macOS installer creates a per-user LaunchAgent at
`~/Library/LaunchAgents/com.rockclaver.rootmote-agent.plist`, installs the binary
under `~/Library/Application Support/RootmoteAgent/bin`, stores agent data under
`~/Library/Application Support/RootmoteAgent`, and writes logs to
`~/Library/Logs/RootmoteAgent`. Do not run it with `sudo`; the agent should use
the same user-level Claude, Codex, GitHub CLI, and SSH state as the account
Rootmote connects to.

macOS support is for running coding sessions, project operations, and the
read-only Infrastructure views on the MacBook. The Overview tab uses native
macOS metrics, Services lists `launchd` jobs, Processes uses `ps`, Firewall
falls back to read-only listening sockets through `netstat`, and Webservers checks
common Homebrew Caddy/Nginx/Apache config paths. Linux-only controls such as
ufw/firewalld rule edits and Linux storage cleanup are reported as unavailable
or limited on macOS.

### Local macOS development deploy

To test unreleased agent changes on the same MacBook without cutting a GitHub
release, run:

```sh
./scripts/deploy-macos-local.sh
```

The script builds the current working tree for macOS, installs it into the same
per-user LaunchAgent location as `install-macos.sh`, restarts launchd, and
probes the WebSocket health and Infrastructure endpoints. Local builds are
versioned as `dev-<git-sha>` with a `-dirty` suffix when the tree has
uncommitted changes.

The requested version must already exist as a GitHub release. Push a tag such
as `v0.1.0` to publish the `rootmote-agent-linux-amd64`,
`rootmote-agent-linux-arm64`, `rootmote-agent-darwin-amd64`,
`rootmote-agent-darwin-arm64`, `rootmote-agent.service`,
`rootmote-agent-firewall.sudoers`, `rootmote-agent-sudo.tmpfiles.conf`, and
`install-macos.sh` assets consumed by the installers.
