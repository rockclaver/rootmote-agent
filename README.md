# claver-agent

The VPS-side companion for [Claver](https://github.com/rockclaver/claver). A single Go binary, supervised by
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
go run ./cmd/claver-agent --addr 127.0.0.1:7676
```

The agent refuses to start if `--addr` is anything other than a loopback IP.
Interactive Claude and Codex sessions run with a stable agent HOME. On the
systemd install that HOME is `/var/lib/claver`, so CLI auth, transcripts, and
skills installed by the agents live under `/var/lib/claver/.claude` and
`/var/lib/claver/.codex` instead of the project workspace. The agent also adds
the relevant `skills` directory to each CLI's writable roots, so skill installs
persist across sessions, logins, and binary upgrades.

### Startup options

| Flag | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `--addr` | | `127.0.0.1:7676` | Loopback bind address for the WebSocket control plane. |
| `--data-dir` | | `$HOME/claver` | Directory for `state.db`, project workspaces, tool installs, and token vault files. |
| `--caddy-fragments-dir` | `CLAVER_CADDY_FRAGMENTS_DIR` | `/etc/caddy/claver` | Directory where preview site-block fragments are written. |
| `--preview-expected-ip` | `CLAVER_PREVIEW_EXPECTED_IP` | unset | Optional DNS guard; preview setup requires wildcard DNS to resolve to this IP. |
| `--version` | | `false` | Print the installed agent version and exit. |

Examples:

```sh
# Local development
go run ./cmd/claver-agent \
  --addr 127.0.0.1:7676 \
  --data-dir ./claver-data
```

For a systemd install, prefer an override instead of editing the packaged unit:

```sh
sudo systemctl edit claver-agent
```

```ini
[Service]
Environment=CLAVER_PREVIEW_EXPECTED_IP=203.0.113.10
```

Then reload and restart:

```sh
sudo systemctl daemon-reload
sudo systemctl restart claver-agent
```

### GitHub setup

GitHub imports use GitHub CLI authentication. No custom OAuth app, callback URL,
or Client ID is required.

Install `gh` on the VPS, then sign in as the same user that runs
`claver-agent`:

```sh
sudo -u claver -H gh auth login \
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
curl -fsSL https://raw.githubusercontent.com/rockclaver/claver-agent/main/scripts/install.sh \
  | sudo bash
```

By default the installer resolves the latest GitHub release. To pin a specific
version, pass `--version`:

```sh
curl -fsSL https://raw.githubusercontent.com/rockclaver/claver-agent/main/scripts/install.sh \
  | sudo bash -s -- --version 0.1.2
```

The installer creates a `claver` system user, drops the binary at
`/usr/local/bin/claver-agent`, installs the systemd unit, enables and starts
the service, and prints the installed version on stdout. It also installs the
OS-level Bubblewrap package so Codex CLI can find `bwrap` on PATH, and creates
the persistent Claude/Codex skill roots under `/var/lib/claver`.

The requested version must already exist as a GitHub release. Push a tag such
as `v0.1.0` to publish the `claver-agent-linux-amd64`,
`claver-agent-linux-arm64`, `claver-agent.service`, and
`claver-agent-firewall.sudoers` assets consumed by the installer.
