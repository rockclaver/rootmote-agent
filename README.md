# claver-agent

The VPS-side companion for [Claver](../). A single Go binary, supervised by
`systemd`, that binds only to `127.0.0.1` and speaks a JSON-over-WebSocket
protocol to the mobile app over an SSH-forwarded port.

## Status

Phase 1 (issue #2): control plane skeleton with `server.health`. Sessions,
projects, git, and preview are stubs that will land in later phases.

## Build

```sh
cd agent
go build ./...
```

## Run locally

```sh
go run ./cmd/claver-agent --addr 127.0.0.1:7676
```

The agent refuses to start if `--addr` is anything other than a loopback IP.

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
cd agent
go test ./...
```

## Install on a VPS

```sh
curl -fsSL https://raw.githubusercontent.com/rockclaver/claver/main/agent/scripts/install.sh \
  | sudo bash -s -- --version 0.1.0
```

The installer creates a `claver` system user, drops the binary at
`/usr/local/bin/claver-agent`, installs the systemd unit, enables and starts
the service, and prints the installed version on stdout.

The requested version must already exist as a GitHub release. Push a tag such
as `v0.1.0` to publish the `claver-agent-linux-amd64`,
`claver-agent-linux-arm64`, and `claver-agent.service` assets consumed by the
installer.
