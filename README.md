# rootmote-agent

The VPS-side companion for [Rootmote](https://github.com/rockclaver/rootmote). A single Go binary, supervised by
`systemd`, that binds only to `127.0.0.1` and speaks a JSON-over-WebSocket
protocol to the mobile app over an SSH-forwarded port.

## Incident operations

Rootmote monitors the host, diagnoses incidents from bounded local evidence,
proposes runbooks through an authenticated Claude or Codex CLI, and performs
only reviewed, typed remediation with durable audit records. Watchtower, alerts,
push notifications, and recovery remain available. Developer workspaces, coding
sessions, repositories, pull requests, previews, skill catalogs, and generic
action jobs are not part of the agent.

## Build

```sh
go build ./...
```

## Run locally

```sh
go run ./cmd/rootmote-agent --addr 127.0.0.1:7676
```

The agent refuses to start if `--addr` is anything other than a loopback IP.
The agent keeps a stable HOME for Claude and Codex authentication. Those CLI
credentials are used only by diagnosis and runbook planning.

### Startup options

| Flag | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `--addr` | | `127.0.0.1:7676` | Loopback bind address for the WebSocket control plane. |
| `--data-dir` | | `$HOME/rootmote` | Directory for `state.db`, tool installs, and encrypted CLI credentials. |
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

 Then reload and restart:

```sh
sudo systemctl daemon-reload
sudo systemctl restart rootmote-agent
```

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
the service, and prints the installed version on stdout.

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
the same user-level Claude, Codex, and SSH state as the account Rootmote
connects to.

macOS support provides monitoring, diagnosis, and reviewed recovery on the
MacBook. The Overview tab uses native
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

## Migrating from claver-agent

The installer retires a legacy `claver-agent` service and frees port 7676
automatically, but it never touches legacy state. If a server has history
worth keeping (pairing key, projects, session/audit history, Claude/Codex/gh
sign-ins), migrate it manually — only if you have NOT already paired the new
agent on that server (this replaces fresh rootmote state):

```sh
systemctl stop rootmote-agent
rm -rf /var/lib/rootmote/rootmote          # fresh, unpaired state only!
mv /var/lib/claver/claver /var/lib/rootmote/rootmote
mv /var/lib/claver/go /var/lib/rootmote/go 2>/dev/null || true
mv /var/lib/claver/probe /var/lib/rootmote/probe 2>/dev/null || true
cp -a /var/lib/claver/. /var/lib/rootmote/ # home dotfiles: CLI sign-ins
rm -rf /var/lib/claver && mkdir /var/lib/claver
ln -s /var/lib/rootmote/rootmote /var/lib/claver/claver  # state.db keeps absolute paths
[ -e /var/lib/rootmote/go ] && ln -s /var/lib/rootmote/go /var/lib/claver/go
[ -e /var/lib/rootmote/probe ] && ln -s /var/lib/rootmote/probe /var/lib/claver/probe
chown -R rootmote:rootmote /var/lib/rootmote /var/lib/claver
id -nG claver 2>/dev/null | grep -qw docker && usermod -aG docker rootmote
systemctl start rootmote-agent
```
