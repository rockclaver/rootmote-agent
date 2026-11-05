# rootmote-agent

The VPS-side companion for [Rootmote](https://github.com/rockclaver/rootmote). A single Go binary, supervised by
`systemd`, that binds only to `127.0.0.1` and speaks a JSON-over-WebSocket
protocol to the mobile app over an SSH-forwarded port.

## Incident operations

Rootmote monitors the host, collects bounded local evidence for each incident,
proposes a playbook, and performs only reviewed, typed remediation with durable
audit records. Developer workspaces, coding sessions, repositories, pull
requests, previews, skill catalogs, and generic action jobs are not part of the
agent.

### How an incident becomes a fix

1. A local monitor fires. The agent sends the event to Watchtower, which opens
   the incident and answers with its id. The agent remembers which monitor the
   incident came from.
2. The agent collects redacted evidence (logs, service and container state,
   resource use, the biggest folders on a full disk, PM2 apps, certificate
   expiry) and matches fixed failure signatures against it.
3. If a signature has a rule, the agent builds a **catalog playbook** on the
   spot, with no network call. The rules are in `internal/playbook/rules.go`:

   | Signature | Playbook |
   | --- | --- |
   | Container restart loop or stopped | `container.restart`, or `compose.up` (starts the service's existing containers) for a Compose service. Adds "Check the last deploy" when a recent change was found. |
   | Systemd unit failed | `service.restart`, or `phpfpm.restart` for a PHP-FPM unit. |
   | Out of memory | Restart the killed service, plus manual memory and swap steps with the numbers from the evidence. |
   | Disk or inodes full | `disk.journal_vacuum`, `disk.docker_prune` and `disk.apt_clean` where they apply, plus the five biggest folders. |
   | Certificate expiring | `cert.renew`. |
   | Proxy upstream error | Restart the upstream service or container, then `check.http`. |
   | PM2 app stopped or crashed | `pm2.restart`. |

4. If a **critical** incident has no catalog playbook and monitoring is on, the
   agent asks the playbook service once, so the playbook is ready when you open
   the app. For any other incident the app offers "Generate a playbook", which
   calls `incident.playbook.generate`.
5. Either way the playbook ends in `remediation.Manager.Propose`. You review it
   in the app, approve it with biometrics, and the agent runs each catalog step,
   verifies each step with the catalog's own check, and records the result.

Nothing runs a free-form command. A playbook can only name steps from the
catalog (`rootmote-agent steps --json`), and every name must exist on this
server. The agent checks a playbook from the service again before showing it.
Steps that have no undo are listed as "cannot be undone" before you approve.

### What leaves the server

Only when a playbook is generated, the agent sends one signed request to
Watchtower (`POST /v1/agents/playbooks`): the matched signatures, names of
services, containers and apps (no paths or settings), resource numbers, the OS
name, and at most 100 log lines (8 KB). Passwords, keys, tokens, JWTs, emails
and connection strings are removed first with the rules in
`internal/diagnose/redact/rules.json` (the same file Watchtower uses). The host
name and public IP addresses become `host-1` and `ip-1`. There is no AI
tool, login or API key on the server.

## Build

```sh
go build ./...
```

## Run locally

```sh
go run ./cmd/rootmote-agent --addr 127.0.0.1:7676
```

The agent refuses to start if `--addr` is anything other than a loopback IP.

### Startup options

| Flag | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `--addr` | | `127.0.0.1:7676` | Loopback bind address for the WebSocket control plane. |
| `--data-dir` | | `$HOME/rootmote` | Directory for `state.db` and the agent's keys. |
| `--require-pairing` | | `true` | Require the pairing key from `rootmote-agent pairing-key` on the WebSocket. Turn off only for local development. |
| `--watchtower-relay-url` | `ROOTMOTE_WATCHTOWER_RELAY_URL` | empty | Watchtower base URL. Empty until the app enrolls the agent. |
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

## Privilege model

The agent runs as the unprivileged `rootmote` user. `systemd/rootmote-agent.sudoers`
holds exactly one rule:

```
rootmote ALL=(root) NOPASSWD: /usr/local/bin/rootmote-agent priv *
```

The sudoers file also has a `Cmnd_Alias` for the read-only actions the agent
polls (`pm2-list`, `supervisor-status`, `certs-list`, `web-errors`,
`firewall-rules`) and `Defaults!ROOTMOTE_READONLY !log_allowed`, so those calls
do not fill the sudo log. It grants nothing: the one rule above is still the
only grant, and calls that change the server stay logged.

`rootmote-agent priv <action> <args...>` is the privilege helper. It accepts only
the root steps of the fix catalog (`rootmote-agent steps --json` prints the full
catalog) plus six read-only actions, and checks every argument again as root.
It first changes its working directory to `/`, so nothing it starts reads files
from a folder the caller chose. Names must match `^[A-Za-z0-9@._:-]{1,128}$` and
exist right now. Only `.service` units are accepted (a bare name means the
`.service` unit); `.target`, `.slice`, `.scope`, `.mount`, `.socket` and every
other type are refused, and so is any name that systemd resolves to a unit whose
id does not end in `.service`. `ssh`, `sshd`, `sshd-*`, `systemd-*`, `dbus*`,
`networking`, `network`, `ifup@*`, `NetworkManager`, `wpa_supplicant`, `ufw`,
`firewalld`, `nftables`, `iptables`, `ip6tables`, `netfilter-persistent`,
`user@*`, `rootmote-agent`, `getty@*`, `docker` and `containerd` are never
touched. A process id must be above 1, match its start time, and never be the
agent, its children, `sshd` or `sshd-session`. The helper pins the process with a
pidfd before it checks the start time and signals only through that pidfd, and
it checks the start time again before `SIGKILL`. The firewall helper never
closes an SSH port (it also finds SSH ports of `sshd-session` and of
socket-activated `ssh.socket`) and never enables, disables or resets the
firewall. firewalld rules are changed in the running and the saved
configuration one after the other, without a reload. Certificate names must exist
under `/etc/letsencrypt/live/`. `supervisorctl` runs with `-c` and a
root-owned settings file (`/etc/supervisor/supervisord.conf`,
`/etc/supervisord.conf` or `/etc/supervisord/supervisord.conf`) that others
cannot write. `web-errors` prints the last 200 lines (at most 64 KB) of the web
server error logs: the `error_log` and `ErrorLog` files named in the main nginx
and Apache configs plus `/var/log/nginx/error.log`, `/var/log/apache2/error.log`
and `/var/log/httpd/error_log`. It reads only regular files below `/var/log`,
never follows a symlink, and refuses everything else. This is why `rootmote` is
not in the `adm` group: that group can read `auth.log` and other private logs.
Commands run with an exact argv and no shell. Exit code 0 is
success, 2 is a refusal (one plain sentence on stderr) and 1 is a failure.

Actions: `service.restart|start|stop|reload`, `phpfpm.restart`, `nginx.reload`,
`supervisor.restart`, `pm2.restart`, `disk.journal_vacuum`,
`disk.apt_clean`, `cert.renew` (accepts `--dry-run`), `process.stop`,
`firewall.allow`, `firewall.remove`, and the read-only `pm2-list <user>`,
`certs-list`, `supervisor-status`, `firewall-rules`, `nginx-test`, `web-errors`. Actions that
must write outside the agent's systemd sandbox (certbot, journal vacuum, apt
clean, nginx config test, PM2 in `/home`) re-run themselves inside
PID 1's mount namespace with `nsenter --mount=/proc/1/ns/mnt`.

`compose.up` does not run as root and never reads or runs a Compose file. It
finds the containers of the service by their Compose labels, requires all of
them to share one `com.docker.compose.config-hash` and one project folder
label, and then starts (or restarts, when unhealthy) those existing containers
through the Docker API as the agent user. If the service has no containers it
refuses and tells you to run `docker compose up` yourself.

### Docker access is root-equivalent

The one sudoers rule is not the whole picture on a Docker host. The agent reads
and restarts containers through the Docker socket (monitoring, discovery,
`container.restart`, `disk.docker_prune`). Only root and the `docker` group can
open that socket, so `install.sh` adds `rootmote` to the `docker` group when the
group exists. Anyone in the `docker` group can start a container that mounts the
host's filesystem, which is the same as root. So on a Docker host, whoever
controls the `rootmote` user controls the server. The privilege helper still
limits what the agent's own code can do, but it is not a security boundary
against someone who already runs as `rootmote`. If you do not want this, do not
install Docker on the host, or remove the user from the group
(`gpasswd -d rootmote docker`); container steps and Docker monitors then stop
working. Re-running the installer after Docker is installed adds the group.

The agent never executes free-form commands. Anything a playbook suggests outside
the catalog is shown to the operator as text to run themselves.

## Test

```sh
go test ./...
```

## Install on a VPS

The installer needs an exact release tag. It will not install "latest".

```sh
curl -fsSL https://raw.githubusercontent.com/rockclaver/rootmote-agent/v0.2.0/scripts/install.sh \
  | sudo ROOTMOTE_AGENT_VERSION=v0.2.0 sh
```

`ROOTMOTE_AGENT_VERSION` is required and must look like `vX.Y.Z`. The script
comes from the same tag, so you read the code that you run. It downloads the
binary and `SHA256SUMS` from that release, checks the binary's SHA-256 before
installing anything, and stops with `Checksum mismatch for <file>: refusing to
install.` if they differ. The app runs this same command with the version it
was tested with. For local testing, `ROOTMOTE_AGENT_BASE_URL` replaces the
download directory.

The installer creates a `rootmote` system user, drops the binary at
`/usr/local/bin/rootmote-agent`, writes the one sudoers rule (checked with
`visudo`; older broad rules are removed), adds `rootmote` to the `docker`
group when it exists, installs the systemd unit, enables and starts the
service, and prints the installed version on stdout.

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
  | bash -s -- --version 0.2.0
```

The macOS installer is a manual, developer-machine path. Unlike the Linux
installer it is not tag-pinned and does not check a checksum; the app does not
use it.

The macOS installer creates a per-user LaunchAgent at
`~/Library/LaunchAgents/com.rockclaver.rootmote-agent.plist`, installs the binary
under `~/Library/Application Support/RootmoteAgent/bin`, stores agent data under
`~/Library/Application Support/RootmoteAgent`, and writes logs to
`~/Library/Logs/RootmoteAgent`. Do not run it with `sudo`; the agent should use
the same user-level SSH state as the account Rootmote connects to.

macOS support provides monitoring, diagnosis, and reviewed recovery on the
MacBook. The Overview tab uses native
macOS metrics, Services lists `launchd` jobs, Processes uses `ps`, Firewall
falls back to read-only listening sockets through `netstat`, and Webservers checks
common Homebrew Caddy/Nginx/Apache config paths. Linux-only controls such as
ufw/firewalld rule edits and the other root fix steps are reported as unavailable
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
as `v0.2.0` to publish the `rootmote-agent-linux-amd64`,
`rootmote-agent-linux-arm64`, `rootmote-agent-darwin-amd64`,
`rootmote-agent-darwin-arm64`, `rootmote-agent.service`,
`rootmote-agent.sudoers`, `install-macos.sh` and `SHA256SUMS` assets consumed
by the installers. The release workflow runs `go vet` and `go test` first.

## Migrating from claver-agent

The installer retires a legacy `claver-agent` service and frees port 7676
automatically, but it never touches legacy state. If a server has history
worth keeping (pairing key, projects, session/audit history), migrate it manually — only if you have NOT already paired the new
agent on that server (this replaces fresh rootmote state):

```sh
systemctl stop rootmote-agent
rm -rf /var/lib/rootmote/rootmote          # fresh, unpaired state only!
mv /var/lib/claver/claver /var/lib/rootmote/rootmote
mv /var/lib/claver/go /var/lib/rootmote/go 2>/dev/null || true
mv /var/lib/claver/probe /var/lib/rootmote/probe 2>/dev/null || true
cp -a /var/lib/claver/. /var/lib/rootmote/ # home dotfiles
rm -rf /var/lib/claver && mkdir /var/lib/claver
ln -s /var/lib/rootmote/rootmote /var/lib/claver/claver  # state.db keeps absolute paths
[ -e /var/lib/rootmote/go ] && ln -s /var/lib/rootmote/go /var/lib/claver/go
[ -e /var/lib/rootmote/probe ] && ln -s /var/lib/rootmote/probe /var/lib/claver/probe
chown -R rootmote:rootmote /var/lib/rootmote /var/lib/claver
id -nG claver 2>/dev/null | grep -qw docker && usermod -aG docker rootmote
systemctl start rootmote-agent
```
