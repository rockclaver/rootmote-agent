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
