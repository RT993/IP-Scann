# IP Scanner

A local, web-based IP scanner for macOS (Intel and Apple Silicon), in the
spirit of Advanced IP Scanner / LanScan for Mac: sweep your whole subnet,
see every device that responds, and get flagged when two devices are
fighting over the same IP address.

It ships as a single self-contained Go binary. There's no install step, no
Node/npm build, no external services: the binary starts a small local web
server and opens the UI in your browser.

## Features

- **Whole-network discovery** — enumerates every host in a subnet (ICMP
  ping, with a TCP-connect fallback for devices/firewalls that block ping),
  concurrently, with live results streamed to the UI as hosts are found.
- **Duplicate IP / conflict detection** — runs multiple ARP-observation
  passes a little apart in time. If an IP address answers from two
  different MAC addresses across passes, or the same MAC address turns up
  behind two different IPs, it's flagged as a conflict in the results table
  and summarized in a banner at the top. This works without root/admin
  privileges (see [How conflict detection works](#how-conflict-detection-works)).
- **Hostname, MAC & vendor lookup** — reverse DNS plus an offline OUI
  reference table for common vendors (Apple, Raspberry Pi, Ubiquiti,
  Netgear, Espressif/IoT, etc).
- **Optional port scan** — checks a curated list of common ports (SSH, HTTP,
  SMB, RDP, printers, databases, …) per host.
- **CSV export** of the current results.
- Vintage-terminal-meets-modern-app UI: amber/paper light theme, a
  dark "phosphor" theme, live progress bar, sortable/filterable results
  table.

## Quick start

```sh
go run .
```

This starts the server on `http://127.0.0.1:7890` and opens it in your
default browser. Pick a subnet (your active interface's subnet is
pre-filled) and press **Scan network**.

### Building a macOS binary

```sh
make build-darwin-amd64     # Intel Macs
make build-darwin-arm64     # Apple Silicon Macs
make build-darwin-universal # single binary that runs on both (requires macOS + lipo)
```

Binaries are written to `dist/`. Run one directly:

```sh
./dist/ip-scanner-darwin-universal
```

Flags: `-port 7890` (listen port), `-host 127.0.0.1` (bind address),
`-open=false` (don't auto-open a browser), `-version`.

### macOS permissions

The first scan may trigger macOS's "Local Network" permission prompt
(System Settings → Privacy & Security → Local Network) since the app pings
and connects to addresses on your LAN — allow it for full functionality.
No sudo/root is required.

## How conflict detection works

A true IP conflict (two devices configured with the same static IP, or a
DHCP lease handed out twice) shows up at the network layer as one IP
address answering ARP "who has" requests from more than one MAC address.
Reading that definitively usually means sending raw ARP requests yourself,
which needs raw sockets and root/admin privileges.

This tool takes a practical, unprivileged approach instead: it pings every
host in the subnet (which causes the OS to populate its own ARP cache),
then reads that cache back. It repeats this for a configurable number of
"passes" a few seconds apart (2 by default). If the MAC address behind an
IP changes between passes, that IP is flagged as a conflict, and the
specific MAC addresses involved are shown. As a second signal, if the same
MAC address is seen behind more than one IP (a cloned/duplicated MAC, or a
device caught mid-DHCP-renewal), that's flagged too.

This is the same category of technique real-world "unprivileged" scanners
use, and it needs no elevated permissions — trade-off being that a
conflict occurring between passes, or on a very brief window, could be
missed. Increase **Advanced options → Conflict-detection passes** for more
thorough (if slower) checking on networks where you suspect an
intermittent conflict.

## Architecture

```
main.go                     entrypoint: flags, HTTP server, opens browser
internal/netutil/           local interface discovery, CIDR → host list
internal/scanner/           ping/TCP probing, ARP table reading, OUI vendor
                             lookup, duplicate-IP/MAC conflict detection,
                             scan orchestration
internal/api/                job manager, Server-Sent Events streaming,
                             REST + CSV export endpoints
internal/webui/static/      embedded frontend (plain HTML/CSS/JS, no
                             build step, no external dependencies)
```

No third-party Go modules are used — everything is standard library, which
is what makes cross-compiling a single static binary for both Mac
architectures (`GOOS=darwin GOARCH=amd64|arm64`) trivial and dependency-free.

## Development

```sh
make test   # unit tests (CIDR expansion, ARP parsing, vendor lookup, conflict logic)
make vet    # go vet
make run    # go run .
```

## Responsible use

Only scan networks you own or are explicitly authorized to test. Network
scanning of systems you don't control may violate policy or law.
