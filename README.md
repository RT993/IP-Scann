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
- **Hostname, MAC & vendor lookup** — chains reverse DNS, an mDNS/Bonjour
  reverse-PTR query, and a NetBIOS Name Service query so most devices get
  named even when the router's DNS doesn't know about them (see
  [How hostname detection works](#how-hostname-detection-works)). Vendor
  names come from an offline snapshot of the full IEEE OUI registry (40k+
  manufacturer prefixes); refresh it any time with `make update-oui`.
- **Optional port scan** — checks a curated list of common ports (SSH, HTTP,
  SMB, RDP, printers, databases, …) per host during the sweep.
- **CSV export** of the current results.
- **Per-host tools** — click the wrench icon on any row to open:
  - **OS guess** — a heuristic label (Linux/macOS/Unix, Windows, network
    device, …) with the evidence behind it, computed automatically for
    every host during the sweep and refinable here.
  - **Ping / latency check** — sends 4 echo requests and reports
    min/avg/max round-trip time and packet loss.
  - **Port scanner + service/version detection** — scans a broad list of
    ~100 well-known ports, then grabs a live banner from each one that's
    open to identify the service (and version, where the service
    advertises one).
  - **Traceroute** — maps the network path to the host, hop by hop, live.
  - **Deep scan (optional, nmap)** — real raw-packet OS fingerprinting and
    nmap's full version-detection probe database, if nmap is installed. Off
    by default and opt-in per host; see
    [Deep scan (optional, nmap)](#deep-scan-optional-nmap).
  - **Wake-on-LAN** — sends a magic packet to power on a sleeping,
    WoL-enabled device.
  - **Shared folder / printer / remote-access quick links** — one-click
    `smb://`, printer, RDP, VNC, and SSH links, generated from whatever
    ports the scan found open.

  See [How the tools work](#how-the-tools-work) for what each one can and
  can't actually tell you.
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

If the scanner flags a conflict where *this Mac* is one of the two
addresses, `scripts/renew-dhcp-lease.sh` will force this machine to
request a fresh lease from the router. It only touches this machine —
resolving a conflict on some *other* device means logging into the router
itself, which is out of scope for this tool.

```sh
./scripts/renew-dhcp-lease.sh          # auto-detects the active interface
./scripts/renew-dhcp-lease.sh en0      # or name one explicitly
```

**Don't run this on a machine whose IP has to stay fixed** (e.g. it's
running a server like Jellyfin, has port forwards pointing at it, or other
devices reference it by IP). "Static IP" usually means one of two
different things, and only one of them is safe here:

- **DHCP reservation** — the *router* always hands this Mac the same
  address, but the Mac's own network settings still say "Using DHCP."
  Renewing is harmless: you get the same address back.
- **Manually configured** — set to "Manually" in System Settings → Network
  directly on the Mac, not from the router. Forcing DHCP here doesn't
  renew anything — it **switches the interface from Manual to DHCP**,
  handing it whatever address the router's pool assigns next.

The script checks which one it's dealing with (`networksetup -getinfo`)
and refuses to touch a manually-configured interface, printing why. If
you're not sure which kind you have, the script's refusal message (or
lack of one) will tell you.

## How hostname detection works

Most home routers don't publish DNS names for the devices they hand out
DHCP leases to, so relying on reverse DNS alone (`net.LookupAddr`) misses
most phones, smart-home gear, and IoT devices. For each host, the scanner
tries three things in order and keeps the first name it gets:

1. **Reverse DNS** — works when the router (or a local DNS server) does
   publish DHCP client names.
2. **mDNS/Bonjour** — sends a direct (unicast) reverse-lookup query to the
   device's port 5353. Anything running an mDNS responder answers this —
   which is effectively all Apple devices, most phones, printers, smart
   speakers, and IoT gear (avahi, the responder embedded in most embedded
   Linux devices, honors it too) — independent of whatever the router's DNS
   knows.
3. **NetBIOS Name Service** — sends a node-status query to port 137, which
   reliably returns the computer name for Windows PCs and older NAS/printer
   appliances that speak SMB/NetBIOS but don't run mDNS.

A device that answers none of these (rare, but it happens with some
minimal IoT firmware) shows up with a blank hostname — that's the device
genuinely not advertising a name over any of the three protocols, not a
scan failure.

## How the tools work

Every tool except the optional nmap-backed deep scan below is built to need
no root/admin privileges and no raw sockets. That keeps the app simple to
run, but it's worth being clear about what each one actually is:

- **OS guess is a heuristic, not fingerprinting.** Real OS fingerprinting
  (what nmap or p0f do) inspects the exact ordering and values of TCP
  options in a raw SYN/ACK packet, which needs a raw socket and elevated
  privileges. Instead, this combines three unprivileged signals: the TTL on
  the ping reply (Linux/macOS/BSD default to 64, Windows to 128, and many
  routers/appliances to 255 — a strong but not certain tell), the MAC
  vendor, and any well-known ports found open (e.g. 3389 strongly implies
  Windows). The "signals" list under the guess shows exactly which of these
  fired, so you can judge the guess yourself rather than trust a label. Run
  a deep scan (below) for the real thing.
- **Service/version detection is banner-grabbing, not nmap's probe
  database.** It reads whatever a service volunteers on connect (SSH, FTP,
  SMTP, MySQL, Redis, etc. all send a greeting first), or for HTTP/TLS ports
  sends a minimal request and reads the `Server:` header or the TLS
  certificate. This correctly identifies most common services and their
  version string when the service exposes one in its banner, but won't
  reverse-engineer a version nmap's much larger signature database might
  catch, and a service that doesn't volunteer a version just gets the
  conventional name for its port.
- **Traceroute and ping** shell out to the OS's own `traceroute`/`ping`
  binaries (both run unprivileged on macOS by default), the same approach
  used for the main sweep and conflict detection.
- **Wake-on-LAN** only sends the magic packet — it's inherently
  fire-and-forget UDP, so no tool (this one included) can confirm the
  target actually woke up. It requires Wake-on-LAN to be enabled in the
  target device's firmware/OS network settings.
- **Quick-open links** (shared folder, printer, RDP, VNC, SSH) are plain
  `smb://`, `rdp://`, `vnc://`, `ssh://`, and `http(s)://` links generated
  from whichever ports a port scan found open; your browser hands them off
  to whatever app your Mac has registered for that scheme (Finder for
  `smb://`, Microsoft Remote Desktop for `rdp://`, etc.) — the same
  handoff any desktop scanner's "open share" button relies on, just via a
  standard link instead of a native API call.

## Deep scan (optional, nmap)

Everything above is deliberately built to never need root/admin privileges
or an external dependency. Real OS fingerprinting and nmap's full
version-detection probe database need both, so instead of baking that in as
the default (and asking everyone to run this app as root to get it), it's
an opt-in tool: install nmap yourself, and use it only when you actually
need the deeper answer for one specific host.

**Setup:**

```sh
brew install nmap
```

That alone unlocks service/version detection via nmap's probe database
(more thorough than this app's own banner-grabbing) from the Tools panel's
"Deep scan" section — still no sudo needed. **OS detection** additionally
needs raw sockets, which means running the whole app as root:

```sh
sudo ./dist/ip-scanner-darwin-universal
```

**Think about that trade-off before doing it.** Running the entire server
as root — rather than just the one nmap process that needs it — means any
bug in this app's own code, or in a browser tab that reaches its local
port, now has root-level reach instead of your user account's. It's why
this isn't the default and isn't required for anything else in the app. If
you only need service/version detection, skip `sudo` entirely; it works
fine without it. Only reach for `sudo` when you specifically need OS
detection on a specific host, and treat that as a temporary, deliberate
session rather than how you normally run the tool.

If nmap isn't installed, the deep-scan section explains that and disables
itself rather than silently failing.

## Architecture

```
main.go                     entrypoint: flags, HTTP server, opens browser
internal/netutil/           local interface discovery, CIDR → host list,
                             broadcast-address math for Wake-on-LAN
internal/scanner/           ping/TCP probing, ARP table reading, OUI vendor
                             lookup, duplicate-IP/MAC conflict detection,
                             scan orchestration, and the per-host tools:
                             OS guessing, banner/service detection,
                             traceroute, Wake-on-LAN, and the optional
                             nmap-backed deep scan
internal/api/                job manager, Server-Sent Events streaming,
                             REST + CSV export endpoints, per-host tool
                             endpoints (/api/tools/*)
internal/webui/static/      embedded frontend (plain HTML/CSS/JS, no
                             build step, no external dependencies)
```

No third-party Go modules are used — everything is standard library, which
is what makes cross-compiling a single static binary for both Mac
architectures (`GOOS=darwin GOARCH=amd64|arm64`) trivial and dependency-free.

## Development

```sh
make test   # unit tests (CIDR expansion, ARP parsing, vendor lookup, conflict
            # logic, OS-guess heuristic, banner parsing, traceroute parsing,
            # Wake-on-LAN packet construction)
make vet    # go vet
make run    # go run .
```

## Responsible use

Only scan networks you own or are explicitly authorized to test. Network
scanning of systems you don't control may violate policy or law.
