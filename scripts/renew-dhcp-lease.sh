#!/usr/bin/env bash
# Renews the DHCP lease on THIS Mac's own active network interface.
#
# Scope: this only affects the machine you run it on. It cannot renew,
# clear, or otherwise touch another device's DHCP lease -- doing that
# would mean logging into the router/DHCP server itself, which this
# script does not attempt. If the IP Scanner flagged a conflict on some
# *other* device, this script won't resolve that; it's meant for cases
# like "my own Mac is the one holding a stale or conflicting lease."
#
# Safety: refuses to run if the interface's IP is configured Manually
# rather than via DHCP (System Settings -> Network -> the interface ->
# Configure IPv4: "Manually"). Forcing DHCP on a manually-configured
# interface doesn't just renew a lease -- it switches the interface over
# to DHCP entirely, handing it whatever address the router's pool assigns
# next. On a machine running a server (Jellyfin, etc.) that other devices,
# port forwards, or bookmarks depend on having a fixed address, that's not
# a "renewal," it's an unwanted address change. If that's your setup, this
# script is not what you want -- leave the interface alone.
#
# Usage:
#   ./scripts/renew-dhcp-lease.sh          # auto-detect the active interface
#   ./scripts/renew-dhcp-lease.sh en0      # renew a specific interface
#
# Requires sudo (macOS's "ipconfig set ... DHCP" needs it to force a fresh
# DHCP negotiation rather than just reporting the current lease).

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This script uses macOS-specific tools (ipconfig, route, networksetup) and only runs on macOS." >&2
  exit 1
fi

interface="${1:-}"

if [[ -z "$interface" ]]; then
  interface=$(route get default 2>/dev/null | awk '/interface: / {print $2}')
fi

if [[ -z "$interface" ]]; then
  echo "Could not auto-detect the active network interface." >&2
  echo "Pass one explicitly, e.g.: $0 en0" >&2
  echo "List available interfaces with: networksetup -listallhardwareports" >&2
  exit 1
fi

if ! ifconfig "$interface" >/dev/null 2>&1; then
  echo "Interface \"$interface\" not found." >&2
  echo "List available interfaces with: networksetup -listallhardwareports" >&2
  exit 1
fi

# Map the BSD interface name (en0) to the network service name
# (e.g. "Wi-Fi", "Ethernet") that `networksetup -getinfo` wants, by
# scanning `networksetup -listallhardwareports` for the matching block.
service=$(networksetup -listallhardwareports | awk -v iface="$interface" '
  /^Hardware Port: / { port = substr($0, 17) }
  $0 == "Device: " iface { print port; exit }
')

if [[ -z "$service" ]]; then
  echo "Could not map interface \"$interface\" to a network service name." >&2
  echo "Check it manually with: networksetup -listallhardwareports" >&2
  exit 1
fi

config_info=$(networksetup -getinfo "$service")
if echo "$config_info" | head -n1 | grep -qi "^Manual"; then
  echo "Refusing to continue: \"$service\" ($interface) has a MANUALLY configured IP address, not a DHCP lease." >&2
  echo >&2
  echo "$config_info" >&2
  echo >&2
  echo "Forcing DHCP here would strip that manual configuration and hand this Mac a" >&2
  echo "new, router-assigned address -- not a renewal of the address it already has." >&2
  echo "If something depends on this machine keeping a fixed IP (a server like" >&2
  echo "Jellyfin, port forwards, other devices' bookmarks, ...), leave this interface" >&2
  echo "alone. This script is only for interfaces actually configured via DHCP." >&2
  exit 1
fi

old_ip=$(ipconfig getifaddr "$interface" 2>/dev/null || echo "none")
echo "Interface:   $interface ($service)"
echo "Current IP:  $old_ip"
echo "Renewing DHCP lease (requires sudo)..."

sudo ipconfig set "$interface" DHCP

# The lease negotiation happens asynchronously; give it a moment before
# checking the result.
sleep 2
new_ip=$(ipconfig getifaddr "$interface" 2>/dev/null || echo "none")
echo "New IP:      $new_ip"

if [[ "$new_ip" == "none" ]]; then
  echo "Warning: no IP address was assigned after renewal. Check the network connection on $interface." >&2
  exit 1
elif [[ "$new_ip" == "$old_ip" ]]; then
  echo "Lease renewed; the DHCP server handed back the same address (normal unless something was forcing a change)."
else
  echo "Lease renewed with a new address: $old_ip -> $new_ip"
fi
