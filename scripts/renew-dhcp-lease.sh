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
# Usage:
#   ./scripts/renew-dhcp-lease.sh          # auto-detect the active interface
#   ./scripts/renew-dhcp-lease.sh en0      # renew a specific interface
#
# Requires sudo (macOS's "ipconfig set ... DHCP" needs it to force a fresh
# DHCP negotiation rather than just reporting the current lease).

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This script uses macOS-specific tools (ipconfig, route) and only runs on macOS." >&2
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

old_ip=$(ipconfig getifaddr "$interface" 2>/dev/null || echo "none")
echo "Interface:   $interface"
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
