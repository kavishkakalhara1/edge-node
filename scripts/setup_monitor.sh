#!/usr/bin/env bash
set -euo pipefail

PARENT=${IOT_GUARD_MONITOR_PARENT:-wlan1}
MONITOR=${IOT_GUARD_MONITOR_INTERFACE:-wlan1mon}
CHANNEL=${IOT_GUARD_WIFI_CHANNEL:-6}

if [[ $EUID -ne 0 ]]; then
  echo "Run this script as root." >&2
  exit 1
fi
if [[ -e /sys/class/net/$MONITOR ]]; then
  ip link set "$MONITOR" up
  iw dev "$MONITOR" set channel "$CHANNEL"
  echo "$MONITOR is monitoring channel $CHANNEL."
  exit 0
fi
if [[ ! -e /sys/class/net/$PARENT ]]; then
  echo "Monitor adapter $PARENT is not present." >&2
  exit 1
fi
ip link set "$MONITOR" down 2>/dev/null || true
iw dev "$MONITOR" del 2>/dev/null || true
ip link set "$PARENT" down
if iw dev "$PARENT" set type monitor 2>/dev/null; then
  ip link set "$PARENT" name "$MONITOR"
else
  ip link set "$PARENT" up
  iw dev "$PARENT" interface add "$MONITOR" type monitor
fi
ip link set "$MONITOR" up
iw dev "$MONITOR" set channel "$CHANNEL"
echo "$MONITOR is monitoring channel $CHANNEL."
