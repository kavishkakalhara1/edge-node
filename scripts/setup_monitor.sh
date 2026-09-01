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
  ip address flush dev "$MONITOR"
  ip link set "$MONITOR" up
  iw dev "$MONITOR" set channel "$CHANNEL"
  echo "$MONITOR is monitoring channel $CHANNEL."
  exit 0
fi
if [[ ! -e /sys/class/net/$PARENT ]]; then
  echo "Monitor adapter $PARENT is not present." >&2
  exit 1
fi
HOTSPOT=${IOT_GUARD_HOTSPOT_INTERFACE:-wlan0}
if [[ $PARENT == "$HOTSPOT" ]]; then
  echo "Monitor parent and hotspot interface must use different radios." >&2
  exit 1
fi
if command -v nmcli >/dev/null; then
  nmcli device disconnect "$PARENT" >/dev/null 2>&1 || true
  nmcli device set "$PARENT" managed no
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
ip address flush dev "$MONITOR"
ip link set "$MONITOR" up
iw dev "$MONITOR" set channel "$CHANNEL"
MODE=$(iw dev "$MONITOR" info | awk '$1 == "type" {print $2; exit}')
if [[ $MODE != monitor ]]; then
  echo "$MONITOR did not enter monitor mode." >&2
  exit 1
fi
echo "$MONITOR is monitoring channel $CHANNEL."
