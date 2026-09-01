#!/usr/bin/env bash
set -euo pipefail

SSID=${IOT_GUARD_HOTSPOT_SSID:-IoT-Guard}
PASSPHRASE=${IOT_GUARD_HOTSPOT_PASSPHRASE:-}
INTERFACE=${IOT_GUARD_HOTSPOT_INTERFACE:-wlan0}
CLOUD_INTERFACE=${IOT_GUARD_CLOUD_UPLINK_INTERFACE:-eth0}
CHANNEL=${IOT_GUARD_WIFI_CHANNEL:-6}
ADDRESS=${IOT_GUARD_HOTSPOT_ADDRESS:-10.42.0.1/24}
CONNECTION=iot-guard-hotspot

if [[ $EUID -ne 0 ]]; then
  echo "Run this script as root." >&2
  exit 1
fi
if [[ ${#PASSPHRASE} -lt 12 ]]; then
  echo "Set IOT_GUARD_HOTSPOT_PASSPHRASE to at least 12 characters." >&2
  exit 1
fi
if [[ $INTERFACE == "$CLOUD_INTERFACE" ]]; then
  echo "IoT hotspot and cloud uplink must use different interfaces." >&2
  exit 1
fi
command -v nmcli >/dev/null || { echo "NetworkManager/nmcli is required." >&2; exit 1; }

nmcli connection delete "$CONNECTION" >/dev/null 2>&1 || true
nmcli connection add type wifi ifname "$INTERFACE" con-name "$CONNECTION" ssid "$SSID"
nmcli connection modify "$CONNECTION" \
  802-11-wireless.mode ap \
  802-11-wireless.band bg \
  802-11-wireless.channel "$CHANNEL" \
  802-11-wireless.hidden no \
  802-11-wireless.powersave disable \
  wifi-sec.key-mgmt wpa-psk \
  wifi-sec.proto rsn \
  wifi-sec.pairwise ccmp \
  wifi-sec.group ccmp \
  wifi-sec.pmf disable \
  wifi-sec.psk "$PASSPHRASE" \
  ipv4.method shared \
  ipv4.addresses "$ADDRESS" \
  ipv4.never-default yes \
  ipv6.method disabled \
  connection.autoconnect yes
nmcli connection up "$CONNECTION"
echo "Hotspot $SSID is active on $INTERFACE at $ADDRESS channel $CHANNEL."
