#!/usr/bin/env bash
set -euo pipefail

SSID=${IOT_TEST_WIFI_SSID:-IoT-Guard}
PASSPHRASE=${IOT_TEST_WIFI_PASSPHRASE:-}
INTERFACE=${IOT_TEST_WIFI_INTERFACE:-wlan0}
CONNECTION=iot-guard-test-device

if [[ $EUID -ne 0 ]]; then
  echo "Run this script as root." >&2
  exit 1
fi
if [[ ${#PASSPHRASE} -lt 12 ]]; then
  echo "Set IOT_TEST_WIFI_PASSPHRASE to the hotspot passphrase (at least 12 characters)." >&2
  exit 1
fi
command -v nmcli >/dev/null || { echo "NetworkManager/nmcli is required." >&2; exit 1; }

nmcli connection delete "$CONNECTION" >/dev/null 2>&1 || true
nmcli connection add type wifi ifname "$INTERFACE" con-name "$CONNECTION" ssid "$SSID"
nmcli connection modify "$CONNECTION" \
  wifi-sec.key-mgmt wpa-psk \
  wifi-sec.psk "$PASSPHRASE" \
  ipv4.method auto \
  ipv6.method disabled \
  connection.autoconnect yes
nmcli connection up "$CONNECTION"
echo "Connected $INTERFACE to $SSID."
