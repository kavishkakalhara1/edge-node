#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR=${IOT_GUARD_INSTALL_DIR:-/opt/iot-guard}
ENV_FILE=${IOT_GUARD_ENV_FILE:-/etc/iot-guard/iot-guard.env}
HOTSPOT=${IOT_GUARD_HOTSPOT_INTERFACE:-wlan0}
UPLINK=${IOT_GUARD_CLOUD_UPLINK_INTERFACE:-eth0}
SSID=${IOT_GUARD_HOTSPOT_SSID:-IoT-Guard}
CHANNEL=${IOT_GUARD_WIFI_CHANNEL:-6}
ADDRESS=${IOT_GUARD_HOTSPOT_ADDRESS:-10.42.0.1/24}
PASSPHRASE=${IOT_GUARD_HOTSPOT_PASSPHRASE:-}

if [[ $EUID -ne 0 ]]; then
  echo "Run this script as root." >&2
  exit 1
fi
if [[ ${#PASSPHRASE} -lt 12 ]]; then
  echo "Set IOT_GUARD_HOTSPOT_PASSPHRASE to at least 12 characters." >&2
  exit 1
fi
for interface in "$HOTSPOT" "$UPLINK"; do
  if [[ ! -e /sys/class/net/$interface ]]; then
    echo "Required interface $interface is not present." >&2
    exit 1
  fi
done
if [[ $HOTSPOT == "$UPLINK" ]]; then
  echo "Hotspot and upstream must use different interfaces." >&2
  exit 1
fi
if [[ $(cat "/sys/class/net/$UPLINK/carrier" 2>/dev/null || echo 0) != 1 ]]; then
  echo "Ethernet upstream $UPLINK has no carrier; refusing to reconfigure Wi-Fi." >&2
  exit 1
fi

set_env() {
  local key=$1 value=$2
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

LEGACY_HOSTAPD_ACTIVE=$(systemctl is-active hostapd.service 2>/dev/null || true)
LEGACY_DNSMASQ_ACTIVE=$(systemctl is-active dnsmasq.service 2>/dev/null || true)
recover_legacy_hotspot() {
  local exit_code=$?
  ip address flush dev "$HOTSPOT" scope global 2>/dev/null || true
  if [[ $LEGACY_DNSMASQ_ACTIVE == active ]]; then
    systemctl restart dnsmasq.service || true
  fi
  if [[ $LEGACY_HOSTAPD_ACTIVE == active ]]; then
    systemctl restart hostapd.service || true
  fi
  echo "Gateway migration failed; the previous hotspot services were restored." >&2
  exit "$exit_code"
}
trap recover_legacy_hotspot ERR

systemctl stop iot-guard-collector.service iot-guard-monitor.service
systemctl stop hostapd.service dnsmasq.service 2>/dev/null || true
IOT_GUARD_HOTSPOT_INTERFACE=$HOTSPOT \
IOT_GUARD_CLOUD_UPLINK_INTERFACE=$UPLINK \
IOT_GUARD_HOTSPOT_SSID=$SSID \
IOT_GUARD_HOTSPOT_PASSPHRASE=$PASSPHRASE \
IOT_GUARD_WIFI_CHANNEL=$CHANNEL \
IOT_GUARD_HOTSPOT_ADDRESS=$ADDRESS \
  "$INSTALL_DIR/configure_hotspot.sh"

set_env IOT_GUARD_HOTSPOT_INTERFACE "$HOTSPOT"
set_env IOT_GUARD_HOTSPOT_SSID "$SSID"
set_env IOT_GUARD_HOTSPOT_ADDRESS "$ADDRESS"
set_env IOT_GUARD_CLOUD_UPLINK_INTERFACE "$UPLINK"
set_env IOT_GUARD_MONITOR_INTERFACE ""
set_env IOT_GUARD_WIFI_CHANNEL "$CHANNEL"
set_env IOT_GUARD_CAPTURE_INTERFACES "$HOTSPOT"
set_env IOT_GUARD_DHCP_LEASE_FILE "/var/lib/NetworkManager/dnsmasq-${HOTSPOT}.leases"

systemctl disable hostapd.service dnsmasq.service iot-guard-monitor.service 2>/dev/null || true
IOT_GUARD_HOTSPOT_INTERFACE=$HOTSPOT \
IOT_GUARD_CLOUD_UPLINK_INTERFACE=$UPLINK \
  "$INSTALL_DIR/ensure_forwarding.sh"
systemctl daemon-reload
systemctl restart iot-guard-collector.service iot-guard-web.service
trap - ERR
echo "Gateway configured: upstream=$UPLINK hotspot=$HOTSPOT address=$ADDRESS capture=$HOTSPOT channel=$CHANNEL."