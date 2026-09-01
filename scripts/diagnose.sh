#!/usr/bin/env bash
set -euo pipefail

ENV_FILE=${IOT_GUARD_ENV_FILE:-/etc/iot-guard/iot-guard.env}
if [[ -r $ENV_FILE ]]; then
	set -a
	source "$ENV_FILE"
	set +a
fi

HOTSPOT_INTERFACE=${IOT_GUARD_HOTSPOT_INTERFACE:-wlan0}
MONITOR_INTERFACE=${IOT_GUARD_MONITOR_INTERFACE:-}
CLOUD_INTERFACE=${IOT_GUARD_CLOUD_UPLINK_INTERFACE:-eth0}
LEASE_FILE=${IOT_GUARD_DHCP_LEASE_FILE:-/var/lib/NetworkManager/dnsmasq-wlan0.leases}
HOTSPOT_SSID=$(iw dev "$HOTSPOT_INTERFACE" info 2>/dev/null | awk '$1 == "ssid" {$1=""; sub(/^ /, ""); print; exit}')
HOTSPOT_CHANNEL=$(iw dev "$HOTSPOT_INTERFACE" info 2>/dev/null | awk '$1 == "channel" {print $2; exit}')
if [[ -n $MONITOR_INTERFACE ]]; then
	MONITOR_STATUS=$(ip -brief link show "$MONITOR_INTERFACE" 2>/dev/null || echo missing)
	MONITOR_MODE=$(iw dev "$MONITOR_INTERFACE" info 2>/dev/null | awk '$1 == "type" {print $2; exit}')
	MONITOR_CHANNEL=$(iw dev "$MONITOR_INTERFACE" info 2>/dev/null | awk '$1 == "channel" {print $2; exit}')
else
	MONITOR_STATUS=disabled
	MONITOR_MODE=disabled
	MONITOR_CHANNEL=none
fi

if [[ -r $LEASE_FILE ]]; then
	LEASE_STATUS="readable ($(awk 'NF >= 4 {count++} END {print count + 0}' "$LEASE_FILE") clients)"
elif [[ -e $LEASE_FILE ]]; then
	LEASE_STATUS=unreadable
else
	LEASE_STATUS=missing
fi

printf '%-24s %s\n' "Architecture" "$(uname -m)"
printf '%-24s %s\n' "Hotspot interface" "$(ip -brief link show "$HOTSPOT_INTERFACE" 2>/dev/null || echo missing)"
printf '%-24s %s\n' "Cloud uplink" "$(ip -brief link show "$CLOUD_INTERFACE" 2>/dev/null || echo missing)"
printf '%-24s %s\n' "Monitor interface" "$MONITOR_STATUS"
printf '%-24s %s\n' "Monitor mode" "${MONITOR_MODE:-inactive}"
printf '%-24s %s\n' "Channel alignment" "AP=${HOTSPOT_CHANNEL:-none} monitor=${MONITOR_CHANNEL:-none}"
printf '%-24s %s\n' "Hotspot SSID" "${HOTSPOT_SSID:-inactive}"
printf '%-24s %s\n' "DHCP lease file" "$LEASE_FILE"
printf '%-24s %s\n' "DHCP lease status" "$LEASE_STATUS"
printf '%-24s %s\n' "Collector" "$(systemctl is-active iot-guard-collector.service 2>/dev/null || true)"
printf '%-24s %s\n' "Dashboard" "$(systemctl is-active iot-guard-web.service 2>/dev/null || true)"
/opt/iot-guard/venv/bin/iot-guard check
