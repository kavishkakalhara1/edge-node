#!/usr/bin/env bash
set -euo pipefail

ENV_FILE=${IOT_GUARD_ENV_FILE:-/etc/iot-guard/iot-guard.env}
if [[ -r $ENV_FILE ]]; then
	set -a
	source "$ENV_FILE"
	set +a
fi

HOTSPOT_INTERFACE=${IOT_GUARD_HOTSPOT_INTERFACE:-wlan0}
MONITOR_INTERFACE=${IOT_GUARD_MONITOR_INTERFACE:-wlan1mon}
CLOUD_INTERFACE=${IOT_GUARD_CLOUD_UPLINK_INTERFACE:-eth0}
HOTSPOT_SSID=$(iw dev "$HOTSPOT_INTERFACE" info 2>/dev/null | awk '$1 == "ssid" {$1=""; sub(/^ /, ""); print; exit}')

printf '%-24s %s\n' "Architecture" "$(uname -m)"
printf '%-24s %s\n' "Hotspot interface" "$(ip -brief link show "$HOTSPOT_INTERFACE" 2>/dev/null || echo missing)"
printf '%-24s %s\n' "Cloud uplink" "$(ip -brief link show "$CLOUD_INTERFACE" 2>/dev/null || echo missing)"
printf '%-24s %s\n' "Monitor interface" "$(ip -brief link show "$MONITOR_INTERFACE" 2>/dev/null || echo missing)"
printf '%-24s %s\n' "Hotspot SSID" "${HOTSPOT_SSID:-inactive}"
printf '%-24s %s\n' "Collector" "$(systemctl is-active iot-guard-collector.service 2>/dev/null || true)"
printf '%-24s %s\n' "Dashboard" "$(systemctl is-active iot-guard-web.service 2>/dev/null || true)"
/opt/iot-guard/venv/bin/iot-guard check
