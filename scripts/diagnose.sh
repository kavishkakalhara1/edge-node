#!/usr/bin/env bash
set -euo pipefail

printf '%-24s %s\n' "Architecture" "$(uname -m)"
printf '%-24s %s\n' "Hotspot interface" "$(ip -brief link show wlan0 2>/dev/null || echo missing)"
printf '%-24s %s\n' "Monitor interface" "$(ip -brief link show wlan1mon 2>/dev/null || echo missing)"
printf '%-24s %s\n' "Hotspot connection" "$(nmcli -t -f NAME,DEVICE connection show --active | grep '^iot-guard-hotspot:' || echo inactive)"
printf '%-24s %s\n' "Collector" "$(systemctl is-active iot-guard-collector.service 2>/dev/null || true)"
printf '%-24s %s\n' "Dashboard" "$(systemctl is-active iot-guard-web.service 2>/dev/null || true)"
/opt/iot-guard/venv/bin/iot-guard check
