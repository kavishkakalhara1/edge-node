#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
INSTALL_DIR=/opt/iot-guard
STATE_DIR=/var/lib/iot-guard
CONFIG_DIR=/etc/iot-guard
SERVICE_USER=iotguard

if [[ $EUID -ne 0 ]]; then
  echo "Run this script as root on Raspberry Pi OS Bookworm." >&2
  exit 1
fi
if [[ $(uname -m) != aarch64 ]]; then
  echo "Warning: expected a 64-bit Raspberry Pi OS (aarch64)." >&2
fi

apt-get update
apt-get install -y python3-venv python3-dev libopenblas-dev network-manager iw tcpdump acl openssh-server
id "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --home "$STATE_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"
install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
install -d -m 0755 "$INSTALL_DIR"
setfacl -m "u:$SERVICE_USER:--x" /var/lib/NetworkManager
setfacl -m "d:u:$SERVICE_USER:r--" /var/lib/NetworkManager
find /var/lib/NetworkManager -maxdepth 1 -type f -name 'dnsmasq-*.leases' \
  -exec setfacl -m "u:$SERVICE_USER:r--" {} +
cp -a "$ROOT/src" "$ROOT/pyproject.toml" "$ROOT/README.md" "$INSTALL_DIR/"
cp -a "$ROOT/model" "$INSTALL_DIR/model"
cp "$ROOT/.env.example" "$CONFIG_DIR/iot-guard.env"
head -c 32 /dev/urandom > "$CONFIG_DIR/device-id.key"
chown root:"$SERVICE_USER" "$CONFIG_DIR/device-id.key" "$CONFIG_DIR/iot-guard.env"
chmod 0640 "$CONFIG_DIR/device-id.key" "$CONFIG_DIR/iot-guard.env"

python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install "$INSTALL_DIR"
"$INSTALL_DIR/venv/bin/iot-guard" verify-model "$INSTALL_DIR/model"
"$INSTALL_DIR/venv/bin/iot-guard" init-db
chown -R "$SERVICE_USER":"$SERVICE_USER" "$STATE_DIR"

install -m 0755 "$ROOT/scripts/setup_monitor.sh" "$INSTALL_DIR/setup_monitor.sh"
install -m 0755 "$ROOT/scripts/configure_hotspot.sh" "$INSTALL_DIR/configure_hotspot.sh"
install -m 0755 "$ROOT/scripts/diagnose.sh" "$INSTALL_DIR/diagnose.sh"
install -m 0644 "$ROOT/systemd/iot-guard-monitor.service" /etc/systemd/system/
install -m 0644 "$ROOT/systemd/iot-guard-collector.service" /etc/systemd/system/
install -m 0644 "$ROOT/systemd/iot-guard-web.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable ssh.service iot-guard-monitor.service iot-guard-collector.service iot-guard-web.service

echo "Installation complete. Configure hotspot credentials, then run:"
echo "  sudo IOT_GUARD_HOTSPOT_PASSPHRASE='strong-password' $INSTALL_DIR/configure_hotspot.sh"
echo "Review $CONFIG_DIR/iot-guard.env before starting services."
