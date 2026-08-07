#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
INSTALL_DIR=/opt/iot-test-device
CONFIG_DIR=/etc/iot-test-device
SERVICE_USER=iottest

if [[ $EUID -ne 0 ]]; then
  echo "Run this script as root on Raspberry Pi OS Bookworm." >&2
  exit 1
fi
if [[ $(uname -m) != aarch64 ]]; then
  echo "Warning: expected a 64-bit Raspberry Pi OS (aarch64)." >&2
fi

apt-get update
apt-get install -y python3-venv network-manager
id "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
install -d -m 0755 "$INSTALL_DIR"
install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
cp -a "$ROOT/src" "$ROOT/pyproject.toml" "$ROOT/README.md" "$INSTALL_DIR/"
install -m 0640 -o root -g "$SERVICE_USER" "$ROOT/config/test-device.env" "$CONFIG_DIR/test-device.env"

python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install "$INSTALL_DIR"

install -m 0755 "$ROOT/scripts/configure_wifi.sh" "$INSTALL_DIR/configure_wifi.sh"
install -m 0644 "$ROOT/systemd/iot-test-device.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable iot-test-device.service

echo "Installation complete. Configure Wi-Fi with $INSTALL_DIR/configure_wifi.sh, then start the service."
