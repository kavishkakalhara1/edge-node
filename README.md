# Raspberry Pi IoT Guard

Passive, per-device anomaly monitoring for a Raspberry Pi 5 hotspot. The built-in `wlan0` hosts IoT clients, while a USB Wi-Fi adapter supplies `wlan1mon` for supplemental monitor-mode visibility. Traffic is aggregated into the 71 numeric features expected by the bundled Deep SVDD + GRU ensemble.

## What it does

- Creates a WPA2 hotspot for IoT devices with NetworkManager.
- Discovers clients from DHCP leases; unrelated nearby MAC addresses are ignored.
- Converts each client MAC into a stable HMAC-derived ID. Raw MAC addresses are not stored.
- Captures decrypted hotspot traffic passively on `wlan0`; `wlan1mon` is supplemental.
- Produces aligned 2-second point windows and 10-second temporal windows.
- Scores point anomalies immediately and fused anomalies after seven 10-second windows.
- Stores traffic summaries, decisions, risk history, and service logs in SQLite WAL mode.
- Hosts a local FastAPI dashboard listing devices, anomalies, and rolling risk.
- Never retrains from live traffic or allows anomalies to update the normal baseline.

## Architecture

```text
IoT clients
    |
wlan0 WPA2 hotspot ---- NetworkManager DHCP leases
    |                              |
    |                              +-- HMAC device identity
    |
passive capture <---- wlan1mon supplemental USB monitor
    |
per-device 2s + 10s feature windows
    |
Deep SVDD point score + GRU temporal score
    |
OR-preserving fused decision + decaying risk score
    |
SQLite WAL <---- FastAPI dashboard :8080
```

Monitor-mode frames on a WPA2 channel are generally encrypted and do not reproduce the model's IP/TCP features. The app therefore uses decrypted traffic visible on the hotspot interface for ML and treats the external adapter as supplemental passive visibility. It performs no deauthentication, injection, blocking, or active probing.

## Hardware and OS

- Raspberry Pi 5 running 64-bit Raspberry Pi OS Bookworm.
- Built-in Wi-Fi available as `wlan0`.
- USB Wi-Fi adapter with Linux monitor-mode support, normally `wlan1`.
- Ethernet uplink is recommended so `wlan0` can remain dedicated to the hotspot.
- Use only on networks and devices you own or are authorized to monitor.

Check adapter monitor support:

```bash
iw list | sed -n '/Supported interface modes:/,/Band/p'
```

## Install on the Pi

Copy this project to the Pi, then run:

```bash
cd raspberry-pi-iot-guard
sudo ./scripts/install_pi.sh
```

The installer enables SSH and all IoT Guard systemd services to start automatically on future boots.

Choose a strong hotspot passphrase and create the access point:

```bash
sudo IOT_GUARD_HOTSPOT_SSID='IoT-Guard' \
  IOT_GUARD_HOTSPOT_PASSPHRASE='kali12345678' \
  IOT_GUARD_WIFI_CHANNEL=6 \
  /opt/iot-guard/configure_hotspot.sh
```

Review `/etc/iot-guard/iot-guard.env`, particularly interface names and the NetworkManager lease path. Start services:

```bash
sudo systemctl start iot-guard-monitor iot-guard-collector iot-guard-web
sudo /opt/iot-guard/diagnose.sh
```

Open `http://10.42.0.1:8080/` from a device connected to the hotspot. Do not expose the dashboard to the public internet without authentication and TLS through a reverse proxy.

## Service operations

```bash
sudo systemctl status iot-guard-monitor iot-guard-collector iot-guard-web
sudo journalctl -u iot-guard-collector -f
sudo systemctl restart iot-guard-collector
sudo /opt/iot-guard/venv/bin/iot-guard check
sudo /opt/iot-guard/venv/bin/iot-guard verify-model
```

The collector needs `CAP_NET_RAW` and `CAP_NET_ADMIN`; the web service runs without network-administration capabilities. Application state is restricted to `/var/lib/iot-guard`.

## Data flow

A DHCP lease registers a connected client. Its MAC is normalized in memory and transformed with:

```text
device_id = "iot-" + HMAC-SHA256(secret, mac)[0:20]
```

The database stores `device_id` and a separate HMAC audit fingerprint, not the raw MAC. For every active device, the feature engine emits:

- One 71-feature row every 2 seconds.
- One 71-feature row every 10 seconds.
- Zero-traffic windows when a connected device is silent, preserving temporal alignment.

The temporal model warms for 70 seconds because it needs seven consecutive 10-second windows. The first six are history and the seventh is the observed target.

## Risk score

Risk decays with a configurable six-hour half-life. An anomaly adds severity based on the largest point, temporal, or fused threshold ratio. Simultaneous point and temporal anomalies receive an additional increment. Normal decisions slowly reduce risk. Levels are:

- `low`: below 25
- `medium`: 25 to 49
- `high`: 50 to 74
- `critical`: 75 to 100

Risk is prioritization metadata, not proof that a device is compromised.

## Feature compatibility warning

The original packet-to-feature generator was not included with the datasets; the available archive contains feature-selection code only. This project implements explicit formulas for all 71 fields in `src/iot_guard/features.py`, but matching names does not prove distributional equivalence.

Before operational use:

1. Capture several hours of known-benign traffic from representative devices.
2. Compare standardized feature means against `model/monitoring_baseline.json`.
3. Review false alerts per device type.
4. Recalibrate or retrain offline if live feature distributions differ.
5. Do not automatically train on traffic labeled benign by the deployed model.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest -q
uvicorn iot_guard.web:app --reload --port 8080
```

For a local dashboard database:

```bash
export IOT_GUARD_STATE_DIR="$PWD/.state"
export IOT_GUARD_DATABASE="$PWD/.state/iot-guard.db"
iot-guard init-db
iot-guard-web
```
