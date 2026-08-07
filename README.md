# Raspberry Pi IoT Guard

Passive, per-device anomaly monitoring for a Raspberry Pi 5 hotspot. The built-in `wlan0` hosts IoT clients, while a USB Wi-Fi adapter supplies `wlan1mon` for supplemental monitor-mode visibility. Traffic is aggregated into the 36 numeric features expected by the exported fused GRU + Deep SVDD detector.

## What it does

- Creates a WPA2 hotspot for IoT devices with NetworkManager.
- Discovers clients from DHCP leases; unrelated nearby MAC addresses are ignored.
- Converts each client MAC into a stable HMAC-derived ID. Raw MAC addresses are not stored.
- Captures decrypted hotspot traffic passively on `wlan0`; `wlan1mon` is supplemental.
- Produces aligned 2-second point windows and 10-second temporal windows.
- Scores each interval after four consecutive aggregated records are available.
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
exported scaler + single-layer GRU
    |
newest scaled row + final hidden state
    |
bias-free Deep SVDD head + center distance
    |
raw threshold decision + decaying risk score
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
sudo /opt/iot-guard/venv/bin/iot-guard benchmark-latency --iterations 300
```

The collector needs `CAP_NET_RAW` and `CAP_NET_ADMIN`; the web service runs without network-administration capabilities. Application state is restricted to `/var/lib/iot-guard`.

## Data flow

A DHCP lease registers a connected client. Its MAC is normalized in memory and transformed with:

```text
device_id = "iot-" + HMAC-SHA256(secret, mac)[0:20]
```

The database stores `device_id` and a separate HMAC audit fingerprint, not the raw MAC. For every active device, the feature engine emits aggregated numeric records:

- One record every 2 seconds.
- One record every 10 seconds.
- Zero-traffic windows when a connected device is silent, preserving temporal alignment.

Buffers are isolated by device, aggregation interval, and collector session. The exported `window_size` is four, giving an 8-second warm-up for 2-second records and a 40-second warm-up for 10-second records. Gaps, stream resets, disconnections, and stale timeouts clear the affected buffer. Each complete rolling window scores its newest record.

## Exported model contract

Production startup requires these files with matching SHA-256 entries in `model/manifest.json`:

- `pipeline_artifacts_gru_svdd.joblib`: ordered columns, `MinMaxScaler`, SVDD center, dimensions, window size, and raw threshold.
- `gru_feature_extractor_svdd.pth`: single-layer GRU weights.
- `deep_svdd_head.pth`: bias-free Deep SVDD MLP weights.

The exported dimensions are 36 inputs, 64 GRU hidden values, 100 fused values, and 8 SVDD representation values. Inference reindexes each numeric aggregate to the exported order, applies the exported scaler, concatenates the newest scaled row with the final GRU hidden state, and computes squared Euclidean distance from the exported center. A score strictly greater than the raw threshold is anomalous.

The required ordered schema is stored in the pipeline artifact. It contains log aggregates and numeric network statistics such as packet sizes, header lengths, counts, flags, timing, and TTL. Raw labels, timestamps, IP addresses, MAC addresses, device IDs, and other identifiers are never passed to the model. Categorical codes are not fitted or recomputed online; fixed no-data codes are used where the export did not include mappings.

## Risk score

Risk decays with a configurable six-hour half-life. An anomaly adds severity based on the largest point, temporal, or fused threshold ratio. Simultaneous point and temporal anomalies receive an additional increment. Normal decisions slowly reduce risk. Levels are:

- `low`: below 25
- `medium`: 25 to 49
- `high`: 50 to 74
- `critical`: 75 to 100

Risk is prioritization metadata, not proof that a device is compromised.

## Edge inference controls

Configure these in `/etc/iot-guard/iot-guard.env`:

```text
IOT_GUARD_MODEL_CPU_THREADS=2
IOT_GUARD_MODEL_BUFFER_TIMEOUT_SECONDS=120
IOT_GUARD_MODEL_LOG_LATENCY=false
IOT_GUARD_MODEL_ALLOW_FALLBACK=false
IOT_GUARD_MODEL_MAX_LATENCY_MS=0
```

The fallback is the bundled lightweight point SVDD and is disabled by default. When enabled, it is used if fused artifacts cannot load, or after inference exceeds a nonzero latency limit. Buffers are bounded and no training datasets or training code are loaded on the Pi.

## Feature compatibility warning

The original packet-to-feature generator and categorical encoders were not included with the datasets. This project computes the selected numeric aggregates in `src/iot_guard/features.py` and uses the exported no-data codes for label-coded fields, but matching names does not prove distributional equivalence.

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

Deploy, restart, and diagnose on the Pi:

```bash
sudo ./scripts/install_pi.sh
sudo systemctl restart iot-guard-collector iot-guard-web
sudo /opt/iot-guard/venv/bin/iot-guard verify-model
sudo /opt/iot-guard/venv/bin/iot-guard check
sudo journalctl -u iot-guard-collector -n 100 --no-pager
```

Measure latency, throughput, peak RAM, and CPU use:

```bash
sudo /usr/bin/time -v /opt/iot-guard/venv/bin/iot-guard benchmark-latency --iterations 1000
pidstat -p "$(systemctl show -p MainPID --value iot-guard-collector)" 1
grep -E 'VmRSS|VmHWM' "/proc/$(systemctl show -p MainPID --value iot-guard-collector)/status"
```

The benchmark reports latency percentiles and scores per second; `time -v` reports peak RAM and `pidstat` reports live CPU usage.

For a local dashboard database:

```bash
export IOT_GUARD_STATE_DIR="$PWD/.state"
export IOT_GUARD_DATABASE="$PWD/.state/iot-guard.db"
iot-guard init-db
iot-guard-web
```
