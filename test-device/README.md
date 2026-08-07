# IoT Guard Test Device

This folder contains the program for a separate Raspberry Pi Zero 2 W used as a controlled IoT client. It connects to the IoT Guard hotspot and generates sensor-like traffic only toward the configured guard gateway.

## Traffic profiles

- `normal`: one small UDP sensor message every 5 seconds and one dashboard HTTP check per minute.
- `burst`: ten larger UDP messages every 100 ms and one HTTP check every 10 seconds. Use this profile briefly to exercise anomaly detection.

The default destination is `10.42.0.1`. The UDP receiver does not need to exist: the hotspot interface still observes the packets. HTTP checks against port `8080` provide bidirectional TCP traffic when the dashboard is running.

## Install on the test Pi

Copy only this `test-device` folder to the Pi Zero 2 W, then run:

```bash
cd test-device
sudo ./scripts/install_pi.sh
sudo IOT_TEST_WIFI_SSID='IoT-Guard' \
  IOT_TEST_WIFI_PASSPHRASE='the-same-hotspot-passphrase' \
  /opt/iot-test-device/configure_wifi.sh
sudo systemctl start iot-test-device
```

Check operation with:

```bash
systemctl status iot-test-device
journalctl -u iot-test-device -f
```

The edge dashboard should list the Pi after NetworkManager records its DHCP lease. The fused model needs four records, giving an 8-second warm-up for 2-second aggregates and 40 seconds for 10-second aggregates.

## Run profiles manually

Stop the service before a manual test so two generators do not run at once:

```bash
sudo systemctl stop iot-test-device
/opt/iot-test-device/venv/bin/iot-test-device --profile normal --duration 120
/opt/iot-test-device/venv/bin/iot-test-device --profile burst --duration 30
sudo systemctl start iot-test-device
```

For persistent profile selection, edit `/etc/iot-test-device/test-device.env`, set `IOT_TEST_PROFILE` to `normal` or `burst`, and restart the service. Keep `burst` tests short; the profile sends about 100 packets per second on the private hotspot.

## Development

From this folder:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```