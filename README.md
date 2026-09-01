# Raspberry Pi IoT Guard

IoT Guard turns a Raspberry Pi 5 into an IoT gateway that provides a WPA2 access point, observes each connected device, performs local GRU + Deep SVDD anomaly detection, records evidence in SQLite, reports only detected anomalies to a cloud API, and executes bounded healing actions.

The supported default topology is Ethernet upstream and management on `eth0`, with the built-in `wlan0` dedicated to the IoT access point and decrypted IP capture.

## System overview

```text
                    management and cloud network
                              |
                       eth0 (upstream)
                      /                 \
       dashboard :8080                   cloud API
       10 Mbps reserved                  anomalies only
              |                               |
              +---------- Raspberry Pi ------+
                              |
                   routing, NAT and healing
                              |
                       wlan0 WPA2 AP
                     192.168.50.1/24
                              |
                         IoT devices
```

The project defaults use `10.42.0.1/24`; the deployed example above uses `192.168.50.1/24`. Use the values configured in `/etc/iot-guard/iot-guard.env`.

The runtime consists of:

- `iot-guard-collector`: DHCP discovery, packet capture, feature windows, inference, cloud reporting, and healing execution.
- `iot-guard-web`: local FastAPI dashboard and administration API on port `8080`.
- NetworkManager: WPA2 AP, DHCP, DNS forwarding, routing, and masquerading.
- SQLite WAL database: devices, feature windows, inference, risk, logs, and healing requests.
- `ensure_forwarding.sh`: forwarding compatibility, dashboard isolation, and management bandwidth reservation.

No packet payloads or packet capture files are retained. Model features are numeric traffic summaries.

## Requirements

- Raspberry Pi 5 with 64-bit Raspberry Pi OS Bookworm or a compatible Debian system.
- `eth0` connected to an upstream network with internet access.
- Built-in `wlan0` available for AP mode.
- Root access for installation and gateway configuration.
- Devices and networks that you own or are authorized to monitor.

The normal IP monitoring path does not require a USB Wi-Fi adapter. A separate adapter is required for reliable monitor-mode visibility into raw 802.11 management frames.

## Installation

From the repository root:

```bash
sudo ./scripts/install_pi.sh
```

The installer:

- installs Python, NetworkManager, nftables, iptables, `tc`, Scapy dependencies, and OpenSSH;
- creates the unprivileged `iotguard` service account;
- installs the application and model under `/opt/iot-guard`;
- creates state under `/var/lib/iot-guard`;
- creates `/etc/iot-guard/iot-guard.env` from `.env.example`;
- generates a healing API token and device identity secret;
- verifies all model artifact hashes and initializes SQLite;
- installs and enables the collector and dashboard services;
- leaves the optional monitor service disabled.

Configure the Ethernet/AP gateway with a passphrase of at least 12 characters:

```bash
sudo IOT_GUARD_HOTSPOT_SSID='IoTGuard24' \
  IOT_GUARD_HOTSPOT_PASSPHRASE='replace-with-a-strong-password' \
  IOT_GUARD_HOTSPOT_ADDRESS='192.168.50.1/24' \
  IOT_GUARD_WIFI_CHANNEL=6 \
  /opt/iot-guard/configure_gateway.sh
```

This configures `wlan0` as a visible 2.4 GHz WPA2-RSN/CCMP AP, disables Wi-Fi power saving and IPv6 on the AP, enables NetworkManager shared-mode DHCP/NAT, persists the runtime interface settings, disables legacy `hostapd`/`dnsmasq` services, and restarts IoT Guard. If migration fails, the script attempts to restore legacy hotspot services that were active before it ran.

Do not start `iot-guard-monitor.service` in the normal AP-only topology.

## Dashboard access and protection

The dashboard binds to `0.0.0.0:8080`, but the installed firewall permits access only through loopback and the management/uplink interface. IoT clients on `wlan0` are rejected on dashboard port `8080`.

For the deployed example, open:

```text
http://192.168.8.10:8080/
```

Use the actual `eth0` address shown by:

```bash
ip -4 address show dev eth0
```

The management helper reserves 10 Mbps of `eth0` egress for dashboard responses by default. HTB gives dashboard traffic priority while `fq_codel` controls queue latency. Dashboard and ordinary traffic can borrow unused capacity up to the configured link rate. The web service runs with maximum systemd CPU weight and elevated I/O weight, while the collector is capped at 250% CPU on the four-core Pi so flood processing cannot consume every core.

These controls protect management availability from forwarded IP traffic and local resource contention. They cannot guarantee access during RF jamming, AP deauthentication, physical link failure, kernel exhaustion, or a saturated upstream device. A separate management interface or out-of-band network is required for that level of isolation.

## Configuration

Runtime settings are read from `/etc/iot-guard/iot-guard.env`. Restart affected services after editing it:

```bash
sudo systemctl restart iot-guard-collector iot-guard-web
```

### Application settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `IOT_GUARD_STATE_DIR` | `/var/lib/iot-guard` | State directory. |
| `IOT_GUARD_DATABASE` | `$STATE_DIR/iot-guard.db` | SQLite database. |
| `IOT_GUARD_ARTIFACT_DIR` | `/opt/iot-guard/model` | Model artifact directory. |
| `IOT_GUARD_ID_SECRET_FILE` | `/etc/iot-guard/device-id.key` | HMAC identity secret. |
| `IOT_GUARD_DHCP_LEASE_FILE` | `/var/lib/NetworkManager/dnsmasq-wlan0.leases` | AP lease file. |
| `IOT_GUARD_DEVICE_REGISTRY` | `/etc/iot-guard/devices.json` | Operator-managed MAC-to-name registry. |
| `IOT_GUARD_CAPTURE_INTERFACES` | `wlan0` | Comma-separated capture interfaces. |
| `IOT_GUARD_IGNORED_DEVICE_MACS` | empty | Comma-separated devices omitted from monitoring/UI. |
| `IOT_GUARD_PROTECTED_DEVICE_MACS` | empty | Comma-separated devices that healing cannot target. |
| `IOT_GUARD_HOTSPOT_INTERFACE` | `wlan0` | IoT AP interface. |
| `IOT_GUARD_HOTSPOT_SSID` | `IoT-Guard` | Expected AP SSID. |
| `IOT_GUARD_HOTSPOT_SUBNET` | `10.42.0.0/24` | Reserved subnet metadata; currently not used for enforcement. |
| `IOT_GUARD_MONITOR_INTERFACE` | empty | Optional monitor-mode interface; empty disables it. |
| `IOT_GUARD_WEB_HOST` | `0.0.0.0` | Dashboard bind address. |
| `IOT_GUARD_WEB_PORT` | `8080` | Dashboard and management firewall port. |
| `IOT_GUARD_HEALING_API_TOKEN` | generated | Token for healing and reset API calls. |
| `IOT_GUARD_CLOUD_API_ENDPOINT` | empty in code | Cloud POST URL; empty disables cloud delivery. |
| `IOT_GUARD_CLOUD_UPLINK_INTERFACE` | `eth0` | Interface to which cloud sockets are bound. |
| `IOT_GUARD_CLOUD_API_TOKEN` | empty | Optional cloud bearer token. |
| `IOT_GUARD_CLOUD_API_TIMEOUT_SECONDS` | `30` | Cloud HTTP timeout. |
| `IOT_GUARD_CLOUD_ANOMALY_INTERVAL_SECONDS` | `120` | Minimum successful report interval per device. |
| `IOT_GUARD_RETENTION_DAYS` | `30` | Historical database retention. |
| `IOT_GUARD_MODEL_CPU_THREADS` | `2` | PyTorch CPU threads. |
| `IOT_GUARD_MODEL_BUFFER_TIMEOUT_SECONDS` | `120` | Stale rolling-buffer timeout. |
| `IOT_GUARD_MODEL_LOG_LATENCY` | `false` | Log each inference latency. |
| `IOT_GUARD_MODEL_ALLOW_FALLBACK` | `false` | Permit legacy point-SVDD fallback. |
| `IOT_GUARD_MODEL_MAX_LATENCY_MS` | `0` | Fallback trigger; zero disables latency switching. |

The supplied `.env.example` enables the project cloud endpoint and contains example MAC addresses. Review and replace those values before deployment. The installer generates the local healing token but does not generate a cloud token.

### Gateway-only settings

These values are consumed by shell configuration scripts. `configure_gateway.sh` persists the interface, SSID, address, channel, capture, and lease settings where applicable.

| Variable | Default | Purpose |
| --- | --- | --- |
| `IOT_GUARD_HOTSPOT_ADDRESS` | `10.42.0.1/24` | AP address and DHCP subnet. |
| `IOT_GUARD_HOTSPOT_PASSPHRASE` | none | WPA2 PSK; minimum 12 characters. |
| `IOT_GUARD_WIFI_CHANNEL` | `6` | Fixed 2.4 GHz AP channel. |
| `IOT_GUARD_MONITOR_PARENT` | `wlan1` | Optional adapter used by monitor setup. |
| `IOT_GUARD_UPLINK_RATE_MBIT` | detected from sysfs, otherwise `100` | HTB root rate. |
| `IOT_GUARD_MANAGEMENT_RATE_MBIT` | `10` | Dashboard guaranteed egress rate. |
| `IOT_GUARD_INSTALL_DIR` | `/opt/iot-guard` | Gateway helper installation path. |
| `IOT_GUARD_ENV_FILE` | `/etc/iot-guard/iot-guard.env` | Environment file updated/read by scripts. |

The hotspot, cloud uplink, and optional monitor roles must use valid interfaces. Hotspot and cloud uplink must differ; an enabled monitor interface must also differ from the AP. The management rate must be positive and lower than the uplink rate.

## Networking, firewall, and QoS

`ensure_forwarding.sh` runs as a privileged `ExecStartPre` command whenever the collector starts. It is idempotent and performs the following operations:

- allows `wlan0 -> eth0` forwarding;
- allows established/related `eth0 -> wlan0` return traffic;
- leaves NetworkManager's subnet-scoped masquerading in control of NAT;
- permits dashboard TCP traffic only from loopback and `eth0`;
- rejects dashboard TCP traffic arriving on all other interfaces;
- recreates the `eth0` HTB scheduler and dashboard/default `fq_codel` classes.

It does not flush Docker chains or the IoT Guard nftables healing table. The explicit forward rules also prevent an older iptables-nft `FORWARD DROP` policy from silently blocking AP clients.

Inspect the live controls:

```bash
sudo iptables -S IOT_GUARD_MANAGEMENT
sudo iptables -L FORWARD -n -v --line-numbers
sudo nft list table inet iot_guard
tc -s class show dev eth0
tc filter show dev eth0 parent 1:
sysctl net.ipv4.ip_forward
```

## Device discovery and identity

The collector reads NetworkManager DHCP leases and intersects them with stations currently associated to the AP. Nearby devices that are not associated are not registered. Packets are attributed when a registered device MAC is either the Ethernet source or destination, so incoming and outgoing AP traffic contributes to that device's window.

Friendly device names can be maintained in `/etc/iot-guard/devices.json`. A configured
name overrides the DHCP hostname and also names an associated device before it receives a
lease. MAC addresses are normalized, so colon- and hyphen-separated forms are accepted.
The installer creates this file once and preserves local edits during future reinstalls.

```json
{
  "devices": [
    {
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "name": "Living room camera"
    },
    {
      "mac_address": "02:00:00:00:00:01",
      "name": "Test smart plug"
    }
  ]
}
```

Edit it as root, validate the JSON, and restart the collector to update names immediately:

```bash
sudoedit /etc/iot-guard/devices.json
sudo python3 -m json.tool /etc/iot-guard/devices.json >/dev/null
sudo systemctl restart iot-guard-collector
```

The collector also reloads the file during normal device refreshes. Invalid JSON, malformed
MAC addresses, blank names, and duplicate MAC entries are ignored and logged without
stopping packet monitoring. For duplicate MACs, the first valid entry wins.

The local identifier is:

```text
device_id = "id-" + normalized_mac_without_colons
```

SQLite stores the normalized MAC for local administration and a separate HMAC audit fingerprint. MACs, IPs, timestamps, and device IDs are not model inputs. Attack context may include local peer identity and address data in anomaly cloud reports.

## Capture and features

Scapy captures decrypted Ethernet frames on `wlan0` with `promisc=False`. The model path accepts IPv4 packets and extracts IP plus TCP/UDP metadata: addresses, ports, protocol, packet/IP/header/payload lengths, IP and TCP flags, MSS, TTL, TCP window, fragmentation, and timing. Payload content is not inspected or stored.

Each connected device has aligned 2-second and 10-second accumulators. Every completed record contains 79 finite numeric fields, including directional packet counts, unique IP/MAC/port/protocol counts, fragmentation, TCP flag counts, and average/minimum/maximum/standard-deviation statistics. Silent connected devices produce zero-traffic records to retain temporal alignment.

The active model requires 36 ordered columns. All 36 are present in every generated record; the remaining 43 fields are retained for evidence and cloud analysis. The required columns include five `log_*` fields and several categorical-code fields for which the original encoders were not exported. They therefore use fixed no-data values. This satisfies the artifact schema but does not prove training/live distribution parity.

Current model-path limitations:

- IPv6, ARP, DHCP, and non-IP Ethernet frames do not feed GRU-SVDD features.
- Application payloads hidden by TLS or other end-to-end encryption are not visible.
- Empty windows can participate in scoring.
- Fixed legacy categorical codes and `log_*` placeholders are not observed telemetry.
- The model detects deviation; it does not prove compromise or classify every attack.
- A single AP radio cannot guarantee visibility during jamming or interface disruption.

## Model and inference

Production inference requires hashes in `model/manifest.json` to match:

- `pipeline_artifacts_gru_svdd.joblib`: scaler, ordered feature columns, dimensions, window size, center, and threshold;
- `gru_feature_extractor_svdd.pth`: single-layer GRU weights;
- `deep_svdd_head.pth`: bias-free Deep SVDD head weights.

The fused model uses 36 inputs, 64 GRU hidden values, a 100-value fused vector, and an 8-value SVDD representation. Four consecutive records are required per device and resolution. This gives an 8-second warm-up for 2-second records and a 40-second warm-up for 10-second records. Gaps larger than 1.5 intervals, stale buffers, disconnects, and collector restarts prevent unrelated records from being joined.

The exported scaler transforms each record in the exact artifact order. The newest scaled record is concatenated with the final GRU hidden state, passed through the SVDD head, and compared with the exported center. A squared distance strictly greater than the exported threshold is anomalous. The edge never retrains from live traffic.

The optional fallback loads the bundled point SVDD when fused artifacts fail, or when an enabled latency limit is exceeded. It is disabled by default to avoid silently changing the production detector.

Verify the deployed artifacts:

```bash
sudo /opt/iot-guard/venv/bin/iot-guard verify-model
sudo /opt/iot-guard/venv/bin/iot-guard benchmark-latency --iterations 300
```

## Risk

Risk is local prioritization metadata in the range `[0, 1]`. An anomalous result combines normalized GRU/SVDD evidence and a bounded repeat-anomaly boost. A benign result decreases risk by `0.04` toward a `0.05` baseline. Consecutive anomalies are capped at five for the boost calculation.

| Level | Range |
| --- | --- |
| Low | `< 0.25` |
| Medium | `0.25` to `< 0.50` |
| High | `0.50` to `< 0.75` |
| Critical | `>= 0.75` |

Risk and consecutive-anomaly state reset at UTC day boundaries. Historical records remain subject to the retention period.

## Cloud reporting

Cloud reporting is disabled when `IOT_GUARD_CLOUD_API_ENDPOINT` is empty. When enabled, HTTP(S) sockets are bound to `IOT_GUARD_CLOUD_UPLINK_INTERFACE` with `SO_BINDTODEVICE`. An optional token is sent as `Authorization: Bearer <token>`.

Only detected anomalies are sent. This is enforced twice:

1. the collector calls the cloud reporter only when `is_anomaly` is true;
2. the cloud reporter rejects any payload whose `flag` is not exactly `anomaly`.

Benign windows, inference results, and risk changes remain local. After each cloud delivery attempt, that device waits for the configured anomaly interval before another report. Intervals are independent per device, and failed requests retry after the interval instead of on every anomalous window. Submission is synchronous with the configured timeout; there is no durable outbound queue.

Example payload:

```json
{
  "flag": "anomaly",
  "risk_score": 0.72,
  "device_id": "id-aabbccddeeff",
  "network_features": {
    "network_packets_all_count": 12.0,
    "network_ttl_avg": 63.5
  },
  "attack_context": {
    "basis": "dominant_incoming_peer",
    "attacker": {
      "device_id": "id-020000000001",
      "mac_address": "02:00:00:00:00:01",
      "ipv4": "192.168.50.20",
      "hostname": "scanner"
    },
    "victim": {
      "device_id": "id-aabbccddeeff",
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "ipv4": "192.168.50.30",
      "hostname": "camera"
    }
  }
}
```

`network_features` contains the complete unscaled 79-field map; only two fields are shown above. `attack_context` is included when the dominant peer can be resolved. It is directional evidence, not definitive attribution.

The cloud may return an `actions` array. It may target an explicit `device_id`, or use `"target": "attacker"`/`"victim"` when attack context exists. Accepted actions are written to SQLite with `source=cloud` and executed by the collector. Unsupported, malformed, and protected-device targets are rejected locally.

## Dashboard and API

The dashboard shows connected and historical devices, SLST (`Asia/Colombo`) timestamps, risk, recent anomalies, model features, attacker/victim context, and healing status. It supports device filtering, unblocking, and a token-protected database reset.

| Method and path | Purpose | Token required |
| --- | --- | --- |
| `GET /` | Dashboard. | No |
| `GET /devices/{device_id}` | Device detail. | No |
| `GET /api/devices` | Dashboard JSON. | No |
| `GET /api/devices/{device_id}` | Device JSON. | No |
| `GET /health` | Web/database health. | No |
| `POST /api/devices/{device_id}/healing-actions/{action_id}` | Queue action. | Yes |
| `GET /api/healing-actions/{request_id}` | Read action status. | Yes |
| `POST /api/admin/reset-database` | Delete runtime data. | Yes |

The firewall is the dashboard's access boundary; read-only routes do not implement user authentication. Do not expose port `8080` to an untrusted or public management network. Use an authenticated TLS reverse proxy if remote access is required.

## Healing actions

The web process has no network-administration capability. It validates the API token and queues requests in SQLite. The collector claims queued work and applies it with bounded `CAP_NET_ADMIN`. Request states are `queued`, `running`, `succeeded`, and `failed`; a `202` response means queued, not enforced.

Automatic cloud actions:

| ID | Behavior |
| --- | --- |
| `NET-01` | Adaptive bidirectional device rate limit. |
| `NET-02` | Timed flood hardening. |
| `NET-03` | Timed source IPv4 block. |
| `NET-05` | Timed NULL/FIN/Xmas, SYN-rate, and ICMP-rate scan filtering. |
| `NET-08` | Fixed bidirectional device traffic shaping. |
| `SEG-02` | MAC block in both directions. |
| `SEG-03` | Full IPv4 isolation with optional heartbeat exception. |
| `L2-01`, `L2-02` | Restore and pin DHCP IP-to-MAC neighbor binding. |
| `ACC-01` | Progressive 1/5/15/60/1440-minute source ban. |
| `ESC-01` | Operator notification in the journal. |
| `ESC-03` | Incident snapshot stored with current evidence. |

Dashboard/API-only parameterized actions:

| ID | Required parameters |
| --- | --- |
| `NET-04` | `port`; optional `protocol` (`tcp` or `udp`). |
| `NET-06` | `destination_ipv4`. |
| `NET-07` | `source_cidr`. |
| `ESC-02` | `approved: true`; applies permanent isolation. |
| `UNBLOCK` | Internal action that removes device controls. |

Most actions require the target to be currently connected with a valid leased IPv4. Protected MACs cannot be targeted. `UNBLOCK` removes IPv4/MAC set entries, pair entries, and the deterministic per-device `tc` filters. Full details and feasibility notes are in `docs/healing-actions.json`.

Queue and inspect an action from the management network:

```bash
TOKEN='value-from-/etc/iot-guard/iot-guard.env'
BASE_URL='http://192.168.8.10:8080'

curl -X POST \
  "$BASE_URL/api/devices/id-aabbccddeeff/healing-actions/NET-03" \
  -H "X-IoT-Guard-Token: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"parameters":{"source_ipv4":"192.168.50.20","ttl_seconds":300}}'

curl "$BASE_URL/api/healing-actions/REQUEST_ID" \
  -H "X-IoT-Guard-Token: $TOKEN"
```

Reset all runtime database records only when intentionally rebuilding state:

```bash
curl -X POST "$BASE_URL/api/admin/reset-database" \
  -H "X-IoT-Guard-Token: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"confirmation":"RESET"}'
```

## Optional wireless monitoring

The code can inspect raw 802.11 observations for evil-twin beacons, deauthentication/disassociation floods, authentication/association floods, and probe-request floods. This requires an independent monitor-capable adapter on the AP channel. The normal gateway configuration explicitly disables monitor mode and captures only `wlan0` Ethernet/IP traffic.

Check adapter support before attempting monitor setup:

```bash
iw list | sed -n '/Supported interface modes:/,/Band/p'
```

RF alerts are stored and logged; they are not inputs to the current 36-feature GRU-SVDD artifact. Monitor mode cannot prevent jamming and may not observe all frames under load.

## Operations

```bash
sudo systemctl status iot-guard-collector iot-guard-web
sudo systemctl restart iot-guard-collector iot-guard-web
sudo journalctl -u iot-guard-collector -f
sudo journalctl -u iot-guard-web -f
sudo /opt/iot-guard/diagnose.sh
sudo /opt/iot-guard/venv/bin/iot-guard check
sudo /opt/iot-guard/venv/bin/iot-guard verify-model
curl http://127.0.0.1:8080/health
```

Run `iot-guard check` as root or as `iotguard`; SQLite initialization requires write access to the state directory.

Useful network checks:

```bash
ip -4 -brief address show eth0
ip -4 -brief address show wlan0
ip route
nmcli connection show --active
iw dev wlan0 station dump
sudo cat /var/lib/NetworkManager/dnsmasq-wlan0.leases
sudo tcpdump -ni wlan0 ip
curl --interface eth0 https://example.com
```

### Common failures

**AP client has a lease and can reach the Pi but has no internet**

Check `net.ipv4.ip_forward`, NetworkManager NAT, and the legacy FORWARD policy. Restarting the collector reruns the forwarding helper:

```bash
sudo systemctl restart iot-guard-collector
sudo iptables -L FORWARD -n -v --line-numbers
```

**Dashboard works locally but not from Ethernet**

Confirm the `eth0` address, port, service, and management chain:

```bash
sudo systemctl status iot-guard-web
sudo ss -ltnp | grep ':8080'
sudo iptables -S IOT_GUARD_MANAGEMENT
```

Access from the IoT hotspot is intentionally blocked.

**No devices appear**

Confirm the station is associated and the lease file path is current and readable by the service account:

```bash
iw dev wlan0 station dump
sudo -u iotguard cat /var/lib/NetworkManager/dnsmasq-wlan0.leases
```

**Cloud delivery fails**

Check the endpoint/token without printing secrets, verify `eth0` internet access, and inspect collector logs. Cloud and hotspot interfaces must differ.

**Healing fails**

Read the request `error`, verify that the device is connected with a current lease, and inspect the nftables table. Protected devices are intentionally refused.

## Data and security

- `/var/lib/iot-guard/iot-guard.db`: runtime database.
- `/var/lib/iot-guard/latency-benchmark.json`: latest benchmark result.
- `/etc/iot-guard/iot-guard.env`: service configuration and API tokens, mode `0640`.
- `/etc/iot-guard/devices.json`: operator-managed device names, mode `0640`.
- `/etc/iot-guard/device-id.key`: local identity secret, mode `0640`.
- `/opt/iot-guard/model`: verified inference artifacts.

The collector has only `CAP_NET_RAW` and `CAP_NET_ADMIN`; the web service has neither. Systemd applies filesystem, home, kernel, control-group, and privilege restrictions. Keep the management network trusted, protect configuration backups, rotate exposed tokens, and never commit real credentials.

Additional design documents:

- `docs/database-schema.md`
- `docs/devices.example.json`
- `docs/healing-actions.json`
- `docs/threat-model.md`

## Development and tests

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

Run locally with isolated state:

```bash
export IOT_GUARD_STATE_DIR="$PWD/.state"
export IOT_GUARD_DATABASE="$PWD/.state/iot-guard.db"
export IOT_GUARD_ARTIFACT_DIR="$PWD/model"
iot-guard init-db
iot-guard-web
```

The test suite covers packet parsing, bidirectional feature attribution, feature/model contracts, temporal buffer isolation, risk/database behavior, anomaly-only cloud delivery, cloud healing responses, protected devices, nftables/traffic-control commands, and dashboard administration.

Before operational deployment, collect representative benign traffic, compare live feature distributions with `model/monitoring_baseline.json`, review false alerts by device type, and recalibrate or retrain offline when distributions differ. Do not train automatically on traffic that the deployed detector labels benign.
