# Threat model

## Protected assets

- Device identity secret
- Model artifacts and thresholds
- Device activity and anomaly history
- Hotspot credentials
- Dashboard availability

## Controls

- Device identifiers are keyed HMAC values; raw MAC addresses are not stored.
- Model files are verified against SHA-256 hashes at startup.
- Live anomalies never update model weights or preprocessing baselines.
- Collector capabilities are limited to raw/network administration operations.
- Web service has no capture capabilities.
- systemd applies filesystem, kernel, home-directory, and privilege restrictions.
- SQLite stores summaries rather than packet payloads or complete feature vectors.

## Residual risks

- A local root compromise exposes hotspot credentials, identity secret, and telemetry.
- MAC randomization creates a new pseudonymous device identity.
- DHCP lease disappearance can temporarily mark a sleeping device offline.
- Monitor-mode capture cannot decrypt arbitrary WPA2 traffic.
- Feature distribution mismatch can cause false alerts until benign replay validation is complete.
- The dashboard has no built-in authentication and must remain on the management/hotspot network or sit behind an authenticated TLS proxy.
