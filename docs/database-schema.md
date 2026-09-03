# Database schema

`devices` stores pseudonymous identity, current address, connection state, last-seen time, and the current report-defined risk state. Risk is stored natively in the range `[0,1]` with its UTC date and consecutive-anomaly counter. Raw MAC addresses are not persisted.

`anomaly_events` stores both normal and anomalous inference decisions so a device timeline can be audited. Scores are branch-specific and include risk before and after each decision.

`traffic_windows` stores only window time, resolution, packet count, and byte count. Full feature vectors and packet payloads are intentionally not retained.

At startup and each UTC date change, the collector resets every device's current risk score to `0`, level to `low`, and consecutive-anomaly counter to `0`. This does not delete device identities or `anomaly_events`; historical retention remains independently controlled by `IOT_GUARD_RETENTION_DAYS`.

`service_logs` stores structured operational events. Historical retention is enforced hourly by the collector using `IOT_GUARD_RETENTION_DAYS`.

`cloud_deliveries` stores recent cloud request outcomes, durations, payloads, responses, and errors for the dashboard. It follows the same retention policy.

`runtime_settings` stores operator-controlled runtime state. The `cloud_delivery_enabled` key allows the dashboard to pause or resume cloud requests without changing endpoint credentials or restarting services.

SQLite runs in WAL mode so the collector and dashboard can operate concurrently. The deployment assumes one Raspberry Pi writer; use PostgreSQL before introducing multiple collectors.
