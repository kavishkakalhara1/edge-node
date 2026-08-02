# Database schema

`devices` stores pseudonymous identity, current address, connection state, last-seen time, and current risk. Raw MAC addresses are not persisted.

`anomaly_events` stores both normal and anomalous inference decisions so a device timeline can be audited. Scores are branch-specific and include risk before and after each decision.

`traffic_windows` stores only window time, resolution, packet count, and byte count. Full feature vectors and packet payloads are intentionally not retained.

`service_logs` stores structured operational events. Retention is enforced hourly by the collector using `IOT_GUARD_RETENTION_DAYS`.

SQLite runs in WAL mode so the collector and dashboard can operate concurrently. The deployment assumes one Raspberry Pi writer; use PostgreSQL before introducing multiple collectors.
