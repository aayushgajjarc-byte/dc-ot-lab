# Security policy

This repository is a **training lab**, not production software.

- Run it only on an isolated network. Several components are insecure on purpose or by nature: Modbus has no authentication, the Node-RED editor has no login by default, OpenPLC v3 is archived, and the SOC receives plain UDP syslog.
- **Never commit secrets.** InfluxDB tokens, the diode HMAC key and passwords belong in `/etc/diode/*.env` and similar files on the lab hosts. The repository only contains `*.env.example` templates, and `.gitignore` blocks real `.env` files.
- If you find a problem in the lab's scripts or detection content, open an issue. Do not include tokens, keys or captured traffic from your own lab in the issue.
