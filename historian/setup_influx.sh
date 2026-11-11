#!/bin/bash
# L3 historian setup: InfluxDB 2.x on Debian 12. Run as root INSIDE the historian LXC.
#   ADMIN_PASSWORD='choose-a-strong-one' ./setup_influx.sh
# Creates org "lab", bucket "dc_ot" (30 day retention) and two least-privilege tokens:
#   - nodered-writer : write-only to dc_ot  (goes into the Node-RED InfluxDB config node)
#   - reader         : read-only from dc_ot (for Grafana / replication later)
set -euo pipefail

ORG=${ORG:-lab}
BUCKET=${BUCKET:-dc_ot}
RETENTION=${RETENTION:-720h}
ADMIN=${ADMIN:-admin}
: "${ADMIN_PASSWORD:?set ADMIN_PASSWORD (at least 8 characters)}"

apt update
apt install -y curl gnupg ca-certificates

# InfluxData apt repository (verify the signing key fingerprint before trusting it)
mkdir -p /etc/apt/keyrings
curl -fsSL https://repos.influxdata.com/influxdata-archive.key -o /tmp/influxdata-archive.key
if ! gpg --show-keys --with-fingerprint --with-colons /tmp/influxdata-archive.key 2>&1 \
     | grep -q '^fpr:\+24C975CBA61A024EE1B631787C3D57159FC2F927:$'; then
  echo "InfluxData key fingerprint mismatch. Check https://docs.influxdata.com/influxdb/v2/install/ and abort." >&2
  exit 1
fi
gpg --dearmor < /tmp/influxdata-archive.key > /etc/apt/keyrings/influxdata-archive.gpg
echo 'deb [signed-by=/etc/apt/keyrings/influxdata-archive.gpg] https://repos.influxdata.com/debian stable main' \
  > /etc/apt/sources.list.d/influxdata.list
apt update
apt install -y influxdb2 influxdb2-cli
systemctl enable --now influxdb

# wait for the API
for i in $(seq 1 30); do curl -sf http://127.0.0.1:8086/health >/dev/null && break; sleep 1; done

# first-run setup (non-interactive)
influx setup --username "$ADMIN" --password "$ADMIN_PASSWORD" \
  --org "$ORG" --bucket "$BUCKET" --retention "$RETENTION" --force

BID=$(influx bucket list --name "$BUCKET" --hide-headers | cut -f1)
echo
echo "=== write-only token for Node-RED (copy the Token column) ==="
influx auth create --org "$ORG" --write-bucket "$BID" --description nodered-writer
echo
echo "=== read-only token (for Grafana / replication later) ==="
influx auth create --org "$ORG" --read-bucket "$BID" --description reader
echo
echo "Done. UI: http://<this-ip>:8086   org=$ORG bucket=$BUCKET"
