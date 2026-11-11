#!/bin/bash
# L4 IT dashboard: installs Grafana and provisions the DMZ-mirror data source + the lab dashboard.
# Run as root INSIDE the Grafana LXC (Debian 12). It needs internet access during the install only.
#   MIRROR_READ_TOKEN='<read token from the MIRROR InfluxDB>' ./setup_grafana.sh
# Optional: MIRROR_URL (default http://192.168.74.10:8086), ORG (lab), BUCKET (dc_ot),
#           GRAFANA_ADMIN_PASSWORD (sets the admin password on first start).
# dc_it_dashboard.json must be in the same folder as this script.
set -euo pipefail

MIRROR_URL=${MIRROR_URL:-http://192.168.74.10:8086}
ORG=${ORG:-lab}
BUCKET=${BUCKET:-dc_ot}
: "${MIRROR_READ_TOKEN:?set MIRROR_READ_TOKEN (the READ token of the mirror InfluxDB)}"
DIR=$(cd "$(dirname "$0")" && pwd)
[ -f "$DIR/dc_it_dashboard.json" ] || { echo "dc_it_dashboard.json not found next to this script" >&2; exit 1; }

apt update
apt install -y apt-transport-https wget gnupg ca-certificates curl

# Grafana APT repository (current instructions from grafana.com/docs)
mkdir -p /etc/apt/keyrings
wget -O /etc/apt/keyrings/grafana.asc https://apt.grafana.com/gpg-full.key
chmod 644 /etc/apt/keyrings/grafana.asc
echo "deb [signed-by=/etc/apt/keyrings/grafana.asc] https://apt.grafana.com stable main" > /etc/apt/sources.list.d/grafana.list
apt update
apt install -y grafana

# Data source: the DMZ mirror, Flux, read-only token (file readable by root and grafana only)
cat > /etc/grafana/provisioning/datasources/mirror.yaml <<YAML
apiVersion: 1
datasources:
  - name: DMZ Mirror
    uid: dmz-mirror
    type: influxdb
    access: proxy
    url: ${MIRROR_URL}
    isDefault: true
    jsonData:
      version: Flux
      organization: ${ORG}
      defaultBucket: ${BUCKET}
      tlsSkipVerify: true
    secureJsonData:
      token: ${MIRROR_READ_TOKEN}
YAML
chown root:grafana /etc/grafana/provisioning/datasources/mirror.yaml
chmod 640 /etc/grafana/provisioning/datasources/mirror.yaml

# Dashboard provisioning
mkdir -p /var/lib/grafana/dashboards
cp "$DIR/dc_it_dashboard.json" /var/lib/grafana/dashboards/
chown -R grafana:grafana /var/lib/grafana/dashboards
cat > /etc/grafana/provisioning/dashboards/ot-lab.yaml <<YAML
apiVersion: 1
providers:
  - name: OT lab
    folder: OT Lab
    type: file
    disableDeletion: false
    allowUiUpdates: true
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards
YAML

# Service environment: no phone-home from an OT lab
{
  echo "GF_ANALYTICS_REPORTING_ENABLED=false"
  echo "GF_ANALYTICS_CHECK_FOR_UPDATES=false"
  echo "GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES=false"
  echo "GF_PLUGINS_PREINSTALL_DISABLED=true"     # no internet in the IT zone: skip plugin downloads at start-up
  [ -n "${GRAFANA_ADMIN_PASSWORD:-}" ] && echo "GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}"
} >> /etc/default/grafana-server

# Pre-flight: can this host query the mirror with the token? (warning only)
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST "${MIRROR_URL}/api/v2/query?org=${ORG}" \
  -H "Authorization: Token ${MIRROR_READ_TOKEN}" -H 'Content-Type: application/vnd.flux' \
  --data "from(bucket: \"${BUCKET}\") |> range(start: -1m) |> limit(n: 1)" || true)
echo "mirror query test: HTTP ${code} (200 = reachable and token accepted)"

systemctl daemon-reload
systemctl enable --now grafana-server
# Grafana can take 30-60 s on first start (database migrations, provisioning, bundled plugins)
ok=0
for i in $(seq 1 90); do
  if curl -sf http://127.0.0.1:3000/api/health >/dev/null; then ok=1; break; fi
  sleep 1
done
if [ "$ok" != 1 ]; then
  echo >&2
  echo "Grafana did NOT come up on port 3000. Last log lines:" >&2
  systemctl --no-pager --full status grafana-server 2>&1 | head -15 >&2 || true
  journalctl -u grafana-server -n 40 --no-pager -o cat >&2 || true
  exit 1
fi
echo
echo "Grafana is up on port 3000. Default login admin / admin (you are asked to change it) unless GRAFANA_ADMIN_PASSWORD was set."
# Make the provisioned dashboard the home page (one copy only, so file updates always show)
code=$(curl -s -o /dev/null -w '%{http_code}' -u "admin:${GRAFANA_ADMIN_PASSWORD:-admin}" -X PUT \
  http://127.0.0.1:3000/api/org/preferences -H 'Content-Type: application/json' \
  -d '{"homeDashboardUID":"dc-it-mirror"}' || true)
echo "set home dashboard: HTTP ${code} (200 = done; otherwise set it in Administration > Default preferences)"
echo "Dashboard: OT Lab > Data Centre - IT view (DMZ mirror)"
