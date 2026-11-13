#!/bin/bash
# Lab health check: run as root on a Proxmox node after a reboot (or any time).
# It checks every lab container that lives on THIS node and prints PASS / FAIL per check.
#   bash lab_health.sh                     # uses the container IDs below
#   PLC_CT=105 FW_CT=108 bash lab_health.sh  # override IDs
# Containers that are not on this node are skipped, so the same script runs on dell and pc1.
set -u

PLC_CT=${PLC_CT:-105}        # debian-L0-1: dc_sim + OpenPLC
FW_CT=${FW_CT:-108}          # fw-l1: Modbus DPI firewall
SCADA_CT=${SCADA_CT:-107}    # debian-L2: Node-RED
HIST_CT=${HIST_CT:-109}      # influx-l3: historian + diode-send
MIRROR_CT=${MIRROR_CT:-111}   # mirror-dmz (pc1)
GRAFANA_CT=${GRAFANA_CT:-112} # grafana-it (pc1)

fails=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n         -> %s\n' "$1" "$2"; fails=$((fails+1)); }
check() {  # check <ct> <description> <hint> <shell command run inside the container>
  if pct exec "$1" -- bash -c "$4" >/dev/null 2>&1; then ok "$2"; else bad "$2" "$3"; fi
}
here() {   # is the container on this node and running?
  [ -n "$1" ] || return 1
  pct status "$1" >/dev/null 2>&1 || return 1
  if ! pct status "$1" | grep -q running; then
    bad "CT $1 is running" "pct start $1"; return 1
  fi
}

echo "== Lab health on $(hostname) at $(date -u '+%F %T') UTC"

if here "$PLC_CT"; then
  echo "-- L0/L1 PLC host (CT $PLC_CT)"
  check "$PLC_CT" "simulator service dcsim active" "systemctl enable --now dcsim" "systemctl is-active -q dcsim"
  check "$PLC_CT" "simulator listening on 127.0.0.1:5020" "journalctl -u dcsim -n 20" "ss -tln | grep -q ':5020 '"
  check "$PLC_CT" "OpenPLC runtime listening on :502 (PLC in RUN)" \
        "OpenPLC web UI > Start PLC; tick Settings > Start OpenPLC in RUN mode" "ss -tln | grep -q ':502 '"
  check "$PLC_CT" "PLC clock advancing (HR0 changes within 3 s)" \
        "PLC running but not polling the simulator: check Slave Devices in OpenPLC" \
        'P=/opt/dcsim/venv/bin/python; r(){ $P -c "from pymodbus.client import ModbusTcpClient as C;c=C(\"127.0.0.1\",port=502);c.connect();print(c.read_holding_registers(0,count=1).registers[0])"; }; a=$(r); sleep 3; b=$(r); [ -n "$a" ] && [ "$a" != "$b" ]'
fi

if here "$FW_CT"; then
  echo "-- fw-l1 (CT $FW_CT)"
  check "$FW_CT" "IP forwarding on" "sysctl -w net.ipv4.ip_forward=1" "[ \$(cat /proc/sys/net/ipv4/ip_forward) = 1 ]"
  check "$FW_CT" "Modbus DPI rules loaded (MB_POLICY chain)" "bash /root/fw_ot.sh && netfilter-persistent save" "iptables -L MB_POLICY -n | grep -q u32"
  check "$FW_CT" "drop rules log with NFLOG" "re-run the current fw_ot.sh; host needs nfnetlink_log xt_NFLOG" "iptables -L MB_DROP -n | grep -q NFLOG"
  check "$FW_CT" "ulogd2 active" "systemctl enable --now ulogd2" "systemctl is-active -q ulogd2"
  check "$FW_CT" "rsyslog active" "systemctl enable --now rsyslog" "systemctl is-active -q rsyslog"
  check "$FW_CT" "route to SOC via pfSense" "systemctl enable --now dmz-route" "ip route get 192.168.76.10 | grep -q 'via 192.168.73.3'"
fi

if here "$SCADA_CT"; then
  echo "-- L2 SCADA (CT $SCADA_CT)"
  check "$SCADA_CT" "Node-RED listening on :1880" "systemctl enable --now nodered" "ss -tln | grep -q ':1880 '"
  check "$SCADA_CT" "PLC reachable through fw-l1 (TCP 502)" "check fw-l1 and the PLC" "timeout 3 bash -c '</dev/tcp/192.168.71.10/502'"
  check "$SCADA_CT" "historian reachable through fw-l1 (TCP 8086)" "check fw-l1 and InfluxDB" "timeout 3 bash -c '</dev/tcp/192.168.73.10/8086'"
fi

if here "$HIST_CT"; then
  echo "-- L3 historian (CT $HIST_CT)"
  check "$HIST_CT" "InfluxDB active" "systemctl enable --now influxdb" "systemctl is-active -q influxdb"
  check "$HIST_CT" "new HVAC data in the last minute" \
        "SCADA is not writing: check OpenPLC (RUN) and the Node-RED historian node" \
        "influx query 'from(bucket:\"dc_ot\") |> range(start:-1m) |> filter(fn:(r)=> r._measurement==\"dc_temp\") |> count()' | grep -qE '[0-9]+\s*\$'"
  check "$HIST_CT" "diode-send active" "systemctl enable --now diode-send" "systemctl is-active -q diode-send"
  check "$HIST_CT" "routes to DMZ and SOC via pfSense" "systemctl enable --now dmz-route" \
        "ip route get 192.168.74.10 | grep -q 'via 192.168.73.3' && ip route get 192.168.76.10 | grep -q 'via 192.168.73.3'"
  check "$HIST_CT" "rsyslog active (SOC forwarding)" "systemctl enable --now rsyslog" "systemctl is-active -q rsyslog"
fi

if here "$MIRROR_CT"; then
  echo "-- L3.5 mirror (CT $MIRROR_CT)"
  check "$MIRROR_CT" "InfluxDB active" "systemctl enable --now influxdb" "systemctl is-active -q influxdb"
  check "$MIRROR_CT" "diode-recv active" "systemctl enable --now diode-recv" "systemctl is-active -q diode-recv"
  check "$MIRROR_CT" "HVAC data arriving over the diode (last minute)" \
        "if the historian has data, check the pfSense UDP 8094 rule" \
        "influx query 'from(bucket:\"dc_ot\") |> range(start:-1m) |> filter(fn:(r)=> r._measurement==\"dc_temp\") |> count()' | grep -qE '[0-9]+\s*\$'"
  check "$MIRROR_CT" "Wazuh agent active" "systemctl enable --now wazuh-agent" "systemctl is-active -q wazuh-agent"
fi

if here "$GRAFANA_CT"; then
  echo "-- L4 Grafana (CT $GRAFANA_CT)"
  check "$GRAFANA_CT" "Grafana healthy on :3000" "systemctl restart grafana-server; journalctl -u grafana-server -n 40" "curl -sf http://127.0.0.1:3000/api/health"
  check "$GRAFANA_CT" "Wazuh agent active" "systemctl enable --now wazuh-agent" "systemctl is-active -q wazuh-agent"
fi

echo
if [ "$fails" -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "$fails CHECK(S) FAILED"; fi
exit "$fails"
