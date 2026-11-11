#!/bin/bash
# Log forwarding to the Wazuh SOC. Run as root on each log source:
#   ./setup_log_forwarding.sh fw-l1       on fw-l1      (NFLOG -> ulogd2 -> rsyslog -> UDP syslog)
#   ./setup_log_forwarding.sh historian   on influx-l3  (journal -> rsyslog -> UDP syslog)
#   ./setup_log_forwarding.sh mirror      on mirror-dmz (Wazuh agent, journald)
#   ./setup_log_forwarding.sh grafana     on grafana-it (Wazuh agent, journald + Grafana log file)
# Environment: WAZUH_IP (default 192.168.76.10), WAZUH_PORT (514).
# Testing: ROOT=/tmp/x TEST_ONLY=1 renders the files under ROOT without installing or restarting anything.
# OT hosts send ONE-WAY UDP syslog only (no agent, no connection back); IT-side hosts run the Wazuh agent.
set -euo pipefail

ROLE=${1:-}
WAZUH_IP=${WAZUH_IP:-192.168.76.10}
WAZUH_PORT=${WAZUH_PORT:-514}
ROOT=${ROOT:-}
TEST_ONLY=${TEST_ONLY:-0}
case "$ROLE" in fw-l1|historian|mirror|grafana) ;; *) echo "usage: $0 fw-l1|historian|mirror|grafana" >&2; exit 1;; esac

run() { if [ "$TEST_ONLY" = 1 ]; then echo "[skipped] $*"; else "$@"; fi; }
put() { mkdir -p "$(dirname "$ROOT$1")"; cat > "$ROOT$1"; echo "wrote $ROOT$1"; }

# --------------------------------------------------------------------------- rsyslog roles
rsyslog_config() {   # $1 = extra program names to forward from the journal, $2 = also tail the NFLOG file (yes/no)
  local progs="'sshd' or \$programname == 'sudo' or \$programname == 'su'"
  for p in $1; do progs="$progs or \$programname == '$p'"; done
  {
    echo "# Managed by setup_log_forwarding.sh. One-way UDP syslog to the Wazuh SOC ($WAZUH_IP:$WAZUH_PORT)."
    echo 'module(load="imjournal" StateFile="imjournal.state" Ratelimit.Interval="0")'
    if [ "$2" = yes ]; then
      echo 'module(load="imfile" PollingInterval="1")'
    fi
    echo
    # default ruleset: sees journal (imjournal) and local syslog (imuxsock); only the listed programs leave the host
    echo "if (\$programname == $progs) then {"
    echo "  action(type=\"omfwd\" target=\"$WAZUH_IP\" port=\"$WAZUH_PORT\" protocol=\"udp\")"
    echo '}'
    if [ "$2" = yes ]; then
      echo
      echo 'ruleset(name="from_file") {'
      echo "  action(type=\"omfwd\" target=\"$WAZUH_IP\" port=\"$WAZUH_PORT\" protocol=\"udp\")"
      echo '}'
      # The tag MUST end with a colon, otherwise Wazuh cannot find the program name (tested).
      echo 'input(type="imfile" File="/var/log/ulog/syslogemu.log" Tag="fw-l1-nflog:" Severity="warning" Facility="local5" ruleset="from_file" reopenOnTruncate="on")'
    fi
  } | put /etc/rsyslog.d/60-wazuh.conf
}

systemd_identifier() {   # $1 = unit name (without .service), $2 = identifier
  printf '[Service]\nSyslogIdentifier=%s\n' "$2" | put "/etc/systemd/system/$1.service.d/10-syslog-id.conf"
}

# Append a block to the Wazuh agent's ossec.conf (inside the last </ossec_config>) unless the marker is already there.
agent_localfile() {   # $1 = marker text, $2 = block
  local conf="$ROOT/var/ossec/etc/ossec.conf"
  [ -f "$conf" ] || { echo "ERROR: $conf not found. Is the Wazuh agent installed?" >&2; exit 1; }
  if grep -qF -- "$1" "$conf"; then echo "ossec.conf already contains: $1"; return; fi
  BLOCK="$2" perl -0pi -e 'BEGIN{$b=$ENV{BLOCK}} s#(.*)</ossec_config>#$1$b</ossec_config>#s' "$conf"
  echo "added to $conf: $1"
}

case "$ROLE" in
  fw-l1)
    run apt-get update
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y rsyslog ulogd2
    # ulogd2: NFLOG group 1 -> text lines in /var/log/ulog/syslogemu.log
    [ "$TEST_ONLY" = 1 ] || { [ -f /etc/ulogd.conf.orig ] || cp /etc/ulogd.conf /etc/ulogd.conf.orig; }
    put /etc/ulogd.conf <<'CONF'
[global]
logfile="syslog"
loglevel=3
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_inppkt_NFLOG.so"
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_raw2packet_BASE.so"
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_filter_IFINDEX.so"
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_filter_IP2STR.so"
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_filter_PRINTPKT.so"
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_output_LOGEMU.so"
stack=log1:NFLOG,base1:BASE,ifi1:IFINDEX,ip2str1:IP2STR,print1:PRINTPKT,emu1:LOGEMU

[log1]
group=1

[emu1]
file="/var/log/ulog/syslogemu.log"
sync=1
CONF
    run mkdir -p /var/log/ulog
    rsyslog_config "" yes
    run systemctl enable --now ulogd2
    run systemctl restart ulogd2 rsyslog
    echo
    echo "fw-l1 is ready. Make sure fw_ot.sh has been re-run (it adds the NFLOG rules) and that the Proxmox host has:"
    echo "  modprobe nfnetlink_log xt_NFLOG   (and the same names in /etc/modules-load.d/fw-lab.conf)"
    ;;
  historian)
    run apt-get update
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y rsyslog
    systemd_identifier diode-send diode-send
    rsyslog_config "diode-send" no
    run systemctl daemon-reload
    run systemctl restart rsyslog diode-send
    ;;
  mirror)
    systemd_identifier diode-recv diode-recv
    run systemctl daemon-reload
    run systemctl restart diode-recv
    agent_localfile "<log_format>journald</log_format>" "
  <!-- OT lab: collect the journal (diode receiver, sshd, sudo) -->
  <localfile>
    <location>journald</location>
    <log_format>journald</log_format>
  </localfile>
"
    run systemctl restart wazuh-agent
    ;;
  grafana)
    agent_localfile "<log_format>journald</log_format>" "
  <!-- OT lab: collect the journal (sshd, sudo) -->
  <localfile>
    <location>journald</location>
    <log_format>journald</log_format>
  </localfile>
"
    agent_localfile "/var/log/grafana/grafana.log" "
  <!-- OT lab: Grafana application log (login failures) -->
  <localfile>
    <location>/var/log/grafana/grafana.log</location>
    <log_format>syslog</log_format>
  </localfile>
"
    run systemctl restart wazuh-agent
    ;;
esac

# One test message so you can look for it in Wazuh (OT roles only: they use plain UDP syslog)
if [ "$ROLE" = fw-l1 ] || [ "$ROLE" = historian ]; then
  run logger -n "$WAZUH_IP" -P "$WAZUH_PORT" -t ot-lab-test "log forwarding configured on $(hostname) ($ROLE)"
fi
echo "done ($ROLE)"
