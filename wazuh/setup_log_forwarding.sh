#!/bin/bash
# Log forwarding and file integrity monitoring (FIM) for the Wazuh SOC. Run as root on each log source:
#   ./setup_log_forwarding.sh plc         on the PLC host  (OpenPLC web log + simulator + ot-fim -> UDP syslog)
#   ./setup_log_forwarding.sh scada       on the SCADA host (Node-RED log incl. audit + ot-fim -> UDP syslog)
#   ./setup_log_forwarding.sh fw-l1       on fw-l1          (NFLOG -> ulogd2 -> rsyslog + ot-fim -> UDP syslog)
#   ./setup_log_forwarding.sh historian   on the historian  (diode-send + ot-fim -> UDP syslog)
#   ./setup_log_forwarding.sh mirror      on mirror-dmz     (Wazuh agent: journald; FIM via the manager's agent.conf)
#   ./setup_log_forwarding.sh grafana     on grafana-it     (Wazuh agent: journald + Grafana log; FIM via agent.conf)
# Environment: WAZUH_IP (default 192.168.76.10), WAZUH_PORT (514),
#              OPENPLC_DIR (/root/OpenPLC_v3), NODERED_DIR (/home/nr/.node-red).
# Testing: ROOT=/tmp/x TEST_ONLY=1 renders the files under ROOT without installing or restarting anything.
# OT hosts send ONE-WAY UDP syslog only (no agent, no connection back); IT-side hosts run the Wazuh agent.
set -euo pipefail

ROLE=${1:-}
WAZUH_IP=${WAZUH_IP:-192.168.76.10}
WAZUH_PORT=${WAZUH_PORT:-514}
OPENPLC_DIR=${OPENPLC_DIR:-/root/OpenPLC_v3}
NODERED_DIR=${NODERED_DIR:-/home/nr/.node-red}
ROOT=${ROOT:-}
TEST_ONLY=${TEST_ONLY:-0}
ROLES="plc|scada|fw-l1|historian|mirror|grafana"
case "$ROLE" in plc|scada|fw-l1|historian|mirror|grafana) ;; *) echo "usage: $0 $ROLES" >&2; exit 1;; esac

run() { if [ "$TEST_ONLY" = 1 ]; then echo "[skipped] $*"; else "$@"; fi; }
put() { mkdir -p "$(dirname "$ROOT$1")"; cat > "$ROOT$1"; echo "wrote $ROOT$1"; }

# --------------------------------------------------------------------------- rsyslog (OT roles)
rsyslog_config() {   # $1 = extra program names to forward from the journal, $2 = also tail the NFLOG file (yes/no)
  local progs="'sshd' or \$programname == 'sudo' or \$programname == 'su' or \$programname == 'ot-fim'"
  for p in $1; do progs="$progs or \$programname == '$p'"; done
  {
    echo "# Managed by setup_log_forwarding.sh. One-way UDP syslog to the Wazuh SOC ($WAZUH_IP:$WAZUH_PORT)."
    # No imjournal: Debian's rsyslog already receives the journal through imuxsock (/run/systemd/journal/syslog).
    # Loading imjournal as well delivers every message twice.
    if [ "$2" = yes ]; then
      echo 'module(load="imfile" PollingInterval="1")'
    fi
    echo
    # OpenPLC's web pages poll these URLs every second; they carry no security value, so they never leave the host.
    echo "if (\$programname == 'openplc' and re_match(\$msg, '\"GET /(runtime_logs|monitor-update|point-info|static/)')) then stop"
    # The web UI talks to the runtime's "Interactive Server" for every page; keep only its errors.
    echo "if (\$programname == 'openplc' and \$msg contains 'Interactive Server:' and not (\$msg contains 'error')) then stop"
    # At every start OpenPLC prints each PLC variable as three lines (Name:/Location:/Type:); keep them local.
    echo "if (\$programname == 'openplc' and re_match(\$msg, '^ ?(Name: |Location: %|Type: )')) then stop"
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

# --------------------------------------------------------------------------- ot-fim (OT roles, no agent)
# A small inotify watcher: every real change (content, permissions, owner, delete, rename) in the watched
# paths becomes one syslog line tagged ot-fim, e.g.
#   FIM change path=/root/fw_ot.sh event=CLOSE_WRITE,CLOSE sha256=3f2a... mode=755 owner=root:root
# A file that is opened for writing but not changed (SQLite does this on every read) is not reported.
# The account files (/etc/passwd, shadow, group) are compared as users and groups instead, one line per change:
#   ACCOUNT user-added name=testfim uid=1001 gid=1001 home=/home/testfim shell=/bin/sh
# Every OT role also watches the same tamper-relevant places: the logging setup itself (rsyslog, ot-fim),
# service definitions and the top of /etc (passwd, shadow, hosts, sudoers, rsyslog.conf, ulogd.conf).
FIM_COMMON_DIRS="/etc/rsyslog.d /etc/systemd/system /etc/sudoers.d"
FIM_COMMON_FLAT="/etc /usr/local/sbin"
ot_fim() {   # $1 = role-specific recursive directories, $2 = role-specific non-recursive directories
  local d f x
  d=$(for x in $1 $FIM_COMMON_DIRS; do echo "$x"; done | awk '!seen[$0]++' | xargs)
  f=$(for x in $2 $FIM_COMMON_FLAT; do echo "$x"; done | awk '!seen[$0]++' | xargs)
  set -- "$d" "$f"
  put /usr/local/sbin/ot-fim <<'FIM'
#!/bin/bash
# ot-fim: file integrity and account monitoring for hosts without a Wazuh agent. Logs to syslog, tag "ot-fim".
#   FIM change path=<file> event=<inotify events> sha256=<hash> mode=<octal> owner=<user:group>
#   FIM delete path=<file> event=<inotify events>
#   ACCOUNT <event> name=<user or group> [details]      one line per user, password or group change
# Excluded: editor/temp files, SQLite journals, caches, and the lock, temp and backup files that useradd,
# passwd and friends create next to /etc/passwd etc. (passwd.lock, passwd+, passwd.1234, passwd-, .pwd.lock).
EXCL=${FIM_EXCLUDE:-'(\.sw[px]$|~$|-journal$|-wal$|-shm$|\.pyc$|/\.bash_history$|/\.viminfo$|/\.lesshst$|/\.cache/|/\.local/|/venv/|/node_modules/|/\.npm/|\.backup$|\.lock$|/\.pwd\.lock$|\+$|\.[0-9]+$|/(passwd|shadow|group|gshadow|subuid|subgid)-$)'}
ETC=${FIM_ETC:-/etc}
STATE_DIR=${FIM_STATE_DIR:-/var/lib/ot-fim}
SETTLE=${FIM_SETTLE:-2}          # seconds of quiet before the account files are compared
ACCT_RE="^$ETC/(passwd|shadow|group|gshadow|subuid|subgid)\$"
umask 077

state() { local h=- m
          m=$(stat -c '%a %U:%G' "$1" 2>/dev/null) || { echo gone; return; }
          [ -f "$1" ] && h=$(sha256sum "$1" 2>/dev/null | cut -c1-64)
          echo "sha256=$h mode=${m% *} owner=${m#* }"; }
perm()  { stat -c 'mode=%a owner=%U:%G' "$1" 2>/dev/null || echo gone; }

# ---------------------------------------------------------------- account database
# One tool run (useradd, passwd, usermod ...) rewrites several files. Instead of reporting files, ot-fim waits
# until they are quiet, compares the users, passwords and groups with the last snapshot, and reports each
# difference once. The snapshot is kept on disk, so changes made while ot-fim was stopped are reported at start.
# Password hashes never leave the host: the snapshot stores only a hash of the shadow field.
acct_snapshot() {
  awk -F: 'NF>=7 {print "U|"$1"|"$3"|"$4"|"$6"|"$7}' "$ETC/passwd" 2>/dev/null
  awk -F: 'NF>=3 {print "G|"$1"|"$3"|"$4}' "$ETC/group" 2>/dev/null
  local n p rest st h
  while IFS=: read -r n p rest; do
    [ -n "$n" ] || continue
    h=-
    if   [ -z "$p" ];            then st=none                       # empty field: login without a password
    elif [[ "$p" =~ ^[!*]+$ ]];  then st=disabled                   # no usable password
    else
      st=set
      if [[ "$p" == '!'* ]]; then st=locked; while [[ "$p" == '!'* ]]; do p=${p#!}; done; fi
      h=$(printf %s "$p" | sha256sum | cut -c1-16)
    fi
    echo "P|$n|$st|$h"
  done < "$ETC/shadow" 2>/dev/null
}
ACCT_DIFF='
BEGIN { FS="|" }
FNR==NR { o[$1 FS $2]=$0; next }
        { n[$1 FS $2]=$0 }
END {
  for (k in n) { if (substr(k,1,2)!="U|") continue; split(n[k],a,"|")
    if (!(k in o)) { print "user-added name=" a[2] " uid=" a[3] " gid=" a[4] " home=" a[5] " shell=" a[6]; add[a[2]]=1 }
    else if (o[k]!=n[k]) { split(o[k],b,"|"); c=""
      if (b[3]!=a[3]) c=c " uid=" b[3] "->" a[3]
      if (b[4]!=a[4]) c=c " gid=" b[4] "->" a[4]
      if (b[5]!=a[5]) c=c " home=" b[5] "->" a[5]
      if (b[6]!=a[6]) c=c " shell=" b[6] "->" a[6]
      print "user-modified name=" a[2] c } }
  for (k in o) { if (substr(k,1,2)!="U|" || (k in n)) continue
    split(o[k],b,"|"); print "user-deleted name=" b[2] " uid=" b[3]; del[b[2]]=1 }

  for (k in n) { if (substr(k,1,2)!="P|") continue; split(n[k],a,"|")
    if (a[2] in add) { if (a[3]=="none") print "password-removed name=" a[2]; continue }
    if (!(k in o)) { print "password-changed name=" a[2]; continue }
    if (o[k]==n[k]) continue
    split(o[k],b,"|")
    if      (a[3]=="none")                    ev="password-removed"
    else if (a[3]=="disabled")                ev="password-disabled"
    else if (a[4]==b[4] && a[3]=="locked")    ev="password-locked"
    else if (a[4]==b[4] && b[3]=="locked")    ev="password-unlocked"
    else                                      ev="password-changed"
    print ev " name=" a[2] }

  for (k in n) { if (substr(k,1,2)!="G|") continue; split(n[k],a,"|")
    if (!(k in o)) {                       # the private group of a new user is part of "user-added"
      if (!(a[2] in add) || a[4]!="") print "group-added name=" a[2] " gid=" a[3] " members=" (a[4]=="" ? "-" : a[4])
      continue }
    if (o[k]==n[k]) continue
    split(o[k],b,"|")
    if (b[3]!=a[3]) print "group-modified name=" a[2] " gid=" b[3] "->" a[3]
    if (b[4]!=a[4]) {
      delete om; delete nm; x=""; y=""; real=0
      m=split(b[4],t,","); for (i=1;i<=m;i++) if (t[i]!="") om[t[i]]=1
      m=split(a[4],t,","); for (i=1;i<=m;i++) if (t[i]!="") nm[t[i]]=1
      for (u in nm) if (!(u in om)) { x=x (x==""?"":",") u; real=1 }
      for (u in om) if (!(u in nm)) { y=y (y==""?"":",") u; if (!(u in del)) real=1 }
      # a deleted user dropping out of its groups is part of "user-deleted"
      if (real) print "group-members-changed name=" a[2] " added=" (x==""?"-":x) " removed=" (y==""?"-":y) } }
  for (k in o) { if (substr(k,1,2)!="G|" || (k in n)) continue
    split(o[k],b,"|"); if (!(b[2] in del)) print "group-deleted name=" b[2] " gid=" b[3] }
}'
acct_flush() {
  local old="$STATE_DIR/accounts.snap" new="$STATE_DIR/accounts.new" line
  acct_snapshot > "$new" || return
  if [ -f "$old" ]; then
    awk "$ACCT_DIFF" "$old" "$new" | while IFS= read -r line; do logger -t ot-fim "ACCOUNT $line"; done
  fi
  mv -f "$new" "$old"
}

# ---------------------------------------------------------------- file watcher
watch() {   # $1 = -r or -, then paths
  local rec=$1; shift
  local paths=() p; for p in "$@"; do [ -e "$p" ] && paths+=("$p"); done
  [ ${#paths[@]} -gt 0 ] || return 0
  local acct=0; for p in "${paths[@]}"; do [ "$p" = "$ETC" ] && acct=1; done
  declare -A last
  local f ev s
  while IFS= read -r f; do
    if [[ "$f" =~ $ACCT_RE ]]; then last[$f]=$(perm "$f"); else last[$f]=$(state "$f"); fi
  done < <(
    if [ "$rec" = -r ]; then find "${paths[@]}" -type f 2>/dev/null; else find "${paths[@]}" -maxdepth 1 -type f 2>/dev/null; fi |
    grep -Ev "$EXCL")
  if [ $acct = 1 ]; then mkdir -p "$STATE_DIR"; acct_flush; fi     # report what changed while ot-fim was not running
  local opt=(); [ "$rec" = -r ] && opt=(-r)
  logger -t ot-fim "FIM start watching ${paths[*]}"
  local pending=0 since=0
  inotifywait -m -q "${opt[@]}" -e close_write,attrib,delete,moved_to,moved_from,create \
      --exclude "$EXCL" --format '%w%f|%e' "${paths[@]}" |
  while true; do
    if IFS='|' read -r -t "$SETTLE" f ev; then
      if [ $acct = 1 ] && [[ "$f" =~ $ACCT_RE ]]; then
        # content: compared as users/groups once the files are quiet. Permissions and owner: reported as a file change.
        [ $pending = 0 ] && since=$SECONDS; pending=1
        s=$(perm "$f")
        if [ "$s" != gone ] && [ "${last[$f]:-$s}" != "$s" ]; then logger -t ot-fim "FIM change path=$f event=$ev sha256=- $s"; fi
        [ "$s" != gone ] && last[$f]=$s
      elif [ -d "$f" ] && [[ "$ev" != *DELETE* ]]; then :
      elif [[ "$ev" == *DELETE* || "$ev" == *MOVED_FROM* ]]; then
        logger -t ot-fim "FIM delete path=$f event=$ev"; unset "last[$f]"
      else
        s=$(state "$f")
        # gone = removed again already (the DELETE event follows); same state = opened for writing but not changed
        if [ "$s" != gone ] && [ "${last[$f]:-}" != "$s" ]; then last[$f]=$s; logger -t ot-fim "FIM change path=$f event=$ev $s"; fi
      fi
      if [ $pending = 1 ] && [ $((SECONDS - since)) -ge $((SETTLE * 5)) ]; then acct_flush; pending=0; fi
    else
      [ $? -gt 128 ] || break                      # not a timeout: inotifywait ended
      if [ $pending = 1 ]; then acct_flush; pending=0; fi
    fi
  done
}
watch -r ${FIM_DIRS:-} &
watch -  ${FIM_FLAT:-} &
wait
FIM
  run chmod 755 "$ROOT/usr/local/sbin/ot-fim"
  put /etc/systemd/system/ot-fim.service <<UNIT
[Unit]
Description=OT file integrity monitoring (inotify -> syslog tag ot-fim)
After=local-fs.target

[Service]
Environment="FIM_DIRS=$1"
Environment="FIM_FLAT=$2"
ExecStart=/usr/local/sbin/ot-fim
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
}

ot_common() {   # packages for every OT role; apt (internet) is only used if something is missing
  local missing=()
  for p in rsyslog inotify-tools "$@"; do
    dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || missing+=("$p")
  done
  if [ ${#missing[@]} -eq 0 ]; then echo "packages already installed: rsyslog inotify-tools $*"; return; fi
  echo "installing: ${missing[*]} (needs a package source: internet or local .deb files, see the guide)"
  run apt-get update
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
}

ot_restart() {  # $@ = extra units to restart
  run systemctl daemon-reload
  run systemctl enable ot-fim
  run systemctl restart rsyslog ot-fim "$@"
}

# --------------------------------------------------------------------------- Wazuh agent (IT roles)
# Append a block to the Wazuh agent's ossec.conf (inside the last </ossec_config>) unless the marker is already there.
agent_localfile() {   # $1 = marker text, $2 = block
  local conf="$ROOT/var/ossec/etc/ossec.conf"
  [ -f "$conf" ] || { echo "ERROR: $conf not found. Is the Wazuh agent installed?" >&2; exit 1; }
  if grep -qF -- "$1" "$conf"; then echo "ossec.conf already contains: $1"; return; fi
  BLOCK="$2" perl -0pi -e 'BEGIN{$b=$ENV{BLOCK}} s#(.*)</ossec_config>#$1$b</ossec_config>#s' "$conf"
  echo "added to $conf: $1"
}
JOURNAL_BLOCK="
  <!-- OT lab: collect the journal (services, sshd, sudo) -->
  <localfile>
    <location>journald</location>
    <log_format>journald</log_format>
  </localfile>
"

case "$ROLE" in
  plc)
    ot_common
    [ -d "$ROOT$OPENPLC_DIR/webserver" ] || [ "$TEST_ONLY" = 1 ] || { echo "ERROR: $OPENPLC_DIR/webserver not found; set OPENPLC_DIR" >&2; exit 1; }
    systemd_identifier openplc openplc       # web UI requests (logins, start/stop, uploads, settings) and runtime messages
    # Werkzeug colours every non-200 request line with ANSI escapes. journald then stores those lines as binary
    # and does not pass them to syslog, so logins (302), PLC start/stop (302) and errors (4xx) never reach the SOC.
    # Switch the colours off in OpenPLC's web server (one line, original kept as webserver.py.orig).
    w="$ROOT$OPENPLC_DIR/webserver/webserver.py"
    if [ -f "$w" ] && ! grep -q "_log_add_style = False" "$w"; then
      [ "$TEST_ONLY" = 1 ] || cp -n "$w" "$w.orig"
      sed -i '0,/^import flask_login/s//import flask_login\nimport werkzeug.serving; werkzeug.serving._log_add_style = False  # OT lab: plain request log for syslog/' "$w"
      grep -q "_log_add_style = False" "$w" && echo "patched $w (no ANSI colours in the request log)" || echo "WARNING: could not patch $w; add the werkzeug line by hand"
    fi
    systemd_identifier dcsim dcsim
    rsyslog_config "openplc dcsim" no
    # programs, the database (users, settings, slave devices), the active program and the simulator
    ot_fim "$OPENPLC_DIR/webserver/st_files" "$OPENPLC_DIR/webserver /opt/dcsim /root"
    ot_restart openplc
    echo "Note: restarting openplc stops the PLC unless 'Start OpenPLC in RUN mode' is ticked in Settings."
    ;;
  scada)
    ot_common
    systemd_identifier nodered node-red
    rsyslog_config "node-red" no
    # Node-RED audit log: deploys (flows.set), logins, palette installs. The default settings.js has audit: false.
    s="$ROOT$NODERED_DIR/settings.js"
    if [ -f "$s" ] && grep -q "audit: false" "$s"; then
      [ "$TEST_ONLY" = 1 ] || cp -n "$s" "$s.orig"
      sed -i 's/audit: false/audit: true/' "$s"; echo "enabled audit logging in $s"
    elif [ -f "$s" ] && grep -q "audit: true" "$s"; then echo "audit logging already on in $s"
    else echo "WARNING: set logging.console.audit = true in $NODERED_DIR/settings.js by hand"; fi
    ot_fim "" "$NODERED_DIR"
    ot_restart nodered
    ;;
  fw-l1)
    ot_common ulogd2
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
    ot_fim "/etc/iptables" "/root"
    run systemctl enable --now ulogd2
    ot_restart ulogd2
    echo
    echo "fw-l1 is ready. Make sure fw_ot.sh has been re-run (it adds the NFLOG rules) and that the Proxmox host has:"
    echo "  modprobe nfnetlink_log xt_NFLOG   (and the same names in /etc/modules-load.d/fw-lab.conf)"
    ;;
  historian)
    ot_common
    systemd_identifier diode-send diode-send
    rsyslog_config "diode-send" no
    ot_fim "/etc/diode /opt/diode /etc/influxdb" "/root"
    ot_restart diode-send
    ;;
  mirror)
    systemd_identifier diode-recv diode-recv
    run systemctl daemon-reload
    run systemctl restart diode-recv
    agent_localfile "<log_format>journald</log_format>" "$JOURNAL_BLOCK"
    run systemctl restart wazuh-agent
    echo "FIM for this host comes from the manager: install wazuh/agent.conf as /var/ossec/etc/shared/default/agent.conf"
    ;;
  grafana)
    agent_localfile "<log_format>journald</log_format>" "$JOURNAL_BLOCK"
    agent_localfile "/var/log/grafana/grafana.log" "
  <!-- OT lab: Grafana application log (logins, failed logins) -->
  <localfile>
    <location>/var/log/grafana/grafana.log</location>
    <log_format>syslog</log_format>
  </localfile>
"
    run systemctl restart wazuh-agent
    echo "FIM for this host comes from the manager: install wazuh/agent.conf as /var/ossec/etc/shared/default/agent.conf"
    ;;
esac

# One test message so you can look for it in Wazuh (OT roles only: they use plain UDP syslog)
case "$ROLE" in plc|scada|fw-l1|historian)
  run logger -n "$WAZUH_IP" -P "$WAZUH_PORT" -t ot-lab-test "log forwarding configured on $(hostname) ($ROLE)";;
esac
echo "done ($ROLE)"
