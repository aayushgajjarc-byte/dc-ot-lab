#!/bin/bash
# OT internal firewall (fw-l1): Modbus/TCP deep-packet-inspection + zone conduits.
# Modbus filtering uses the iptables u32 match (Nivethan & Papa, 2016). Run inside the firewall LXC.
#
#   eth0 192.168.71.2 (vmbr10, L1)   eth1 192.168.72.2 (vmbr20, L2)   eth2 192.168.73.2 (vmbr30, L3)
#
#   L2 Node-RED 192.168.72.10 --> L1 OpenPLC 192.168.71.10:502      (function-code filtered)
#   L2 Node-RED 192.168.72.10 --> L3 InfluxDB 192.168.73.10:8086    (historian writes only)
#   everything else between zones: dropped and logged
#
set -e
trap 'echo "fw_ot.sh FAILED at line $LINENO: $BASH_COMMAND" >&2; echo "FORWARD policy may now be DROP with no rules. Usual cause: netfilter modules not loaded on the Proxmox HOST (xt_u32 nft_compat xt_LOG nf_log_syslog xt_limit nf_conntrack xt_conntrack)." >&2' ERR

PLC=192.168.71.10    # OpenPLC (debian-L0-1)
HMI=192.168.72.10    # Node-RED (debian-L2), only host allowed to write
ENG=192.168.72.11    # Engineering WS (read-only), optional, adjust or remove
HIST=192.168.73.10   # InfluxDB historian (L3)
HIST_PORT=8086
PORT=502

# u32 prefix: jump over IP header, then TCP header -> start of Modbus MBAP
#   0>>22&0x3C   = IP header length in bytes (IHL*4)
#   12>>26&0x3C  = TCP header length in bytes (data offset*4)
# Modbus PDU: byte 7 = function code, bytes 8-9 = sub-function (FC 0x08)
J="0>>22&0x3C@ 12>>26&0x3C@"

sysctl -w net.ipv4.ip_forward=1 >/dev/null

iptables -F; iptables -X
iptables -P INPUT   ACCEPT      # tighten later (SSH from mgmt only)
iptables -P OUTPUT  ACCEPT
iptables -P FORWARD DROP        # default deny, as in the paper

# --- drop + log helper chain
iptables -N MB_DROP
iptables -A MB_DROP -m limit --limit 60/min --limit-burst 20 -j NFLOG --nflog-group 1 --nflog-prefix "MODBUS-BLOCK: "
iptables -A MB_DROP -j DROP

# --- Modbus policy chain (function-code rules, below)
iptables -N MB_POLICY   # per-function policy
iptables -N MB_FILTER   # source gate: only HMI/ENG may talk to the PLC at all

# 0. packets with no Modbus payload (SYN, ACK, FIN): let TCP work
iptables -A MB_POLICY -m u32 ! --u32 "$J 0&0x0=0x0" -j ACCEPT

# 1. dangerous functions, blocked for EVERY source
iptables -A MB_POLICY -m u32 --u32 "$J 7>>8&0xFFFFFF=0x080001" -j MB_DROP  # FC08/01 restart comms
iptables -A MB_POLICY -m u32 --u32 "$J 7>>8&0xFFFFFF=0x080004" -j MB_DROP  # FC08/04 force listen-only
iptables -A MB_POLICY -m u32 --u32 "$J 7>>8&0xFFFFFF=0x08000A" -j MB_DROP  # FC08/0A clear counters
iptables -A MB_POLICY -m u32 --u32 "$J 7>>24&0xFF=0x11"        -j MB_DROP  # FC17 report slave ID
iptables -A MB_POLICY -m u32 --u32 "$J 7>>24&0xFF=0x2B"        -j MB_DROP  # FC43 read device ID

# 2. writes (FC 5,6,15,16): HMI only
for fc in 0x05 0x06 0x0F 0x10; do
  iptables -A MB_POLICY -s $HMI -m u32 --u32 "$J 7>>24&0xFF=$fc" -j ACCEPT
done

# 3. reads (FC 1-4): HMI and ENG
for src in $HMI $ENG; do
  for fc in 0x01 0x02 0x03 0x04; do
    iptables -A MB_POLICY -s $src -m u32 --u32 "$J 7>>24&0xFF=$fc" -j ACCEPT
  done
done

# 4. everything else
iptables -A MB_POLICY -j MB_DROP

# --- source gate: unknown sources are dropped before the TCP handshake completes
iptables -A MB_FILTER -s $HMI -j MB_POLICY
iptables -A MB_FILTER -s $ENG -j MB_POLICY
iptables -A MB_FILTER -j MB_DROP

# --- hook into FORWARD: only L2 -> PLC:502 is considered; every packet is inspected
iptables -A FORWARD -p tcp -d $PLC --dport $PORT -j MB_FILTER
# replies from PLC (state-tracked)
iptables -A FORWARD -p tcp -s $PLC --sport $PORT -m conntrack --ctstate ESTABLISHED -j ACCEPT

# --- conduit L2 -> L3: only Node-RED may reach the historian API, only on 8086
iptables -A FORWARD -p tcp -s $HMI -d $HIST --dport $HIST_PORT -j ACCEPT
iptables -A FORWARD -p tcp -s $HIST --sport $HIST_PORT -d $HMI -m conntrack --ctstate ESTABLISHED -j ACCEPT

# --- anything else trying to cross zones: rate-limited log, then the FORWARD policy (DROP) applies
iptables -A FORWARD -m limit --limit 10/min -j NFLOG --nflog-group 1 --nflog-prefix "FW-DENY: "

iptables -L -n -v --line-numbers
