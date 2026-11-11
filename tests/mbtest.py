#!/usr/bin/env python3
"""
Firewall test client: sends raw Modbus/TCP requests and reports whether the
PLC replied (allowed) or the packet was dropped (timeout / no connection).
No dependencies. Run from the L2 host (debian-L2).

  python3 mbtest.py                          # as Node-RED (192.168.72.10): reads+writes ok, dangerous FCs dropped
  python3 mbtest.py --src 192.168.72.99      # as an unauthorized host: everything dropped
  (add the test IP first:  ip addr add 192.168.72.99/24 dev eth0)
"""
import argparse
import socket
import struct

p = argparse.ArgumentParser()
p.add_argument("--host", default="192.168.71.10")
p.add_argument("--port", type=int, default=502)
p.add_argument("--src", default=None, help="source IP to bind (must exist on this host)")
p.add_argument("--timeout", type=float, default=2.0)
a = p.parse_args()

H = lambda *v: struct.pack(">" + "H" * len(v), *v)

# name, PDU, expected outcome when run from the authorised HMI host
TESTS = [
    ("FC03 read holding regs 0-5",     b"\x03" + H(0, 6),        "reply"),
    ("FC01 read coils 0-2",            b"\x01" + H(0, 3),        "reply"),
    ("FC06 write HR 50 (harmless)",    b"\x06" + H(50, 1234),    "reply"),
    ("FC17 report slave ID",           b"\x11",                  "dropped"),
    ("FC43 read device identification", b"\x2b\x0e\x01\x00",     "dropped"),
    ("FC08/0001 restart comms",        b"\x08" + H(0x0001, 0),   "dropped"),
    ("FC08/0004 force listen-only",    b"\x08" + H(0x0004, 0),   "dropped"),
    ("FC08/000A clear counters",       b"\x08" + H(0x000A, 0),   "dropped"),
]


def send(pdu, tid):
    frame = struct.pack(">HHHB", tid, 0, len(pdu) + 1, 1) + pdu
    s = socket.socket()
    s.settimeout(a.timeout)
    try:
        if a.src:
            s.bind((a.src, 0))
        s.connect((a.host, a.port))
        s.sendall(frame)
        return "reply" if s.recv(260) else "dropped"
    except (socket.timeout, ConnectionError, OSError):
        return "dropped"
    finally:
        s.close()


expect_all_dropped = a.src is not None
print(f"target {a.host}:{a.port}  source {a.src or 'default'}\n")
bad = 0
for i, (name, pdu, expected) in enumerate(TESTS, 1):
    want = "dropped" if expect_all_dropped else expected
    got = send(pdu, i)
    ok = got == want
    bad += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {name:36s} got={got:8s} expected={want}")
print("\nALL PASS" if not bad else f"\n{bad} FAILED")
