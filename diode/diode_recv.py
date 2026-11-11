#!/usr/bin/env python3
"""
diode_recv.py - one-way UDP replication receiver (runs in the DMZ, next to the mirror InfluxDB).

Listens for datagrams from diode_send.py, verifies them, and writes the accepted points to the
mirror InfluxDB 2.x (write-only token). It never sends anything back to the sender.

A datagram is accepted only if:
  * the header is well formed and the CRC matches the body,
  * the HMAC matches (when DIODE_KEY is set),
  * every line belongs to an allowed measurement (dc_temp, dc_power, dc_state).
Anything else is counted as rejected and dropped. Missing sequence numbers are counted as lost.

It also writes a "diode_stats" point every STATS_INTERVAL seconds into the mirror
(received, lost, rejected, points, write_errors, last_seq, heartbeats) so link health and packet
loss can be graphed. Counters restart from zero when the receiver restarts.

Configuration (environment variables, or the same names in --env-file):
    DIODE_LISTEN   host:port to listen on, default 0.0.0.0:8094
    DIODE_KEY      shared secret (must match the sender)
    MIRROR_URL     default http://127.0.0.1:8086
    MIRROR_ORG     default lab
    MIRROR_BUCKET  default dc_ot
    MIRROR_TOKEN   write token for the mirror bucket (required)
    STATS_INTERVAL seconds, default 5
    LOG_EVERY      seconds between summary log lines, default 30 (0 = off)
Standard library only (Python 3.9+).
"""
import hashlib
import hmac
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.request
import zlib

ALLOWED = {"dc_temp", "dc_power", "dc_state"}
HEAD_RE = re.compile(r"^#DIODE v1 seq=(\d+) ts=(\d+) n=(\d+) crc=([0-9a-f]{8}) mac=([0-9a-f]{32}|-)$")


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def load_env_file(path):
    if path and os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def verify(data, key):
    """Return (ok, reason, seq, lines)."""
    head, sep, body = data.partition(b"\n")
    try:
        m = HEAD_RE.match(head.decode("ascii"))
    except UnicodeDecodeError:
        m = None
    if not m:
        return False, "bad header", None, []
    seq, ts, n, crc, mac = int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4), m.group(5)
    if zlib.crc32(body) & 0xFFFFFFFF != int(crc, 16):
        return False, "crc mismatch", seq, []
    if key:
        want = hmac.new(key, ("%d|%d|%d|" % (seq, ts, n)).encode() + body, hashlib.sha256).hexdigest()[:32]
        if mac == "-" or not hmac.compare_digest(want, mac):
            return False, "bad mac", seq, []
    try:
        lines = [ln for ln in body.decode("utf-8").split("\n") if ln]
    except UnicodeDecodeError:
        return False, "not utf-8", seq, []
    if len(lines) != n:
        return False, "line count mismatch", seq, []
    for ln in lines:
        meas = re.split(r"[ ,]", ln, 1)[0]
        if meas not in ALLOWED:
            return False, "measurement not allowed: %r" % meas[:40], seq, []
    return True, "", seq, lines


class Mirror:
    def __init__(self, url, org, bucket, token):
        self.endpoint = "%s/api/v2/write?org=%s&bucket=%s&precision=ns" % (url.rstrip("/"), org, bucket)
        self.token = token

    def write(self, lines):
        req = urllib.request.Request(self.endpoint, data="\n".join(lines).encode(),
                                     headers={"Authorization": "Token " + self.token})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status


def main():
    env_file = sys.argv[sys.argv.index("--env-file") + 1] if "--env-file" in sys.argv else None
    load_env_file(env_file)
    g = os.environ.get
    token = g("MIRROR_TOKEN")
    if not token:
        sys.exit("MIRROR_TOKEN is required")
    key = g("DIODE_KEY", "").encode()
    if not key:
        log("WARNING: DIODE_KEY not set - datagrams are NOT authenticated")
    host, port = g("DIODE_LISTEN", "0.0.0.0:8094").rsplit(":", 1)
    mirror = Mirror(g("MIRROR_URL", "http://127.0.0.1:8086"), g("MIRROR_ORG", "lab"), g("MIRROR_BUCKET", "dc_ot"), token)
    stats_every, log_every = float(g("STATS_INTERVAL", "5")), float(g("LOG_EVERY", "30"))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)       # receive-only: never sendto()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind((host, int(port)))
    sock.settimeout(1.0)
    log("diode_recv: listening on udp://%s:%s, writing to %s" % (host, port, mirror.endpoint.split("?")[0]))

    c = dict(received=0, heartbeats=0, lost=0, rejected=0, points=0, write_errors=0)
    expected, last_seq, next_stats = None, -1, time.time() + stats_every
    next_log = time.time() + log_every
    while True:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            data = None
        if data is not None:
            ok, why, seq, lines = verify(data, key)
            if not ok:
                c["rejected"] += 1
                log("REJECTED datagram from %s: %s" % (addr[0], why))
            else:
                if expected is not None and seq > expected:
                    c["lost"] += seq - expected
                    log("sequence gap: expected %d got %d (%d lost)" % (expected, seq, seq - expected))
                elif expected is not None and seq < expected:
                    log("sequence went backwards (%d < %d): sender restarted or reordering" % (seq, expected))
                expected, last_seq = seq + 1, seq
                if c["received"] == 0:
                    log("first valid datagram received from %s (seq %d)" % (addr[0], seq))
                c["received"] += 1
                if not lines:
                    c["heartbeats"] += 1
                else:
                    try:
                        mirror.write(lines)
                        c["points"] += len(lines)
                    except (urllib.error.URLError, OSError) as e:
                        c["write_errors"] += 1
                        log("mirror write failed (%s); data dropped (no retry path in a one-way link)" % e)
        if log_every and time.time() >= next_log:
            next_log = time.time() + log_every
            log("summary: " + " ".join("%s=%d" % kv for kv in c.items()) + " last_seq=%d" % max(last_seq, 0))
        if time.time() >= next_stats:
            next_stats = time.time() + stats_every
            line = "diode_stats %s,last_seq=%di %d" % (
                ",".join("%s=%di" % (k, v) for k, v in c.items()), max(last_seq, 0), time.time_ns())
            try:
                mirror.write([line])
            except (urllib.error.URLError, OSError) as e:
                log("stats write failed (%s)" % e)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
