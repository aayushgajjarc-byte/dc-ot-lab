#!/usr/bin/env python3
"""
diode_send.py - one-way UDP replication sender (runs on the L3 historian, influx-l3).

Every INTERVAL seconds it reads the points written since the last cycle from the local
InfluxDB 2.x (Flux query, read-only token) and sends them as UDP datagrams in InfluxDB
line protocol to the DMZ receiver (diode_recv.py). There is NO return channel: it never
reads from the socket, never retries and never backfills. Anything lost on the way, or
sent while the link is down, stays lost (that is what a data diode does).

Each datagram starts with one header line:
    #DIODE v1 seq=<n> ts=<unix> n=<lines> crc=<crc32 of body> mac=<hmac-sha256/128 or ->
and is followed by the line-protocol body. Sequence numbers let the receiver count losses;
the HMAC (shared key) stops other DMZ hosts from injecting data. Datagrams with no body are
heartbeats so the receiver can see the link is alive.

Configuration (environment variables, or the same names in the --env-file):
    INFLUX_URL   default http://127.0.0.1:8086
    INFLUX_ORG   default lab
    INFLUX_BUCKET default dc_ot
    INFLUX_TOKEN read-only token for the bucket (required)
    DIODE_TARGET host:port of the receiver, e.g. 192.168.74.10:8094 (required)
    DIODE_KEY    shared secret for the HMAC (strongly recommended)
    DIODE_INTERVAL seconds between cycles, default 5
    DIODE_LAG    seconds to stay behind "now" so late writes are included, default 2
    DIODE_MAX_BACKLOG  if the sender was down longer than this many seconds, skip the old data, default 30
    DIODE_PACE   seconds to pause between datagrams, default 0.003
    DIODE_STATE  state file, default /var/lib/diode/send_state.json
Standard library only (Python 3.9+).
"""
import calendar
import csv
import hashlib
import hmac
import io
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.request
import zlib
from datetime import datetime, timedelta, timezone

MEASUREMENTS = ("dc_temp", "dc_power", "dc_state")
STD_COLS = {"", "result", "table", "_start", "_stop", "_time", "_value", "_field", "_measurement", "_vtype"}
MAX_BODY = 1200          # bytes of line protocol per datagram (stays well below the 1450 MTU)


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def load_env_file(path):
    if path and os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def rfc3339(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_time_ns(s):
    """RFC3339 (any number of fractional digits) -> integer nanoseconds since the epoch."""
    m = re.match(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?Z$", s)
    if not m:
        raise ValueError("bad time " + s)
    y, mo, d, h, mi, sec = (int(x) for x in m.groups()[:6])
    frac = (m.group(7) or "").ljust(9, "0")[:9]
    return calendar.timegm((y, mo, d, h, mi, sec)) * 10**9 + int(frac)


def query_points(url, org, bucket, token, start, stop):
    flt = " or ".join('r._measurement == "%s"' % m for m in MEASUREMENTS)
    flux = (
        'from(bucket: "%s")\n'
        "  |> range(start: %s, stop: %s)\n"
        "  |> filter(fn: (r) => %s)\n"
        '  |> drop(columns: ["_start", "_stop"])\n' % (bucket, rfc3339(start), rfc3339(stop), flt)
    )
    body = json.dumps({
        "query": flux, "type": "flux",
        "dialect": {"header": True, "delimiter": ",", "commentPrefix": "#", "dateTimeFormat": "RFC3339",
                    "annotations": ["datatype", "group", "default"]},
    })
    req = urllib.request.Request(
        url.rstrip("/") + "/api/v2/query?org=" + org,
        data=body.encode(),
        headers={"Authorization": "Token " + token, "Content-Type": "application/json", "Accept": "application/csv"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode()


def parse_csv(text):
    """Parse Flux annotated CSV into a list of row dicts (adds _vtype from #datatype)."""
    rows, header, dtypes = [], None, None
    for rec in csv.reader(io.StringIO(text)):
        if not rec or all(c == "" for c in rec):
            header, dtypes = None, None          # blank line = next table
            continue
        if rec[0].startswith("#"):
            if rec[0] == "#group":                 # first annotation of a new table block
                header, dtypes = None, None
            elif rec[0] == "#datatype":
                dtypes = rec
            continue
        if header is None:
            header = rec
            continue
        row = dict(zip(header, rec))
        row["_vtype"] = dtypes[header.index("_value")] if dtypes and "_value" in header and header.index("_value") < len(dtypes) else ""
        rows.append(row)
    return rows


def esc_tag(s):
    return s.replace("\\", "\\\\").replace(",", "\\,").replace(" ", "\\ ").replace("=", "\\=")


def fmt_value(v, vtype):
    """Line-protocol field value. Uses the Flux #datatype when present, otherwise infers from the text."""
    if vtype == "boolean" or (vtype in ("", "double") and v.lower() in ("true", "false")):
        return "true" if v.lower() == "true" else "false"
    if vtype == "long":
        return "%di" % int(v)
    if vtype == "unsignedLong":
        return "%du" % int(v)
    if vtype != "string":
        try:
            return repr(float(v))
        except ValueError:
            pass                                   # not numeric: fall through and send as a string
    escaped = v.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + escaped + '"'


def to_lines(rows):
    points = {}
    for r in rows:
        if r.get("_measurement") not in MEASUREMENTS or not r.get("_time") or r.get("_value", "") == "":
            continue
        tags = tuple(sorted((k, v) for k, v in r.items() if k not in STD_COLS and v != ""))
        key = (r["_measurement"], tags, parse_time_ns(r["_time"]))
        points.setdefault(key, {})[r["_field"]] = fmt_value(r["_value"], r["_vtype"])
    out = []
    for (meas, tags, ts), fields in sorted(points.items(), key=lambda kv: kv[0][2]):
        head = esc_tag(meas) + "".join("," + esc_tag(k) + "=" + esc_tag(v) for k, v in tags)
        out.append("%s %s %d" % (head, ",".join("%s=%s" % (esc_tag(k), v) for k, v in sorted(fields.items())), ts))
    return out


def chunk(lines):
    cur, size = [], 0
    for ln in lines:
        b = len(ln) + 1
        if cur and size + b > MAX_BODY:
            yield cur
            cur, size = [], 0
        cur.append(ln)
        size += b
    if cur:
        yield cur


def make_datagram(seq, lines, key):
    body = ("\n".join(lines)).encode()
    ts = int(time.time())
    crc = zlib.crc32(body) & 0xFFFFFFFF
    mac = "-"
    if key:
        mac = hmac.new(key, ("%d|%d|%d|" % (seq, ts, len(lines))).encode() + body, hashlib.sha256).hexdigest()[:32]
    head = "#DIODE v1 seq=%d ts=%d n=%d crc=%08x mac=%s\n" % (seq, ts, len(lines), crc, mac)
    return head.encode() + body


def main():
    env_file = sys.argv[sys.argv.index("--env-file") + 1] if "--env-file" in sys.argv else None
    load_env_file(env_file)
    g = os.environ.get
    url, org, bucket = g("INFLUX_URL", "http://127.0.0.1:8086"), g("INFLUX_ORG", "lab"), g("INFLUX_BUCKET", "dc_ot")
    token, target = g("INFLUX_TOKEN"), g("DIODE_TARGET")
    if not token or not target:
        sys.exit("INFLUX_TOKEN and DIODE_TARGET are required")
    host, port = target.rsplit(":", 1)
    key = g("DIODE_KEY", "").encode()
    if not key:
        log("WARNING: DIODE_KEY not set - datagrams are NOT authenticated")
    interval, lag = float(g("DIODE_INTERVAL", "5")), float(g("DIODE_LAG", "2"))
    max_backlog, pace = float(g("DIODE_MAX_BACKLOG", "30")), float(g("DIODE_PACE", "0.003"))
    state_path = g("DIODE_STATE", "/var/lib/diode/send_state.json")
    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    try:
        st = json.load(open(state_path))
    except Exception:
        st = {}
    seq = int(st.get("seq", 0))
    cursor = datetime.fromisoformat(st["cursor"].replace("Z", "+00:00")) if st.get("cursor") else \
        datetime.now(timezone.utc) - timedelta(seconds=interval + lag)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)       # send-only: never recv
    log("diode_send: %s/%s -> udp://%s every %.0fs" % (url, bucket, target, interval))
    while True:
        t0 = time.time()
        stop = datetime.now(timezone.utc) - timedelta(seconds=lag)
        if (stop - cursor).total_seconds() > max_backlog:
            log("skipping %.0f s of old data (sender was down); a one-way link does not replay" % (stop - cursor).total_seconds())
            cursor = stop - timedelta(seconds=interval)
        if stop > cursor:
            try:
                lines = to_lines(parse_csv(query_points(url, org, bucket, token, cursor, stop)))
                cursor = stop                                      # advance only after a good read
            except (urllib.error.URLError, OSError, ValueError) as e:
                log("historian query failed (%s); will retry the same window" % e)
                lines = None
            if lines is not None:
                batches = list(chunk(lines)) or [[]]               # empty -> one heartbeat datagram
                for b in batches:
                    try:
                        sock.sendto(make_datagram(seq, b, key), (host, int(port)))
                    except OSError as e:
                        log("send failed (%s)" % e)
                    seq += 1
                    time.sleep(pace)                               # avoid bursts overflowing the receiver buffer
                log("sent %d points in %d datagram(s), seq now %d" % (len(lines), len(batches), seq))
                json.dump({"seq": seq, "cursor": rfc3339(cursor)}, open(state_path, "w"))
        time.sleep(max(0.2, interval - (time.time() - t0)))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
