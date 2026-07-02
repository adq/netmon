#!/usr/bin/env python3
# Simple read-only HTTP dashboard. Stdlib-only ThreadingHTTPServer; serves
# index.html at / and JSON endpoints under /api/*. Surfaces per-(device,
# country) and per-(device, ASN) traffic rollups that flow_analyzer populates
# into metrics.db, plus the existing alerts.jsonl log. Runs as a thread under
# the netmon orchestrator.

import argparse
import concurrent.futures
import datetime
import http.server
import ipaddress
import json
import os
import signal
import socket
import socketserver
import sqlite3
import sys
import threading
import time
import traceback
import urllib.parse

import daily_summary
from config import ALERTS_FILE, DATA_DIR, METRICS_DB, STATE_FILE, TI_DB


HOSTNAMES_FILE = os.path.join(DATA_DIR, "hosts")

LISTEN = os.environ.get("NETMON_WEB_LISTEN", "0.0.0.0:49210")
INDEX_HTML_PATH = os.environ.get(
    "NETMON_WEB_INDEX_HTML",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"),
)


def load_index_html():
    with open(INDEX_HTML_PATH, "rb") as f:
        return f.read()


# Reverse-DNS cache. Resolution happens in parallel on a small thread pool
# with a soft total deadline so the dropdown doesn't hang on a slow resolver.
# Successful answers are cached for 1h; failures for 5min so we retry sooner.
_DNS_CACHE = {}                     # ip -> (hostname_or_None, expires_ts)
_DNS_LOCK = threading.Lock()
_DNS_TTL_OK = 3600
_DNS_TTL_FAIL = 300
_DNS_BATCH_TIMEOUT = 2.0
_DNS_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=16, thread_name_prefix="netmon-dns")

# Optional static hostname map. /etc/hosts-style: lines like "192.168.1.10 kitchen-tv"
# (whitespace-separated, '#' starts a comment). Reloaded automatically on mtime change.
_HOSTNAMES_MAP = {}
_HOSTNAMES_MTIME = 0.0


def load_hostname_map():
    """Return {ip: hostname} from HOSTNAMES_FILE. Cached on mtime; missing file
    is fine (returns {})."""
    global _HOSTNAMES_MAP, _HOSTNAMES_MTIME
    try:
        mtime = os.path.getmtime(HOSTNAMES_FILE)
    except FileNotFoundError:
        if _HOSTNAMES_MAP:
            _HOSTNAMES_MAP = {}
            _HOSTNAMES_MTIME = 0.0
        return _HOSTNAMES_MAP
    if mtime == _HOSTNAMES_MTIME and _HOSTNAMES_MAP:
        return _HOSTNAMES_MAP
    mapping = {}
    try:
        with open(HOSTNAMES_FILE) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    mapping[parts[0]] = parts[1]
    except OSError as e:
        print(f"[web-server] failed to read {HOSTNAMES_FILE}: {e}", file=sys.stderr)
        return _HOSTNAMES_MAP
    _HOSTNAMES_MAP = mapping
    _HOSTNAMES_MTIME = mtime
    return mapping


def _resolve_blocking(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    # Drop trailing dot and only keep the leftmost label if it's a long FQDN —
    # most home routers serve names like "kitchen-tv.lan", display the short form.
    host = host.rstrip(".")
    return host


def resolve_hostnames(ips):
    """Return {ip: hostname_or_None} for the given IPs. Static map at
    HOSTNAMES_FILE wins; otherwise reverse-DNS in parallel with a TTL cache
    and a per-batch deadline so the dropdown can't hang on a slow resolver."""
    static = load_hostname_map()
    now = time.time()
    out = {}
    pending = []
    with _DNS_LOCK:
        for ip in ips:
            if ip in static:
                out[ip] = static[ip]
                continue
            entry = _DNS_CACHE.get(ip)
            if entry and entry[1] > now:
                out[ip] = entry[0]
            else:
                pending.append(ip)
    if not pending:
        return out
    futures = {_DNS_EXECUTOR.submit(_resolve_blocking, ip): ip for ip in pending}
    done, not_done = concurrent.futures.wait(
        futures.keys(), timeout=_DNS_BATCH_TIMEOUT)
    with _DNS_LOCK:
        for fut in done:
            ip = futures[fut]
            try:
                hn = fut.result()
            except Exception:
                hn = None
            out[ip] = hn
            ttl = _DNS_TTL_OK if hn else _DNS_TTL_FAIL
            _DNS_CACHE[ip] = (hn, now + ttl)
        for fut in not_done:
            ip = futures[fut]
            out[ip] = None
            _DNS_CACHE[ip] = (None, now + _DNS_TTL_FAIL)
    return out


def _ip_sort_key(ip):
    """Numeric sort key for IPv4/IPv6; invalid strings sort last."""
    try:
        addr = ipaddress.ip_address(ip)
        return (0, addr.version, int(addr))
    except ValueError:
        return (1, 0, ip)


def parse_listen(spec):
    host, _, port = spec.rpartition(":")
    if not port.isdigit():
        raise ValueError(f"NETMON_WEB_LISTEN must be host:port, got {spec!r}")
    return (host or "0.0.0.0"), int(port)


def open_metrics_ro():
    return sqlite3.connect(f"file:{METRICS_DB}?mode=ro", uri=True)


def _qs_str(qs, key, default=""):
    return (qs.get(key) or [default])[0]


def _qs_int(qs, key, default):
    try:
        return int((qs.get(key) or [str(default)])[0])
    except ValueError:
        return default


def api_health():
    out = {"ok": True}
    try:
        out["last_state_write_ts"] = int(os.path.getmtime(STATE_FILE))
    except FileNotFoundError:
        out["last_state_write_ts"] = None
    feeds = []
    if os.path.exists(TI_DB):
        try:
            con = sqlite3.connect(f"file:{TI_DB}?mode=ro", uri=True)
            for row in con.execute(
                "SELECT source, ok, row_count, last_fetch_ts FROM ti_meta ORDER BY source"
            ):
                feeds.append({
                    "source": row[0], "ok": bool(row[1]),
                    "rows": row[2], "last_fetch_ts": row[3],
                })
            con.close()
        except sqlite3.Error:
            pass
    out["ti_feeds"] = feeds
    return out


def api_devices(_qs):
    if not os.path.exists(METRICS_DB):
        return {"devices": []}
    end = datetime.datetime.now(datetime.timezone.utc).date()
    start = end - datetime.timedelta(days=30)
    con = open_metrics_ro()
    rows = con.execute(
        "SELECT internal_ip, MAX(date), SUM(bytes) FROM country_daily "
        "WHERE date >= ? AND date <= ? GROUP BY internal_ip",
        (start.isoformat(), end.isoformat()),
    ).fetchall()
    con.close()
    ips = [r[0] for r in rows]
    hostnames = resolve_hostnames(ips)
    devices = [
        {"ip": r[0], "hostname": hostnames.get(r[0]),
         "last_seen": r[1], "bytes_30d": r[2] or 0}
        for r in rows
    ]
    devices.sort(key=lambda d: _ip_sort_key(d["ip"]))
    return {"devices": devices}


def _country_breakdown(con, start_date, end_date, device):
    if device:
        rows = con.execute(
            "SELECT country, SUM(flows), SUM(bytes), SUM(packets) "
            "FROM country_daily WHERE date >= ? AND date <= ? AND internal_ip = ? "
            "GROUP BY country ORDER BY SUM(bytes) DESC",
            (start_date.isoformat(), end_date.isoformat(), device),
        ).fetchall()
    else:
        rows = con.execute(
            "SELECT country, SUM(flows), SUM(bytes), SUM(packets) "
            "FROM country_daily WHERE date >= ? AND date <= ? "
            "GROUP BY country ORDER BY SUM(bytes) DESC",
            (start_date.isoformat(), end_date.isoformat()),
        ).fetchall()
    return [{"country": r[0], "flows": r[1] or 0, "bytes": r[2] or 0, "packets": r[3] or 0}
            for r in rows]


def _asn_breakdown(con, start_date, end_date, device):
    if device:
        rows = con.execute(
            "SELECT asn, MAX(asn_org), SUM(flows), SUM(bytes), SUM(packets) "
            "FROM asn_daily WHERE date >= ? AND date <= ? AND internal_ip = ? "
            "GROUP BY asn ORDER BY SUM(bytes) DESC",
            (start_date.isoformat(), end_date.isoformat(), device),
        ).fetchall()
    else:
        rows = con.execute(
            "SELECT asn, MAX(asn_org), SUM(flows), SUM(bytes), SUM(packets) "
            "FROM asn_daily WHERE date >= ? AND date <= ? "
            "GROUP BY asn ORDER BY SUM(bytes) DESC",
            (start_date.isoformat(), end_date.isoformat()),
        ).fetchall()
    return [{"asn": r[0] or 0, "asn_org": r[1] or "",
             "flows": r[2] or 0, "bytes": r[3] or 0, "packets": r[4] or 0}
            for r in rows]


def api_summary(qs):
    days = max(1, _qs_int(qs, "days", 1))
    device = _qs_str(qs, "device") or None
    end_ts = int(time.time())
    start_ts = end_ts - days * 86400
    end_date = datetime.datetime.fromtimestamp(end_ts, tz=datetime.timezone.utc).date()
    start_date = datetime.datetime.fromtimestamp(start_ts, tz=datetime.timezone.utc).date()

    countries = []
    asns = []
    if os.path.exists(METRICS_DB):
        con = open_metrics_ro()
        countries = _country_breakdown(con, start_date, end_date, device)
        asns = _asn_breakdown(con, start_date, end_date, device)
        con.close()

    by_ip_alerts = daily_summary.summarise_window(start_ts, end_ts)
    if device:
        a = by_ip_alerts.get(device, {"ti-match": {}, "new-asn": {}, "new-country": {}})
        ti_hits_total = sum(h["count"] for h in a["ti-match"].values())
    else:
        ti_hits_total = sum(
            sum(h["count"] for h in v["ti-match"].values())
            for v in by_ip_alerts.values()
        )

    totals = {
        "flows": sum(c["flows"] for c in countries),
        "bytes": sum(c["bytes"] for c in countries),
        "packets": sum(c["packets"] for c in countries),
        "country_count": len(countries),
        "asn_count": len(asns),
        "ti_hits": ti_hits_total,
    }
    return {
        "window": {"start_ts": start_ts, "end_ts": end_ts, "days": days},
        "totals": totals,
        "countries": countries,
        "asns": asns,
    }


def api_timeseries(qs):
    days = max(1, _qs_int(qs, "days", 1))
    device = _qs_str(qs, "device") or None
    end_date = datetime.datetime.now(datetime.timezone.utc).date()
    start_date = end_date - datetime.timedelta(days=days - 1)

    by_date = {}
    if os.path.exists(METRICS_DB):
        con = open_metrics_ro()
        # Sum from country_daily — every flow is recorded there exactly once,
        # so totals match the sum across asn_daily.
        if device:
            rows = con.execute(
                "SELECT date, SUM(flows), SUM(bytes), SUM(packets) "
                "FROM country_daily WHERE date >= ? AND date <= ? AND internal_ip = ? "
                "GROUP BY date ORDER BY date",
                (start_date.isoformat(), end_date.isoformat(), device),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT date, SUM(flows), SUM(bytes), SUM(packets) "
                "FROM country_daily WHERE date >= ? AND date <= ? "
                "GROUP BY date ORDER BY date",
                (start_date.isoformat(), end_date.isoformat()),
            ).fetchall()
        con.close()
        for r in rows:
            by_date[r[0]] = {"flows": r[1] or 0, "bytes": r[2] or 0, "packets": r[3] or 0}

    buckets = []
    d = start_date
    while d <= end_date:
        ds = d.isoformat()
        b = by_date.get(ds, {"flows": 0, "bytes": 0, "packets": 0})
        buckets.append({"date": ds, **b})
        d += datetime.timedelta(days=1)
    return {"buckets": buckets}


def api_alerts(qs):
    days = max(1, _qs_int(qs, "days", 1))
    device = _qs_str(qs, "device") or None
    kind = _qs_str(qs, "kind") or None
    limit = max(1, min(2000, _qs_int(qs, "limit", 500)))
    end_ts = int(time.time())
    start_ts = end_ts - days * 86400

    matched = []
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = rec.get("ts", 0)
                if ts < start_ts or ts >= end_ts:
                    continue
                if device and rec.get("internal_ip") != device:
                    continue
                if kind and rec.get("kind") != kind:
                    continue
                matched.append(rec)
    truncated = len(matched) > limit
    if truncated:
        matched = matched[-limit:]
    matched.sort(key=lambda a: -a.get("ts", 0))
    return {"alerts": matched, "truncated": truncated}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "netmon/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[web-server] %s %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype):
        b = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json; charset=utf-8")

    def do_GET(self):
        try:
            url = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(url.query)
            if url.path == "/":
                self._send(200, load_index_html(), "text/html; charset=utf-8")
            elif url.path == "/api/health":
                self._json(200, api_health())
            elif url.path == "/api/devices":
                self._json(200, api_devices(qs))
            elif url.path == "/api/summary":
                self._json(200, api_summary(qs))
            elif url.path == "/api/timeseries":
                self._json(200, api_timeseries(qs))
            elif url.path == "/api/alerts":
                self._json(200, api_alerts(qs))
            else:
                self._json(404, {"error": "not found", "path": url.path})
        except BrokenPipeError:
            pass
        except Exception as e:
            traceback.print_exc()
            try:
                self._json(500, {"error": f"{type(e).__name__}: {e}"})
            except Exception:
                pass


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def loop_forever(stop_event):
    host, port = parse_listen(LISTEN)
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"[web-server] listening on http://{host}:{port}", file=sys.stderr)
    serve = threading.Thread(target=server.serve_forever, name="web-server-srv", daemon=True)
    serve.start()
    try:
        stop_event.wait()
    finally:
        server.shutdown()
        server.server_close()
        serve.join(timeout=5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true",
                    help="dump /api/summary?days=1 to stdout and exit (no server)")
    args = ap.parse_args()

    if args.once:
        print(json.dumps(api_summary({"days": ["1"]}), indent=2, default=str))
        return

    stop = threading.Event()

    def handle_sig(signum, _frame):
        print(f"received signal {signum}, exiting", file=sys.stderr)
        stop.set()

    signal.signal(signal.SIGTERM, handle_sig)
    signal.signal(signal.SIGINT, handle_sig)
    loop_forever(stop)


if __name__ == "__main__":
    main()
