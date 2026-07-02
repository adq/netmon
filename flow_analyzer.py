#!/usr/bin/env python3

import argparse
import datetime
import glob
import ipaddress
import json
import os
import signal
import socket
import sqlite3
import sys
import threading
import time
import traceback

from config import (
    ALERTS_FILE,
    DATA_DIR,
    ERROR_EMAIL_INTERVAL_SEC,
    FLOWS_FILE,
    GEOIP_DIR,
    METRICS_DB,
    STATE_FILE,
    SUBJECT_PREFIX,
    TI_DB,
    send_email,
)


DEDUPE_HOURS = int(os.environ.get("NETMON_DEDUPE_HOURS", "6"))
DEDUPE_LOW_HOURS = int(os.environ.get("NETMON_DEDUPE_LOW_HOURS", "24"))
MIN_BYTES = int(os.environ.get("NETMON_MIN_BYTES", "2048"))
MIN_PACKETS = int(os.environ.get("NETMON_MIN_PACKETS", "2"))
EMAIL_MIN_SEVERITY = os.environ.get("NETMON_EMAIL_MIN_SEVERITY", "low")
LOOP_INTERVAL_SEC = int(os.environ.get("NETMON_LOOP_INTERVAL_SEC", "120"))

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

PRIVATE_V4 = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("255.255.255.255/32"),
]

PRIVATE_V6 = [
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("::/128"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("ff00::/8"),
]

PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "icmp6"}


def is_private_addr(addr):
    try:
        ip = ipaddress.ip_address(addr)
    except (ValueError, TypeError):
        return True
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in n for n in PRIVATE_V4)
    return any(ip in n for n in PRIVATE_V6)


def empty_state():
    return {
        "flow_cursor": None,
        "baseline_asn": {},
        "baseline_country": {},
        "alerts_sent": {},
    }


def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return empty_state()


def save_state(state, path):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def append_alerts(path, records):
    with open(path, "a") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def init_metrics_db(con):
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS country_daily (
            date TEXT NOT NULL,
            internal_ip TEXT NOT NULL,
            country TEXT NOT NULL,
            flows INTEGER NOT NULL DEFAULT 0,
            bytes INTEGER NOT NULL DEFAULT 0,
            packets INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (date, internal_ip, country)
        );
        CREATE INDEX IF NOT EXISTS idx_country_daily_date ON country_daily(date);
        CREATE TABLE IF NOT EXISTS asn_daily (
            date TEXT NOT NULL,
            internal_ip TEXT NOT NULL,
            asn INTEGER NOT NULL,
            asn_org TEXT NOT NULL DEFAULT '',
            flows INTEGER NOT NULL DEFAULT 0,
            bytes INTEGER NOT NULL DEFAULT 0,
            packets INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (date, internal_ip, asn)
        );
        CREATE INDEX IF NOT EXISTS idx_asn_daily_date ON asn_daily(date);
        """
    )


def flush_rollup(con, country_rollup, asn_rollup):
    if not country_rollup and not asn_rollup:
        return
    with con:
        for (date, ip, cc), v in country_rollup.items():
            con.execute(
                "INSERT INTO country_daily(date, internal_ip, country, flows, bytes, packets) "
                "VALUES(?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(date, internal_ip, country) DO UPDATE SET "
                "flows = flows + excluded.flows, "
                "bytes = bytes + excluded.bytes, "
                "packets = packets + excluded.packets",
                (date, ip, cc, v["flows"], v["bytes"], v["packets"]),
            )
        for (date, ip, asn), v in asn_rollup.items():
            con.execute(
                "INSERT INTO asn_daily(date, internal_ip, asn, asn_org, flows, bytes, packets) "
                "VALUES(?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(date, internal_ip, asn) DO UPDATE SET "
                "asn_org = CASE WHEN excluded.asn_org != '' THEN excluded.asn_org ELSE asn_org END, "
                "flows = flows + excluded.flows, "
                "bytes = bytes + excluded.bytes, "
                "packets = packets + excluded.packets",
                (date, ip, asn, v["asn_org"], v["flows"], v["bytes"], v["packets"]),
            )


def get_cursor(state, file_path):
    """Return (inode, offset, end, archive_drain) for this tick.
    inode/offset/end describe progress against the active flows file.
    archive_drain, when not None, is (path, start, end) of a rotated archive's
    unread tail that must be drained first — it covers the gap between our
    last cursor save and goflow2's SIGHUP-driven reopen."""
    try:
        st = os.stat(file_path)
    except FileNotFoundError:
        return None, 0, 0, None
    cursor = state.get("flow_cursor")
    if not cursor:
        # First run: skip the existing backlog so we don't process old history
        return st.st_ino, st.st_size, st.st_size, None
    saved_inode, saved_offset = cursor["inode"], cursor["offset"]
    if saved_inode == st.st_ino:
        offset = saved_offset if saved_offset <= st.st_size else 0
        return saved_inode, offset, st.st_size, None
    archive_drain = None
    for archive in sorted(glob.glob(file_path + ".archived.*")):
        try:
            ast = os.stat(archive)
        except FileNotFoundError:
            continue
        if ast.st_ino == saved_inode and saved_offset < ast.st_size:
            archive_drain = (archive, saved_offset, ast.st_size)
            break
    return st.st_ino, 0, st.st_size, archive_drain


def save_cursor(state, inode, offset):
    state["flow_cursor"] = {"inode": inode, "offset": offset}


def load_geoip():
    try:
        import maxminddb
    except ImportError:
        print("python3-maxminddb not installed; GeoIP enrichment disabled", file=sys.stderr)
        return None, None
    country = None
    asn = None
    cpath = os.path.join(GEOIP_DIR, "GeoLite2-Country.mmdb")
    apath = os.path.join(GEOIP_DIR, "GeoLite2-ASN.mmdb")
    if os.path.exists(cpath):
        country = maxminddb.open_database(cpath)
    if os.path.exists(apath):
        asn = maxminddb.open_database(apath)
    return country, asn


def lookup_geoip(country_db, asn_db, ip):
    cc = None
    asn_num = None
    asn_org = None
    if country_db is not None:
        try:
            r = country_db.get(ip) or {}
            cc = (r.get("country") or {}).get("iso_code") or \
                 (r.get("registered_country") or {}).get("iso_code")
        except Exception:
            pass
    if asn_db is not None:
        try:
            r = asn_db.get(ip) or {}
            asn_num = r.get("autonomous_system_number")
            asn_org = r.get("autonomous_system_organization")
        except Exception:
            pass
    return cc, asn_num, asn_org


def lookup_ti(ti_con, ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return []
    if not isinstance(addr, ipaddress.IPv4Address):
        return []
    ip_int = int(addr)
    return list(ti_con.execute(
        "SELECT source, severity FROM ti_indicators "
        "WHERE family=4 AND cidr_start<=? AND ?<=cidr_end",
        (ip_int, ip_int),
    ))


def max_severity(matches):
    return max((m[1] for m in matches), key=lambda s: SEVERITY_RANK.get(s, -1))


def baseline_check(state, src, asn_num, country, now_ts):
    """Update baseline; return 'new-asn'|'new-country' if a first-seen pair was inserted."""
    new_kind = None
    if asn_num is not None:
        bucket = state["baseline_asn"].setdefault(src, {})
        # JSON object keys are strings; coerce ASN once and stick with it.
        key = str(asn_num)
        entry = bucket.get(key)
        if entry is None:
            new_kind = "new-asn"
            bucket[key] = {"first_seen": now_ts, "last_seen": now_ts, "flow_count": 1}
        else:
            entry["last_seen"] = now_ts
            entry["flow_count"] += 1
    if country:
        bucket = state["baseline_country"].setdefault(src, {})
        entry = bucket.get(country)
        if entry is None:
            if new_kind is None:
                new_kind = "new-country"
            bucket[country] = {"first_seen": now_ts, "last_seen": now_ts, "flow_count": 1}
        else:
            entry["last_seen"] = now_ts
            entry["flow_count"] += 1
    return new_kind


def process_flow(flow, state, ti_con, country_db, asn_db, now_ts):
    src = flow.get("src_addr")
    dst = flow.get("dst_addr")
    if not src or not dst:
        return None
    if not is_private_addr(src):
        return None
    if is_private_addr(dst):
        return None

    bytes_ = int(flow.get("bytes") or 0)
    packets = int(flow.get("packets") or 0)
    if bytes_ < MIN_BYTES and packets < MIN_PACKETS:
        return None

    proto_num = flow.get("proto")
    proto_name = PROTO_NAMES.get(proto_num, str(proto_num) if proto_num is not None else "?")
    dport = int(flow.get("dst_port") or 0)

    matches = lookup_ti(ti_con, dst)
    cc, asn_num, asn_org = lookup_geoip(country_db, asn_db, dst)
    new_baseline = baseline_check(state, src, asn_num, cc, now_ts)

    base = {
        "internal_ip": src,
        "dst_ip": dst,
        "dst_port": dport,
        "proto": proto_name,
        "asn": asn_num,
        "asn_org": asn_org,
        "country": cc,
        "bytes": bytes_,
        "packets": packets,
    }

    if matches:
        sev = max_severity(matches)
        sources = ",".join(sorted({m[0] for m in matches}))
        return {**base, "kind": "ti-match", "severity": sev, "sources": sources}
    if new_baseline:
        return {**base, "kind": new_baseline, "severity": "low", "sources": ""}
    return None


def collapse(alerts):
    """Merge identical (internal_ip, dst_ip, kind) alerts within this batch."""
    by_key = {}
    for a in alerts:
        key = (a["internal_ip"], a["dst_ip"], a["kind"])
        if key not in by_key:
            by_key[key] = dict(a)
        else:
            by_key[key]["bytes"] += a["bytes"]
            by_key[key]["packets"] += a["packets"]
    return list(by_key.values())


def is_rate_limited(state, alert, now_ts):
    key = f"{alert['internal_ip']}|{alert['dst_ip']}|{alert['kind']}"
    window_h = DEDUPE_LOW_HOURS if alert["severity"] == "low" else DEDUPE_HOURS
    cutoff = now_ts - window_h * 3600
    last = state["alerts_sent"].get(key, 0)
    return last > cutoff


def mark_sent(state, alert, now_ts):
    key = f"{alert['internal_ip']}|{alert['dst_ip']}|{alert['kind']}"
    state["alerts_sent"][key] = now_ts


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None


def format_email(alert):
    rdns = reverse_dns(alert["dst_ip"]) or ""
    asn_part = f"AS{alert['asn']} ({alert['asn_org']})" if alert.get("asn") else "unknown ASN"
    cc = alert.get("country") or "??"
    kb = alert["bytes"] / 1024.0
    sev = alert["severity"].upper()

    if alert["kind"] == "ti-match":
        subj = f"{SUBJECT_PREFIX} {sev}: {alert['internal_ip']} -> {alert['dst_ip']} | {alert['sources']}"
    elif alert["kind"] == "new-asn":
        subj = f"{SUBJECT_PREFIX} {sev}: {alert['internal_ip']} -> new ASN {asn_part}"
    elif alert["kind"] == "new-country":
        subj = f"{SUBJECT_PREFIX} {sev}: {alert['internal_ip']} -> new country {cc}"
    else:
        subj = f"{SUBJECT_PREFIX} {sev}: {alert['internal_ip']} -> {alert['dst_ip']}"

    body = "\n".join([
        f"timestamp:    {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
        f"kind:         {alert['kind']}",
        f"severity:     {alert['severity']}",
        f"source:       {alert['internal_ip']}",
        f"destination:  {alert['dst_ip']}{f' ({rdns})' if rdns else ''} :{alert['dst_port']}/{alert['proto']}",
        f"geoip:        {cc} / {asn_part}",
        f"bytes/pkts:   {kb:.1f} KB / {alert['packets']}",
        f"matched:      {alert.get('sources') or '(none)'}",
    ])
    return subj, body


def run_once():
    if not os.path.exists(FLOWS_FILE):
        print(f"flow file {FLOWS_FILE} does not exist; nothing to do", file=sys.stderr)
        return

    os.makedirs(DATA_DIR, exist_ok=True)
    state = load_state(STATE_FILE)

    if not os.path.exists(TI_DB):
        print(f"threat-intel DB {TI_DB} does not exist; run ti-updater first", file=sys.stderr)
        return

    ti_con = sqlite3.connect(f"file:{TI_DB}?mode=ro", uri=True)
    metrics_con = sqlite3.connect(METRICS_DB)
    init_metrics_db(metrics_con)
    country_db, asn_db = load_geoip()

    inode, offset, end, archive_drain = get_cursor(state, FLOWS_FILE)
    if inode is None:
        ti_con.close()
        metrics_con.close()
        return

    now_ts = int(time.time())
    today = datetime.datetime.fromtimestamp(now_ts, tz=datetime.timezone.utc).date().isoformat()
    raw_alerts = []
    country_rollup = {}
    asn_rollup = {}
    line_count = 0

    def consume(path, start, stop):
        nonlocal line_count
        pos = start
        with open(path, "rb") as f:
            f.seek(start)
            while pos < stop:
                line = f.readline()
                if not line:
                    break
                pos += len(line)
                line_count += 1
                try:
                    flow = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                # Roll up every outbound flow by (device, country) and (device, ASN),
                # regardless of the MIN_BYTES alert threshold — the dashboard wants
                # the full traffic picture, not just alert-eligible flows.
                src = flow.get("src_addr")
                dst = flow.get("dst_addr")
                if src and dst and is_private_addr(src) and not is_private_addr(dst):
                    bytes_ = int(flow.get("bytes") or 0)
                    packets = int(flow.get("packets") or 0)
                    cc, asn_num, asn_org = lookup_geoip(country_db, asn_db, dst)
                    ck = (today, src, cc or "")
                    cb = country_rollup.setdefault(
                        ck, {"flows": 0, "bytes": 0, "packets": 0})
                    cb["flows"] += 1
                    cb["bytes"] += bytes_
                    cb["packets"] += packets
                    ak = (today, src, int(asn_num or 0))
                    ab = asn_rollup.setdefault(
                        ak, {"flows": 0, "bytes": 0, "packets": 0, "asn_org": ""})
                    ab["flows"] += 1
                    ab["bytes"] += bytes_
                    ab["packets"] += packets
                    if asn_org and not ab["asn_org"]:
                        ab["asn_org"] = asn_org
                a = process_flow(flow, state, ti_con, country_db, asn_db, now_ts)
                if a:
                    raw_alerts.append(a)
        return pos

    if archive_drain:
        a_path, a_start, a_end = archive_drain
        consume(a_path, a_start, a_end)
        print(f"drained archive tail: {a_path} [{a_start}-{a_end}]", file=sys.stderr)

    new_offset = consume(FLOWS_FILE, offset, end) if offset < end else end
    save_cursor(state, inode, new_offset)

    alerts = collapse(raw_alerts)
    min_email_rank = SEVERITY_RANK.get(EMAIL_MIN_SEVERITY, 0)
    sent_count = 0
    alert_records = []

    for a in alerts:
        # New-ASN / new-country are auto-accepted: recorded for the daily digest
        # but never emailed individually. TI matches still email per-flow.
        sev_rank = SEVERITY_RANK.get(a["severity"], 0)
        rate_limited = is_rate_limited(state, a, now_ts)
        will_email = (
            a["kind"] == "ti-match"
            and sev_rank >= min_email_rank
            and not rate_limited
        )
        if will_email:
            mark_sent(state, a, now_ts)
        alert_records.append({
            "ts": now_ts,
            "severity": a["severity"],
            "kind": a["kind"],
            "internal_ip": a["internal_ip"],
            "dst_ip": a["dst_ip"],
            "dst_port": a["dst_port"],
            "proto": a["proto"],
            "asn": a.get("asn"),
            "asn_org": a.get("asn_org"),
            "country": a.get("country"),
            "sources": a.get("sources"),
            "bytes": a["bytes"],
            "packets": a["packets"],
            "suppressed": 0 if will_email else 1,
        })
        if will_email:
            subj, body = format_email(a)
            if send_email(subj, body):
                sent_count += 1

    if alert_records:
        append_alerts(ALERTS_FILE, alert_records)
    save_state(state, STATE_FILE)
    flush_rollup(metrics_con, country_rollup, asn_rollup)
    metrics_con.close()
    ti_con.close()

    if line_count or alerts:
        print(
            f"flows={line_count} alerts={len(alerts)} emailed={sent_count} "
            f"cursor={new_offset}",
            file=sys.stderr,
        )


def loop_forever(stop_event):
    last_error_email = 0
    while not stop_event.is_set():
        tick_start = time.time()
        try:
            run_once()
        except Exception as e:
            traceback.print_exc()
            now = time.time()
            if now - last_error_email > ERROR_EMAIL_INTERVAL_SEC:
                send_email(
                    f"{SUBJECT_PREFIX} ERROR: flow-analyzer tick failed",
                    f"Tick raised {type(e).__name__}: {e}\n\n{traceback.format_exc()}",
                )
                last_error_email = now
        # Sleep the remainder of the interval, interruptible
        elapsed = time.time() - tick_start
        remaining = max(1.0, LOOP_INTERVAL_SEC - elapsed)
        stop_event.wait(remaining)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true", help="run forever, sleeping NETMON_LOOP_INTERVAL_SEC between ticks")
    args = ap.parse_args()

    if not args.loop:
        run_once()
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
