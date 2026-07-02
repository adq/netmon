#!/usr/bin/env python3

import argparse
import datetime
import json
import os
import signal
import sys
import threading
import time
import traceback

import flow_analyzer
import config as cfg


HOUR_UTC = int(os.environ.get("NETMON_DAILY_SUMMARY_HOUR_UTC", "6"))


def _sentinel():
    """Path of the daily-summary sentinel. Read from cfg.DATA_DIR at call time
    so tests can redirect the data dir after import."""
    return os.path.join(cfg.DATA_DIR, ".last_daily_summary")


def next_fire_ts(now_ts, last_run_ts):
    """Earliest epoch second T with UTC hour == HOUR_UTC, T > now_ts, and
    T >= last_run_ts + 23h. The 23h floor stops a same-day restart from
    re-firing the digest if the container bounces shortly after a send."""
    now = datetime.datetime.fromtimestamp(now_ts, tz=datetime.timezone.utc)
    candidate = now.replace(hour=HOUR_UTC, minute=0, second=0, microsecond=0)
    if candidate <= now:
        candidate += datetime.timedelta(days=1)
    cand_ts = int(candidate.timestamp())
    while cand_ts < last_run_ts + 23 * 3600:
        candidate += datetime.timedelta(days=1)
        cand_ts = int(candidate.timestamp())
    return cand_ts


def _empty_entry():
    return {"ti-match": {}, "new-asn": {}, "new-country": {}}


def summarise_window(start_ts, end_ts):
    """Stream alerts.jsonl, return {internal_ip: {"ti-match": {(dst, sources): info},
    "new-asn": {asn: (org, dst)}, "new-country": {cc: dst}}} for records in
    [start_ts, end_ts). TI matches are aggregated per (dst, sources): count +
    total bytes accumulate, severity is the max seen."""
    by_ip = {}
    if not os.path.exists(cfg.ALERTS_FILE):
        return by_ip
    with open(cfg.ALERTS_FILE) as f:
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
            kind = rec.get("kind")
            if kind not in ("ti-match", "new-asn", "new-country"):
                continue
            ip = rec.get("internal_ip")
            if not ip:
                continue
            entry = by_ip.setdefault(ip, _empty_entry())
            if kind == "ti-match":
                key = (rec.get("dst_ip") or "", rec.get("sources") or "")
                hit = entry["ti-match"].get(key)
                sev = rec.get("severity") or "low"
                if hit is None:
                    entry["ti-match"][key] = {
                        "severity": sev,
                        "count": 1,
                        "bytes": int(rec.get("bytes") or 0),
                        "asn": rec.get("asn"),
                        "asn_org": rec.get("asn_org") or "",
                        "country": rec.get("country") or "",
                    }
                else:
                    hit["count"] += 1
                    hit["bytes"] += int(rec.get("bytes") or 0)
                    if flow_analyzer.SEVERITY_RANK.get(sev, -1) > \
                       flow_analyzer.SEVERITY_RANK.get(hit["severity"], -1):
                        hit["severity"] = sev
            elif kind == "new-asn":
                asn = rec.get("asn")
                if asn is not None and asn not in entry["new-asn"]:
                    entry["new-asn"][asn] = (rec.get("asn_org") or "", rec.get("dst_ip") or "")
            else:
                cc = rec.get("country")
                if cc and cc not in entry["new-country"]:
                    entry["new-country"][cc] = rec.get("dst_ip") or ""
    return by_ip


def format_digest(by_ip, start_ts, end_ts):
    ti_total = sum(sum(h["count"] for h in v["ti-match"].values()) for v in by_ip.values())
    ti_unique = sum(len(v["ti-match"]) for v in by_ip.values())
    asn_total = sum(len(v["new-asn"]) for v in by_ip.values())
    country_total = sum(len(v["new-country"]) for v in by_ip.values())
    start = datetime.datetime.fromtimestamp(start_ts, tz=datetime.timezone.utc).isoformat()
    end = datetime.datetime.fromtimestamp(end_ts, tz=datetime.timezone.utc).isoformat()

    subj = (f"{cfg.SUBJECT_PREFIX} daily summary: "
            f"{ti_total} TI hit(s), {asn_total} new ASN(s), "
            f"{country_total} new country code(s)")

    lines = [
        f"window:  {start} -> {end}",
        f"totals:  {ti_total} TI hit(s) across {ti_unique} unique destination(s), "
        f"{asn_total} new ASN(s), {country_total} new country code(s) "
        f"across {len(by_ip)} device(s)",
        "",
    ]
    for ip in sorted(by_ip.keys()):
        entry = by_ip[ip]
        lines.append(ip)
        if entry["ti-match"]:
            lines.append("  threat-intel hits:")
            # Sort: severity desc, then count desc, then dst_ip asc
            def hit_sort_key(item):
                (dst, _), info = item
                return (
                    -flow_analyzer.SEVERITY_RANK.get(info["severity"], -1),
                    -info["count"],
                    dst,
                )
            for (dst, sources), info in sorted(entry["ti-match"].items(), key=hit_sort_key):
                sev = info["severity"].upper()
                kb = info["bytes"] / 1024.0
                geo = info.get("country") or "??"
                asn = info.get("asn")
                asn_part = f"AS{asn}" if asn else "AS?"
                lines.append(
                    f"    {sev:<6}  {dst:<15}  {sources:<40}  "
                    f"({info['count']}x, {kb:.1f} KB)  [{geo} {asn_part}]"
                )
        if entry["new-asn"]:
            lines.append("  new ASNs:")
            for asn in sorted(entry["new-asn"].keys()):
                org, example = entry["new-asn"][asn]
                asn_str = f"AS{asn}"
                lines.append(f"    {asn_str:<12}  {org or '(unknown)':<32}  e.g. {example}")
        if entry["new-country"]:
            lines.append("  new countries:")
            for cc in sorted(entry["new-country"].keys()):
                lines.append(f"    {cc:<4}  e.g. {entry['new-country'][cc]}")
        lines.append("")
    return subj, "\n".join(lines)


def has_content(by_ip):
    return any(e["ti-match"] or e["new-asn"] or e["new-country"] for e in by_ip.values())


def run_once_dry():
    """One-shot: print what would be sent for the last 24h. Does not email or
    touch the sentinel. Used by `/app/daily-summary` for ad-hoc inspection."""
    end = int(time.time())
    start = end - 24 * 3600
    by_ip = summarise_window(start, end)
    if not has_content(by_ip):
        print(f"(no new-asn/new-country in last 24h; window {start}-{end})")
        return
    subj, body = format_digest(by_ip, start, end)
    print(f"Subject: {subj}\n")
    print(body)


def loop_forever(stop_event):
    last_error_email = 0
    sentinel = _sentinel()
    if not os.path.exists(sentinel):
        # Anchor first fire to the next HOUR_UTC after startup, not immediately.
        open(sentinel, "a").close()
    while not stop_event.is_set():
        try:
            now_ts = int(time.time())
            try:
                last_ts = int(os.path.getmtime(sentinel))
            except FileNotFoundError:
                open(sentinel, "a").close()
                last_ts = now_ts
            fire_ts = next_fire_ts(now_ts, last_ts)
            wait = max(1, fire_ts - now_ts)
            if stop_event.wait(wait):
                return
            window_end = fire_ts
            window_start = fire_ts - 24 * 3600
            by_ip = summarise_window(window_start, window_end)
            if has_content(by_ip):
                subj, body = format_digest(by_ip, window_start, window_end)
                if cfg.send_email(subj, body):
                    print(f"[daily-summary] sent: {subj}", file=sys.stderr)
                else:
                    print("[daily-summary] send_email failed", file=sys.stderr)
            else:
                print("[daily-summary] empty window; no email sent", file=sys.stderr)
            os.utime(sentinel, (fire_ts, fire_ts))
        except Exception as e:
            traceback.print_exc()
            now = time.time()
            if now - last_error_email > cfg.ERROR_EMAIL_INTERVAL_SEC:
                cfg.send_email(
                    f"{cfg.SUBJECT_PREFIX} ERROR: daily-summary tick failed",
                    f"Tick raised {type(e).__name__}: {e}\n\n{traceback.format_exc()}",
                )
                last_error_email = now
            stop_event.wait(3600)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true",
                    help="run forever, firing daily at NETMON_DAILY_SUMMARY_HOUR_UTC")
    args = ap.parse_args()

    if not args.loop:
        run_once_dry()
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
