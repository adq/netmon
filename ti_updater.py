#!/usr/bin/env python3

import argparse
import datetime
import ipaddress
import os
import signal
import smtplib
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from email.message import EmailMessage


DATA_DIR = os.environ.get("NETMON_DATA_DIR", "/data/netmon")
TI_DB = os.path.join(DATA_DIR, "ti.db")
GEOIP_DIR = os.path.join(DATA_DIR, "geoip")
USER_AGENT = "netmon/1.0"

LOOP_INTERVAL_SEC = int(os.environ.get("NETMON_TI_LOOP_INTERVAL_SEC", "86400"))
ERROR_EMAIL_INTERVAL_SEC = int(os.environ.get("NETMON_ERROR_EMAIL_INTERVAL_SEC", "3600"))
RECIPIENT = os.environ.get("NETMON_RECIPIENT", "adq@lidskialf.net")
SUBJECT_PREFIX = os.environ.get("NETMON_SUBJECT_PREFIX", "[house-net]")
SMTP_HOST = os.environ.get("NETMON_SMTP_HOST", "smtp.resend.com")
SMTP_PORT = int(os.environ.get("NETMON_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("NETMON_SMTP_USER", "resend")
SMTP_PASSWORD = os.environ.get("NETMON_SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("NETMON_SMTP_FROM", "root@admin.lidskialf.net")


FEEDS = [
    {
        "source": "spamhaus-drop",
        "severity": "high",
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "parser": "comment-stripped",
    },
    {
        "source": "firehol-level1",
        "severity": "high",
        "url": "https://iplists.firehol.org/files/firehol_level1.netset",
        "parser": "comment-stripped",
    },
    {
        "source": "feodo-tracker",
        "severity": "high",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "parser": "comment-stripped",
    },
    {
        "source": "ipsum-l5",
        "severity": "medium",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt",
        "parser": "comment-stripped",
    },
    {
        "source": "tor-exit",
        "severity": "low",
        "url": "https://check.torproject.org/torbulkexitlist",
        "parser": "comment-stripped",
    },
]


def fetch(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}")
        return resp.read().decode("utf-8", errors="replace")


def parse_comment_stripped(text):
    nets = []
    for line in text.splitlines():
        # Strip both ; and # comments
        line = line.split(";", 1)[0].split("#", 1)[0].strip()
        if not line:
            continue
        # First whitespace-separated token (handles ipsum's "ip\tcount" lines)
        token = line.split()[0]
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network):
            nets.append(net)
    return nets


PARSERS = {
    "comment-stripped": parse_comment_stripped,
}


def init_db(con):
    con.executescript("""
        CREATE TABLE IF NOT EXISTS ti_indicators (
            cidr_start INTEGER NOT NULL,
            cidr_end   INTEGER NOT NULL,
            family     INTEGER NOT NULL,
            source     TEXT NOT NULL,
            severity   TEXT NOT NULL,
            last_seen  INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ti_meta (
            source        TEXT PRIMARY KEY,
            last_fetch_ts INTEGER NOT NULL,
            row_count     INTEGER NOT NULL,
            ok            INTEGER NOT NULL,
            note          TEXT
        );
    """)


def insert_rows(con, source, severity, networks, now_ts):
    rows = [
        (int(n.network_address), int(n.broadcast_address), 4, source, severity, now_ts)
        for n in networks
    ]
    con.executemany(
        "INSERT INTO ti_indicators (cidr_start, cidr_end, family, source, severity, last_seen) "
        "VALUES (?,?,?,?,?,?)",
        rows,
    )
    return len(rows)


def carry_forward(new_con, old_path, source):
    """Copy rows for `source` from a previous ti.db so coverage isn't lost on a fetch failure."""
    if not os.path.exists(old_path):
        return 0
    try:
        old = sqlite3.connect(f"file:{old_path}?mode=ro", uri=True)
        rows = list(old.execute(
            "SELECT cidr_start, cidr_end, family, source, severity, last_seen "
            "FROM ti_indicators WHERE source=?",
            (source,),
        ))
        old.close()
    except sqlite3.Error:
        return 0
    if not rows:
        return 0
    new_con.executemany(
        "INSERT INTO ti_indicators (cidr_start, cidr_end, family, source, severity, last_seen) "
        "VALUES (?,?,?,?,?,?)",
        rows,
    )
    return len(rows)


def update_geoip():
    account = os.environ.get("MAXMIND_ACCOUNT_ID")
    key = os.environ.get("MAXMIND_LICENSE_KEY")
    if not (account and key):
        print("MaxMind credentials not set; skipping GeoIP refresh", file=sys.stderr)
        return
    os.makedirs(GEOIP_DIR, exist_ok=True)
    cfg_path = os.path.join(GEOIP_DIR, "GeoIP.conf")
    with open(cfg_path, "w") as f:
        f.write(f"AccountID {account}\n")
        f.write(f"LicenseKey {key}\n")
        f.write("EditionIDs GeoLite2-Country GeoLite2-ASN\n")
        f.write(f"DatabaseDirectory {GEOIP_DIR}\n")
    os.chmod(cfg_path, 0o600)
    try:
        subprocess.check_call(["geoipupdate", "-f", cfg_path])
    except FileNotFoundError:
        print("geoipupdate not installed; skipping GeoIP refresh", file=sys.stderr)
    except subprocess.CalledProcessError as e:
        print(f"geoipupdate failed: {e}", file=sys.stderr)


def send_email(subject, body):
    if not SMTP_PASSWORD:
        print("NETMON_SMTP_PASSWORD not set; skipping email send", file=sys.stderr)
        return False
    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = RECIPIENT
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASSWORD)
            s.send_message(msg)
        return True
    except (smtplib.SMTPException, OSError) as e:
        print(f"SMTP send failed: {e}", file=sys.stderr)
        return False


def run_once():
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp_db = TI_DB + ".tmp"
    bak_db = TI_DB + ".bak"
    if os.path.exists(tmp_db):
        os.remove(tmp_db)

    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    con = sqlite3.connect(tmp_db)
    init_db(con)

    fail_count = 0
    for feed in FEEDS:
        source = feed["source"]
        try:
            text = fetch(feed["url"])
            nets = PARSERS[feed["parser"]](text)
            if not nets:
                raise RuntimeError("parsed 0 networks")
            n = insert_rows(con, source, feed["severity"], nets, now_ts)
            con.execute(
                "INSERT OR REPLACE INTO ti_meta (source, last_fetch_ts, row_count, ok, note) "
                "VALUES (?,?,?,1,NULL)",
                (source, now_ts, n),
            )
            print(f"{source}: {n} rows", file=sys.stderr)
        except Exception as e:
            fail_count += 1
            kept = carry_forward(con, TI_DB, source)
            con.execute(
                "INSERT OR REPLACE INTO ti_meta (source, last_fetch_ts, row_count, ok, note) "
                "VALUES (?,?,?,0,?)",
                (source, now_ts, kept, str(e)),
            )
            print(f"{source}: FAILED ({e}); kept {kept} stale rows", file=sys.stderr)

    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_ti_range ON ti_indicators (family, cidr_start, cidr_end)"
    )
    con.commit()
    con.close()

    # Atomic swap. On Linux os.rename is atomic; .bak retained for rollback.
    if os.path.exists(TI_DB):
        if os.path.exists(bak_db):
            os.remove(bak_db)
        os.rename(TI_DB, bak_db)
    os.rename(tmp_db, TI_DB)

    update_geoip()

    if fail_count == len(FEEDS):
        raise RuntimeError("all threat-intel feeds failed to fetch")


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
                    f"{SUBJECT_PREFIX} ERROR: ti-updater tick failed",
                    f"Tick raised {type(e).__name__}: {e}\n\n{traceback.format_exc()}",
                )
                last_error_email = now
        elapsed = time.time() - tick_start
        remaining = max(1.0, LOOP_INTERVAL_SEC - elapsed)
        stop_event.wait(remaining)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true", help="run forever, sleeping NETMON_TI_LOOP_INTERVAL_SEC between ticks")
    args = ap.parse_args()

    if not args.loop:
        try:
            run_once()
        except RuntimeError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
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
