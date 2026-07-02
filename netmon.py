#!/usr/bin/env python3
# PID 1 inside the netmon container.
# Spawns goflow2 as a subprocess; runs ti_updater + flow_analyzer + rotator
# in threads. Exits (nonzero) if goflow2 dies so docker restart-policy kicks in.

import datetime
import glob
import os
import signal
import subprocess
import sys
import threading
import time
import traceback

import daily_summary
import flow_analyzer
import ti_updater
import web_server
import config as cfg


GOFLOW2_BIN = os.environ.get("NETMON_GOFLOW2_BIN", "/usr/local/bin/goflow2")
GOFLOW2_LISTEN = os.environ.get("NETMON_GOFLOW2_LISTEN", "netflow://:2055")

FLOWS_ROTATE_SEC = int(os.environ.get("NETMON_FLOWS_ROTATE_SEC", "3600"))
FLOWS_RETAIN = int(os.environ.get("NETMON_FLOWS_RETAIN", "4"))
ROTATE_TICK_SEC = 60


def _archive_glob():
    """Glob for rotated flow archives. Read from cfg.FLOWS_FILE at call time
    so tests can redirect the data dir after import."""
    return f"{cfg.FLOWS_FILE}.archived.*"


def _rotate_sentinel():
    """Path of the rotation sentinel. Read from cfg.DATA_DIR at call time."""
    return os.path.join(cfg.DATA_DIR, ".flows_rotated")


def maintain_archives():
    """Prune oldest archives beyond FLOWS_RETAIN. Cheap when nothing to do."""
    archives = sorted(glob.glob(_archive_glob()))
    excess = len(archives) - FLOWS_RETAIN
    for old in archives[:max(0, excess)]:
        try:
            os.remove(old)
        except OSError as e:
            print(f"[netmon] failed to prune {old}: {e}", file=sys.stderr)


def maybe_rotate_flows(goflow):
    """Rotate flows.jsonl every FLOWS_ROTATE_SEC. Renames to a timestamped
    archive (kept uncompressed) and SIGHUPs goflow2 so it closes the old fd
    and opens a fresh flows.jsonl with a new inode. The analyzer's get_cursor
    matches the old inode against the archive on its next tick and drains
    any unread tail before reading the new file from byte 0."""
    maintain_archives()
    sentinel = _rotate_sentinel()
    now = time.time()
    try:
        last = os.path.getmtime(sentinel)
    except FileNotFoundError:
        # First run: establish baseline so the first rotation lands one interval out.
        open(sentinel, "a").close()
        return
    if now - last < FLOWS_ROTATE_SEC:
        return
    try:
        size = os.path.getsize(cfg.FLOWS_FILE)
    except FileNotFoundError:
        return
    if size == 0:
        os.utime(sentinel, None)
        return
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive_path = f"{cfg.FLOWS_FILE}.archived.{ts}"
    os.rename(cfg.FLOWS_FILE, archive_path)
    try:
        goflow.send_signal(signal.SIGHUP)
    except ProcessLookupError:
        pass
    os.utime(sentinel, None)
    print(f"[netmon] rotated flows: {archive_path} ({size} bytes)", file=sys.stderr)


def make_rotate_loop(goflow):
    def rotate_loop(stop_event):
        while not stop_event.is_set():
            try:
                maybe_rotate_flows(goflow)
            except Exception:
                traceback.print_exc()
            stop_event.wait(ROTATE_TICK_SEC)
    return rotate_loop


def thread_runner(name, fn, stop_event):
    try:
        fn(stop_event)
    except BaseException:
        print(f"[netmon] {name} thread crashed:", file=sys.stderr)
        traceback.print_exc()
        stop_event.set()


def main():
    os.makedirs(cfg.DATA_DIR, exist_ok=True)
    os.makedirs(os.path.join(cfg.DATA_DIR, "geoip"), exist_ok=True)
    os.makedirs(os.path.dirname(cfg.FLOWS_FILE), exist_ok=True)

    # Drop the legacy learn-mode flag if present from a pre-upgrade install.
    try:
        os.unlink(os.path.join(cfg.DATA_DIR, "learn"))
    except FileNotFoundError:
        pass

    goflow = subprocess.Popen([
        GOFLOW2_BIN,
        f"-listen={GOFLOW2_LISTEN}",
        "-format=json",
        f"-transport.file={cfg.FLOWS_FILE}",
    ])
    print(f"[netmon] goflow2 pid={goflow.pid}", file=sys.stderr)

    stop = threading.Event()
    received_signal = threading.Event()

    def handle_signal(signum, _frame):
        print(f"[netmon] received signal {signum}", file=sys.stderr)
        received_signal.set()
        stop.set()

    def handle_sighup(_signum, _frame):
        # Forward to goflow2 so it closes+reopens its output file (logrotate hook).
        print("[netmon] forwarding SIGHUP to goflow2", file=sys.stderr)
        try:
            goflow.send_signal(signal.SIGHUP)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGHUP, handle_sighup)

    threads = []
    for name, fn in (("ti-updater", ti_updater.loop_forever),
                     ("flow-analyzer", flow_analyzer.loop_forever),
                     ("daily-summary", daily_summary.loop_forever),
                     ("web-server", web_server.loop_forever),
                     ("rotator", make_rotate_loop(goflow))):
        t = threading.Thread(
            target=thread_runner, args=(name, fn, stop), name=name, daemon=True,
        )
        t.start()
        threads.append((name, t))
        print(f"[netmon] {name} thread started", file=sys.stderr)

    while not stop.is_set():
        if goflow.poll() is not None:
            print(f"[netmon] goflow2 exited (status={goflow.returncode})", file=sys.stderr)
            stop.set()
            break
        time.sleep(2)

    print("[netmon] shutting down", file=sys.stderr)
    if goflow.poll() is None:
        goflow.terminate()
        try:
            goflow.wait(timeout=10)
        except subprocess.TimeoutExpired:
            goflow.kill()
            goflow.wait()

    for name, t in threads:
        t.join(timeout=5)
        if t.is_alive():
            print(f"[netmon] {name} thread did not exit within 5s", file=sys.stderr)

    # Exit 0 on graceful shutdown (signal received). If goflow2 died on its own,
    # propagate a non-zero status so docker restart-policy kicks in.
    if received_signal.is_set():
        sys.exit(0)
    sys.exit(goflow.returncode if goflow.returncode else 1)


if __name__ == "__main__":
    main()
