"""Tests for the netmon orchestrator's rotator and thread helpers.

The orchestrator is `netmon.py`; it is imported via the `netmon_mod` session
fixture. `main()` itself spawns goflow2 and binds signals; it is exercised with
heavy mocking.
"""
import os
import signal
import threading
import time

import pytest

import config


pytestmark = pytest.mark.usefixtures("netmon_mod")


def test_maintain_archives_prunes_oldest(netmon_mod, tmp_path):
    # set FLOWS_FILE under the tmp data dir (cfg_paths already points
    # cfg.FEOIP etc there) and create more archives than FLOWS_RETAIN
    flows = config.FLOWS_FILE
    retain = netmon_mod.FLOWS_RETAIN
    # create retain+2 archives with increasing mtime
    archives = []
    for i in range(retain + 2):
        p = f"{flows}.archived.2024010{i}T000000Z"
        with open(p, "w") as f:
            f.write("x")
        os.utime(p, (i, i))  # older = smaller mtime
        archives.append(p)
    netmon_mod.maintain_archives()
    remaining = [a for a in archives if os.path.exists(a)]
    assert len(remaining) == retain
    # the oldest (lowest mtime) should have been pruned
    assert not os.path.exists(archives[0])


def test_maintain_archives_noop_when_under_retain(netmon_mod):
    flows = config.FLOWS_FILE
    for i in range(netmon_mod.FLOWS_RETAIN):
        with open(f"{flows}.archived.2024010{i}T000000Z", "w") as f:
            f.write("x")
    netmon_mod.maintain_archives()  # should not raise or remove anything
    import glob
    assert len(glob.glob(netmon_mod._archive_glob())) == netmon_mod.FLOWS_RETAIN


def test_maintain_archives_swallows_oserror(netmon_mod, monkeypatch):
    flows = config.FLOWS_FILE
    retain = netmon_mod.FLOWS_RETAIN
    for i in range(retain + 1):
        with open(f"{flows}.archived.2024010{i}T000000Z", "w") as f:
            f.write("x")
    # force os.remove to fail
    real_remove = os.remove

    def fail_remove(path):
        raise OSError("perm denied")
    monkeypatch.setattr(os, "remove", fail_remove)
    # should not raise
    netmon_mod.maintain_archives()


def test_maybe_rotate_flows_first_run_creates_sentinel(netmon_mod, monkeypatch):
    # no sentinel yet -> creates it and returns
    sentinel = netmon_mod._rotate_sentinel()
    assert not os.path.exists(sentinel)
    goflow = type("G", (), {"signals": []})()
    goflow.send_signal = lambda s: goflow.signals.append(s)
    netmon_mod.maybe_rotate_flows(goflow)
    assert os.path.exists(sentinel)
    assert goflow.signals == []  # no SIGHUP on first run


def test_maybe_rotate_flows_within_interval_noop(netmon_mod):
    sentinel = netmon_mod._rotate_sentinel()
    open(sentinel, "a").close()
    os.utime(sentinel, (time.time(), time.time()))  # just touched
    goflow = type("G", (), {"signals": []})()
    goflow.send_signal = lambda s: goflow.signals.append(s)
    # write a non-empty flows file
    with open(config.FLOWS_FILE, "w") as f:
        f.write("data")
    netmon_mod.maybe_rotate_flows(goflow)
    assert goflow.signals == []
    assert os.path.exists(config.FLOWS_FILE)  # not rotated


def test_maybe_rotate_flows_missing_file_returns(netmon_mod):
    sentinel = netmon_mod._rotate_sentinel()
    open(sentinel, "a").close()
    # age the sentinel past the interval
    old = time.time() - netmon_mod.FLOWS_ROTATE_SEC - 10
    os.utime(sentinel, (old, old))
    # no flows file exists
    goflow = type("G", (), {"signals": []})()
    goflow.send_signal = lambda s: goflow.signals.append(s)
    netmon_mod.maybe_rotate_flows(goflow)  # should not raise
    assert goflow.signals == []


def test_maybe_rotate_flows_empty_file_touches_sentinel(netmon_mod):
    sentinel = netmon_mod._rotate_sentinel()
    open(sentinel, "a").close()
    old = time.time() - netmon_mod.FLOWS_ROTATE_SEC - 10
    os.utime(sentinel, (old, old))
    open(config.FLOWS_FILE, "w").close()  # empty flows file
    goflow = type("G", (), {"signals": []})()
    goflow.send_signal = lambda s: goflow.signals.append(s)
    netmon_mod.maybe_rotate_flows(goflow)
    assert goflow.signals == []  # empty -> no rotation
    # sentinel mtime was refreshed (now recent)
    assert os.path.getmtime(sentinel) > old


def test_maybe_rotate_flows_rotates_and_sighups(netmon_mod):
    sentinel = netmon_mod._rotate_sentinel()
    open(sentinel, "a").close()
    old = time.time() - netmon_mod.FLOWS_ROTATE_SEC - 10
    os.utime(sentinel, (old, old))
    with open(config.FLOWS_FILE, "w") as f:
        f.write("flowdata\n")
    goflow = type("G", (), {"signals": []})()
    goflow.send_signal = lambda s: goflow.signals.append(s)
    netmon_mod.maybe_rotate_flows(goflow)
    assert goflow.signals == [signal.SIGHUP]
    # flows file was renamed away (new archive exists)
    assert not os.path.exists(config.FLOWS_FILE)
    import glob
    archives = glob.glob(netmon_mod._archive_glob())
    assert len(archives) == 1
    # sentinel refreshed
    assert os.path.getmtime(sentinel) > old


def test_maybe_rotate_flows_process_lookup_swallowed(netmon_mod):
    sentinel = netmon_mod._rotate_sentinel()
    open(sentinel, "a").close()
    old = time.time() - netmon_mod.FLOWS_ROTATE_SEC - 10
    os.utime(sentinel, (old, old))
    with open(config.FLOWS_FILE, "w") as f:
        f.write("flowdata\n")

    class G:
        def send_signal(self, s):
            raise ProcessLookupError("no such process")
    netmon_mod.maybe_rotate_flows(G())  # should not raise


def test_make_rotate_loop_exits_on_stop(netmon_mod, monkeypatch):
    called = []
    monkeypatch.setattr(netmon_mod, "maybe_rotate_flows",
                        lambda g: called.append(1))
    goflow = object()
    stop = threading.Event()
    stop.set()
    loop = netmon_mod.make_rotate_loop(goflow)
    loop(stop)
    assert called == []  # never ticked because stop pre-set


def test_make_rotate_loop_ticks_until_stop(netmon_mod, monkeypatch):
    called = []
    monkeypatch.setattr(netmon_mod, "maybe_rotate_flows",
                        lambda g: called.append(1))
    monkeypatch.setattr(netmon_mod, "ROTATE_TICK_SEC", 0)
    goflow = object()
    stop = threading.Event()
    ticks = [0]

    def fake_wait(timeout):
        ticks[0] += 1
        if ticks[0] >= 2:
            stop.set()
        return False
    monkeypatch.setattr(stop, "wait", fake_wait)
    loop = netmon_mod.make_rotate_loop(goflow)
    loop(stop)
    assert len(called) >= 1


def test_thread_runner_normal_completion(netmon_mod):
    stop = threading.Event()
    netmon_mod.thread_runner("x", lambda ev: None, stop)
    assert not stop.is_set()  # no crash -> stop not set


def test_thread_runner_crash_sets_stop(netmon_mod, capsys):
    stop = threading.Event()

    def boom(ev):
        raise RuntimeError("crashed")
    netmon_mod.thread_runner("x", boom, stop)
    assert stop.is_set()
    assert "crashed" in capsys.readouterr().err


def test_main_runs_and_shuts_down(netmon_mod, monkeypatch, tmp_path):
    """Light integration: mock goflow2, signals, and the four loop_forever
    functions so main() starts threads then exits when stop is set."""
    import subprocess

    class FakePopen:
        pid = 1234
        returncode = None

        def __init__(self, *a, **k):
            pass

        def poll(self):
            return None  # goflow2 stays alive

        def terminate(self):
            self.returncode = 0

        def wait(self, timeout=None):
            return 0

        def send_signal(self, sig):
            pass

    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    monkeypatch.setattr(signal, "signal", lambda *a, **k: None)
    # make the loop_forever functions set+wait on a stop event that we trip
    started = threading.Event()

    def fake_loop(ev):
        started.set()
        # block until the test signals shutdown by setting the event from main
        ev.wait(5)

    for mod in ("flow_analyzer", "ti_updater", "daily_summary", "web_server"):
        m = __import__(mod)
        monkeypatch.setattr(m, "loop_forever", fake_loop)
    # make_rotate_loop uses maybe_rotate_flows; patch to no-op and a fast tick
    monkeypatch.setattr(netmon_mod, "ROTATE_TICK_SEC", 0)
    monkeypatch.setattr(netmon_mod, "maybe_rotate_flows", lambda g: None)

    # main() polls goflow.poll() every 2s then exits; force a quick exit by
    # having Popen.poll return non-zero after the first call.
    poll_calls = [0]

    class FakePopenDie(FakePopen):
        def poll(self):
            poll_calls[0] += 1
            if poll_calls[0] >= 1:
                self.returncode = 0
                return 0
            return None
    monkeypatch.setattr(subprocess, "Popen", FakePopenDie)
    # speed up the watch sleep
    monkeypatch.setattr(time, "sleep", lambda s: None)

    with pytest.raises(SystemExit):
        netmon_mod.main()
    # goflow2 "died" on its own (no signal) -> non-zero exit propagated
    # (returncode 0 -> main exits 1 per the fallback)
    assert started.is_set()