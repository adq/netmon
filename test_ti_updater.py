"""Tests for ti_updater.py."""
import ipaddress
import os
import sqlite3
import subprocess
import urllib.error

import pytest

import config
import ti_updater


# --- fetch ------------------------------------------------------------------

class _FakeResp:
    def __init__(self, status, body=b"ok", raise_on_read=False):
        self.status = status
        self._body = body
        self._raise = raise_on_read

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        if self._raise:
            raise OSError("read failed")
        return self._body


def test_fetch_success(monkeypatch):
    monkeypatch.setattr(ti_updater.urllib.request, "urlopen",
                        lambda req, timeout=60: _FakeResp(200, b"hello"))
    assert ti_updater.fetch("http://x") == "hello"


def test_fetch_non_200_raises(monkeypatch):
    monkeypatch.setattr(ti_updater.urllib.request, "urlopen",
                        lambda req, timeout=60: _FakeResp(404))
    with pytest.raises(RuntimeError, match="HTTP 404"):
        ti_updater.fetch("http://x")


def test_fetch_propagates_timeout(monkeypatch):
    def raise_timeout(req, timeout=60):
        raise urllib.error.URLError("timeout")
    monkeypatch.setattr(ti_updater.urllib.request, "urlopen", raise_timeout)
    with pytest.raises(urllib.error.URLError):
        ti_updater.fetch("http://x")


# --- parse_comment_stripped -------------------------------------------------

def test_parse_comment_stripped_spamhaus_style():
    text = """; Spamhaus DROP
1.2.3.0/24 ; comment
5.6.7.8/32
# a hash comment
"""
    nets = ti_updater.parse_comment_stripped(text)
    addrs = [str(n) for n in nets]
    assert "1.2.3.0/24" in addrs
    assert "5.6.7.8/32" in addrs


def test_parse_comment_stripped_ipsum_tab_format():
    # ipsum lines look like "ip\tcount" — only the first token is the ip
    text = "8.8.8.8\t123\n9.9.9.9\t45\n"
    nets = ti_updater.parse_comment_stripped(text)
    assert {str(n) for n in nets} == {"8.8.8.8/32", "9.9.9.9/32"}


def test_parse_comment_stripped_skips_ipv6():
    text = "::1\n2001:db8::/32\n1.2.3.4/32\n"
    nets = ti_updater.parse_comment_stripped(text)
    assert [str(n) for n in nets] == ["1.2.3.4/32"]


def test_parse_comment_stripped_skips_blank_and_garbage():
    text = "\n\nnot-an-ip\n1.2.3.4/30\n"
    nets = ti_updater.parse_comment_stripped(text)
    assert [str(n) for n in nets] == ["1.2.3.4/30"]


def test_parse_comment_stripped_empty():
    assert ti_updater.parse_comment_stripped("") == []


# --- init_db / insert_rows -------------------------------------------------

def test_init_db_idempotent():
    con = sqlite3.connect(":memory:")
    ti_updater.init_db(con)
    ti_updater.init_db(con)
    tabs = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"ti_indicators", "ti_meta"} <= tabs


def test_insert_rows_counts_and_family():
    con = sqlite3.connect(":memory:")
    ti_updater.init_db(con)
    nets = [ipaddress.ip_network("8.8.8.0/24"), ipaddress.ip_network("1.2.3.4/32")]
    n = ti_updater.insert_rows(con, "test", "high", nets, 100)
    assert n == 2
    rows = con.execute("SELECT cidr_start, cidr_end, family, source, severity "
                       "FROM ti_indicators ORDER BY cidr_start").fetchall()
    # 1.2.3.4 int (16909060) < 8.8.8.0 int (134744064), so it sorts first
    assert all(r[2] == 4 for r in rows)  # family is IPv4
    assert all(r[3] == "test" for r in rows)
    assert all(r[4] == "high" for r in rows)
    starts = {r[0] for r in rows}
    assert int(ipaddress.ip_address("8.8.8.0")) in starts
    assert int(ipaddress.ip_address("1.2.3.4")) in starts


def test_insert_rows_empty():
    con = sqlite3.connect(":memory:")
    ti_updater.init_db(con)
    assert ti_updater.insert_rows(con, "x", "low", [], 100) == 0


# --- carry_forward ---------------------------------------------------------

def _make_old_db(path, source, count):
    con = sqlite3.connect(path)
    ti_updater.init_db(con)
    nets = [ipaddress.ip_network(f"10.0.0.{i}/32") for i in range(1, count + 1)]
    ti_updater.insert_rows(con, source, "high", nets, 100)
    con.commit()
    con.close()


def test_carry_forward_copies_rows(tmp_path):
    old = str(tmp_path / "old.db")
    _make_old_db(old, "feed-x", 3)
    new = sqlite3.connect(":memory:")
    ti_updater.init_db(new)
    assert ti_updater.carry_forward(new, old, "feed-x") == 3
    assert new.execute("SELECT COUNT(*) FROM ti_indicators").fetchone()[0] == 3


def test_carry_forward_missing_old_returns_zero():
    new = sqlite3.connect(":memory:")
    ti_updater.init_db(new)
    assert ti_updater.carry_forward(new, "/no/such/old.db", "feed-x") == 0


def test_carry_forward_empty_rows_returns_zero(tmp_path):
    old = str(tmp_path / "old.db")
    con = sqlite3.connect(old)
    ti_updater.init_db(con)
    con.commit(); con.close()
    new = sqlite3.connect(":memory:")
    ti_updater.init_db(new)
    assert ti_updater.carry_forward(new, old, "feed-x") == 0


def test_carry_forward_corrupt_old_returns_zero(tmp_path):
    old = str(tmp_path / "old.db")
    with open(old, "w") as f:
        f.write("not a database")
    new = sqlite3.connect(":memory:")
    ti_updater.init_db(new)
    assert ti_updater.carry_forward(new, old, "feed-x") == 0


# --- update_geoip ----------------------------------------------------------

def test_update_geoip_no_creds_skips(monkeypatch):
    monkeypatch.delenv("MAXMIND_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("MAXMIND_LICENSE_KEY", raising=False)
    # Should not create GeoIP.conf
    ti_updater.update_geoip()
    assert not os.path.exists(os.path.join(config.GEOIP_DIR, "GeoIP.conf"))


def test_update_geoip_writes_conf_and_runs(monkeypatch):
    monkeypatch.setattr(ti_updater.os, "environ",
                        {**os.environ, "MAXMIND_ACCOUNT_ID": "123",
                         "MAXMIND_LICENSE_KEY": "secret"})
    called = []
    monkeypatch.setattr(ti_updater.subprocess, "check_call",
                        lambda args: called.append(args))
    ti_updater.update_geoip()
    cfg_path = os.path.join(config.GEOIP_DIR, "GeoIP.conf")
    assert os.path.exists(cfg_path)
    content = open(cfg_path).read()
    assert "AccountID 123" in content
    assert "LicenseKey secret" in content
    assert "GeoLite2-Country GeoLite2-ASN" in content
    assert "DatabaseDirectory" in content
    # 0o600 permissions
    assert (os.stat(cfg_path).st_mode & 0o777) == 0o600
    assert called and called[0][0] == "geoipupdate"


def test_update_geoip_missing_binary_swallowed(monkeypatch):
    monkeypatch.setattr(ti_updater.os, "environ",
                        {**os.environ, "MAXMIND_ACCOUNT_ID": "123",
                         "MAXMIND_LICENSE_KEY": "secret"})
    def raise_fnf(args):
        raise FileNotFoundError("no geoipupdate")
    monkeypatch.setattr(ti_updater.subprocess, "check_call", raise_fnf)
    # should not raise
    ti_updater.update_geoip()


def test_update_geoip_called_process_error_swallowed(monkeypatch):
    monkeypatch.setattr(ti_updater.os, "environ",
                        {**os.environ, "MAXMIND_ACCOUNT_ID": "123",
                         "MAXMIND_LICENSE_KEY": "secret"})
    def raise_cpe(args):
        raise subprocess.CalledProcessError(1, args)
    monkeypatch.setattr(ti_updater.subprocess, "check_call", raise_cpe)
    ti_updater.update_geoip()  # no raise


# --- run_once (integration) ------------------------------------------------

def _fake_fetch_returning(per_source):
    """Return a fetch replacement that maps url->body via source name."""
    def fake_fetch(url, timeout=60):
        for src, body in per_source.items():
            # match by source url: just return the body for whichever source
            # url is requested, keyed by the source's url
            if url in per_source:
                return per_source[url]
        return ""
    return fake_fetch


def test_run_once_atomic_swap_and_meta(monkeypatch):
    feed_bodies = {f["url"]: "1.2.3.0/24\n5.6.7.8/32\n" for f in ti_updater.FEEDS}
    monkeypatch.setattr(ti_updater, "fetch", lambda url, timeout=60: feed_bodies[url])
    monkeypatch.setattr(ti_updater, "update_geoip", lambda: None)

    ti_updater.run_once()

    assert os.path.exists(config.TI_DB)
    assert not os.path.exists(config.TI_DB + ".tmp")  # tmp renamed away
    assert os.path.exists(config.TI_DB + ".bak") is False  # no prior ti.db -> no bak
    con = sqlite3.connect(f"file:{config.TI_DB}?mode=ro", uri=True)
    rows = con.execute("SELECT source, ok, row_count FROM ti_meta ORDER BY source").fetchall()
    assert all(ok == 1 for _, ok, _ in rows)
    assert len(rows) == len(ti_updater.FEEDS)
    con.close()


def test_run_once_bak_retained_on_second_run(monkeypatch):
    feed_bodies = {f["url"]: "1.2.3.0/24\n" for f in ti_updater.FEEDS}
    monkeypatch.setattr(ti_updater, "fetch", lambda url, timeout=60: feed_bodies[url])
    monkeypatch.setattr(ti_updater, "update_geoip", lambda: None)
    ti_updater.run_once()
    ti_updater.run_once()
    assert os.path.exists(config.TI_DB + ".bak")  # retained from first run


def test_run_once_partial_failure_carries_forward(monkeypatch):
    # First run: populate ti.db with all feeds.
    feed_bodies = {f["url"]: "10.0.0.0/8\n" for f in ti_updater.FEEDS}
    monkeypatch.setattr(ti_updater, "fetch", lambda url, timeout=60: feed_bodies[url])
    monkeypatch.setattr(ti_updater, "update_geoip", lambda: None)
    ti_updater.run_once()

    # Second run: every feed "fails" (0 networks -> RuntimeError parsed 0 networks)
    # -> carry_forward copies stale rows from the existing ti.db.
    def failing_fetch(url, timeout=60):
        raise RuntimeError("network down")
    monkeypatch.setattr(ti_updater, "fetch", failing_fetch)
    with pytest.raises(RuntimeError, match="all threat-intel feeds failed"):
        ti_updater.run_once()
    # despite all-fail, carry_forward kept rows + .bak retained
    con = sqlite3.connect(f"file:{config.TI_DB}?mode=ro", uri=True)
    meta = {row[0]: (row[1], row[2])
            for row in con.execute("SELECT source, ok, row_count FROM ti_meta").fetchall()}
    con.close()
    # all feeds marked not-ok but kept their stale rows
    assert all(ok == 0 for ok, _ in meta.values())
    assert sum(rc for _, rc in meta.values()) > 0


def test_run_once_missing_flows_no_state_required(monkeypatch):
    # run_once creates DATA_DIR; with empty feeds it still builds ti.db
    feed_bodies = {f["url"]: "203.0.113.0/24\n" for f in ti_updater.FEEDS}
    monkeypatch.setattr(ti_updater, "fetch", lambda url, timeout=60: feed_bodies[url])
    monkeypatch.setattr(ti_updater, "update_geoip", lambda: None)
    ti_updater.run_once()
    assert os.path.isdir(config.DATA_DIR)


# --- FEEDS / PARSERS consistency --------------------------------------------

def test_every_feed_parser_is_registered():
    for feed in ti_updater.FEEDS:
        assert feed["parser"] in ti_updater.PARSERS


def test_feeds_have_required_fields():
    for feed in ti_updater.FEEDS:
        assert {"source", "severity", "url", "parser"} <= set(feed)
        assert feed["severity"] in ("low", "medium", "high")


# --- loop_forever / main -----------------------------------------------------

def test_loop_forever_exits_when_stop_pre_set(monkeypatch):
    import threading
    called = []
    monkeypatch.setattr(ti_updater, "run_once", lambda: called.append(1))
    stop = threading.Event()
    stop.set()
    ti_updater.loop_forever(stop)
    assert called == []


def test_main_no_loop_runs_once(monkeypatch):
    monkeypatch.setattr(ti_updater, "run_once", lambda: None)
    monkeypatch.setattr("sys.argv", ["ti_updater.py"])
    ti_updater.main()


def test_main_no_loop_exits_nonzero_on_runtime_error(monkeypatch):
    monkeypatch.setattr(ti_updater, "run_once",
                        lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr("sys.argv", ["ti_updater.py"])
    with pytest.raises(SystemExit) as exc:
        ti_updater.main()
    assert exc.value.code == 1


def test_main_loop_dispatches(monkeypatch):
    import threading
    started = threading.Event()
    monkeypatch.setattr(ti_updater, "loop_forever", lambda ev: started.set())
    monkeypatch.setattr("sys.argv", ["ti_updater.py", "--loop"])
    ti_updater.main()
    assert started.is_set()