"""Tests for web_server.py."""
import json
import os
import socket
import threading
import urllib.parse
import urllib.request

import pytest

import config
import web_server
from test_fakes import write_alerts, write_metrics_db_file


# --- parse_listen ----------------------------------------------------------

def test_parse_listen_host_port():
    assert web_server.parse_listen("1.2.3.4:8080") == ("1.2.3.4", 8080)


def test_parse_listen_default_host():
    assert web_server.parse_listen(":8080") == ("0.0.0.0", 8080)


def test_parse_listen_bare_port_only():
    assert web_server.parse_listen("49210") == ("0.0.0.0", 49210)


def test_parse_listen_non_digit_raises():
    with pytest.raises(ValueError):
        web_server.parse_listen("host:abc")


# --- _ip_sort_key -----------------------------------------------------------

def test_ip_sort_key_v4_numeric():
    # 10.0.0.2 sorts after 10.0.0.1 numerically
    k1 = web_server._ip_sort_key("10.0.0.1")
    k2 = web_server._ip_sort_key("10.0.0.2")
    assert k1 < k2


def test_ip_sort_key_invalid_sorts_last():
    k_valid = web_server._ip_sort_key("10.0.0.1")
    k_invalid = web_server._ip_sort_key("not-an-ip")
    assert k_valid < k_invalid


def test_ip_sort_key_v4_before_v6():
    assert web_server._ip_sort_key("9.9.9.9") < web_server._ip_sort_key("2001:db8::1")


# --- _qs_str / _qs_int -----------------------------------------------------

def _qs(s):
    return urllib.parse.parse_qs(s)


def test_qs_str_present():
    assert web_server._qs_str(_qs("device=10.0.0.1"), "device") == "10.0.0.1"


def test_qs_str_missing_default():
    assert web_server._qs_str(_qs(""), "device", "def") == "def"


def test_qs_int_present():
    assert web_server._qs_int(_qs("days=7"), "days", 1) == 7


def test_qs_int_malformed_default():
    assert web_server._qs_int(_qs("days=abc"), "days", 5) == 5


def test_qs_int_missing_default():
    assert web_server._qs_int(_qs(""), "days", 3) == 3


# --- load_index_html -------------------------------------------------------

def test_load_index_html(tmp_path, monkeypatch):
    f = tmp_path / "index.html"
    f.write_bytes(b"<html>hi</html>")
    monkeypatch.setattr(web_server, "INDEX_HTML_PATH", str(f))
    assert web_server.load_index_html() == b"<html>hi</html>"


# --- load_hostname_map -----------------------------------------------------

def _write_hosts(content):
    with open(os.path.join(config.DATA_DIR, "hosts"), "w") as f:
        f.write(content)


def test_load_hostname_map_parses(tmp_path):
    _write_hosts("# a comment\n192.168.1.10 kitchen-tv\n10.0.0.1 nas\n")
    m = web_server.load_hostname_map()
    assert m == {"192.168.1.10": "kitchen-tv", "10.0.0.1": "nas"}


def test_load_hostname_map_missing_returns_empty():
    assert web_server.load_hostname_map() == {}


def test_load_hostname_map_caches_on_mtime(tmp_path):
    _write_hosts("192.168.1.10 kitchen-tv\n")
    first = web_server.load_hostname_map()
    # second call without mtime change returns the same cached object
    second = web_server.load_hostname_map()
    assert second == first


def test_load_hostname_map_clears_when_file_removed(tmp_path):
    _write_hosts("192.168.1.10 kitchen-tv\n")
    web_server.load_hostname_map()
    os.remove(os.path.join(config.DATA_DIR, "hosts"))
    assert web_server.load_hostname_map() == {}


# --- resolve_hostnames / _resolve_blocking ---------------------------------

def test_resolve_blocking_trims_trailing_dot(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyaddr",
                        lambda ip: ("host.example.com.", [], [ip]))
    assert web_server._resolve_blocking("8.8.8.8") == "host.example.com"


def test_resolve_blocking_failure_returns_none(monkeypatch):
    def raise_(ip):
        raise socket.herror("nope")
    monkeypatch.setattr(socket, "gethostbyaddr", raise_)
    assert web_server._resolve_blocking("8.8.8.8") is None


def test_resolve_hostnames_static_map_wins(tmp_path):
    _write_hosts("8.8.8.8 dns.google\n")
    out = web_server.resolve_hostnames(["8.8.8.8"])
    assert out["8.8.8.8"] == "dns.google"


def test_resolve_hostnames_cache_hit(monkeypatch):
    # First call resolves via the pool; second should hit the cache without
    # calling gethostbyaddr again.
    calls = []

    def fake_get(ip):
        calls.append(ip)
        return ("resolved.example.com", [], [ip])
    monkeypatch.setattr(socket, "gethostbyaddr", fake_get)
    web_server.resolve_hostnames(["1.2.3.4"])
    web_server.resolve_hostnames(["1.2.3.4"])
    assert len(calls) == 1  # cached, not re-resolved


# --- api_health ------------------------------------------------------------

def test_api_health_no_state_no_ti(tmp_path):
    h = web_server.api_health()
    assert h["ok"] is True
    assert h["last_state_write_ts"] is None
    assert h["ti_feeds"] == []


def test_api_health_with_state_and_ti(tmp_path):
    # write state.json to set mtime
    with open(config.STATE_FILE, "w") as f:
        f.write("{}")
    # build a ti.db with meta rows
    import sqlite3
    import ti_updater
    con = sqlite3.connect(config.TI_DB)
    ti_updater.init_db(con)
    con.execute("INSERT INTO ti_meta (source, last_fetch_ts, row_count, ok, note) "
                "VALUES ('spamhaus-drop', 100, 5, 1, NULL)")
    con.execute("INSERT INTO ti_meta (source, last_fetch_ts, row_count, ok, note) "
                "VALUES ('tor-exit', 200, 3, 0, 'fail')")
    con.commit(); con.close()
    h = web_server.api_health()
    assert h["last_state_write_ts"] is not None
    feeds = {f["source"]: f for f in h["ti_feeds"]}
    assert feeds["spamhaus-drop"]["ok"] is True
    assert feeds["spamhaus-drop"]["rows"] == 5
    assert feeds["tor-exit"]["ok"] is False


# --- _country_breakdown / _asn_breakdown -----------------------------------

def _today():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).date()


def _metrics_rows():
    today = _today().isoformat()
    return [
        (today, "10.0.0.1", "US", 15169, "Google", 10, 1000, 100),
        (today, "10.0.0.1", "DE", 12345, "Telco", 5, 500, 50),
        (today, "10.0.0.2", "US", 15169, "Google", 3, 200, 20),
    ]


def test_country_breakdown_global(tmp_path):
    write_metrics_db_file(config.METRICS_DB, _metrics_rows())
    con = web_server.open_metrics_ro()
    today = _today()
    out = web_server._country_breakdown(con, today, today, None)
    con.close()
    # ordered by SUM(bytes) desc: US (1000+200=1200) then DE (500)
    assert out[0]["country"] == "US"
    assert out[0]["bytes"] == 1200
    assert out[1]["country"] == "DE"


def test_country_breakdown_device_filter(tmp_path):
    write_metrics_db_file(config.METRICS_DB, _metrics_rows())
    con = web_server.open_metrics_ro()
    today = _today()
    out = web_server._country_breakdown(con, today, today, "10.0.0.1")
    con.close()
    countries = {c["country"] for c in out}
    assert countries == {"US", "DE"}


def test_asn_breakdown_global(tmp_path):
    write_metrics_db_file(config.METRICS_DB, _metrics_rows())
    con = web_server.open_metrics_ro()
    today = _today()
    out = web_server._asn_breakdown(con, today, today, None)
    con.close()
    asns = {a["asn"]: a for a in out}
    assert asns[15169]["bytes"] == 1200
    assert asns[15169]["asn_org"] == "Google"


# --- api_devices / api_summary / api_timeseries / api_alerts ----------------

def test_api_devices_empty_when_no_metrics(tmp_path):
    assert web_server.api_devices({}) == {"devices": []}


def test_api_devices_returns_sorted(tmp_path, monkeypatch):
    write_metrics_db_file(config.METRICS_DB, _metrics_rows())
    # avoid real DNS in the test
    monkeypatch.setattr(web_server, "resolve_hostnames", lambda ips: {})
    out = web_server.api_devices({})
    ips = [d["ip"] for d in out["devices"]]
    assert "10.0.0.1" in ips
    assert "10.0.0.2" in ips
    # sorted by _ip_sort_key
    assert ips == sorted(ips, key=web_server._ip_sort_key)


def test_api_summary_no_metrics(tmp_path, monkeypatch):
    monkeypatch.setattr(web_server, "daily_summary", __import__("daily_summary"))
    out = web_server.api_summary({"days": ["1"]})
    assert out["totals"]["flows"] == 0
    assert out["totals"]["ti_hits"] == 0
    assert out["countries"] == []
    assert out["asns"] == []


def test_api_summary_with_metrics_and_alerts(tmp_path, monkeypatch):
    import time
    write_metrics_db_file(config.METRICS_DB, _metrics_rows())
    write_alerts(config.ALERTS_FILE, [
        {"ts": int(time.time()) - 100, "kind": "ti-match", "internal_ip": "10.0.0.1",
         "dst_ip": "8.8.8.8", "sources": "x", "bytes": 100, "severity": "high",
         "asn": 15169, "asn_org": "Google", "country": "US"},
    ])
    out = web_server.api_summary({"days": ["30"]})
    assert out["totals"]["flows"] >= 1
    assert out["totals"]["ti_hits"] == 1


def test_api_timeseries_fills_missing_days(tmp_path):
    write_metrics_db_file(config.METRICS_DB, [
        ("2024-01-01", "10.0.0.1", "US", 15169, "Google", 1, 10, 1),
    ])
    out = web_server.api_timeseries({"days": ["3"]})
    # 3 buckets, only one has data, rest zero-filled
    assert len(out["buckets"]) == 3
    flows = {b["date"]: b["flows"] for b in out["buckets"]}
    assert 0 in flows.values()  # some zero-filled


def test_api_alerts_filters(tmp_path):
    recs = [
        {"ts": 100, "kind": "ti-match", "internal_ip": "10.0.0.1", "dst_ip": "1.1.1.1"},
        {"ts": 200, "kind": "new-asn", "internal_ip": "10.0.0.2", "dst_ip": "2.2.2.2"},
        {"ts": 300, "kind": "ti-match", "internal_ip": "10.0.0.1", "dst_ip": "3.3.3.3"},
    ]
    write_alerts(config.ALERTS_FILE, recs)
    # days=1 window with end_ts far in future: monkeypatch time? api_alerts uses
    # time.time(). Easier: set a huge days window.
    out = web_server.api_alerts({"days": ["100000"], "kind": ["ti-match"]})
    kinds = {a["kind"] for a in out["alerts"]}
    assert kinds == {"ti-match"}
    assert len(out["alerts"]) == 2


def test_api_alerts_device_filter(tmp_path):
    write_alerts(config.ALERTS_FILE, [
        {"ts": 100, "kind": "ti-match", "internal_ip": "10.0.0.1", "dst_ip": "1.1.1.1"},
        {"ts": 200, "kind": "ti-match", "internal_ip": "10.0.0.2", "dst_ip": "2.2.2.2"},
    ])
    out = web_server.api_alerts({"days": ["100000"], "device": ["10.0.0.1"]})
    assert len(out["alerts"]) == 1
    assert out["alerts"][0]["internal_ip"] == "10.0.0.1"


def test_api_alerts_limit_and_truncation(tmp_path):
    recs = [{"ts": i, "kind": "ti-match", "internal_ip": "10.0.0.1",
             "dst_ip": f"1.1.1.{i % 255}"} for i in range(10)]
    write_alerts(config.ALERTS_FILE, recs)
    out = web_server.api_alerts({"days": ["100000"], "limit": ["3"]})
    assert len(out["alerts"]) == 3
    assert out["truncated"] is True
    # sorted desc by ts -> last 3 (ts 9,8,7)
    assert out["alerts"][0]["ts"] == 9


def test_api_alerts_malformed_json_skipped(tmp_path):
    with open(config.ALERTS_FILE, "w") as f:
        f.write(json.dumps({"ts": 100, "kind": "ti-match",
                            "internal_ip": "10.0.0.1", "dst_ip": "1.1.1.1"}) + "\n")
        f.write("not json\n")
    out = web_server.api_alerts({"days": ["100000"]})
    assert len(out["alerts"]) == 1


# --- Handler routing via a real server on an ephemeral port -----------------

def _start_server(monkeypatch):
    """Start the web server on an ephemeral port using cfg paths (already
    redirected to tmp_path by cfg_paths). Returns (base_url, stop_event)."""
    # Pick a free port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    monkeypatch.setattr(web_server, "LISTEN", f"127.0.0.1:{port}")
    stop = threading.Event()
    # Serve the repo's real index.html (sits alongside this test file at the
    # repo root, same dir as web_server.py).
    repo_index = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "index.html")
    monkeypatch.setattr(web_server, "INDEX_HTML_PATH", repo_index)
    t = threading.Thread(target=web_server.loop_forever, args=(stop,), daemon=True)
    t.start()
    # wait for the port to accept connections
    import time as _time
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            s.close()
            break
        except OSError:
            _time.sleep(0.02)
    return f"http://127.0.0.1:{port}", stop, t


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=5) as r:
        return r.status, r.read()


def test_handler_serves_index_html(monkeypatch):
    base, stop, t = _start_server(monkeypatch)
    try:
        status, body = _get(base, "/")
        assert status == 200
        assert b"<html" in body.lower() or b"<!doctype" in body.lower()
    finally:
        stop.set()
        t.join(timeout=5)


def test_handler_api_health(monkeypatch):
    base, stop, t = _start_server(monkeypatch)
    try:
        status, body = _get(base, "/api/health")
        assert status == 200
        data = json.loads(body)
        assert data["ok"] is True
    finally:
        stop.set()
        t.join(timeout=5)


def test_handler_api_devices(monkeypatch):
    base, stop, t = _start_server(monkeypatch)
    monkeypatch.setattr(web_server, "resolve_hostnames", lambda ips: {})
    try:
        status, body = _get(base, "/api/devices")
        assert status == 200
        assert "devices" in json.loads(body)
    finally:
        stop.set()
        t.join(timeout=5)


def test_handler_404(monkeypatch):
    base, stop, t = _start_server(monkeypatch)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(base + "/nope", timeout=5)
        assert exc.value.code == 404
    finally:
        stop.set()
        t.join(timeout=5)


def test_handler_500_on_exception(monkeypatch):
    base, stop, t = _start_server(monkeypatch)
    monkeypatch.setattr(web_server, "api_health", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(base + "/api/health", timeout=5)
        assert exc.value.code == 500
    finally:
        stop.set()
        t.join(timeout=5)


# --- main(--once) ----------------------------------------------------------

def test_main_once_prints_summary(monkeypatch, capsys):
    monkeypatch.setattr(web_server, "api_summary",
                        lambda qs: {"totals": {"flows": 42}})
    monkeypatch.setattr("sys.argv", ["web_server.py", "--once"])
    web_server.main()
    out = capsys.readouterr().out
    assert "42" in out