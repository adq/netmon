"""Tests for flow_analyzer.py — the core analyzer."""
import json
import os
import socket
import sqlite3

import pytest

import config
import flow_analyzer
from test_fakes import (
    FakeGeoIP,
    fake_goflow,
    flow,
    make_metrics_con,
    make_ti_con,
    make_ti_db_file,
    write_flows,
)


# --- is_private_addr --------------------------------------------------------

@pytest.mark.parametrize("addr", [
    "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
    "192.168.1.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0",
    "255.255.255.255", "::1", "::", "fc00::1", "fd00::1", "fe80::1", "ff00::1",
])
def test_is_private_addr_private(addr):
    assert flow_analyzer.is_private_addr(addr) is True


@pytest.mark.parametrize("addr", ["8.8.8.8", "1.1.1.1", "203.0.113.5",
                                  "2001:4860:4860::8888"])
def test_is_private_addr_public(addr):
    assert flow_analyzer.is_private_addr(addr) is False


@pytest.mark.parametrize("addr", ["garbage", None, "", "not-an-ip", 12345])
def test_is_private_addr_invalid_returns_true(addr):
    # invalid/unparseable addresses are treated as private (skip alerting)
    assert flow_analyzer.is_private_addr(addr) is True


# --- state IO ---------------------------------------------------------------

def test_empty_state_shape():
    s = flow_analyzer.empty_state()
    assert s == {"flow_cursor": None, "baseline_asn": {},
                 "baseline_country": {}, "alerts_sent": {}}


def test_load_state_missing_returns_empty(tmp_path):
    s = flow_analyzer.load_state(str(tmp_path / "nope.json"))
    assert s == flow_analyzer.empty_state()


def test_save_state_atomic_round_trip(tmp_path):
    path = str(tmp_path / "state.json")
    state = flow_analyzer.empty_state()
    state["baseline_asn"]["10.0.0.1"] = {"15169": {"first_seen": 1,
                                                   "last_seen": 2,
                                                   "flow_count": 3}}
    flow_analyzer.save_state(state, path)
    # no leftover .tmp on success
    assert not os.path.exists(path + ".tmp")
    assert flow_analyzer.load_state(path) == state


def test_append_alerts_ndjson(tmp_path):
    path = str(tmp_path / "alerts.jsonl")
    recs = [{"ts": 1, "kind": "ti-match"}, {"ts": 2, "kind": "new-asn"}]
    flow_analyzer.append_alerts(path, recs)
    flow_analyzer.append_alerts(path, [{"ts": 3, "kind": "new-country"}])
    with open(path) as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines == [recs[0], recs[1], {"ts": 3, "kind": "new-country"}]


# --- metrics db -------------------------------------------------------------

def test_init_metrics_db_idempotent():
    con = sqlite3.connect(":memory:")
    flow_analyzer.init_metrics_db(con)
    flow_analyzer.init_metrics_db(con)  # CREATE IF NOT EXISTS, no error
    tabs = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"country_daily", "asn_daily"} <= tabs


def test_flush_rollup_upsert_accumulates():
    con = make_metrics_con()
    country = {("2024-01-01", "10.0.0.1", "US"):
                {"flows": 2, "bytes": 100, "packets": 10}}
    flow_analyzer.flush_rollup(con, country, {})
    # second flush with same key accumulates
    country2 = {("2024-01-01", "10.0.0.1", "US"):
                {"flows": 3, "bytes": 50, "packets": 5}}
    flow_analyzer.flush_rollup(con, country2, {})
    row = con.execute("SELECT flows, bytes, packets FROM country_daily "
                      "WHERE date='2024-01-01' AND internal_ip='10.0.0.1' "
                      "AND country='US'").fetchone()
    assert row == (5, 150, 15)


def test_flush_rollup_asn_org_keep_nonempty():
    con = make_metrics_con()
    asn1 = {("2024-01-01", "10.0.0.1", 15169):
            {"asn_org": "Google", "flows": 1, "bytes": 10, "packets": 1}}
    flow_analyzer.flush_rollup(con, {}, asn1)
    # later flush with empty asn_org must NOT clobber the existing org
    asn2 = {("2024-01-01", "10.0.0.1", 15169):
            {"asn_org": "", "flows": 2, "bytes": 20, "packets": 2}}
    flow_analyzer.flush_rollup(con, {}, asn2)
    row = con.execute("SELECT asn_org, flows, bytes FROM asn_daily "
                      "WHERE date='2024-01-01' AND internal_ip='10.0.0.1' "
                      "AND asn=15169").fetchone()
    assert row == ("Google", 3, 30)


def test_flush_rollup_empty_noop():
    con = make_metrics_con()
    flow_analyzer.flush_rollup(con, {}, {})
    assert con.execute("SELECT COUNT(*) FROM country_daily").fetchone()[0] == 0


# --- get_cursor / save_cursor -----------------------------------------------

def _write_file(path, content):
    with open(path, "w") as f:
        f.write(content)
    return os.stat(path).st_ino, os.stat(path).st_size


def test_get_cursor_first_run_skips_backlog(tmp_path):
    path = str(tmp_path / "flows.jsonl")
    inode, size = _write_file(path, "line\n" * 10)
    state = flow_analyzer.empty_state()
    i, off, end, drain = flow_analyzer.get_cursor(state, path)
    assert i == inode
    assert off == size  # skip existing backlog
    assert end == size
    assert drain is None


def test_get_cursor_same_inode_resume(tmp_path):
    path = str(tmp_path / "flows.jsonl")
    _write_file(path, "aaaa\n")  # 5 bytes
    inode = os.stat(path).st_ino
    state = flow_analyzer.empty_state()
    flow_analyzer.save_cursor(state, inode, 3)
    # append more
    with open(path, "a") as f:
        f.write("bbbb\n")
    size = os.stat(path).st_size  # 10
    i, off, end, drain = flow_analyzer.get_cursor(state, path)
    assert i == inode
    assert off == 3
    assert end == size
    assert drain is None


def test_get_cursor_truncated_offset_resets(tmp_path):
    path = str(tmp_path / "flows.jsonl")
    _write_file(path, "aaaa\n")  # 5 bytes
    inode = os.stat(path).st_ino
    state = flow_analyzer.empty_state()
    flow_analyzer.save_cursor(state, inode, 999)  # beyond file size
    # truncate file to smaller
    with open(path, "w") as f:
        f.write("aa\n")
    i, off, end, drain = flow_analyzer.get_cursor(state, path)
    assert off == 0  # saved_offset > size -> reset to 0
    assert drain is None


def test_get_cursor_inode_change_finds_archive_drain(tmp_path):
    path = str(tmp_path / "flows.jsonl")
    _write_file(path, "old-content\n")
    old_inode = os.stat(path).st_ino
    old_size = os.stat(path).st_size
    state = flow_analyzer.empty_state()
    flow_analyzer.save_cursor(state, old_inode, 2)  # read 2 bytes of old file
    # rotate: rename old file to an archive, create a new flows.jsonl
    archive = path + ".archived.20240101T000000Z"
    os.rename(path, archive)
    _write_file(path, "new-content\n")
    i, off, end, drain = flow_analyzer.get_cursor(state, path)
    assert i == os.stat(path).st_ino
    assert off == 0
    assert drain is not None
    a_path, a_start, a_end = drain
    assert a_path == archive
    assert a_start == 2
    assert a_end == old_size


def test_get_cursor_missing_file():
    state = flow_analyzer.empty_state()
    i, off, end, drain = flow_analyzer.get_cursor(state, "/no/such/file")
    assert (i, off, end, drain) == (None, 0, 0, None)


def test_save_cursor_mutates():
    state = flow_analyzer.empty_state()
    flow_analyzer.save_cursor(state, 42, 99)
    assert state["flow_cursor"] == {"inode": 42, "offset": 99}


# --- lookup_ti --------------------------------------------------------------

def test_lookup_ti_ipv4_in_range():
    con = make_ti_con({"spamhaus-drop": [("high", "8.8.8.0/24")]})
    rows = flow_analyzer.lookup_ti(con, "8.8.8.8")
    assert rows == [("spamhaus-drop", "high")]


def test_lookup_ti_out_of_range():
    con = make_ti_con({"spamhaus-drop": [("high", "8.8.8.0/24")]})
    assert flow_analyzer.lookup_ti(con, "9.9.9.9") == []


def test_lookup_ti_boundary():
    # network 8.8.8.0/24 -> start=8.8.8.0 end=8.8.8.255
    con = make_ti_con({"x": [("low", "8.8.8.0/24")]})
    assert flow_analyzer.lookup_ti(con, "8.8.8.0") == [("x", "low")]
    assert flow_analyzer.lookup_ti(con, "8.8.8.255") == [("x", "low")]


def test_lookup_ti_rejects_ipv6():
    con = make_ti_con({"x": [("low", "0.0.0.0/0")]})
    assert flow_analyzer.lookup_ti(con, "2001:db8::1") == []


def test_lookup_ti_invalid_returns_empty():
    con = make_ti_con({"x": [("low", "0.0.0.0/0")]})
    assert flow_analyzer.lookup_ti(con, "garbage") == []
    assert flow_analyzer.lookup_ti(con, None) == []


def test_lookup_ti_multiple_feeds_max_severity_via_caller():
    con = make_ti_con({
        "feed-a": [("low", "1.0.0.0/8")],
        "feed-b": [("high", "1.0.0.0/8")],
    })
    rows = flow_analyzer.lookup_ti(con, "1.2.3.4")
    assert sorted(rows) == [("feed-a", "low"), ("feed-b", "high")]
    assert flow_analyzer.max_severity(rows) == "high"


# --- lookup_geoip -----------------------------------------------------------

def test_lookup_geoip_none_dbs():
    assert flow_analyzer.lookup_geoip(None, None, "8.8.8.8") == (None, None, None)


def test_lookup_geoip_country_and_asn():
    country = FakeGeoIP(country_map={"8.8.8.8": {"country": {"iso_code": "US"}}})
    asn = FakeGeoIP(asn_map={"8.8.8.8": {"autonomous_system_number": 15169,
                                          "autonomous_system_organization": "Google"}})
    cc, asn_num, org = flow_analyzer.lookup_geoip(country, asn, "8.8.8.8")
    assert cc == "US"
    assert asn_num == 15169
    assert org == "Google"


def test_lookup_geoip_registered_country_fallback():
    country = FakeGeoIP(country_map={"8.8.8.8":
                                     {"registered_country": {"iso_code": "DE"}}})
    cc, _, _ = flow_analyzer.lookup_geoip(country, None, "8.8.8.8")
    assert cc == "DE"


def test_lookup_geoip_exception_swallowed():
    country = FakeGeoIP(country_map={}, raise_on=["8.8.8.8"])
    asn = FakeGeoIP(asn_map={}, raise_on=["8.8.8.8"])
    cc, asn_num, org = flow_analyzer.lookup_geoip(country, asn, "8.8.8.8")
    assert (cc, asn_num, org) == (None, None, None)


# --- max_severity -----------------------------------------------------------

def test_max_severity_picks_highest():
    assert flow_analyzer.max_severity([("a", "low"), ("b", "high"),
                                        ("c", "medium")]) == "high"


def test_max_severity_unknown():
    assert flow_analyzer.max_severity([("a", "bogus")]) == "bogus"


# --- baseline_check --------------------------------------------------------

def test_baseline_check_first_seen_asn():
    state = flow_analyzer.empty_state()
    kind = flow_analyzer.baseline_check(state, "10.0.0.1", 15169, None, 100)
    assert kind == "new-asn"
    entry = state["baseline_asn"]["10.0.0.1"]["15169"]
    assert entry == {"first_seen": 100, "last_seen": 100, "flow_count": 1}


def test_baseline_check_repeat_asn_no_new():
    state = flow_analyzer.empty_state()
    flow_analyzer.baseline_check(state, "10.0.0.1", 15169, None, 100)
    kind = flow_analyzer.baseline_check(state, "10.0.0.1", 15169, None, 200)
    assert kind is None
    entry = state["baseline_asn"]["10.0.0.1"]["15169"]
    assert entry["last_seen"] == 200
    assert entry["flow_count"] == 2
    assert entry["first_seen"] == 100


def test_baseline_check_first_seen_country():
    state = flow_analyzer.empty_state()
    kind = flow_analyzer.baseline_check(state, "10.0.0.1", None, "DE", 100)
    assert kind == "new-country"
    assert "DE" in state["baseline_country"]["10.0.0.1"]


def test_baseline_check_asn_wins_over_country_when_both_new():
    state = flow_analyzer.empty_state()
    kind = flow_analyzer.baseline_check(state, "10.0.0.1", 15169, "US", 100)
    assert kind == "new-asn"
    # both buckets populated
    assert "15169" in state["baseline_asn"]["10.0.0.1"]
    assert "US" in state["baseline_country"]["10.0.0.1"]


def test_baseline_check_str_asn_key_coercion():
    state = flow_analyzer.empty_state()
    flow_analyzer.baseline_check(state, "10.0.0.1", 15169, None, 100)
    # json round-trip makes keys strings; second call with int must hit same entry
    state2 = json.loads(json.dumps(state))
    kind = flow_analyzer.baseline_check(state2, "10.0.0.1", 15169, None, 200)
    assert kind is None  # not new
    assert state2["baseline_asn"]["10.0.0.1"]["15169"]["flow_count"] == 2


# --- process_flow -----------------------------------------------------------

def _proc(flow_dict, state=None, ti_con=None, country=None, asn=None, now=100):
    state = state or flow_analyzer.empty_state()
    ti_con = ti_con or make_ti_con({})
    return flow_analyzer.process_flow(flow_dict, state, ti_con, country, asn, now)


def test_process_flow_missing_src():
    assert _proc({"dst_addr": "8.8.8.8", "bytes": 9999, "packets": 9}) is None


def test_process_flow_missing_dst():
    assert _proc({"src_addr": "10.0.0.1", "bytes": 9999, "packets": 9}) is None


def test_process_flow_src_not_private():
    assert _proc(flow("203.0.113.5", "8.8.8.8")) is None


def test_process_flow_dst_private():
    assert _proc(flow("10.0.0.1", "192.168.1.1")) is None


def test_process_flow_below_threshold():
    # bytes < MIN_BYTES(2048) and packets < MIN_PACKETS(2)
    assert _proc(flow("10.0.0.1", "8.8.8.8", bytes_=100, packets=1)) is None


def test_process_flow_bytes_threshold_only_passes():
    # bytes >= MIN_BYTES but packets < MIN_PACKETS -> gate does NOT skip (AND),
    # so a TI match still produces an alert.
    ti_con = make_ti_con({"bad": [("high", "8.8.8.0/24")]})
    a = flow_analyzer.process_flow(flow("10.0.0.1", "8.8.8.8", bytes_=4096,
                                         packets=1), flow_analyzer.empty_state(),
                                   ti_con, None, None, 100)
    assert a is not None
    assert a["kind"] == "ti-match"


def test_process_flow_packets_threshold_only_passes():
    # packets >= MIN_PACKETS but bytes < MIN_BYTES -> gate does NOT skip
    ti_con = make_ti_con({"bad": [("high", "8.8.8.0/24")]})
    a = flow_analyzer.process_flow(flow("10.0.0.1", "8.8.8.8", bytes_=100,
                                         packets=5), flow_analyzer.empty_state(),
                                   ti_con, None, None, 100)
    assert a is not None
    assert a["kind"] == "ti-match"


def test_process_flow_ti_match():
    ti_con = make_ti_con({"bad": [("high", "8.8.8.0/24")]})
    state = flow_analyzer.empty_state()
    a = flow_analyzer.process_flow(flow("10.0.0.1", "8.8.8.8", bytes_=4096,
                                         packets=5), state, ti_con, None, None, 100)
    assert a["kind"] == "ti-match"
    assert a["severity"] == "high"
    assert a["sources"] == "bad"
    assert a["internal_ip"] == "10.0.0.1"
    assert a["dst_ip"] == "8.8.8.8"


def test_process_flow_new_baseline_when_country_known():
    country = FakeGeoIP(country_map={"7.7.7.7": {"country": {"iso_code": "US"}}})
    state = flow_analyzer.empty_state()
    a = flow_analyzer.process_flow(flow("10.0.0.1", "7.7.7.7", bytes_=4096,
                                         packets=5), state, make_ti_con({}),
                                   country, None, 100)
    assert a["kind"] == "new-country"
    assert a["severity"] == "low"


def test_process_flow_new_baseline_when_asn_known():
    asn = FakeGeoIP(asn_map={"7.7.7.7": {"autonomous_system_number": 15169,
                                          "autonomous_system_organization": "G"}})
    state = flow_analyzer.empty_state()
    a = flow_analyzer.process_flow(flow("10.0.0.1", "7.7.7.7", bytes_=4096,
                                         packets=5), state, make_ti_con({}),
                                   None, asn, 100)
    assert a["kind"] == "new-asn"


def test_process_flow_no_match_no_baseline():
    # country known but already in baseline -> None
    country = FakeGeoIP(country_map={"7.7.7.7": {"country": {"iso_code": "US"}}})
    state = flow_analyzer.empty_state()
    flow_analyzer.baseline_check(state, "10.0.0.1", None, "US", 50)
    a = flow_analyzer.process_flow(flow("10.0.0.1", "7.7.7.7", bytes_=4096,
                                         packets=5), state, make_ti_con({}),
                                   country, None, 100)
    assert a is None


def test_process_flow_proto_name_resolution():
    ti_con = make_ti_con({"bad": [("high", "8.8.8.0/24")]})
    a = flow_analyzer.process_flow(flow("10.0.0.1", "8.8.8.8", proto=6,
                                         dst_port=443, bytes_=4096, packets=5),
                                   flow_analyzer.empty_state(), ti_con, None, None, 100)
    assert a["proto"] == "tcp"
    assert a["dst_port"] == 443


def test_process_flow_unknown_proto():
    ti_con = make_ti_con({"bad": [("high", "8.8.8.0/24")]})
    a = flow_analyzer.process_flow(flow("10.0.0.1", "8.8.8.8", proto=99,
                                         bytes_=4096, packets=5),
                                   flow_analyzer.empty_state(), ti_con, None, None, 100)
    assert a["proto"] == "99"


# --- collapse ---------------------------------------------------------------

def test_collapse_merges_identical():
    alerts = [
        {"internal_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "kind": "ti-match",
         "bytes": 100, "packets": 1, "severity": "high", "sources": "a"},
        {"internal_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "kind": "ti-match",
         "bytes": 200, "packets": 2, "severity": "high", "sources": "a"},
        {"internal_ip": "10.0.0.1", "dst_ip": "9.9.9.9", "kind": "ti-match",
         "bytes": 50, "packets": 1, "severity": "low", "sources": "b"},
    ]
    out = flow_analyzer.collapse(alerts)
    by_dst = {a["dst_ip"]: a for a in out}
    assert by_dst["8.8.8.8"]["bytes"] == 300
    assert by_dst["8.8.8.8"]["packets"] == 3
    assert by_dst["9.9.9.9"]["bytes"] == 50
    assert len(out) == 2


def test_collapse_empty():
    assert flow_analyzer.collapse([]) == []


# --- is_rate_limited / mark_sent --------------------------------------------

def test_is_rate_limited_low_uses_low_window(monkeypatch):
    monkeypatch.setattr(flow_analyzer, "DEDUPE_LOW_HOURS", 24)
    monkeypatch.setattr(flow_analyzer, "DEDUPE_HOURS", 6)
    state = flow_analyzer.empty_state()
    alert = {"internal_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
             "kind": "new-country", "severity": "low"}
    now = 100000
    flow_analyzer.mark_sent(state, alert, now)
    # low severity: 24h window -> still rate limited at now+23h
    assert flow_analyzer.is_rate_limited(state, alert, now + 23 * 3600) is True
    # but not rate limited past 24h
    assert flow_analyzer.is_rate_limited(state, alert, now + 25 * 3600) is False
    # and rate limited at now+1
    assert flow_analyzer.is_rate_limited(state, alert, now + 10) is True


def test_is_rate_limited_nonlow_uses_normal_window(monkeypatch):
    monkeypatch.setattr(flow_analyzer, "DEDUPE_LOW_HOURS", 24)
    monkeypatch.setattr(flow_analyzer, "DEDUPE_HOURS", 6)
    state = flow_analyzer.empty_state()
    alert = {"internal_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
             "kind": "ti-match", "severity": "high"}
    now = 100000
    flow_analyzer.mark_sent(state, alert, now)
    # high severity: 6h window -> not rate limited at now+7h
    assert flow_analyzer.is_rate_limited(state, alert, now + 7 * 3600) is False
    # but rate limited at now+1h
    assert flow_analyzer.is_rate_limited(state, alert, now + 3600) is True


def test_is_rate_limited_never_sent():
    state = flow_analyzer.empty_state()
    alert = {"internal_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
             "kind": "ti-match", "severity": "high"}
    assert flow_analyzer.is_rate_limited(state, alert, 999999) is False


# --- reverse_dns ------------------------------------------------------------

def test_reverse_dns_success(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyaddr",
                        lambda ip: ("host.example.com", [], [ip]))
    assert flow_analyzer.reverse_dns("8.8.8.8") == "host.example.com"


@pytest.mark.parametrize("exc", [socket.herror, socket.gaierror,
                                  socket.timeout, OSError])
def test_reverse_dns_failures(monkeypatch, exc):
    def raise_(ip):
        raise exc("nope")
    monkeypatch.setattr(socket, "gethostbyaddr", raise_)
    assert flow_analyzer.reverse_dns("8.8.8.8") is None


# --- format_email -----------------------------------------------------------

def _base_alert(**over):
    base = {"internal_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "dst_port": 53,
            "proto": "udp", "asn": 15169, "asn_org": "Google", "country": "US",
            "bytes": 4096, "packets": 5, "sources": "spamhaus-drop",
            "severity": "high", "kind": "ti-match"}
    base.update(over)
    return base


def test_format_email_ti_match(monkeypatch):
    monkeypatch.setattr(flow_analyzer, "reverse_dns", lambda ip: "dns.google")
    subj, body = flow_analyzer.format_email(_base_alert())
    assert subj == "[house-net] HIGH: 10.0.0.1 -> 8.8.8.8 | spamhaus-drop"
    assert "10.0.0.1" in body
    assert "8.8.8.8 (dns.google) :53/udp" in body
    assert "US / AS15169 (Google)" in body
    assert "4.0 KB" in body
    assert "matched:      spamhaus-drop" in body


def test_format_email_new_asn(monkeypatch):
    monkeypatch.setattr(flow_analyzer, "reverse_dns", lambda ip: None)
    subj, _ = flow_analyzer.format_email(
        _base_alert(kind="new-asn", severity="low", asn=12345,
                    asn_org="Telco"))
    assert subj == "[house-net] LOW: 10.0.0.1 -> new ASN AS12345 (Telco)"


def test_format_email_new_country(monkeypatch):
    monkeypatch.setattr(flow_analyzer, "reverse_dns", lambda ip: None)
    subj, _ = flow_analyzer.format_email(
        _base_alert(kind="new-country", severity="low"))
    assert subj == "[house-net] LOW: 10.0.0.1 -> new country US"


def test_format_email_else_kind(monkeypatch):
    monkeypatch.setattr(flow_analyzer, "reverse_dns", lambda ip: None)
    subj, _ = flow_analyzer.format_email(_base_alert(kind="other", severity="medium"))
    assert subj == "[house-net] MEDIUM: 10.0.0.1 -> 8.8.8.8"


def test_format_email_unknown_asn(monkeypatch):
    monkeypatch.setattr(flow_analyzer, "reverse_dns", lambda ip: None)
    _, body = flow_analyzer.format_email(
        _base_alert(kind="new-asn", asn=None, asn_org=None))
    assert "unknown ASN" in body


# --- load_geoip -------------------------------------------------------------

def test_load_geoip_no_maxminddb(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "maxminddb":
            raise ImportError("no maxminddb")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert flow_analyzer.load_geoip() == (None, None)


def test_load_geoip_opens_when_present(monkeypatch):
    import sys
    fake_mod = types_module = type(sys)("maxminddb")
    opened = []

    def open_database(path):
        opened.append(path)
        return f"reader:{path}"
    fake_mod.open_database = open_database
    monkeypatch.setitem(sys.modules, "maxminddb", fake_mod)
    # config.GEOIP_DIR is patched to tmp_path/geoip by cfg_paths fixture; touch
    # the mmdb files so os.path.exists passes.
    cpath = os.path.join(config.GEOIP_DIR, "GeoLite2-Country.mmdb")
    apath = os.path.join(config.GEOIP_DIR, "GeoLite2-ASN.mmdb")
    open(cpath, "w").close()
    open(apath, "w").close()
    country, asn = flow_analyzer.load_geoip()
    assert country == f"reader:{cpath}"
    assert asn == f"reader:{apath}"


def test_load_geoip_missing_files(monkeypatch):
    import sys
    fake_mod = type(sys)("maxminddb")
    fake_mod.open_database = lambda p: p
    monkeypatch.setitem(sys.modules, "maxminddb", fake_mod)
    # no mmdb files exist in tmp_path/geoip
    country, asn = flow_analyzer.load_geoip()
    assert country is None
    assert asn is None


# --- run_once (integration) -------------------------------------------------

def test_run_once_missing_flows_file(capsys):
    # flows.jsonl does not exist in tmp_path
    flow_analyzer.run_once()
    assert "does not exist" in capsys.readouterr().err


def test_run_once_missing_ti_db(tmp_path, capsys):
    # flows file exists but ti.db does not
    write_flows(config.FLOWS_FILE, [flow("10.0.0.1", "8.8.8.8")])
    flow_analyzer.run_once()
    assert "threat-intel DB" in capsys.readouterr().err


def test_run_once_integration(tmp_path, monkeypatch, capsys):
    # build a ti.db on disk with one bad destination
    make_ti_db_file(config.TI_DB, {"bad": [("high", "8.8.8.0/24")]})
    flows = [
        flow("10.0.0.1", "8.8.8.8", bytes_=4096, packets=5),   # TI match
        flow("10.0.0.1", "7.7.7.7", bytes_=4096, packets=5),   # new-baseline (no geoip -> nothing)
        flow("10.0.0.1", "9.9.9.9", bytes_=100, packets=1),     # below threshold -> skipped
    ]
    write_flows(config.FLOWS_FILE, flows)

    # Seed a cursor at offset 0 so run_once reads the file (first-run would
    # otherwise skip the existing backlog).
    state = flow_analyzer.empty_state()
    flow_analyzer.save_cursor(state, os.stat(config.FLOWS_FILE).st_ino, 0)
    flow_analyzer.save_state(state, config.STATE_FILE)

    sent = []
    monkeypatch.setattr(config, "send_email", lambda subj, body: sent.append(subj) or True)
    monkeypatch.setattr(flow_analyzer, "load_geoip", lambda: (None, None))

    flow_analyzer.run_once()

    # alerts.jsonl written with one ti-match (new-baseline produced nothing
    # because country is None without geoip)
    with open(config.ALERTS_FILE) as f:
        recs = [json.loads(l) for l in f if l.strip()]
    assert len(recs) == 1
    assert recs[0]["kind"] == "ti-match"
    assert recs[0]["severity"] == "high"
    assert recs[0]["dst_ip"] == "8.8.8.8"
    assert recs[0]["suppressed"] == 0  # emailed

    # email was sent
    assert any("8.8.8.8" in s for s in sent)

    # state.json cursor advanced past the consumed bytes
    state = flow_analyzer.load_state(config.STATE_FILE)
    assert state["flow_cursor"] is not None
    assert state["flow_cursor"]["offset"] > 0

    # metrics.db got rollup rows (every outbound flow, regardless of threshold)
    con = sqlite3.connect(config.METRICS_DB)
    n = con.execute("SELECT COUNT(*) FROM country_daily").fetchone()[0]
    assert n >= 1
    con.close()


def test_run_once_rate_limits_email(tmp_path, monkeypatch):
    make_ti_db_file(config.TI_DB, {"bad": [("high", "8.8.8.0/24")]})
    # pre-mark the alert as sent recently so it's rate-limited
    state = flow_analyzer.empty_state()
    state["flow_cursor"] = None  # first run skips backlog; we'll write fresh
    # set a cursor so we actually read the file
    write_flows(config.FLOWS_FILE, [flow("10.0.0.1", "8.8.8.8", bytes_=4096, packets=5)])
    # pre-seed state with a recent send for this alert key
    flow_analyzer.save_cursor(state, os.stat(config.FLOWS_FILE).st_ino, 0)
    state["alerts_sent"]["10.0.0.1|8.8.8.8|ti-match"] = 9_999_999_999  # far future
    flow_analyzer.save_state(state, config.STATE_FILE)

    sent = []
    monkeypatch.setattr(config, "send_email", lambda s, b: sent.append(s) or True)
    monkeypatch.setattr(flow_analyzer, "load_geoip", lambda: (None, None))
    flow_analyzer.run_once()

    with open(config.ALERTS_FILE) as f:
        recs = [json.loads(l) for l in f if l.strip()]
    assert len(recs) == 1
    assert recs[0]["suppressed"] == 1  # rate-limited, not emailed
    assert sent == []


# --- loop_forever / main -----------------------------------------------------

def test_loop_forever_exits_when_stop_pre_set(monkeypatch):
    import threading
    called = []
    monkeypatch.setattr(flow_analyzer, "run_once", lambda: called.append(1))
    stop = threading.Event()
    stop.set()
    flow_analyzer.loop_forever(stop)
    assert called == []  # never ticked


def test_loop_forever_ticks_until_stop(monkeypatch):
    import threading
    import time as _time
    monkeypatch.setattr(flow_analyzer, "run_once", lambda: None)
    monkeypatch.setattr(flow_analyzer, "LOOP_INTERVAL_SEC", 0)
    # make stop_event.wait return immediately and set after 2 calls
    stop = threading.Event()
    calls = [0]

    def fake_wait(timeout=None):
        calls[0] += 1
        if calls[0] >= 2:
            stop.set()
        return False
    monkeypatch.setattr(stop, "wait", fake_wait)
    flow_analyzer.loop_forever(stop)
    assert calls[0] >= 2


def test_main_no_loop_calls_run_once(monkeypatch):
    monkeypatch.setattr(flow_analyzer, "run_once", lambda: None)
    monkeypatch.setattr("sys.argv", ["flow_analyzer.py"])
    flow_analyzer.main()


def test_main_loop_dispatches(monkeypatch):
    import threading
    started = threading.Event()
    monkeypatch.setattr(flow_analyzer, "loop_forever", lambda ev: started.set())
    monkeypatch.setattr("sys.argv", ["flow_analyzer.py", "--loop"])
    flow_analyzer.main()
    assert started.is_set()