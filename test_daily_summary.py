"""Tests for daily_summary.py."""
import json
import os
import threading

import pytest

import config
import daily_summary
import flow_analyzer
from test_fakes import write_alerts


# --- next_fire_ts ----------------------------------------------------------

def test_next_fire_ts_rolls_to_next_day_when_hour_passed(monkeypatch):
    # HOUR_UTC=6. now 10:00 UTC -> candidate 06:00 same day is in the past,
    # so roll to 06:00 next day.
    monkeypatch.setattr(daily_summary, "HOUR_UTC", 6)
    now_ts = 1704103200      # 2024-01-01 10:00 UTC
    fire = daily_summary.next_fire_ts(now_ts, 0)
    assert fire == 1704175200  # 2024-01-02 06:00 UTC


def test_next_fire_ts_before_hour_same_day(monkeypatch):
    # HOUR_UTC=6. now 03:00 UTC -> candidate 06:00 same day is in the future.
    monkeypatch.setattr(daily_summary, "HOUR_UTC", 6)
    now_ts = 1704078000      # 2024-01-01 03:00 UTC
    fire = daily_summary.next_fire_ts(now_ts, 0)
    assert fire == 1704088800  # 2024-01-01 06:00 UTC


def test_next_fire_ts_23h_floor_advances_a_day(monkeypatch):
    # Just fired at 07:30 UTC; candidate 06:00 tomorrow is < last_run+23h, so
    # the 23h floor forces a second advance to 06:00 the day after tomorrow.
    monkeypatch.setattr(daily_summary, "HOUR_UTC", 6)
    now_ts = 1704094200      # 2024-01-01 07:30 UTC
    last_run = now_ts        # just fired
    fire = daily_summary.next_fire_ts(now_ts, last_run)
    # candidate 2024-01-02 06:00 = 1704175200 < last_run+23h(1704177000) -> advance
    assert fire == 1704261600  # 2024-01-03 06:00 UTC


def test_next_fire_ts_advances_until_past_floor(monkeypatch):
    monkeypatch.setattr(daily_summary, "HOUR_UTC", 0)
    now_ts = 1704104400      # 2024-01-01 10:20 UTC
    last_run = 0
    fire = daily_summary.next_fire_ts(now_ts, last_run)
    # candidate 2024-01-02 00:00 UTC; floor 82800 satisfied -> first candidate
    assert fire == 1704153600  # 2024-01-02 00:00 UTC


# --- _empty_entry / has_content ---------------------------------------------

def test_empty_entry_shape():
    e = daily_summary._empty_entry()
    assert e == {"ti-match": {}, "new-asn": {}, "new-country": {}}


def test_has_content_empty():
    by_ip = {"10.0.0.1": daily_summary._empty_entry()}
    assert daily_summary.has_content(by_ip) is False


def test_has_content_populated():
    by_ip = {"10.0.0.1": {"ti-match": {("1.1.1.1", ""): {"count": 1}},
                          "new-asn": {}, "new-country": {}}}
    assert daily_summary.has_content(by_ip) is True


# --- summarise_window ------------------------------------------------------

def _alert(ts, kind="ti-match", ip="10.0.0.1", dst="8.8.8.8", sources="",
          bytes_=1000, severity="high", asn=None, asn_org="", country=""):
    return {"ts": ts, "kind": kind, "internal_ip": ip, "dst_ip": dst,
            "dst_port": 53, "proto": "udp", "asn": asn, "asn_org": asn_org,
            "country": country, "sources": sources, "bytes": bytes_,
            "packets": 1, "suppressed": 0, "severity": severity}


def test_summarise_window_missing_file_returns_empty():
    assert daily_summary.summarise_window(0, 999999) == {}


def test_summarise_window_filters_by_time(tmp_path):
    recs = [
        _alert(100, ip="10.0.0.1"),   # in [50, 200)
        _alert(10, ip="10.0.0.2"),    # before window
        _alert(250, ip="10.0.0.3"),   # after window
    ]
    write_alerts(config.ALERTS_FILE, recs)
    by_ip = daily_summary.summarise_window(50, 200)
    assert "10.0.0.1" in by_ip
    assert "10.0.0.2" not in by_ip
    assert "10.0.0.3" not in by_ip


def test_summarise_window_malformed_json_skipped(tmp_path):
    with open(config.ALERTS_FILE, "w") as f:
        f.write(json.dumps(_alert(100)) + "\n")
        f.write("not json\n")
        f.write(json.dumps(_alert(100, dst="9.9.9.9")) + "\n")
    by_ip = daily_summary.summarise_window(0, 999999)
    ti = by_ip["10.0.0.1"]["ti-match"]
    assert ("8.8.8.8", "") in ti
    assert ("9.9.9.9", "") in ti


def test_summarise_window_unknown_kind_skipped(tmp_path):
    write_alerts(config.ALERTS_FILE, [_alert(100, kind="other")])
    by_ip = daily_summary.summarise_window(0, 999999)
    assert by_ip == {}


def test_summarise_window_ti_aggregation(tmp_path):
    recs = [
        _alert(100, dst="8.8.8.8", sources="spamhaus", bytes_=1000, severity="low"),
        _alert(101, dst="8.8.8.8", sources="spamhaus", bytes_=2000, severity="high"),
        _alert(102, dst="8.8.8.8", sources="firehol", bytes_=500, severity="low"),
    ]
    write_alerts(config.ALERTS_FILE, recs)
    by_ip = daily_summary.summarise_window(0, 999999)
    ti = by_ip["10.0.0.1"]["ti-match"]
    # two distinct (dst, sources) keys
    assert ("8.8.8.8", "spamhaus") in ti
    assert ("8.8.8.8", "firehol") in ti
    spam = ti[("8.8.8.8", "spamhaus")]
    assert spam["count"] == 2
    assert spam["bytes"] == 3000
    assert spam["severity"] == "high"  # max seen


def test_summarise_window_new_asn_first_wins(tmp_path):
    recs = [
        _alert(100, kind="new-asn", dst="8.8.8.8", asn=15169, asn_org="Google"),
        _alert(101, kind="new-asn", dst="9.9.9.9", asn=15169, asn_org="Other"),
    ]
    write_alerts(config.ALERTS_FILE, recs)
    by_ip = daily_summary.summarise_window(0, 999999)
    asn_map = by_ip["10.0.0.1"]["new-asn"]
    assert 15169 in asn_map
    # first-wins: org+dst from the first record
    assert asn_map[15169] == ("Google", "8.8.8.8")


def test_summarise_window_new_country_first_wins(tmp_path):
    recs = [
        _alert(100, kind="new-country", dst="8.8.8.8", country="US"),
        _alert(101, kind="new-country", dst="9.9.9.9", country="US"),
    ]
    write_alerts(config.ALERTS_FILE, recs)
    by_ip = daily_summary.summarise_window(0, 999999)
    cc_map = by_ip["10.0.0.1"]["new-country"]
    assert cc_map["US"] == "8.8.8.8"  # first wins


def test_summarise_window_missing_ip_skipped(tmp_path):
    rec = _alert(100)
    rec["internal_ip"] = None
    write_alerts(config.ALERTS_FILE, [rec])
    assert daily_summary.summarise_window(0, 999999) == {}


# --- format_digest ---------------------------------------------------------

def test_format_digest_totals_and_blocks():
    by_ip = {
        "10.0.0.2": {
            "ti-match": {("8.8.8.8", "spamhaus"): {"severity": "high", "count": 3,
                                                    "bytes": 4096, "asn": 15169,
                                                    "asn_org": "Google", "country": "US"},
                          ("9.9.9.9", "firehol"): {"severity": "low", "count": 1,
                                                    "bytes": 1024, "asn": None,
                                                    "asn_org": "", "country": ""}},
            "new-asn": {12345: ("Telco", "7.7.7.7")},
            "new-country": {"DE": "7.7.7.7"},
        },
        "10.0.0.1": {
            "ti-match": {("1.1.1.1", ""): {"severity": "low", "count": 1,
                                            "bytes": 512, "asn": None,
                                            "asn_org": "", "country": "AU"}},
            "new-asn": {},
            "new-country": {},
        },
    }
    subj, body = daily_summary.format_digest(by_ip, 1000, 2000)
    # totals: ti_total = 3+1+1 = 5; ti_unique = 3; asn_total = 1; country_total = 1
    assert "5 TI hit(s)" in subj
    assert "1 new ASN(s)" in subj
    assert "1 new country code(s)" in subj
    # devices sorted by ip
    assert body.index("10.0.0.1") < body.index("10.0.0.2")
    # ti-match sort: severity desc then count desc then dst asc
    # for 10.0.0.2: high(3) first, then low(1)
    assert body.index("8.8.8.8") < body.index("9.9.9.9")
    assert "4.0 KB" in body  # 4096 bytes
    assert "[US AS15169]" in body


def test_format_digest_empty_by_ip():
    subj, body = daily_summary.format_digest({}, 1000, 2000)
    assert "0 TI hit(s)" in subj
    assert "0 device(s)" in body


def test_format_digest_window_iso_timestamps():
    subj, body = daily_summary.format_digest({}, 1704067200, 1704153600)
    # 2024-01-01 00:00:00 UTC -> 2024-01-02 00:00:00 UTC
    assert "2024-01-01T00:00:00+00:00" in body
    assert "2024-01-02T00:00:00+00:00" in body


# --- run_once_dry ----------------------------------------------------------

def test_run_once_dry_empty(monkeypatch, capsys):
    monkeypatch.setattr(daily_summary.time, "time", lambda: 100000)
    daily_summary.run_once_dry()
    out = capsys.readouterr().out
    assert "(no new-asn/new-country" in out


def test_run_once_dry_with_content(monkeypatch, capsys, tmp_path):
    write_alerts(config.ALERTS_FILE, [_alert(99999, kind="new-country", country="US",
                                            dst="8.8.8.8")])
    monkeypatch.setattr(daily_summary.time, "time", lambda: 100000)
    daily_summary.run_once_dry()
    out = capsys.readouterr().out
    assert "Subject:" in out
    assert "new country" in out


# --- loop_forever / main ----------------------------------------------------

def test_loop_forever_creates_sentinel_if_missing(tmp_path, monkeypatch):
    # sentinel path is cfg.DATA_DIR/.last_daily_summary; pre-set stop so it
    # exits after the create-on-missing branch.
    monkeypatch.setattr(daily_summary, "next_fire_ts", lambda now, last: 9_999_999_999)
    stop = threading.Event(); stop.set()
    daily_summary.loop_forever(stop)
    assert os.path.exists(os.path.join(config.DATA_DIR, ".last_daily_summary"))


def test_main_no_loop_runs_dry(monkeypatch):
    called = []
    monkeypatch.setattr(daily_summary, "run_once_dry", lambda: called.append(1))
    monkeypatch.setattr("sys.argv", ["daily_summary.py"])
    daily_summary.main()
    assert called == [1]


def test_main_loop_dispatches(monkeypatch):
    started = threading.Event()
    monkeypatch.setattr(daily_summary, "loop_forever", lambda ev: started.set())
    monkeypatch.setattr("sys.argv", ["daily_summary.py", "--loop"])
    daily_summary.main()
    assert started.is_set()