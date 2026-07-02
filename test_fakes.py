"""Shared fakes and factory helpers for the netmon test suite.

These build real, lightweight stand-ins for the external surfaces the modules
touch (MaxMind readers, goflow2 process, on-disk ti.db/metrics.db) so tests can
exercise the real SQL/parse/format logic without network, MaxMind, or goflow2.
"""
import ipaddress
import os
import sqlite3
import types

import flow_analyzer
import ti_updater


# --- Threat-intel DB --------------------------------------------------------

def make_ti_con(networks_by_source):
    """Build an in-memory ti.db (via the real init_db/insert_rows) seeded with
    {source: [(severity, "cidr"), ...]} and return an open connection."""
    con = sqlite3.connect(":memory:")
    ti_updater.init_db(con)
    now = 1_700_000_000
    for source, entries in networks_by_source.items():
        nets = []
        for severity, cidr in entries:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        ti_updater.insert_rows(con, source, severity, nets, now)
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_ti_range ON ti_indicators "
        "(family, cidr_start, cidr_end)"
    )
    con.commit()
    return con


def make_ti_db_file(path, networks_by_source):
    """Persist a ti.db file (so flow_analyzer can open it read-only via URI)
    seeded with {source: [(severity, "cidr"), ...]}."""
    con = sqlite3.connect(path)
    ti_updater.init_db(con)
    now = 1_700_000_000
    for source, entries in networks_by_source.items():
        nets = [ipaddress.ip_network(c, strict=False) for _, c in entries]
        ti_updater.insert_rows(con, source, entries[0][0] if entries else "low",
                               nets, now)
        con.execute(
            "INSERT OR REPLACE INTO ti_meta "
            "(source, last_fetch_ts, row_count, ok, note) VALUES (?,?,?,1,NULL)",
            (source, now, len(nets)),
        )
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_ti_range ON ti_indicators "
        "(family, cidr_start, cidr_end)"
    )
    con.commit()
    con.close()


# --- Metrics DB -------------------------------------------------------------

def make_metrics_con(rows=None):
    """In-memory metrics.db via the real init_metrics_db. `rows` is an optional
    list of (date, ip, country, asn, asn_org, flows, bytes, packets) tuples
    inserted directly so breakdown/timeseries tests have known data."""
    con = sqlite3.connect(":memory:")
    flow_analyzer.init_metrics_db(con)
    if rows:
        for (date, ip, country, asn, asn_org, flows, bytes_, packets) in rows:
            con.execute(
                "INSERT INTO country_daily(date, internal_ip, country, flows, bytes, packets) "
                "VALUES(?,?,?,?,?,?)",
                (date, ip, country, flows, bytes_, packets),
            )
            con.execute(
                "INSERT INTO asn_daily(date, internal_ip, asn, asn_org, flows, bytes, packets) "
                "VALUES(?,?,?,?,?,?,?)",
                (date, ip, asn, asn_org, flows, bytes_, packets),
            )
        con.commit()
    return con


def write_metrics_db_file(path, rows):
    """Persist a metrics.db file with the given rows (same tuple shape as
    make_metrics_con) so web_server can open it read-only via URI."""
    con = sqlite3.connect(path)
    flow_analyzer.init_metrics_db(con)
    for (date, ip, country, asn, asn_org, flows, bytes_, packets) in rows:
        con.execute(
            "INSERT INTO country_daily(date, internal_ip, country, flows, bytes, packets) "
            "VALUES(?,?,?,?,?,?)",
            (date, ip, country, flows, bytes_, packets),
        )
        con.execute(
            "INSERT INTO asn_daily(date, internal_ip, asn, asn_org, flows, bytes, packets) "
            "VALUES(?,?,?,?,?,?,?)",
            (date, ip, asn, asn_org, flows, bytes_, packets),
        )
    con.commit()
    con.close()


# --- MaxMind stand-in -------------------------------------------------------

class FakeGeoIP:
    """Duck-typed MaxMind reader: `.get(ip)` returns a dict (or raises).

    `country_map`: {ip: {"country": {"iso_code": cc}}} or
                   {ip: {"registered_country": {"iso_code": cc}}}
    `asn_map`: {ip: {"autonomous_system_number": n,
                     "autonomous_system_organization": org}}
    `raise_on`: if set, `.get` raises this exception for these ips.
    """

    def __init__(self, country_map=None, asn_map=None, raise_on=None):
        self.country_map = country_map or {}
        self.asn_map = asn_map or {}
        self.raise_on = set(raise_on or [])

    def get(self, ip):
        if ip in self.raise_on:
            raise RuntimeError("boom")
        if self.country_map:
            return self.country_map.get(ip)
        if self.asn_map:
            return self.asn_map.get(ip)
        return None


# --- goflow2 process stand-in ------------------------------------------------

class FakeGoflow:
    """Records signals sent; optionally raises ProcessLookupError on
    send_signal."""

    def __init__(self, raise_lookup=False):
        self.signals = []
        self._raise_lookup = raise_lookup

    def send_signal(self, sig):
        if self._raise_lookup:
            raise ProcessLookupError("no such process")
        self.signals.append(sig)


def fake_goflow(raise_lookup=False):
    return FakeGoflow(raise_lookup=raise_lookup)


# --- File fixture writers ----------------------------------------------------

def write_flows(path, flows):
    """Write a list of flow dicts as NDJSON (goflow2 json output shape)."""
    import json
    with open(path, "w") as f:
        for flow in flows:
            f.write(json.dumps(flow) + "\n")


def write_alerts(path, records):
    """Write alert records as NDJSON (the shape run_once writes)."""
    import json
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def flow(src, dst, bytes_=4096, packets=5, proto=17, dst_port=53):
    """Build a single flow dict in the goflow2 json shape process_flow reads."""
    return {
        "src_addr": src,
        "dst_addr": dst,
        "bytes": bytes_,
        "packets": packets,
        "proto": proto,
        "dst_port": dst_port,
    }