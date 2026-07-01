# netmon — MikroTik outbound connection monitor

Pulls Netflow/IPFIX flow records from the MikroTik gateway, matches every outbound flow's destination against a daily-refreshed threat-intel database (Spamhaus DROP, FireHOL level1, abuse.ch Feodo, IPsum L5, Tor exits), tracks a per-device baseline of (ASN, country) pairs, and emails alerts via Resend SMTP.

A few minutes of latency. SQLite on disk. **One container** with a single bind-mounted state directory.

## Architecture

A multi-stage Docker image bundles the upstream `goflow2` Go binary alongside the Python analyzer and updater. A single Python orchestrator is PID 1 — it spawns `goflow2` as a subprocess and runs the analyzer / updater loops as threads in the same process. SIGTERM exits cleanly (status 0); if `goflow2` dies on its own the orchestrator exits with its status so Compose restart-policy kicks in.

```
container netmon
└── /app/netmon  (Python, PID 1)
    ├── goflow2 subprocess
    │     -listen=netflow://:2055 -format=json -transport.file=/data/netmon/flows.jsonl
    ├── thread: ti_updater.loop_forever     (daily TI feeds + GeoLite2 refresh)
    ├── thread: flow_analyzer.loop_forever  (every 2 min)
    ├── thread: daily_summary.loop_forever  (daily digest of new ASNs/countries)
    ├── thread: web_server.loop_forever     (HTTP dashboard on :49210)
    └── thread: rotator                     (rotate flows.jsonl + gzip/prune archives)

bind mount: /data/netmon
    ├── state.json      (cursor, baselines, dedupe — atomically rewritten per tick)
    ├── alerts.jsonl    (append-only alert history)
    ├── ti.db           (threat-intel DB, atomically rebuilt daily)
    ├── metrics.db      (per-device-per-(country|ASN) daily rollups for the dashboard)
    ├── geoip/*.mmdb    (MaxMind GeoLite2)
    └── flows.jsonl     (goflow2 output, rotated by the orchestrator)
```

## Files

| Path | Role |
|------|------|
| `Dockerfile` | Multi-stage: pulls `/goflow2` from `netsampler/goflow2`, base `python:3.12-slim` with `maxminddb` + `geoipupdate` |
| `netmon` | Python orchestrator (PID 1) — spawns goflow2 + runs both loops in threads |
| `flow_analyzer.py` | Importable module: `run_once`, `loop_forever`, `main` |
| `ti_updater.py` | Importable module: `run_once`, `loop_forever`, `main` |
| `daily_summary.py` | Importable module: `loop_forever`, `main` (one-shot prints what would be sent) |
| `web_server.py` | Importable module: `loop_forever`, `main` (stdlib HTTP dashboard + JSON API) |
| `flow-analyzer` / `ti-updater` / `daily-summary` / `web-server` | Thin shell shims for ad-hoc CLI use (`docker exec netmon /app/ti-updater`) |
| `netmon.env` (gitignored, at repo root) | SMTP creds, MaxMind keys, tunables |

## One-time setup

### 1. Host directory

```sh
sudo mkdir -p /data/netmon
sudo chown 0:0 /data/netmon
```

`flows.jsonl` is rotated in-container every `NETMON_FLOWS_ROTATE_SEC` (default 3600 s): the analyzer renames it to `flows.jsonl.<UTC-timestamp>`, SIGHUPs goflow2 to reopen, gzips the archive on the next tick, and prunes oldest beyond `NETMON_FLOWS_RETAIN` (default 4). Manual reopen: `docker kill -s HUP netmon`.

### 2. Create `netmon.env`

Copy the template and fill in your secrets:

```sh
cd /path/to/netmon-repo
cp netmon.env.example netmon.env
chmod 600 netmon.env
$EDITOR netmon.env
```

The minimum required is `NETMON_SMTP_PASSWORD` (Resend API key) for alert delivery and the `MAXMIND_*` pair for GeoIP/ASN enrichment. Everything else has sensible defaults — see `netmon.env.example` for the full list.

New ASN / country first-sightings are auto-accepted: they're appended to `alerts.jsonl` (with `suppressed=1`) and rolled into a single digest email sent once per day at `NETMON_DAILY_SUMMARY_HOUR_UTC` (default `06:00` UTC). The digest also rolls up every threat-intel hit from the past 24 h (deduped per `(dst_ip, sources)` with a count and total bytes) so you get a daily roundup as well as the immediate per-flow alerts. On a day with no TI hits and no new pairs, no digest email is sent. TI matches still email per-flow as before — the digest is a roundup, not a replacement.

Without MaxMind credentials: TI matching still works; ASN/country baseline does not.
Without `NETMON_SMTP_PASSWORD`: alerts are appended to `alerts.jsonl` but no email is sent.

### 3. Build and start

```sh
cd /path/to/netmon-repo
docker-compose up -d --build
```

This repo ships its own `docker-compose.yml` (service `netmon`, `build: .`), so it runs standalone. On the housebot host, the parent `housebotscripts` compose instead points at this repo with `build: ../netmon` / `env_file: ../netmon/netmon.env`, and its `update` script (`docker-compose down && docker-compose up -d --pull always --build`) rebuilds netmon automatically when the source or Dockerfile changes. Either way the container, image, and `/data/netmon` state are identical.

### 4. Configure the MikroTik

```routeros
/ip traffic-flow set enabled=yes interfaces=<wan-iface>
/ip traffic-flow target add dst-address=<docker-host-ip> port=2055 version=ipfix
```

Replace `<wan-iface>` with your actual WAN interface (e.g. `ether1`, `pppoe-out1`, or the WAN bridge — `/ip route print where dst-address=0.0.0.0/0` shows it). On RouterOS 7 `interfaces=` also accepts an `/interface list` name (e.g. a `WAN` list), which is handy for failover. Restricting to the WAN side gives you exactly LAN↔WAN flows and avoids the duplicate ingress+egress records that `interfaces=all` produces.

The container uses `network_mode: host` so UDP/2055 binds directly on the host. Within seconds of LAN→WAN traffic, JSON flow records appear in `/data/netmon/flows.jsonl`.

Caveat: hardware-offloaded bridge / fast-path traffic is invisible to `traffic-flow`; only CPU-routed traffic is exported (covers all WAN-bound flows).

## Tunables (`netmon.env`)

| Variable | Default | Effect |
|----------|---------|--------|
| `NETMON_SMTP_PASSWORD` | unset | Resend API key — required to send alerts |
| `NETMON_SMTP_HOST`/`_PORT`/`_USER`/`_FROM` | smtp.resend.com / 587 / resend / root@admin.lidskialf.net | SMTP overrides |
| `NETMON_RECIPIENT` | adq@lidskialf.net | Where alerts are emailed |
| `NETMON_SUBJECT_PREFIX` | `[house-net]` | Subject line prefix |
| `MAXMIND_ACCOUNT_ID`/`MAXMIND_LICENSE_KEY` | unset | Enable GeoIP/ASN enrichment + baseline detection |
| `NETMON_DAILY_SUMMARY_HOUR_UTC` | `6` | UTC hour (0–23) at which the daily digest of new ASN/country first-sightings is emailed. Empty days are skipped. |
| `NETMON_LOOP_INTERVAL_SEC` | `120` | flow-analyzer tick interval |
| `NETMON_TI_LOOP_INTERVAL_SEC` | `86400` | ti-updater interval (default daily) |
| `NETMON_DEDUPE_HOURS` | `6` | Dedupe window for medium/high alerts |
| `NETMON_DEDUPE_LOW_HOURS` | `24` | Dedupe window for low-severity alerts |
| `NETMON_MIN_BYTES` | `2048` | Skip flows below this byte count (and below `NETMON_MIN_PACKETS`) |
| `NETMON_MIN_PACKETS` | `2` | Combined with `NETMON_MIN_BYTES` |
| `NETMON_EMAIL_MIN_SEVERITY` | `low` | `low`/`medium`/`high` — gate emails by severity |
| `NETMON_ERROR_EMAIL_INTERVAL_SEC` | `3600` | Min spacing between "tick failed" emails |
| `NETMON_FLOWS_ROTATE_SEC` | `3600` | Rotate `flows.jsonl` this often (seconds) |
| `NETMON_FLOWS_RETAIN` | `4` | Number of gzipped archives to keep |
| `NETMON_WEB_LISTEN` | `0.0.0.0:49210` | host:port the dashboard binds to (the container is `network_mode: host`, so this is the host-visible address) |

Reload after edits: `docker-compose restart netmon`.

## Operations

```sh
# Live tail of all four children
docker-compose logs -f netmon

# What's been alerting
tail -20 /data/netmon/alerts.jsonl | jq -c '{ts: (.ts|todate), severity, kind, internal_ip, dst_ip, sources, suppressed}'

# TI feed health (ok=0 = last fetch failed; row_count = currently loaded)
sudo sqlite3 -header -column /data/netmon/ti.db \
  "SELECT source, ok, row_count, datetime(last_fetch_ts,'unixepoch') ts, note FROM ti_meta"

# Per-device baseline (after the soak)
jq '.baseline_asn | to_entries | map({ip: .key, asns: (.value | length)})' /data/netmon/state.json

# Inspect the whole live state
jq . /data/netmon/state.json

# Force a TI refresh now (one-shot run inside the running container)
docker-compose exec netmon /app/ti-updater

# Preview the daily digest body that would be sent for the last 24h (no email, no sentinel touch)
docker-compose exec netmon /app/daily-summary

# Pause without losing state
docker-compose stop netmon

# See what goflow2 is receiving
docker-compose exec netmon tail -f /data/netmon/flows.jsonl
```

Both Python scripts also support a one-shot mode (no `--loop`) for ad-hoc runs and testing.

## Triggering a real alert for testing

The cleanest way to verify the pipeline end-to-end with real traffic (not a synthetic DB insert) is to connect to a Tor exit node from any LAN host. Tor exits are in the `tor-exit` TI feed (severity `low`), the IPs are public and harmless, and they answer on 443 so you'll comfortably clear the `NETMON_MIN_BYTES` / `NETMON_MIN_PACKETS` floor.

```sh
# From a LAN host routed out the MikroTik WAN:
EXIT=$(curl -s https://check.torproject.org/torbulkexitlist | shuf -n1)
echo "hitting $EXIT"
curl -k --max-time 10 https://$EXIT/ -o /dev/null
```

Wait up to `NETMON_LOOP_INTERVAL_SEC` (~2 min) and check:

```sh
tail -5 /data/netmon/alerts.jsonl | jq -c '{ts: (.ts|todate), severity, kind, internal_ip, dst_ip, sources, suppressed}'
```

Gotchas:

- **Dedupe.** Low-severity has a 24 h window (`NETMON_DEDUPE_LOW_HOURS`). Re-test against a different exit IP, or clear `alerts_sent` with `jq '.alerts_sent = {}' state.json | sponge state.json` (stop the container first).
- **Email gate.** If `NETMON_EMAIL_MIN_SEVERITY` is above `low`, the row still lands in `alerts` but no email goes out. For a `high` test, pick from `feodo-tracker` / `firehol-level1` / `spamhaus-drop` — but many of those IPs won't accept connections, so you may not clear the byte threshold; try a few.
- **Source must be a LAN host.** The analyzer skips flows whose src isn't a private address — running the `curl` on the Docker host itself won't trigger if it doesn't egress via the MikroTik WAN export.
- **Fast-path.** Hardware-offloaded traffic is invisible to `traffic-flow`; use a normal CPU-routed LAN client.

To confirm the flow arrived before waiting:

```sh
docker-compose exec netmon tail -f /data/netmon/flows.jsonl | grep "$EXIT"
```

## Web dashboard

A read-only HTTP dashboard runs alongside the analyzer in the same container. It breaks the egress traffic down by **country** and **ASN** over the last 1 / 7 / 30 days, optionally filtered to a single device.

What it shows:

- top-line tiles: total flows, total bytes, distinct countries, distinct ASNs, TI hits in window
- a daily traffic line chart (bytes + flows, for the selected window)
- "by country" and "by ASN" tables, sorted by bytes desc, with proportional bars
- the recent alert log (TI hits, new ASNs, new countries) with severity colouring
- TI feed health (via `/api/health`)

Open it at `http://<docker-host>:49210/` from any LAN client. The page is one self-contained file (vanilla HTML/CSS/JS, inline SVG charts, no CDN). Override the bind via `NETMON_WEB_LISTEN` (e.g. `127.0.0.1:49210` to restrict to the host and front it with a reverse proxy).

### Device names

The dashboard tries to attach a hostname to each device IP. It looks them up in this order:

1. **Static map** at `/data/netmon/hosts` (optional, `/etc/hosts`-style: `IP HOSTNAME` per line, `#` for comments). Reloaded automatically when the file's mtime changes — no restart needed.
2. **Reverse DNS** (`gethostbyaddr`) using the container's resolver, with a 2s batch deadline and TTL caching (1h on success, 5min on failure).

If reverse DNS only finds the docker host itself (`housebot`), your LAN DNS probably doesn't serve PTR records for client devices — that's normal for most home routers. Drop the names into `/data/netmon/hosts` once and they'll show up immediately. Example:

```
# /data/netmon/hosts
192.168.1.1   router
192.168.1.10  kitchen-tv
192.168.1.20  media-server
```

To diagnose the in-container resolver: `docker-compose exec netmon getent hosts <ip>` — empty output means the resolver couldn't (or didn't try to) PTR-lookup that address.

### Data sources

Traffic data is sourced from `/data/netmon/metrics.db` (created lazily on first analyzer tick after upgrade), which holds two rollup tables: `country_daily(date, internal_ip, country, flows, bytes, packets)` and `asn_daily(date, internal_ip, asn, asn_org, flows, bytes, packets)`. `flow_analyzer` does the GeoIP lookup and UPSERTs both tables once per tick. The alert side reads `/data/netmon/alerts.jsonl` directly. There is no auth — the trusted-LAN model matches the rest of the host (gitea, vaultwarden, etc.).

JSON endpoints are also useful for scripts:

```sh
curl -s http://localhost:49210/api/summary?days=7 | jq .
curl -s http://localhost:49210/api/timeseries?days=30 | jq '.buckets'
curl -s http://localhost:49210/api/alerts?days=1&kind=ti-match | jq .
curl -s http://localhost:49210/api/devices | jq .
curl -s http://localhost:49210/api/health | jq .
```

## Phase 2 — DNS visibility (deferred)

To layer DNS on top later, on the MikroTik:

```routeros
/ip dns set log=yes
/system logging action add name=remote-dns target=remote remote=<docker-host-ip> remote-port=514 \
  src-address=<router-lan-ip>
/system logging add topics=dns,!debug action=remote-dns
```

That feeds the existing `remote-syslog.service` (`socat` UDP/514 → journald). A `dns-analyzer` child added to the supervisor would `journalctl -f` the DNS topic, parse `name=… type=…`, and check domains against URLhaus / ThreatFox / HaGeZi blocklists. Note: clients that hardcode `1.1.1.1`/`8.8.8.8` bypass the router's resolver — fix with a NAT redirect rule on port 53 if it becomes a gap.
