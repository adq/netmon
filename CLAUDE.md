# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`netmon` — a self-contained MikroTik outbound connection monitor. One Docker container, built
from this repo (`build: .`, `image: netmon:latest`), `network_mode: host` so UDP/2055 binds the
host directly, with a single bind-mounted state directory at `/data/netmon`. It pulls
Netflow/IPFIX flows from the MikroTik gateway, matches destinations against a daily-refreshed
threat-intel DB, tracks a per-device (ASN, country) baseline, and emails alerts via Resend SMTP.
See `README.md` for the full architecture, data-flow diagram, env vars, and operational recipes —
that is the source of truth; do not duplicate that knowledge here.

## Running it

On this host netmon is run via the parent `housebotscripts` compose, which points at this repo
with `build: ../netmon` / `env_file: ../netmon/netmon.env`. This repo's own `docker-compose.yml`
mirrors that service block with `build: .` so it can also be cloned and run standalone elsewhere.
Either way: `docker-compose up -d --build netmon`.

`netmon.env` is gitignored; `netmon.env.example` is the template.

## Working in this repo

Both Python modules are importable *and* directly runnable (`--loop` for the daemon mode, no
flag for one-shot). The PID-1 orchestrator (`netmon`) spawns `goflow2` as a subprocess and runs
the analyzer / TI-updater / daily-summary / web-server / rotator as threads in the same process.

## Conventions worth keeping

- Python scripts use `#!/usr/bin/python3` (system Python, no venv) and `subprocess.call`/`check_call` for shelling out. There is no test suite, no linter config, no package manifest.
- The image installs `maxminddb` via pip and pulls `goflow2` + `geoipupdate` binaries from upstream images via multi-stage `COPY --from=`. No Python deps beyond `maxminddb`; everything else is stdlib.
- State on disk is load-bearing: `state.json` is atomically rewritten per tick (`.tmp` + `os.replace`), `ti.db` is rebuilt to `.tmp` and atomically swapped (with `.bak` retained for rollback), `flows.jsonl` rotates via rename + SIGHUP to `goflow2`. Preserve those patterns when editing — silent state loss is the failure mode.