"""Shared pytest fixtures for netmon.

The single important fixture is `cfg_paths` (autouse): it redirects every
config-sourced path on the `config` module to a per-test tmp_path. Because the
source modules read these via `cfg.<NAME>` at call time (after the refactor),
patching them once here isolates every test — no env-var/reload gymnastics.
"""
import os
import sys

import pytest

# Repo root is where conftest.py lives (alongside the source modules and the
# test_*.py files). Make it importable so `import config`, `import
# flow_analyzer`, etc. resolve (pyproject.toml's [tool.pytest.ini_options] also
# sets pythonpath=.).
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import config  # noqa: E402
import web_server  # noqa: E402


@pytest.fixture(autouse=True)
def cfg_paths(tmp_path, monkeypatch):
    """Redirect all config-sourced paths to a per-test tmp_path and ensure the
    geoip subdir exists. Modules read these via cfg.<NAME> at call time."""
    data_dir = str(tmp_path)
    monkeypatch.setattr(config, "DATA_DIR", data_dir)
    monkeypatch.setattr(config, "STATE_FILE", os.path.join(data_dir, "state.json"))
    monkeypatch.setattr(config, "ALERTS_FILE", os.path.join(data_dir, "alerts.jsonl"))
    monkeypatch.setattr(config, "TI_DB", os.path.join(data_dir, "ti.db"))
    monkeypatch.setattr(config, "METRICS_DB", os.path.join(data_dir, "metrics.db"))
    monkeypatch.setattr(config, "GEOIP_DIR", os.path.join(data_dir, "geoip"))
    monkeypatch.setattr(config, "FLOWS_FILE", os.path.join(data_dir, "flows.jsonl"))
    os.makedirs(os.path.join(data_dir, "geoip"), exist_ok=True)
    yield


@pytest.fixture(autouse=True)
def reset_web_caches():
    """Clear web_server's module-global caches between tests."""
    web_server._DNS_CACHE.clear()
    web_server._HOSTNAMES_MAP = {}
    web_server._HOSTNAMES_MTIME = 0.0
    yield
    web_server._DNS_CACHE.clear()
    web_server._HOSTNAMES_MAP = {}
    web_server._HOSTNAMES_MTIME = 0.0


@pytest.fixture(scope="session", autouse=True)
def _shutdown_dns_executor():
    """web_server creates an idle ThreadPoolExecutor at import; release it once
    the test session is done so the process can exit cleanly."""
    yield
    try:
        web_server._DNS_EXECUTOR.shutdown(wait=False)
    except Exception:
        pass


@pytest.fixture(scope="session")
def netmon_mod():
    """The netmon orchestrator module (netmon.py). Imported lazily so the
    cfg_paths autouse fixture has a chance to redirect config paths first."""
    import netmon
    return netmon