"""Tests for config.py: send_email behaviour and env-derived defaults."""
import smtplib

import config


def test_send_email_no_password_returns_false(capsys, monkeypatch):
    monkeypatch.setattr(config, "SMTP_PASSWORD", "")
    assert config.send_email("subj", "body") is False
    assert "NETMON_SMTP_PASSWORD not set" in capsys.readouterr().err


def test_send_email_missing_recipient_raises(monkeypatch):
    monkeypatch.setattr(config, "SMTP_PASSWORD", "secret")
    monkeypatch.setattr(config, "RECIPIENT", None)
    monkeypatch.setattr(config, "SMTP_FROM", "from@example.com")
    try:
        config.send_email("subj", "body")
    except RuntimeError:
        return
    raise AssertionError("expected RuntimeError for missing RECIPIENT")


def test_send_email_missing_from_raises(monkeypatch):
    monkeypatch.setattr(config, "SMTP_PASSWORD", "secret")
    monkeypatch.setattr(config, "RECIPIENT", "to@example.com")
    monkeypatch.setattr(config, "SMTP_FROM", None)
    try:
        config.send_email("subj", "body")
    except RuntimeError:
        return
    raise AssertionError("expected RuntimeError for missing SMTP_FROM")


def test_send_email_success(monkeypatch):
    monkeypatch.setattr(config, "SMTP_PASSWORD", "secret")
    monkeypatch.setattr(config, "RECIPIENT", "to@example.com")
    monkeypatch.setattr(config, "SMTP_FROM", "from@example.com")
    monkeypatch.setattr(config, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(config, "SMTP_PORT", 587)
    monkeypatch.setattr(config, "SMTP_USER", "user")

    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=30):
            sent["host"] = host
            sent["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self):
            sent["starttls"] = True

        def login(self, user, pw):
            sent["login"] = (user, pw)

        def send_message(self, msg):
            sent["msg"] = msg

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    assert config.send_email("the subject", "the body") is True
    assert sent["host"] == "smtp.example.com"
    assert sent["port"] == 587
    assert sent["starttls"] is True
    assert sent["login"] == ("user", "secret")
    assert sent["msg"]["Subject"] == "the subject"
    assert sent["msg"]["To"] == "to@example.com"


def test_send_email_smtp_exception_returns_false(monkeypatch, capsys):
    monkeypatch.setattr(config, "SMTP_PASSWORD", "secret")
    monkeypatch.setattr(config, "RECIPIENT", "to@example.com")
    monkeypatch.setattr(config, "SMTP_FROM", "from@example.com")

    class FakeSMTP:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self):
            raise smtplib.SMTPException("boom")

        def login(self, *a):
            pass

        def send_message(self, *a):
            pass

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    assert config.send_email("subj", "body") is False
    assert "SMTP send failed" in capsys.readouterr().err


def test_send_email_oserror_returns_false(monkeypatch):
    monkeypatch.setattr(config, "SMTP_PASSWORD", "secret")
    monkeypatch.setattr(config, "RECIPIENT", "to@example.com")
    monkeypatch.setattr(config, "SMTP_FROM", "from@example.com")

    class FakeSMTP:
        def __init__(self, *a, **k):
            raise OSError("connection refused")

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    assert config.send_email("subj", "body") is False


def test_env_defaults(monkeypatch):
    """When env vars are unset, config picks its documented defaults."""
    # config is already imported with whatever env was set at import; just
    # assert the documented default constants are sane types/values.
    assert config.SMTP_HOST == "smtp.resend.com"
    assert config.SMTP_PORT == 587
    assert config.SMTP_USER == "resend"
    assert config.SUBJECT_PREFIX == "[house-net]"
    assert config.ERROR_EMAIL_INTERVAL_SEC == 3600
    assert config.STATE_FILE.endswith("state.json")
    assert config.ALERTS_FILE.endswith("alerts.jsonl")
    assert config.TI_DB.endswith("ti.db")
    assert config.METRICS_DB.endswith("metrics.db")
    assert config.GEOIP_DIR.endswith("geoip")
    assert config.FLOWS_FILE.endswith("flows.jsonl")