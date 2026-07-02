#!/usr/bin/env python3
# Shared configuration for all netmon programs.
#
# Every netmon module (flow_analyzer, ti_updater, daily_summary, web_server, and
# the netmon orchestrator) reads the same NETMON_* environment variables. This
# module is the single place those common reads live, so a default only needs
# fixing once. Only stdlib is imported here, so importing this module can never
# fail regardless of how the environment is configured.

import os
import smtplib
import sys
from email.message import EmailMessage


# --- Paths (NETMON_DATA_DIR is read by every program) -----------------------
DATA_DIR = os.environ.get("NETMON_DATA_DIR", "/data/netmon")
STATE_FILE = os.path.join(DATA_DIR, "state.json")
ALERTS_FILE = os.path.join(DATA_DIR, "alerts.jsonl")
TI_DB = os.path.join(DATA_DIR, "ti.db")
METRICS_DB = os.path.join(DATA_DIR, "metrics.db")
GEOIP_DIR = os.path.join(DATA_DIR, "geoip")
FLOWS_FILE = os.environ.get("NETMON_FLOWS_FILE", os.path.join(DATA_DIR, "flows.jsonl"))


# --- Email / SMTP ------------------------------------------------------------
# RECIPIENT and SMTP_FROM have no default: they are required config. send_email()
# raises if they are unset once SMTP is otherwise configured (see below).
RECIPIENT = os.environ.get("NETMON_RECIPIENT")
SMTP_FROM = os.environ.get("NETMON_SMTP_FROM")
SUBJECT_PREFIX = os.environ.get("NETMON_SUBJECT_PREFIX", "[house-net]")
ERROR_EMAIL_INTERVAL_SEC = int(os.environ.get("NETMON_ERROR_EMAIL_INTERVAL_SEC", "3600"))

SMTP_HOST = os.environ.get("NETMON_SMTP_HOST", "smtp.resend.com")
SMTP_PORT = int(os.environ.get("NETMON_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("NETMON_SMTP_USER", "resend")
SMTP_PASSWORD = os.environ.get("NETMON_SMTP_PASSWORD", "")


def send_email(subject, body):
    if not SMTP_PASSWORD:
        print("NETMON_SMTP_PASSWORD not set; skipping email send", file=sys.stderr)
        return False
    if not RECIPIENT or not SMTP_FROM:
        raise RuntimeError(
            "NETMON_RECIPIENT and NETMON_SMTP_FROM must be set when SMTP is configured")
    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = RECIPIENT
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASSWORD)
            s.send_message(msg)
        return True
    except (smtplib.SMTPException, OSError) as e:
        print(f"SMTP send failed: {e}", file=sys.stderr)
        return False
