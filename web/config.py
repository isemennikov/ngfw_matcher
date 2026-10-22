"""Runtime configuration from environment (12-factor).

All values are read once at import time. Secrets must come from the
environment / secret manager in production; for local development an
ephemeral random key is generated if NGFW_SECRET_KEY is not set.
"""
from __future__ import annotations

import logging
import os
import secrets

log = logging.getLogger("ngfw.config")

# ── Session signing key ──────────────────────────────────────────────────────
# Used only by starlette SessionMiddleware as the HMAC key for the signed
# session cookie. In production set NGFW_SECRET_KEY (32+ random bytes) via
# the environment / secret manager.
SECRET_KEY = os.environ.get("NGFW_SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_urlsafe(48)
    log.warning(
        "NGFW_SECRET_KEY is not set — generated an ephemeral key. "
        "Sessions will be invalidated on restart. Set NGFW_SECRET_KEY in production."
    )

# ── Session cookie ───────────────────────────────────────────────────────────
SESSION_MAX_AGE = int(os.environ.get("NGFW_SESSION_MAX_AGE", str(12 * 3600)))
# App is served over plain HTTP inside a local Docker network for now, so
# https_only stays off. Enable it (NGFW_COOKIE_SECURE=1) once behind TLS.
COOKIE_HTTPS_ONLY = os.environ.get("NGFW_COOKIE_SECURE", "0") == "1"

# ── Upstream PT NGFW API ─────────────────────────────────────────────────────
# Default False preserves current behaviour (SU often uses self-signed certs).
# Set NGFW_VERIFY_SSL=1 to enforce certificate validation.
VERIFY_SSL = os.environ.get("NGFW_VERIFY_SSL", "0") == "1"

# ── Uploads ──────────────────────────────────────────────────────────────────
# Max size of an uploaded snapshot JSON, bytes (default 64 MiB).
MAX_UPLOAD_BYTES = int(os.environ.get("NGFW_MAX_UPLOAD_MB", "64")) * 1024 * 1024

# ── Server bind (used by the `ngfw-matcher-web` entry point) ───────────────────
HOST = os.environ.get("NGFW_HOST", "127.0.0.1")
PORT = int(os.environ.get("NGFW_PORT", "8080"))

# ── Rule date badges ─────────────────────────────────────────────────────────
# Порог «недавно изменено» для метки updatedAt: правило подсвечивается, если
# правилось не позже N дней назад.
RULE_RECENT_DAYS = int(os.environ.get("NGFW_RULE_RECENT_DAYS", "30"))


def warn_if_insecure() -> None:
    if not VERIFY_SSL:
        log.warning("NGFW_VERIFY_SSL is off — upstream TLS certificates are not validated.")
    if not COOKIE_HTTPS_ONLY:
        log.warning("Session cookie is not marked Secure (HTTP/local mode).")
