import json
import os
import secrets

from django.core.exceptions import ImproperlyConfigured
from pathlib import Path
from datetime import timedelta

BASE_DIR = Path(__file__).resolve().parent.parent

# -------------------------------------------------------------------
# SECURITY
# -------------------------------------------------------------------

def _env_flag(name: str, default: bool = False) -> bool:
    return os.environ.get(name, "1" if default else "0").lower() in ("1", "true", "yes", "on")


def _env_list(name: str, default: str = "") -> list:
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


# DEBUG was hardcoded True with no way to turn it off short of editing this
# file, so any unhandled exception returned a traceback carrying settings, SQL
# and local variables. It is now off unless the environment asks for it.
DEBUG = _env_flag("DJANGO_DEBUG", default=False)

# The signing key for sessions, password reset tokens and, because SIMPLE_JWT
# sets no SIGNING_KEY of its own, every JWT this service issues. A fallback
# lived here in source, which meant anyone who could read the repository could
# mint tokens for any account. Development gets an ephemeral key instead.
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY must be set. It signs sessions and every JWT."
        )
    SECRET_KEY = secrets.token_urlsafe(64)

# Empty is a silent localhost-only setting under DEBUG and a total outage the
# moment DEBUG is turned off, so development gets a working default.
ALLOWED_HOSTS = _env_list("DJANGO_ALLOWED_HOSTS") or (
    ["localhost", "127.0.0.1", "[::1]"] if DEBUG else []
)

# Transport and cookie hardening. None of this was set, so `manage.py check
# --deploy` reported seven warnings. Each is enabled outside development, where
# a plain-HTTP dev server would otherwise be unusable.
SECURE_SSL_REDIRECT = _env_flag("DJANGO_SECURE_SSL_REDIRECT", default=not DEBUG)
SECURE_HSTS_SECONDS = 0 if DEBUG else int(os.environ.get("DJANGO_HSTS_SECONDS", 31536000))
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = not DEBUG
CSRF_TRUSTED_ORIGINS = _env_list("DJANGO_CSRF_TRUSTED_ORIGINS")
X_FRAME_OPTIONS = "DENY"

# Bound what a single request may submit, so a large body cannot be used to
# exhaust memory. The defender middleware reads request bodies.
DATA_UPLOAD_MAX_MEMORY_SIZE = int(os.environ.get("DJANGO_MAX_BODY_BYTES", 10 * 1024 * 1024))
DATA_UPLOAD_MAX_NUMBER_FIELDS = 1000

# -------------------------------------------------------------------
# APPLICATIONS
# -------------------------------------------------------------------

INSTALLED_APPS = [
    # Django core
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # Third-party
    "rest_framework",
    "rest_framework_simplejwt",
    "corsheaders",

    # Local apps
    "accounts",
    "audit",
    "detection",
    "pentest",
    "failsafe",
]

# -------------------------------------------------------------------
# MIDDLEWARE
# -------------------------------------------------------------------

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",

    # Audit request metadata (IP, UA, path, method, request_id)
    "audit.middleware.RequestMetadataMiddleware",
    "audit.middleware.DefenderMiddleware",

    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# -------------------------------------------------------------------
# URL / WSGI / ASGI
# -------------------------------------------------------------------

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# -------------------------------------------------------------------
# DATABASE
# -------------------------------------------------------------------

# SQLite with the settings a server needs.
#
# The defaults are the ones for a single-user desktop program: rollback
# journal, so one writer blocks every reader; no busy timeout, so a second
# concurrent write raises "database is locked" immediately instead of waiting;
# and deferred transactions, which take the write lock partway through and
# cannot wait for it even when a timeout is set. Twenty concurrent scans
# produced sixteen OperationalErrors on the stock configuration.
#
# WAL lets readers proceed while a writer holds the database, IMMEDIATE takes
# the write lock at the start of the transaction so the timeout applies to it,
# and the timeout gives a contending writer twenty seconds rather than none.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("DJANGO_DB_PATH") or BASE_DIR / "db.sqlite3",
        "OPTIONS": {
            "timeout": float(os.environ.get("DJANGO_DB_TIMEOUT", 20)),
            "transaction_mode": "IMMEDIATE",
            "init_command": "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;",
        },
    }
}

# -------------------------------------------------------------------
# AUTH / RBAC
# -------------------------------------------------------------------

AUTH_USER_MODEL = "accounts.CustomUser"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# -------------------------------------------------------------------
# REST FRAMEWORK / JWT
# -------------------------------------------------------------------

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    # List endpoints returned every row. A hundred and fifty scans came back in
    # one response, and nothing bounded it.
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
    # There was no rate limiting anywhere, so the token endpoint accepted
    # unlimited credential guesses.
    "DEFAULT_THROTTLE_CLASSES": (
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ),
    "DEFAULT_THROTTLE_RATES": {
        "anon": os.environ.get("DJANGO_THROTTLE_ANON", "30/min"),
        "user": os.environ.get("DJANGO_THROTTLE_USER", "300/min"),
    },
    # Without this, DRF's throttles key anonymous callers on the whole raw
    # X-Forwarded-For header, so rotating one header defeated the rate limit
    # on the token endpoint entirely. This is the same trust depth the audit
    # middleware uses; zero means the header is not trusted at all and
    # REMOTE_ADDR is the key.
    "NUM_PROXIES": int(os.environ.get("DEFENDER_TRUSTED_PROXY_COUNT", 0)),
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "AUTH_HEADER_TYPES": ("Bearer",),
    # Stated rather than inherited. SimpleJWT falls back to SECRET_KEY, which
    # had a published default in this file, so anyone who could read the
    # repository could mint a token for any account.
    "SIGNING_KEY": SECRET_KEY,
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
}

# -------------------------------------------------------------------
# INTERNATIONALIZATION
# -------------------------------------------------------------------

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# -------------------------------------------------------------------
# STATIC / MEDIA
# -------------------------------------------------------------------

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# -------------------------------------------------------------------
# EMAIL (DEV SAFE)
# -------------------------------------------------------------------

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
# Credentials come from the environment only. A live Google app password was
# committed here as a default argument, which put the company mailbox in the
# hands of anyone with read access to this repository. Revoke and reissue any
# password that was ever a default in this file.
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
DEFAULT_FROM_EMAIL = "Mythos AI Security <noreply@infoai.local>"

# -------------------------------------------------------------------
# CORS
# -------------------------------------------------------------------

# Every origin was allowed. Bearer authentication meant it was not directly
# exploitable, but it removes a layer and reads as a red flag in any customer
# security review.
CORS_ALLOWED_ORIGINS = _env_list("DJANGO_CORS_ALLOWED_ORIGINS")
CORS_ALLOW_ALL_ORIGINS = DEBUG and not CORS_ALLOWED_ORIGINS

# -------------------------------------------------------------------
# EXTERNAL CYBERSECURITY AI ENGINE (ONLY AI CONFIG DJANGO SHOULD HAVE)
# -------------------------------------------------------------------

CYBERENGINE_URL = os.environ.get(
    "CYBERENGINE_URL",
    "http://127.0.0.1:8001",
)

CYBERENGINE_OPERATOR_KEY = os.environ.get("CYBERENGINE_OPERATOR_KEY")

# Whether a scan is refused when the engine is not the deployment that was
# approved. Defaults to observe, matching the engine's own extension gate: a
# gate that blocks on the day it is switched on, in a deployment nobody has
# approved yet, is one somebody turns off -- and a gate that is off is worse
# than no gate, because the record says it was on. In observe a blocked
# verdict is logged and the scan proceeds, so the record shows what would
# have been refused before anyone relies on it refusing.
CYBERENGINE_ASSURANCE_MODE = os.environ.get("CYBERENGINE_ASSURANCE_MODE", "observe")

# -------------------------------------------------------------------
# FAILSAFE CONTROL PLANE (operator-held pause / stand down / terminate)
# -------------------------------------------------------------------
# Enrolled operator PUBLIC keys, key_id -> hex ed25519, as a JSON object in the
# env. These MUST match the keys the engine is configured with, or a command
# this plane calls "ready" would be refused by the engine. This plane holds no
# private key -- operators sign out of band with the mythos-failsafe CLI.
FAILSAFE_OPERATOR_KEYS = json.loads(os.environ.get("FAILSAFE_OPERATOR_KEYS", "{}"))

# Optional per-action signature-count overrides, action -> int. Unset actions
# use the library defaults (pause/resume 1; stand_down/release/terminate 2 --
# the two-person rule).
FAILSAFE_THRESHOLDS = json.loads(os.environ.get("FAILSAFE_THRESHOLDS", "{}"))

# How long a drafted command stays signable / servable before it expires. Short
# by design: a command is an emergency instruction, not a standing grant.
FAILSAFE_COMMAND_TTL_SECONDS = int(os.environ.get("FAILSAFE_COMMAND_TTL_SECONDS", "600"))

# Shared token the engine presents when polling /api/failsafe/pending. The
# engine is not an operator, so it authenticates with this rather than a JWT.
FAILSAFE_POLL_TOKEN = os.environ.get("FAILSAFE_POLL_TOKEN")

# -------------------------------------------------------------------
# AI DEFENDER (SAFE MODE) NOT AI LOGIC JUST A SAFETY SWITCH
# -------------------------------------------------------------------

# Monitor mode logs what would have been blocked and blocks nothing. It was
# hardcoded True with no override, so the whole enforcement path shipped dead:
# there was no way to turn the defender on without editing this file.
DEFENDER_MONITOR_ONLY = _env_flag("DEFENDER_MONITOR_ONLY", default=True)


# -------------------------------------------------------------------
# LOGGING
# -------------------------------------------------------------------
# There was no logging configuration at all, so the defender middleware's
# alerts fell through to Python's last-resort stderr handler at WARNING: no
# timestamp, no rotation, nothing to alert on, and every info-level line about
# the engine recovering was discarded.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
        },
    },
    "root": {"handlers": ["console"], "level": os.environ.get("DJANGO_LOG_LEVEL", "INFO")},
    "loggers": {
        # The gateway's decisions and failures are operational signal.
        "audit": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "django.request": {"handlers": ["console"], "level": "WARNING", "propagate": False},
    },
}

# -------------------------------------------------------------------
# DEFENDER MIDDLEWARE
# -------------------------------------------------------------------
# These were read through getattr defaults with nothing in settings, so an
# operator had no way to discover they were tunable.
DEFENDER_TIMEOUT_SECONDS = float(os.environ.get("DEFENDER_TIMEOUT_SECONDS", 0.5))
DEFENDER_FAILURE_ALERT_AFTER = int(os.environ.get("DEFENDER_FAILURE_ALERT_AFTER", 10))
DEFENDER_FAILURE_WINDOW_SECONDS = int(os.environ.get("DEFENDER_FAILURE_WINDOW_SECONDS", 60))
DEFENDER_MAX_BODY_BYTES = int(os.environ.get("DEFENDER_MAX_BODY_BYTES", 64 * 1024))
# How many proxies in front of this service append to X-Forwarded-For. Zero
# means the header is not trusted, which is the safe default: it is the only
# key the engine's rate limiter and block table use.
DEFENDER_TRUSTED_PROXY_COUNT = int(os.environ.get("DEFENDER_TRUSTED_PROXY_COUNT", 0))
