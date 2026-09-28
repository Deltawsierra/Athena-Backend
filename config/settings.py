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


def _env_number(name: str, default):
    """``name`` from the environment as a number of ``default``'s type, or the
    default when it is unset. A value that is not one is kept as given, so
    ``manage.py check`` names it and the code that reads it logs it once and uses
    the default -- rather than every process failing to import its settings."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return type(default)(raw)
    except ValueError:
        return raw


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
    # A refresh spends the refresh token it is given (ROTATE_REFRESH_TOKENS and
    # BLACKLIST_AFTER_ROTATION below did nothing without this app), so a used
    # one no longer verifies -- and is no longer exempt from the gateway and
    # the throttles as a valid refresh (safety.stops).
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",

    # Local apps
    "accounts",
    "audit",
    "detection",
    "pentest",
    "failsafe",
    "assurance",
    # The stop-safety rules (safety.stops); its one table counts sign-in
    # attempts, shared by every worker (safety.sign_in).
    "safety",
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
    # DRF's defaults with its JSON parser swapped for one that answers a body
    # nested past the interpreter's stack with a 400 rather than a 500.
    "DEFAULT_PARSER_CLASSES": (
        "config.parsers.SafeJSONParser",
        "rest_framework.parsers.FormParser",
        "rest_framework.parsers.MultiPartParser",
    ),
    # The failsafe service token first: it authenticates a stop, and nothing
    # else, without a password sign-in (safety.service_token). Anywhere else it
    # is ignored and the JWT decides, as it always has.
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "safety.service_token.FailsafeServiceTokenAuthentication",
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
    # unlimited credential guesses. DRF's own two throttles, except that a stop
    # (safety.stops) is never refused and never counted: they answered 429 to a
    # flooded operator's pause and to the engines' command poll. Sign-in has
    # its own limit on attempts that reach a password hash (safety.sign_in).
    "DEFAULT_THROTTLE_CLASSES": (
        "safety.throttling.StopExemptAnonRateThrottle",
        "safety.throttling.StopExemptUserRateThrottle",
    ),
    "DEFAULT_THROTTLE_RATES": {
        "anon": os.environ.get("DJANGO_THROTTLE_ANON", "30/min"),
        "user": os.environ.get("DJANGO_THROTTLE_USER", "300/min"),
        # Sign-in attempts (safety.sign_in): of one username, as authentication
        # reads it, from one address; and of every username from one address.
        # Each attempt is counted in the database before its password is
        # hashed, atomically and for every worker at once, and refused unhashed
        # past either limit; a successful sign-in is given back.
        "sign_in": os.environ.get("DJANGO_THROTTLE_SIGN_IN", "10/min"),
        "sign_in_address": os.environ.get("DJANGO_THROTTLE_SIGN_IN_ADDRESS", "60/min"),
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
# ASSURANCE COMMERCIAL SPINE — connector / posture credential encryption
# -------------------------------------------------------------------
# The symmetric key that encrypts per-tenant connector and posture credentials at
# rest (assurance.crypto). A Fernet key: URL-safe base64 of 32 random bytes; a
# comma-separated list enables rotation (the first writes new ciphertext, all
# decrypt old). ABSENT BY DEFAULT and deliberately so — with no key, no credential
# can be stored, so every connector and posture binding stays inert and the system
# behaves exactly as it does with no integration configured. A missing key never
# falls back to plaintext. Generate one with:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ASSURANCE_CREDENTIAL_KEY = os.environ.get("ASSURANCE_CREDENTIAL_KEY", "")

# Kill switch for the automated-dispatch signal. Even on (the default), dispatch is
# a no-op unless a deployment has an admin-enabled DispatchPolicy and connector
# bindings — this only lets an operator disable the whole path at once.
ASSURANCE_AUTO_DISPATCH_ENABLED = _env_flag("ASSURANCE_AUTO_DISPATCH_ENABLED", default=True)

# This installation's id in the systems it files issues in (assurance.markers).
# Unset, a random id generated once and kept in the database is used; set it to
# give a database restored into another environment (staging from production) an
# id of its own, so it never adopts the first environment's issues. Never derived
# from DJANGO_SECRET_KEY: rotating that key changes no marker.
ASSURANCE_INSTALLATION_ID = os.environ.get("ASSURANCE_INSTALLATION_ID", "").strip()
# The blocking-decision dispatch a stop owes runs in the background (#303): how
# many runs push at once per process, how many more threads may wait for one, and
# how often the sweeper retries what is still owed (0 turns it off).
ASSURANCE_DISPATCH_MAX_CONCURRENT_RUNS = _env_number("ASSURANCE_DISPATCH_MAX_CONCURRENT_RUNS", 4)
ASSURANCE_DISPATCH_MAX_WAITING_RUNS = _env_number("ASSURANCE_DISPATCH_MAX_WAITING_RUNS", 32)
ASSURANCE_DISPATCH_SWEEP_SECONDS = _env_number("ASSURANCE_DISPATCH_SWEEP_SECONDS", 300.0)
# The wall-clock limit on one whole connector request, in seconds.
ASSURANCE_CONNECTOR_DEADLINE_SECONDS = _env_number("ASSURANCE_CONNECTOR_DEADLINE_SECONDS", 30.0)

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

# The failsafe service credential (safety.service_token): a stop client -- the
# dashboard's server -- presents this in the X-Failsafe-Service-Token header on
# a stop, and is authenticated as FAILSAFE_SERVICE_USER without signing in with
# a password, which a gateway block or a guessing flood could refuse. Accepted
# ONLY on a request that is a stop, or a read of the stop lane; anywhere else
# the header is ignored. At least 32 characters (`openssl rand -hex 32`), or it
# is treated as unset.
FAILSAFE_SERVICE_TOKEN = os.environ.get("FAILSAFE_SERVICE_TOKEN")
FAILSAFE_SERVICE_USER = os.environ.get("FAILSAFE_SERVICE_USER")

# How long the failsafe state view waits, in all, for the engine's live
# governor state before reporting it "not reported". That view is how the
# dashboard's second operator finds a command to sign, so it is bounded.
FAILSAFE_STATE_ENGINE_SECONDS = float(os.environ.get("FAILSAFE_STATE_ENGINE_SECONDS", "2.0"))

# The most unsigned stop drafts one account has awaiting a signature. A stop
# draft is never refused: one past this is made, and that account's OLDEST
# unsigned stop drafts past it are superseded (never another account's, never
# one already carrying a signature). The dashboard's service account is one
# account, so its drafts share this.
FAILSAFE_UNSIGNED_STOP_DRAFTS_PER_ACCOUNT = int(os.environ.get("FAILSAFE_UNSIGNED_STOP_DRAFTS_PER_ACCOUNT", "100"))

# The most bytes of commands one stop-lane read (the failsafe list and state)
# returns; what it leaves out it says, in X-Failsafe-More (and "more" in state).
FAILSAFE_STOP_LANE_READ_BYTES = int(os.environ.get("FAILSAFE_STOP_LANE_READ_BYTES", "1000000"))

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
#
# The timeout is a total deadline on one engine call: connecting, sending, and
# reading the answer. It used to be requests' per-socket timeout, so an engine
# that sent a byte every 0.3 s held each request for as long as it kept sending.
# Past the deadline the request is allowed without a decision, as it is when the
# engine is down (fail open). A stop is never sent to the engine at all
# (safety.stops).
DEFENDER_TIMEOUT_SECONDS = float(os.environ.get("DEFENDER_TIMEOUT_SECONDS", 0.5))
# At most this many engine calls run at once. A call its request stopped waiting
# for can still be running; a request that finds every slot taken waits for one
# only until its own deadline.
DEFENDER_MAX_IN_FLIGHT = int(os.environ.get("DEFENDER_MAX_IN_FLIGHT", 32))
DEFENDER_FAILURE_ALERT_AFTER = int(os.environ.get("DEFENDER_FAILURE_ALERT_AFTER", 10))
DEFENDER_FAILURE_WINDOW_SECONDS = int(os.environ.get("DEFENDER_FAILURE_WINDOW_SECONDS", 60))
DEFENDER_MAX_BODY_BYTES = int(os.environ.get("DEFENDER_MAX_BODY_BYTES", 64 * 1024))
# How many proxies in front of this service append to X-Forwarded-For. Zero
# means the header is not trusted, which is the safe default: it is the only
# key the engine's rate limiter and block table use.
DEFENDER_TRUSTED_PROXY_COUNT = int(os.environ.get("DEFENDER_TRUSTED_PROXY_COUNT", 0))
