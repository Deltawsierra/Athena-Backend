import ipaddress
import json
import logging
import re
import threading
import time
import uuid
from urllib.parse import unquote_plus, urlencode

import requests
from django.conf import settings
from django.core.exceptions import RequestDataTooBig
from django.http import JsonResponse, UnreadablePostError

logger = logging.getLogger(__name__)


class RequestMetadataMiddleware:
    """
    Attaches request metadata for audit logging.
    Does NOT write audit logs itself.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.audit_metadata = {
            "request_id": str(uuid.uuid4()),
            "ip_address": client_ip(request),
            "user_agent": request.META.get("HTTP_USER_AGENT", ""),
            "method": request.method,
            "path": request.path,
        }
        return self.get_response(request)


def client_ip(request):
    """
    The caller's address, trusting X-Forwarded-For only behind a known proxy.

    The first value in that header used to be taken unconditionally. Any client
    can set it, and this address is the only key the engine's rate limiter and
    block table use, so a caller could rotate the header to evade rate limiting
    entirely, or forge one request to get somebody else's address blocked.

    Set DEFENDER_TRUSTED_PROXY_COUNT to the number of proxies that append to
    the header in front of this service. Zero, the default, means the header is
    not trusted at all.
    """
    remote = request.META.get("REMOTE_ADDR")
    try:
        depth = int(getattr(settings, "DEFENDER_TRUSTED_PROXY_COUNT", 0) or 0)
    except (TypeError, ValueError):
        # A misconfigured setting used to raise here, on every request.
        logger.error("DEFENDER_TRUSTED_PROXY_COUNT is not a number; not trusting the header")
        depth = 0
    if depth <= 0:
        return remote

    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
    if not hops:
        return remote

    # Count from the right: the rightmost entries were added by our own
    # proxies and are the only ones a client cannot control.
    index = len(hops) - depth
    candidate = hops[index] if 0 <= index < len(hops) else remote

    # Even a trusted position can hold anything the hop in front of it copied
    # in. A value that is not an address was passed on to the engine's block
    # table verbatim, so `1.2.3.4:8080` and `1.2.3.4` were different callers.
    try:
        ipaddress.ip_address(candidate)
    except (ValueError, TypeError):
        return remote
    return candidate


# Request bodies are forwarded to the engine for inspection. These never are:
# the engine learns nothing from a credential that it could not learn from the
# path, and forwarding them puts passwords and refresh tokens into another
# service's logs.
SENSITIVE_PATHS = ("/api/token", "/admin/login", "/api/accounts/users")

# Only these content types are worth inspecting. A multipart upload is skipped:
# forwarding it would copy the whole file into another service.
INSPECTABLE_TYPES = ("application/json", "application/x-www-form-urlencoded", "text/plain")

# Paths that never carry an attack worth a synchronous round trip.
#
# "/api/detection/defender/" is here for a different reason: it is the log
# analysis endpoint, so its body is attack text the analyst deliberately
# submitted for inspection. Scoring it as the caller's own behaviour meant
# pasting one hostile log line got the analyst's address blocked from the whole
# platform. Content a user submits for analysis is not conduct.
SKIP_PREFIXES = (
    "/static/",
    "/media/",
    "/admin/jsi18n/",
    "/api/health/",
    "/api/detection/defender/",
)

# Key fragments whose values are replaced before the body is forwarded.
_SENSITIVE_KEY_PARTS = (
    "pass", "pwd", "secret", "token", "authorization", "auth", "api_key", "apikey",
    "api-key", "credential", "session", "cookie", "private_key", "privatekey",
    "otp", "mfa", "totp", "ssn", "signature", "client_secret",
)

REDACTED = "[redacted]"

# Every spelling of "no". Reading only "block" meant "deny" was permission,
# which is the failure the explicit `allow` boolean was added to prevent and
# which the comment in __call__ already claimed to have fixed.
_BLOCKING_ACTIONS = frozenset({"block", "blocked", "deny", "denied", "refuse", "refused", "reject", "rejected"})


def _is_sensitive_key(key):
    lowered = str(key).lower()
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def _redact_structure(value):
    """Replace every value under a sensitive key, at any depth and of any type."""
    if isinstance(value, dict):
        return {
            key: (REDACTED if _is_sensitive_key(key) else _redact_structure(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_structure(item) for item in value]
    return value


# Fallback for text that is neither valid JSON nor a form body: a JSON-ish
# "key": value pair, or a bare key=value / key: value pair. The value runs to
# the end of the line for a colon (so `Authorization: Bearer x` loses the whole
# credential, not just the word "Bearer") and to the next separator otherwise.
#
# A SCAN, not one regex. The single pattern this replaces put a sensitive-part
# alternation between two unbounded runs of key characters -- a class that
# includes `[` and `]` -- and could start at every position inside a run. A body
# of brackets that is not JSON (so the structured path fails) took quadratic time
# with a large constant: eight kilobytes held a worker for seven seconds, before
# authentication, on any route. Here a key token may only START where a run of
# key characters starts, so each run is tried once; whether it names a secret is
# decided in Python, and the value is matched once, anchored where the key ends.
_KEY_CHARS = r"A-Za-z0-9_.\[\]-"
_TEXT_KEY_BODY = r'("?)([' + _KEY_CHARS + r']+)\1\s*([:=])\s*'
# Anywhere a run of key characters starts ...
_TEXT_KEY = re.compile(r'("?)(?<![' + _KEY_CHARS + r'])([' + _KEY_CHARS + r']+)\1\s*([:=])\s*')
# ... or exactly where the scan resumes, which may be mid-run: a value stops at
# `]`, and the pattern this replaces let the next key begin on that `]`.
_TEXT_KEY_HERE = re.compile(_TEXT_KEY_BODY)
_SENSITIVE_TEXT_PART = re.compile(
    "|".join(part.replace("_", "[_-]?") for part in _SENSITIVE_KEY_PARTS), re.I
)
_TEXT_VALUE = {
    ":": re.compile(r'"(?:\\.|[^"\\])*"|[^\r\n,}\]]+'),
    "=": re.compile(r'"(?:\\.|[^"\\])*"|[^&;\r\n]+'),
}


def _text_value(text, key):
    """The value after a sensitive key, or ``None``.

    Tried where the whitespace after the separator ends, then -- as the pattern
    this replaces did by backtracking -- at each earlier position back to the
    separator. Every failed attempt there is at a line break, which fails at its
    first character, so this stays linear.
    """
    pattern = _TEXT_VALUE[key.group(3)]
    for start in range(key.end(), key.end(3) - 1, -1):
        value = pattern.match(text, start)
        if value is not None:
            return value
    return None


def _redact_text(text):
    """``text`` with the value after every sensitive ``key:`` / ``key=`` replaced.

    Linear in the length of ``text``: see the note above ``_TEXT_KEY``.
    """
    out = []
    pos = 0
    while True:
        key = _TEXT_KEY_HERE.match(text, pos) or _TEXT_KEY.search(text, pos)
        if key is None:
            break
        value = _text_value(text, key) if _SENSITIVE_TEXT_PART.search(key.group(2)) else None
        if value is None:
            # Not a secret, or a secret with nothing after it: kept verbatim, and
            # the scan resumes after the separator, where the next key can start.
            out.append(text[pos:key.end()])
            pos = key.end()
            continue
        quote = key.group(1)
        out.append(text[pos:key.start()])
        out.append(f"{quote}{key.group(2)}{quote}: {REDACTED}")
        pos = value.end()
    out.append(text[pos:])
    return "".join(out)


def _redact_form(text):
    """
    A form body or query string with sensitive values replaced.

    Each pair is rewritten in place rather than re-encoded, so an attack
    payload in a harmless field reaches the engine exactly as the client sent
    it. Re-encoding the whole string percent-escaped the very characters the
    engine is looking for.
    """
    out = []
    for chunk in text.split("&"):
        key, sep, _value = chunk.partition("=")
        if sep and _is_sensitive_key(unquote_plus(key)):
            out.append(f"{key}={REDACTED}")
        else:
            out.append(chunk)
    return "&".join(out)


def redact(text, form=False):
    """
    The text with credential values removed, whatever shape it is in.

    The previous version was a single regex over a JSON string value, so a
    form-encoded body, a bearer token in plain text, a non-string JSON value,
    a key with an escaped quote in its value, and a body in any encoding other
    than UTF-8 all forwarded the secret verbatim to another service.

    `form` says the caller knows this is urlencoded (a form body, or a query
    string). It is not guessed: prose containing an "=" was being parsed as a
    form and re-encoded, which destroyed the attack signal the engine is asked
    to look for.
    """
    if not text:
        return text

    if form:
        return _redact_form(text)

    stripped = text.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            return json.dumps(_redact_structure(json.loads(text)), separators=(",", ":"))
        except (ValueError, TypeError, RecursionError):
            pass

    return _redact_text(text)


class DefenderMiddleware:
    """
    Thin enforcement layer.
    NO AI logic lives here.
    Calls the Cybersecurity AI Engine and enforces its decision.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.engine_url = settings.CYBERENGINE_URL.rstrip("/")
        self.operator_key = settings.CYBERENGINE_OPERATOR_KEY
        self.monitor_only = getattr(settings, "DEFENDER_MONITOR_ONLY", True)
        self.timeout = getattr(settings, "DEFENDER_TIMEOUT_SECONDS", 0.5)
        self.failure_alert_threshold = getattr(settings, "DEFENDER_FAILURE_ALERT_AFTER", 10)
        self.failure_window = getattr(settings, "DEFENDER_FAILURE_WINDOW_SECONDS", 60)
        self.max_body_bytes = getattr(settings, "DEFENDER_MAX_BODY_BYTES", 64 * 1024)

        # Failures within a window, not consecutive ones. A counter reset by
        # every success never escalates on a half-dead engine, which is the
        # common case: half the traffic can go uninspected without a word.
        # One middleware instance serves every worker thread, and the window
        # was a read-modify-write across two statements: under load most
        # failures were lost, so the alert fired late or not at all exactly
        # when an outage mattered most.
        self._lock = threading.Lock()
        self._recent_failures = []
        # None, not 0.0. time.monotonic() counts from an arbitrary point,
        # which on a freshly booted machine is near zero, so a 0.0 sentinel
        # read as "alerted a moment ago" and suppressed the first alert.
        self._last_alert = None
        self._last_outcome_failed = False

        if not self.operator_key:
            logger.error(
                "CYBERENGINE_OPERATOR_KEY is not set: the defender middleware "
                "will allow every request without asking the engine."
            )

    def __call__(self, request):
        if request.path.startswith(SKIP_PREFIXES):
            return self.get_response(request)

        meta = getattr(request, "audit_metadata", {})
        body, body_problem = self._get_body(request)

        ctx = {
            "ip": meta.get("ip_address") or client_ip(request),
            "path": meta.get("path") or request.path,
            "method": meta.get("method") or request.method,
            "user_agent": request.META.get("HTTP_USER_AGENT", ""),
            # The query string was copied through with no redaction at all, so
            # ?token=... reached the engine in clear while the same value in
            # the body was replaced.
            "query": redact(request.META.get("QUERY_STRING", ""), form=True),
            "body": body,
        }

        if body_problem:
            # A body we could not read is not an empty body. Saying so is the
            # difference between "nothing suspicious" and "not inspected".
            self._record_failure(body_problem)

        decision = self._ask_engine(ctx)
        if not decision:
            return self.get_response(request)

        action = str(decision.get("action", "allow")).strip().lower()

        # The engine sends an explicit boolean. Reading only the action string
        # meant any spelling it did not recognise, including "deny" or "BLOCK",
        # was treated as permission.
        refused = decision.get("allow") is False or action in _BLOCKING_ACTIONS
        throttled = action == "throttle"

        if refused:
            if self.monitor_only:
                logger.warning(
                    "Defender would have blocked %s %s from %s (%s); monitor mode is on",
                    ctx["method"], ctx["path"], ctx["ip"], decision.get("reason"),
                )
                return self.get_response(request)
            return JsonResponse(
                {
                    "detail": "Request blocked by AI Defender",
                    "reason": decision.get("reason"),
                },
                status=403,
            )

        if throttled:
            if self.monitor_only:
                logger.info(
                    "Defender would have throttled %s %s from %s; monitor mode is on",
                    ctx["method"], ctx["path"], ctx["ip"],
                )
                return self.get_response(request)
            # Sleeping here spent a worker on the caller's behalf, which turns
            # a rate-limit signal into a self-inflicted denial of service.
            response = JsonResponse({"detail": "Rate limited"}, status=429)
            response["Retry-After"] = str(int(decision.get("block_seconds") or 1))
            return response

        if action not in ("allow", ""):
            logger.warning("Defender returned an unrecognised action %r; allowing", action)

        return self.get_response(request)

    def _ask_engine(self, ctx):
        """
        Ask the engine for a decision.

        Returning None means "no decision", and the caller then allows the
        request. That is the right default for a gateway, but it used to happen
        in complete silence: a wrong header, an expired key or an engine that
        was simply down turned this defensive layer off and nothing said so.
        """
        try:
            response = requests.post(
                f"{self.engine_url}/defend",
                json=ctx,
                headers={
                    # The engine authenticates every privileged route on
                    # X-API-Key. It still accepts the old X-Operator-Key for
                    # now, but that spelling is deprecated.
                    "X-API-Key": self.operator_key,
                    "Content-Type": "application/json",
                },
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            self._record_failure(f"engine unreachable: {exc.__class__.__name__}")
            return None

        if response.status_code == 200:
            try:
                decision = response.json()
            except ValueError:
                self._record_failure("engine returned a body that is not JSON")
                return None

            # Valid JSON of the wrong shape used to reach decision.get() and
            # raise, turning a bad engine response into a 500 on every request.
            if not isinstance(decision, dict):
                self._record_failure("engine returned a decision that is not an object")
                return None

            self._note_success()
            return decision

        if response.status_code in (401, 403):
            self._record_failure(
                "engine refused the operator key (check CYBERENGINE_OPERATOR_KEY)"
            )
        else:
            self._record_failure(f"engine returned HTTP {response.status_code}")
        return None

    def _get_body(self, request):
        """
        The part of the body worth inspecting, and why it was skipped.

        Returns (body, problem). A problem is a reason the request could not be
        inspected, and is recorded as a failure. Reading the body used to sit
        inside a bare except, so a request larger than
        DATA_UPLOAD_MAX_MEMORY_SIZE raised, was swallowed, and reached the
        engine as an empty body: padding a payload past that limit walked past
        inspection with nothing logged.
        """
        if request.path.startswith(SENSITIVE_PATHS):
            return "", None

        content_type = (request.META.get("CONTENT_TYPE") or "").split(";")[0].strip().lower()

        if content_type == "multipart/form-data":
            # Skipping multipart entirely was a complete bypass: the same
            # payload that was inspected as JSON went uninspected as a form.
            # The ordinary fields are read; request.FILES is not, so an upload
            # is still never copied into another service.
            try:
                fields = list(request.POST.items())
            except Exception as exc:  # noqa: BLE001 - the audit trail must never crash the request it is recording
                return "", f"multipart body could not be inspected: {exc.__class__.__name__}"
            if not fields:
                return "", None
            return self._trim(
                redact(urlencode([(key, value) for key, value in fields]), form=True)
            )

        if content_type and content_type not in INSPECTABLE_TYPES:
            return "", None

        try:
            raw = request.body
        except (RequestDataTooBig, UnreadablePostError) as exc:
            return "", f"request body could not be inspected: {exc.__class__.__name__}"
        except Exception as exc:  # noqa: BLE001 - the known cases are narrowed above; this is the last resort, and it reports rather than hides
            return "", f"request body could not be read: {exc.__class__.__name__}"

        if not raw:
            return "", None

        text = raw.decode("utf-8", errors="ignore")

        # Redact first, then truncate. The other order let a secret straddling
        # the size limit lose its closing quote, miss the pattern, and be
        # forwarded in clear.
        text = redact(text, form=content_type == "application/x-www-form-urlencoded")
        return self._trim(text)

    def _trim(self, text):
        if len(text) > self.max_body_bytes:
            # Truncation used to be silent, so a padded payload was inspected
            # in its first 64 KiB and reported as a clean inspection: the same
            # walk-past-inspection this method already fixed once, at a lower
            # threshold.
            return (
                text[: self.max_body_bytes],
                f"request body was truncated at {self.max_body_bytes} bytes for inspection",
            )
        return text, None

    def _note_success(self):
        # The window is deliberately not cleared here. Clearing it on every
        # success is what made a half-dead engine invisible: alternating
        # failure and success never reached the threshold, so half the traffic
        # could go uninspected without one line in the log.
        if self._last_outcome_failed:
            self._last_outcome_failed = False
            logger.info("Defender engine is answering again")

    def _record_failure(self, reason):
        now = time.monotonic()

        with self._lock:
            self._last_outcome_failed = True
            self._recent_failures = [
                at for at in self._recent_failures if now - at < self.failure_window
            ]
            self._recent_failures.append(now)
            failures = len(self._recent_failures)
            escalate = failures >= self.failure_alert_threshold and (
                self._last_alert is None or now - self._last_alert >= self.failure_window
            )
            if escalate:
                self._last_alert = now

        if failures < self.failure_alert_threshold:
            logger.warning("Defender engine gave no decision: %s", reason)
            return

        # Escalate, but not once per request: a real outage would otherwise
        # fill the log at request rate. Between escalations the count keeps
        # rising and is reported with the next one, so a continuing outage is
        # never silent about its size.
        if escalate:
            logger.error(
                "Defender engine unavailable for %s of the last %ss: %s. "
                "Requests are being allowed without a decision.",
                failures,
                self.failure_window,
                reason,
            )
