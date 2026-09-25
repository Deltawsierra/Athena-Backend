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
    """Whether ``key`` names a secret -- the ONE judgement every path uses.

    casefold, not lower: "paſſword".lower() keeps the ſ, and "paßword" only
    becomes "password" when folded. And both spellings of each part: the plain
    substring ("private_key") and the text path's separator-tolerant pattern
    ("private-key"). Three predicates had drifted apart, so a key one path
    redacted another forwarded."""
    text = str(key)
    lowered = text.casefold()
    # The pattern runs on the raw key: it is compiled re.I, which already matches
    # ſ, K and İ, and none of its separator-tolerant spellings (private-key,
    # api-key, client-secret) holds a letter that casefolding expands.
    return (
        any(part in lowered for part in _SENSITIVE_KEY_PARTS)
        or _SENSITIVE_TEXT_PART.search(text) is not None
    )


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
# FAIL CLOSED. Text on this path is by definition not well formed, and seven
# rounds of point fixes each found another shape whose value the scanner ended
# too early: a quote the cut left open, `[Summer]2024-S3CR3T`, SQL's `'o''x'`,
# a key that lost its opening quote. So a value keeps a precise end only when a
# delimiter plainly follows it -- a comma, `&`, `;`, a line break, the end of the
# text, or whitespace and then the next key. Anything else means the scanner
# cannot tell where the secret stops, and the value is redacted to the end of its
# line; that is reported, so a sensitive key planted in front of an attack cannot
# quietly blind the engine to it.
#
# A SCAN, not one regex. The single pattern this replaces put a sensitive-part
# alternation between two unbounded runs of key characters -- a class that
# includes `[` and `]` -- and could start at every position inside a run. A body
# of brackets that is not JSON (so the structured path fails) took quadratic time
# with a large constant: eight kilobytes held a worker for seven seconds, before
# authentication, on any route. Here a key token may only START where a run of
# key characters starts, so each run is tried once; whether it names a secret is
# decided in Python, and the value is matched once, anchored where the key ends.
# `\w`, not `A-Za-z0-9_`: a key in any script is one token. With ASCII only,
# "Passwörter=hunter2" split at the ö into "Passw" and "rter", neither of which
# the separator follows, and the value went through.
_KEY_CHARS = r"\w.\[\]-"
# A key may be bare, double-quoted, or single-quoted: `{'password': 'x'}` is not
# JSON, so it reaches this path. The closing quote need not match the opening
# one, or have one at all: `{password": "x"}` -- a key that lost its opening
# quote -- was read by nothing, and its value went through.
#
# Case-insensitive, as the pattern it replaces was: under re.I, [A-Za-z] also
# matches the letters whose case folds into ASCII (ſ U+017F -> s, K U+212A -> k),
# so "paſſword=hunter2" was one key token and redacted. Without it the ſ split
# the token and the secret went through.
_TEXT_KEY = re.compile(
    r'(["\']?)(?<![' + _KEY_CHARS + r'])([' + _KEY_CHARS + r']+)(["\']?)\s*([:=])\s*', re.I
)
_SENSITIVE_TEXT_PART = re.compile(
    "|".join(part.replace("_", "[_-]?") for part in _SENSITIVE_KEY_PARTS), re.I
)
# A quoted string, POSSESSIVELY: `"[^"\\]*+(?:\\.[^"\\]*+)*+"`. The alternation it
# replaces, `"(?:[^"\\]|\\.)*"`, makes Python's engine keep backtracking state for
# every character it matches -- about 120 bytes each, so one 10 MB string in a
# request body took 1.3 GB before authentication. The possessive form keeps
# none: a run of ordinary characters is taken whole and never given back, which
# is all a string needs, since the only way out of one is its closing quote.
# DOTALL, so a backslash-newline is an escape like any other and does not end
# the string early -- a value cut there left the rest of the secret in clear.
_STRINGS = {
    '"': re.compile(r'"[^"\\]*+(?:\\.[^"\\]*+)*+"', re.S),
    "'": re.compile(r"'[^'\\]*+(?:\\.[^'\\]*+)*+'", re.S),
}
# A value that is neither quoted nor bracketed runs to the end of its line after
# a colon, or to the next pair after an equals sign.
_UNQUOTED = {
    ":": re.compile(r"[^\r\n,}\]]+"),
    "=": re.compile(r"[^&;\r\n]+"),
}
_OPENERS = "[{"
_CLOSERS = "]}"
# What may follow a value whose end is certain: any closing brackets, then a
# delimiter or the end of the text -- or whitespace and the next key, as in
# `password="x" q="UNION SELECT"`.
_AFTER_CLOSERS = r"(?:[ \t]*+[\]})])*+"
_CLEAN_END = re.compile(
    _AFTER_CLOSERS + r"[ \t]*+(?:[,&;\r\n]|\Z)"
    + "|" + _AFTER_CLOSERS + r"[ \t]++[\"']?[" + _KEY_CHARS + r"]++[\"']?[ \t]*+[:=]"
)
# An unquoted value that stopped at a delimiter mid-line is only certain if the
# delimiter cannot be inside something the value opened: `password: a[b,SECRET]`
# stopped at the comma, and `password: x"y,SECRET"` inside a string. A quote as
# the last thing in the value is the close of a string around the whole pair.
_DOUBT = re.compile(r"[\[{(]|[\"'](?![ \t]*\Z)")
_LINE_BREAK = re.compile(r"[\r\n]")
# Everything in a bracketed value that is neither a quote nor a bracket.
_GROUP_TEXT = re.compile(r"[^\"'\[\]{}]++")


def _line_end(text, index):
    found = _LINE_BREAK.search(text, index)
    return len(text) if found is None else found.start()


def _bracketed_end(text, start):
    """Where the array or object opening at ``start`` closes, or ``None`` if it
    never does.

    A value under a sensitive key can be a list of secrets. The value patterns
    stop at the first `,` or `]`, so `"tokens": ["t1", "SECRET"]` lost only
    `["t1"` and forwarded the rest. One pass, strings of either quote skipped
    whole, so a bracket inside a string does not count: `['a]b', 'SECRET']` is a
    Python list, and skipping only double-quoted strings closed it at the `]`.
    """
    depth = 0
    index = start
    length = len(text)
    while index < length:
        char = text[index]
        if char in _STRINGS:
            string = _STRINGS[char].match(text, index)
            if string is None:
                return None
            index = string.end()
            continue
        if char in _OPENERS:
            depth += 1
        elif char in _CLOSERS:
            depth -= 1
            if depth == 0:
                return index + 1
        else:
            index = _GROUP_TEXT.match(text, index).end()
            continue
        index += 1
    return None


def _value_end(text, start, separator):
    """Where the value starting at ``start`` ends, and whether that end is certain;
    ``None`` if there is no value there.

    An end that is not certain is the end of the line: the value is redacted
    through it. A quote or bracket that never closes may span lines, so a value
    that opens one runs to the end of the text.
    """
    length = len(text)
    if start >= length:
        return None
    char = text[start]
    if char in _OPENERS:
        end = _bracketed_end(text, start)
    elif char in _STRINGS:
        string = _STRINGS[char].match(text, start)
        end = None if string is None else string.end()
    else:
        value = _UNQUOTED[separator].match(text, start)
        if value is None:
            return None
        end = value.end()
        if end == length or text[end] in "\r\n":
            # The whole rest of the line: nothing is left on it to lose.
            return end, True
        if _DOUBT.search(text, start, end):
            return _line_end(text, end), False
        if text[end] not in _CLOSERS:
            return end, True
        # Stopped at a closing bracket, which ends the value only if a delimiter
        # follows it: `password: abc]SECRET` is one value.
    if end is None:
        return length, False
    if _CLEAN_END.match(text, end):
        return end, True
    return _line_end(text, end), False


# A line break, any blank lines, and the indentation of the next line with text.
_NEXT_LINE = re.compile(r"(?:\r\n?|\n)(?:[ \t]*+(?:\r\n?|\n))*+([ \t]*+)[^\r\n]*+")
_INDENT = re.compile(r"[ \t]*+")


def _continued(text, separator_at, end):
    """``end`` carried over every following line indented deeper than the line the
    key's separator is on.

    A value that runs to the end of its line does not always end there: under
    `private_key: |` the key itself is on the indented lines after it, and a
    folded header or a YAML scalar continues the same way. Those lines went
    through in clear. Whether the text is YAML cannot be known here, so a value
    carried over is reported as one without a certain end."""
    line = max(text.rfind("\n", 0, separator_at), text.rfind("\r", 0, separator_at)) + 1
    depth = _INDENT.match(text, line).end() - line
    while True:
        following = _NEXT_LINE.match(text, end)
        if following is None or len(following.group(1)) <= depth:
            return end
        end = following.end()


def _text_value(text, start, separator_at, separator):
    """Where the value after a separator ends, as ``(end, certain)``, or ``None``.

    Tried where the whitespace after the separator ends, then -- as the pattern
    this replaces did by backtracking -- at each earlier position back to the
    separator. Every failed attempt there is at a line break, which fails at its
    first character, so this stays linear.
    """
    for index in range(start, separator_at, -1):
        found = _value_end(text, index, separator)
        if found is not None:
            end, certain = found
            if end < len(text) and text[end] in "\r\n":
                carried = _continued(text, separator_at, end)
                if carried != end:
                    return carried, False
            return found
    return None


# QUOTED keys the token scan cannot read: one with a space (`"client secret"`),
# JSON escapes (`"p\u0061ssword"`), or single quotes (`'new password'`), in a body
# that is not JSON (a trailing comma) and so reaches this path, where the
# structured path would have redacted it.
#
# ANCHORED ON THE SEPARATOR, walking back. Every quote followed by `:` or `=`
# closes a candidate key; its opening quote is the nearest unescaped quote of the
# same kind before it. Pairing quotes from the start of the text went wrong at
# the first stray quote -- `{"size": 5", ...}` -- and every quoted key after it
# was read as a value. Walking back from each separator needs no pairing at all,
# so a stray quote costs nothing after it. Each character is scanned once: the
# walk back never passes the previous candidate's closing quote.
_KEY_CLOSE = re.compile(r"([\"'])\s*+([:=])\s*+")


def _escaped(text, index, floor):
    """Whether the character at ``index`` follows an odd run of backslashes that
    starts no earlier than ``floor``."""
    run = 0
    while index - 1 - run >= floor and text[index - 1 - run] == "\\":
        run += 1
    return run % 2 == 1


def _opening_quote(text, close, bound):
    """The nearest unescaped quote like the one at ``close`` before it, no earlier
    than ``bound``; -1 if there is none."""
    quote = text[close]
    start = close
    while True:
        start = text.rfind(quote, bound, start)
        if start < 0 or not _escaped(text, start, bound):
            return start


_ESCAPE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|(.))", re.S)
_ESCAPED_CHARS = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def _decoded_name(quoted):
    r"""A quoted key as the structured path would read it.

    JSON's escapes are read as JSON reads them: `"o\tp"` is o, tab, p, and names
    nothing. Any other backslash is dropped rather than judged raw:
    `"p\u0061ssword\x"` is not JSON at all, and judged raw it read
    "p\u0061ssword", which names nothing, and the value went through. Python's
    escapes in a single-quoted key are the same ones."""
    return _ESCAPE.sub(
        lambda m: chr(int(m.group(1), 16)) if m.group(1) else _ESCAPED_CHARS.get(m.group(2), m.group(2)),
        quoted[1:-1],
    )


class _QuotedKeys:
    """The quoted keys of ``text``, in order, each read back from its separator."""

    def __init__(self, text):
        self.text = text
        self.closes = _KEY_CLOSE.finditer(text)
        self.floor = 0
        self.pending = None

    def peek(self, pos):
        """The next candidate that starts at or after ``pos``, as ``(start, close)``."""
        text = self.text
        while True:
            if self.pending is not None:
                if self.pending[0] >= pos:
                    return self.pending
                # The scan ran past this key's opening quote. Read back again
                # from where it stopped, no other quote would open it: the scan
                # stops only at a delimiter, a line break or just past a
                # separator, never inside a run of backslashes that could change
                # which quote is escaped.
                self.pending = None
                continue
            close = next(self.closes, None)
            if close is None:
                return None
            quote = close.start(1)
            if quote < pos or _escaped(text, quote, pos):
                continue
            bound = max(pos, self.floor)
            self.floor = quote + 1
            start = _opening_quote(text, quote, bound)
            if start >= 0:
                self.pending = (start, close)

    def take(self):
        self.pending = None


def _token_pair(text, key):
    """``(key_start, key_text, end, certain)`` for a sensitive token key with a
    value, else ``None``."""
    if not _is_sensitive_key(key.group(2)):
        return None
    value = _text_value(text, key.end(), key.start(4), key.group(4))
    if value is None:
        return None
    return (key.start(), text[key.start():key.end(3)], *value)


def _quoted_pair(text, start, close):
    """The same for a quoted key.

    A key/value pair can be written INSIDE the quotes -- `'s my token: abc and
    the users': x` walks back from the second quote to the first -- and the
    quoted key is copied out verbatim. So such a pair's own value is redacted
    too, through whichever reading ends latest. A key that merely ENDS in a
    separator, `{"New Password:": "x"}`, is not one: nothing follows it but the
    closing quote."""
    quote = close.start(1)
    if not _is_sensitive_key(_decoded_name(text[start:quote + 1])):
        return None
    # Which reading is right cannot always be told: `{a: "b", user_token: ":"}`
    # reads back from the quote of ":" to the quote that closed "b", and a
    # missing comma puts a real key in the same place. Picking one reading
    # forwarded the other's secret, so every reading's value is redacted, through
    # the latest end, and reported -- unless only one reading parses at all.
    #
    # Every value read here is redacted -- here, or as the pair's own when the
    # scan reaches it. A value read and thrown away was read again for the next
    # key on the line, and a line of them took quadratic time.
    opens = _opens_a_key(text, start)
    first = None
    ends = []
    for inner in _TEXT_KEY.finditer(text, start + 1, quote):
        if not _is_sensitive_key(inner.group(2)):
            continue
        if inner.end() == quote:
            # A key that ends in its separator, like "New Password:". Read as a
            # pair, its value begins on the closing quote; that reading counts
            # only where the key opens where no key can, and a string on that
            # quote ends cleanly -- looked at no further than the string.
            found = None if opens else _held(text, quote)
        else:
            found = _text_value(text, inner.end(), inner.start(4), inner.group(4))
        if found is None:
            continue
        if first is None:
            first, first_certain = inner, found[1]
        ends.append(found[0])
    value = _text_value(text, close.end(), close.start(2), close.group(2))
    if value is None:
        return None
    end, certain = value
    if first is None:
        return start, text[start:quote + 1], end, certain
    latest = max(end, *ends)
    # Precise only where the first pair's own reading is, reaches furthest, and
    # this key's reading is no clean parse: then what went is that pair's value
    # and nothing more, as in a list after an unquoted key that holds a ":".
    precise = first_certain and ends[0] == latest and not certain
    return first.start(), text[first.start():first.end(3)], latest, precise


def _opens_a_key(text, index):
    """Whether the quote at ``index`` stands where a key can open: at the start of
    the text or a line, or after `{`, `[`, `(`, `,` or `;`."""
    index -= 1
    while index >= 0 and text[index] in " \t":
        index -= 1
    return index < 0 or text[index] in "{[(,;\r\n"


def _held(text, quote):
    """``(end, True)`` for a string opening on ``quote`` that closes and ends
    cleanly -- a value the quote may belong to -- else ``None``."""
    string = _STRINGS[text[quote]].match(text, quote)
    if string is None or _CLEAN_END.match(text, string.end()) is None:
        return None
    return string.end(), True


def _text_redaction(text):
    """``text`` with the value after every sensitive ``key:`` / ``key=`` replaced,
    and whether any value had no certain end and was redacted to the end of its
    line.

    One pass over the ORIGINAL text, quoted and token keys merged by where they
    start. Two passes, the second reading what the first had rewritten, let a
    value the first pass redacted pair with a quote after it: the second pass
    then took the next key's opening quote as the end of a bogus value and
    forwarded that key's secret. Linear in the length of ``text``: each key token
    starts where a run of key characters does, each quoted key is walked back no
    further than the one before it, and a value is read only to be redacted, after
    which the scan is past it.
    """
    out = []
    pos = 0
    doubtful = False
    quoted = _QuotedKeys(text)
    token = _TEXT_KEY.search(text)
    while True:
        if token is not None and token.start() < pos:
            token = _TEXT_KEY.search(text, pos)
        candidate = quoted.peek(pos)
        if candidate is not None and (token is None or candidate[0] <= token.start()):
            # A quoted key first when both start at the same quote: it is read
            # whole, escapes and spaces included.
            quoted.take()
            found = _quoted_pair(text, *candidate)
            if found is None:
                continue
        elif token is not None:
            found = _token_pair(text, token)
            if found is None:
                # Not a secret, or a secret with nothing after it: kept verbatim,
                # and the scan resumes after the separator, where the next key
                # can start.
                out.append(text[pos:token.end()])
                pos = token.end()
                continue
        else:
            break
        key_start, key_text, end, certain = found
        out.append(text[pos:key_start])
        out.append(f"{key_text}: {REDACTED}")
        pos = end
        doubtful = doubtful or not certain
    out.append(text[pos:])
    return "".join(out), doubtful


def _redact_text(text):
    """``text`` with the value after every sensitive ``key:`` / ``key=`` replaced."""
    return _text_redaction(text)[0]


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


_STRUCTURED = re.compile(r"\s*[\[{]")


def _is_form(text):
    """Whether ``text`` really is ``key=value&...``: every pair has its `=`, and
    it does not open like JSON."""
    return not _STRUCTURED.match(text) and all("=" in chunk for chunk in text.split("&") if chunk)


def redact(text, form=False, limit=None):
    """See :func:`redact_within`; the text alone."""
    return redact_within(text, form=form, limit=limit)[0]


def redact_within(text, form=False, limit=None):
    """
    The text with credential values removed, whatever shape it is in.

    The previous version was a single regex over a JSON string value, so a
    form-encoded body, a bearer token in plain text, a non-string JSON value,
    a key with an escaped quote in its value, and a body in any encoding other
    than UTF-8 all forwarded the secret verbatim to another service.

    `form` says the caller was told this is urlencoded (a form body, or a query
    string). It is not guessed: prose containing an "=" was being parsed as a
    form and re-encoded, which destroyed the attack signal the engine is asked
    to look for. But it is checked: jQuery posts `JSON.stringify(...)` with the
    form content type by default, and a chunk with no `=` was forwarded verbatim
    -- in a JSON body, every field. What is not a form is read as JSON or text as
    well, after its pairs are redacted as a form.

    Returns ``(text, cut, doubtful)``: ``cut`` is True when only the first
    ``limit`` characters were redacted, so the caller can say the body was
    truncated even when what redaction left happens to fit; ``doubtful`` when a
    value had no certain end and was redacted to the end of its line, which may
    have taken more than that value with it.
    """
    if not text:
        return text, False, False

    if form:
        redacted = _redact_form(text)
        if _is_form(text):
            return redacted, False, False
        text = redacted

    # Both passes run before authentication. On a whole 10 MB body the text pass
    # held a worker for ten seconds, and the structured one -- parse, rebuild,
    # serialise -- took four seconds and 180 MB for 9 MB of tiny keys, to produce
    # text of which the caller keeps the first 64 KiB. `limit` is how much the
    # caller can use: only that prefix is read, and as text, since a JSON
    # document cannot be parsed from part of itself. A value the cut runs through
    # is still redacted, because an unterminated one runs to the end of what it is
    # given.
    if limit is not None and len(text) > limit:
        redacted, doubtful = _text_redaction(text[:limit])
        return redacted, True, doubtful

    if _STRUCTURED.match(text):
        try:
            return (
                json.dumps(_redact_structure(json.loads(text)), separators=(",", ":")),
                False,
                False,
            )
        except (ValueError, TypeError, RecursionError):
            pass

    redacted, doubtful = _text_redaction(text)
    return redacted, False, doubtful


# What a body problem says when a value had to be redacted to the end of its line.
DOUBTFUL_VALUE = (
    "could not be fully inspected: a value after a sensitive key had no certain end "
    "and was redacted to the end of its line"
)


def _joined(problem, more):
    """Both reasons, when a request has two: one is recorded per request."""
    if problem and more:
        return f"{problem}; {more}"
    return problem or more


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
        # The query string was copied through with no redaction at all, so
        # ?token=... reached the engine in clear while the same value in the
        # body was replaced. One that is not a form is read as text too, and a
        # value that text had to redact to its end is reported like the body's.
        query, _cut, query_doubtful = redact_within(
            request.META.get("QUERY_STRING", ""), form=True
        )
        if query_doubtful:
            body_problem = _joined(body_problem, f"query string {DOUBTFUL_VALUE}")

        ctx = {
            "ip": meta.get("ip_address") or client_ip(request),
            "path": meta.get("path") or request.path,
            "method": meta.get("method") or request.method,
            "user_agent": request.META.get("HTTP_USER_AGENT", ""),
            "query": query,
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
        # forwarded in clear. The body is read only in a bounded prefix -- four
        # times what is kept, since redaction can shrink it -- and a body longer
        # than that prefix is reported as truncated even when what is left after
        # redaction happens to fit.
        prefix = 4 * self.max_body_bytes
        redacted, cut, doubtful = redact_within(
            text, form=content_type == "application/x-www-form-urlencoded", limit=prefix
        )
        body, problem = self._trim(redacted)
        if problem is None and cut:
            problem = f"request body was truncated at {prefix} bytes for inspection"
        if doubtful:
            # Redacting to the end of the line may have taken the attack with
            # the secret. A body that lost more than its secrets is not a clean
            # inspection, and a sensitive key planted in front of a payload must
            # not blind the engine in silence.
            problem = _joined(problem, f"request body {DOUBTFUL_VALUE}")
        return body, problem

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
