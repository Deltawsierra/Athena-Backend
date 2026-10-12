"""Every HTTP request this service sends with ``requests`` itself.

The engines reach the outside world through mythos-core's ``safe_http``. This
service does not: it calls ``requests`` directly, at four call sites, and each
goes through :func:`get` or :func:`post` here.

========================================  =======================================
call site                                 what it reaches, with which credential
========================================  =======================================
``ai_engine.services.cyberengine_client``  the engine (``CYBERENGINE_URL``): scans,
                                          their Stop, receipts to sign, the
                                          defender; ``X-API-Key``. The engine's
                                          lane (``engine=True``), below.
``audit.middleware.DefenderMiddleware``    the engine's ``/defend``; ``X-API-Key``
``assurance.connectors.base               a customer's Jira, ServiceNow, GitHub,
.RequestsTransport``                      Splunk or webhook, and Minotaur's
                                          remediation-outcomes route (the closure
                                          forward); each one's own token
``assurance.posture.base.RequestsFetcher``  a customer's cloud, repository or
                                          secrets posture source; its read token
========================================  =======================================

Three things hold at every one of them.

* **No redirect to another host is followed, and outside the engine's lane none
  at all.** Each of these is a machine API at a base URL an operator configured.
  A redirect to another host is an intermediary's (a login page, a proxy, a moved
  host), and following it sent the request's own headers -- ``X-API-Key``,
  ``X-Minotaur-Key``, a webhook's token header -- to wherever ``Location`` pointed:
  ``requests`` strips ``Authorization`` on a hop to another host and keeps every
  other header. The 3xx is answered to the caller instead, which reads it as the
  non-2xx it is: a refused call, a failed push, an unknown posture check, or (a
  scan's launch) an outcome not known (``cyberengine_client.run_scan``). The
  engine's lane alone follows a redirect that stays on the engine's host: a 307 or
  308 (and a 301, 302 or 303 answering a GET, which is sent again as the same GET),
  to the same host compared case-insensitively after IDNA, at any port, with the
  scheme kept or moved from http to https, and with no login of its own; the
  method, the body and the key are sent again, at most ``ENGINE_REDIRECT_HOPS``
  times in one call. An engine moved behind a trailing slash or onto https answers
  a scan's Stop that way, and refusing it left the Stop owed for ever. Anything
  else -- another host, https to http, a 301, 302 or 303 answering a POST, a
  fourth hop -- is answered to the caller as the 3xx it is, and nothing is sent
  where it points.
* **Nothing is taken from the environment but the engine's proxy.**
  ``trust_env`` is off on every lane, so no ``.netrc`` login is put on a request
  (GHSA-9hjg-9r4m-mvj7's channel: a Session that trusts the environment puts the
  login kept for the request's host on it, in place of the ``Authorization`` the
  caller set). The engine's lane takes its proxy from the process environment
  explicitly -- ``urllib.request.getproxies()`` (``HTTP_PROXY``, ``HTTPS_PROXY``,
  ``ALL_PROXY``), bypassed for a host ``NO_PROXY`` names
  (``urllib.request.proxy_bypass``) -- and passes it as ``proxies``: an engine a
  deployment reaches only through its proxy is reached, and its scans stopped,
  as before. A proxy's userinfo is withheld from every error and answer. No
  other lane reads a proxy; one that comes to need one names it in a setting of
  its own and passes it as ``proxies``, never through the environment. The TLS
  roots an operator named in ``REQUESTS_CA_BUNDLE`` or ``CURL_CA_BUNDLE`` are still
  used: they are trust, not a credential, and dropping them would only fail
  verification closed.
* **No error quotes a credential.** ``requests`` puts the request's path and
  query in the text of a failed connection ("Max retries exceeded with url:
  /services/T0/B0/<the webhook's secret>?token=..."), and a malformed URL whole,
  userinfo and all, in an ``InvalidURL``; the call sites put that text in a
  record (a dispatch attempt, a closure forward's ``last_error``, a scan's error),
  an answer and a log line with its traceback. So an exception raised here has
  its text, and the text of every exception it was caused by, cut to the
  scheme, host and port of any URL in it, and every header value the request
  carried, the proxy's userinfo and each value a call site asks to be withheld (a
  scan target's login) withheld; what it is (its class, and the cause the call
  sites classify a failure by) is unchanged, and it is the same exception object.
  An answer is read with every credential the request carried, the proxy's among
  them, withheld from its body: whoever answered may quote the request back (a
  debugging proxy's error page does, headers and all), and the engine's refusal
  becomes ``Engine error <status>: <its body>`` on a scan's record, its answer and
  its report. Withholding never raises and never waits: if it fails, the
  exception says only its class.

Nothing here decides whether a request may be sent: a scan's Stop goes through
:func:`post` like every other call, on the engine's lane, and what changes for it
is only which redirects are followed and that the environment gives it nothing
but its proxy.
"""

from __future__ import annotations

import base64
import contextlib
import os
import re
import urllib.request
from urllib.parse import unquote, urljoin, urlsplit

import requests

#: The headers whose values are not secrets and are left in an error's text.
_PLAIN_HEADERS = frozenset({"accept", "content-type", "content-length", "user-agent", "idempotency-key"})

#: A URL in an error's text: its scheme and authority, and whatever follows.
_URL = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*://)(?P<authority>[^/\s'\"?#<>]*)(?P<rest>[^\s'\"<>)]*)")
#: A request path urllib3 quotes on its own ("with url: /path?query").
_PATH = re.compile(r"(?P<lead>\burl: )(?P<path>/[^\s'\"<>]*)")
#: A URL requests refused to read, which it quotes whole ("Invalid URL '<it>': ...").
_INVALID = re.compile(r"(?P<lead>Invalid URL ')(?P<url>[^']*)(?P<end>')")

WITHHELD = "[withheld]"

#: How many redirects the engine's lane follows in one call; the next is answered
#: to the caller as the 3xx it is.
ENGINE_REDIRECT_HOPS = 3
#: What the engine's lane follows, for any method: the method and body are sent again.
_FOLLOWED = frozenset({307, 308})
#: What it follows answering a GET only: sent again as the same GET. On any other
#: method these turn the request into a GET without its body, and are refused.
_FOLLOWED_FOR_GET = frozenset({301, 302, 303})
#: A scheme kept, or moved from http to https; never https to http.
_SCHEME_MOVES = frozenset({("http", "http"), ("https", "https"), ("http", "https")})


def _configured_ca_bundle():
    """The TLS roots the environment names, if it names any, else ordinary verification."""
    for variable in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        value = os.environ.get(variable)
        if value:
            return value
    return True


def session() -> requests.Session:
    """A Session that reads nothing from the environment: no ``.netrc``, no proxy (the
    engine's lane passes the environment's proxy itself, as ``proxies``)."""
    made = requests.Session()
    made.trust_env = False
    return made


def _origin(match: re.Match) -> str:
    authority = match.group("authority").rsplit("@", 1)[-1]
    rest = match.group("rest")
    return f"{match.group('scheme')}{authority}{'/' + WITHHELD if rest else ''}"


def _replaced(text: str, secrets=()) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, WITHHELD)
    return text


def withhold(text: str, secrets=()) -> str:
    """``text`` with every URL cut to its scheme, host and port, every quoted request
    path withheld, and each of ``secrets`` withheld."""
    text = _replaced(text, secrets)
    text = _INVALID.sub(lambda m: f"{m.group('lead')}{WITHHELD}{m.group('end')}", text)
    text = _URL.sub(_origin, text)
    return _PATH.sub(lambda m: f"{m.group('lead')}{WITHHELD}", text)


def _chain(exc: BaseException):
    """``exc``, every exception it was raised from or during, and every exception
    one of them carries as an argument or a ``reason`` (urllib3's MaxRetryError)."""
    seen: set[int] = set()
    pending = [exc]
    while pending:
        current = pending.pop()
        if not isinstance(current, BaseException) or id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        pending.extend(arg for arg in current.args if isinstance(arg, BaseException))
        pending.extend(
            linked
            for linked in (getattr(current, "reason", None), current.__cause__, current.__context__)
            if isinstance(linked, BaseException)
        )


def quiet(exc: BaseException, secrets=(), *, urls: bool = True) -> BaseException:
    """``exc``, its text and its causes' withheld in place (:func:`withhold`; with
    ``urls=False``, ``secrets`` alone, every URL left as it is -- a message this
    service wrote). The same object, so its class and its causes still say what
    failed. Never raises: an exception that cannot be withheld says only its class."""
    try:
        values = _longest_first(value for value in secrets if isinstance(value, str) and value)
        rewrite = withhold if urls else _replaced
        for current in _chain(exc):
            current.args = tuple(
                rewrite(arg, values) if isinstance(arg, str) else arg for arg in current.args
            )
            url = getattr(current, "url", None)
            if isinstance(url, str):
                current.url = rewrite(url, values)
    except Exception:  # noqa: BLE001 - withholding fails towards saying less
        try:
            linked = list(_chain(exc))
        except Exception:  # noqa: BLE001 - a chain that cannot be walked: the exception alone
            linked = [exc]
        for current in linked:
            # Each says its class alone; one whose args cannot be set says what it says.
            with contextlib.suppress(Exception):
                current.args = (type(current).__name__,)
            with contextlib.suppress(Exception):
                if isinstance(getattr(current, "url", None), str):
                    current.url = WITHHELD
    return exc


#: The shortest part of a header value withheld on its own ("Bearer <token>": the token).
_MIN_SECRET = 8


def _value_secrets(value: str) -> set[str]:
    """A header value that may be a credential, and each part of it that may be: the
    token after ``Bearer``, and a ``Basic`` login decoded and its password."""
    found = {value}
    parts = value.split()
    found.update(part for part in parts if len(part) >= _MIN_SECRET)
    if len(parts) == 2 and parts[0].lower() == "basic":
        with contextlib.suppress(Exception):
            login = base64.b64decode(parts[1], validate=True).decode("utf-8")
            found.add(login)
            found.update(piece for piece in login.split(":", 1) if len(piece) >= _MIN_SECRET)
    return found


def _secrets(kwargs: dict) -> list[str]:
    """Every header value the request carries that may be a credential, and each part
    of one that may be (:func:`_value_secrets`). Longest first, so a whole value is
    withheld before its parts."""
    found: set[str] = set()
    for name, value in (kwargs.get("headers") or {}).items():
        if not isinstance(value, str) or str(name).lower() in _PLAIN_HEADERS or not value:
            continue
        found |= _value_secrets(value)
    return sorted(found, key=len, reverse=True)


def _longest_first(values) -> list[str]:
    return sorted({value for value in values if value}, key=len, reverse=True)


def withheld_text(text: str, values=()) -> str:
    """``text`` with each of ``values`` withheld, longest first, and nothing else
    changed. Never raises: text that cannot be withheld from is withheld whole."""
    try:
        return _replaced(text, _longest_first(v for v in values if isinstance(v, str)))
    except Exception:  # noqa: BLE001 - withholding fails towards saying less
        return WITHHELD


def logins_in(url) -> tuple[str, ...]:
    """The login a URL carries, to be withheld wherever it could be said: its
    userinfo whole and its password, each as written and percent-decoded, longest
    first. The userinfo is what precedes the authority's last ``@``, as
    ``pentest.models.target_shown`` reads it. Empty when it carries none; never
    raises (a URL that cannot be read gives nothing to withhold)."""
    try:
        text = str(url or "")
        rest = text.partition("://")[2] or text
        cut = min((i for i in (rest.find(c) for c in "/?#") if i >= 0), default=len(rest))
        authority = rest[:cut]
        if "@" not in authority:
            return ()
        userinfo = authority.rsplit("@", 1)[0]
        password = userinfo.partition(":")[2]
        return tuple(_longest_first({userinfo, password, unquote(userinfo), unquote(password)}))
    except Exception:  # noqa: BLE001 - nothing read, nothing to withhold
        return ()


def withheld_body(content: bytes, secrets) -> bytes:
    """``content`` with each of ``secrets`` withheld."""
    for secret in secrets:
        content = content.replace(secret.encode("utf-8", "surrogatepass"), WITHHELD.encode())
    return content


def _withhold_body(response: requests.Response, secrets) -> None:
    """Every credential the request carried, withheld from the answer's body before
    anyone reads it. Whoever answered -- the far end, or a proxy's or gateway's error
    page -- may quote the request back, headers and all, and the call sites put an
    answer's text in a record, an error and a log line (an engine's refusal is
    ``Engine error <status>: <its body>``). A streamed answer is read by its caller
    as it arrives and is left as it is. Never raises, and fails towards saying less:
    an answer whose body cannot be withheld from is handed on with no body, which
    its caller reads as the unreadable answer it then is (the request was sent and
    answered, a Stop's included: this runs after, and decides nothing about it)."""
    try:
        if not secrets or response.raw is None or getattr(response, "_content_consumed", False) is False:
            return
        content = response.content
        if content:
            response._content = withheld_body(content, secrets)
    except Exception:  # noqa: BLE001 - withholding fails towards saying less
        with contextlib.suppress(Exception):
            response._content = b""


# ---------------------------------------------------------------------------
# The engine's lane: its proxy, and the redirects it follows
# ---------------------------------------------------------------------------


def _environment_proxies() -> dict[str, str]:
    """The proxies the process environment names (``urllib.request.getproxies``), by
    scheme, ``NO_PROXY`` aside. None when they cannot be read: the engine is then
    dialled directly, and a Stop that cannot reach it is owed, never held."""
    try:
        return {
            scheme: value
            for scheme, value in urllib.request.getproxies().items()
            if scheme != "no" and isinstance(value, str) and value
        }
    except Exception:  # noqa: BLE001 - no proxy read is a direct dial
        return {}


def _proxies_for(url: str, proxies: dict[str, str]) -> dict[str, str]:
    """``proxies``, or none for a host ``NO_PROXY`` names (``urllib.request.proxy_bypass``)."""
    if not proxies:
        return {}
    bypassed = False
    with contextlib.suppress(Exception):  # a bypass that cannot be read: the environment's proxy
        parts = urlsplit(url)
        hosts = [parts.hostname or "", parts.netloc.rsplit("@", 1)[-1]]
        bypassed = any(host and urllib.request.proxy_bypass(host) for host in hosts)
    return {} if bypassed else dict(proxies)


def _basic(user: str, password: str) -> set[str]:
    """``Proxy-Authorization``'s values for this login, as requests encodes it."""
    found = set()
    for encoding in ("latin-1", "utf-8"):
        with contextlib.suppress(Exception):
            found.add("Basic " + base64.b64encode(f"{user}:{password}".encode(encoding)).decode("ascii"))
    return found


def _proxy_secrets(proxies: dict[str, str]) -> tuple[list[str], list[str]]:
    """What the proxies' userinfo is, to be withheld: from an answer's body (the
    ``Proxy-Authorization`` requests sends, as a header value is withheld, and the
    userinfo whole), and further from an error's text (the password, however
    short). Never raises."""
    carried: set[str] = set()
    said: set[str] = set()
    for value in proxies.values():
        with contextlib.suppress(Exception):
            raw = value if "://" in value else f"http://{value}"
            authority = urlsplit(raw).netloc
            if "@" not in authority:
                continue
            userinfo = authority.rsplit("@", 1)[0]
            user, _, password = userinfo.partition(":")
            carried.update({userinfo, unquote(userinfo)})
            for header in _basic(unquote(user), unquote(password)):
                carried.update(_value_secrets(header))
            said.update({password, unquote(password)})
    carried.discard("")
    said.discard("")
    return _longest_first(carried), _longest_first(carried | said)


def _host_key(host: str | None) -> str | None:
    """A host as compared for a redirect: IDNA-encoded, case folded. None if it is
    not a host that can be compared."""
    if not host:
        return None
    try:
        return host.encode("idna").decode("ascii").lower()
    except Exception:  # noqa: BLE001 - a host that cannot be encoded is not the same host
        return None


def _same_host_hop(method: str, url: str, response: requests.Response) -> str | None:
    """Where the engine's lane follows ``response`` to, or None: it is answered to
    the caller as it is. Followed: a 307 or 308 (a 301, 302 or 303 answering a GET)
    whose ``Location`` names the same host (IDNA, any case), at any port, with the
    scheme kept or moved from http to https, and no login of its own."""
    status = response.status_code
    if status not in _FOLLOWED and not (method == "GET" and status in _FOLLOWED_FOR_GET):
        return None
    try:
        location = response.headers.get("Location")
        if not location:
            return None
        following = urljoin(url, location)
        was, now = urlsplit(url), urlsplit(following)
        if (was.scheme.lower(), now.scheme.lower()) not in _SCHEME_MOVES:
            return None
        if "@" in now.netloc:
            return None
        here = _host_key(was.hostname)
        if here is None or here != _host_key(now.hostname):
            return None
        now.port  # noqa: B018 - a port that cannot be read raises here, and is not followed
    except Exception:  # noqa: BLE001 - a Location that cannot be read is not followed
        return None
    return following


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------


def _send(method: str, url: str, *, engine: bool = False, also_withhold=(), **kwargs) -> requests.Response:
    kwargs["allow_redirects"] = False
    kwargs.setdefault("verify", _configured_ca_bundle())
    carried = _secrets(kwargs)
    said = carried
    proxies: dict[str, str] = {}
    if engine:
        proxies = _environment_proxies()
        from_proxy, said_of_proxy = _proxy_secrets(proxies)
        carried = _longest_first([*carried, *from_proxy])
        said = _longest_first([*carried, *said_of_proxy])
    # What the request's own content chose (a scan target's login) is withheld from
    # an error's text, never from the answer's body: the answer is read as the
    # engine wrote it -- a run id, a state -- and a value a tenant chose must not be
    # able to rewrite the run id a Stop names. The call site withholds it from the
    # texts it keeps.
    said = _longest_first([*said, *(value for value in also_withhold if isinstance(value, str))])
    # As requests.get and requests.post do: one Session for the call, closed after
    # it (a streamed answer is still read to its end).
    with session() as sending:
        hops = 0
        while True:
            if engine:
                kwargs["proxies"] = _proxies_for(url, proxies)
            try:
                response = sending.request(method, url, **kwargs)
            except requests.RequestException as exc:
                quiet(exc, said)
                raise
            following = _same_host_hop(method, url, response) if engine and hops < ENGINE_REDIRECT_HOPS else None
            if following is None:
                break
            with contextlib.suppress(Exception):
                response.close()
            url, hops = following, hops + 1
    if not kwargs.get("stream"):
        _withhold_body(response, carried)
    return response


def get(url: str, *, engine: bool = False, also_withhold=(), **kwargs) -> requests.Response:
    """``requests.get``, following no redirect and reading nothing from the environment;
    on the engine's lane (``engine=True``) following a redirect that stays on the
    engine's host and taking the environment's proxy. ``also_withhold``: further
    values no error may quote (a scan target's login)."""
    return _send("GET", url, engine=engine, also_withhold=also_withhold, **kwargs)


def post(url: str, *, engine: bool = False, also_withhold=(), **kwargs) -> requests.Response:
    """``requests.post``, as :func:`get` sends a GET."""
    return _send("POST", url, engine=engine, also_withhold=also_withhold, **kwargs)
