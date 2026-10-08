"""Every HTTP request this service sends with ``requests`` itself.

The engines reach the outside world through mythos-core's ``safe_http``. This
service does not: it calls ``requests`` directly, at four call sites, and each
goes through :func:`get` or :func:`post` here.

========================================  =======================================
call site                                 what it reaches, with which credential
========================================  =======================================
``ai_engine.services.cyberengine_client``  the engine (``CYBERENGINE_URL``): scans,
                                          their Stop, receipts to sign, the
                                          defender; ``X-API-Key``
``audit.middleware.DefenderMiddleware``    the engine's ``/defend``; ``X-API-Key``
``assurance.connectors.base               a customer's Jira, ServiceNow, GitHub,
.RequestsTransport``                      Splunk or webhook, and Minotaur's
                                          remediation-outcomes route (the closure
                                          forward); each one's own token
``assurance.posture.base.RequestsFetcher``  a customer's cloud, repository or
                                          secrets posture source; its read token
========================================  =======================================

Three things hold at every one of them.

* **No redirect is followed.** Each of these is a machine API at a base URL an
  operator configured. None of them answers a request with a redirect; one that
  arrives is an intermediary's (a login page, a proxy, a moved host), and
  following it sent the request's own headers -- ``X-API-Key``, ``X-Minotaur-Key``,
  a webhook's token header -- to wherever ``Location`` pointed: ``requests`` strips
  ``Authorization`` on a hop to another host and keeps every other header. The
  3xx is answered to the caller instead, which reads it as the non-2xx it is: a
  refused call, a failed push, an unknown posture check, or (a scan's launch) an
  outcome not known (``cyberengine_client.run_scan``).
* **Nothing is taken from the environment.** ``trust_env`` is off, so no
  ``.netrc`` login is put on a request (GHSA-9hjg-9r4m-mvj7's channel: a Session
  that trusts the environment puts the login kept for the request's host on it,
  in place of the ``Authorization`` the caller set), and no proxy -- with or
  without credentials in it -- is read from ``HTTP_PROXY``, ``HTTPS_PROXY`` or
  ``ALL_PROXY``. No call site here needs a proxy; one that comes to need one
  names it in a setting of its own and passes it as ``proxies``, never through
  the environment. The TLS roots an operator named in ``REQUESTS_CA_BUNDLE`` or
  ``CURL_CA_BUNDLE`` are still used: they are trust, not a credential, and
  dropping them would only fail verification closed.
* **No error quotes a credential.** ``requests`` puts the request's path and
  query in the text of a failed connection ("Max retries exceeded with url:
  /services/T0/B0/<the webhook's secret>?token=..."), and a malformed URL whole,
  userinfo and all, in an ``InvalidURL``; the call sites put that text in a
  record (a dispatch attempt, a closure forward's ``last_error``, a scan's error),
  an answer and a log line with its traceback. So an exception raised here has
  its text, and the text of every exception it was caused by, cut to the
  scheme, host and port of any URL in it, and every header value the request
  carried withheld; what it is (its class, and the cause the call sites classify
  a failure by) is unchanged, and it is the same exception object. An answer is
  read with every credential the request carried withheld from its body: whoever
  answered may quote the request back (a debugging proxy's error page does, headers
  and all), and the engine's refusal becomes ``Engine error <status>: <its body>``
  on a scan's record, its answer and its report. Withholding never raises and never
  waits: if it fails, the exception says only its class.

Nothing here decides whether a request may be sent: a scan's Stop goes through
:func:`post` like every other call, and what changes for it is only that a
redirect is not followed and the environment is not read.
"""

from __future__ import annotations

import base64
import contextlib
import os
import re

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


def _configured_ca_bundle():
    """The TLS roots the environment names, if it names any, else ordinary verification."""
    for variable in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        value = os.environ.get(variable)
        if value:
            return value
    return True


def session() -> requests.Session:
    """A Session that reads nothing from the environment: no ``.netrc``, no proxy."""
    made = requests.Session()
    made.trust_env = False
    return made


def _origin(match: re.Match) -> str:
    authority = match.group("authority").rsplit("@", 1)[-1]
    rest = match.group("rest")
    return f"{match.group('scheme')}{authority}{'/' + WITHHELD if rest else ''}"


def withhold(text: str, secrets=()) -> str:
    """``text`` with every URL cut to its scheme, host and port, every quoted request
    path withheld, and each of ``secrets`` withheld."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, WITHHELD)
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


def quiet(exc: BaseException, secrets=()) -> BaseException:
    """``exc``, its text and its causes' withheld in place (:func:`withhold`). The
    same object, so its class and its causes still say what failed. Never raises:
    an exception that cannot be withheld says only its class."""
    try:
        values = [value for value in secrets if isinstance(value, str) and value]
        for current in _chain(exc):
            current.args = tuple(
                withhold(arg, values) if isinstance(arg, str) else arg for arg in current.args
            )
            url = getattr(current, "url", None)
            if isinstance(url, str):
                current.url = withhold(url, values)
    except Exception:  # noqa: BLE001 - withholding fails towards saying less
        # Nothing more can be taken out of one whose args cannot be set either.
        with contextlib.suppress(Exception):
            exc.args = (type(exc).__name__,)
    return exc


#: The shortest part of a header value withheld on its own ("Bearer <token>": the token).
_MIN_SECRET = 8


def _secrets(kwargs: dict) -> list[str]:
    """Every header value the request carries that may be a credential, and each part
    of one that may be: the token after ``Bearer``, and a ``Basic`` login decoded and
    its password. Longest first, so a whole value is withheld before its parts."""
    found: set[str] = set()
    for name, value in (kwargs.get("headers") or {}).items():
        if not isinstance(value, str) or str(name).lower() in _PLAIN_HEADERS or not value:
            continue
        found.add(value)
        parts = value.split()
        found.update(part for part in parts if len(part) >= _MIN_SECRET)
        if len(parts) == 2 and parts[0].lower() == "basic":
            with contextlib.suppress(Exception):
                login = base64.b64decode(parts[1], validate=True).decode("utf-8")
                found.add(login)
                found.update(piece for piece in login.split(":", 1) if len(piece) >= _MIN_SECRET)
    return sorted(found, key=len, reverse=True)


def _withhold_body(response: requests.Response, secrets) -> None:
    """Every credential the request carried, withheld from the answer's body before
    anyone reads it. Whoever answered -- the far end, or a proxy's or gateway's error
    page -- may quote the request back, headers and all, and the call sites put an
    answer's text in a record, an error and a log line (an engine's refusal is
    ``Engine error <status>: <its body>``). A streamed answer is read by its caller
    as it arrives and is left as it is. Never raises: an answer that cannot be read
    here is left for its caller to find unreadable."""
    try:
        if not secrets or response.raw is None or getattr(response, "_content_consumed", False) is False:
            return
        content = response.content
        if not content:
            return
        for secret in secrets:
            content = content.replace(secret.encode("utf-8", "surrogatepass"), WITHHELD.encode())
        response._content = content
    except Exception:  # noqa: BLE001 - withholding fails towards leaving the answer to its caller
        return


def _send(method: str, url: str, **kwargs) -> requests.Response:
    kwargs["allow_redirects"] = False
    kwargs.setdefault("verify", _configured_ca_bundle())
    secrets = _secrets(kwargs)
    # As requests.get and requests.post do: one Session for the call, closed after
    # it (a streamed answer is still read to its end).
    with session() as sending:
        try:
            response = sending.request(method, url, **kwargs)
        except requests.RequestException as exc:
            quiet(exc, secrets)
            raise
    if not kwargs.get("stream"):
        _withhold_body(response, secrets)
    return response


def get(url: str, **kwargs) -> requests.Response:
    """``requests.get``, following no redirect and reading nothing from the environment."""
    return _send("GET", url, **kwargs)


def post(url: str, **kwargs) -> requests.Response:
    """``requests.post``, following no redirect and reading nothing from the environment."""
    return _send("POST", url, **kwargs)
