"""The backend's target guard and engagement scope decide on the host the client dials.

Mythos-Core#47 found that a destination is judged in one place and reached in
another: the policy read a host out of a URL one way, and the HTTP client read it
another and dialled that. Its decide/connect map lists two places in this service
that still decided their own way:

* ``pentest.views.target_is_out_of_bounds`` compared the URL's host, as written,
  against a name list of its own, and resolved it with ``socket.getaddrinfo`` --
  whose IDNA 2003 codec folds ``straße`` to ``strasse``, a different registered
  name from the ``xn--strae-oqa`` the client dials. It decides through core's
  ``egress.check_target`` now (which reads the host with ``host_from_target``, in
  the client's form, and refuses what the client cannot read), and then holds the
  approved addresses to this service's own internal-address list as before.
* ``pentest.models.Engagement.covers`` compared hosts lowercased, with no IDNA and
  no percent-decoding. It reduces both sides with core's ``normalise_host`` now,
  and a host or entry the HTTP client cannot read covers nothing.

Both only tighten. The guard refuses everything it refused (the same internal
address list is applied after core's), and refuses every spelling of the #47
corpus core refuses; ``covers`` answers yes only where it did before AND the host
the client dials is within the entry the client reads.

Hermetic, as #47's suite is: name resolution is a table, answering the way the
socket module does (a non-ASCII name is IDNA 2003 encoded first, a numeric IPv4
form is read as ``inet_aton`` reads it). Nothing leaves the process.
"""

import ipaddress
import socket

import pytest
import requests
from mythos_core.http import egress
from urllib3.util import parse_url

from pentest import views
from pentest.models import Engagement

PUBLIC = "93.184.216.34"
ELSEWHERE = "93.184.216.36"  # public too: a different host's address
LOOPBACK = "127.0.0.1"
CREDENTIALS = "169.254.170.2"

#: What the nameserver answers, by the name the socket layer asks for (#47's table).
NAMES = {
    "public.test": (PUBLIC,),
    # `straße.test`: IDNA 2003 (the socket module) asks for the first, IDNA 2008
    # (urllib3, so the HTTP client) for the second. Two registered names.
    "strasse.test": (ELSEWHERE,),
    "xn--strae-oqa.test": (LOOPBACK,),
    "strasse.customer.test": (PUBLIC,),
    "xn--strae-oqa.customer.test": (ELSEWHERE,),
    # A zone the attacker runs answers both the literal and the decoded name.
    "%6c%6fcalhost.evil.test": (PUBLIC,),
    "localhost.evil.test": (LOOPBACK,),
    "pub%zzlic.evil.test": (PUBLIC,),
    "http": (PUBLIC,),
    "metadata.google.internal": (CREDENTIALS,),
    "instance-data": (CREDENTIALS,),
    "metadata": (CREDENTIALS,),
}

LINK_LOCAL = ["169.254.0.0/16"]

#: Mythos-Core#47's corpus, (url, allowlist), unchanged.
CORPUS = [
    # case
    ("http://PUBLIC.TEST/", []),
    ("HTTP://Public.Test:80/x", []),
    # a trailing dot
    ("http://public.test./", []),
    ("http://localhost./", []),
    ("http://public.test../", []),
    # IDNA, Unicode confusables, full-width and ideographic dots
    ("http://straße.test/", []),
    ("http://xn--strae-oqa.test/", []),
    ("http://ſtrasse.test/", []),
    ("http://ｌｏｃａｌｈｏｓｔ/", []),
    ("http://ｍｅｔａｄａｔａ.google.internal/", LINK_LOCAL),
    ("http://metadata。google。internal/", LINK_LOCAL),
    ("http://metadata．google．internal/", LINK_LOCAL),
    ("http://ｉｎｓｔａｎｃｅ-ｄａｔａ/", LINK_LOCAL),
    ("http://public.test​/", []),
    # percent-encoding in the host
    ("http://%6c%6fcalhost.evil.test/", []),
    ("http://%70ublic.test/", []),
    ("http://pub%zzlic.evil.test/", []),
    ("http://public.test%2f@127.0.0.1/", []),
    # userinfo
    ("http://user@public.test/", []),
    ("http://user:@public.test/", []),
    ("http://public.test@127.0.0.1/", []),
    ("http://a@b@public.test/", []),
    ("http://127.0.0.1#@public.test/", []),
    ("http://public.test?@127.0.0.1/", []),
    # backslashes
    ("http://127.0.0.1\\@public.test/", []),
    ("http://public.test\\.evil.test/", []),
    # IPv4 in decimal, octal, hex and short forms
    ("http://2130706433/", []),
    ("http://0177.0.0.1/", []),
    ("http://0x7f.0.0.1/", []),
    ("http://127.1/", []),
    ("http://2130706433/", ["127.0.0.0/8"]),
    ("http://0x7f.1/", ["127.0.0.0/8"]),
    ("http://2852039166/", LINK_LOCAL),
    ("http://0xa9.0xfe.0xa9.0xfe/", LINK_LOCAL),
    # IPv6: plain, IPv4-mapped, zone IDs, NAT64
    ("http://[::1]/", []),
    ("http://[::ffff:127.0.0.1]/", []),
    ("http://[::ffff:a9fe:a9fe]/", LINK_LOCAL),
    ("http://[fd00:ec2::254%25eth0]/", ["fd00:ec2::/32"]),
    ("http://[fd00:ec2::254%eth0]/", ["fd00:ec2::/32"]),
    ("http://[fe80::1%25eth0]/", ["fe80::/10"]),
    ("http://[64:ff9b::a9fe:a9fe]/", []),
    ("http://[64:ff9b::5db8:d822]/", []),
    # default-port equivalence, and ports only one side can read
    ("http://public.test:80/", []),
    ("http://public.test:0080/", []),
    ("https://public.test:443/", []),
    ("http://public.test:/", []),
    ("http://public.test:8080/", []),
    ("http://public.test:99999/", []),
    ("http://public.test:+80/", []),
    ("http://public.test:8٠/", []),
    # whitespace and control characters
    (" http://public.test/", []),
    ("http://public.test\xa0/", []),
    ("http://public.test\t/", []),
    ("http://pub\x00lic.test/", []),
    ("http://public.test /", []),
    # no authority at all
    ("http:public.test/", []),
    ("http:/public.test/", []),
]


def _inet_aton(text):
    """The address ``inet_aton`` -- and so ``getaddrinfo`` -- reads in `text`."""
    parts = text.split(".")
    if not 1 <= len(parts) <= 4 or "" in parts:
        return None
    values = []
    for part in parts:
        if not part.isascii():
            return None
        try:
            if part[:2].lower() == "0x":
                values.append(int(part[2:] or "0", 16))
            elif len(part) > 1 and part[0] == "0":
                values.append(int(part, 8))
            elif part.isdigit():
                values.append(int(part, 10))
            else:
                return None
        except ValueError:
            return None
    *head, last = values
    if any(v > 255 for v in head) or last >= 256 ** (4 - len(head)):
        return None
    number = last
    for index, value in enumerate(head):
        number |= value << (24 - 8 * index)
    return str(ipaddress.IPv4Address(number))


class Resolver:
    """The real resolver's place: ``socket.getaddrinfo``, answered from a table."""

    def __init__(self):
        self.asked = []

    def answer(self, host):
        name = host.decode("ascii") if isinstance(host, bytes) else str(host)
        if not name.isascii():
            # What CPython's socket module does to a str host before the C
            # library sees it -- and it raises UnicodeError where it cannot.
            name = name.encode("idna").decode("ascii")
        self.asked.append(name)
        numeric = _inet_aton(name)
        if numeric is not None:
            return (numeric,)
        try:
            return (str(ipaddress.IPv6Address(name)),)
        except ValueError:
            pass
        key = name.lower()[:-1] if name.endswith(".") else name.lower()
        if key in NAMES:
            return NAMES[key]
        raise socket.gaierror(socket.EAI_NONAME, f"{name} is not in the test's table")

    def getaddrinfo(self, host, port, family=0, type=0, proto=0, flags=0):
        result = []
        for address in self.answer(host):
            if ":" in address.split("%", 1)[0]:
                result.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, port or 0, 0, 0)))
            else:
                result.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port or 0)))
        return result


@pytest.fixture
def resolver(monkeypatch):
    table = Resolver()
    # The module attribute, so both this service's code and core's egress resolve
    # through it (and through nothing else), whatever wrapper was installed.
    monkeypatch.setattr(socket, "getaddrinfo", table.getaddrinfo)
    return table


def _client_host(url):
    """The host the HTTP client would dial for `url`, or None when it cannot."""
    try:
        client = parse_url(requests.Request("GET", url).prepare().url or "")
        (client.host or "").strip("[]").encode("idna")
    except Exception:  # noqa: BLE001 - any failure is "the client cannot dial it"
        return None
    if not client.host:
        return None
    return client.host.strip("[]").rstrip(".").lower()


def _core_refuses(url, allowlist):
    """Core's verdict. An allowlist core will not decide under (an entry too broad
    for its policy, such as #47's `fe80::/10`) refuses everything."""
    try:
        return egress.check_target(url, allowlist).blocked
    except egress.AllowlistTooBroad:
        return True


# --- the guard -------------------------------------------------------------------------


@pytest.mark.parametrize("url, allowlist", CORPUS)
def test_every_spelling_core_refuses_the_backend_refuses_too(resolver, url, allowlist):
    """The #47 corpus through this service's guard. Wherever core's egress policy
    refuses a spelling -- with the corpus row's allowlist, or with none, which is
    what this service has -- the backend refuses it too. The backend holds no
    allowlist, so it may refuse more; never less."""
    refused_by_core = _core_refuses(url, allowlist) or _core_refuses(url, [])
    refusal = views.target_is_out_of_bounds(url)
    if refused_by_core:
        assert refusal, f"{url!r}: core refuses it and the backend admitted it"


@pytest.mark.parametrize("url, allowlist", CORPUS)
def test_what_the_backend_admits_is_the_host_the_client_dials(resolver, url, allowlist):
    """And the other half of #47's oracle: a spelling the backend admits is one the
    client can read, decided on as the host the client dials, at addresses that are
    that host's -- never a name the socket module's IDNA 2003 codec folded."""
    if views.target_is_out_of_bounds(url):
        return
    decision = egress.check_target(url, [])
    assert decision.allowed, (url, decision.reason)
    assert _client_host(url) == decision.host.strip("[]"), (url, decision.host)
    for address in decision.addresses:
        assert ipaddress.ip_address(str(address).split("%", 1)[0]).is_global, (url, address)


@pytest.mark.parametrize(
    "url, why",
    [
        # The guard's own getaddrinfo asked for the literal name, which the
        # attacker's zone answers publicly; the client dials `localhost.evil.test`.
        ("http://%6c%6fcalhost.evil.test/", "percent-escape"),
        # The guard's getaddrinfo folded this to `strasse.test` (IDNA 2003), a
        # public name; the client dials `xn--strae-oqa.test`, loopback here.
        ("http://straße.test/", "IDNA 2003 vs 2008"),
        ("https://straße.test/login", "IDNA 2003 vs 2008, https"),
        # Ports the guard never read and the client cannot.
        ("http://public.test:99999/", "port out of range"),
        ("http://public.test:+80/", "signed port"),
        ("http://public.test:8٠/", "Arabic-Indic digit"),
        # A host the client cannot read at all.
        ("http://pub%zzlic.evil.test/", "malformed escape"),
        ("http://public.test\xa0/", "trailing no-break space"),
        ("http://public.test../", "two root dots"),
    ],
)
def test_the_guard_refuses_what_it_used_to_admit_for_another_host(resolver, url, why):
    """Each of these the old guard admitted: it judged one host (as written, or
    folded with IDNA 2003) and the client dials another, or cannot dial the URL at
    all. Each is refused now, before anything reaches the engine."""
    assert views.target_is_out_of_bounds(url), f"{why}: {url!r} was admitted"


def test_the_guard_resolves_only_the_name_the_client_dials(resolver):
    """No IDNA 2003 lookup of its own: the only name resolved for `straße.test` is
    the A-label the client dials -- never `strasse.test`."""
    views.target_is_out_of_bounds("https://straße.test/")
    assert resolver.asked == ["xn--strae-oqa.test"]


def test_a_public_host_is_still_admitted(resolver):
    assert views.target_is_out_of_bounds("https://public.test/login") is None
    assert views.target_is_out_of_bounds("https://PUBLIC.test./login") is None
    assert views.target_is_out_of_bounds("https://xn--strae-oqa.customer.test/") is None


@pytest.mark.parametrize(
    "url, dialled",
    [
        # Both names public: the old guard resolved `strasse.customer.test` and
        # admitted it, and the engine was sent to `xn--strae-oqa.customer.test`.
        ("https://straße.customer.test/", "xn--strae-oqa.customer.test"),
        # The old guard resolved the literal, which a real resolver does not
        # answer, and refused it -- for the wrong reason.
        ("https://%70ublic.test/login", "public.test"),
    ],
)
def test_a_host_written_otherwise_than_the_client_dials_it_is_refused(resolver, url, dialled):
    """Where the URL's host as written and the host the client dials differ, the
    URL is refused, with the form to write instead. Never looser than before: each
    such URL was either refused, or judged as a host the engine was not sent to."""
    refusal = views.target_is_out_of_bounds(url)
    assert refusal and f"dials {dialled!r}" in refusal, refusal


@pytest.mark.parametrize("name", ["localhost", "metadata", "metadata.google.internal", "instance-data"])
def test_every_name_the_backend_listed_is_still_refused_in_every_spelling(resolver, monkeypatch, name):
    """The names the backend's own list held are refused through core's lists, as
    written and in the spellings that fold to them -- even where the name answers a
    public address, so it is the name that refuses them and not the address."""
    monkeypatch.setitem(NAMES, name, (PUBLIC,))
    fullwidth = "".join(chr(ord(c) + 0xFEE0) if c.isalnum() else c for c in name)
    for spelling in (name, name.upper() + ".", fullwidth, name.replace(".", "。")):
        assert views.target_is_out_of_bounds(f"https://{spelling}/"), spelling


# --- the engagement scope ------------------------------------------------------------


def test_the_scope_is_compared_in_the_form_the_client_dials():
    """Case and the root dot, as before, on both sides."""
    engagement = Engagement(scope_hosts=["Client.Example."])
    assert engagement.covers("app.client.example")
    assert engagement.covers("APP.Client.Example.")
    assert not engagement.covers("client.example.attacker.test")


@pytest.mark.parametrize(
    "host",
    [
        "ａｐｐ.client.example",  # fullwidth: the client's IDNA 2008 reader refuses it
        "app。client.example",  # an ideographic dot
        "pub%zzlic.client.example",  # a malformed percent-escape
        "app.client.example​",  # a zero-width space
        ".app.client.example",  # an empty first label
    ],
)
def test_a_host_the_client_cannot_read_is_covered_by_nothing(host):
    """These were covered: as written, each ends in `.client.example`. The HTTP
    client cannot dial any of them, while the socket module folds several onto a
    name; a scope answer about a host nobody can dial is not one to give."""
    engagement = Engagement(scope_hosts=["client.example", "*.client.example"])
    assert not engagement.covers(host)


def test_a_scope_entry_the_client_cannot_read_authorises_nothing():
    """`ｃｌｉｅｎｔ.example` (fullwidth) covered itself, as written. It names no host the
    client can dial, so it authorises nothing."""
    engagement = Engagement(scope_hosts=["ｃｌｉｅｎｔ.example"])
    assert not engagement.covers("ｃｌｉｅｎｔ.example")
    assert not engagement.covers("client.example")


def test_a_scope_entry_whose_dialled_form_is_a_public_suffix_authorises_nothing():
    """`co%2euk` is one label as written and `co.uk` as the client reads it."""
    engagement = Engagement(scope_hosts=["co%2euk"])
    assert not engagement.covers("bank.co.uk")
    assert not engagement.covers("bank.co%2euk")


def test_an_idna_2003_twin_of_the_scope_is_not_covered():
    """#47 finding 7: a scope of `strasse.customer.test` must not cover
    `straße.customer.test`, which the client dials as `xn--strae-oqa.customer.test`,
    a name the engagement never listed."""
    engagement = Engagement(scope_hosts=["strasse.customer.test"])
    assert not engagement.covers("straße.customer.test")
    assert not engagement.covers("xn--strae-oqa.customer.test")
    assert engagement.covers("strasse.customer.test")


def test_an_idn_scope_still_covers_its_own_spelling():
    engagement = Engagement(scope_hosts=["straße.customer.test"])
    assert engagement.covers("straße.customer.test")
    assert engagement.covers("api.straße.customer.test")
    assert engagement.covers("STRASSE.customer.test") is False
