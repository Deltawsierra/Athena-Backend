"""The receipt said the engine signs it. Nothing ever asked.

``assurance.receipt`` has said since it was written that the dict it returns is
"the canonical signable payload" and that "signing (Ed25519) is the engine's job,
which owns the keys; this backend produces the object to be signed, not a
signature." Every word of that was true and none of it happened: no code path in
this repo called the engine to sign anything, so the honest disclaimer described
a step that did not exist.

The engine now has the signer (athena-engine #61: DSSE envelope bound to the
document kind, a keyring whose retired keys still verify). This is the call.

Signed on read, not stored. The receipt is deterministic over stable content, so
signing at read time yields the same digest for the same state, in an envelope that
says when it was issued (4.1), and there is nothing to go stale. A STORED signature
over an older assurance state, served beside a current receipt, would vouch for
something other than what the reader is looking at -- which is the failure mode this
whole project exists to remove.
"""

from __future__ import annotations

import base64
import json
import time
from datetime import UTC, datetime, timedelta

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from ai_engine.services.cyberengine_client import (
    ENGINE_REFUSED,
    ENGINE_UNREACHABLE,
    MAX_JSON_DEPTH,
    CyberEngineClient,
    EngineError,
    _nesting_depth,
)
from assurance import receipt, views
from assurance.models import (
    Asset,
    Deployment,
    Evidence,
    EvidenceClass,
    Finding,
    Provider,
    ProviderAssertion,
)
from assurance.views import DeploymentViewSet
from tests.decision_surfaces import stamped_under_the_rules_in_force

pytestmark = pytest.mark.django_db

User = get_user_model()

#: Any well-formed uuid; `reverse` only needs the shape, and this test wants no rows.
_UUID = "00000000-0000-0000-0000-000000000001"

#: The backend's clock, held where a test compares two signed documents whole.
_HELD = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _user(name="analyst", role=None):
    return User.objects.create_user(
        username=name, password="x", role=role or User.Roles.ANALYST
    )


def _deployment(owner, name="checkout-assistant"):
    dep = Deployment.objects.create(
        name=name,
        owner=owner,
        environment=Deployment.Environment.PRODUCTION,
        decision=Deployment.Decision.NEEDS_MORE_EVIDENCE,
    )
    finding = Finding.objects.create(
        deployment=dep,
        fingerprint="fp1",
        finding_type="xss",
        title="F",
        severity="high",
    )
    Evidence.objects.create(
        finding=finding,
        classification=EvidenceClass.VENDOR_ASSERTED,
        source="vendor_doc",
        content_hash="a" * 64,
    )
    provider = Provider.objects.create(
        name="Acme Model Co", kind=Provider.Kind.MODEL_PROVIDER
    )
    ProviderAssertion.objects.create(
        provider=provider, field=ProviderAssertion.Field.REGION, value="us-east-1"
    )
    Asset.objects.create(
        deployment=dep,
        kind=Asset.Kind.MODEL,
        name="gpt-x",
        provider=provider,
        classification=Asset.Classification.APPROVED,
    )
    # The hand-written decision stands for one the rules computed: stamped as such,
    # or the receipt recomputes it (decision.current_decision).
    return stamped_under_the_rules_in_force(dep)


def _fetch(dep, user):
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "signed_assurance_receipt"})
    request = factory.get(
        f"/api/assurance/deployments/{dep.uuid}/signed-assurance-receipt/"
    )
    force_authenticate(request, user=user)
    return view(request, uuid=str(dep.uuid))


class _Signer:
    """An engine that signs. Records what it was handed, because what the backend
    sends is half of what this route is for.

    It returns an envelope over THAT PAYLOAD. It used to return
    ``"payload": "eyJ9"`` -- base64 of ``{"}``, not valid JSON and certainly not the
    receipt -- and all nineteen tests passed, because nothing looked. A fixture that
    encodes an envelope which does not contain the signed document, in a suite about
    signing that document, was declaring the route correct for the wrong reason.
    """

    def __init__(self):
        self.signed = None

    def sign_assurance_receipt(self, payload):
        self.signed = payload
        return _envelope_over(payload)


def _envelope_over(document, *, payload_type=receipt.ASSURANCE_RECEIPT_TYPE, signatures=None):
    """A well-formed DSSE envelope over ``document``, as the engine returns one."""
    return {
        "envelope_version": 1,
        "payloadType": payload_type,
        "payload": base64.b64encode(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        ).decode(),
        "signatures": [{"keyid": "sha256:" + "a" * 32, "sig": "c2ln"}]
        if signatures is None
        else signatures,
    }


def _engine(monkeypatch, engine):
    monkeypatch.setattr(
        CyberEngineClient, "from_settings", classmethod(lambda cls: engine)
    )


# --------------------------------------------------------------- the happy path


def test_the_receipt_is_sent_to_the_engine_and_the_envelope_comes_back(monkeypatch):
    """THE FIX. Before this, nothing in this repo asked the engine for a
    signature."""
    signer = _Signer()
    _engine(monkeypatch, signer)
    dep = _deployment(_user())
    # The backend's clock held, so the document signed and the one rebuilt below are
    # issued at one time and can be compared whole.
    monkeypatch.setattr(receipt, "_utc_now", lambda: _HELD)

    resp = _fetch(dep, _user("reader"))

    assert resp.status_code == 200
    assert resp.data["signed"] is True
    assert resp.data["reason"] is None
    assert resp.data["envelope"]["payloadType"].endswith("assurance-receipt+json")

    # What was signed is the receipt this deployment actually produces -- not a
    # re-derivation, not a different document. Compared against the SIGNED FORM,
    # because a whole-dict comparison against `build_assurance_receipt` cannot
    # succeed: `computed_at` is a wall clock and two builds are microseconds apart.
    # That is the same reason the signed form leaves it out, not a concession to the
    # test.
    assert signer.signed == receipt.signable_receipt(receipt.build_assurance_receipt(dep))
    assert signer.signed["issued_at"] == "2026-01-02T03:04:05Z"
    # And the response serves the signed bytes themselves, not a second document.
    assert resp.data["receipt"] == signer.signed


def test_the_response_says_how_to_verify_and_that_it_is_not_self_verified(monkeypatch):
    """A checker that trusted the signer's own report would establish only that the
    engine agrees with itself, so this route does not verify what it just asked to
    be signed -- it says where to."""
    _engine(monkeypatch, _Signer())
    resp = _fetch(_deployment(_user()), _user("reader"))

    assert "verify offline" in resp.data["verify"]
    assert "keyring" in resp.data["verify"]
    assert "agree with each other" in resp.data["verify"]


# ------------------------------------------------------------- failing closed


@pytest.mark.parametrize(
    "boom,expected",
    [
        (
            EngineError("Engine unreachable: timed out", kind=ENGINE_UNREACHABLE),
            "could not be reached",
        ),
        (
            EngineError("Engine error 503: no signing key", kind=ENGINE_REFUSED, status=503),
            "refused to sign",
        ),
        (RuntimeError("CYBERENGINE_URL is not configured"), "not configured"),
    ],
    ids=["unreachable", "refused", "not-configured"],
)
def test_an_engine_that_cannot_sign_yields_an_unsigned_receipt_and_the_reason(
    monkeypatch, boom, expected
):
    """Three different failures, three different reasons, and NO envelope in any of
    them. A missing setting and an engine that refused are different things to go
    and fix, and collapsing them would send a reader to the wrong place.

    The engine-side reasons are this service's words now, keyed off the failure
    KIND. The second case used to assert ``"no signing key" in reason`` -- the
    engine's own body text, quoted through ``str(exc)`` into the response. That
    assertion is what pinned the leak in place, so it is gone rather than loosened,
    and the paragraph below tests what replaced it.
    """

    class _Broken:
        def sign_assurance_receipt(self, payload):
            raise boom

    _engine(monkeypatch, _Broken())
    dep = _deployment(_user())

    resp = _fetch(dep, _user("reader"))

    # 200, not 500: a 500 would make an unsigned receipt indistinguishable from a
    # broken server, and the receipt itself is still worth reading.
    assert resp.status_code == 200
    assert resp.data["signed"] is False
    assert expected in resp.data["reason"]
    assert resp.data["envelope"] is None, (
        "an envelope alongside signed=False is a receipt that looks signed"
    )
    # The receipt is still there and still correct.
    assert resp.data["receipt"]["digest"] == receipt.build_assurance_receipt(dep)["digest"]


def test_from_settings_refusing_is_caught_and_not_a_500(monkeypatch):
    """`from_settings` raises RuntimeError when the engine is not configured at
    all, and it is raised at client CONSTRUCTION, before any method exists to
    fail. Catching only EngineError would leave an unconfigured deployment
    answering 500 to a read."""

    def _refuse(cls):
        raise RuntimeError("CYBERENGINE_OPERATOR_KEY is not configured")

    monkeypatch.setattr(CyberEngineClient, "from_settings", classmethod(_refuse))
    resp = _fetch(_deployment(_user()), _user("reader"))

    assert resp.status_code == 200
    assert resp.data["signed"] is False
    assert "OPERATOR_KEY" in resp.data["reason"]


def test_signed_is_never_true_without_an_envelope(monkeypatch):
    """The shape is load-bearing: a caller reading `signed` and then `envelope`
    must never get True and None."""
    for engine in (_Signer(),):
        _engine(monkeypatch, engine)
        data = _fetch(_deployment(_user()), _user("r")).data
        assert data["signed"] is (data["envelope"] is not None)


# --------------------------------------------------------------- the surfaces


def test_the_unsigned_route_is_unchanged(monkeypatch):
    """`assurance-receipt` promised existing callers a stable shape. The signed
    surface is BESIDE it, not instead of it -- and it does not call the engine."""

    class _Exploding:
        def sign_assurance_receipt(self, payload):
            raise AssertionError("the unsigned route must not call the engine")

    _engine(monkeypatch, _Exploding())
    dep = _deployment(_user())

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "assurance_receipt"})
    request = factory.get(f"/api/assurance/deployments/{dep.uuid}/assurance-receipt/")
    force_authenticate(request, user=_user("reader"))
    resp = view(request, uuid=str(dep.uuid))

    assert resp.status_code == 200
    # The bare canonical payload, not the wrapper -- no `envelope`, no `verify`,
    # and the receipt's own honesty fields still saying this copy is unsigned.
    assert set(resp.data) == set(receipt.build_assurance_receipt(dep))
    assert resp.data["signed"] is False
    assert resp.data["signature"] is None
    assert resp.data["unsigned_reason"] == receipt.UNSIGNED_REASON
    assert "envelope" not in resp.data


def test_it_is_an_open_read_like_the_rest_of_the_assurance_reads(monkeypatch):
    """A receipt an auditor cannot fetch cannot be verified."""
    _engine(monkeypatch, _Signer())
    dep = _deployment(_user("boss", role=User.Roles.ADMIN))

    resp = _fetch(dep, _user("ana", role=User.Roles.ANALYST))
    assert resp.status_code == 200
    assert resp.data["signed"] is True


def test_the_signed_payload_carries_the_receipts_honesty_through(monkeypatch):
    """A signature over a weak claim is a signature over a weak claim. The
    deployment here is `needs_more_evidence` resting on a `vendor_asserted` claim,
    and signing must not launder either."""
    signer = _Signer()
    _engine(monkeypatch, signer)
    dep = _deployment(_user())

    _fetch(dep, _user("reader"))

    assert signer.signed["result"]["decision"] == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert signer.signed["evidence"]["finding_count"] >= 1


def test_the_client_posts_to_the_engines_sign_route():
    """The method exists and addresses the route the engine actually serves. A
    client method pointing at a path nobody serves would fail only in production."""
    calls = {}

    class _Client(CyberEngineClient):
        def __init__(self):  # no network, no settings
            pass

        def _post(self, path, payload):
            calls["path"] = path
            calls["payload"] = payload
            return {"envelope_version": 1}

    _Client().sign_assurance_receipt({"digest": "d"})
    assert calls["path"] == "/api/assurance/receipt/sign"
    assert calls["payload"] == {"receipt": {"digest": "d"}}


def test_the_client_can_fetch_the_published_keyring():
    calls = {}

    class _Client(CyberEngineClient):
        def __init__(self):
            pass

        def _get(self, path):
            calls["path"] = path
            return {"version": 1, "keys": {}}

    _Client().assurance_keyring()
    assert calls["path"] == "/api/assurance/keyring"


# ------------------------------------------- what a signature is allowed to cover


def test_the_signed_bytes_do_not_deny_their_own_signature(monkeypatch):
    """THE TRAP THIS PROJECTION EXISTS FOR. `build_assurance_receipt` carries
    `signed: false` -- deliberately, so an unsigned copy says so. Hand that dict
    to a signer unchanged and the signature covers the assertion that there is no
    signature. Nothing would have caught it: the envelope verifies, the digest
    matches, and only a human reading the signed payload would notice it says the
    opposite of what the envelope proves."""
    signer = _Signer()
    _engine(monkeypatch, signer)

    _fetch(_deployment(_user()), _user("reader"))

    # A LITERAL, not `for field in receipt.NOT_SIGNED_OVER`. That loop iterated the
    # very constant it was validating, so removing a field from the deny-list
    # removed it from the assertion too -- and `unsigned_reason` really did survive
    # being dropped, putting "THIS COPY is unsigned" back inside the signed bytes
    # with all nineteen tests green. A test that reads its subject as its own oracle
    # cannot fail.
    assert set(receipt.NOT_SIGNED_OVER) == {"computed_at", "signed", "signature", "unsigned_reason"}
    for field in ("computed_at", "signed", "signature", "unsigned_reason"):
        assert field not in signer.signed, f"{field} must not be inside the signed bytes"


def test_the_same_state_signs_to_the_same_digest_and_differs_only_by_its_time(monkeypatch):
    """Two signings of an unchanged deployment carry ONE DIGEST, and differ by the
    time each was issued and by nothing else.

    This used to be `test_the_same_state_signs_to_the_same_bytes`, and it pinned the
    signed document as identical on every read. Ed25519 is deterministic, so the
    envelope was identical too: a signed `ready` from before a regression was, byte
    for byte, the signature the same state would get today, and a retired key goes on
    verifying it for ever. That was the defect (docs/receipt-spec/v4.0.md, sections 1
    and 10), pinned in place as a guarantee.

    This is the truth that replaces it, not a relaxation of it. The question the old
    test protected -- "did anything change?" -- is answered by `digest`, which no
    clock enters and which this still pins exactly, against the unsigned copy's too.
    What moved is the one member that must: `issued_at`, asserted to be exactly the
    backend's clock at each signing. Every other member of the two signed documents
    is still asserted equal."""
    signer = _Signer()
    _engine(monkeypatch, signer)
    dep = _deployment(_user())

    monkeypatch.setattr(receipt, "_utc_now", lambda: _HELD)
    first = _fetch(dep, _user("a")).data["receipt"]
    monkeypatch.setattr(receipt, "_utc_now", lambda: _HELD + timedelta(days=30))
    second = _fetch(dep, _user("b")).data["receipt"]

    assert first["digest"] == second["digest"] == receipt.build_assurance_receipt(dep)["digest"]
    assert (first["issued_at"], second["issued_at"]) == ("2026-01-02T03:04:05Z", "2026-02-01T03:04:05Z")
    assert {k: v for k, v in first.items() if k != "issued_at"} == {
        k: v for k, v in second.items() if k != "issued_at"
    }
    # The render clock is still not what is signed: the full payload carries it, the
    # signed form carries the issue time instead.
    assert "computed_at" in receipt.build_assurance_receipt(dep)
    assert "computed_at" not in first


def test_both_copies_carry_the_same_digest(monkeypatch):
    """An auditor holding the signed copy and an auditor holding
    `assurance-receipt` must be able to tell they are looking at the same
    assurance state. They can, because nothing the projection drops was ever
    inside the digest."""
    _engine(monkeypatch, _Signer())
    dep = _deployment(_user())

    signed = _fetch(dep, _user("reader")).data["receipt"]
    assert signed["digest"] == receipt.build_assurance_receipt(dep)["digest"]


def test_the_response_names_what_was_left_out_and_why(monkeypatch):
    """A reader diffing the two copies finds fields missing. Telling them only in
    a docstring in this repository is telling the one reader who cannot see it."""
    _engine(monkeypatch, _Signer())
    data = _fetch(_deployment(_user()), _user("reader")).data

    assert data["not_signed_over"]["fields"] == list(receipt.NOT_SIGNED_OVER)
    assert "computed_at" in data["not_signed_over"]["why"]
    # Present on the failure branch too -- it describes the projection, which is
    # served either way.
    assert set(data) >= {"receipt", "signed", "reason", "envelope", "not_signed_over"}


def test_the_unsigned_reason_points_at_the_signed_copy():
    """`unsigned_reason` used to say the engine's signing "covers the evidence-pack
    manifest, a different artifact with no path to this one." That path exists now.
    A receipt that still said otherwise would send an auditor away from a signature
    they could have had."""
    assert "signed-assurance-receipt" in receipt.UNSIGNED_REASON
    assert "no path to this one" not in receipt.UNSIGNED_REASON


def test_the_projection_keeps_everything_else():
    """It is a projection, not a rewrite: one dict comprehension over a deny-list,
    so a field added to the receipt tomorrow is signed without anyone remembering
    to add it here -- plus the one member the signed form adds, the time it is
    issued (4.1)."""
    full = {
        "a": 1,
        "digest": "d",
        "computed_at": "t",
        "signed": False,
        "signature": None,
        # Present because its absence is what let a shrunken deny-list survive: this
        # was the one deny-listed field the fixture did not carry, so dropping it
        # from NOT_SIGNED_OVER changed nothing here.
        "unsigned_reason": "because",
    }
    assert receipt.signable_receipt(full, issued_at=_HELD) == {
        "a": 1,
        "digest": "d",
        "issued_at": "2026-01-02T03:04:05Z",
    }


def test_the_route_is_actually_routed():
    """Every test above drives the viewset method directly through `as_view`, which
    would keep passing if the router never exposed it -- an endpoint nobody can
    reach, with a full green suite behind it. So the URL is resolved for real."""
    from django.urls import resolve, reverse

    url = reverse("deployment-signed-assurance-receipt", kwargs={"uuid": _UUID})
    assert url.endswith("/signed-assurance-receipt/")
    assert resolve(url).func.cls is DeploymentViewSet
    # And it is a different endpoint from the unsigned one, not an alias.
    assert url != reverse("deployment-assurance-receipt", kwargs={"uuid": _UUID})


# ------------------------- signed: true meant "the call did not raise" -------
#
# An adversarial pass over the merged route found the one field the response tells
# a reader is authoritative saying `true` for anything the engine handed back. Each
# case below was measured through the real view before it was closed.


@pytest.mark.parametrize(
    "answer,expected",
    [
        ({}, "envelope_version"),
        ({"envelope_version": 2}, "version 1"),
        (
            {
                "envelope_version": 1,
                "payloadType": "application/vnd.mythos.evidence-pack+json",
                "payload": "e30=",
                "signatures": [{"keyid": "k", "sig": "s"}],
            },
            "another document kind",
        ),
        ({"error": "lol", "status": "ok"}, "envelope_version"),
    ],
    ids=["empty-dict", "wrong-version", "wrong-payload-type", "not-an-envelope"],
)
def test_a_thing_that_is_not_an_envelope_is_not_served_as_signed(monkeypatch, answer, expected):
    class _Hostile:
        def sign_assurance_receipt(self, payload):
            return answer

    _engine(monkeypatch, _Hostile())
    data = _fetch(_deployment(_user()), _user("r")).data

    assert data["signed"] is False
    assert data["envelope"] is None
    assert expected in data["reason"]
    # And the receipt is still there and still correct: this is a missing signature,
    # not a broken server.
    assert data["receipt"]["digest"]


@pytest.mark.parametrize(
    "signatures",
    [[], [{}], [{"keyid": "k"}], [{"sig": "s"}], [{"keyid": "", "sig": "s"}]],
    ids=["none", "empty-entry", "no-sig", "no-keyid", "blank-keyid"],
)
def test_an_envelope_nobody_signed_is_not_signed(monkeypatch, signatures):
    """The route's own docstring: "an envelope with an empty signature list would be
    a receipt that looks signed, which is worse than one that says it is not." It
    served exactly that."""

    class _Unsigned:
        def sign_assurance_receipt(self, payload):
            return _envelope_over(payload, signatures=signatures)

    _engine(monkeypatch, _Unsigned())
    data = _fetch(_deployment(_user()), _user("r")).data

    assert data["signed"] is False
    assert data["envelope"] is None


def test_an_envelope_over_a_different_document_is_refused(monkeypatch):
    """THE WORST OF THEM. The envelope attested `ready`; the receipt served beside it
    said `needs_more_evidence`; `signed` said true. A reader is told exactly one
    place to look, and it pointed at a signature on something else.

    Not covered by "verification is the auditor's job": an auditor checks the
    envelope, not the receipt printed next to it, so a compromised engine holding a
    trusted key makes this verify OFFLINE too -- over the forged document.
    """

    class _Substitutes:
        def sign_assurance_receipt(self, payload):
            return _envelope_over({"result": {"decision": "ready"}, "digest": "0" * 64})

    _engine(monkeypatch, _Substitutes())
    dep = _deployment(_user())
    data = _fetch(dep, _user("r")).data

    assert data["signed"] is False
    assert data["envelope"] is None
    assert "DIFFERENT document" in data["reason"]
    assert data["receipt"]["result"]["decision"] == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_a_payload_that_is_not_readable_json_is_refused(monkeypatch):
    class _Garbage:
        def sign_assurance_receipt(self, payload):
            envelope = _envelope_over(payload)
            envelope["payload"] = base64.b64encode(b"{not json").decode()
            return envelope

    _engine(monkeypatch, _Garbage())
    data = _fetch(_deployment(_user()), _user("r")).data
    assert data["signed"] is False
    assert "not readable JSON" in data["reason"]


def test_the_check_compares_content_and_not_bytes(monkeypatch):
    """A signer is entitled to re-serialise. The claim worth making is "the envelope
    contains the document we sent", so an envelope whose JSON differs only in key
    order and whitespace is accepted -- byte equality would refuse a correct
    envelope."""

    class _Reserialises:
        def sign_assurance_receipt(self, payload):
            envelope = _envelope_over(payload)
            envelope["payload"] = base64.b64encode(
                json.dumps(payload, indent=2, sort_keys=False).encode()
            ).decode()
            return envelope

    _engine(monkeypatch, _Reserialises())
    data = _fetch(_deployment(_user()), _user("r")).data
    assert data["signed"] is True
    assert data["envelope"] is not None


def test_signed_is_still_true_for_an_honest_signer(monkeypatch):
    """The control. Every case above must not have made the route refuse everything."""
    signer = _Signer()
    _engine(monkeypatch, signer)
    data = _fetch(_deployment(_user()), _user("r")).data
    assert data["signed"] is True
    assert data["envelope"]["signatures"]
    assert json.loads(base64.b64decode(data["envelope"]["payload"])) == data["receipt"]


def test_the_response_field_list_follows_the_constant(monkeypatch):
    """`not_signed_over.fields` must be DERIVED. A literal that happened to equal
    `list(NOT_SIGNED_OVER)` satisfied the old assertion, so the suite could not tell
    a derived value from a clone -- and the constant exists precisely so the route
    and the tests cannot disagree about what was signed."""
    _engine(monkeypatch, _Signer())
    monkeypatch.setattr(views, "NOT_SIGNED_OVER", ("computed_at",))
    data = _fetch(_deployment(_user()), _user("r")).data
    assert data["not_signed_over"]["fields"] == ["computed_at"]


# ------------------------------------------- the reason must not quote the engine


#: An EngineError message shaped like the real ones. `requests` puts the host and
#: port in for an unreachable engine, and `_excerpt` puts up to MAX_BODY_EXCERPT
#: characters of the engine's own body in for a non-2xx.
_LEAKY_UNREACHABLE = (
    "Engine unreachable: HTTPConnectionPool(host='cyberengine.internal', port=8443): "
    "Max retries exceeded with url: /api/assurance/sign (Caused by "
    "NameResolutionError(\"Failed to resolve 'cyberengine.internal'\"))"
)
_LEAKY_BODY = (
    "Engine error 500: Traceback (most recent call last):\n"
    '  File "/srv/cyberengine/signer.py", line 88, in sign\n'
    "    key = load(os.environ['OPERATOR_KEY_PATH'])  # /etc/athena/operator.pem\n"
    "FileNotFoundError: /etc/athena/operator.pem\nupstream: 10.4.2.19:9000\n"
)

#: Every substring that must not appear in a response served to a reader.
#: The port is matched as the leaked message spells it ("port=8443"): a bare
#: "8443" also turns up by chance in the response's own random ids, digest and
#: microsecond timestamp, which failed this test on a clean run.
_SECRETS = (
    "cyberengine.internal",
    "port=8443",
    "HTTPConnectionPool",
    "/srv/cyberengine/signer.py",
    "/etc/athena/operator.pem",
    "OPERATOR_KEY_PATH",
    "10.4.2.19",
    "Traceback",
)


@pytest.mark.parametrize(
    "boom",
    [
        EngineError(_LEAKY_UNREACHABLE, kind=ENGINE_UNREACHABLE),
        EngineError(_LEAKY_BODY, kind=ENGINE_REFUSED, status=500),
    ],
    ids=["unreachable", "refused-with-a-traceback"],
)
def test_the_engines_own_words_do_not_reach_the_reader(monkeypatch, boom):
    """This route is IsAuthenticated, and `reason` was `str(exc)`.

    So every authenticated reader of an unsigned receipt was served the engine's
    internal hostname and port, and for a non-2xx up to 500 characters of whatever
    body it answered with -- source paths, a key path, an upstream address. None of
    it was ever on the signed route, and none of it is the reader's business.

    Asserted over the WHOLE serialized response rather than over `reason` alone: the
    point is that this text does not leave the process by this door, and a future
    field carrying it would satisfy a check that only read `reason`.
    """

    class _Broken:
        def sign_assurance_receipt(self, payload):
            raise boom

    _engine(monkeypatch, _Broken())
    data = _fetch(_deployment(_user()), _user("reader")).data

    served = json.dumps(data, default=str)
    leaked = [secret for secret in _SECRETS if secret in served]
    assert not leaked, f"the engine's own words reached the reader: {leaked}"

    # ...and the reader is still told something they can act on.
    assert data["signed"] is False
    assert "unsigned" in data["reason"]
    assert data["receipt"]["digest"]


def test_the_engines_message_is_logged_even_though_it_is_not_served(monkeypatch, caplog):
    """Withheld from the reader, not discarded. An operator debugging an unsigned
    receipt needs the engine's address and its body; the difference is who sees it.

    Without this, "do not publish the message" and "lose the message" are the same
    change, and the second makes the failure harder to fix than before."""

    class _Broken:
        def sign_assurance_receipt(self, payload):
            raise EngineError(_LEAKY_UNREACHABLE, kind=ENGINE_UNREACHABLE)

    _engine(monkeypatch, _Broken())
    with caplog.at_level("WARNING", logger="assurance.views"):
        _fetch(_deployment(_user()), _user("reader"))

    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "cyberengine.internal" in logged, "the operator needs the engine's address"
    assert "could not be signed" in logged


def test_the_status_travels_but_the_body_does_not(monkeypatch):
    """A status code is the engine's ANSWER, not its contents: 503 and 500 send an
    operator to different places and neither is a secret. The body is different --
    it is whatever that engine chose to write."""

    class _Broken:
        def sign_assurance_receipt(self, payload):
            raise EngineError(_LEAKY_BODY, kind=ENGINE_REFUSED, status=503)

    _engine(monkeypatch, _Broken())
    data = _fetch(_deployment(_user()), _user("reader")).data

    assert "503" in data["reason"]
    assert "Traceback" not in data["reason"]


def test_a_failure_kind_nobody_wrote_a_reason_for_does_not_fall_back_to_the_message():
    """The hazard the mapping introduces: a NEW kind added to the client with no
    reason written here, falling through to `str(exc)` and reopening the leak. The
    fallback is ours and says plainly that it could not be more specific."""
    from ai_engine.services import cyberengine_client
    from assurance.receipt import unsigned_reason_for

    exc = EngineError(_LEAKY_UNREACHABLE, kind=ENGINE_UNREACHABLE)
    # A kind the mapping does not know. Set after construction because the
    # constructor refuses one it does not recognise -- which is the point of the
    # test below; this one asks what happens if a future kind gets past it.
    exc.kind = "a_kind_added_later"

    reason = unsigned_reason_for(exc)

    assert "cyberengine.internal" not in reason
    assert "could not classify" in reason
    assert cyberengine_client.ENGINE_UNREACHABLE  # the real constants still exist


def test_an_unknown_kind_is_refused_at_construction_rather_than_at_publication():
    """Better still: the client cannot raise an unknown kind in the first place.
    The test above covers a kind smuggled past that check; this covers the check."""
    with pytest.raises(ValueError, match="unknown engine failure kind"):
        EngineError("boom", kind="not-a-kind")


def test_kind_is_required_and_has_no_default():
    """The reasoning behind that, asserted rather than only written down.

    A default would be taken by every raise site nobody updated, and the value of the
    field is that it is always the RIGHT one -- a caller branching on a kind that
    silently means "some other failure" is back to reading the message, which is the
    leak. Mutating the signature to ``kind: str = "refused"`` passed the whole suite
    before this test existed: a new raise site would then quietly claim the engine
    had refused when it had not.
    """
    with pytest.raises(TypeError, match="kind"):
        EngineError("boom")


@pytest.mark.parametrize(
    "call,expected_kind,expected_status",
    [
        ("_get", ENGINE_REFUSED, 503),
        ("_post", ENGINE_REFUSED, 503),
    ],
)
def test_a_refusing_engine_is_classified_with_its_status(
    monkeypatch, call, expected_kind, expected_status
):
    """Both halves at every raise site, not just at one.

    Mutating all three refused sites to drop ``status=resp.status_code`` passed the
    suite: only ``unsigned_reason_for`` was ever asked about a status, and it was
    handed one by a hand-built exception. Nothing checked that the CLIENT records it,
    so the status could stop travelling at the source with the reason-formatting test
    still green.
    """
    import requests

    from ai_engine.services import cyberengine_client

    class _Resp:
        status_code = expected_status
        text = "the engine's own body, which must not travel"

        def json(self):
            return {}

    monkeypatch.setattr(requests, "get", lambda *a, **k: _Resp())
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp())
    client = cyberengine_client.CyberEngineClient("http://engine", "key")

    with pytest.raises(EngineError) as raised:
        getattr(client, call)("/api/x") if call == "_get" else getattr(client, call)("/api/x", {})

    assert raised.value.kind == expected_kind
    assert raised.value.status == expected_status


def test_an_unreachable_engine_is_classified_unreachable_at_every_call(monkeypatch):
    """And not as "refused". Mutating all three unreachable sites to ENGINE_REFUSED
    passed the suite, which would tell a reader the engine had answered and declined
    when it was never reached -- two different things to go and fix, which is the
    distinction the kinds exist to carry."""
    import requests

    from ai_engine.services import cyberengine_client

    def _boom(*args, **kwargs):
        raise requests.RequestException("no route to host")

    monkeypatch.setattr(requests, "get", _boom)
    monkeypatch.setattr(requests, "post", _boom)
    client = cyberengine_client.CyberEngineClient("http://engine", "key")

    for attempt in (lambda: client._get("/api/x"), lambda: client._post("/api/x", {})):
        with pytest.raises(EngineError) as raised:
            attempt()
        assert raised.value.kind == ENGINE_UNREACHABLE
        assert raised.value.status is None


# ------------------- a payload nested past what any engine answer may nest -------
#
# `envelope_over` read the signer's payload with a bare `json.loads` and caught
# `(ValueError, binascii.Error)`. The parser reports nesting past its stack as
# RecursionError, which is neither, so it left `envelope_over` -- whose contract is
# that it raises NotAnEnvelope for anything that is not an envelope over the
# document.
#
# Measured through the real route, that was NOT a 500, and only by an accident of
# ancestry: RecursionError is a RuntimeError, and the route names RuntimeError for a
# different reason (`from_settings` refusing). So the read answered "unsigned", and
# `unsigned_reason_for` -- which publishes `str(exc)` for anything that is not an
# EngineError -- served the interpreter's own sentence as the reason: "maximum
# recursion depth exceeded while decoding a JSON array from a unicode string". That
# is not this service's words, names no cause a reader can act on, and reads as a
# fault in this backend when the fault is in the signer's payload.
#
# The engine's OUTER answer has been depth-checked since round 4 (the client's
# `_json_of`), but the payload is a string INSIDE it, so its nesting was never
# looked at. It is bounded now by the same limit, read by the same linear scan,
# before anything is parsed, and what is refused says so in our words.

#: What "well under a second" means for a case that must not do real work. A request
#: below measures about 20 to 30 ms (it builds a receipt from the database; the first
#: request of a process about 250 ms), and the check on its own a few milliseconds.
#: The bound is generous on purpose: it exists to catch a scan that is quadratic or
#: reads the whole of a hostile payload, not to grade a machine. No sleeps anywhere:
#: the bound is on the work.
_WELL_UNDER_A_SECOND = 1.0

#: A string only a hostile payload carries. If it is ever served or logged, the
#: reason has quoted the payload.
_CANARY = "canary-7f3a9c-from-the-signers-payload"


def _arrays(depth):
    return "[" * depth + "]" * depth


def _objects(depth):
    return '{"a":' * depth + "1" + "}" * depth


def _document_with_a_field_nested(document, arrays):
    """The signed document's own JSON but for one field: ``digest`` becomes ``arrays``
    levels of nesting, and a canary rides beside it. Everything a reader glances at is
    what was sent; only the nesting gives it away.

    Built as TEXT. ``json.dumps`` of the real structure is recursive too, and would
    raise before the case began."""
    head = json.dumps(
        {**document, "digest": None, "note": _CANARY}, sort_keys=True, separators=(",", ":")
    )
    marker = '"digest":null'
    assert head.count(marker) == 1
    return head.replace(marker, '"digest":' + _arrays(arrays))


def _envelope_carrying(document, payload):
    """An envelope that is well formed in every respect but its payload, which is
    ``payload`` (text, encoded as UTF-8, or the bytes themselves): the version, the
    payload type and a signature entry are what an honest signer sends, so the payload
    is the only thing left to make the route refuse it."""
    if isinstance(payload, str):
        payload = payload.encode()
    envelope = _envelope_over(document)
    envelope["payload"] = base64.b64encode(payload).decode()
    return envelope


class _SignsWith:
    """A signer whose payload is whatever ``build(document)`` says."""

    def __init__(self, build):
        self.build = build

    def sign_assurance_receipt(self, payload):
        return _envelope_carrying(payload, self.build(payload))


def _timed(call):
    """``call()`` and the seconds it took. Wrap ONLY the request: the fixtures that
    build users and deployments are outside it on purpose. ``create_user`` hashes a
    password, which costs about a second, and a bound that includes it measures the
    hasher, not the route."""
    started = time.perf_counter()
    result = call()
    return result, time.perf_counter() - started


#: Every one nests past MAX_JSON_DEPTH, in a different way.
_PAST_THE_LIMIT = {
    "arrays-100000-deep": lambda document: _arrays(100_000),
    "objects-100000-deep": lambda document: _objects(100_000),
    "opened-and-never-closed": lambda document: "[" * 100_000,
    # The parser sniffs the encoding, so a scan that read the wrong text would let
    # this one through: the payload picks the encoding.
    "arrays-100000-deep-in-utf-16": lambda document: _arrays(100_000).encode("utf-16"),
    "one-past-the-limit": lambda document: _arrays(MAX_JSON_DEPTH + 1),
    "the-document-with-one-field-nested-past-it": lambda document: (
        _document_with_a_field_nested(document, 100_000)
    ),
}


@pytest.mark.parametrize("build", list(_PAST_THE_LIMIT.values()), ids=list(_PAST_THE_LIMIT))
def test_a_payload_nested_past_the_limit_reads_unsigned_with_the_depth_as_the_reason(
    monkeypatch, caplog, build
):
    """THE FIX, at the route. Master answered 200 unsigned here too, but with the
    interpreter's sentence as the reason (see the note above) -- and for
    ``one-past-the-limit``, which the parser reads without trouble, with "DIFFERENT
    document", which is the wrong reason: a payload the bound refuses is refused for
    its nesting.

    The reason is this service's own words and names the LIMIT, never the payload or
    the parser, and the receipt beside it is still there and still correct."""
    _engine(monkeypatch, _SignsWith(build))
    dep = _deployment(_user())
    reader = _user("reader")

    with caplog.at_level("WARNING", logger="assurance.views"):
        resp, took = _timed(lambda: _fetch(dep, reader))

    assert resp.status_code == 200
    assert resp.data["signed"] is False
    assert resp.data["envelope"] is None, (
        "an envelope alongside signed=False is a receipt that looks signed"
    )
    assert f"deeper than {MAX_JSON_DEPTH} levels" in resp.data["reason"]
    assert resp.data["receipt"]["digest"] == receipt.build_assurance_receipt(dep)["digest"]

    # Not the interpreter's words: that sentence is what master served.
    assert "recursion" not in resp.data["reason"].lower()

    # The payload is the signer's text. It is not the reader's business and not the
    # log's: asserted over the WHOLE response and every log line, not over `reason`.
    served = json.dumps(resp.data, default=str)
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert _CANARY not in served
    assert _CANARY not in logged
    assert "[[[" not in resp.data["reason"] and '{"a"' not in resp.data["reason"]
    assert "NotAnEnvelope" in logged, "the operator still gets the reason in the log"

    assert took < _WELL_UNDER_A_SECOND, f"took {took:.3f}s"


#: Every one nests up to MAX_JSON_DEPTH and no further, and none of them is the
#: document. `at-the-limit` is the deepest a payload may be and still be read.
_UP_TO_THE_LIMIT = {
    "arrays-one-under": lambda document: _arrays(MAX_JSON_DEPTH - 1),
    "arrays-at-the-limit": lambda document: _arrays(MAX_JSON_DEPTH),
    # The document's own keys and values, with `digest` nested. One container is the
    # document itself, so the field carries the rest of the depth.
    "the-document-with-one-field-nested-one-under": lambda document: (
        _document_with_a_field_nested(document, MAX_JSON_DEPTH - 2)
    ),
    "the-document-with-one-field-nested-at-the-limit": lambda document: (
        _document_with_a_field_nested(document, MAX_JSON_DEPTH - 1)
    ),
}


@pytest.mark.parametrize("build", list(_UP_TO_THE_LIMIT.values()), ids=list(_UP_TO_THE_LIMIT))
def test_a_payload_that_nests_up_to_the_limit_is_read_and_refused_as_a_different_document(
    monkeypatch, build
):
    """The other side of the bound. A payload that nests right up to the limit is
    READ -- parsed and compared -- and, differing from the document, refused for THAT
    reason. It is not refused for its nesting, and the comparison it reaches is
    bounded by the limit rather than by the stack.

    Green on master as well, by construction: the bound is new, so nothing that was
    read before it is refused by it. This is what keeps the fix from over-refusing --
    from an off-by-one that turns the limit into a depth of 63."""
    _engine(monkeypatch, _SignsWith(build))
    dep = _deployment(_user())
    reader = _user("reader")

    resp, took = _timed(lambda: _fetch(dep, reader))

    assert resp.status_code == 200
    assert resp.data["signed"] is False
    assert resp.data["envelope"] is None
    assert "DIFFERENT document" in resp.data["reason"]
    assert "deeper than" not in resp.data["reason"]
    assert resp.data["receipt"]["digest"] == receipt.build_assurance_receipt(dep)["digest"]
    assert took < _WELL_UNDER_A_SECOND, f"took {took:.3f}s"


def test_brackets_inside_strings_are_not_nesting(monkeypatch):
    """The control that keeps the bound honest. It reads STRUCTURE. A deployment whose
    NAME is two hundred brackets -- `system.name` is user-supplied and rides inside
    the signed document -- has a receipt whose text is full of `[` and `{` and nests a
    handful of levels. A check that counted bracket characters, or that stopped
    reading at the first quote, would refuse the honest signer, and an honest
    envelope reading unsigned is the opposite failure."""
    signer = _Signer()
    _engine(monkeypatch, signer)
    name = "[{" * 100
    dep = _deployment(_user(), name=name)

    resp = _fetch(dep, _user("reader"))

    assert resp.data["signed"] is True
    assert resp.data["reason"] is None
    assert resp.data["envelope"] is not None
    assert resp.data["receipt"]["system"]["name"] == name
    # Not vacuous: the bytes that were signed really do carry the brackets.
    assert json.dumps(signer.signed).count("[") >= 100


def test_a_real_receipt_nests_far_inside_the_bound():
    """Why the engine-answer limit is safe to apply to the payload. An honest receipt
    nests a handful of levels; if it ever grew toward the bound, the route would start
    reading a VALID envelope as unsigned, and nothing else would say so. Half the bound
    is the tripwire, so the growth is noticed before it breaks signing."""
    document = receipt.signable_receipt(receipt.build_assurance_receipt(_deployment(_user())))
    depth = _nesting_depth(json.dumps(document), limit=10 * MAX_JSON_DEPTH)

    assert 1 <= depth <= MAX_JSON_DEPTH // 2, (
        f"a receipt nests {depth} levels; the signed route reads {MAX_JSON_DEPTH} at most"
    )


def test_a_payload_nested_past_the_limit_is_unsigned_and_not_a_500_through_the_real_url_stack(
    monkeypatch,
):
    """The cases above call the view directly, where an exception that escaped it would
    reach the caller. In production that is a 500. This one drives the real URL and the
    real handler, so the status code itself is what is asserted: a hostile payload must
    never be a 500. Nor does that now rest on `RecursionError` happening to be a
    `RuntimeError` -- `envelope_over` raises only NotAnEnvelope (see the tests below)."""
    _engine(monkeypatch, _SignsWith(lambda document: _arrays(100_000)))
    dep = _deployment(_user())
    client = APIClient()
    client.force_authenticate(user=_user("reader"))
    client.raise_request_exception = False
    url = reverse("deployment-signed-assurance-receipt", kwargs={"uuid": str(dep.uuid)})

    # No timing bound here, unlike the direct-view cases: the real stack includes
    # middleware that makes its own outbound attempt to a Defender engine, so a
    # bound would measure the network, not this route.
    response = client.get(url)

    assert response.status_code == 200, f"the route answered {response.status_code}"
    body = response.json()
    assert body["signed"] is False
    assert body["envelope"] is None
    assert f"deeper than {MAX_JSON_DEPTH} levels" in body["reason"]
    assert "recursion" not in body["reason"].lower()
    assert body["receipt"]["digest"] == receipt.build_assurance_receipt(dep)["digest"]


def test_a_payload_far_past_the_limit_is_refused_without_reading_all_of_it():
    """The scan stops at the first bracket past the limit, so ten million of them cost
    what sixty-five do. A scan that measured the whole payload first is what this
    catches: on this input it would take over two seconds (the depth pass runs at about
    a quarter of a microsecond per bracket), and a hostile signer would choose the
    input."""
    document = {"a": 1}
    envelope = _envelope_carrying(document, "[" * 10_000_000)

    started = time.perf_counter()
    with pytest.raises(receipt.NotAnEnvelope, match=f"deeper than {MAX_JSON_DEPTH} levels"):
        receipt.envelope_over(document, envelope)
    took = time.perf_counter() - started

    assert took < _WELL_UNDER_A_SECOND, f"took {took:.3f}s"


def test_a_payload_at_the_limit_that_equals_the_document_is_still_signed():
    """The accept side of the boundary, through the REAL comparison: a document that
    nests exactly MAX_JSON_DEPTH levels, and an envelope over it, is returned as it
    came. The bound is `>`, not `>=`, and the comparison recurses MAX_JSON_DEPTH deep
    -- the most it ever can after the bound."""
    document = {"deep": json.loads(_arrays(MAX_JSON_DEPTH - 1))}
    assert _nesting_depth(json.dumps(document), limit=MAX_JSON_DEPTH + 1) == MAX_JSON_DEPTH
    envelope = _envelope_over(document)

    assert receipt.envelope_over(document, envelope) is envelope


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-32"])
def test_a_payload_in_another_unicode_encoding_is_read_as_json_reads_it(monkeypatch, encoding):
    """`json.loads(bytes)` sniffs a byte-order mark and reads UTF-16 and UTF-32, and the
    route accepted an envelope whose payload was any of them. The nesting scan decodes
    the same way, so it and the parser always read the same text -- which is also why
    the UTF-16 case above cannot slip past it. Unchanged for an honest payload, and green
    on master."""

    class _Encodes:
        def sign_assurance_receipt(self, payload):
            return _envelope_carrying(payload, json.dumps(payload).encode(encoding))

    _engine(monkeypatch, _Encodes())
    resp = _fetch(_deployment(_user()), _user("reader"))

    assert resp.data["signed"] is True, resp.data["reason"]
    assert resp.data["envelope"] is not None


def test_a_parser_that_runs_out_of_stack_anyway_is_still_not_an_envelope(monkeypatch):
    """The bound makes this unreachable for a payload. It is not the only thing between
    a hostile signer and the interpreter's sentence being served as the reason: a stack
    already nearly spent when the route is called, a limit changed later, a scanner
    bug -- any of them lets `json.loads` recurse, and RecursionError is not a
    ValueError.

    The parser is replaced, because a real overrun cannot be produced portably: from
    3.12 the C parser's recursion is no longer governed by `sys.setrecursionlimit`."""

    def _out_of_stack(*args, **kwargs):
        raise RecursionError("maximum recursion depth exceeded while decoding a JSON array")

    monkeypatch.setattr(json, "loads", _out_of_stack)
    document = {"a": 1}

    with pytest.raises(receipt.NotAnEnvelope, match="too deeply") as refused:
        receipt.envelope_over(document, _envelope_over(document))

    assert "maximum recursion depth" not in str(refused.value), "the parser's words do not travel"


def test_a_comparison_that_runs_out_of_stack_is_still_not_an_envelope():
    """The same, for the comparison. After the bound it recurses at most
    MAX_JSON_DEPTH levels; a comparison that overruns anyway is containment not
    established, which reads unsigned -- never signed, and never anything but
    NotAnEnvelope."""

    class _Unbounded(dict):
        def __ne__(self, other):
            raise RecursionError("maximum recursion depth exceeded in comparison")

        __eq__ = __ne__
        __hash__ = None

    document = _Unbounded(a=1)

    with pytest.raises(receipt.NotAnEnvelope, match="too deeply"):
        receipt.envelope_over(document, _envelope_over(document))
