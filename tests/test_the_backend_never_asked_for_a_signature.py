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
signing at read time yields the same envelope for the same state and there is
nothing to go stale. A STORED signature over an older assurance state, served
beside a current receipt, would vouch for something other than what the reader is
looking at -- which is the failure mode this whole project exists to remove.
"""

from __future__ import annotations

import base64
import json

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from ai_engine.services.cyberengine_client import CyberEngineClient, EngineError
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

pytestmark = pytest.mark.django_db

User = get_user_model()

#: Any well-formed uuid; `reverse` only needs the shape, and this test wants no rows.
_UUID = "00000000-0000-0000-0000-000000000001"


def _user(name="analyst", role=None):
    return User.objects.create_user(
        username=name, password="x", role=role or User.Roles.ANALYST
    )


def _deployment(owner):
    dep = Deployment.objects.create(
        name="checkout-assistant",
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
    return dep


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

    resp = _fetch(dep, _user("reader"))

    assert resp.status_code == 200
    assert resp.data["signed"] is True
    assert resp.data["reason"] is None
    assert resp.data["envelope"]["payloadType"].endswith("assurance-receipt+json")

    # What was signed is the receipt this deployment actually produces -- not a
    # re-derivation, not a different document. Compared against the PROJECTION,
    # because a whole-dict comparison against `build_assurance_receipt` cannot
    # succeed: `computed_at` is a wall clock and two builds are microseconds apart.
    # That is the same reason the projection exists, not a concession to the test.
    assert signer.signed == receipt.signable_receipt(receipt.build_assurance_receipt(dep))
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
        (EngineError("Engine unreachable: timed out"), "unreachable"),
        (EngineError("Engine error 503: no signing key"), "no signing key"),
        (RuntimeError("CYBERENGINE_URL is not configured"), "not configured"),
    ],
    ids=["unreachable", "no-key", "not-configured"],
)
def test_an_engine_that_cannot_sign_yields_an_unsigned_receipt_and_the_reason(
    monkeypatch, boom, expected
):
    """Three different failures, three different reasons, and NO envelope in any of
    them. A missing setting and an engine with no key are different things to go
    and fix, and collapsing them would send a reader to the wrong place."""

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


def test_the_same_state_signs_to_the_same_bytes(monkeypatch):
    """The route's whole claim for signing on read instead of storing is that an
    unchanged deployment yields the same envelope every time -- which is what makes
    "did anything change?" answerable by comparing two envelopes. `computed_at`
    alone would break it, and the break would be invisible: every envelope verifies
    fine, they just never match."""
    signer = _Signer()
    _engine(monkeypatch, signer)
    dep = _deployment(_user())

    first = _fetch(dep, _user("a")).data["receipt"]
    second = _fetch(dep, _user("b")).data["receipt"]

    assert first == second
    # Not vacuous: the full payload DOES carry the field that would have broken it.
    # Asserting two builds' clocks differ would itself be a test that can fail for
    # the wrong reason, so the claim is made structurally instead.
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
    to add it here."""
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
    assert receipt.signable_receipt(full) == {"a": 1, "digest": "d"}


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
