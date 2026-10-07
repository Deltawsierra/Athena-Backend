"""A closure stands only on a replay the engine service recorded (Phase 6 item 3, A1).

``assurance.retest_closure.record_closure_evidence`` had no caller: the closure gate
read evidence nothing could write, so no retest-gated finding could be closed at
all. ``POST /api/assurance/findings/<uuid>/closure-evidence/`` is its one route. It
takes one finding's retest-evidence document -- Minotaur-Backend's remediation
replay row (``reached``, ``original_effect``, ``variants``, ``utility``) with the
gate's fixture document -- from the engine's own service identity only, refuses
anything it cannot read whole, and stores what it can through
``record_closure_evidence``. The gate then decides as it always has; a record that
carries a replay is held to it as well, so a replay that did not show the effect
gone (inconclusive, unreachable, cosmetic, partial, utility-breaking) is kept and
closes nothing. FREEZE.md: "No closing remediation because a ticket status changed
-- closure is effect-backed only."
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from assurance.models import ClaimEvidence, Deployment, Finding, RetestClosureEvidence
from tests.repair_contracts import agree, held_to
from assurance.retest_closure import (
    CLOSABLE,
    INCOMPLETE_REPAIR,
    INCOMPLETE_REPAIR_PATTERNS,
    NOT_CLOSABLE,
    VERIFIED_CLOSED,
    record_closure_evidence,
    refusal_reasons,
)

pytestmark = pytest.mark.django_db

User = get_user_model()

#: The engine service's pre-shared credential, as the tests configure it. Long
#: enough to be accepted (closure_evidence.MIN_TOKEN_LENGTH); used nowhere else.
SERVICE_CREDENTIAL = "closure-evidence-engine-service-test-only-0000"
SERVICE_ACCOUNT = "closure-engine"

COMPLETE = {
    "vulnerable": {"ran": True, "outcome": "failed"},
    "repaired": {"ran": True, "outcome": "passed"},
    "benign": {"ran": True, "outcome": "passed"},
    INCOMPLETE_REPAIR: {p: {"ran": True, "outcome": "failed"} for p in INCOMPLETE_REPAIR_PATTERNS},
}


@pytest.fixture(autouse=True)
def service(settings):
    """The engine's service identity, configured: a dedicated account the credential
    authenticates as, and the credential itself."""
    settings.CLOSURE_EVIDENCE_SERVICE_TOKEN = SERVICE_CREDENTIAL
    settings.CLOSURE_EVIDENCE_SERVICE_USER = SERVICE_ACCOUNT
    account = User.objects.create_user(username=SERVICE_ACCOUNT, role=User.Roles.VIEWER)
    account.set_unusable_password()
    account.save()
    return account


def _admin():
    return User.objects.create_user(
        username=f"admin{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )


def _finding(retest_required=True, **kwargs):
    dep = Deployment.objects.create(name=f"d{Deployment.objects.count()}", owner=_admin())
    defaults = dict(
        deployment=dep, fingerprint=f"fp{Finding.objects.count()}", finding_type="sql_injection",
        title="SQLi", severity="critical", retest_required=retest_required,
    )
    defaults.update(kwargs)
    finding = Finding.objects.create(**defaults)
    # Its repair agreed before it is worked on (assurance.repair_contract); the
    # replay below is held to it.
    agree(finding)
    return finding


def _document(finding, **overrides):
    document = {
        "finding_type": finding.finding_type,
        "finding_ref": str(finding.uuid),
        "engine": "replay-under-test",
        "origin": ClaimEvidence.Origin.INDEPENDENT.value,
        "remediation": {"kind": "parameterised query", "control_changed": "orders search query"},
        "replay": {
            "reached": True,
            "original_effect": "gone",
            "variants": {"restored_reachability": "gone", "displaced_effects": "gone"},
            "utility": "retained",
        },
        "fixtures": copy.deepcopy(COMPLETE),
    }
    if isinstance(finding, Finding):  # held to its repair contract (a stub has none)
        document["contract"] = held_to(finding)
    document.update(copy.deepcopy(overrides))
    return document


def _digest(document):
    """The canonical digest, computed here independently of the module: sorted keys,
    no spaces, UTF-8 -- Minotaur-Backend's ``remediation_outcomes.digest``."""
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _body(document):
    return {"document": document, "content_digest": _digest(document)}


def _url(finding):
    return f"/api/assurance/findings/{finding.uuid}/closure-evidence/"


def _as_service(credential=SERVICE_CREDENTIAL):
    client = APIClient()
    client.credentials(HTTP_X_CLOSURE_EVIDENCE_TOKEN=credential)
    return client


def _post(finding, body, client=None):
    return (client or _as_service()).post(_url(finding), body, format="json")


def _close(finding):
    """The admin's close, through the API: the gate decides it."""
    client = APIClient()
    client.force_authenticate(user=_admin())
    return client.patch(f"/api/assurance/findings/{finding.uuid}/", {"status": "closed"}, format="json")


def _standing(finding):
    client = APIClient()
    client.force_authenticate(user=_admin())
    answer = client.get(f"/api/assurance/findings/{finding.uuid}/")
    assert answer.status_code == 200, answer.content
    return answer.json()["closure"]


# ---------------------------------------------------------------------------
# A replay that shows the effect gone, and the gate's conditions
# ---------------------------------------------------------------------------


def test_a_complete_replay_from_the_engine_service_is_recorded_and_the_close_is_verified(service):
    finding = _finding()
    document = _document(finding)

    answer = _post(finding, _body(document))

    assert answer.status_code == 201, answer.content
    body = answer.json()
    assert body["result"] == VERIFIED_CLOSED and body["reasons"] == []
    assert body["closure"]["standing"] == CLOSABLE, "recording closes nothing by itself"
    (record,) = RetestClosureEvidence.objects.filter(finding=finding)
    assert str(record.uuid) == body["uuid"]
    assert record.fixtures == COMPLETE
    assert record.origin == ClaimEvidence.Origin.INDEPENDENT
    assert record.content_digest == _digest(document)
    assert record.document == document
    assert record.recorded_by == service

    closed = _close(finding)
    assert closed.status_code == 200, closed.content
    assert _standing(finding)["standing"] == VERIFIED_CLOSED


@pytest.mark.parametrize(
    "overrides, reason",
    [
        ({"origin": "vendor"}, "origin: vendor"),
        (
            {"fixtures": {**COMPLETE, INCOMPLETE_REPAIR: {
                **COMPLETE[INCOMPLETE_REPAIR], "displaced_effects": {"ran": True, "outcome": "passed"}}}},
            "displaced_effects: passed",
        ),
        (
            {"fixtures": {k: v for k, v in COMPLETE.items() if k != "benign"}},
            "benign: not recorded",
        ),
        ({"fixtures": {**COMPLETE, "repaired": {"ran": False, "outcome": None}}}, "repaired: not run"),
    ],
    ids=["vendor", "fooled", "benign-missing", "repaired-not-run"],
)
def test_a_recorded_replay_closes_only_where_the_gate_s_conditions_hold(overrides, reason):
    finding = _finding()

    answer = _post(finding, _body(_document(finding, **overrides)))

    assert answer.status_code == 201, answer.content
    assert answer.json()["result"] == "inconclusive"
    assert RetestClosureEvidence.objects.filter(finding=finding).count() == 1, "kept, as a record"
    refused = _close(finding)
    assert refused.status_code == 400
    assert any(reason in r for r in refused.json()["status"]), refused.json()
    assert Finding.objects.get(pk=finding.pk).status != Finding.Status.CLOSED
    assert _standing(finding)["standing"] == NOT_CLOSABLE


def test_a_replay_recorded_before_the_finding_was_seen_again_closes_nothing():
    finding = _finding()
    assert _post(finding, _body(_document(finding))).status_code == 201
    Finding.objects.filter(pk=finding.pk).update(last_seen=timezone.now() + timedelta(minutes=1))

    refused = _close(finding)

    assert refused.status_code == 400
    assert any("recorded before the finding was last observed" in r for r in refused.json()["status"])


# ---------------------------------------------------------------------------
# A replay that did not show the effect gone: kept, and closes nothing
# ---------------------------------------------------------------------------


_GONE_BOTH = {"restored_reachability": "gone", "displaced_effects": "gone"}


@pytest.mark.parametrize(
    "replay, result, reason",
    [
        (
            {"reached": False, "original_effect": "unknown", "variants": _GONE_BOTH, "utility": "unknown"},
            "inconclusive",
            "did not reach the target",
        ),
        (
            {"reached": True, "original_effect": "unknown", "variants": _GONE_BOTH, "utility": "retained"},
            "inconclusive",
            "original scenario",
        ),
        (
            {"reached": True, "original_effect": "gone",
             "variants": {**_GONE_BOTH, "displaced_effects": "unknown"}, "utility": "retained"},
            "inconclusive",
            "displaced_effects",
        ),
        (
            {"reached": True, "original_effect": "gone", "variants": _GONE_BOTH, "utility": "unknown"},
            "inconclusive",
            "legitimate use",
        ),
        (
            {"reached": True, "original_effect": "gone", "variants": {}, "utility": "retained"},
            "inconclusive",
            "no adjacent path",
        ),
        (
            {"reached": True, "original_effect": "present", "variants": _GONE_BOTH, "utility": "retained"},
            "cosmetic",
            "still produces",
        ),
        (
            {"reached": True, "original_effect": "gone",
             "variants": {**_GONE_BOTH, "restored_reachability": "present"}, "utility": "retained"},
            "partial",
            "restored_reachability",
        ),
        (
            {"reached": True, "original_effect": "gone", "variants": _GONE_BOTH, "utility": "broken"},
            "utility_breaking",
            "legitimate use",
        ),
    ],
    ids=[
        "unreachable", "original-unknown", "variant-unknown", "utility-unknown", "no-variants",
        "cosmetic", "partial", "utility-breaking",
    ],
)
def test_a_replay_that_did_not_show_the_effect_gone_is_kept_and_closes_nothing(replay, result, reason):
    """Every fixture proven, an independent observer's, recorded after the finding
    was last seen: everything the gate reads without the replay would carry the
    close. The replay says the effect was not shown gone, so it carries nothing."""
    finding = _finding()

    answer = _post(finding, _body(_document(finding, replay=replay)))

    assert answer.status_code == 201, answer.content
    assert answer.json()["result"] == result
    (record,) = RetestClosureEvidence.objects.filter(finding=finding)
    assert record.document["replay"] == replay, "stored as it was sent"
    refused = _close(finding)
    assert refused.status_code == 400, refused.content
    assert any(reason in r for r in refused.json()["status"]), refused.json()
    served = _standing(finding)
    assert served["standing"] == NOT_CLOSABLE
    assert served["reasons"] == refusal_reasons(finding)


def test_a_later_replay_that_did_not_reach_the_target_outranks_an_earlier_one_that_closed():
    finding = _finding()
    assert _post(finding, _body(_document(finding))).status_code == 201
    unreached = {"reached": False, "original_effect": "unknown", "variants": _GONE_BOTH, "utility": "unknown"}
    assert _post(finding, _body(_document(finding, replay=unreached))).status_code == 201

    assert _close(finding).status_code == 400
    assert _standing(finding)["standing"] == NOT_CLOSABLE


def test_the_gate_reads_a_record_s_replay_and_judges_one_without_a_replay_as_before():
    unreached = _finding()
    document = _document(
        unreached,
        replay={"reached": False, "original_effect": "unknown", "variants": {}, "utility": "unknown"},
    )
    record_closure_evidence(
        unreached, fixtures=copy.deepcopy(COMPLETE), origin=ClaimEvidence.Origin.INDEPENDENT,
        content_digest=_digest(document), document=document,
    )
    assert any("did not reach the target" in r for r in refusal_reasons(unreached))

    unreadable = _finding()
    record_closure_evidence(
        unreadable, fixtures=copy.deepcopy(COMPLETE), origin=ClaimEvidence.Origin.INDEPENDENT,
        content_digest="sha256:ab12", document={"replay": ["not", "a", "replay"], "fixtures": COMPLETE},
    )
    assert any("replay: unreadable" in r for r in refusal_reasons(unreadable))

    # A record without a replay is still judged on everything it was judged on before
    # -- and, since the repair contract, cannot close: it names no contract.
    legacy = _finding()
    record_closure_evidence(
        legacy, fixtures=copy.deepcopy(COMPLETE), origin=ClaimEvidence.Origin.INDEPENDENT,
        content_digest="sha256:ab12",
    )
    (reason,) = refusal_reasons(legacy)
    assert reason.startswith("contract: the closure evidence carries no replay document")


# ---------------------------------------------------------------------------
# What is refused: nothing is stored
# ---------------------------------------------------------------------------


def _without(mapping, key):
    return {k: v for k, v in mapping.items() if k != key}


def _refusals(finding):
    good = _document(finding)
    replay = good["replay"]
    return {
        "body-unknown-field": {**_body(good), "closed": True},
        "body-missing-digest": {"document": good},
        "body-not-an-object": [good],
        "document-unknown-field": _body({**good, "notes": "x"}),
        "document-outcome-sent": _body({**good, "outcome": "verified_closed"}),
        "document-result-sent": _body({**good, "result": "verified_closed"}),
        "document-missing-replay": _body(_without(good, "replay")),
        "remediation-unknown-field": _body({**good, "remediation": {**good["remediation"], "ticket": "J-1"}}),
        "remediation-missing-kind": _body({**good, "remediation": _without(good["remediation"], "kind")}),
        "replay-unknown-field": _body({**good, "replay": {**replay, "closed": True}}),
        "replay-missing-variants": _body({**good, "replay": _without(replay, "variants")}),
        "replay-reached-not-bool": _body({**good, "replay": {**replay, "reached": "yes"}}),
        "replay-reached-number": _body({**good, "replay": {**replay, "reached": 1}}),
        "replay-effect-unknown-word": _body({**good, "replay": {**replay, "original_effect": "fixed"}}),
        "replay-utility-unknown-word": _body({**good, "replay": {**replay, "utility": "fine"}}),
        "replay-variants-list": _body({**good, "replay": {**replay, "variants": ["a"]}}),
        "replay-variant-reading": _body({**good, "replay": {**replay, "variants": {"a": "closed"}}}),
        "replay-variant-padded-name": _body({**good, "replay": {**replay, "variants": {" a": "gone"}}}),
        "replay-too-many-variants": _body(
            {**good, "replay": {**replay, "variants": {f"v{i}": "gone" for i in range(33)}}}
        ),
        "fixtures-unknown-class": _body({**good, "fixtures": {**COMPLETE, "extra": {"ran": True, "outcome": "failed"}}}),
        "fixtures-unknown-pattern": _body({**good, "fixtures": {
            **COMPLETE, INCOMPLETE_REPAIR: {**COMPLETE[INCOMPLETE_REPAIR], "novel": {"ran": True, "outcome": "failed"}}}}),
        "fixtures-run-unknown-field": _body({**good, "fixtures": {
            **COMPLETE, "benign": {"ran": True, "outcome": "passed", "note": "x"}}}),
        "fixtures-ran-not-bool": _body({**good, "fixtures": {**COMPLETE, "benign": {"ran": "true", "outcome": "passed"}}}),
        "fixtures-outcome-unknown-word": _body({**good, "fixtures": {**COMPLETE, "benign": {"ran": True, "outcome": "ok"}}}),
        "fixtures-outcome-not-text": _body({**good, "fixtures": {**COMPLETE, "benign": {"ran": True, "outcome": ["passed"]}}}),
        "fixtures-ran-without-outcome": _body({**good, "fixtures": {**COMPLETE, "benign": {"ran": True}}}),
        "fixtures-not-run-with-outcome": _body({**good, "fixtures": {**COMPLETE, "benign": {"ran": False, "outcome": "passed"}}}),
        "fixtures-patterns-list": _body({**good, "fixtures": {**COMPLETE, INCOMPLETE_REPAIR: []}}),
        "origin-unknown": _body({**good, "origin": "auditor"}),
        "origin-padded": _body({**good, "origin": " independent"}),
        "engine-not-text": _body({**good, "engine": 7}),
        "engine-blank": _body({**good, "engine": "  "}),
        "engine-too-long": _body({**good, "engine": "e" * 501}),
        "engine-nul": _body({**good, "engine": "a\x00b"}),
        "finding-ref-another-finding": _body({**good, "finding_ref": "5b1c0b52-8a40-4c1f-9b55-0d4a1f8a7f10"}),
        "finding-type-another-type": _body({**good, "finding_type": "directory_traversal"}),
        "digest-mismatch": {"document": good, "content_digest": _digest({**good, "engine": "other"})},
        "digest-malformed": {"document": good, "content_digest": "sha256:XYZ"},
        "digest-blank": {"document": good, "content_digest": ""},
        "digest-not-text": {"document": good, "content_digest": 12},
    }


def _refusal_names():
    # Built against a stand-in so the parametrisation needs no database.
    class _Stub:
        finding_type = "sql_injection"
        uuid = "00000000-0000-0000-0000-000000000000"

    return sorted(_refusals(_Stub()))


@pytest.mark.parametrize("name", _refusal_names())
def test_a_document_that_cannot_be_read_whole_is_refused_and_nothing_is_stored(name):
    finding = _finding()

    answer = _post(finding, _refusals(finding)[name])

    assert answer.status_code == 400, (name, answer.status_code, answer.content)
    assert RetestClosureEvidence.objects.count() == 0


def test_an_oversize_body_is_refused_before_it_is_read():
    from assurance import closure_evidence

    finding = _finding()
    body = _body(_document(finding))
    body["document"]["remediation"]["control_changed"] = "x" * (closure_evidence.MAX_BODY_BYTES + 1)

    answer = _post(finding, body)

    assert answer.status_code == 413, answer.content
    assert RetestClosureEvidence.objects.count() == 0


def test_a_body_that_is_not_json_is_refused():
    finding = _finding()
    answer = _as_service().post(_url(finding), {"document": "x"}, format="multipart")
    assert answer.status_code == 415, answer.content
    assert RetestClosureEvidence.objects.count() == 0


def test_an_unknown_finding_is_not_found():
    finding = _finding()
    body = _body(_document(finding))
    for path in ("5b1c0b52-8a40-4c1f-9b55-0d4a1f8a7f10", "not-a-uuid"):
        answer = _as_service().post(f"/api/assurance/findings/{path}/closure-evidence/", body, format="json")
        assert answer.status_code == 404
    assert RetestClosureEvidence.objects.count() == 0
    assert _post(finding, body).status_code == 201, "and the same body is recorded for its own finding"


# ---------------------------------------------------------------------------
# Who may call it: the engine service, and nobody else
# ---------------------------------------------------------------------------


def _signed_in(role):
    client = APIClient()
    user = User.objects.create_user(username=f"{role}{User.objects.count()}", password="x", role=role)
    client.force_authenticate(user=user)
    return client


@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
def test_an_operator_s_own_session_cannot_record_closure_evidence(role):
    finding = _finding()

    answer = _post(finding, _body(_document(finding)), client=_signed_in(role))

    assert answer.status_code == 403, answer.content
    assert RetestClosureEvidence.objects.count() == 0


def test_the_service_account_signed_in_as_itself_is_not_the_service(service):
    finding = _finding()
    client = APIClient()
    client.force_authenticate(user=service)

    assert _post(finding, _body(_document(finding)), client=client).status_code == 403
    assert RetestClosureEvidence.objects.count() == 0


@pytest.mark.parametrize(
    "client",
    [
        lambda: APIClient(),
        lambda: _as_service("closure-evidence-engine-service-test-only-0001"),
        lambda: _as_service(""),
    ],
    ids=["no-credential", "wrong-credential", "empty-credential"],
)
def test_no_credential_or_the_wrong_one_is_unauthenticated(client):
    finding = _finding()

    answer = _post(finding, _body(_document(finding)), client=client())

    assert answer.status_code == 401, answer.content
    assert RetestClosureEvidence.objects.count() == 0


@pytest.mark.parametrize(
    "configure",
    [
        lambda s: setattr(s, "CLOSURE_EVIDENCE_SERVICE_TOKEN", None),
        lambda s: setattr(s, "CLOSURE_EVIDENCE_SERVICE_TOKEN", SERVICE_CREDENTIAL[:31]),
        lambda s: setattr(s, "CLOSURE_EVIDENCE_SERVICE_USER", ""),
        lambda s: setattr(s, "CLOSURE_EVIDENCE_SERVICE_USER", "nobody-of-that-name"),
    ],
    ids=["credential-unset", "credential-too-short", "account-unset", "account-missing"],
)
def test_the_route_is_off_unless_the_service_identity_is_configured(settings, configure):
    finding = _finding()
    configure(settings)

    answer = _post(finding, _body(_document(finding)))

    assert answer.status_code == 401, answer.content
    assert RetestClosureEvidence.objects.count() == 0


def test_an_inactive_service_account_is_unauthenticated(service):
    service.is_active = False
    service.save()
    finding = _finding()

    assert _post(finding, _body(_document(finding))).status_code == 401
    assert RetestClosureEvidence.objects.count() == 0


def test_the_credential_authenticates_nowhere_else():
    finding = _finding()
    client = _as_service()
    assert _post(finding, _body(_document(finding)), client=client).status_code == 201

    assert client.get(f"/api/assurance/findings/{finding.uuid}/").status_code == 401
    assert client.patch(f"/api/assurance/findings/{finding.uuid}/", {"status": "closed"}, format="json").status_code == 401


# ---------------------------------------------------------------------------
# No closure without a stored record
# ---------------------------------------------------------------------------


def test_no_finding_is_verified_closed_without_a_stored_record():
    """Every way of sending a closure that this route refuses stores nothing, and
    with nothing stored the close is refused and nothing is served verified."""
    finding = _finding()
    good = _body(_document(finding))
    attempts = [
        _post(finding, good, client=APIClient()),
        _post(finding, good, client=_signed_in("admin")),
        _post(finding, {**good, "content_digest": _digest({**good["document"], "engine": "x"})}),
        _post(finding, {**good, "verified": True}),
    ]
    assert [a.status_code for a in attempts] == [401, 403, 400, 400]
    assert RetestClosureEvidence.objects.count() == 0

    refused = _close(finding)
    assert refused.status_code == 400
    assert any("no closure evidence recorded" in r for r in refused.json()["status"])
    assert _standing(finding)["standing"] == NOT_CLOSABLE


# ---------------------------------------------------------------------------
# The document, digested as Minotaur-Backend digests a row
# ---------------------------------------------------------------------------


#: A fixed document and its digest. Minotaur-Backend's
#: tests/test_athena_s_closure_document_is_a_dataset_row.py pins the same pair
#: against ``remediation_outcomes.digest(normalize(row))``: the document a producer
#: sends here is the row Minotaur stores, under one digest in both places.
GOLDEN_DOCUMENT = {
    "finding_type": "sql_injection",
    "finding_ref": "0f6f1d1e-3c55-4a8e-9a0e-5f0c2b7d9e11",
    "engine": "closure-replay",
    "origin": "independent",
    "remediation": {"kind": "parameterised query", "control_changed": "orders search query"},
    "replay": {
        "reached": True,
        "original_effect": "gone",
        "variants": {"displaced_effects": "gone", "restored_reachability": "gone"},
        "utility": "retained",
    },
    "fixtures": copy.deepcopy(COMPLETE),
}
GOLDEN_DIGEST = "sha256:de5164072ac7de5a7e262b0a92dff0b6754ddd96794aa7cd02e401c7e99d0bf6"


def test_the_document_s_digest_is_minotaur_s_digest_of_the_same_row():
    from assurance import closure_evidence

    assert closure_evidence.canonical_digest(GOLDEN_DOCUMENT) == _digest(GOLDEN_DOCUMENT) == GOLDEN_DIGEST
