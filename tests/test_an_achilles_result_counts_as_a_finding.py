"""An Achilles scan's results count in the release decision exactly as Athena's do.

Owner freeze exception 22 (14 Oct 2026), second half: "Achilles results feeding
backend findings and the release decision", under the terms of item 6. Until now an
Achilles scan's verdicts reached this backend nowhere: a critical failure Achilles
found against a deployment left its release decision READY.

What is held here (assurance.achilles_results):

- a result is taken only as the envelope Achilles' scan-result key signed for THIS
  deployment, naming by its digest the result document posted beside it -- unsigned,
  tampered, replayed, wrong-signer and wrong-tenant results are refused, each refusal
  recorded with why, and nothing else of them recorded;
- a screened failure is a finding at its severity, with its provenance (engine,
  release, scan id, evidence digest), and it places the decision exactly where an
  Athena finding of that severity does; an inconclusive one is a gap; a pass is none;
- a result whose capability Achilles has not been screened for (no Validity Card, below
  the screen, a release the screen did not measure) is recorded as informational and
  grades nothing;
- the ingest stops nothing and sits on no stop path.

The new names are imported inside the tests, so on a base without them each test
fails on its own rather than the module failing to collect.
"""

from __future__ import annotations

import ast
import base64
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.utils import timezone
from mythos_core import outcome as oc
from rest_framework.test import APIClient

from assurance.decision import recompute_decision
from assurance.models import Deployment, Evidence, EvidenceClass, Finding, WorkflowChainOutcome
from tests.decision_surfaces import one_decision
from tests.signed_chains import ENGINE_KEYS

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()
ROOT = Path(__file__).resolve().parent.parent
RELEASE = "1.4.0"
CAPABILITIES = ("goal_hijack", "rag_leakage", "tool_misuse", "jailbreak")
_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


# ----------------------------------------------------------------- the world


def _admin():
    return User.objects.create_user(
        username=f"admin{User.objects.count()}-{uuid.uuid4().hex[:6]}", password="x", role=User.Roles.ADMIN
    )


def _client(user=None):
    client = APIClient()
    client.force_authenticate(user=user or _admin())
    return client


def _unassessed():
    return Deployment.objects.create(name=f"achilles-{uuid.uuid4().hex[:8]}", owner=_admin())


def _scanned():
    """A deployment a complete scan found nothing on: READY, stored and current."""
    dep = _unassessed()
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    dep.refresh_from_db()
    recompute_decision(dep)
    return Deployment.objects.get(pk=dep.pk)


def _result(scenario_id="goal_hijack.direct", *, verdict="fail", severity="critical", capability=None):
    failed = verdict == "fail"
    return {
        "scenario_id": scenario_id,
        "capability": capability or scenario_id.split(".")[0],
        "verdict": verdict,
        "severity": severity if failed else "info",
        "evidence_tier": "authority_violation" if failed else None,
        "confidence": None if verdict == "inconclusive" else 0.65,
        "title": f"Probe {scenario_id}",
        "implication": "The assistant crossed the boundary it is approved to keep." if failed else "",
        "recommendation": "Constrain the assistant's instructions and re-test." if failed else "",
    }


def _document(dep, results, *, scan_id=None, release=RELEASE, status="completed", when=None, deployment=None):
    when = when or datetime.now(dt_timezone.utc) - timedelta(minutes=1)
    return {
        "schema": "mythos.achilles-scan-result/v1",
        "deployment": deployment or str(dep.uuid),
        "scan_id": scan_id or f"scan-{uuid.uuid4().hex[:12]}",
        "release": release,
        "observed_at": when.astimezone(dt_timezone.utc).strftime(_FORMAT),
        "status": status,
        "evidence_pack": {"pack_head": "ab" * 32, "anchored": True},
        "results": results,
    }


def _envelope(document, *, key="achilles-scan", engine=None, deployment=None, status=None, outcome_id=None,
              private_key=None):
    """The outcome Achilles' scan-result key signs over ``document``."""
    status = status or (oc.HELD if document["status"] == "completed" else oc.INCOMPLETE)
    outcome = oc.build_outcome(
        deployment=deployment or document["deployment"],
        workflow="achilles-scan",
        status=status,
        engine=engine or key,
        engine_version=document["release"],
        run_id=document["scan_id"],
        evidence_digest=oc.evidence_digest_of(document),
        observed_at=datetime.strptime(document["observed_at"], _FORMAT).replace(tzinfo=dt_timezone.utc),
        reason="" if status == oc.HELD else "the operator stopped the scan before it finished",
        outcome_id=outcome_id,
    )
    return oc.sign_outcome(outcome, private_key or ENGINE_KEYS[key])


def _post(dep, body, client=None):
    return (client or _client()).post(
        f"/api/assurance/deployments/{dep.uuid}/achilles-scan-results/", body, format="json"
    )


def _signed(dep, results, **kwargs):
    document = _document(dep, results, **kwargs)
    return {"envelope": _envelope(document), "result": document}


@pytest.fixture
def screened(monkeypatch):
    """Every capability these tests probe screened for :data:`RELEASE`: a Validity Card
    and an answer key named by digest, and the screen passed."""
    from assurance import achilles_results

    monkeypatch.setattr(
        achilles_results,
        "SCREENED",
        {
            capability: achilles_results.Screen(
                validity_card="sha256:" + "1" * 64,
                answer_key="sha256:" + "2" * 64,
                passed=True,
                releases=frozenset({RELEASE}),
            )
            for capability in CAPABILITIES
        },
    )


def _recorded(dep):
    from assurance.models import AchillesScanResult

    return list(AchillesScanResult.objects.filter(deployment=dep))


def _refusals(dep):
    from assurance.models import AchillesScanRefusal

    return list(AchillesScanRefusal.objects.filter(deployment=dep).order_by("id"))


def _achilles_findings(dep):
    return list(Finding.objects.filter(deployment=dep, finding_type__startswith="achilles."))


# ------------------------------------------------- a screened result is a finding


def test_a_screened_failure_becomes_a_finding_with_its_provenance(screened):
    dep = _scanned()
    body = _signed(
        dep,
        [
            _result("goal_hijack.direct", severity="critical"),
            _result("rag_leakage.cross_context", verdict="inconclusive"),
            _result("tool_misuse.scope_escalation", verdict="pass"),
        ],
    )
    response = _post(dep, body)
    assert response.status_code == 201, response.content
    answer = response.json()
    assert len(answer["findings"]) == 2
    assert answer["informational"] == []
    dispositions = {g["scenario_id"]: g["disposition"] for g in answer["grading"]}
    assert dispositions == {
        "goal_hijack.direct": "finding",
        "rag_leakage.cross_context": "finding",
        "tool_misuse.scope_escalation": "no_finding",
    }

    document = body["result"]
    failure = Finding.objects.get(deployment=dep, location="achilles:goal_hijack.direct")
    assert failure.severity == "critical"
    assert failure.finding_type == "achilles.goal_hijack"
    assert failure.retest_required is True
    assert failure.status == Finding.Status.OPEN
    assert failure.scan is None
    row = _recorded(dep)[0]
    outcome_id = row.outcome_id
    provenance = {
        "engine": "achilles",
        "release": RELEASE,
        "scan_id": document["scan_id"],
        "outcome_id": outcome_id,
        "evidence_digest": oc.evidence_digest_of(document),
        "pack_head": "ab" * 32,
    }
    for name, value in provenance.items():
        assert failure.raw[name] == value, name
    evidence = Evidence.objects.get(finding=failure)
    assert evidence.source == "achilles_scan"
    assert evidence.classification == EvidenceClass.PARTIALLY_VERIFIED
    for name, value in provenance.items():
        assert evidence.raw[name] == value, name

    gap = Finding.objects.get(deployment=dep, location="achilles:rag_leakage.cross_context")
    assert gap.severity == "info"
    assert Evidence.objects.get(finding=gap).classification == EvidenceClass.UNKNOWN
    assert not Finding.objects.filter(deployment=dep, location="achilles:tool_misuse.scope_escalation").exists()

    assert row.scan_id == document["scan_id"]
    assert row.release == RELEASE
    assert row.evidence_digest == oc.evidence_digest_of(document)
    assert row.document == document
    assert one_decision(dep, _client()) == Deployment.Decision.NOT_RECOMMENDED


def _athena_twin(severity):
    """A deployment Athena's own ingest found one finding of ``severity`` on."""
    from pentest.models import PentestScan

    from assurance import ingest

    dep = _unassessed()
    scan = PentestScan.objects.create(
        user=dep.owner,
        target_url="https://app.example/",
        consent=True,
        status=PentestScan.STATUS_COMPLETED,
        engine_response={"findings": [{"type": "goal_hijack", "severity": severity, "title": "Goal hijack"}]},
    )
    ingest.ingest_scan(scan, deployment=Deployment.objects.get(pk=dep.pk))
    return dep


@pytest.mark.parametrize("severity", ["low", "medium", "high", "critical"])
def test_an_achilles_failure_places_the_decision_where_athenas_finding_does(screened, severity):
    """The same rule, read off the same rows: an Achilles failure of a severity and an
    Athena finding of that severity put their deployments in one place."""
    client = _client()
    athena = _athena_twin(severity)
    dep = _scanned()
    response = _post(dep, _signed(dep, [_result(severity=severity)]))
    assert response.status_code == 201, response.content
    finding = Finding.objects.get(deployment=dep, finding_type="achilles.goal_hijack")
    twin = Finding.objects.get(deployment=athena)
    assert (finding.severity, finding.retest_required, finding.evidence_class) == (
        twin.severity,
        twin.retest_required,
        twin.evidence_class,
    )
    assert one_decision(dep, client) == one_decision(athena, client)


@pytest.mark.parametrize(
    ("severity", "decision"),
    [("critical", Deployment.Decision.NOT_RECOMMENDED), ("high", Deployment.Decision.NEEDS_REMEDIATION)],
)
def test_a_blocking_achilles_finding_blocks_the_release_decision(screened, severity, decision):
    dep = _scanned()
    client = _client()
    assert one_decision(dep, client) == Deployment.Decision.READY
    response = _post(dep, _signed(dep, [_result(severity=severity)]))
    assert response.status_code == 201, response.content
    assert one_decision(dep, client) == decision


def test_a_benign_result_does_not_block_and_lifts_nothing(screened):
    ready, unassessed = _scanned(), _unassessed()
    client = _client()
    benign = [_result(f"{capability}.probe", verdict="pass") for capability in CAPABILITIES]
    for dep in (ready, unassessed):
        response = _post(dep, _signed(dep, benign))
        assert response.status_code == 201, response.content
        assert response.json()["findings"] == []
        assert _achilles_findings(dep) == []
    assert one_decision(ready, client) == Deployment.Decision.READY
    # A clean Achilles scan is not an assessment that lifts a deployment nothing has
    # assessed: an Achilles result only ever holds a decision back.
    assert one_decision(unassessed, client) is None


def test_an_inconclusive_run_is_a_gap_never_a_pass(screened):
    dep = _scanned()
    response = _post(dep, _signed(dep, [_result("jailbreak.crescendo", verdict="inconclusive")]))
    assert response.status_code == 201, response.content
    assert one_decision(dep, _client()) == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_an_inconclusive_run_never_lowers_a_failure(screened):
    dep = _scanned()
    first = datetime.now(dt_timezone.utc) - timedelta(minutes=10)
    assert _post(dep, _signed(dep, [_result(severity="critical")], when=first)).status_code == 201
    later = _signed(dep, [_result(verdict="inconclusive")], when=first + timedelta(minutes=5))
    assert _post(dep, later).status_code == 201
    failure = Finding.objects.get(deployment=dep, location="achilles:goal_hijack.direct", severity="critical")
    assert Evidence.objects.get(finding=failure).classification == EvidenceClass.PARTIALLY_VERIFIED
    assert one_decision(dep, _client()) == Deployment.Decision.NOT_RECOMMENDED


def test_an_aborted_scan_records_what_it_found(screened):
    dep = _scanned()
    body = _signed(dep, [_result(severity="high")], status="aborted")
    response = _post(dep, body)
    assert response.status_code == 201, response.content
    assert _recorded(dep)[0].scan_status == "aborted"
    assert one_decision(dep, _client()) == Deployment.Decision.NEEDS_REMEDIATION


# ------------------------------------------------------- each refusal, recorded


def _refused(dep, response, code, *, status_code=400):
    """The refusal answered and recorded, and nothing else of the result recorded."""
    assert response.status_code == status_code, response.content
    answer = response.json()
    assert answer["recorded"] == 0
    assert answer["refused"]["code"] == code, answer
    assert answer["refusal_recorded"] is True
    refusals = _refusals(dep)
    assert refusals and refusals[-1].code == code
    assert refusals[-1].reason == answer["refused"]["reason"]
    return refusals[-1]


def _nothing_recorded(dep, decision):
    assert _recorded(dep) == []
    assert _achilles_findings(dep) == []
    assert one_decision(dep, _client()) == decision


def _unsigned_bodies(dep):
    document = _document(dep, [_result()])
    signed = _envelope(document)
    stranger = Ed25519PrivateKey.generate()
    return {
        "no envelope": {"result": document},
        "no signature": {"envelope": {**signed, "signatures": []}, "result": document},
        "a key this deployment does not trust": {
            "envelope": _envelope(document, private_key=stranger),
            "result": document,
        },
    }


@pytest.mark.parametrize("case", ["no envelope", "no signature", "a key this deployment does not trust"])
def test_an_unsigned_result_is_refused_and_recorded(screened, case):
    dep = _scanned()
    _refused(dep, _post(dep, _unsigned_bodies(dep)[case]), "unsigned")
    _nothing_recorded(dep, Deployment.Decision.READY)


def test_a_result_altered_after_signing_is_refused_and_recorded(screened):
    dep = _scanned()
    body = _signed(dep, [_result(severity="critical")])
    body["result"]["results"][0]["severity"] = "low"
    refusal = _refused(dep, _post(dep, body), "tampered")
    assert "not the document the signature names" in refusal.reason
    assert refusal.outcome_id and refusal.scan_id == body["result"]["scan_id"]
    _nothing_recorded(dep, Deployment.Decision.READY)


def test_a_forged_signature_is_refused_and_recorded(screened):
    dep = _scanned()
    body = _signed(dep, [_result(severity="critical")])
    signature = bytearray(base64.b64decode(body["envelope"]["signatures"][0]["sig"]))
    signature[0] ^= 0x01
    body["envelope"]["signatures"][0]["sig"] = base64.b64encode(bytes(signature)).decode("ascii")
    refusal = _refused(dep, _post(dep, body), "tampered")
    # A forged envelope's claims are not kept: only its digest and the key it names.
    assert refusal.outcome_id == "" and refusal.scan_id == ""
    assert refusal.envelope_digest.startswith("sha256:")
    _nothing_recorded(dep, Deployment.Decision.READY)


def test_the_same_result_posted_twice_is_refused_the_second_time(screened):
    dep = _scanned()
    body = _signed(dep, [_result(severity="high")])
    assert _post(dep, body).status_code == 201
    refusal = _refused(dep, _post(dep, body), "replayed")
    assert "already recorded" in refusal.reason
    assert len(_recorded(dep)) == 1


def test_a_scan_signed_again_under_a_new_outcome_is_refused(screened):
    dep = _scanned()
    body = _signed(dep, [_result(severity="high")])
    assert _post(dep, body).status_code == 201
    again = {"envelope": _envelope(body["result"]), "result": body["result"]}
    refusal = _refused(dep, _post(dep, again), "replayed")
    assert body["result"]["scan_id"] in refusal.reason
    assert len(_recorded(dep)) == 1


def test_an_older_result_after_a_newer_one_is_refused(screened):
    dep = _scanned()
    now = datetime.now(dt_timezone.utc)
    newer = _signed(dep, [_result(severity="critical")], when=now - timedelta(minutes=1))
    older = _signed(dep, [_result(verdict="pass")], when=now - timedelta(hours=1))
    assert _post(dep, newer).status_code == 201
    refusal = _refused(dep, _post(dep, older), "replayed")
    assert "older than the newest" in refusal.reason
    assert len(_recorded(dep)) == 1


def test_a_result_older_than_the_window_is_refused(screened):
    dep = _scanned()
    stale = _signed(dep, [_result(severity="critical")], when=datetime.now(dt_timezone.utc) - timedelta(days=31))
    _refused(dep, _post(dep, stale), "replayed")
    _nothing_recorded(dep, Deployment.Decision.READY)


def test_a_result_signed_for_another_deployment_is_refused_and_recorded(screened):
    dep, other = _scanned(), _scanned()
    body = _signed(other, [_result(severity="critical")])
    refusal = _refused(dep, _post(dep, body), "wrong_tenant")
    assert str(other.uuid) in refusal.reason
    _nothing_recorded(dep, Deployment.Decision.READY)
    _nothing_recorded(other, Deployment.Decision.READY)


def test_a_document_naming_another_deployment_is_refused_and_recorded(screened):
    dep, other = _scanned(), _scanned()
    document = _document(dep, [_result(severity="critical")], deployment=str(other.uuid))
    body = {"envelope": _envelope(document, deployment=str(dep.uuid)), "result": document}
    _refused(dep, _post(dep, body), "wrong_tenant")
    _nothing_recorded(dep, Deployment.Decision.READY)


def test_a_caller_without_the_deployment_records_nothing(screened):
    dep = _scanned()
    viewer = User.objects.create_user(username=f"viewer-{uuid.uuid4().hex[:6]}", password="x", role=User.Roles.VIEWER)
    response = _post(dep, _signed(dep, [_result(severity="critical")]), client=_client(viewer))
    assert response.status_code in (403, 404), response.content
    assert _refusals(dep) == []
    _nothing_recorded(dep, Deployment.Decision.READY)


@pytest.mark.parametrize("signer", ["achilles", "achilles-effect", "athena"])
def test_a_result_signed_by_any_other_key_is_refused(screened, signer):
    dep = _scanned()
    document = _document(dep, [_result(severity="critical")])
    body = {"envelope": _envelope(document, key=signer), "result": document}
    _refused(dep, _post(dep, body), "wrong_signer")
    _nothing_recorded(dep, Deployment.Decision.READY)


def test_a_scan_key_naming_another_engine_is_refused(screened):
    dep = _scanned()
    document = _document(dep, [_result(severity="critical")])
    body = {"envelope": _envelope(document, engine="achilles", private_key=ENGINE_KEYS["achilles-scan"]),
            "result": document}
    _refused(dep, _post(dep, body), "wrong_signer")
    _nothing_recorded(dep, Deployment.Decision.READY)


@pytest.mark.parametrize(
    "case",
    ["a failure with no severity", "a held outcome over an aborted scan", "an extra field"],
)
def test_a_result_this_deployment_cannot_read_is_refused(screened, case):
    dep = _scanned()
    if case == "a failure with no severity":
        bad = _result(severity="critical")
        bad["severity"] = "info"
        document = _document(dep, [bad])
        envelope = _envelope(document)
    elif case == "a held outcome over an aborted scan":
        document = _document(dep, [_result()], status="aborted")
        envelope = _envelope(document, status=oc.HELD)
    else:
        document = {**_document(dep, [_result()]), "transcript": "the whole conversation"}
        envelope = _envelope(document)
    _refused(dep, _post(dep, {"envelope": envelope, "result": document}), "malformed")
    _nothing_recorded(dep, Deployment.Decision.READY)


def test_without_a_keyring_nothing_is_verified_and_the_refusal_is_recorded(screened, monkeypatch):
    from assurance import observed_outcomes

    dep = _scanned()
    monkeypatch.delenv(observed_outcomes.KEYRING_ENV)
    _refused(dep, _post(dep, _signed(dep, [_result()])), "keyring_unavailable", status_code=503)
    _nothing_recorded(dep, Deployment.Decision.READY)


# ----------------------------------------------- unscreened: informational only


def test_the_screen_is_empty_until_a_validity_card_exists():
    """No Achilles capability has a Validity Card yet, so none grades. Screening one is
    a reviewed change to this registry -- and to this test."""
    from assurance import achilles_results

    assert dict(achilles_results.SCREENED) == {}


def _screen(passed=True, releases=(RELEASE,), card="sha256:" + "1" * 64):
    from assurance import achilles_results

    return achilles_results.Screen(
        validity_card=card, answer_key="sha256:" + "2" * 64, passed=passed, releases=frozenset(releases)
    )


@pytest.mark.parametrize(
    ("case", "why"),
    [
        ("no Validity Card", "no Validity Card on record"),
        ("below the screen", "below the benchmark screen"),
        ("another release screened", "not on '1.4.0'"),
        ("a record naming no card", "does not name a Validity Card"),
    ],
)
def test_an_unscreened_result_is_informational_and_grades_nothing(monkeypatch, case, why):
    from assurance import achilles_results

    entries = {
        "no Validity Card": {},
        "below the screen": {"goal_hijack": _screen(passed=False)},
        "another release screened": {"goal_hijack": _screen(releases=("1.3.0",))},
        "a record naming no card": {"goal_hijack": _screen(card="a card, trust me")},
    }
    monkeypatch.setattr(achilles_results, "SCREENED", entries[case])
    client = _client()
    for dep, decision in ((_scanned(), Deployment.Decision.READY), (_unassessed(), None)):
        response = _post(dep, _signed(dep, [_result(severity="critical")]))
        assert response.status_code == 201, response.content
        answer = response.json()
        assert answer["findings"] == []
        [informational] = answer["informational"]
        assert informational["scenario_id"] == "goal_hijack.direct"
        assert why in informational["why"]
        assert _recorded(dep)[0].grading[0]["disposition"] == "informational"
        assert _achilles_findings(dep) == []
        assert one_decision(dep, client) == decision


# ------------------------------------------------------- the other signed routes


def test_the_chain_outcome_route_refuses_a_scan_result(screened):
    dep = _scanned()
    body = _signed(dep, [_result(severity="critical")])
    response = _client().post(
        f"/api/assurance/deployments/{dep.uuid}/chain-outcomes/observed/", body["envelope"], format="json"
    )
    assert response.status_code == 400, response.content
    [refusal] = response.json()["refused"]
    assert "achilles-scan-results" in refusal["reason"]
    assert not WorkflowChainOutcome.objects.filter(deployment=dep).exists()


def test_the_read_lists_what_was_recorded_and_what_was_refused(screened):
    dep = _scanned()
    accepted = _signed(dep, [_result(severity="high")])
    assert _post(dep, accepted).status_code == 201
    assert _post(dep, accepted).status_code == 400
    listing = _client().get(f"/api/assurance/deployments/{dep.uuid}/achilles-scan-results/").json()
    assert listing["recorded_count"] == 1 and listing["refused_count"] == 1
    assert listing["results"][0]["scan_id"] == accepted["result"]["scan_id"]
    assert listing["refusals"][0]["code"] == "replayed"
    assert listing["truncated"] is False


# ------------------------------------------------------------------- safety


def test_the_ingest_is_evidence_and_no_stop():
    from safety.stops import NOT_STOPS, STOP_ROUTES

    assert "deployment-achilles-scan-results" not in STOP_ROUTES
    assert set(NOT_STOPS["deployment-achilles-scan-results"]) == {"GET", "POST"}


def test_nothing_on_a_stop_path_imports_the_ingest():
    """The stop, pause and revoke paths (safety, failsafe) import nothing of it, so no
    stop can wait on it."""
    from assurance import achilles_results  # noqa: F401 -- the module under test exists

    for package in ("safety", "failsafe"):
        for path in sorted((ROOT / package).rglob("*.py")):
            # Settings files are never read, by this test or anything else.
            if "migrations" in path.parts or "settings" in path.name:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or "", *(alias.name for alias in node.names)]
                assert not any("achilles_results" in name for name in names), path
