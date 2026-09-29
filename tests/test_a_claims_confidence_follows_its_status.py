"""Roadmap P2.7: one evidence-strength vocabulary, and a claim's confidence that
follows its status.

1. ONE VOCABULARY. A claim's confidence is mythos-core's strength for its evidence
   class (``mythos_core.evidence``, Mythos-Core#31), read from that module at every
   call -- never this app's own ``max(0.1, 1.0 - 0.12 * rank)``, a second mapping
   from evidence to strength that no reader of mythos-core would find. So are the
   rank a finding's weakest evidence is taken by and the qualitative reading of a
   class. The assurance policy pins the core's order of the classes, so a change to
   that table moves the pin and the published decision with it. Every confidence
   the API serves carries ``confidence_basis``: the class and the table, or
   ``"none: "`` and why.
2. IT FOLLOWS THE STATUS A PERSON SETS. A person who moves a claim back to SUPPORTED
   over a derived CONTRADICTED gives it the strength of its evidence class, and one
   who moves it to UNKNOWN over a derived VERIFIED takes its confidence away -- when
   the move is made, and on every re-derive the person's status stands through.
   Both used to keep the deriver's confidence for the deriver's status: None under
   the person's SUPPORTED, 0.88 under the person's UNKNOWN.
3. The machine's STALE marks carry none either, and a retroactive claim takes its
   confidence from its status and class: nobody can type one in.
4. Migration 0048 recomputes the stored confidence of every claim still believed,
   and leaves superseded history as it was closed.
"""

from __future__ import annotations

from datetime import timedelta
from types import MappingProxyType

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone
from mythos_core import evidence as core_evidence
from rest_framework.test import APIClient

from assurance import claims as claims_module
from assurance.change import EVIDENCE_TTL_DAYS
from assurance.claims import apply_claim_transition, derive_claims, record_retroactive_claim
from assurance.decision import compute_decision, current_decision, recompute_decision
from assurance.invalidation import check_invalidations
from assurance.models import (
    EVIDENCE_STRENGTH_ORDER,
    Asset,
    AssuranceClaim,
    Deployment,
    Evidence,
    EvidenceClass,
    Finding,
    evidence_strength,
    qualitative_evidence_label,
)
from assurance.policy import policy_pin
from assurance.serializers import AssuranceClaimSerializer
from tests.test_spine_evidence_audit import _access_claim, _current, _deployment, _user

Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType

CONFIGURATION_VERIFIED = EvidenceClass.CONFIGURATION_VERIFIED.value

#: The table a basis must name: mythos-core's, the one every engine reads.
TABLE = "mythos_core.evidence.strength_from_evidence_class"


def _strength(evidence_class):
    """What mythos-core's table gives ``evidence_class``: the only oracle here."""
    return core_evidence.strength_from_evidence_class(evidence_class)


def _served(claim):
    claim.refresh_from_db()
    return AssuranceClaimSerializer(claim).data


def _contradicted(dep):
    """The deployment's EFFECTIVE_ACCESS claim as the deriver reads it once a tool
    declares ``shell``: CONTRADICTED, on configuration-verified evidence, carrying
    no confidence."""
    _access_claim(dep)
    Asset.objects.filter(deployment=dep, identifier="reporter").update(metadata={"permissions": ["shell"]})
    derive_claims(dep)
    claim = _current(dep)
    assert (claim.status, claim.evidence_class, claim.confidence) == (Status.CONTRADICTED, CONFIGURATION_VERIFIED, None)
    return claim


def _admin_client(name):
    client = APIClient()
    client.force_authenticate(user=_user(name))
    return client


# ---------------------------------------------------------------------------
# 1. One vocabulary: mythos-core's table
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_a_claims_confidence_is_the_strength_mythos_cores_table_gives_its_class(monkeypatch):
    """Fail-first. The number is read through the core's table at every call: a
    table that says something else is what the claim carries. Before, the claim
    carried this app's own 1.0 - 0.12 * rank (0.88 here) whatever the table said."""
    asked = []

    def table(evidence_class):
        asked.append(str(evidence_class))
        return 0.37  # on neither ladder: only the table can have put it there

    monkeypatch.setattr(core_evidence, "strength_from_evidence_class", table)

    claim = _access_claim(_deployment("one-table"))

    assert (claim.status, claim.evidence_class) == (Status.VERIFIED, CONFIGURATION_VERIFIED)
    assert claim.confidence == 0.37
    assert CONFIGURATION_VERIFIED in asked


def test_every_class_under_every_status_reads_the_table_or_none():
    """The whole rule: the table's strength for the class under a status that stands
    on supporting evidence, and none under every other. An unrecognised class is the
    table's floor for it, never a 0 and never a pass."""
    from assurance.claim_confidence import SUPPORTING_STATUSES, claim_confidence

    assert SUPPORTING_STATUSES == {Status.SUPPORTED, Status.PARTIALLY_VERIFIED, Status.VERIFIED}
    classes = [*core_evidence.EVIDENCE_CLASSES, "Configuration_Verified", "", "made-up", None]
    for status in Status.values:
        for evidence_class in classes:
            expected = _strength(evidence_class) if status in SUPPORTING_STATUSES else None
            assert claim_confidence(status, evidence_class) == expected, (status, evidence_class)
            assert claim_confidence(Status(status), evidence_class) == expected, (status, evidence_class)
    floor = claim_confidence(Status.SUPPORTED, "made-up")
    assert floor == _strength("made-up") and 0 < floor < min(_strength(c) for c in core_evidence.EVIDENCE_CLASSES)


def test_the_rank_and_the_qualitative_reading_are_the_core_tables(monkeypatch):
    """Fail-first. This app ranks a class, and reads it qualitatively, by the core's
    table, at every call. Before, both were copies this app kept, and a change to
    the table -- a class reordered, a reading changed -- never reached them."""
    reordered = ("unknown", *(c for c in core_evidence.EVIDENCE_CLASSES if c != "unknown"))
    monkeypatch.setattr(core_evidence, "EVIDENCE_CLASSES", reordered)
    assert evidence_strength(EvidenceClass.UNKNOWN) == 0
    assert evidence_strength("unknown") < evidence_strength(EvidenceClass.TECHNICALLY_VERIFIED)

    relabelled = MappingProxyType({**core_evidence.QUALITATIVE_LABELS, "vendor_asserted": "Hypothesized"})
    monkeypatch.setattr(core_evidence, "QUALITATIVE_LABELS", relabelled)
    assert qualitative_evidence_label(EvidenceClass.VENDOR_ASSERTED) == "Hypothesized"


def test_this_apps_evidence_classes_are_the_core_tables_in_its_order():
    """The app's choices and the core's table name the same classes in the same
    order, each ranked and read as the core ranks and reads it; an unrecognised
    label still ranks below every class and reads Unknown."""
    assert [c.value for c in EvidenceClass] == list(core_evidence.EVIDENCE_CLASSES)
    assert [c.value for c in EVIDENCE_STRENGTH_ORDER] == list(core_evidence.EVIDENCE_CLASSES)
    for rank, name in enumerate(core_evidence.EVIDENCE_CLASSES):
        assert evidence_strength(name) == evidence_strength(EvidenceClass(name)) == rank
        assert qualitative_evidence_label(name) == core_evidence.qualitative_label(name)
    assert evidence_strength("made-up") == len(core_evidence.EVIDENCE_CLASSES)
    assert qualitative_evidence_label("made-up") == "Unknown"


def test_the_class_sets_the_rules_name_are_the_tables_readings():
    """The rules that name sets of classes rather than a number -- which grades may
    back a VERIFIED claim or count as the platform's own observation, and which read
    as unverified or grade nothing -- name exactly the classes the core's table reads
    as Observed and as Unknown. Should the table ever read a class otherwise, this
    fails, and a person decides which rule follows."""
    from assurance import claims, decision
    from assurance import evidence_audit as ea

    def reading(label):
        return {c for c in core_evidence.EVIDENCE_CLASSES if core_evidence.qualitative_label(c) == label}

    assert set(claims._VERIFIED_GRADE) == set(ea._OBSERVED_CLASSES) == reading("Observed")
    assert {str(c) for c in decision._UNVERIFIED} == set(ea._UNGRADED_CLASSES) == reading("Unknown")


@pytest.mark.django_db
def test_a_reordered_core_table_moves_the_pin_and_the_published_decision_follows(monkeypatch):
    """Fail-first. A finding's evidence class is its weakest evidence row's by the
    core's order, and the decision reads it, so the pin moves with that order and a
    stored decision stamped under the old one is recomputed when it is read. Before,
    the pin and the rank both read this app's copy, and the core's table moved
    neither."""
    dep = Deployment.objects.create(name="pin", owner=_user("pin-owner"))
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    finding = Finding.objects.create(
        deployment=dep, fingerprint="fp-info", finding_type="t", title="T", severity="info"
    )
    Evidence.objects.create(finding=finding, classification=EvidenceClass.TECHNICALLY_VERIFIED)
    Evidence.objects.create(finding=finding, classification=EvidenceClass.UNKNOWN)
    before = recompute_decision(Deployment.objects.get(pk=dep.pk))
    pin = policy_pin()

    # "unknown" read as the strongest class: the finding's weakest evidence is now
    # technically verified, and nothing unverified is left open.
    reordered = ("unknown", *(c for c in core_evidence.EVIDENCE_CLASSES if c != "unknown"))
    monkeypatch.setattr(core_evidence, "EVIDENCE_CLASSES", reordered)

    assert policy_pin() != pin
    computed = compute_decision(Deployment.objects.get(pk=dep.pk))
    assert computed != before
    assert current_decision(Deployment.objects.get(pk=dep.pk)) == computed


@pytest.mark.django_db
def test_every_confidence_is_served_with_its_basis():
    """Fail-first. Beside every confidence the API serves, what it is: the core's
    basis line, the evidence class and the table -- or "none: " and why. Before, a
    bare number, which a reader takes for a probability."""
    dep = _deployment("basis")
    verified = _access_claim(dep)
    data = _served(verified)
    assert data["confidence"] == _strength(CONFIGURATION_VERIFIED)
    assert data["confidence_basis"].startswith(core_evidence.CLASS_BASIS)
    assert f"{CONFIGURATION_VERIFIED!r}" in data["confidence_basis"]
    assert TABLE in data["confidence_basis"]

    unknown = _served(_access_claim(_deployment("basis-unknown"), principals=False))
    assert unknown["confidence"] is None
    assert unknown["confidence_basis"].startswith("none: ") and "unknown" in unknown["confidence_basis"]

    client = _admin_client("basis-reader")
    listed = client.get(f"/api/assurance/deployments/{dep.uuid}/assurance-claims/")
    assert listed.status_code == 200, listed.content
    assert listed.json() and all(c["confidence_basis"] for c in listed.json())
    detail = client.get(f"/api/assurance/claims/{verified.uuid}/").json()
    assert (detail["confidence"], detail["confidence_basis"]) == (data["confidence"], data["confidence_basis"])


@pytest.mark.django_db
def test_the_confidence_under_an_evidence_hold_is_served_with_its_basis_too():
    """The served evidence audit carries the confidence of the reading under a hold
    (``base_confidence``); it is served with what it is, as the claim's own is.
    Before, a bare number there too."""
    from assurance import evidence_audit as ea
    from tests.test_spine_evidence_audit import _good

    claim = _access_claim(_deployment("held-basis"))
    ea.record_claim_evidence(claim, **_good(claim, outcome="fail"))
    served = _served(claim)
    audit = served["evidence_audit"]
    assert audit["held"] is True and served["confidence"] is None
    assert audit["base_confidence"] == _strength(CONFIGURATION_VERIFIED)
    assert audit["base_confidence_basis"].startswith(core_evidence.CLASS_BASIS)
    assert f"{CONFIGURATION_VERIFIED!r}" in audit["base_confidence_basis"]


def test_the_basis_says_why_there_is_none_and_never_calls_a_stray_number_the_tables():
    from assurance.claim_confidence import confidence_basis

    for status in (Status.UNKNOWN, Status.CONTRADICTED, Status.STALE, Status.REVOKED, Status.DRAFT, Status.SUPERSEDED):
        basis = confidence_basis(status, CONFIGURATION_VERIFIED, None)
        assert basis.startswith("none: "), basis
        assert len(basis) > len("none: ") + 10, basis
    assert "unknown" in confidence_basis(Status.UNKNOWN, CONFIGURATION_VERIFIED, None)
    assert "contradicted" in confidence_basis(Status.CONTRADICTED, CONFIGURATION_VERIFIED, None)
    assert "stale" in confidence_basis(Status.STALE, CONFIGURATION_VERIFIED, None)
    # A superseded version keeps what it carried when it was closed, and says so.
    closed = confidence_basis(Status.SUPERSEDED, CONFIGURATION_VERIFIED, _strength(CONFIGURATION_VERIFIED))
    assert closed.startswith(core_evidence.CLASS_BASIS) and "superseded" in closed
    # A number that is not the table's for the class is never described as it.
    stray = confidence_basis(Status.SUPPORTED, CONFIGURATION_VERIFIED, 0.5)
    assert not stray.startswith(core_evidence.CLASS_BASIS) and TABLE in stray and "not" in stray


# ---------------------------------------------------------------------------
# 2. It follows the status a person sets
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_a_person_who_moves_a_claim_back_to_supported_gives_it_the_strength_of_its_evidence():
    """Fail-first, one direction. The deriver reads CONTRADICTED (no confidence); a
    person moves it back to SUPPORTED. The claim now stands on its evidence --
    configuration verified -- and carries that class's strength, stored and served,
    on the move and on every re-derive the person's status stands through. Before,
    it kept the deriver's None under the person's SUPPORTED."""
    dep = _deployment("up")
    claim = _contradicted(dep)
    client = _admin_client("up-reviewer")
    moved = client.post(
        f"/api/assurance/claims/{claim.uuid}/transition/",
        {"to_status": "supported", "note": "the shell tool is sandboxed; reviewed"},
        format="json",
    )
    assert moved.status_code == 200, moved.content

    strength = _strength(CONFIGURATION_VERIFIED)
    for moment in ("moved", "re-derived", "re-derived again"):
        current = _current(dep)
        assert current.pk == claim.pk, moment
        assert current.status == Status.SUPPORTED, moment
        assert current.confidence == strength, moment
        served = client.get(f"/api/assurance/claims/{current.uuid}/").json()
        assert served["confidence"] == strength, moment
        assert f"{CONFIGURATION_VERIFIED!r}" in served["confidence_basis"], moment
        assert claims_module._status_set_by_a_person(current), moment
        derive_claims(dep)


@pytest.mark.django_db
def test_a_person_who_moves_a_claim_to_unknown_takes_its_confidence_away():
    """Fail-first, the other direction. The deriver reads VERIFIED (0.88); a person
    moves it to UNKNOWN. An unknown carries no number -- stored, served, on the move
    and on every re-derive the person's status stands through. Before, it kept the
    deriver's 0.88 under the person's UNKNOWN: a confidence for a status the claim no
    longer had."""
    dep = _deployment("down")
    claim = _access_claim(dep)
    assert (claim.status, claim.confidence) == (Status.VERIFIED, _strength(CONFIGURATION_VERIFIED))

    apply_claim_transition(claim, Status.UNKNOWN, actor=_user("down-doubter"), note="the inventory is incomplete")

    for moment in ("moved", "re-derived", "re-derived again"):
        current = _current(dep)
        assert current.pk == claim.pk, moment
        assert current.status == Status.UNKNOWN, moment
        assert current.confidence is None, moment
        served = AssuranceClaimSerializer(current).data
        assert served["confidence"] is None, moment
        assert served["confidence_basis"].startswith("none: ") and "unknown" in served["confidence_basis"], moment
        derive_claims(dep)


@pytest.mark.django_db
def test_a_persons_stop_and_their_move_back_each_carry_the_confidence_of_their_own_status():
    """A person contradicts a VERIFIED claim (none: a stop carries no confidence),
    then moves it back to SUPPORTED on the same evidence: the strength of that
    evidence again. Before, the move back kept the stop's None."""
    dep = _deployment("round-trip")
    claim = _access_claim(dep)
    person = _user("round-trip-person")
    apply_claim_transition(claim, Status.CONTRADICTED, actor=person, note="stop: it reaches prod secrets")
    assert (_current(dep).status, _current(dep).confidence) == (Status.CONTRADICTED, None)

    apply_claim_transition(_current(dep), Status.SUPPORTED, actor=person, note="it does not; the grant was revoked")
    assert (_current(dep).status, _current(dep).confidence) == (Status.SUPPORTED, _strength(CONFIGURATION_VERIFIED))
    derive_claims(dep)
    assert (_current(dep).status, _current(dep).confidence) == (Status.SUPPORTED, _strength(CONFIGURATION_VERIFIED))


# ---------------------------------------------------------------------------
# 3. The machine's stale marks, and a claim recorded after the fact
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_a_stale_mark_leaves_no_confidence_behind():
    """Expired evidence, and an input that drifted, each mark a claim STALE: no
    current evidence supports it, so it carries none. Before, both kept the number
    the claim carried while its evidence was current."""
    from tests.test_assurance_claims import _claim

    dep = _deployment("expired")
    expired = _claim(
        dep,
        fingerprint="expired-fp",
        status=Status.SUPPORTED,
        confidence=_strength(CONFIGURATION_VERIFIED),
        last_seen=timezone.now() - timedelta(days=EVIDENCE_TTL_DAYS + 5),
    )
    derive_claims(dep)
    expired.refresh_from_db()
    assert (expired.status, expired.confidence) == (Status.STALE, None)

    drifted_dep = _deployment("drifted")
    drifted = _access_claim(drifted_dep)
    assert drifted.confidence == _strength(CONFIGURATION_VERIFIED)
    Asset.objects.create(
        deployment=drifted_dep, kind=Asset.Kind.AGENT, name="a2", identifier="a2",
        classification=Asset.Classification.APPROVED, metadata={"tools": []},
    )
    check_invalidations(drifted_dep)
    drifted.refresh_from_db()
    assert (drifted.status, drifted.confidence) == (Status.STALE, None)
    assert _served(drifted)["confidence_basis"].startswith("none: ")


@pytest.mark.django_db
def test_a_retroactive_claim_takes_its_confidence_from_its_status_and_class_and_nobody_types_one_in():
    dep = _deployment("retro")
    now = timezone.now()
    window = dict(
        statement="last week", effective_from=now - timedelta(days=8), effective_to=now - timedelta(days=1),
        system_fingerprint="sysfp",
    )
    verified = record_retroactive_claim(
        dep, claim_type=ClaimType.EFFECTIVE_ACCESS, status=Status.VERIFIED,
        evidence_class=EvidenceClass.TECHNICALLY_VERIFIED.value, **window,
    )
    assert verified.confidence == _strength(EvidenceClass.TECHNICALLY_VERIFIED.value)
    contradicted = record_retroactive_claim(
        dep, claim_type=ClaimType.AI_BOM, status=Status.CONTRADICTED,
        evidence_class=CONFIGURATION_VERIFIED, **window,
    )
    assert contradicted.confidence is None
    with pytest.raises(TypeError):
        record_retroactive_claim(
            dep, claim_type=ClaimType.DATA_BOUNDARY, status=Status.SUPPORTED,
            evidence_class=CONFIGURATION_VERIFIED, confidence=0.99, **window,
        )


# ---------------------------------------------------------------------------
# 4. Migration 0048
# ---------------------------------------------------------------------------


_BEFORE_0048 = ("assurance", "0047_claim_event_person_snapshot")


def _migrate(target):
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate([target])


@pytest.mark.django_db(transaction=True)
def test_migration_0048_recomputes_every_believed_claims_confidence_and_leaves_history_as_it_was_closed():
    """Rows as the code before P2.7 left them, written as they were stored. Every
    row still believed takes the confidence its status and class give -- and a held
    row's base, the reading's -- and a superseded version keeps what it carried."""
    from tests.test_assurance_claims import _claim

    dep = _deployment("mig-0048")
    strong = _strength(CONFIGURATION_VERIFIED)
    vendor = _strength(EvidenceClass.VENDOR_ASSERTED.value)
    rows = {
        # A person's SUPPORTED over a derived CONTRADICTED kept the deriver's none.
        "person-supported": _claim(dep, fingerprint="a", status=Status.SUPPORTED, confidence=None),
        # A person's UNKNOWN over a derived VERIFIED kept the deriver's number.
        "person-unknown": _claim(dep, fingerprint="b", status=Status.UNKNOWN, confidence=strong),
        # A stale mark kept the number the claim carried before it.
        "stale": _claim(
            dep, fingerprint="c", status=Status.STALE, evidence_class=EvidenceClass.VENDOR_ASSERTED,
            vendor_asserted=True, confidence=vendor,
        ),
        # A withdrawal from before stops carried none.
        "revoked": _claim(dep, fingerprint="d", status=Status.REVOKED, confidence=strong),
        # A person's SUPPORTED held by a failure, whose base recorded the deriver's none.
        "held": _claim(
            dep, fingerprint="e", status=Status.CONTRADICTED, confidence=None,
            evidence_verdict="fail",
            evidence_audit={"held": True, "status": "contradicted", "base_status": "supported", "base_confidence": None},
        ),
        # Already right: untouched.
        "verified": _claim(dep, fingerprint="f", status=Status.VERIFIED, confidence=strong),
        # Closed history keeps what it carried when it was closed.
        "superseded": _claim(
            dep, fingerprint="g", status=Status.SUPERSEDED, confidence=strong, valid_to=timezone.now(),
        ),
    }
    head = MigrationExecutor(connection).loader.graph.leaf_nodes("assurance")[0]
    assert head[1] == "0048_claim_confidence_follows_its_status"
    try:
        _migrate(_BEFORE_0048)
        _migrate(head)
    finally:
        _migrate(head)

    read = {name: AssuranceClaim.objects.get(pk=row.pk) for name, row in rows.items()}
    assert read["person-supported"].confidence == strong
    assert read["person-unknown"].confidence is None
    assert read["stale"].confidence is None
    assert read["revoked"].confidence is None
    assert read["held"].confidence is None
    assert read["held"].evidence_audit["base_confidence"] == strong
    assert read["held"].evidence_audit["base_status"] == "supported"
    assert read["verified"].confidence == strong
    assert read["superseded"].confidence == strong
    # And every believed row now reads the confidence its status and class give.
    from assurance.claim_confidence import claim_confidence

    for name, claim in read.items():
        if claim.valid_to is None:
            assert claim.confidence == claim_confidence(claim.status, claim.evidence_class), name
