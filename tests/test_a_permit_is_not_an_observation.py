"""A permit is not an observation, and no surface may publish one as if it were.

Achilles signs ``held`` whenever the action gate's dispatch-time permit check
passes (``achilles/chain_outcome.py::attach_outcome``). That shows the gate
authorized the workflow's action, so the authority chain resolves. It does not
show the effect happened: the gate never sees an effect. Before this file, such a
row was published as ``signed: true``, ``basis_in_force: demonstrated`` and
"Demonstrated — a run produced this outcome", and the composition said "Every
chain held ... ready" -- with nothing on any surface to tell a permit check from
an effect somebody watched.

What this file pins is the LABELLING, not the gating. Whether a signed permit
check may count towards READY is an owner decision recorded in the research
plan, and every decision asserted here is the one the rule already made.
"""

from __future__ import annotations

from datetime import timedelta
from itertools import permutations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.utils import timezone
from mythos_core import outcome as oc
from rest_framework.test import APIClient

from assurance import composition as comp
from assurance import observed_outcomes
from assurance.composition import HELD, NOT_DEMONSTRATED, VIOLATED, ChainOutcome, compose
from assurance.models import ApprovedWorkflow, Deployment, WorkflowChainOutcome
from assurance.workflow_chains import composition_decision_signal, composition_for
from tests import signed_chains
from tests.signed_chains import record_signed, write_keyring

User = get_user_model()

AUTHORIZATION_CLAUSE = "rest on an authorization check, not an observed effect"
WHAT_IT_DOES_NOT_SHOW = "it does not show the effect happened"


def _held(workflow, signer, *, at=None, basis=comp.BASIS_DEMONSTRATED):
    return ChainOutcome(workflow, HELD, observed_at=at, basis=basis, signer=signer)


# --- the rule: which kind of evidence each signer is ---------------------------


def test_what_each_signer_is_evidence_of():
    assert comp.evidence_kind(comp.BASIS_DEMONSTRATED, "achilles") == comp.EVIDENCE_AUTHORIZATION_CHECK
    assert comp.evidence_kind(comp.BASIS_DEMONSTRATED, "athena") == comp.EVIDENCE_SCAN
    # A signer nobody classified is a signature and nothing more -- and never
    # whichever listed name it resembles.
    assert comp.evidence_kind(comp.BASIS_DEMONSTRATED, "hermes") == comp.EVIDENCE_UNCLASSIFIED
    assert comp.evidence_kind(comp.BASIS_DEMONSTRATED, "Achilles") == comp.EVIDENCE_UNCLASSIFIED
    assert comp.evidence_kind(comp.BASIS_DEMONSTRATED, "") == comp.EVIDENCE_UNCLASSIFIED


def test_nothing_produces_an_observed_effect_yet():
    """Reserved for an independent collector's key. The first signer to claim it
    has to be added here on purpose, and this test is where that shows."""
    assert comp.EVIDENCE_OBSERVED_EFFECT in comp.EVIDENCE_KINDS
    assert comp.EVIDENCE_OBSERVED_EFFECT not in comp.SIGNER_EVIDENCE.values()
    assert "Nothing records this kind yet" in comp.EVIDENCE_LABELS[comp.EVIDENCE_OBSERVED_EFFECT]


def test_an_unsigned_basis_is_its_own_kind_whatever_engine_the_row_names():
    """The basis IN FORCE decides whether the signer is read at all. A row whose
    Achilles signature no longer verifies is attested, and the engine it names
    vouches for nothing."""
    assert comp.evidence_kind(comp.BASIS_ATTESTED, "achilles") == comp.EVIDENCE_ATTESTED
    assert comp.evidence_kind(comp.BASIS_UNKNOWN, "achilles") == comp.EVIDENCE_UNKNOWN
    assert comp.evidence_kind(comp.BASIS_ATTESTED) == comp.EVIDENCE_ATTESTED


def test_a_basis_nobody_classified_is_refused_not_defaulted():
    with pytest.raises(KeyError):
        comp.evidence_kind("inferred", "achilles")


def test_every_kind_has_a_label_and_the_authorization_check_says_what_it_does_not_show():
    assert set(comp.EVIDENCE_LABELS) == comp.EVIDENCE_KINDS
    label = comp.EVIDENCE_LABELS[comp.EVIDENCE_AUTHORIZATION_CHECK]
    assert "authorized" in label and "permit check" in label
    assert WHAT_IT_DOES_NOT_SHOW in label


def test_the_evidence_rank_is_total_over_the_kinds():
    assert set(comp._EVIDENCE_RANK) == comp.EVIDENCE_KINDS
    assert len(set(comp._EVIDENCE_RANK.values())) == len(comp.EVIDENCE_KINDS)


# --- the rule: the composition's census and its sentence -----------------------


def test_the_evidence_census_names_every_kind_and_the_permit_checks():
    result = compose(
        [_held("refund", "achilles"), _held("export", "athena"), _held("typed", "", basis=comp.BASIS_ATTESTED)],
        expected_workflows=["refund", "export", "typed", "unrun"],
    )
    assert result.evidence_census == {
        comp.EVIDENCE_ATTESTED: 1,
        comp.EVIDENCE_AUTHORIZATION_CHECK: 1,
        comp.EVIDENCE_OBSERVED_EFFECT: 0,
        comp.EVIDENCE_SCAN: 1,
        comp.EVIDENCE_UNCLASSIFIED: 0,
        # The approved workflow nobody reported: no record, so the record says nothing.
        comp.EVIDENCE_UNKNOWN: 1,
    }
    assert result.authorization_checked == ("refund",)


def test_an_all_held_sentence_over_a_permit_check_says_it_is_one_and_the_decision_is_unmoved():
    """The case #103's own test pins: one approved workflow, one Achilles-signed
    held, READY. The decision stays READY; the sentence stops reading as an
    effect somebody watched."""
    result = compose([_held("refund", "achilles")], expected_workflows=["refund"])
    assert result.decision == comp.READY
    sentence = comp.explain(result)
    assert sentence.startswith("Every chain held across 1 workflow(s)")
    assert f"1 of these {AUTHORIZATION_CLAUSE} (refund)" in sentence
    assert "the gate authorized the workflow's action at dispatch (a permit check)" in sentence
    assert "shows the authority chain resolves" in sentence
    assert WHAT_IT_DOES_NOT_SHOW in sentence


def test_the_clause_is_said_under_a_floor_too():
    """A refused dispatch is an authorization check as well, and here it is what
    sets the floor -- the deciding sentence carries the clause, not only the
    all-held one."""
    result = compose(
        [ChainOutcome("refund", NOT_DEMONSTRATED, basis=comp.BASIS_DEMONSTRATED, signer="achilles")],
        expected_workflows=["refund"],
    )
    assert result.decision == comp.NEEDS_MORE_EVIDENCE
    assert result.deciding == ("refund",)
    assert f"1 of these {AUTHORIZATION_CLAUSE} (refund)" in comp.explain(result)


@pytest.mark.parametrize(
    "outcome",
    [
        _held("export", "athena"),
        _held("export", "hermes"),
        _held("export", "achilles", basis=comp.BASIS_ATTESTED),
        ChainOutcome("export", VIOLATED, basis=comp.BASIS_DEMONSTRATED, signer="athena"),
    ],
    ids=["scan", "unclassified", "typed-in-naming-achilles", "scan-violated"],
)
def test_no_clause_where_no_standing_outcome_is_a_permit_check(outcome):
    result = compose([outcome], expected_workflows=["export"])
    assert result.authorization_checked == ()
    assert AUTHORIZATION_CLAUSE not in comp.explain(result)


def test_the_clause_rolls_up_past_the_named_limit():
    names = [f"w{i:02d}" for i in range(comp._UNEXERCISED_NAMED + 2)]
    result = compose([_held(name, "achilles") for name in names], expected_workflows=names)
    assert result.authorization_checked == tuple(names)
    assert f"{len(names)} of these {AUTHORIZATION_CLAUSE} (w00, w01, w02 and 2 more)" in comp.explain(result)
    # Exactly at the limit, every one is named and nothing is rolled up.
    at_limit = names[: comp._UNEXERCISED_NAMED]
    exact = compose([_held(name, "achilles") for name in at_limit], expected_workflows=at_limit)
    assert f"3 of these {AUTHORIZATION_CLAUSE} (w00, w01, w02):" in comp.explain(exact)


def test_a_permit_check_superseded_by_a_scan_is_no_longer_named():
    """The clause is about the STANDING outcome. A later signed verdict displaces
    the earlier permit check, and the sentence follows it."""
    t0 = timezone.now() - timedelta(hours=2)
    result = compose(
        [_held("refund", "achilles", at=t0), _held("refund", "athena", at=t0 + timedelta(hours=1))],
        expected_workflows=["refund"],
    )
    assert result.superseded == 1
    assert result.authorization_checked == ()
    assert result.evidence_census[comp.EVIDENCE_SCAN] == 1


def test_a_tie_between_signers_is_broken_the_same_way_in_any_order():
    """An Achilles and an Athena held at one instant for one workflow: both stand,
    and which kind the census reports must not depend on which arrived first."""
    at = timezone.now() - timedelta(hours=1)
    outcomes = [
        _held("refund", "achilles", at=at),
        _held("refund", "athena", at=at),
        _held("refund", "hermes", at=at),
    ]
    reported = set()
    for order in permutations(outcomes):
        result = compose(list(order), expected_workflows=["refund"])
        reported.add(
            (tuple(sorted(result.evidence_census.items())), result.authorization_checked, comp.explain(result))
        )
    assert len(reported) == 1
    (census, checked, _), = reported
    assert dict(census)[comp.EVIDENCE_SCAN] == 1
    assert checked == ()


def test_who_signed_moves_the_labelling_and_never_the_rules_decision():
    """The RULE is unchanged: the same held, demonstrated, composes to the same
    decision, census and basis census whoever signed it. What that decision
    contributes to the deployment's is capped for a permit check alone -- below."""
    results = [
        compose([_held("refund", signer)], expected_workflows=["refund"])
        for signer in ("achilles", "athena", "hermes", "")
    ]
    assert {r.decision for r in results} == {comp.READY}
    assert len({tuple(sorted(r.census.items())) for r in results}) == 1
    assert len({tuple(sorted(r.basis_census.items())) for r in results}) == 1
    assert len({r.workflows_unexercised for r in results}) == 1


# --- every surface that publishes a chain outcome or the composition ----------


@pytest.fixture
def engines(engine_keyring, monkeypatch):
    """The two engines the platform classifies, and one it does not."""
    monkeypatch.setitem(signed_chains.ENGINE_KEYS, "hermes", Ed25519PrivateKey.generate())
    write_keyring(engine_keyring)
    return engine_keyring


def _admin():
    return User.objects.create_user(
        username=f"admin{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )


def _deployment(*approved):
    dep = Deployment.objects.create(name=f"d{Deployment.objects.count()}", owner=_admin())
    for slug in approved:
        ApprovedWorkflow.objects.create(deployment=dep, slug=slug, name=slug)
    return dep


def _client():
    client = APIClient()
    client.force_authenticate(user=_admin())
    return client


def _recently():
    return timezone.now() - timedelta(minutes=5)


@pytest.mark.django_db
def test_every_published_row_says_what_kind_of_evidence_it_is(engines):
    dep = _deployment()
    record_signed(dep, "refund", HELD, _recently(), engine="achilles")
    record_signed(dep, "export", HELD, _recently(), engine="athena")
    record_signed(dep, "notify", HELD, _recently(), engine="hermes")
    WorkflowChainOutcome.objects.create(
        deployment=dep, workflow="typed", status=HELD, basis=comp.BASIS_ATTESTED, observed_at=_recently()
    )
    WorkflowChainOutcome.objects.create(deployment=dep, workflow="silent", status=HELD, observed_at=_recently())

    rows = _client().get(f"/api/assurance/deployments/{dep.uuid}/chain-outcomes/").json()["outcomes"]
    kinds = {row["workflow"]: row["evidence_kind"] for row in rows}
    assert kinds == {
        "refund": comp.EVIDENCE_AUTHORIZATION_CHECK,
        "export": comp.EVIDENCE_SCAN,
        "notify": comp.EVIDENCE_UNCLASSIFIED,
        "typed": comp.EVIDENCE_ATTESTED,
        "silent": comp.EVIDENCE_UNKNOWN,
    }
    labels = {row["workflow"]: row["evidence_kind_label"] for row in rows}
    assert labels == {workflow: comp.EVIDENCE_LABELS[kind] for workflow, kind in kinds.items()}
    # The Achilles row still says what it said -- signed, demonstrated, held --
    # and now says beside it what that signature is evidence of.
    refund = next(row for row in rows if row["workflow"] == "refund")
    assert (refund["signed"], refund["basis_in_force"], refund["status"]) == (True, comp.BASIS_DEMONSTRATED, HELD)
    assert WHAT_IT_DOES_NOT_SHOW in refund["evidence_kind_label"]
    assert comp.EVIDENCE_OBSERVED_EFFECT not in kinds.values()


@pytest.mark.django_db
def test_a_withdrawn_achilles_key_leaves_an_attested_row_not_a_permit_check(engines, tmp_path, monkeypatch):
    """The row keeps ``observer_engine="achilles"``. What it is evidence of follows
    the signature that verifies NOW, and without one it is a person's say-so."""
    dep = _deployment()
    record_signed(dep, "refund", HELD, _recently(), engine="achilles")
    only_athena = tmp_path / "rotated.json"
    write_keyring(only_athena, {"athena": signed_chains.ENGINE_KEYS["athena"]})
    monkeypatch.setenv(observed_outcomes.KEYRING_ENV, str(only_athena))

    row = _client().get(f"/api/assurance/deployments/{dep.uuid}/chain-outcomes/").json()["outcomes"][0]
    assert row["observer_engine"] == "achilles"
    assert row["basis_in_force"] == comp.BASIS_ATTESTED
    assert row["evidence_kind"] == comp.EVIDENCE_ATTESTED
    assert composition_for(dep).authorization_checked == ()


@pytest.mark.django_db
def test_the_signed_route_answers_with_the_kind_and_the_composition_names_it(engine_keyring):
    """The route that records a signed outcome is the first surface a caller meets,
    and it is named ``observed``. Its answer must not let that word stand alone."""
    dep = _deployment("refund")
    envelope = oc.sign_outcome(
        oc.build_outcome(
            deployment=str(dep.uuid), workflow="refund", status=oc.HELD, engine="achilles",
            engine_version="1.0.0", run_id="run-1", evidence_digest="sha256:" + "ab" * 32,
            observed_at=_recently(),
        ),
        signed_chains.ENGINE_KEYS["achilles"],
    )
    response = _client().post(
        f"/api/assurance/deployments/{dep.uuid}/chain-outcomes/observed/", envelope, format="json"
    )
    assert response.status_code == 201, response.content
    body = response.json()
    assert body["outcomes"][0]["evidence_kind"] == comp.EVIDENCE_AUTHORIZATION_CHECK
    composition = body["composition"]
    assert composition["rule_decision"] == comp.READY
    assert composition["evidence_census"][comp.EVIDENCE_AUTHORIZATION_CHECK] == 1
    assert composition["evidence_census"][comp.EVIDENCE_OBSERVED_EFFECT] == 0
    assert composition["authorization_checked"] == ["refund"]
    assert f"1 of these {AUTHORIZATION_CLAUSE} (refund)" in composition["explanation"]


@pytest.mark.django_db
def test_decision_support_names_the_permit_check_behind_its_ready(engine_keyring):
    """Held on a permit check alone, the decision is ready WITH RESTRICTIONS (owner
    default, #278), and the note says why: the held it rests on is an authorization
    check, not an effect anyone saw."""
    dep = _deployment("refund")
    record_signed(dep, "refund", HELD, _recently(), engine="achilles")

    support = _client().get(f"/api/assurance/deployments/{dep.uuid}/decision-support/").json()
    assert support["decision"] == comp.READY_RESTRICTED
    assert support["note"].startswith(
        "Ready with restrictions: every one of the 1 approved workflow(s) has a chain outcome "
        "and all of them hold, but 1 hold on an authorization check alone"
    )
    assert f"1 of these {AUTHORIZATION_CLAUSE} (refund)" in support["note"]
    assert WHAT_IT_DOES_NOT_SHOW in support["note"]
    assert support["composition"]["authorization_checked"] == ["refund"]
    assert f"1 of these {AUTHORIZATION_CLAUSE} (refund)" in support["composition"]["explanation"]


# --- what a permit check alone contributes to the deployment decision (#278) ----


def _signal(outcomes, expected):
    return composition_decision_signal(compose(outcomes, expected_workflows=expected))


def test_a_workflow_held_on_a_permit_check_alone_is_ready_with_restrictions():
    """Owner default (#278): Achilles signs held when its permit check passes at
    dispatch. That shows the authority chain resolves and not that the effect
    happened, so the deployment it speaks for is ready WITH RESTRICTIONS at best."""
    assert _signal([_held("refund", "achilles")], ["refund"]) == comp.READY_RESTRICTED


@pytest.mark.parametrize("signer", ["athena", "hermes", ""], ids=["scan", "unclassified", "unnamed"])
def test_a_held_that_is_not_a_permit_check_is_not_restricted_by_it(signer):
    """The cap is about the permit check, not about who else signs: a scan, or a
    signer this platform has not classified, contributes what the rule decided."""
    assert _signal([_held("refund", signer)], ["refund"]) == comp.READY


def test_one_permit_check_restricts_a_deployment_whose_other_workflows_were_scanned():
    """Worst-of-N: another workflow's scan says nothing about this one's effect."""
    outcomes = [_held("refund", "achilles"), _held("export", "athena"), _held("notify", "athena")]
    assert _signal(outcomes, ["refund", "export", "notify"]) == comp.READY_RESTRICTED


def test_a_later_scan_that_displaces_the_permit_check_lifts_the_restriction():
    t0 = timezone.now() - timedelta(hours=2)
    outcomes = [_held("refund", "achilles", at=t0), _held("refund", "athena", at=t0 + timedelta(hours=1))]
    assert _signal(outcomes, ["refund"]) == comp.READY
    # And the other way round: the permit check is what stands, so it restricts.
    outcomes = [_held("refund", "athena", at=t0), _held("refund", "achilles", at=t0 + timedelta(hours=1))]
    assert _signal(outcomes, ["refund"]) == comp.READY_RESTRICTED


def test_the_restriction_never_softens_a_floor():
    """A violated or undemonstrated chain places the deployment where the rule
    floors it, whoever signed it: the cap only ever applies to READY."""
    violated = ChainOutcome("refund", VIOLATED, basis=comp.BASIS_DEMONSTRATED, signer="achilles")
    assert _signal([violated, _held("export", "achilles")], ["refund", "export"]) == comp.NOT_RECOMMENDED
    missing = ChainOutcome("refund", NOT_DEMONSTRATED, basis=comp.BASIS_DEMONSTRATED, signer="achilles")
    assert _signal([missing, _held("export", "achilles")], ["refund", "export"]) == comp.NEEDS_MORE_EVIDENCE


def test_a_permit_check_in_an_open_scope_contributes_nothing_either_way():
    """No approved set recorded: the chains do not speak for the deployment, so
    they contribute neither READY nor its restricted form."""
    assert _signal([_held("refund", "achilles")], None) is None


def test_the_restriction_follows_the_standing_outcome_in_any_order():
    t0 = timezone.now() - timedelta(hours=2)
    outcomes = [
        _held("refund", "achilles", at=t0),
        _held("refund", "athena", at=t0 + timedelta(hours=1)),
        _held("export", "achilles", at=t0),
    ]
    seen = {_signal(list(order), ["refund", "export"]) for order in permutations(outcomes)}
    assert seen == {comp.READY_RESTRICTED}


@pytest.mark.django_db
def test_the_decision_is_restricted_until_a_scan_displaces_the_permit_check(engine_keyring):
    """End to end, through decision support."""
    dep = _deployment("refund")
    url = f"/api/assurance/deployments/{dep.uuid}/decision-support/"
    record_signed(dep, "refund", HELD, timezone.now() - timedelta(minutes=10), engine="achilles")
    support = _client().get(url).json()
    assert support["decision"] == comp.READY_RESTRICTED
    assert support["composition"]["authorization_checked"] == ["refund"]
    record_signed(dep, "refund", HELD, timezone.now() - timedelta(minutes=5), engine="athena")
    support = _client().get(url).json()
    assert support["decision"] == comp.READY
    assert support["composition"]["authorization_checked"] == []

