"""An accepted risk is carried, not removed (owner decision Q6).

Accepting a finding took it out of the decision altogether, so accepting a critical
finding read READY -- the same answer as fixing it. An acceptance now:

- holds the deployment at READY_RESTRICTED at best while it stands;
- must name when it ends, in the future, to be made at all;
- caps the decision at NEEDS_MORE_EVIDENCE once it lapses, or if it never named an
  end (every acceptance made before this rule);
- lapses at its moment even when nothing is written: the stored decision records
  when it stops holding, and the first read after that recomputes it.
"""

from __future__ import annotations

from datetime import timedelta
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from assurance.decision import compute_decision, current_decision, decision_support, recompute_decision
from assurance.models import Deployment, Finding
from assurance.revision import read_decision
from tests.decision_surfaces import one_decision

pytestmark = pytest.mark.django_db

User = get_user_model()
D = Deployment.Decision


def _admin():
    return User.objects.create_user(
        username=f"admin{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )


def _client():
    client = APIClient()
    client.force_authenticate(user=_admin())
    return client


def _scanned():
    dep = Deployment.objects.create(name=f"d{Deployment.objects.count()}", owner=_admin())
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    dep.refresh_from_db()
    return dep


def _finding(dep, severity="critical", *, status=Finding.Status.OPEN, until=None, n="1", accepted_at=None):
    # An acceptance written here covers the severity the finding has, as the
    # acceptance route records it (Finding.risk_accepted_severity), unless a test
    # says it was given at another.
    accepted = severity if accepted_at is None else accepted_at
    return Finding.objects.create(
        deployment=dep, fingerprint=f"fp-{severity}-{n}", finding_type="t", title=f"T{n}",
        severity=severity, status=status, risk_accepted_until=until,
        risk_accepted_severity=accepted if status == Finding.Status.ACCEPTED else "",
    )


def _in(days):
    return timezone.now() + timedelta(days=days)


def _stamped_under_these_rules(dep) -> bool:
    """Whether ``dep``'s stored decision carries the stamp of the rules in force."""
    from assurance.decision import stamped_in_force

    return stamped_in_force(Deployment.objects.get(pk=dep.pk))


# ---- The rule. ----


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info"])
def test_a_standing_acceptance_is_ready_with_restrictions_at_best(severity):
    dep = _scanned()
    _finding(dep, severity, status=Finding.Status.ACCEPTED, until=_in(30))
    assert compute_decision(dep) == D.READY_RESTRICTED


def test_an_acceptance_that_never_named_an_end_needs_more_evidence():
    """Every acceptance made before the rule. Nobody decided how long to carry it."""
    dep = _scanned()
    _finding(dep, status=Finding.Status.ACCEPTED, until=None)
    assert compute_decision(dep) == D.NEEDS_MORE_EVIDENCE


def test_a_lapsed_acceptance_needs_more_evidence():
    dep = _scanned()
    _finding(dep, status=Finding.Status.ACCEPTED, until=_in(-1))
    assert compute_decision(dep) == D.NEEDS_MORE_EVIDENCE


def test_one_lapsed_acceptance_among_standing_ones_needs_more_evidence():
    dep = _scanned()
    _finding(dep, status=Finding.Status.ACCEPTED, until=_in(30), n="a")
    _finding(dep, status=Finding.Status.ACCEPTED, until=_in(-1), n="b")
    assert compute_decision(dep) == D.NEEDS_MORE_EVIDENCE


def test_an_acceptance_never_lifts_the_decision():
    """A cap: an open high finding beside a standing acceptance still needs
    remediation."""
    dep = _scanned()
    _finding(dep, "high", n="open")
    _finding(dep, status=Finding.Status.ACCEPTED, until=_in(30), n="acc")
    assert compute_decision(dep) == D.NEEDS_REMEDIATION


def test_closed_and_false_positive_still_leave_the_decision():
    dep = _scanned()
    _finding(dep, status=Finding.Status.CLOSED, n="cl")
    _finding(dep, status=Finding.Status.FALSE_POSITIVE, n="fp")
    assert compute_decision(dep) == D.READY


# ---- Time moves the decision where no write does. ----


def test_the_stored_decision_records_when_it_stops_holding():
    dep = _scanned()
    first, second = _in(10), _in(30)
    _finding(dep, status=Finding.Status.ACCEPTED, until=second, n="a")
    _finding(dep, status=Finding.Status.ACCEPTED, until=first, n="b")
    recompute_decision(dep)
    dep.refresh_from_db()
    assert dep.decision == D.READY_RESTRICTED
    assert dep.decision_valid_until == first


def test_an_acceptance_lapses_on_every_surface_without_a_write():
    """Nothing is written between the two reads. The stored READY_RESTRICTED used
    to stand until something else recomputed the deployment."""
    dep = _scanned()
    until = _in(1)
    _finding(dep, status=Finding.Status.ACCEPTED, until=until)
    recompute_decision(dep)
    client = _client()
    assert one_decision(dep, client) == D.READY_RESTRICTED

    later = until + timedelta(seconds=1)
    with mock.patch.object(timezone, "now", return_value=later):
        assert read_decision(dep)["decision"] == D.NEEDS_MORE_EVIDENCE
        assert one_decision(dep, client) == D.NEEDS_MORE_EVIDENCE
    dep.refresh_from_db()
    assert dep.decision == D.NEEDS_MORE_EVIDENCE
    assert dep.decision_valid_until is None


def test_a_decision_with_nothing_to_lapse_records_no_end():
    dep = _scanned()
    _finding(dep, "high")
    recompute_decision(dep)
    dep.refresh_from_db()
    assert dep.decision_valid_until is None


def test_a_pause_records_no_end():
    dep = _scanned()
    _finding(dep, status=Finding.Status.ACCEPTED, until=_in(1))
    recompute_decision(dep, paused=True)
    dep.refresh_from_db()
    assert dep.decision == D.PAUSED
    assert dep.decision_valid_until is None


# ---- The upgrade. ----


def test_acceptances_made_before_the_rule_are_recomputed_at_their_first_read():
    """Their stored decision was computed with the finding left out: READY, logged
    as READY, and stamped with the rules it was computed under. The upgrade moves
    the policy pin; the first read sees a decision stamped under other rules and
    recomputes it under these. Without the stamp, the stale READY is what every
    surface publishes -- and marking it from a migration would write a decision
    column behind the transition log."""
    dep = _scanned()
    untouched = _scanned()
    _finding(untouched, "low")
    for d in (dep, untouched):
        recompute_decision(d)
    # Accepted before the rule: `bulk_create` sends no signal, so nothing
    # recomputes -- the stored READY is the one the old rule computed, which left
    # the accepted finding out.
    Finding.objects.bulk_create([
        Finding(deployment=dep, fingerprint="fp-legacy", finding_type="t", title="legacy",
                severity="critical", status=Finding.Status.ACCEPTED),
    ])
    dep = Deployment.objects.get(pk=dep.pk)
    assert current_decision(dep) == D.READY, "stamped under the rules in force: read as stored"

    # The decisions as the release before this one left them: stamped under its pin.
    Deployment.objects.filter(pk__in=[dep.pk, untouched.pk]).update(decision_policy="policy-before")

    dep = Deployment.objects.get(pk=dep.pk)
    assert current_decision(dep) == D.NEEDS_MORE_EVIDENCE
    assert Deployment.objects.get(pk=dep.pk).decision == D.NEEDS_MORE_EVIDENCE
    assert _stamped_under_these_rules(dep)
    # The other is recomputed too -- to what it already was, and stamped.
    untouched = Deployment.objects.get(pk=untouched.pk)
    before = untouched.decision
    assert current_decision(untouched) == before
    assert _stamped_under_these_rules(untouched)


def test_the_upgrade_recomputes_every_decision_stamped_under_other_rules():
    """Eagerly, at migrate, for a deployment nothing reads: the post-migrate
    receiver recomputes each stored decision whose stamp is not the pin in force,
    and leaves one stamped under it alone."""
    from django.apps import apps

    from assurance import signals

    stale, current = _scanned(), _scanned()
    for d in (stale, current):
        recompute_decision(d)
    Finding.objects.bulk_create([
        Finding(deployment=stale, fingerprint="fp-legacy-2", finding_type="t", title="legacy",
                severity="critical", status=Finding.Status.ACCEPTED),
    ])
    Deployment.objects.filter(pk=stale.pk).update(decision_policy=None)
    revision = Deployment.objects.get(pk=current.pk).decision_revision

    signals.recompute_decisions_computed_under_another_rule(apps.get_app_config("assurance"), using="default")

    assert Deployment.objects.get(pk=stale.pk).decision == D.NEEDS_MORE_EVIDENCE
    assert _stamped_under_these_rules(stale)
    assert Deployment.objects.get(pk=current.pk).decision_revision == revision


# ---- Accepting a risk names when the acceptance ends. ----


def _patch(client, finding, body):
    return client.patch(f"/api/assurance/findings/{finding.uuid}/", body, format="json")


def test_accepting_without_an_end_is_refused():
    dep = _scanned()
    finding = _finding(dep)
    response = _patch(_client(), finding, {"status": "accepted"})
    assert response.status_code == 400
    assert "risk_accepted_until" in response.json()
    finding.refresh_from_db()
    assert finding.status == Finding.Status.OPEN


def test_accepting_with_an_end_in_the_past_is_refused():
    dep = _scanned()
    finding = _finding(dep)
    response = _patch(_client(), finding, {"status": "accepted", "risk_accepted_until": _in(-1).isoformat()})
    assert response.status_code == 400


def test_accepting_with_an_end_holds_the_deployment_at_ready_with_restrictions():
    dep = _scanned()
    finding = _finding(dep)
    recompute_decision(dep)
    client = _client()
    assert one_decision(dep, client) == D.NOT_RECOMMENDED
    response = _patch(client, finding, {"status": "accepted", "risk_accepted_until": _in(30).isoformat()})
    assert response.status_code == 200, response.content
    assert one_decision(dep, client) == D.READY_RESTRICTED


def test_extending_a_standing_acceptance_keeps_it_and_moves_its_end():
    dep = _scanned()
    finding = _finding(dep, status=Finding.Status.ACCEPTED, until=_in(1))
    recompute_decision(dep)
    later = _in(60)
    response = _patch(_client(), finding, {"risk_accepted_until": later.isoformat()})
    assert response.status_code == 200, response.content
    dep.refresh_from_db()
    assert dep.decision_valid_until == later


def test_any_other_status_clears_the_end():
    dep = _scanned()
    finding = _finding(dep, status=Finding.Status.ACCEPTED, until=_in(30))
    response = _patch(_client(), finding, {"status": "open"})
    assert response.status_code == 200, response.content
    finding.refresh_from_db()
    assert finding.risk_accepted_until is None


@pytest.mark.parametrize("until", [_in(-1), None], ids=["lapsed", "never-dated"])
def test_editing_an_accepted_finding_is_not_judged_as_a_new_acceptance(until):
    """Reassigning an accepted finding, or noting its impact, is not accepting it
    again: it was refused when the acceptance had lapsed or predates the rule, so
    the finding could not be handed to anyone. The acceptance is left as it was --
    still lapsed, still holding the decision -- until someone renews it."""
    dep = _scanned()
    finding = _finding(dep, status=Finding.Status.ACCEPTED, until=until)
    recompute_decision(dep)
    client = _client()
    response = _patch(client, finding, {"business_impact": "Refunds past the limit reach a real account."})
    assert response.status_code == 200, response.content
    finding.refresh_from_db()
    assert finding.status == Finding.Status.ACCEPTED
    assert finding.risk_accepted_until == until
    assert finding.business_impact.startswith("Refunds")
    assert one_decision(dep, client) == D.NEEDS_MORE_EVIDENCE
    # Renewing it is still judged: a past end is refused, a future one stands.
    assert _patch(client, finding, {"risk_accepted_until": _in(-2).isoformat()}).status_code == 400
    assert _patch(client, finding, {"risk_accepted_until": _in(30).isoformat()}).status_code == 200
    assert one_decision(dep, client) == D.READY_RESTRICTED


def test_an_end_on_a_risk_nobody_accepted_is_refused():
    dep = _scanned()
    finding = _finding(dep)
    response = _patch(_client(), finding, {"risk_accepted_until": _in(30).isoformat()})
    assert response.status_code == 400


# ---- decision-support says so. ----


def test_decision_support_names_the_acceptance_that_binds():
    dep = _scanned()
    until = _in(30)
    _finding(dep, status=Finding.Status.ACCEPTED, until=until)
    payload = decision_support(dep)
    assert payload["decision"] == D.READY_RESTRICTED
    assert payload["accepted_risk_cap"] == D.READY_RESTRICTED
    assert [f["accepted_until"] for f in payload["accepted_risk"]["standing"]] == [until.isoformat()]
    assert payload["accepted_risk"]["lapsed"] == []
    assert "accepted until" in payload["note"]


def test_decision_support_names_the_lapsed_acceptance():
    dep = _scanned()
    _finding(dep, status=Finding.Status.ACCEPTED, until=None)
    payload = decision_support(dep)
    assert payload["decision"] == D.NEEDS_MORE_EVIDENCE
    assert [f["accepted_until"] for f in payload["accepted_risk"]["lapsed"]] == [None]
    assert "lapsed or never named an end" in payload["note"]


# ---- Round 2 of #105: a decision with no stamp, and the pin names every rule. ----


def test_a_stored_decision_with_no_policy_stamp_is_recomputed_at_its_first_read():
    """`loaddata` of a fixture dumped before the stamp: a stored READY, no stamp, and
    nothing that recomputes it -- the post-migrate receiver ran before the load. It
    was published as READY while a fresh computation says it needs more evidence."""
    dep = _scanned()
    _finding(dep, status=Finding.Status.ACCEPTED, until=None)
    paused = _scanned()
    Deployment.objects.filter(pk=dep.pk).update(decision=D.READY, decision_policy=None)
    Deployment.objects.filter(pk=paused.pk).update(decision=D.PAUSED, decision_policy=None)

    assert current_decision(Deployment.objects.get(pk=dep.pk)) == D.NEEDS_MORE_EVIDENCE
    assert Deployment.objects.get(pk=dep.pk).decision == D.NEEDS_MORE_EVIDENCE
    assert _stamped_under_these_rules(dep)
    # A pause with no stamp is recomputed too, and a recompute keeps the pause.
    assert current_decision(Deployment.objects.get(pk=paused.pk)) == D.PAUSED


def _governed(module_name, name):
    from importlib import import_module

    return import_module(module_name), name


def _changed(value):
    """Something ``value`` is not, of its own shape: every governing constant is a
    decision state, a set, a sequence, a mapping of those, or a rank."""
    if isinstance(value, (set, frozenset)):
        return frozenset(value) | {"changed-by-test"}
    if isinstance(value, tuple):
        return value[:-1]
    if isinstance(value, dict):
        return {**value, "changed-by-test": 99}
    if isinstance(value, int):
        return value + 10
    return D.NOT_RECOMMENDED.value if str(value) != D.NOT_RECOMMENDED.value else D.READY.value


#: Every rule the decision applies that is a value rather than a line of code: each
#: cap, floor, threshold and state set, by the module and name the decision code reads
#: it under -- and the key, for one entry of a table.
_GOVERNING = [
    *[("assurance.decision", "CLAIM_CAPS", key) for key in (
        "contradicted", "stale", "unknown", "open_retest", "legally_stale",
        "unread_latent_condition", "held_by_fired_latent_condition",
    )],
    ("assurance.decision", "ACCEPTED_RISK_CAPS", "standing"),
    ("assurance.decision", "ACCEPTED_RISK_CAPS", "lapsed_undated_or_outgrown"),
    ("assurance.decision", "SCAN_INCOMPLETE_CAP", None),
    ("assurance.decision", "COMPLETED_SCAN_SIGNAL", None),
    ("assurance.decision", "FINDING_SEVERITY_DECISIONS", None),
    ("assurance.decision", "FINDING_UNVERIFIED_ONLY", None),
    ("assurance.decision", "FINDING_CLEAN", None),
    ("assurance.decision", "UNTRUSTED_SEVERITY_STATUSES", None),
    ("assurance.decision", "LATENT_UNREAD_STATES", None),
    ("assurance.decision", "LATENT_HOLDING_STATES", None),
    ("assurance.decision", "_LEGALLY_STALE", None),
    ("assurance.decision", "_RESOLVED_STATUSES", None),
    ("assurance.decision", "_UNVERIFIED", None),
    ("assurance.decision", "_READINESS_RANK", None),
    ("assurance.coverage", "COVERAGE_CAP", None),
    ("assurance.coverage", "COMPLETE_AUDIT_SIGNAL", None),
    ("assurance.composition", "FLOORS", "violated"),
    ("assurance.composition", "FLOORS", "incomplete"),
    ("assurance.composition", "FLOORS", "not_demonstrated"),
    ("assurance.composition", "OFF_ROUTE", None),
    ("assurance.composition", "UNEXERCISED_BASES", None),
    ("assurance.composition", "VERDICTS", None),
    ("assurance.composition", "SIGNER_EVIDENCE", "achilles"),
    ("assurance.composition", "SIGNER_EVIDENCE", "athena"),
    ("assurance.workflow_chains", "CHAIN_CAPS", "held_on_authorization_check"),
    ("assurance.workflow_chains", "CHAIN_CAPS", "held_on_unclassified_signer"),
    # Round 3: the orders and ranks every threshold, tie and cap is read against, and
    # what an unsigned basis counts as. A reordered severity scale moved the decision
    # of the same stored inputs and left the pin where it was.
    ("assurance.models", "SEVERITY_ORDER", None),
    ("assurance.models", "EVIDENCE_STRENGTH_ORDER", None),
    ("assurance.composition", "READINESS_ORDER", None),
    ("assurance.composition", "_RANK", None),
    ("assurance.workflow_chains", "READINESS_ORDER", None),
    *[("assurance.composition", "_BASIS_RANK", key) for key in ("demonstrated", "attested", "unknown")],
    *[("assurance.composition", "_ROUTE_RANK", key) for key in ("current", "moved", "unrecorded")],
    *[("assurance.composition", "_EVIDENCE_RANK", key) for key in (
        "observed_effect", "scan", "authorization_check", "unclassified", "attested", "unknown",
    )],
    *[("assurance.composition", "_UNSIGNED_EVIDENCE", key) for key in ("attested", "unknown")],
    ("assurance.composition", "CHAIN_STATUSES", None),
    ("assurance.composition", "CHAIN_BASES", None),
    ("assurance.composition", "CHAIN_ROUTES", None),
    ("assurance.composition", "EVIDENCE_KINDS", None),
    ("assurance.composition", "DEMONSTRATED", None),
    # Round 4: the check states the engine's stored rows are read against -- not
    # spellings of a pinned set: renaming one capped the same stored scan and left the
    # pin where it was -- and the definition of a served route, which the route axis
    # reads every outcome's bound route against.
    *[("assurance.coverage", name, None) for name in (
        "CHECK_PERFORMED", "CHECK_DEGRADED", "CHECK_NOT_PERFORMED", "CHECK_UNMEASURED",
    )],
    *[("assurance.served_route", name, None) for name in (
        "ROUTE_VERSION", "ROUTE_FIELDS", "_METADATA_KEY", "_DIGESTED_FIELDS", "_SERVING_KINDS", "UNKNOWN", "ALGORITHM",
    )],
    # Round 5: the metadata key that takes a stored asset row out of the graph the
    # coverage cap is read over, which stored rows are read against like the check
    # states.
    ("assurance.graph_refs", "RETIRED", None),
]

#: The constants of the modules the decision is computed in that are NOT rules, and
#: why. Every other one must move the pin (`test_every_constant_the_decision_reads_is_in_the_pin`).
_NOT_RULES = {
    ("assurance.decision", "_READ_KEYRING"): "a sentinel meaning 'read the keyring now', not a rule",
    ("assurance.decision", "_KEYRING_MARK"): "which writer recomputed the stored decision; the rule it was "
    "computed under is the pin",
    ("assurance.decision", "RESOLVED_FINDING_STATUSES"): "imported only to be bound to _RESOLVED_STATUSES, "
    "which the code reads and the pin names",
    ("assurance.decision", "_READINESS_ORDER"): "read once, at import, into _READINESS_RANK -- which "
    "every worse-of reads and the pin names",
    ("assurance.decision", "_NO_CHAINS"): "a composition of nothing: the counterfactual a note is "
    "explained with; the decision never reads it",
    ("assurance.composition", "EVIDENCE_LABELS"): "the words shown beside a kind; nothing decides on them",
    ("assurance.composition", "_UNEXERCISED_NAMED"): "how many workflows one sentence names",
    ("assurance.workflow_chains", "PROVENANCE_LIMIT"): "how many sources the provenance census lists",
    ("assurance.workflow_chains", "UNATTRIBUTED"): "the census's name for an outcome with no source",
}
#: A spelling of one value -- a status, a basis, a kind, a route reading, a decision
#: state. Renaming one renames a value; the sets, tables and orders that hold it --
#: every one of them pinned -- are what the decision reads.
_SPELLINGS = {
    "assurance.composition": {
        "HELD", "VIOLATED", "NOT_DEMONSTRATED", "INCOMPLETE", "BASIS_DEMONSTRATED", "BASIS_ATTESTED",
        "BASIS_UNKNOWN", "EVIDENCE_AUTHORIZATION_CHECK", "EVIDENCE_SCAN", "EVIDENCE_OBSERVED_EFFECT",
        "EVIDENCE_UNCLASSIFIED", "EVIDENCE_ATTESTED", "EVIDENCE_UNKNOWN", "ROUTE_CURRENT", "ROUTE_MOVED",
        "ROUTE_UNRECORDED", "READY", "READY_RESTRICTED", "NEEDS_MORE_EVIDENCE", "AUDIT_INCOMPLETE",
        "NEEDS_REMEDIATION", "NOT_RECOMMENDED",
    },
    "assurance.workflow_chains": {
        "EVIDENCE_UNCLASSIFIED", "READY", "READY_RESTRICTED", "ROUTE_CURRENT", "ROUTE_MOVED", "ROUTE_UNRECORDED",
    },
    "assurance.coverage": {"COMPLETE", "INCOMPLETE", "UNDECLARED"},
}


@pytest.mark.parametrize(("module_name", "name", "key"), _GOVERNING, ids=lambda v: str(v))
def test_the_policy_pin_moves_with_every_rule_the_decision_applies(monkeypatch, module_name, name, key):
    """Seven single-line rule changes left the pin where it was: the document named
    some caps as literals and left the chain floors, the scan and coverage caps and
    the state sets out. A rule change the pin does not see leaves every stored
    decision stamped as current under rules that no longer hold."""
    from assurance.policy import policy_pin

    module, name = _governed(module_name, name)
    before = policy_pin()
    if key is None:
        monkeypatch.setattr(module, name, _changed(getattr(module, name)))
    else:
        monkeypatch.setitem(getattr(module, name), key, _changed(getattr(module, name)[key]))
    assert policy_pin() != before, f"{module_name}.{name}{'' if key is None else f'[{key!r}]'}"


def test_every_constant_the_decision_reads_is_in_the_pin(monkeypatch):
    """Not a list someone keeps: every constant of every module the decision is
    computed in either moves the pin when it changes, or is named above as not a rule,
    with the reason. The route and evidence ranks could be dropped from the pin with
    every test passing, and the severity order and the unsigned-evidence table were
    never in it."""
    import re
    import types
    from importlib import import_module

    from assurance.policy import policy_pin

    governed = {(module, name) for module, name, _key in _GOVERNING}
    unaccounted, unmoved = [], []
    for module_name in (
        "assurance.decision", "assurance.composition", "assurance.workflow_chains", "assurance.coverage",
        "assurance.served_route",
    ):
        module = import_module(module_name)
        for name, value in list(vars(module).items()):
            if not re.fullmatch(r"_?[A-Z][A-Z0-9_]*", name) or callable(value) or isinstance(value, types.ModuleType):
                continue
            if (module_name, name) in _NOT_RULES or name in _SPELLINGS.get(module_name, ()):
                continue
            if (module_name, name) not in governed:
                unaccounted.append(f"{module_name}.{name}")
            before = policy_pin()
            monkeypatch.setattr(module, name, _changed(value))
            if policy_pin() == before:
                unmoved.append(f"{module_name}.{name}")
            monkeypatch.undo()
    assert unaccounted == [], "constants the decision is computed with that no test holds to the pin"
    assert unmoved == [], "constants the decision is computed with that do not move the pin"


def test_a_reordered_severity_scale_moves_the_pin_and_the_published_decision_follows(monkeypatch):
    """The adversary's reordering: every threshold and every acceptance is ranked in
    SEVERITY_ORDER. Reordered, the decision computed from the same stored inputs
    moved and the pin did not, so the stored one went on being published."""
    from assurance import models
    from assurance.policy import policy_pin

    dep = _scanned()
    _finding(dep, "medium", n="m")
    assert recompute_decision(dep) == D.READY_RESTRICTED
    pin = policy_pin()

    monkeypatch.setattr(models, "SEVERITY_ORDER", ("info", "medium", "low", "high", "critical"))

    assert policy_pin() != pin
    computed = compute_decision(Deployment.objects.get(pk=dep.pk))
    assert computed != D.READY_RESTRICTED
    assert current_decision(Deployment.objects.get(pk=dep.pk)) == computed


def test_a_renamed_check_state_moves_the_pin_and_the_published_decision_follows(monkeypatch):
    """The check states are compared with the rows the engine stored, not only with
    sets that name them: renamed, the same stored scan reads audit_incomplete. They
    were excused as spellings, so the pin stayed where it was and the stored READY was
    published as current (#105 round 4)."""
    from assurance import coverage
    from assurance.policy import policy_pin

    dep = _scanned()
    Deployment.objects.filter(pk=dep.pk).update(
        check_coverage_at=timezone.now(),
        check_coverage={"checks": [{"check": "injection", "state": "performed"}, {"check": "exfil", "state": "performed"}]},
    )
    assert recompute_decision(Deployment.objects.get(pk=dep.pk)) == D.READY
    pin = policy_pin()

    monkeypatch.setattr(coverage, "CHECK_PERFORMED", "ran")

    assert policy_pin() != pin
    computed = compute_decision(Deployment.objects.get(pk=dep.pk))
    assert computed == D.AUDIT_INCOMPLETE
    assert current_decision(Deployment.objects.get(pk=dep.pk)) == computed


def test_a_renamed_retired_key_moves_the_pin_and_the_published_decision_follows(monkeypatch):
    """The coverage cap reads the stored asset rows through the key that marks one
    retired (graph_refs.in_graph), as it reads the stored check rows through the check
    states. Renamed, a retired high-risk tool is back in the graph and the same rows
    read audit_incomplete; the key was not in the pin, so the stored READY was
    published as current (#105 round 5)."""
    from assurance import graph_refs
    from assurance.models import Asset, DeclaredComponent
    from assurance.policy import policy_pin

    dep = _scanned()
    DeclaredComponent.objects.create(deployment=dep, kind=Asset.Kind.TOOL, name="reader", identifier="reader")
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="reader", identifier="reader",
        classification=Asset.Classification.KNOWN, assessed_at=timezone.now(),
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="old-shell", identifier="old-shell",
        classification=Asset.Classification.HIGH_RISK, metadata={graph_refs.RETIRED: True},
    )
    assert recompute_decision(Deployment.objects.get(pk=dep.pk)) == D.READY
    pin = policy_pin()

    monkeypatch.setattr(graph_refs, "RETIRED", "retired_at")

    assert policy_pin() != pin
    computed = compute_decision(Deployment.objects.get(pk=dep.pk))
    assert computed == D.AUDIT_INCOMPLETE
    assert current_decision(Deployment.objects.get(pk=dep.pk)) == computed


def test_the_claim_cap_is_the_worst_of_every_claim_that_holds_the_decision_back():
    """A contradicted claim beside a stale one needs remediation. The cap taken as the
    last kind that applied, not the worst, read needs more evidence."""
    from assurance.decision import claim_decision_signal
    from assurance.models import AssuranceClaim

    dep = _scanned()
    for n, status in enumerate((AssuranceClaim.ClaimStatus.CONTRADICTED, AssuranceClaim.ClaimStatus.STALE)):
        AssuranceClaim.objects.create(
            deployment=dep, claim_type=AssuranceClaim.ClaimType.AI_BOM, statement="s", fingerprint=f"fp-{n}",
            system_fingerprint="sys", policy_version="p", environment=dep.environment, status=status,
        )

    assert claim_decision_signal(dep)["cap"] == D.NEEDS_REMEDIATION
    assert recompute_decision(dep) == D.NEEDS_REMEDIATION


def test_a_deployment_nothing_has_decided_is_published_as_undecided_and_nothing_is_written():
    """No decision, no stamp, and nothing to redo: the first publishing read writes
    no decision and no stamp for it."""
    dep = Deployment.objects.create(name="never", owner=_admin())

    assert current_decision(Deployment.objects.get(pk=dep.pk)) is None
    row = Deployment.objects.values("decision", "decision_revision", "decision_policy").get(pk=dep.pk)
    assert row == {"decision": None, "decision_revision": 0, "decision_policy": None}
    assert not dep.decision_transitions.exists()


def test_the_decision_applies_the_claim_caps_the_policy_names(monkeypatch):
    from assurance import decision
    from assurance.decision import claim_decision_signal
    from assurance.models import AssuranceClaim

    for key in decision.CLAIM_CAPS:
        monkeypatch.setitem(decision.CLAIM_CAPS, key, D.NOT_RECOMMENDED)
        assert decision._claim_cap({key: [object()]}) == D.NOT_RECOMMENDED, key
        monkeypatch.undo()
    dep = _scanned()
    AssuranceClaim.objects.create(
        deployment=dep, claim_type=AssuranceClaim.ClaimType.AI_BOM, statement="s", fingerprint="fp-stale",
        system_fingerprint="sys", policy_version="p", environment=dep.environment,
        status=AssuranceClaim.ClaimStatus.STALE,
    )
    monkeypatch.setitem(decision.CLAIM_CAPS, "stale", D.AUDIT_INCOMPLETE)
    assert claim_decision_signal(dep)["cap"] == D.AUDIT_INCOMPLETE


def test_the_decision_applies_the_acceptance_caps_the_policy_names(monkeypatch):
    from assurance import decision
    from assurance.decision import accepted_risk_signal

    dep = _scanned()
    _finding(dep, status=Finding.Status.ACCEPTED, until=_in(30))
    monkeypatch.setitem(decision.ACCEPTED_RISK_CAPS, "standing", D.AUDIT_INCOMPLETE)
    assert accepted_risk_signal(dep, now=timezone.now())["cap"] == D.AUDIT_INCOMPLETE
    _finding(dep, status=Finding.Status.ACCEPTED, until=None, n="2")
    monkeypatch.setitem(decision.ACCEPTED_RISK_CAPS, "lapsed_undated_or_outgrown", D.NOT_RECOMMENDED)
    assert accepted_risk_signal(dep, now=timezone.now())["cap"] == D.NOT_RECOMMENDED


def test_the_decision_applies_the_finding_thresholds_the_policy_names(monkeypatch):
    from assurance import decision

    dep = _scanned()
    _finding(dep, "high")
    assert compute_decision(dep) == D.NEEDS_REMEDIATION
    thresholds = decision.FINDING_SEVERITY_DECISIONS
    monkeypatch.setattr(
        decision, "FINDING_SEVERITY_DECISIONS",
        tuple((s, D.AUDIT_INCOMPLETE if s == "high" else placed) for s, placed in thresholds),
    )
    assert compute_decision(dep) == D.AUDIT_INCOMPLETE
    monkeypatch.setattr(decision, "FINDING_SEVERITY_DECISIONS", thresholds)
    clean = _scanned()
    _finding(clean, "high", status=Finding.Status.CLOSED)
    monkeypatch.setattr(decision, "FINDING_CLEAN", D.READY_RESTRICTED)
    assert compute_decision(clean) == D.READY_RESTRICTED
    invalidated = _scanned()
    _finding(invalidated, "high", status=Finding.Status.INVALIDATED)
    monkeypatch.setattr(decision, "FINDING_UNVERIFIED_ONLY", D.AUDIT_INCOMPLETE)
    assert compute_decision(invalidated) == D.AUDIT_INCOMPLETE
    # Trusted, it is placed by its severity.
    monkeypatch.setattr(decision, "UNTRUSTED_SEVERITY_STATUSES", frozenset())
    assert compute_decision(invalidated) == D.NEEDS_REMEDIATION


def test_the_decision_applies_the_scan_and_coverage_caps_the_policy_names(monkeypatch):
    from types import SimpleNamespace

    from assurance import coverage, decision

    monkeypatch.setattr(decision, "SCAN_INCOMPLETE_CAP", D.AUDIT_INCOMPLETE)
    assert decision.incomplete_evidence_cap(SimpleNamespace(evidence_incomplete=True)) == D.AUDIT_INCOMPLETE
    monkeypatch.setattr(decision, "COMPLETED_SCAN_SIGNAL", D.READY_RESTRICTED)
    assert decision._completed_scan_signal(SimpleNamespace(last_complete_scan_at=timezone.now())) == D.READY_RESTRICTED
    monkeypatch.setattr(coverage, "checks_gap", lambda deployment: True)
    monkeypatch.setattr(coverage, "COVERAGE_CAP", D.NOT_RECOMMENDED)
    assert coverage.coverage_decision_cap(SimpleNamespace()) == D.NOT_RECOMMENDED
    monkeypatch.setattr(coverage, "coverage_manifest", lambda deployment: {"verdict": coverage.COMPLETE})
    monkeypatch.setattr(coverage, "COMPLETE_AUDIT_SIGNAL", D.READY_RESTRICTED)
    assert coverage.complete_audit_signal(SimpleNamespace()) == D.READY_RESTRICTED


def test_the_chains_apply_the_floors_and_caps_the_policy_names(monkeypatch):
    from assurance import composition as comp
    from assurance import workflow_chains

    violated = comp.ChainOutcome("refund", comp.VIOLATED, basis=comp.BASIS_DEMONSTRATED, signer="athena",
                                 route=comp.ROUTE_CURRENT)
    monkeypatch.setitem(comp.FLOORS, comp.VIOLATED, comp.NEEDS_REMEDIATION)
    assert comp.compose([violated], expected_workflows=["refund"]).decision == comp.NEEDS_REMEDIATION
    typed = comp.ChainOutcome("refund", comp.HELD, basis=comp.BASIS_ATTESTED, route=comp.ROUTE_CURRENT)
    monkeypatch.setitem(comp.FLOORS, comp.NOT_DEMONSTRATED, comp.AUDIT_INCOMPLETE)
    assert comp.compose([typed], expected_workflows=["refund"]).decision == comp.AUDIT_INCOMPLETE
    permit = comp.ChainOutcome("refund", comp.HELD, basis=comp.BASIS_DEMONSTRATED, signer="achilles",
                               route=comp.ROUTE_CURRENT)
    monkeypatch.setitem(workflow_chains.CHAIN_CAPS, "held_on_authorization_check", comp.NEEDS_MORE_EVIDENCE)
    composed = comp.compose([permit], expected_workflows=["refund"])
    assert workflow_chains.composition_decision_signal(composed) == comp.NEEDS_MORE_EVIDENCE
