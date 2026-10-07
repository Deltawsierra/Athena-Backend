"""No fix is worked on before its repair contract, and no closure stands outside it.

Roadmap Phase 6: "Before proposing a fix, force explicit agreement on two things:
the prohibited effect the repair must eliminate, and the legitimate behavior it must
preserve. Generating candidate repairs first and checking them against requirements
after is backwards -- it lets a repair that passes shallow tests through while
silently breaking preserved behavior."

- A finding's remediation moves into ``in_progress`` (or ``in_review``,
  ``resolved``) only with a current repair contract agreed, on every path: the
  remediation service, its API route, the admin's change and add forms, a save.
- The contract is append-only and versioned: never edited, never deleted on its
  own; a change is a new version.
- A retest-gated closure stands only on a replay naming the finding's CURRENT
  contract and reading every behaviour it preserves ``retained``, and no other.
- The engine service's route and Minotaur-Backend's ``POST /remediation-outcomes``
  read the same document, contract block included, under the same digest.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import timedelta

import pytest
from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import Client
from django.utils import timezone
from rest_framework.test import APIClient

from assurance.models import ClaimEvidence, Deployment, Finding
from assurance.retest_closure import (
    INCOMPLETE_REPAIR,
    INCOMPLETE_REPAIR_PATTERNS,
    ClosureRefused,
    record_closure_evidence,
    refusal_reasons,
)
from tests.repair_contracts import BEHAVIOURS, EFFECT, agree, replay

pytestmark = pytest.mark.django_db

User = get_user_model()
State = Finding.RemediationState

COMPLETE = {
    "vulnerable": {"ran": True, "outcome": "failed"},
    "repaired": {"ran": True, "outcome": "passed"},
    "benign": {"ran": True, "outcome": "passed"},
    INCOMPLETE_REPAIR: {p: {"ran": True, "outcome": "failed"} for p in INCOMPLETE_REPAIR_PATTERNS},
}

SERVICE_CREDENTIAL = "closure-evidence-engine-service-test-only-0000"
SERVICE_ACCOUNT = "closure-engine"


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
    return Finding.objects.create(**defaults)


def _triaged(**kwargs):
    finding = _finding(**kwargs)
    from assurance.remediation import apply_transition

    apply_transition(finding, State.TRIAGED, actor=None)
    return Finding.objects.get(pk=finding.pk)


def _api(user=None):
    client = APIClient()
    client.force_authenticate(user=user or _admin())
    return client


def _contracts_url(finding):
    return f"/api/assurance/findings/{finding.uuid}/repair-contracts/"


# ---------------------------------------------------------------------------
# No fix before agreement: every path into a working state
# ---------------------------------------------------------------------------


def _via_service(finding):
    from assurance.remediation import ContractRequired, apply_transition

    try:
        apply_transition(finding, State.IN_PROGRESS, actor=None)
    except ContractRequired as exc:
        assert finding.remediation_state == State.TRIAGED  # the caller's copy too
        return False, "; ".join(exc.reasons)
    return True, ""


def _via_api(finding):
    answer = _api().post(
        f"/api/assurance/findings/{finding.uuid}/remediation/transition/", {"to_state": "in_progress"},
        format="json",
    )
    if answer.status_code == 200:
        return True, ""
    assert answer.status_code == 400, answer.content
    return False, "; ".join(answer.json()["reasons"])


def _admin_web():
    web = Client()
    name = f"su{User.objects.count()}"
    web.force_login(User.objects.create_superuser(username=name, password=None, email=f"{name}@example.com"))
    return web


def _form_data(response, changes):
    form = response.context["adminform"].form
    data = {}
    for bound in form:
        changed = bound.name in changes
        value = changes[bound.name] if changed else bound.value()
        widget = bound.field.widget
        if isinstance(widget, forms.MultiWidget):
            for i, part in enumerate(widget.decompress(value)):
                data[f"{bound.html_name}_{i}"] = "" if part is None else part
        elif isinstance(widget, forms.CheckboxInput):
            if value:
                data[bound.html_name] = "on"
        else:
            prepared = bound.field.prepare_value(value) if changed else value
            data[bound.html_name] = "" if prepared is None else prepared
    for inline in response.context["inline_admin_formsets"]:
        formset = inline.formset
        for name in ("TOTAL_FORMS", "INITIAL_FORMS", "MIN_NUM_FORMS", "MAX_NUM_FORMS"):
            data[f"{formset.prefix}-{name}"] = formset.management_form[name].value()
        for row in formset.forms:  # the rows already there, as the page holds them
            for bound in row:
                value = bound.value()
                if value not in (None, False):
                    data[bound.html_name] = value
    return data


def _via_admin_change(finding):
    web = _admin_web()
    url = f"/admin/assurance/finding/{finding.pk}/change/"
    response = web.get(url)
    assert response.status_code == 200
    response = web.post(url, _form_data(response, {"remediation_state": "in_progress"}))
    if response.status_code == 302:
        return True, ""
    assert response.status_code == 200, response.status_code
    form = response.context["adminform"].form
    inline_errors = [str(i.formset.errors) for i in response.context["inline_admin_formsets"] if any(i.formset.errors)]
    return False, "; ".join([*form.non_field_errors(), *(f"{k}: {v}" for k, v in form.errors.items()), *inline_errors])


def _via_save(finding):
    from assurance.remediation import ContractRequired

    finding.remediation_state = State.IN_PROGRESS
    try:
        finding.save(update_fields=["remediation_state", "updated_at"])
    except ContractRequired as exc:
        return False, "; ".join(exc.reasons)
    return True, ""


PATHS = {
    "remediation.apply_transition": _via_service,
    "api remediation/transition": _via_api,
    "admin change form": _via_admin_change,
    "ORM save": _via_save,
}


@pytest.mark.parametrize("path", sorted(PATHS))
def test_a_move_into_progress_without_a_contract_is_refused_on_every_path(path):
    finding = _triaged()

    moved, why = PATHS[path](finding)

    assert moved is False
    assert "repair contract" in why and "prohibited effect" in why and "preserve" in why, why
    assert Finding.objects.get(pk=finding.pk).remediation_state == State.TRIAGED
    assert not finding.remediation_events.filter(to_state=State.IN_PROGRESS).exists()


@pytest.mark.parametrize("path", sorted(PATHS))
def test_a_move_into_progress_with_a_contract_is_allowed_on_every_path(path):
    finding = _triaged()
    agree(finding)

    moved, why = PATHS[path](Finding.objects.get(pk=finding.pk))

    assert moved is True, why
    assert Finding.objects.get(pk=finding.pk).remediation_state == State.IN_PROGRESS


def test_a_finding_cannot_be_created_already_in_a_working_state():
    from assurance.remediation import WORKING_STATES, ContractRequired

    dep = Deployment.objects.create(name="born", owner=_admin())
    for state in sorted(WORKING_STATES):
        with pytest.raises(ContractRequired, match="cannot be created already"):
            Finding.objects.create(
                deployment=dep, fingerprint=state, finding_type="t", title="T", severity="low",
                remediation_state=state,
            )
    assert not Finding.objects.filter(deployment=dep).exists()
    # The admin's add form validates the same way: refused on the form, nothing saved.
    unsaved = Finding(deployment=dep, fingerprint="x", finding_type="t", title="T", severity="low",
                      remediation_state=State.IN_PROGRESS)
    with pytest.raises(ValidationError, match="repair contract"):
        unsaved.full_clean()


def test_the_admin_add_form_refuses_a_finding_born_in_progress():
    owner = _admin()
    dep = Deployment.objects.create(name="added", owner=owner)
    web = _admin_web()
    response = web.get("/admin/assurance/finding/add/")
    assert response.status_code == 200
    data = _form_data(response, {
        "deployment": dep.pk, "fingerprint": "added", "finding_type": "t", "title": "T",
        "severity": "low", "remediation_state": "in_progress",
    })
    response = web.post("/admin/assurance/finding/add/", data)
    assert response.status_code == 200, "refused on the form"
    assert "repair contract" in " ".join(response.context["adminform"].form.non_field_errors())
    assert not Finding.objects.filter(deployment=dep).exists()


def test_a_finding_already_past_the_gate_is_not_rewritten_and_needs_a_contract_to_move_on():
    """A finding that reached in_progress before the gate (a row written past it, as
    legacy data is) stays there. It may stop -- wont_fix needs no contract -- but any
    further move into a working state needs one, and its closure is held to it."""
    from assurance.remediation import ContractRequired, apply_transition

    legacy = _finding()
    Finding.objects.filter(pk=legacy.pk).update(remediation_state=State.IN_PROGRESS)
    legacy.refresh_from_db()
    legacy.title = "an owner's edit, which is not a move"
    legacy.save()
    assert Finding.objects.get(pk=legacy.pk).remediation_state == State.IN_PROGRESS

    with pytest.raises(ContractRequired):
        apply_transition(legacy, State.IN_REVIEW, actor=None)
    agree(legacy)
    apply_transition(legacy, State.IN_REVIEW, actor=None)

    stopped = _finding()
    Finding.objects.filter(pk=stopped.pk).update(remediation_state=State.IN_PROGRESS)
    stopped.refresh_from_db()
    apply_transition(stopped, State.WONT_FIX, actor=None)
    assert Finding.objects.get(pk=stopped.pk).remediation_state == State.WONT_FIX
    # Its closure, like every other, is held to a contract it never agreed.
    record_closure_evidence(
        stopped, fixtures=copy.deepcopy(COMPLETE), origin=ClaimEvidence.Origin.INDEPENDENT,
        content_digest="sha256:ab12",
    )
    with pytest.raises(ClosureRefused, match="contract"):
        _close(stopped)


# ---------------------------------------------------------------------------
# The contract: append-only, versioned, digested
# ---------------------------------------------------------------------------


def _canonical(value):
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def test_versions_increase_and_the_latest_is_current():
    from assurance.repair_contract import current_contract

    finding = _finding()
    first = agree(finding)
    second = agree(finding, behaviours=["customer searches own orders"])

    assert (first.version, second.version) == (1, 2)
    assert current_contract(finding).pk == second.pk
    assert first.content_digest == _canonical({
        "finding_ref": str(finding.uuid), "version": 1,
        "prohibited_effect": EFFECT, "preserved_behaviours": list(BEHAVIOURS),
    })
    assert first.content_digest != second.content_digest
    # Each finding counts its own.
    assert agree(_finding()).version == 1


def test_a_contract_is_never_edited_or_deleted():
    from assurance.models import RepairContract
    from assurance.repair_contract import ContractIsAppendOnly

    finding = _finding()
    contract = agree(finding)
    contract.prohibited_effect = "something milder"
    with pytest.raises(ContractIsAppendOnly):
        contract.save()
    with pytest.raises(ContractIsAppendOnly):
        RepairContract.objects.filter(pk=contract.pk).update(prohibited_effect="something milder")
    with pytest.raises(ContractIsAppendOnly):
        RepairContract.objects.bulk_update([contract], ["prohibited_effect"])
    with pytest.raises(ContractIsAppendOnly):
        contract.delete()
    with pytest.raises(ContractIsAppendOnly):
        RepairContract.objects.filter(finding=finding).delete()
    stored = RepairContract.objects.get(pk=contract.pk)
    assert stored.prohibited_effect == EFFECT and stored.version == 1


@pytest.mark.parametrize(
    "effect, behaviours, field",
    [
        ("", ["own rows load"], "prohibited_effect"),
        ("   ", ["own rows load"], "prohibited_effect"),
        (None, ["own rows load"], "prohibited_effect"),
        ("reads others' rows", [], "preserved_behaviours"),
        ("reads others' rows", "own rows load", "preserved_behaviours"),
        ("reads others' rows", ["own rows load", "own rows load"], "preserved_behaviours[1]"),
        ("reads others' rows", ["own rows load", ""], "preserved_behaviours[1]"),
        ("reads others' rows", [" own rows load"], "preserved_behaviours[0]"),
        ("reads others' rows", [7], "preserved_behaviours[0]"),
    ],
)
def test_a_contract_that_does_not_say_both_things_is_refused(effect, behaviours, field):
    from assurance.models import RepairContract
    from assurance.repair_contract import ContractRefused

    finding = _finding()
    with pytest.raises(ContractRefused) as caught:
        agree(finding, effect=effect, behaviours=behaviours)
    assert field in caught.value.errors
    assert not RepairContract.objects.exists()


def test_the_api_agrees_a_version_as_an_admin_and_lists_them_to_who_can_see_the_finding():
    finding = _triaged()
    admin = _admin()

    first = _api(admin).post(_contracts_url(finding), {
        "prohibited_effect": EFFECT, "preserved_behaviours": list(BEHAVIOURS),
    }, format="json")
    assert first.status_code == 201, first.content
    assert first.json()["version"] == 1 and first.json()["agreed_by"] == admin.username
    assert first.json()["current"] is True
    second = _api(admin).post(_contracts_url(finding), {
        "prohibited_effect": EFFECT, "preserved_behaviours": ["customer searches own orders"],
    }, format="json")
    assert second.json()["version"] == 2

    listed = _api(finding.deployment.owner).get(_contracts_url(finding))
    assert listed.status_code == 200
    body = listed.json()
    assert body["current"] == 2
    assert [(c["version"], c["current"]) for c in body["contracts"]] == [(1, False), (2, True)]
    assert body["contracts"][0]["preserved_behaviours"] == list(BEHAVIOURS)

    # Scoped like every finding read: a user who cannot see the finding gets nothing.
    stranger = User.objects.create_user(username="stranger", password="x", role=User.Roles.VIEWER)
    assert _api(stranger).get(_contracts_url(finding)).status_code == 404
    # And agreeing one is an admin's write: an analyst, who can read it, cannot.
    analyst = User.objects.create_user(username="analyst", password="x", role=User.Roles.ANALYST)
    assert _api(analyst).get(_contracts_url(finding)).status_code == 200
    assert _api(analyst).post(
        _contracts_url(finding), {"prohibited_effect": EFFECT, "preserved_behaviours": ["x"]}, format="json",
    ).status_code == 403


def test_the_api_refuses_an_unknown_field_or_a_missing_one_by_name():
    finding = _finding()
    answer = _api().post(_contracts_url(finding), {
        "prohibited_effect": EFFECT, "preserved_behaviours": ["x"], "version": 9,
    }, format="json")
    assert answer.status_code == 400 and answer.json() == {"version": "unknown field"}
    answer = _api().post(_contracts_url(finding), {"prohibited_effect": EFFECT}, format="json")
    assert answer.status_code == 400 and "preserved_behaviours" in answer.json()
    answer = _api().post(_contracts_url(finding), {"prohibited_effect": EFFECT, "preserved_behaviours": []},
                         format="json")
    assert answer.status_code == 400 and "preserved_behaviours" in answer.json()


def test_the_admin_shows_contracts_read_only():
    finding = _finding()
    contract = agree(finding)
    web = _admin_web()
    assert web.get("/admin/assurance/repaircontract/").status_code == 200
    assert web.get(f"/admin/assurance/repaircontract/{contract.pk}/change/").status_code == 200
    assert web.get("/admin/assurance/repaircontract/add/").status_code == 403
    assert web.post(f"/admin/assurance/repaircontract/{contract.pk}/delete/", {"post": "yes"}).status_code == 403
    assert web.post(f"/admin/assurance/repaircontract/{contract.pk}/change/", {
        "prohibited_effect": "milder",
    }).status_code == 403


# ---------------------------------------------------------------------------
# Closure is held to the contract
# ---------------------------------------------------------------------------


def _record(finding, document, now=None):
    return record_closure_evidence(
        finding, fixtures=copy.deepcopy(COMPLETE), origin=ClaimEvidence.Origin.INDEPENDENT,
        content_digest="sha256:ab12", document=document, now=now,
    )


def _close(finding):
    row = Finding.objects.get(pk=finding.pk)
    row.status = Finding.Status.CLOSED
    row.save()


def _refused(finding, *names):
    with pytest.raises(ClosureRefused) as caught:
        _close(finding)
    assert Finding.objects.get(pk=finding.pk).status != Finding.Status.CLOSED
    text = "; ".join(caught.value.reasons)
    for name in names:
        assert name in text, text
    # Held to the contract only: every other condition holds in these documents.
    assert all(reason.startswith("contract:") for reason in caught.value.reasons), text
    return text


def _held(finding, **changes):
    document = replay(finding, COMPLETE)
    document["contract"].update(changes)
    return document


def test_a_replay_held_to_the_current_contract_closes():
    finding = _finding()
    agree(finding)
    _record(finding, replay(finding, COMPLETE))
    assert refusal_reasons(finding) == []
    _close(finding)
    assert Finding.objects.get(pk=finding.pk).status == Finding.Status.CLOSED


def test_a_replay_with_no_contract_block_is_refused():
    finding = _finding()
    agree(finding)
    document = replay(finding, COMPLETE)
    del document["contract"]
    _record(finding, document)
    _refused(finding, "the replay names no repair contract")


def test_a_record_with_no_replay_document_is_refused():
    finding = _finding()
    agree(finding)
    _record(finding, None)
    _refused(finding, "carries no replay document")


def test_a_finding_with_no_contract_agreed_is_refused_whatever_its_replay_says():
    finding = _finding()
    other = _finding()
    agree(other)
    document = replay(other, COMPLETE)  # held to another finding's contract
    document["finding_ref"] = str(finding.uuid)
    _record(finding, document)
    _refused(finding, "no repair contract has been agreed")


def test_a_replay_held_to_a_superseded_contract_cannot_close():
    finding = _finding()
    agree(finding)
    _record(finding, replay(finding, COMPLETE))
    assert refusal_reasons(finding) == []
    # The terms change after the replay: what it was held to no longer stands.
    agree(finding, behaviours=list(BEHAVIOURS))
    _refused(finding, "names version 1, superseded by version 2")


def test_a_digest_that_is_no_contract_of_the_finding_s_is_refused():
    finding = _finding()
    agree(finding)
    _record(finding, _held(finding, digest="sha256:" + "0" * 64))
    _refused(finding, "no version of this finding's contract")


@pytest.mark.parametrize(
    "reading, reason",
    [
        ("broken", "is broken"),
        ("unknown", "could not tell whether preserved behaviour"),
        ("gone", "unreadable reading"),
    ],
)
def test_a_preserved_behaviour_not_retained_is_refused(reading, reason):
    finding = _finding()
    agree(finding)
    document = replay(finding, COMPLETE)
    document["contract"]["preserved"]["admin order export"] = reading
    _record(finding, document)
    text = _refused(finding, reason, "'admin order export'")
    assert "customer searches own orders" not in text


def test_a_preserved_behaviour_left_out_is_refused():
    finding = _finding()
    agree(finding)
    document = replay(finding, COMPLETE)
    del document["contract"]["preserved"]["admin order export"]
    _record(finding, document)
    _refused(finding, "does not report preserved behaviour(s) 'admin order export'")


def test_a_behaviour_the_contract_does_not_name_is_refused():
    finding = _finding()
    agree(finding)
    document = replay(finding, COMPLETE)
    document["contract"]["preserved"]["guest checkout"] = "retained"
    _record(finding, document)
    _refused(finding, "names behaviour(s) the contract does not: 'guest checkout'")


def test_the_contract_only_adds_to_the_existing_conditions():
    """Nothing refused before is allowed now: a replay held to its contract is still
    refused for a planted incomplete repair it passed, a stale run, or a vendor's
    origin -- and named for each."""
    fooled_finding = _finding()
    agree(fooled_finding)
    fooled = copy.deepcopy(COMPLETE)
    fooled[INCOMPLETE_REPAIR]["changed_defaults"] = {"ran": True, "outcome": "passed"}
    document = replay(fooled_finding, fooled)
    record_closure_evidence(
        fooled_finding, fixtures=fooled, origin=ClaimEvidence.Origin.INDEPENDENT,
        content_digest="sha256:ab12", document=document,
    )
    assert any("changed_defaults: passed" in r for r in refusal_reasons(fooled_finding))

    stale = _finding()
    agree(stale)
    _record(stale, replay(stale, COMPLETE))
    Finding.objects.filter(pk=stale.pk).update(last_seen=timezone.now() + timedelta(minutes=5))
    assert any("last observed" in r for r in refusal_reasons(Finding.objects.get(pk=stale.pk)))

    vendor = _finding()
    agree(vendor)
    record_closure_evidence(
        vendor, fixtures=copy.deepcopy(COMPLETE), origin=ClaimEvidence.Origin.VENDOR,
        content_digest="sha256:ab12", document=replay(vendor, COMPLETE, origin="vendor"),
    )
    assert any("origin: vendor" in r for r in refusal_reasons(vendor))

    effect_present = _finding()
    agree(effect_present)
    document = replay(effect_present, COMPLETE)
    document["replay"]["original_effect"] = "present"
    _record(effect_present, document)
    assert any("still produces the unauthorized effect" in r for r in refusal_reasons(effect_present))


def test_the_closure_standing_names_the_current_contract_and_the_block_it_was_held_to():
    finding = _finding()
    contract = agree(finding)
    _record(finding, replay(finding, COMPLETE))
    served = _api(finding.deployment.owner).get(f"/api/assurance/findings/{finding.uuid}/").json()["closure"]
    assert served["standing"] == "closable"
    assert served["contract"] == {"version": 1, "content_digest": contract.content_digest}
    assert served["evidence"]["contract"]["digest"] == contract.content_digest
    assert served["evidence"]["contract"]["preserved"] == {b: "retained" for b in BEHAVIOURS}

    agree(finding, behaviours=["customer searches own orders"])
    served = _api(finding.deployment.owner).get(f"/api/assurance/findings/{finding.uuid}/").json()["closure"]
    assert served["standing"] == "not_closable"
    assert any("superseded" in r for r in served["reasons"])


# ---------------------------------------------------------------------------
# The engine service's route reads the block; Minotaur reads the same document
# ---------------------------------------------------------------------------


@pytest.fixture
def service(settings):
    settings.CLOSURE_EVIDENCE_SERVICE_TOKEN = SERVICE_CREDENTIAL
    settings.CLOSURE_EVIDENCE_SERVICE_USER = SERVICE_ACCOUNT
    return User.objects.create_user(username=SERVICE_ACCOUNT, role=User.Roles.VIEWER)


def _post(finding, document):
    client = APIClient()
    client.credentials(HTTP_X_CLOSURE_EVIDENCE_TOKEN=SERVICE_CREDENTIAL)
    return client.post(
        f"/api/assurance/findings/{finding.uuid}/closure-evidence/",
        {"document": document, "content_digest": _canonical(document)}, format="json",
    )


def test_the_route_records_a_document_without_the_block_and_it_cannot_close(service):
    finding = _finding()
    agree(finding)
    document = replay(finding, COMPLETE)
    del document["contract"]

    answer = _post(finding, document)

    assert answer.status_code == 201, answer.content
    assert answer.json()["closure"]["standing"] == "not_closable"
    _refused(finding, "the replay names no repair contract")


def test_the_route_records_a_document_held_to_the_contract_and_it_closes(service):
    finding = _finding()
    agree(finding)
    document = replay(finding, COMPLETE)

    answer = _post(finding, document)

    assert answer.status_code == 201, answer.content
    assert answer.json()["result"] == "verified_closed"
    assert answer.json()["closure"]["standing"] == "closable"
    assert answer.json()["content_digest"] == _canonical(document)
    _close(finding)
    assert Finding.objects.get(pk=finding.pk).status == Finding.Status.CLOSED


@pytest.mark.parametrize(
    "block, field",
    [
        ({"digest": "sha256:" + "a" * 64, "preserved": {"x": "retained"}, "verified": True}, "document.contract.verified"),
        ({"preserved": {"x": "retained"}}, "document.contract.digest"),
        ({"digest": "sha256:" + "a" * 64}, "document.contract.preserved"),
        ({"digest": "md5:abc", "preserved": {"x": "retained"}}, "document.contract.digest"),
        ({"digest": "sha256:" + "a" * 64, "preserved": {}}, "document.contract.preserved"),
        ({"digest": "sha256:" + "a" * 64, "preserved": ["x"]}, "document.contract.preserved"),
        ({"digest": "sha256:" + "a" * 64, "preserved": {" x": "retained"}}, "document.contract.preserved"),
        ({"digest": "sha256:" + "a" * 64, "preserved": {"x": "fine"}}, "document.contract.preserved.x"),
        ("sha256:" + "a" * 64, "document.contract"),
    ],
)
def test_the_route_refuses_a_contract_block_it_cannot_read_by_name(service, block, field):
    from assurance.models import RetestClosureEvidence

    finding = _finding()
    agree(finding)
    document = replay(finding, COMPLETE)
    document["contract"] = block

    answer = _post(finding, document)

    assert answer.status_code == 400, answer.content
    assert field in answer.json(), answer.json()
    assert not RetestClosureEvidence.objects.filter(finding=finding).exists()


@pytest.mark.parametrize(
    "reading, result",
    [("broken", "utility_breaking"), ("unknown", "inconclusive")],
)
def test_what_the_replay_came_to_counts_a_preserved_behaviour_as_minotaur_does(service, reading, result):
    finding = _finding()
    agree(finding)
    document = replay(finding, COMPLETE)
    document["contract"]["preserved"]["admin order export"] = reading

    answer = _post(finding, document)

    assert answer.status_code == 201, answer.content
    assert answer.json()["result"] == result


#: A document carrying the contract block, and its digest. Minotaur-Backend's
#: tests/test_a_remediation_row_carries_its_repair_contract.py pins the same pair
#: against ``remediation_outcomes.digest(normalize(row))``; the contract's own digest
#: is pinned against this backend's ``content_digest`` of the contract it names.
GOLDEN_CONTRACT_REF = "0f6f1d1e-3c55-4a8e-9a0e-5f0c2b7d9e11"
GOLDEN_CONTRACT_DIGEST = "sha256:56e206523061502319e66699b099c10d7af4d3e9eb3e117cb7df5fdd38766490"
GOLDEN_DOCUMENT_WITH_CONTRACT = {
    "finding_type": "sql_injection",
    "finding_ref": GOLDEN_CONTRACT_REF,
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
    "contract": {
        "digest": GOLDEN_CONTRACT_DIGEST,
        "preserved": {"admin order export": "retained", "customer searches own orders": "retained"},
    },
}
GOLDEN_DIGEST_WITH_CONTRACT = "sha256:46632bf5bf2e47f7f6aac081c10e547193efb18ecfce57d4203c176212fce3cd"


def test_the_contract_and_the_document_carrying_it_digest_as_minotaur_digests_them():
    from assurance import closure_evidence
    from assurance.repair_contract import content_digest

    assert content_digest(GOLDEN_CONTRACT_REF, 1, EFFECT, list(BEHAVIOURS)) == GOLDEN_CONTRACT_DIGEST
    assert closure_evidence.canonical_digest(GOLDEN_DOCUMENT_WITH_CONTRACT) == GOLDEN_DIGEST_WITH_CONTRACT
    assert _canonical(GOLDEN_DOCUMENT_WITH_CONTRACT) == GOLDEN_DIGEST_WITH_CONTRACT


def test_the_route_accepts_the_golden_document_under_its_golden_digest(service):
    from uuid import UUID

    finding = _finding()
    Finding.objects.filter(pk=finding.pk).update(uuid=UUID(GOLDEN_CONTRACT_REF))
    finding = Finding.objects.get(pk=finding.pk)
    contract = agree(finding, effect=EFFECT, behaviours=list(BEHAVIOURS))
    assert contract.content_digest == GOLDEN_CONTRACT_DIGEST

    answer = _post(finding, GOLDEN_DOCUMENT_WITH_CONTRACT)

    assert answer.status_code == 201, answer.content
    assert answer.json()["content_digest"] == GOLDEN_DIGEST_WITH_CONTRACT
    assert answer.json()["result"] == "verified_closed"
    assert answer.json()["closure"]["standing"] == "closable"
