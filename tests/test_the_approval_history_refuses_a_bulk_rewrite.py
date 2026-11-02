"""The approval history refuses a bulk rewrite, as the edge history does.

``ApprovalVersion`` refused an update or a delete of one recorded row (its ``save`` and
``delete``) and nothing refused one in bulk: a queryset ``update()``, ``bulk_update()``
or ``delete()`` rewrote or removed recorded versions. A gate-attested hop names its
approval version by id -- the history row Achilles' gate read from the
approval-in-force route and signed into the observed effect
(``dispatch.verified.workflow_approval.version``), which the G6 tool hop reads its
binding from too -- so one bulk write could change or remove the very row signed
evidence points at, and the hop would read whatever the write said.

The history's queryset now refuses all three, exactly as
``AuthorityEdgeVersionQuerySet`` does (``ApprovalVersionQuerySet``, the default manager,
so the related managers refuse them too), and:

* the rows are unchanged afterwards, whichever manager the write came through;
* a gate-attested hop citing a version still resolves to what the gate signed;
* the two writes that legitimately reach a recorded version still do, through the base
  manager, which stays Django's plain one: removing an operator who declared it -- a
  stop (``accounts:user-detail`` DELETE): the real route answers 204, nulls
  ``declared_by`` and changes nothing else -- and the deployment's cascade.

On master the queryset refuses nothing, so the refusal tests fail there; the stop and
the cascade pass there and pin that the guard keeps them as they are.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone as dt_timezone

import pytest
from django.contrib.auth import get_user_model
from django.db import models
from rest_framework.test import APIClient

from assurance import gate_approval, observed_effects
from assurance.models import ApprovalVersion, ApprovalVersionRewriteRefused, Deployment
from safety import stops
from tests.test_an_observed_effect_proves_the_produces_hop import TOKEN
from tests.test_sign_in_and_delegation_prove_the_person_hops import _chains
from tests.test_spine_authority_chain import WF, _admin, _client, _world
from tests.test_the_gate_attests_the_approval_it_read import _chain, _reading, _reapprove, _record

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()


@pytest.fixture
def service(monkeypatch):
    """The observed-effect service (as in the produces-hop tests)."""
    User.objects.create_user(username="effect-service", password="x")
    monkeypatch.setenv(observed_effects.TOKEN_ENV, TOKEN)
    monkeypatch.setenv(observed_effects.USER_ENV, "effect-service")
    client = APIClient()
    client.credentials(HTTP_X_OBSERVED_EFFECT_TOKEN=TOKEN)
    return client


def _now():
    return datetime.now(dt_timezone.utc)


def _recorded(*deployments):
    """Every recorded version of ``deployments``, every column, read past the refusals
    (the base manager): what a refused write must leave exactly as it was."""
    return list(ApprovalVersion._base_manager.filter(deployment__in=deployments).order_by("id").values())


def _hops(chain):
    return {h["relation"]: h for h in chain["hops"]}


def _codes(hop):
    return [r["code"] for r in (hop["proven_by"] if hop["verdict"] == "proven" else hop["reasons"])]


def _detail(hop, code):
    return next(r["detail"] for r in hop["proven_by"] if r["code"] == code)


def _declarer(dep):
    """The one person who declared every version of ``dep``'s approval (the admin the
    world's approved-workflows PUT signed in as)."""
    (person,) = {v.declared_by for v in ApprovalVersion.objects.filter(deployment=dep)}
    assert person is not None
    return person


# ------------------------------------------------------------------- the refusals


def test_a_bulk_update_or_delete_of_the_approval_history_is_refused_and_changes_nothing():
    dep, client, _, _ = _world()
    _reapprove(client, dep, "update any customer record")
    other, _, _, _ = _world()
    rows = ApprovalVersion.objects.filter(deployment=dep)
    assert rows.count() == 2
    before = _recorded(dep, other)

    rewrites = {
        "digest": "c3" * 32,
        "tools": [["mcp_server", "crm-mcp", "f0" * 32]],
        "in_force_from": _now() + timedelta(days=1),
        "recorded_at": _now() - timedelta(days=1),
        "workflow": "another-workflow",
        "deployment": other,
        "declared_by": None,
    }
    for field, value in rewrites.items():
        with pytest.raises(ApprovalVersionRewriteRefused):
            rows.update(**{field: value})
    with pytest.raises(ApprovalVersionRewriteRefused):
        ApprovalVersion.objects.update(digest="")
    moved = list(rows)
    for version in moved:
        version.digest = "c3" * 32
    with pytest.raises(ApprovalVersionRewriteRefused):
        ApprovalVersion.objects.bulk_update(moved, ["digest"])
    with pytest.raises(ApprovalVersionRewriteRefused):
        rows.delete()
    with pytest.raises(ApprovalVersionRewriteRefused):
        ApprovalVersion.objects.all().delete()

    assert _recorded(dep, other) == before
    # Appending is untouched: the next approval write still notes its version, after
    # the ones recorded, which stay as they were.
    _reapprove(client, dep, "update one customer record")
    after = _recorded(dep, other)
    assert after[: len(before)] == before and len(after) == len(before) + 1
    assert after[-1]["deployment_id"] == dep.pk and after[-1]["workflow"] == WF


def test_every_manager_that_reaches_the_history_refuses_a_bulk_rewrite():
    """The refusal is on the default manager, which the gate and every history read go
    through and every related manager is built from; the base manager stays Django's
    plain one, because the deployment's cascade and an operator's removal (a stop)
    write through it."""
    from assurance.models import ApprovalVersionQuerySet

    dep, client, _, _ = _world()
    person = _declarer(dep)
    (version,) = ApprovalVersion.objects.filter(deployment=dep)
    before = _recorded(dep)

    assert ApprovalVersion._default_manager is ApprovalVersion.objects
    assert isinstance(ApprovalVersion.objects.all(), ApprovalVersionQuerySet)
    for related in (dep.approval_versions, person.declared_approval_versions):
        assert isinstance(related.all(), ApprovalVersionQuerySet)
        with pytest.raises(ApprovalVersionRewriteRefused):
            related.update(digest="c3" * 32)
        with pytest.raises(ApprovalVersionRewriteRefused):
            related.all().delete()
    with pytest.raises(ApprovalVersionRewriteRefused):
        person.declared_approval_versions.clear()
    with pytest.raises(ApprovalVersionRewriteRefused):
        person.declared_approval_versions.remove(version)
    assert _recorded(dep) == before

    assert ApprovalVersion._meta.base_manager_name is None
    assert type(ApprovalVersion._base_manager) is models.Manager
    assert not isinstance(ApprovalVersion._base_manager.all(), ApprovalVersionQuerySet)


def test_a_gate_attested_hop_citing_a_version_still_resolves_after_an_attempted_rewrite(service):
    """The version the gate read and signed (v4: the approval for ``under_policy``, its
    tool binding for ``invokes``) cannot be moved under the signature: each rewrite is
    refused, and both hops still read proven, gate-attested, citing that row."""
    dep, client, permit, _ = _world()
    reading = _reading(dep)
    row, _evidence = _record(service, dep, permit, schema="v4", reading=reading)
    version = ApprovalVersion.objects.get(pk=int(reading["version"]))
    assert version.digest == reading["digest"]
    before = _recorded(dep)

    cited = ApprovalVersion.objects.filter(pk=version.pk)
    forged = ApprovalVersion.objects.get(pk=version.pk)
    forged.digest, forged.tools = "c3" * 32, [["mcp_server", "crm-mcp", "f0" * 32]]
    attempts = {
        "another digest": lambda: cited.update(digest="c3" * 32),
        "another contract": lambda: cited.update(tools=[["mcp_server", "crm-mcp", "f0" * 32]]),
        "no tools": lambda: cited.update(tools=[]),
        "in force only after the dispatch": lambda: cited.update(in_force_from=_now() + timedelta(days=1)),
        "a bulk update": lambda: ApprovalVersion.objects.bulk_update([forged], ["digest", "tools"]),
        "removed": lambda: cited.delete(),
    }
    for why, attempt in attempts.items():
        with pytest.raises(ApprovalVersionRewriteRefused):
            attempt()
        assert _recorded(dep) == before, why

    chain = _chain(client, dep, permit, row)

    policy, invokes = _hops(chain)["under_policy"], _hops(chain)["invokes"]
    assert _codes(policy) == ["approval_attested_in_force_at_dispatch"], policy
    detail = _detail(policy, "approval_attested_in_force_at_dispatch")
    assert f"version {version.id}" in detail and version.digest in detail
    assert "contract_attested_in_force_at_dispatch" in _codes(invokes), invokes
    assert f"version {version.id}" in _detail(invokes, "contract_attested_in_force_at_dispatch")
    assert chain["verdict"] == "proven", {r: _codes(h) for r, h in _hops(chain).items()}
    # And the gate's route still answers that version, level with the approval.
    status, body = gate_approval.approval_in_force(dep, WF, tools=True)
    assert status == 200 and body["version"] == reading["version"] and body["digest"] == reading["digest"]


# ---------------------------------------------- the writes that still reach a version


def _declared_by(person, name):
    """A deployment whose one approval ``person`` declared twice, through the
    approved-workflows PUT alone: nothing here writes past the history's refusals, so
    what this world reads is what the route and the stop leave."""
    dep = Deployment.objects.create(name=name, owner=person)
    for description in ("refunds under 500", "refunds under 100"):
        put = _client(person).put(
            f"/api/assurance/deployments/{dep.uuid}/approved-workflows/",
            {"workflows": [{"slug": "refund", "name": "Refund", "description": description}]},
            format="json",
        )
        assert put.status_code == 200, put.content
    return dep


def _remove(remover, person):
    """``person`` removed through the real route (``accounts:user-detail`` DELETE), its
    answer as the operator's client would see it: a fault is a 500, never raised here."""
    client = _client(remover)
    client.raise_request_exception = False
    return client.delete(f"/api/accounts/users/{person.pk}/")


def test_removing_an_operator_who_declared_versions_is_never_held_back():
    """Removing an operator is a stop. The route answers 204 and removes the account,
    and the one change each version they declared takes is ``declared_by`` nulled (it
    reads "not recorded"); every other column, and every other version, stays."""
    assert stops.STOP_ROUTES["accounts:user-detail"] == {"DELETE": stops.always}
    leaver, stayer, remover = _admin(), _admin(), _admin()
    dep, kept = _declared_by(leaver, "declared-by-the-leaver"), _declared_by(stayer, "declared-by-another")
    before, kept_rows = _recorded(dep), _recorded(kept)
    assert len(before) == 2 and {v["declared_by_id"] for v in before} == {leaver.pk}

    answer = _remove(remover, leaver)

    assert answer.status_code == 204, answer.content
    assert not User.objects.filter(pk=leaver.pk).exists()
    assert _recorded(dep) == [{**v, "declared_by_id": None} for v in before]
    assert _recorded(kept) == kept_rows


def test_a_gate_attested_chain_citing_a_removed_declarers_version_still_reads_proven(service):
    """The operator declared the version a gate-attested chain cites. Removing them
    leaves the row the gate signed as it was signed, but for ``declared_by``, and the
    chain still reads proven, citing the same row."""
    dep, client, permit, _ = _world()
    leaver = _declarer(dep)
    reading = _reading(dep)
    row, _evidence = _record(service, dep, permit, schema="v4", reading=reading)
    _chain(client, dep, permit, row)
    before = _recorded(dep)
    remover = _admin()

    answer = _remove(remover, leaver)

    assert answer.status_code == 204, answer.content
    assert _recorded(dep) == [{**v, "declared_by_id": None} for v in before]
    (chain,) = _chains(_client(remover), dep)
    policy = _hops(chain)["under_policy"]
    assert _codes(policy) == ["approval_attested_in_force_at_dispatch"], policy
    assert f"version {reading['version']}" in _detail(policy, "approval_attested_in_force_at_dispatch")
    assert chain["verdict"] == "proven", {r: _codes(h) for r, h in _hops(chain).items()}


def test_the_approval_history_goes_with_its_deployment_and_only_with_it():
    """The deployment's cascade removes its history -- an instance delete and a queryset
    delete -- and no other deployment's."""
    kept, _, _, _ = _world()
    kept_rows = _recorded(kept)
    assert kept_rows

    gone, _, _, _ = _world()
    pk = gone.pk
    assert ApprovalVersion.objects.filter(deployment_id=pk).exists()
    gone.delete()
    assert not ApprovalVersion._base_manager.filter(deployment_id=pk).exists()

    also, _, _, _ = _world()
    assert ApprovalVersion.objects.filter(deployment_id=also.pk).exists()
    Deployment.objects.filter(pk=also.pk).delete()
    assert not ApprovalVersion._base_manager.filter(deployment_id=also.pk).exists()

    assert _recorded(kept) == kept_rows
