"""Raising a financial source's trust tier (the owner's decision of 12 Oct 2026;
``docs/economics/spec-v1.md``, section 6.1).

Since #154 a production run refuses every source still trusted as ``unverified``,
and nothing but the snapshot loader wrote a tier. The owner adopted the lead's
recommendation:

- only an admin raises a tier (anonymous 401, a signed-in non-admin 403), and a
  tenant's source only where the deployment scoping shows that tenant;
- a raise is a NEW version of the source -- the same tenant, key, provider,
  dataset, url, licence, snapshot hash, retrieval time, schema version and
  synthetic flag, at the new tier -- naming the admin who completed it, beside one
  append-only record of who asked, who approved, why and when;
- only upward, and only from the latest version of the source;
- ``authoritative`` needs a second person: the request stays pending, and a
  DIFFERENT admin approves it, once, atomically.

The new model is read through the module (``econ.FinancialSourceTrustRaise``)
rather than imported by name, so that on the base, where it does not exist, each
test here fails on what it asserts rather than the whole file on its import.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, connection, models, transaction
from rest_framework.test import APIClient

from assurance.economics import models as econ
from assurance.economics import snapshots
from assurance.economics.engine import governance
from assurance.economics.engine.provenance import TrustTier
from assurance.economics.models import (
    EconomicsRefused,
    EconomicsRewriteRefused,
    FinancialSource,
    SourceNotUsableForProduction,
    runs_in_production,
)
from assurance.models import Deployment

pytestmark = pytest.mark.django_db

User = get_user_model()
SNAPSHOT = "sha256:" + "7b" * 32
RETRIEVED = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
REASON = "The Federal Reserve publishes H.10 itself: the official publisher of the figure."


def _raises():
    return econ.FinancialSourceTrustRaise


@pytest.fixture
def people():
    """Three admins (one a superuser with no admin role), an analyst, and a viewer
    who owns the tenant deployment."""
    return {
        "ada": User.objects.create_user(username="ada", password="x", role="admin"),
        "bea": User.objects.create_user(username="bea", password="x", role="admin"),
        "cid": User.objects.create_superuser(username="cid", password="x", email="cid@example.test"),
        "ann": User.objects.create_user(username="ann", password="x", role="analyst"),
        "vic": User.objects.create_user(username="vic", password="x", role="viewer"),
    }


@pytest.fixture
def deployment(people):
    return Deployment.objects.create(name="payments-agent", owner=people["vic"])


@pytest.fixture
def other_deployment():
    return Deployment.objects.create(name="other-tenant")


def _source(**over):
    fields = {
        "source_key": "fed-h10-daily",
        "provider": "Federal Reserve",
        "dataset": "H.10 foreign exchange rates",
        "url": "https://www.federalreserve.gov/releases/h10/",
        "license_class": "open",
        "retrieved_at": RETRIEVED,
        "snapshot_hash": SNAPSHOT,
        "schema_version": "1",
    }
    fields.update(over)
    return FinancialSource.objects.create(**fields)


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


def _raise_url(source) -> str:
    return f"/api/assurance/economics/sources/{source.uuid}/trust-raises/"


def _approve_url(raised) -> str:
    return f"/api/assurance/economics/trust-raises/{raised['uuid'] if isinstance(raised, dict) else raised.uuid}/approve/"


def _withdraw_url(raised) -> str:
    return f"/api/assurance/economics/trust-raises/{raised['uuid'] if isinstance(raised, dict) else raised.uuid}/withdraw/"


def _post(client, url, body=None, raw=False):
    data = body if raw else json.dumps(body if body is not None else {})
    return client.post(url, data=data, content_type="application/json")


def _ask(client, source, to_tier, reason=REASON):
    return _post(client, _raise_url(source), {"to_tier": to_tier, "reason": reason})


def _versions(source_key="fed-h10-daily", deployment=None):
    return list(
        FinancialSource.objects.filter(source_key=source_key, deployment=deployment)
        .order_by("version")
        .values_list("version", "trust_tier")
    )


def _nothing_recorded(source_key="fed-h10-daily", deployment=None, versions=1):
    assert not _raises().objects.exists()
    assert len(_versions(source_key, deployment)) == versions


# ============================================================ the pure rules


def test_the_trust_order_is_the_enum_weakest_first():
    assert governance.TRUST_ORDER == tuple(reversed(list(TrustTier)))
    assert [t.value for t in governance.TRUST_ORDER] == [
        "unverified", "benchmark", "licensed_vendor", "customer", "authoritative",
    ]
    assert governance.TWO_PERSON_TIERS == {TrustTier.AUTHORITATIVE}
    for tier in TrustTier:
        assert governance.needs_second_person(tier.value) is (tier is TrustTier.AUTHORITATIVE)
    assert governance.needs_second_person(None) is False


RULES = [
    ("unverified", "benchmark", False, False, None),
    ("unverified", "authoritative", False, False, None),
    ("licensed_vendor", "customer", False, True, None),
    ("customer", "authoritative", False, True, None),
    ("benchmark", "benchmark", False, False, "trust_not_raised"),
    ("licensed_vendor", "benchmark", False, False, "trust_not_raised"),
    ("authoritative", "customer", False, True, "trust_not_raised"),
    ("unverified", "benchmark", True, False, "synthetic_source"),
    ("unverified", "customer", False, False, "customer_source_without_tenant"),
    ("unverified", "gold", False, False, "code_unrecognised"),
    ("unverified", None, False, False, "code_unrecognised"),
    ("Unverified", "benchmark", False, False, "code_unrecognised"),
]


@pytest.mark.parametrize("from_tier, to_tier, synthetic, has_tenant, code", RULES)
def test_a_raise_is_upward_only_and_keeps_the_source_invariants(from_tier, to_tier, synthetic, has_tenant, code):
    assert (
        governance.trust_raise_refusal(from_tier, to_tier, synthetic=synthetic, has_tenant=has_tenant) == code
    )


def test_the_second_person_is_someone_else_by_account_or_by_name():
    ada = governance.Person(id=1, username="ada")
    assert governance.trust_raise_approval_refusal(ada, governance.Person(id=2, username="bea")) is None
    assert governance.trust_raise_approval_refusal(ada, ada) == "second_person_required"
    # A removed account is still the requester, by its recorded username.
    removed = governance.Person(id=None, username="ada")
    assert governance.trust_raise_approval_refusal(removed, governance.Person(id=7, username="ADA")) == (
        "second_person_required"
    )
    assert governance.trust_raise_approval_refusal(ada, governance.Person()) == "approver_not_named"
    assert governance.trust_raise_withdrawal_refusal(ada, ada) is None
    assert governance.trust_raise_withdrawal_refusal(ada, governance.Person(id=2, username="bea")) == (
        "withdrawn_by_requester_only"
    )
    assert governance.trust_raise_admin_refusal(True) is None
    for not_admin in (False, None, 1, "yes"):
        assert governance.trust_raise_admin_refusal(not_admin) == "admin_required"
    assert governance.trust_raise_reason_refusal("why") is None
    for blank in ("", "   ", None, 7):
        assert governance.trust_raise_reason_refusal(blank) == "required_field_blank"
    assert governance.trust_raise_reason_refusal("x" * governance.TRUST_RAISE_REASON_MAX) is None
    assert governance.trust_raise_reason_refusal("x" * (governance.TRUST_RAISE_REASON_MAX + 1)) == "reason_too_long"


# ============================================================ who may raise


def test_a_signed_out_caller_is_refused_401(people):
    source = _source()
    pending = _raises().request(source, "authoritative", REASON, by=people["ada"])
    client = _client()
    assert client.get(_raise_url(source)).status_code == 401
    assert _ask(client, source, "benchmark").status_code == 401
    assert _post(client, _approve_url(pending)).status_code == 401
    assert _post(client, _withdraw_url(pending)).status_code == 401
    assert _raises().objects.get().state == "pending"
    assert _versions() == [(1, "unverified")]


def test_a_signed_in_non_admin_is_refused_403_and_nothing_is_recorded(people, deployment):
    """An analyst and a viewer -- the viewer owning the tenant -- are refused every
    write with ``admin_required``, on a platform-wide source and on their own
    tenant's, before the body is read; they may read the list."""
    platform = _source()
    own = _source(deployment=deployment, source_key="revenue", license_class="customer")
    pending = _raises().request(platform, "authoritative", REASON, by=people["ada"])
    for name in ("ann", "vic"):
        client = _client(people[name])
        for source in (platform, own):
            refused = _ask(client, source, "benchmark")
            assert refused.status_code == 403, (name, refused.content)
            assert refused.json()["code"] == "admin_required"
            # Refused before the body is read: a malformed one is still 403.
            assert _post(client, _raise_url(source), "{", raw=True).status_code == 403
            assert client.get(_raise_url(source)).status_code == 200
        for url in (_approve_url(pending), _withdraw_url(pending)):
            refused = _post(client, url)
            assert refused.status_code == 403, (name, url, refused.content)
            assert refused.json()["code"] == "admin_required"
    assert list(_raises().objects.values_list("state", flat=True)) == ["pending"]
    assert _versions() == [(1, "unverified")]
    assert _versions("revenue", deployment) == [(1, "unverified")]
    # The model refuses them too, whatever calls it.
    for name in ("ann", "vic"):
        with pytest.raises(EconomicsRefused) as refused:
            _raises().request(platform, "benchmark", REASON, by=people[name])
        assert refused.value.code == "admin_required"
    # So is an admin whose account is switched off.
    people["bea"].is_active = False
    people["bea"].save()
    with pytest.raises(EconomicsRefused) as refused:
        _raises().objects.get(pk=pending.pk).approve(by=people["bea"])
    assert refused.value.code == "admin_required"


def test_a_tenants_source_is_raised_only_where_the_scoping_shows_that_tenant(
    people, deployment, other_deployment, monkeypatch
):
    """A tenant's source is found as its deployment is (``visible_deployments``):
    404 for anyone the scoping does not show that tenant, whether or not it exists,
    on every route, and nothing is recorded. Today the scoping shows an admin every
    deployment, so an admin raises any tenant's source; an admin it did not show a
    tenant (scoped here to their own deployments) is refused that tenant's."""
    from assurance.economics import api

    theirs = _source(deployment=other_deployment, source_key="revenue", license_class="customer")
    pending = _raises().request(theirs, "authoritative", REASON, by=people["bea"])

    # The owner of another tenant, a viewer: 404, not 403.
    viewer = _client(people["vic"])
    assert viewer.get(_raise_url(theirs)).status_code == 404
    assert _ask(viewer, theirs, "customer").status_code == 404
    assert _post(viewer, _approve_url(pending)).status_code == 404
    assert _post(viewer, _withdraw_url(pending)).status_code == 404

    # An admin the scoping does not show the other tenant.
    monkeypatch.setattr(api, "visible_deployments", lambda user: Deployment.objects.filter(owner=user))
    scoped = _client(people["ada"])
    assert scoped.get(_raise_url(theirs)).status_code == 404
    assert _ask(scoped, theirs, "customer").status_code == 404
    assert _post(scoped, _approve_url(pending)).status_code == 404
    assert _post(scoped, _withdraw_url(_raises().objects.get(pk=pending.pk))).status_code == 404
    assert list(_raises().objects.values_list("state", flat=True)) == ["pending"]
    assert _versions("revenue", other_deployment) == [(1, "unverified")]
    # A platform-wide source is every signed-in account's to see.
    platform = _source()
    assert _ask(scoped, platform, "benchmark").status_code == 201
    monkeypatch.undo()

    # As the scoping is today, the admin sees the tenant and raises its source.
    seen = _ask(_client(people["ada"]), theirs, "customer")
    assert seen.status_code == 201, seen.content
    assert _versions("revenue", other_deployment) == [(1, "unverified"), (2, "customer")]


# ============================================================ below the top tier


def test_a_raise_below_the_top_tier_records_a_new_version_the_production_gate_accepts(people, deployment):
    """One admin, one call: a NEW version, every field as the old one's but the
    tier, recorded by that admin; the record is done, requested and approved by the
    same admin at the moment the version was recorded. A production run accepts the
    new version and still refuses the old one."""
    assert runs_in_production(deployment)
    old = _source()
    with pytest.raises(SourceNotUsableForProduction):
        old.check_usable_for_production(deployment)

    answer = _ask(_client(people["ada"]), old, "licensed_vendor")
    assert answer.status_code == 201, answer.content
    body = answer.json()
    assert (body["state"], body["from_tier"], body["to_tier"], body["needs_second_person"]) == (
        "done", "unverified", "licensed_vendor", False,
    )
    assert (body["requested_by"], body["approved_by"], body["reason"]) == ("ada", "ada", REASON)
    assert body["from_version"]["uuid"] == str(old.uuid) and body["from_version"]["version"] == 1
    assert body["to_version"]["version"] == 2 and body["to_version"]["trust_tier"] == "licensed_vendor"
    assert body["to_version"]["recorded_by"] == "ada"
    assert body["deployment"] is None and body["withdrawn_at"] is None

    new = FinancialSource.objects.get(source_key="fed-h10-daily", version=2)
    copied = (
        "deployment_id", "source_key", "provider", "dataset", "url", "license_class", "retrieved_at",
        "snapshot_hash", "schema_version", "synthetic",
    )
    assert {f: getattr(new, f) for f in copied} == {f: getattr(old, f) for f in copied}
    assert (new.trust_tier, new.recorded_by, new.recorded_by_username) == ("licensed_vendor", people["ada"], "ada")
    assert FinancialSource.objects.get(pk=old.pk).trust_tier == "unverified"  # a version never changes

    record = _raises().objects.get()
    assert (record.from_version, record.to_version, record.state) == (old, new, "done")
    assert (record.requested_by, record.approved_by) == (people["ada"], people["ada"])
    assert (record.requested_by_username, record.approved_by_username) == ("ada", "ada")
    assert record.requested_at == record.approved_at == new.recorded_at
    assert body["approved_at"] == new.recorded_at.isoformat()

    # The production gate: the new version is usable, the old one is not.
    new.check_usable_for_production(deployment)
    new.check_usable_for_production(None)
    with pytest.raises(SourceNotUsableForProduction) as refused:
        old.check_usable_for_production(deployment)
    assert refused.value.code == "source_unverified"
    assert set(FinancialSource.objects.usable_for_production(deployment)) == {new}

    # A tenant's own data is raised to customer, in its own tenant.
    own = _source(deployment=deployment, source_key="revenue", license_class="customer")
    raised = _ask(_client(people["cid"]), own, "customer")
    assert raised.status_code == 201, raised.content
    assert raised.json()["deployment"] == str(deployment.uuid)
    assert _versions("revenue", deployment) == [(1, "unverified"), (2, "customer")]
    FinancialSource.objects.get(deployment=deployment, source_key="revenue", version=2).check_usable_for_production(
        deployment
    )


REFUSED = [
    ("the same tier", {"trust_tier": "licensed_vendor"}, "licensed_vendor", REASON, 400, "trust_not_raised"),
    ("a lower tier", {"trust_tier": "licensed_vendor"}, "benchmark", REASON, 400, "trust_not_raised"),
    ("a synthetic source", {"synthetic": True}, "benchmark", REASON, 400, "synthetic_source"),
    ("customer, platform-wide", {}, "customer", REASON, 400, "customer_source_without_tenant"),
    ("an empty reason", {}, "benchmark", "", 400, "required_field_blank"),
    ("a blank reason", {}, "benchmark", "  \n ", 400, "required_field_blank"),
    ("no reason", {}, "benchmark", None, 400, "required_field_blank"),
    ("a reason too long", {}, "benchmark", "x" * 2001, 400, "reason_too_long"),
    ("an unknown tier", {}, "gold", REASON, 400, "code_unrecognised"),
    ("no tier", {}, None, REASON, 400, "code_unrecognised"),
    ("a tier as a number", {}, 3, REASON, 400, "code_unrecognised"),
]


@pytest.mark.parametrize("what, source_fields, to_tier, reason, status, code", REFUSED, ids=[r[0] for r in REFUSED])
def test_a_raise_the_rules_refuse_records_nothing(people, what, source_fields, to_tier, reason, status, code):
    source = _source(**source_fields)
    answer = _post(_client(people["ada"]), _raise_url(source), {"to_tier": to_tier, "reason": reason})
    assert answer.status_code == status, answer.content
    assert answer.json()["code"] == code
    _nothing_recorded()
    # The same through the model, whichever route calls it.
    with pytest.raises(EconomicsRefused) as refused:
        _raises().request(source, to_tier, reason, by=people["ada"])
    assert refused.value.code == code
    _nothing_recorded()


def test_a_raise_from_a_version_that_is_not_the_latest_is_refused(people):
    old = _source()
    _source(trust_tier="benchmark")  # v2, recorded since
    answer = _ask(_client(people["ada"]), old, "licensed_vendor")
    assert answer.status_code == 409, answer.content
    assert answer.json()["code"] == "source_superseded"
    assert _ask(_client(people["ada"]), old, "authoritative").json()["code"] == "source_superseded"
    _nothing_recorded(versions=2)


def test_the_body_is_read_as_the_parameter_set_route_reads_one(people):
    source = _source()
    client = _client(people["ada"])
    url = _raise_url(source)
    duplicate = '{"to_tier": "authoritative", "to_tier": "benchmark", "reason": "x"}'
    for body in (duplicate, '{"to_tier": NaN, "reason": "x"}', "{", "[]", '"benchmark"'):
        assert _post(client, url, body, raw=True).status_code == 400, body
    extra = _post(client, url, {"to_tier": "benchmark", "reason": REASON, "approved_by": "bea"})
    assert extra.status_code == 400, extra.content
    assert client.post(url, {"to_tier": "benchmark", "reason": REASON}, format="multipart").status_code == 415
    from assurance.economics.api import MAX_BODY_BYTES

    # Refused on the DECLARED length, before the body is read, as a valid body too.
    declared = client.post(
        url, data=json.dumps({"to_tier": "benchmark", "reason": REASON}), content_type="application/json",
        CONTENT_LENGTH=str(MAX_BODY_BYTES + 1),
    )
    assert declared.status_code == 413, declared.content
    # And read no further than the limit, whatever was declared.
    padded = json.dumps({"to_tier": "benchmark", "reason": "x" * (MAX_BODY_BYTES + 1)})
    assert _post(client, url, padded, raw=True).status_code == 413
    for method in (client.put, client.patch, client.delete):
        assert method(url).status_code == 405
    _nothing_recorded()
    # Approving and withdrawing read the declared length the same way.
    pending = _raises().request(source, "authoritative", REASON, by=people["bea"])
    for who, url in (("cid", _approve_url(pending)), ("bea", _withdraw_url(pending))):
        refused = _client(people[who]).post(
            url, data="{}", content_type="application/json", CONTENT_LENGTH=str(MAX_BODY_BYTES + 1)
        )
        assert refused.status_code == 413, refused.content
        assert _client(people[who]).get(url).status_code == 405
    assert _raises().objects.get().state == "pending"
    assert _versions() == [(1, "unverified")]


# ============================================================ two people for authoritative


def _pending(people, source=None, by="ada"):
    source = source or _source()
    answer = _ask(_client(people[by]), source, "authoritative")
    assert answer.status_code == 201, answer.content
    return answer.json()


def test_an_authoritative_request_stays_pending_and_records_no_version(people, deployment):
    source = _source()
    body = _pending(people, source)
    assert (body["state"], body["to_version"], body["needs_second_person"]) == ("pending", None, True)
    assert (body["requested_by"], body["approved_by"], body["approved_at"]) == ("ada", None, None)
    assert _versions() == [(1, "unverified")]
    with pytest.raises(SourceNotUsableForProduction):
        source.check_usable_for_production(deployment)
    assert not FinancialSource.objects.usable_for_production(deployment).exists()


def test_the_requester_cannot_approve_their_own_request(people):
    body = _pending(people)
    refused = _post(_client(people["ada"]), _approve_url(body))
    assert refused.status_code == 403, refused.content
    assert refused.json()["code"] == "second_person_required"
    assert _raises().objects.get().state == "pending"
    assert _versions() == [(1, "unverified")]


def test_a_second_admin_approves_and_the_version_is_recorded(people, deployment):
    source = _source()
    body = _pending(people, source)
    approved = _post(_client(people["bea"]), _approve_url(body))
    assert approved.status_code == 200, approved.content
    done = approved.json()
    assert (done["state"], done["requested_by"], done["approved_by"]) == ("done", "ada", "bea")
    assert done["to_version"]["version"] == 2 and done["to_version"]["trust_tier"] == "authoritative"
    new = FinancialSource.objects.get(source_key="fed-h10-daily", version=2)
    assert (new.trust_tier, new.recorded_by_username) == ("authoritative", "bea")
    record = _raises().objects.get()
    assert (record.state, record.to_version, record.approved_by, record.approved_by_username) == (
        "done", new, people["bea"], "bea",
    )
    assert record.approved_at == new.recorded_at and record.requested_at < record.approved_at
    new.check_usable_for_production(deployment)
    with pytest.raises(SourceNotUsableForProduction):
        source.check_usable_for_production(deployment)
    # A superuser with no admin role is an admin too.
    second = _pending(people, _source(source_key="ecb-reference"), by="bea")
    assert _post(_client(people["cid"]), _approve_url(second)).status_code == 200


def test_a_second_approval_of_the_same_request_is_refused(people):
    body = _pending(people)
    assert _post(_client(people["bea"]), _approve_url(body)).status_code == 200
    for approver in ("cid", "bea"):
        again = _post(_client(people[approver]), _approve_url(body))
        assert again.status_code == 409, again.content
        assert again.json()["code"] == "trust_raise_not_pending"
    withdraw = _post(_client(people["ada"]), _withdraw_url(body))
    assert withdraw.status_code == 409 and withdraw.json()["code"] == "trust_raise_not_pending"
    assert _versions() == [(1, "unverified"), (2, "authoritative")]
    assert _raises().objects.get().approved_by_username == "bea"


def test_a_withdrawn_request_cannot_be_approved(people):
    body = _pending(people)
    # Only the requester withdraws it.
    other = _post(_client(people["bea"]), _withdraw_url(body))
    assert other.status_code == 403 and other.json()["code"] == "withdrawn_by_requester_only"
    withdrawn = _post(_client(people["ada"]), _withdraw_url(body))
    assert withdrawn.status_code == 200, withdrawn.content
    assert (withdrawn.json()["state"], withdrawn.json()["approved_by"]) == ("withdrawn", None)
    assert withdrawn.json()["withdrawn_at"] is not None
    refused = _post(_client(people["bea"]), _approve_url(body))
    assert refused.status_code == 409 and refused.json()["code"] == "trust_raise_not_pending"
    again = _post(_client(people["ada"]), _withdraw_url(body))
    assert again.status_code == 409
    assert _versions() == [(1, "unverified")]
    assert _raises().objects.get().state == "withdrawn"


def test_approval_after_the_source_got_a_newer_version_is_refused(people):
    source = _source()
    body = _pending(people, source)
    # Meanwhile another admin raises the same version one step, to benchmark.
    assert _ask(_client(people["cid"]), source, "benchmark").status_code == 201
    refused = _post(_client(people["bea"]), _approve_url(body))
    assert refused.status_code == 409, refused.content
    assert refused.json()["code"] == "source_superseded"
    assert _raises().objects.get(uuid=body["uuid"]).state == "pending"
    assert _versions() == [(1, "unverified"), (2, "benchmark")]
    # A version a snapshot registers counts as newer too.
    latest = FinancialSource.objects.get(source_key="fed-h10-daily", version=2)
    on_latest = _pending(people, latest)
    _source(trust_tier="licensed_vendor")  # v3
    assert _post(_client(people["bea"]), _approve_url(on_latest)).json()["code"] == "source_superseded"
    assert _versions() == [(1, "unverified"), (2, "benchmark"), (3, "licensed_vendor")]


@pytest.mark.django_db(transaction=True)
def test_two_concurrent_approvals_give_exactly_one_version(monkeypatch):
    """Two admins approve the same pending request at once: exactly one new version,
    one approval done and the other refused because the request is no longer pending.

    Each approval is held right after its state check, before it writes, until the
    other arrives -- or for a second, if the database lets only one approval in at a
    time. So if nothing serialised the two, both would pass the state check and write.
    What serialises them differs by database, and the test says which it shows. On
    SQLite, which this suite runs on, Django leaves ``select_for_update`` out and the
    transaction itself is the lock (the database's write lock, taken at BEGIN
    IMMEDIATE): dropping the transaction, or the state check, fails this test. On
    PostgreSQL the row lock does that work; SQLite cannot show it working, so the test
    checks that every approval asks for that lock on the raise's row."""
    from django.db.models.query import QuerySet

    ada, bea, cid = (User.objects.create_user(username=n, password="x", role="admin") for n in ("ada", "bea", "cid"))
    source = _source()
    pending = _raises().request(source, "authoritative", REASON, by=ada)

    locked = []
    real_select_for_update = QuerySet.select_for_update

    def recording(self, *args, **kwargs):
        locked.append(self.model)
        return real_select_for_update(self, *args, **kwargs)

    monkeypatch.setattr(QuerySet, "select_for_update", recording)

    both_in = threading.Barrier(2)
    real_stored = econ._stored_source

    def held(pk):
        try:
            both_in.wait(timeout=1.0)
        except threading.BrokenBarrierError:
            pass  # only one approval at a time got this far
        return real_stored(pk)

    monkeypatch.setattr(econ, "_stored_source", held)

    start = threading.Barrier(2)
    outcomes: dict[str, str] = {}

    def approve(admin):
        start.wait()
        try:
            _raises().objects.get(pk=pending.pk).approve(by=admin)
            outcomes[admin.username] = "done"
        except EconomicsRefused as refused:
            outcomes[admin.username] = refused.code
        except Exception as exc:  # noqa: BLE001 - recorded and asserted below
            outcomes[admin.username] = repr(exc)
        finally:
            connection.close()

    threads = [threading.Thread(target=approve, args=(admin,)) for admin in (bea, cid)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes.values()) == ["done", "trust_raise_not_pending"], outcomes
    winner = next(name for name, outcome in outcomes.items() if outcome == "done")
    assert _versions() == [(1, "unverified"), (2, "authoritative")]
    record = _raises().objects.get(pk=pending.pk)
    assert (record.state, record.approved_by_username) == ("done", winner)
    assert record.to_version.recorded_by_username == winner
    assert locked.count(_raises()) == 2, locked


# ============================================================ the record


def test_the_usernames_survive_deleting_the_user(people):
    """Removing an operator is a stop (``accounts:user-detail`` DELETE): it answers
    204 through the real route, nulls the account columns, and the record and the
    version keep the names."""
    body = _pending(people)
    assert _post(_client(people["bea"]), _approve_url(body)).status_code == 200
    asked = _pending(people, _source(source_key="ecb-reference"))
    remover = _client(people["cid"])
    for name in ("ada", "bea"):
        assert remover.delete(f"/api/accounts/users/{people[name].pk}/").status_code == 204
        assert not User.objects.filter(username=name).exists()
    done = _raises().objects.get(uuid=body["uuid"])
    assert (done.requested_by_id, done.approved_by_id) == (None, None)
    assert (done.requested_by_username, done.approved_by_username) == ("ada", "bea")
    assert (done.to_version.recorded_by_id, done.to_version.recorded_by_username) == (None, "bea")
    listed = _client(people["vic"]).get(_raise_url(done.from_version)).json()["raises"]
    assert [(r["requested_by"], r["approved_by"]) for r in listed] == [("ada", "bea")]
    # A removed requester is still the requester: their name cannot approve it.
    again = User.objects.create_user(username="ada", password="x", role="admin")
    refused = _post(_client(again), _approve_url(asked))
    assert refused.status_code == 403 and refused.json()["code"] == "second_person_required"


def test_the_record_is_never_rewritten_but_for_its_one_transition(people):
    body = _pending(people)
    record = _raises().objects.get()
    with pytest.raises(EconomicsRewriteRefused):
        record.save()
    with pytest.raises(EconomicsRewriteRefused):
        record.delete()
    with pytest.raises(EconomicsRewriteRefused):
        _raises().objects.filter(pk=record.pk).update(state="done")
    with pytest.raises(EconomicsRewriteRefused):
        _raises().objects.filter(pk=record.pk).delete()
    with pytest.raises(EconomicsRefused) as refused:
        _raises().objects.bulk_create([_raises()()])
    assert refused.value.code == "bulk_create_refused"
    assert _post(_client(people["bea"]), _approve_url(body)).status_code == 200
    assert _raises().objects.get().state == "done"


def test_no_orm_write_records_a_raise_past_the_rules(people, deployment):
    """The model refuses what the routes would: a raise to authoritative inserted
    done (or withdrawn) without a second admin's approval, a one-step raise inserted
    pending, a non-admin requester, and a version that is not the next of its source.
    The database refuses a downward pair and a state its fields do not match."""
    source = _source()
    raise_ = _raises()
    v2 = _source(trust_tier="authoritative")
    for state in ("done", "withdrawn"):
        with pytest.raises(EconomicsRefused) as refused:
            raise_.objects.create(
                from_version=source, to_version=v2, to_tier="authoritative", reason=REASON, state=state,
                requested_by=people["ada"], approved_by=people["bea"],
            )
        assert refused.value.code == "second_person_required"
    fresh = _source(source_key="ecb-reference")
    with pytest.raises(EconomicsRefused) as refused:
        raise_.objects.create(from_version=fresh, to_tier="benchmark", reason=REASON, requested_by=people["ada"])
    assert refused.value.code == "trust_raise_not_pending"
    with pytest.raises(EconomicsRefused) as refused:
        raise_.objects.create(
            from_version=fresh, to_tier="authoritative", reason=REASON, requested_by=people["ann"]
        )
    assert refused.value.code == "admin_required"
    # A one-step raise naming a version that is not the next of its source.
    with pytest.raises(EconomicsRefused) as refused:
        raise_.objects.create(
            from_version=fresh, to_version=v2, to_tier="benchmark", reason=REASON, state="done",
            requested_by=people["ada"],
        )
    assert refused.value.code == "source_superseded"
    assert not raise_.objects.exists()
    # Past save, the database's constraints: a downward pair, done with no version,
    # no requester's name.
    for fields in (
        {"from_tier": "benchmark", "to_tier": "unverified", "state": "pending", "requested_by_username": "ada"},
        {"from_tier": "unverified", "to_tier": "authoritative", "state": "done", "requested_by_username": "ada"},
        {"from_tier": "unverified", "to_tier": "authoritative", "state": "pending", "requested_by_username": ""},
        {"from_tier": "unverified", "to_tier": "authoritative", "state": "lost", "requested_by_username": "ada"},
    ):
        row = raise_(from_version=fresh, reason=REASON, **fields)
        with pytest.raises(IntegrityError), transaction.atomic():
            models.Model.save(row, force_insert=True)
    assert not raise_.objects.exists()


def test_a_synthetic_source_stays_unverified(people):
    synthetic = snapshots.register_snapshot()
    for tier in ("benchmark", "authoritative"):
        answer = _ask(_client(people["ada"]), synthetic, tier)
        assert answer.status_code == 400 and answer.json()["code"] == "synthetic_source"
    assert not _raises().objects.exists()
    assert list(FinancialSource.objects.values_list("trust_tier", flat=True)) == ["unverified"]


def test_the_list_reads_every_raise_of_the_source_newest_first(people, deployment):
    source = _source()
    first = _ask(_client(people["ada"]), source, "benchmark").json()
    v2 = FinancialSource.objects.get(source_key="fed-h10-daily", version=2)
    second = _pending(people, v2, by="bea")
    _ask(_client(people["ada"]), _source(source_key="ecb-reference"), "benchmark")
    for version in (source, v2):
        listed = _client(people["vic"]).get(_raise_url(version))
        assert listed.status_code == 200, listed.content
        body = listed.json()
        assert (body["source_key"], body["deployment"], body["truncated"]) == ("fed-h10-daily", None, False)
        assert [r["uuid"] for r in body["raises"]] == [second["uuid"], first["uuid"]]
    assert _client(people["vic"]).get(
        "/api/assurance/economics/sources/00000000-0000-4000-8000-000000000000/trust-raises/"
    ).status_code == 404


# ============================================================ the operator's command


def _command(*args):
    from io import StringIO

    out = StringIO()
    call_command("raise_source_trust", *args, stdout=out, stderr=StringIO())
    return out.getvalue()


def test_the_command_raises_with_the_same_rules_and_the_same_record(people):
    source = _source()
    printed = _command("request", str(source.uuid), "--to", "benchmark", "--reason", REASON, "--as", "ada")
    assert "done" in printed and "unverified -> benchmark" in printed and "recorded as v2" in printed
    assert REASON not in printed
    v2 = FinancialSource.objects.get(source_key="fed-h10-daily", version=2)
    assert v2.recorded_by_username == "ada"
    printed = _command("request", str(v2.uuid), "--to", "authoritative", "--reason", REASON, "--as", "ada")
    pending = _raises().objects.get(state="pending")
    assert f"raise {pending.uuid}: pending" in printed
    with pytest.raises(CommandError, match="second_person_required"):
        _command("approve", str(pending.uuid), "--as", "ada")
    printed = _command("approve", str(pending.uuid), "--as", "bea")
    assert "done" in printed and "approved by bea" in printed
    assert _versions() == [(1, "unverified"), (2, "benchmark"), (3, "authoritative")]
    with pytest.raises(CommandError, match="trust_raise_not_pending"):
        _command("withdraw", str(pending.uuid), "--as", "ada")
    other = _source(source_key="ecb-reference")
    _command("request", str(other.uuid), "--to", "authoritative", "--reason", REASON, "--as", "cid")
    asked = _raises().objects.get(from_version=other)
    with pytest.raises(CommandError, match="withdrawn_by_requester_only"):
        _command("withdraw", str(asked.uuid), "--as", "bea")
    assert "withdrawn" in _command("withdraw", str(asked.uuid), "--as", "cid")


def test_the_command_refuses_a_non_admin_and_writes_nothing(people):
    source = _source()
    for name in ("ann", "vic"):
        with pytest.raises(CommandError, match="admin_required"):
            _command("request", str(source.uuid), "--to", "benchmark", "--reason", REASON, "--as", name)
    with pytest.raises(CommandError, match="no account"):
        _command("request", str(source.uuid), "--to", "benchmark", "--reason", REASON, "--as", "nobody")
    with pytest.raises(CommandError, match="required_field_blank"):
        _command("request", str(source.uuid), "--to", "benchmark", "--reason", " ", "--as", "ada")
    pending = _raises().request(source, "authoritative", REASON, by=people["ada"])
    with pytest.raises(CommandError, match="admin_required"):
        _command("approve", str(pending.uuid), "--as", "ann")
    with pytest.raises(CommandError, match="go with request only"):
        _command("approve", str(pending.uuid), "--to", "benchmark", "--as", "bea")
    assert list(_raises().objects.values_list("state", flat=True)) == ["pending"]
    assert _versions() == [(1, "unverified")]
