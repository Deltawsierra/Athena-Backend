"""Athena Phase 1.5 — the Provider Assurance Profile.

Proves that a provider's posture is recorded as graded, per-field assertions —
each carrying its own evidence class, because a provider's facts are declared,
not measured. Writes are admin-only (open reads), one assertion per field, the
profile summary reports the weakest evidence among the facts, and every edit
records who made it.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.models import EvidenceClass, Provider, ProviderAssertion
from assurance.views import ProviderAssertionViewSet, ProviderViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _provider(name="OpenAI", kind=Provider.Kind.MODEL_PROVIDER):
    return Provider.objects.create(name=name, kind=kind)


factory = APIRequestFactory()


def _create_assertion(user, provider, field, value, **extra):
    view = ProviderAssertionViewSet.as_view({"post": "create"})
    payload = {"provider": str(provider.uuid), "field": field, "value": value, **extra}
    request = factory.post("/api/assurance/provider-assertions/", payload, format="json")
    force_authenticate(request, user=user)
    return view(request)


def test_admin_can_record_a_graded_assertion_and_authorship_is_captured():
    admin = _user("boss", role=User.Roles.ADMIN)
    provider = _provider()
    resp = _create_assertion(
        admin, provider, ProviderAssertion.Field.DATA_RETENTION, "Zero retention",
        evidence_class=EvidenceClass.CONTRACTUALLY_STATED, source=ProviderAssertion.Source.CONTRACT,
    )
    assert resp.status_code == 201
    a = ProviderAssertion.objects.get()
    assert a.field == "data_retention"
    assert a.value == "Zero retention"
    assert a.evidence_class == EvidenceClass.CONTRACTUALLY_STATED
    assert a.updated_by == admin  # authorship recorded


def test_assertion_write_is_denied_to_non_admin():
    analyst = _user("ana", role=User.Roles.ANALYST)
    provider = _provider()
    resp = _create_assertion(analyst, provider, ProviderAssertion.Field.REGION, "us-east-1")
    assert resp.status_code == 403
    assert ProviderAssertion.objects.count() == 0


def test_one_assertion_per_field_per_provider():
    admin = _user("boss", role=User.Roles.ADMIN)
    provider = _provider()
    assert _create_assertion(admin, provider, ProviderAssertion.Field.REGION, "us-east-1").status_code == 201
    # A second region assertion for the same provider is refused; edit the first.
    dup = _create_assertion(admin, provider, ProviderAssertion.Field.REGION, "eu-west-1")
    assert dup.status_code == 400
    assert ProviderAssertion.objects.filter(provider=provider, field="region").count() == 1


def test_assertion_can_be_edited_in_place_by_an_admin():
    admin = _user("boss", role=User.Roles.ADMIN)
    editor = _user("boss2", role=User.Roles.ADMIN)
    provider = _provider()
    _create_assertion(admin, provider, ProviderAssertion.Field.TRAINS_ON_DATA, "Unknown")
    a = ProviderAssertion.objects.get()

    view = ProviderAssertionViewSet.as_view({"patch": "partial_update"})
    request = factory.patch(
        f"/api/assurance/provider-assertions/{a.uuid}/",
        {"value": "No — opted out", "evidence_class": EvidenceClass.DOCUMENT_SUPPORTED},
        format="json",
    )
    force_authenticate(request, user=editor)
    resp = view(request, uuid=str(a.uuid))
    assert resp.status_code == 200
    a.refresh_from_db()
    assert a.value == "No — opted out"
    assert a.evidence_class == EvidenceClass.DOCUMENT_SUPPORTED
    assert a.updated_by == editor  # last editor recorded


def test_provider_profile_reports_the_weakest_evidence():
    admin = _user("boss", role=User.Roles.ADMIN)
    provider = _provider()
    _create_assertion(
        admin, provider, ProviderAssertion.Field.REGION, "us-east-1",
        evidence_class=EvidenceClass.TECHNICALLY_VERIFIED,
    )
    _create_assertion(
        admin, provider, ProviderAssertion.Field.LOGGING, "Abuse monitoring only",
        evidence_class=EvidenceClass.VENDOR_ASSERTED,
    )

    view = ProviderViewSet.as_view({"get": "retrieve"})
    request = factory.get(f"/api/assurance/providers/{provider.uuid}/")
    force_authenticate(request, user=admin)
    resp = view(request, uuid=str(provider.uuid))
    assert resp.status_code == 200
    assert resp.data["profile"]["declared_fields"] == 2
    # The whole profile is only as strong as its softest claim.
    assert resp.data["profile"]["weakest_evidence"] == EvidenceClass.VENDOR_ASSERTED
    fields = {a["field"] for a in resp.data["assertions"]}
    assert fields == {"region", "logging"}


def test_provider_create_is_admin_only():
    view = ProviderViewSet.as_view({"post": "create"})

    analyst = _user("ana", role=User.Roles.ANALYST)
    denied = factory.post("/api/assurance/providers/", {"name": "Pinecone", "kind": "vector_db"}, format="json")
    force_authenticate(denied, user=analyst)
    assert view(denied).status_code == 403

    admin = _user("boss", role=User.Roles.ADMIN)
    ok = factory.post("/api/assurance/providers/", {"name": "Pinecone", "kind": "vector_db"}, format="json")
    force_authenticate(ok, user=admin)
    assert view(ok).status_code == 201
    assert Provider.objects.filter(name="Pinecone", kind="vector_db").exists()


def test_reads_are_open_to_any_authenticated_operator():
    admin = _user("boss", role=User.Roles.ADMIN)
    provider = _provider()
    _create_assertion(admin, provider, ProviderAssertion.Field.REGION, "us-east-1")

    viewer = _user("viewer", role=User.Roles.VIEWER)
    list_view = ProviderAssertionViewSet.as_view({"get": "list"})
    request = factory.get("/api/assurance/provider-assertions/")
    force_authenticate(request, user=viewer)
    resp = list_view(request)
    assert resp.status_code == 200
    count = resp.data["count"] if isinstance(resp.data, dict) else len(resp.data)
    assert count == 1  # a viewer can read the global provider registry


def test_assertion_delete_is_admin_only():
    admin = _user("boss", role=User.Roles.ADMIN)
    provider = _provider()
    _create_assertion(admin, provider, ProviderAssertion.Field.REGION, "us-east-1")
    a = ProviderAssertion.objects.get()

    delete_view = ProviderAssertionViewSet.as_view({"delete": "destroy"})
    analyst = _user("ana", role=User.Roles.ANALYST)
    denied = factory.delete(f"/api/assurance/provider-assertions/{a.uuid}/")
    force_authenticate(denied, user=analyst)
    assert delete_view(denied, uuid=str(a.uuid)).status_code == 403
    assert ProviderAssertion.objects.filter(pk=a.pk).exists()

    ok = factory.delete(f"/api/assurance/provider-assertions/{a.uuid}/")
    force_authenticate(ok, user=admin)
    assert delete_view(ok, uuid=str(a.uuid)).status_code == 204
    assert not ProviderAssertion.objects.filter(pk=a.pk).exists()
