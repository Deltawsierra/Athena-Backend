"""Athena — the assurance list endpoints stay query-bounded (no N+1).

Proves the findings and unknowns lists issue a fixed number of queries
regardless of how many rows they return: the serializers read deployment / asset
/ owner FKs, which must be select_related on the viewset. Before the fix these
were fetched per row (~2 queries each), so the count grew with the result set.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.models import Asset, Deployment, Finding, Unknown
from assurance.views import FindingViewSet, UnknownViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


def _admin():
    return User.objects.create_user(username="boss", password="x", role=User.Roles.ADMIN)


def _rows(data):
    """The row list, whether or not DRF pagination wraps it in {results: [...]}."""
    if isinstance(data, dict) and "results" in data:
        return data["results"]
    return data


def _finding_with_asset_and_owner(dep, i):
    owner = User.objects.create_user(username=f"owner{i}", password="x")
    asset = Asset.objects.create(
        deployment=dep, kind=Asset.Kind.MODEL, classification=Asset.Classification.KNOWN,
        name=f"asset{i}", identifier=f"asset{i}",
    )
    return Finding.objects.create(
        deployment=dep, fingerprint=f"fp{i}", finding_type="t", title="T",
        severity="high", status=Finding.Status.OPEN, owner=owner, asset=asset,
    )


def test_findings_list_is_query_bounded(django_assert_max_num_queries):
    admin = _admin()
    dep = Deployment.objects.create(name="d", owner=admin)
    # Eight findings, each with its OWN asset and owner — an N+1 would add ~2
    # queries per finding (~16), blowing past this fixed bound.
    for i in range(8):
        _finding_with_asset_and_owner(dep, i)

    factory = APIRequestFactory()
    view = FindingViewSet.as_view({"get": "list"})
    req = factory.get("/api/assurance/findings/")
    force_authenticate(req, user=admin)
    with django_assert_max_num_queries(12):
        resp = view(req)
        assert resp.status_code == 200
        # Force full serialization (DRF is lazy until the data is read).
        assert len(_rows(resp.data)) == 8


def test_unknowns_list_is_query_bounded(django_assert_max_num_queries):
    admin = _admin()
    dep = Deployment.objects.create(name="d", owner=admin)
    for i in range(8):
        owner = User.objects.create_user(username=f"u{i}", password="x")
        Unknown.objects.create(
            deployment=dep, fingerprint=f"ufp{i}", question=f"q{i}",
            deployment_impact="high", status=Unknown.Status.OPEN, owner=owner,
        )

    factory = APIRequestFactory()
    view = UnknownViewSet.as_view({"get": "list"})
    req = factory.get("/api/assurance/unknowns/")
    force_authenticate(req, user=admin)
    with django_assert_max_num_queries(10):
        resp = view(req)
        assert resp.status_code == 200
        assert len(_rows(resp.data)) == 8
