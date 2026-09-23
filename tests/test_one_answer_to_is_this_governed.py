"""Every reader of the asset graph must give the same answer to "is this governed?".

Three predicates did not, and they disagreed about half the vocabulary:

=================  =========  =====  =========  =======  =========  =======
predicate          approved   known  unmanaged  unknown  high_risk  retired
=================  =========  =====  =========  =======  =========  =======
``_MANAGED``       governed   gov.   SHADOW     SHADOW   SHADOW     SHADOW
``== UNMANAGED``   governed   gov.   SHADOW     gov.     gov.       gov.
``{UNMANAGED,      governed   gov.   SHADOW     SHADOW   gov.       gov.
  UNKNOWN}``
=================  =========  =====  =========  =======  =========  =======

The measured consequence that matters most: a deployment whose entire inventory
is one asset a person flagged **high risk** reported posture ``baseline`` -- the
best band there is. No deriver ever writes ``high_risk`` or ``retired``; only a
person does. So the one case the headline could not see was the case where
somebody had looked at a component and said, explicitly, that it is dangerous.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from assurance import bom, boundary, roi, route
from assurance.governance import GOVERNED, SHADOW, is_governed, is_shadow
from assurance.models import Asset, DataBoundary, Deployment

pytestmark = pytest.mark.django_db

User = get_user_model()
C = Asset.Classification


def _dep(name="d"):
    owner = User.objects.create_user(username=f"{name}-owner", password="x", role=User.Roles.ANALYST)
    return Deployment.objects.create(name=name, owner=owner)


def _asset(dep, classification, *, name=None, kind=Asset.Kind.DATA_STORE, metadata=None):
    ident = name or f"store-{classification}"
    return Asset.objects.create(
        deployment=dep, kind=kind, identifier=ident, name=ident,
        classification=classification, metadata=metadata or {},
    )


# ---- the vocabulary itself -------------------------------------------------


def test_governed_and_shadow_partition_the_whole_enum():
    """Derived, not listed. A seventh classification added to the model cannot
    end up in neither set, or -- worse -- in both."""
    assert GOVERNED | SHADOW == set(C.values)
    assert not (GOVERNED & SHADOW)
    assert GOVERNED == {C.APPROVED, C.KNOWN}


@pytest.mark.parametrize("classification", [C.APPROVED, C.KNOWN])
def test_the_two_governed_classifications(classification):
    assert is_governed(classification)
    assert not is_shadow(classification)


@pytest.mark.parametrize("classification", [C.UNMANAGED, C.UNKNOWN, C.HIGH_RISK, C.RETIRED])
def test_everything_else_is_shadow(classification):
    """`high_risk` and `retired` are the two the `== UNMANAGED` readings called
    governed, and they are the two only a human ever sets."""
    assert is_shadow(classification)
    assert not is_governed(classification)


@pytest.mark.parametrize("value", ["", None, "something_added_later", 0])
def test_an_unrecognised_classification_fails_safe(value):
    """The old `== UNMANAGED` checks read anything they did not recognise as
    GOVERNED -- a blank from an import, a migration, a seventh enum member -- so
    the one input that says "we do not know" produced the answer that
    under-reports risk, silently. It goes the other way now."""
    assert is_shadow(value)
    assert not is_governed(value)


# ---- the readers agree -----------------------------------------------------


@pytest.mark.parametrize("classification", [C.HIGH_RISK, C.RETIRED, C.UNKNOWN])
def test_every_reader_calls_the_same_asset_shadow(classification):
    """The disagreement, as one deployment. `route`, `bom` and `boundary` used
    `== UNMANAGED` and said "governed"; `capability` used `_MANAGED` and said
    "shadow". Same row, same moment, opposite answers in two reports."""
    dep = _dep(f"agree-{classification}")
    DataBoundary.objects.create(deployment=dep)
    asset = _asset(dep, classification)

    node = next(n for n in route.build_route_map(dep)["nodes"] if n["uuid"] == str(asset.uuid))
    assert node["shadow"] is True, "the system map calls it governed"

    component = next(c for c in bom.build_ai_bom(dep)["components"] if c["uuid"] == str(asset.uuid))
    assert component["shadow"] is True, "the AI-BOM calls it governed"

    assert boundary.assess_boundary(dep)["summary"]["shadow_destinations"] == 1, (
        "the data boundary calls it a governed destination"
    )


def test_a_governed_asset_is_governed_to_every_reader():
    """The negative control. "They all agree" must not be satisfiable by all of
    them calling everything shadow."""
    dep = _dep("clean")
    DataBoundary.objects.create(deployment=dep)
    asset = _asset(dep, C.KNOWN)

    node = next(n for n in route.build_route_map(dep)["nodes"] if n["uuid"] == str(asset.uuid))
    assert node["shadow"] is False
    component = next(c for c in bom.build_ai_bom(dep)["components"] if c["uuid"] == str(asset.uuid))
    assert component["shadow"] is False
    assert boundary.assess_boundary(dep)["summary"]["shadow_destinations"] == 0


# ---- the consequence that mattered most ------------------------------------


@pytest.mark.parametrize("classification", [C.HIGH_RISK, C.RETIRED])
def test_a_flagged_component_is_not_reported_as_a_baseline_posture(classification):
    """A deployment whose entire inventory is one component a person flagged
    high-risk reported posture `baseline` -- the best band -- because the rule
    counted only `unmanaged`, while the capability map on the same deployment
    reported one shadow capability.

    Nothing in the platform derives `high_risk` or `retired`; every derived
    classification is APPROVED, KNOWN or UNMANAGED. So this was exactly the case
    where a human had looked at a component and said it is dangerous, and the
    headline could not see it."""
    dep = _dep(f"posture-{classification}")
    _asset(dep, classification)

    summary = roi.build_executive_summary(dep)

    assert summary["asset_coverage"]["shadow"] == 1
    assert summary["posture"] != "baseline", (
        f"a lone {classification} component reported the best posture band"
    )


def test_a_governed_inventory_still_reports_baseline():
    """The negative control for the posture rule: raising it on everything is
    not the fix."""
    dep = _dep("baseline")
    _asset(dep, C.APPROVED)
    _asset(dep, C.KNOWN, name="second")

    summary = roi.build_executive_summary(dep)

    assert summary["asset_coverage"]["shadow"] == 0
    assert summary["posture"] == "baseline"


def test_one_summary_does_not_report_two_shadow_counts():
    """The executive summary is a single dict handed to one dashboard. Over six
    assets, four of them ungoverned by any reading, it said "1 shadow asset" in
    the headline while the vendor report on the same deployment said "4
    ungoverned dependencies"."""
    dep = _dep("counts")
    for classification in C.values:
        _asset(dep, classification)

    summary = roi.build_executive_summary(dep)

    assert summary["asset_coverage"]["shadow"] == 4
    assert summary["asset_coverage"]["managed"] == 2
    # And the system map, which used the other predicate, now agrees with it.
    assert summary["asset_coverage"]["shadow"] == route.build_route_map(dep)["summary"]["shadow_nodes"]


# ---- coverage is a different axis, and stays one ---------------------------


def test_classified_and_governed_stay_two_questions():
    """`high_risk` is classified -- somebody looked at it -- and ungoverned:
    what they said was bad. Collapsing the two axes is how three predicates
    became three answers, so this pins that they stay apart."""
    dep = _dep("axes")
    _asset(dep, C.HIGH_RISK)
    _asset(dep, C.UNKNOWN, name="nobody-looked")

    coverage = roi.build_executive_summary(dep)["asset_coverage"]

    assert coverage["classified"] == 1, "the high-risk asset IS classified"
    assert coverage["managed"] == 0, "and neither asset is governed"
