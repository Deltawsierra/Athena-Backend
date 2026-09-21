"""The Unknowns Register's second source: postures nobody declared.

The register began as a projection of findings, which quietly made it useless for
the deployment that most needs it. A provider nobody has documented produces no
scan output, so it produces no finding, so a findings-only register reports zero
gaps for the system nothing is known about — the exact silent zero the evidence
discipline exists to prevent. A customer reading that page would see an empty
Unknowns list and conclude there was nothing to ask.

The data-boundary assessment already knew better: it has always reported, per
data flow, the postures it could not assess. What it could not do was make anyone
own one. These tests prove those gaps are now managed rows with an impact grade,
an owner, and a review date — and, just as importantly, that they behave like
every other Unknown: idempotent, never clobbering a human's disposition, and
auto-resolving the moment the posture is declared.
"""

from __future__ import annotations

import pytest

from assurance.models import (
    Asset,
    DataBoundary,
    Deployment,
    EvidenceClass,
    Provider,
    ProviderAssertion,
    Unknown,
)
from assurance.unknowns import derive_unknowns

pytestmark = pytest.mark.django_db


def _provider(name="OpenAI", **assertions):
    provider = Provider.objects.create(name=name, kind=Provider.Kind.MODEL_PROVIDER)
    for field, value in assertions.items():
        ProviderAssertion.objects.create(
            provider=provider,
            field=field,
            value=value,
            evidence_class=EvidenceClass.VENDOR_ASSERTED,
        )
    return provider


def _deployment(*providers, name="payments-agent", boundary=None):
    """A deployment reaching each provider through one model asset."""
    deployment = Deployment.objects.create(name=name)
    for index, provider in enumerate(providers):
        Asset.objects.create(
            deployment=deployment,
            provider=provider,
            kind=Asset.Kind.MODEL,
            classification=Asset.Classification.KNOWN,
            name=f"model-{index}",
            identifier=f"model-{index}",
        )
    if boundary is not None:
        DataBoundary.objects.create(deployment=deployment, **boundary)
    return deployment


def _subjects(deployment):
    return sorted(
        deployment.unknowns.filter(
            source=Unknown.Source.POSTURE, status=Unknown.Status.OPEN
        ).values_list("subject", flat=True)
    )


# ------------------------------------------------------- the gap becomes a row


def test_an_undeclared_training_posture_becomes_a_managed_unknown():
    """The case a findings-only register scored as zero."""
    deployment = _deployment(
        _provider(region="eu-west-1", subprocessors="None"),
        boundary={"allowed_regions": ["eu-west-1"]},
    )

    open_unknowns = derive_unknowns(deployment)

    assert deployment.findings.count() == 0, "the fixture must have no findings at all"
    assert [u.subject for u in open_unknowns] == ["training-posture"]
    gap = open_unknowns[0]
    assert gap.source == Unknown.Source.POSTURE
    assert gap.finding is None
    assert gap.deployment_impact == Unknown.Impact.HIGH
    assert gap.question and gap.why_it_matters and gap.evidence_needed


def test_a_deployment_with_no_declared_posture_at_all_raises_every_gap():
    deployment = _deployment(_provider(), boundary={"allowed_regions": ["eu-west-1"]})

    derive_unknowns(deployment)

    assert _subjects(deployment) == ["region-posture", "sharing-posture", "training-posture"]


def test_an_unapproved_boundary_is_itself_the_gap():
    """No boundary means nothing was assessed — not that everything passed."""
    deployment = _deployment(_provider(region="eu-west-1"))  # no DataBoundary

    derive_unknowns(deployment)

    subjects = _subjects(deployment)
    assert "data-boundary" in subjects
    gap = deployment.unknowns.get(subject="data-boundary")
    assert gap.deployment_impact == Unknown.Impact.HIGH
    # With no approved boundary there is nothing to measure the individual
    # postures against, so the assessment reports the one gap that matters and
    # the register must not invent three more beside it.
    assert subjects == ["data-boundary"]


def test_a_declared_posture_raises_no_gap():
    deployment = _deployment(
        _provider(region="eu-west-1", trains_on_data="No", subprocessors="None"),
        boundary={"allowed_regions": ["eu-west-1"]},
    )

    assert derive_unknowns(deployment) == []
    assert deployment.unknowns.count() == 0


def test_a_deployment_reaching_no_provider_has_no_posture_gaps():
    """Nothing flows anywhere, so there is nothing to be unknown about."""
    deployment = _deployment(boundary={"allowed_regions": ["eu-west-1"]})

    assert derive_unknowns(deployment) == []


# --------------------------------------------------- one question, many vendors


def test_the_same_gap_across_providers_is_one_question_naming_both():
    """The register tracks what the *deployment* cannot answer."""
    deployment = _deployment(
        _provider(name="OpenAI", region="eu-west-1", subprocessors="None"),
        _provider(name="Pinecone", region="eu-west-1", subprocessors="None"),
        boundary={"allowed_regions": ["eu-west-1"]},
    )

    derive_unknowns(deployment)

    gaps = deployment.unknowns.filter(subject="training-posture")
    assert gaps.count() == 1, "two silent vendors are still one unanswered question"
    # Grouping must not lose which vendors are silent, or the gap is unworkable.
    assert "OpenAI" in gaps[0].why_it_matters
    assert "Pinecone" in gaps[0].why_it_matters


# ------------------------------------------------- idempotence and disposition


def test_re_deriving_updates_the_same_row_rather_than_duplicating_it():
    deployment = _deployment(_provider(), boundary={"allowed_regions": ["eu-west-1"]})

    derive_unknowns(deployment)
    first = list(deployment.unknowns.values_list("uuid", flat=True))
    derive_unknowns(deployment)

    assert list(deployment.unknowns.values_list("uuid", flat=True)) == first


def test_a_re_derive_never_clobbers_human_set_disposition():
    deployment = _deployment(_provider(), boundary={"allowed_regions": ["eu-west-1"]})
    derive_unknowns(deployment)

    gap = deployment.unknowns.get(subject="training-posture")
    gap.status = Unknown.Status.INVESTIGATING
    gap.notes = "asked the vendor on the 3rd"
    gap.deployment_impact = Unknown.Impact.LOW
    gap.save()

    derive_unknowns(deployment)

    gap.refresh_from_db()
    assert gap.status == Unknown.Status.INVESTIGATING
    assert gap.notes == "asked the vendor on the 3rd"


def test_declaring_the_posture_auto_resolves_the_gap():
    provider = _provider(region="eu-west-1", subprocessors="None")
    deployment = _deployment(provider, boundary={"allowed_regions": ["eu-west-1"]})
    derive_unknowns(deployment)
    assert _subjects(deployment) == ["training-posture"]

    ProviderAssertion.objects.create(
        provider=provider,
        field=ProviderAssertion.Field.TRAINS_ON_DATA,
        value="No — zero-retention endpoint",
        evidence_class=EvidenceClass.CONTRACTUALLY_STATED,
    )
    derive_unknowns(deployment)

    gap = deployment.unknowns.get(subject="training-posture")
    assert gap.status == Unknown.Status.RESOLVED
    assert gap.auto_resolved is True


def test_a_posture_gap_that_comes_back_re_opens():
    provider = _provider(region="eu-west-1", subprocessors="None")
    deployment = _deployment(provider, boundary={"allowed_regions": ["eu-west-1"]})
    declared = ProviderAssertion.objects.create(
        provider=provider,
        field=ProviderAssertion.Field.TRAINS_ON_DATA,
        value="No",
        evidence_class=EvidenceClass.VENDOR_ASSERTED,
    )
    derive_unknowns(deployment)
    assert _subjects(deployment) == []

    declared.delete()
    derive_unknowns(deployment)

    gap = deployment.unknowns.get(subject="training-posture")
    assert gap.status == Unknown.Status.OPEN
    assert gap.auto_resolved is False


def test_a_human_resolution_survives_the_gap_still_being_open():
    """A human who accepted the residual risk is not overruled by a re-derive."""
    deployment = _deployment(_provider(), boundary={"allowed_regions": ["eu-west-1"]})
    derive_unknowns(deployment)

    gap = deployment.unknowns.get(subject="training-posture")
    gap.status = Unknown.Status.ACCEPTED
    gap.save()

    derive_unknowns(deployment)

    gap.refresh_from_db()
    assert gap.status == Unknown.Status.ACCEPTED
    assert gap.auto_resolved is False


# ----------------------------------------------- the two sources side by side


def test_the_two_sources_do_not_auto_resolve_each_other():
    """Both passes share one live set, or the register flaps on every ingest.

    Each source knows only its own fingerprints. Sweeping for stale rows after
    each pass separately would mean the findings pass resolves every posture gap
    and the posture pass resolves every finding gap, so a deployment with both
    would show half its register closing and re-opening on alternate derives
    while nothing about it had changed.
    """
    from assurance.models import Evidence, Finding

    deployment = _deployment(_provider(), boundary={"allowed_regions": ["eu-west-1"]})
    finding = Finding.objects.create(
        deployment=deployment,
        fingerprint="fp-coexist",
        finding_type="prompt_injection",
        title="Prompt injection may be possible",
        severity="high",
    )
    Evidence.objects.create(
        finding=finding, classification=EvidenceClass.UNKNOWN, source="engine_scan"
    )

    for _ in range(2):
        derive_unknowns(deployment)
        open_rows = deployment.unknowns.filter(status=Unknown.Status.OPEN)
        assert sorted(open_rows.values_list("subject", flat=True)) == [
            "prompt-injection",
            "region-posture",
            "sharing-posture",
            "training-posture",
        ]
        assert not deployment.unknowns.filter(auto_resolved=True).exists()


def test_a_finding_derived_gap_keeps_its_original_fingerprint():
    """Changing that key would orphan every row already in the register.

    A derived Unknown is matched by ``sha256("finding:<pk>")``. If the deriver
    ever hashed something else, every existing gap would fail to match, be
    auto-resolved as stale, and be re-created empty — losing the owner, the
    review date and the notes a human put on it. Pin the key.
    """
    import hashlib

    from assurance.models import Evidence, Finding

    deployment = _deployment()
    finding = Finding.objects.create(
        deployment=deployment,
        fingerprint="fp-pin",
        finding_type="prompt_injection",
        title="Unconfirmed",
        severity="medium",
    )
    Evidence.objects.create(
        finding=finding, classification=EvidenceClass.UNKNOWN, source="engine_scan"
    )
    derive_unknowns(deployment)

    gap = deployment.unknowns.get()
    expected = hashlib.sha256(f"finding:{finding.pk}".encode("utf-8")).hexdigest()
    assert gap.fingerprint == expected
    # The subject is the readable half of the same identity, and it names the
    # kind of thing left unconfirmed rather than the row it came from.
    assert gap.subject == "prompt-injection"


def test_posture_and_finding_fingerprints_cannot_collide():
    """Namespacing is what keeps a finding's pk from ever meaning a posture."""
    from assurance.unknowns import _posture_fingerprint

    codes = ["boundary_undeclared", "region_undeclared", "training_undeclared", "sharing_undeclared"]
    assert len({_posture_fingerprint(c) for c in codes}) == len(codes)


# --------------------------------------------------------------- query budget


def test_deriving_posture_gaps_is_query_bounded(django_assert_max_num_queries):
    """Cost must not grow with the number of providers a deployment reaches.

    The assessment prefetches assets → provider → assertions, so ten vendors cost
    the same handful of queries as one. Without that, a real customer's
    deployment would issue a query per provider per derive, on every ingest.
    """
    providers = [_provider(name=f"vendor-{i}") for i in range(10)]
    deployment = _deployment(*providers, boundary={"allowed_regions": ["eu-west-1"]})

    # Warm the register so the run under measurement is an update, not a create:
    # a steady-state re-derive is what ingestion actually does most of the time.
    derive_unknowns(deployment)

    with django_assert_max_num_queries(20):
        derive_unknowns(deployment)
