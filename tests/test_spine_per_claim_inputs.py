"""Per-claim input fingerprints: a change invalidates the claims that rest on it.

Every claim used to bind to ONE deployment-wide system fingerprint, so any change
anywhere invalidated every claim at once. Widening a data boundary staled the
AI-BOM and effective-access claims too, though neither reads the boundary: two
false accusations on every Minotaur run, and a key case (a permission change
staling THIS claim) that sat as a known gap because "a change touched this claim's
inputs" could not be told from "something changed".

Each claim type now binds to a fingerprint of the inputs its deriver reads
(``assurance.fingerprint.CLAIM_INPUTS``). The tests below pin both directions:
a change moves exactly the claims that rest on it, and -- the dangerous direction
-- no change that alters a claim's derived reading can leave that claim's
fingerprint where it was.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from assurance.claims import (
    _derive_ai_bom,
    _derive_data_boundary,
    _derive_effective_access,
    _prefetched,
    derive_claims,
)
from assurance.fingerprint import (
    CLAIM_INPUTS,
    claim_input_fingerprints,
    compute_system_fingerprint,
)
from assurance.invalidation import check_invalidations
from assurance.models import (
    Asset,
    AssuranceClaim,
    DataBoundary,
    DeclaredComponent,
    Deployment,
    EvidenceClass,
    Provider,
    ProviderAssertion,
    RetestRequirement,
)

pytestmark = pytest.mark.django_db

Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType
BOUNDARY, ACCESS, BOM = (
    ClaimType.DATA_BOUNDARY.value,
    ClaimType.EFFECTIVE_ACCESS.value,
    ClaimType.AI_BOM.value,
)
_DERIVERS = {
    BOUNDARY: _derive_data_boundary,
    ACCESS: _derive_effective_access,
    BOM: _derive_ai_bom,
}
# What a claim SAYS, as the reader sees it -- everything the deriver computes from
# its inputs. `assessment` (the deployment's decision) and the statement (which
# names the deployment) are not inputs to the reading.
_READING = ("status", "evidence_class", "vendor_asserted", "supporting_summary", "contradicting_summary")


def _deployment():
    """A deployment every assessor has something to read in: a provider-backed
    model, an agent with an identity and a tool, a tool with permissions and a
    backend, an approved boundary, and a declared architecture that matches."""
    owner = get_user_model().objects.create_user(username="o", password="x")
    dep = Deployment.objects.create(name="d", owner=owner)
    provider = Provider.objects.create(name="openai", kind=Provider.Kind.MODEL_PROVIDER, region="eu-west-1")
    for field, value in (("region", "eu-west-1"), ("trains_on_data", "No"), ("subprocessors", "None")):
        ProviderAssertion.objects.create(
            provider=provider, field=field, value=value,
            evidence_class=EvidenceClass.CONFIGURATION_VERIFIED,
        )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.MODEL, name="gpt", identifier="gpt",
        provider=provider, classification=Asset.Classification.KNOWN,
        metadata={"model": "gpt-4o", "region": "eu-west-1"},
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.AGENT, name="agent", identifier="agent",
        classification=Asset.Classification.KNOWN,
        metadata={"tools": ["reader"], "identity": "svc-agent"},
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="reader", identifier="reader",
        classification=Asset.Classification.KNOWN,
        metadata={"permissions": ["data_read"], "server": "warehouse"},
    )
    DataBoundary.objects.create(
        deployment=dep, allowed_regions=["eu-west-1"],
        training_allowed=False, third_party_sharing_allowed=False,
    )
    for kind, name in ((Asset.Kind.MODEL, "gpt"), (Asset.Kind.AGENT, "agent"), (Asset.Kind.TOOL, "reader")):
        DeclaredComponent.objects.create(deployment=dep, kind=kind, name=name, identifier=name)
    return dep


def _asset(dep, name):
    return Asset.objects.get(deployment=dep, name=name)


def _widen_boundary(dep):
    boundary = DataBoundary.objects.get(deployment=dep)
    boundary.allowed_regions = ["eu-west-1", "eu-central-1"]
    boundary.save(update_fields=["allowed_regions"])


def _grant_permission(dep):
    tool = _asset(dep, "reader")
    tool.metadata = {**tool.metadata, "permissions": ["data_read", "code_execution"]}
    tool.save(update_fields=["metadata"])


def _move_provider_region(dep):
    assertion = ProviderAssertion.objects.get(provider__name="openai", field="region")
    assertion.value = "us-east-1"
    assertion.save(update_fields=["value"])


def _downgrade_evidence(dep):
    assertion = ProviderAssertion.objects.get(provider__name="openai", field="trains_on_data")
    assertion.evidence_class = EvidenceClass.VENDOR_ASSERTED
    assertion.save(update_fields=["evidence_class"])


def _add_tool_reference(dep):
    agent = _asset(dep, "agent")
    agent.metadata = {**agent.metadata, "tools": ["reader", "shell"]}
    agent.save(update_fields=["metadata"])


def _move_tool_backend(dep):
    tool = _asset(dep, "reader")
    tool.metadata = {**tool.metadata, "server": "public-bucket"}
    tool.save(update_fields=["metadata"])


def _drop_identity(dep):
    agent = _asset(dep, "agent")
    agent.metadata = {k: v for k, v in agent.metadata.items() if k != "identity"}
    agent.save(update_fields=["metadata"])


def _upgrade_model(dep):
    model = _asset(dep, "gpt")
    model.metadata = {**model.metadata, "model": "gpt-5"}
    model.save(update_fields=["metadata"])


def _unmanage_tool(dep):
    tool = _asset(dep, "reader")
    tool.classification = Asset.Classification.UNMANAGED
    tool.save(update_fields=["classification"])


def _undeclare_tool(dep):
    DeclaredComponent.objects.filter(deployment=dep, name="reader").delete()


def _declare_extra(dep):
    DeclaredComponent.objects.create(deployment=dep, kind=Asset.Kind.MODEL, name="claude", identifier="claude")


def _move_environment(dep):
    # PRODUCTION is the default, so a move to it would be no change at all.
    dep.environment = Deployment.Environment.STAGING
    dep.save(update_fields=["environment"])


def _add_component(dep):
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.VECTOR_DB, name="pinecone", identifier="pinecone",
        classification=Asset.Classification.KNOWN,
    )


_MUTATIONS = [
    _widen_boundary,
    _grant_permission,
    _move_provider_region,
    _downgrade_evidence,
    _add_tool_reference,
    _move_tool_backend,
    _drop_identity,
    _upgrade_model,
    _unmanage_tool,
    _undeclare_tool,
    _declare_extra,
    _move_environment,
    _add_component,
]


def _readings(dep):
    fresh = _prefetched(dep)
    return {t: {k: derive(fresh)[k] for k in _READING} for t, derive in _DERIVERS.items()}


def _fps(dep):
    return claim_input_fingerprints(_prefetched(dep))


# --------------------------------------------------------------- soundness


@pytest.mark.parametrize("mutate", _MUTATIONS, ids=lambda f: f.__name__.lstrip("_"))
def test_no_change_to_a_claims_reading_leaves_its_fingerprint_where_it_was(mutate):
    """The dangerous direction. A family missing from a claim's inputs is a change
    that claim would not notice: it would keep reading as current over a state it
    was never true of. So for every mutation, any claim whose DERIVED reading moved
    must have had its input fingerprint move too."""
    dep = _deployment()
    readings_before, fps_before = _readings(dep), _fps(dep)
    mutate(dep)
    readings_after, fps_after = _readings(dep), _fps(dep)

    for claim_type in _DERIVERS:
        if readings_before[claim_type] != readings_after[claim_type]:
            assert fps_before[claim_type] != fps_after[claim_type], (
                f"{mutate.__name__} changed what the {claim_type} claim says "
                f"({readings_before[claim_type]} -> {readings_after[claim_type]}) and left its "
                "input fingerprint unchanged, so the claim would not be invalidated"
            )
    # And every mutation is a change to SOMETHING a claim rests on, or it is not
    # testing a family at all.
    assert fps_before != fps_after, f"{mutate.__name__} moved no claim's inputs"


def test_every_mapped_claim_type_is_a_real_claim_type():
    assert set(CLAIM_INPUTS) == {c.value for c in ClaimType}


# --------------------------------------------------------------- precision


@pytest.mark.parametrize(
    ("mutate", "moved"),
    [
        (_widen_boundary, {BOUNDARY}),
        (_grant_permission, {ACCESS}),
        (_add_tool_reference, {ACCESS}),
        (_drop_identity, {ACCESS}),
        (_upgrade_model, {BOM}),
        (_undeclare_tool, {BOM}),
        (_move_provider_region, {BOUNDARY, BOM}),
        (_add_component, {BOUNDARY, ACCESS, BOM}),
        (_move_environment, {BOUNDARY, ACCESS, BOM}),
    ],
    ids=lambda v: v.__name__.lstrip("_") if callable(v) else "+".join(sorted(v)),
)
def test_a_change_moves_exactly_the_claims_that_rest_on_it(mutate, moved):
    dep = _deployment()
    before = _fps(dep)
    mutate(dep)
    after = _fps(dep)
    assert {t for t in before if before[t] != after[t]} == moved


def test_widening_the_boundary_stales_only_the_boundary_claim():
    """The co-invalidation Minotaur measured. legacy-bot's boundary gained a region;
    its AI-BOM and effective-access claims were staled with it and published as
    accusations, though neither reads the boundary."""
    dep = _deployment()
    derive_claims(dep)
    system_before = compute_system_fingerprint(_prefetched(dep))

    _widen_boundary(dep)
    counts = check_invalidations(dep)

    # Re-read, not the in-memory object: its cached boundary predates the change.
    assert compute_system_fingerprint(_prefetched(dep)) != system_before, "the system did change"
    assert counts["invalidated"] == 1
    assert counts["retests_opened"] == 1
    current = {c.claim_type: c for c in AssuranceClaim.objects.filter(deployment=dep).current()}
    assert current[BOUNDARY].status == Status.STALE
    assert current[BOM].status != Status.STALE
    assert current[ACCESS].status != Status.STALE
    req = RetestRequirement.objects.get(deployment=dep)
    assert req.claim.claim_type == BOUNDARY
    assert "boundary" in req.reason


def test_a_permission_change_stales_only_the_access_claim():
    """The key's `claim.effective_access_stale` case: a permission change moved a
    VERIFIED EFFECTIVE_ACCESS claim to STALE -- and nothing else."""
    dep = _deployment()
    derive_claims(dep)
    _grant_permission(dep)
    check_invalidations(dep)

    stale = {
        c.claim_type
        for c in AssuranceClaim.objects.filter(deployment=dep).current()
        if c.status == Status.STALE
    }
    assert stale == {ACCESS}


def test_a_re_derive_supersedes_only_the_claim_whose_inputs_moved_and_resolves_its_retest():
    dep = _deployment()
    derive_claims(dep)
    _widen_boundary(dep)
    check_invalidations(dep)
    req = RetestRequirement.objects.get(deployment=dep)

    counts = derive_claims(dep)

    assert counts["superseded"] == 1
    assert counts["created"] == 0
    req.refresh_from_db()
    assert req.resolved_at is not None
    assert req.resolving_claim.claim_type == BOUNDARY
    # The two claims the change did not touch were never versioned.
    for claim_type in (BOM, ACCESS):
        assert AssuranceClaim.objects.filter(deployment=dep, claim_type=claim_type).count() == 1


# --------------------------------------------------------------- legacy rows


def test_a_row_bound_before_per_claim_fingerprints_is_compared_on_the_whole_system():
    """A blank input fingerprint is the conservative reading, never a free pass: the
    row was bound to the whole system, so any change to it invalidates the row."""
    dep = _deployment()
    derive_claims(dep)
    AssuranceClaim.objects.filter(deployment=dep).update(input_fingerprint="")

    _widen_boundary(dep)
    counts = check_invalidations(dep)

    assert counts["invalidated"] == 3


def test_a_legacy_row_whose_system_still_holds_is_bound_to_its_inputs_on_re_derive():
    dep = _deployment()
    derive_claims(dep)
    AssuranceClaim.objects.filter(deployment=dep).update(input_fingerprint="")

    counts = derive_claims(dep)

    assert counts["superseded"] == 0
    fps = _fps(dep)
    for claim in AssuranceClaim.objects.filter(deployment=dep).current():
        assert claim.input_fingerprint == fps[claim.claim_type]
