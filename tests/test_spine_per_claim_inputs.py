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
from datetime import timedelta
from types import SimpleNamespace

from assurance.access import assess_effective_access
from assurance.fingerprint import (
    CLAIM_INPUTS,
    _families,
    claim_input_fingerprints,
    claim_state_moved,
    compute_system_fingerprint,
)
from assurance.graph_refs import UNRESOLVED_AMBIGUOUS
from assurance.invalidation import check_invalidations, resolve_satisfied_requirements
from assurance.route import build_route_map
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


def _asset_by_identifier(dep, identifier):
    return Asset.objects.get(deployment=dep, identifier=identifier)


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


def _malform_tools(dep):
    # An empty string is not "no tools": the access graph reports it as a
    # malformed declaration. A descriptor that dropped falsy values could not see it.
    agent = _asset(dep, "agent")
    agent.metadata = {**agent.metadata, "tools": ""}
    agent.save(update_fields=["metadata"])


def _rename_deployment(dep):
    # The effective-access graph names its base principal after the deployment.
    dep.name = "renamed"
    dep.save(update_fields=["name"])


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
    _malform_tools,
    _rename_deployment,
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
        (_malform_tools, {ACCESS}),
        (_rename_deployment, {ACCESS}),
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


def test_a_legacy_row_whose_inputs_the_system_covers_is_bound_to_them_on_re_derive():
    """Only the boundary claim reads nothing outside the system fingerprint, so only
    its legacy row can be shown unchanged and bound in place. The AI-BOM reads the
    declared architecture and the access graph reads the deployment's name, neither
    of which the system fingerprint carries: their legacy rows cannot be shown
    unchanged, and are versioned rather than trusted."""
    dep = _deployment()
    derive_claims(dep)
    AssuranceClaim.objects.filter(deployment=dep).update(input_fingerprint="")

    counts = derive_claims(dep)

    assert counts["superseded"] == 2
    fps = _fps(dep)
    for claim in AssuranceClaim.objects.filter(deployment=dep).current():
        assert claim.input_fingerprint == fps[claim.claim_type]
    assert AssuranceClaim.objects.filter(deployment=dep, claim_type=BOUNDARY).count() == 1


def test_a_legacy_bom_row_is_invalidated_by_a_change_the_system_fingerprint_cannot_see():
    """The system fingerprint deliberately leaves out the declared architecture, and
    the AI-BOM reads it. Comparing a legacy AI-BOM row on the system fingerprint was
    weaker than the per-claim check it stood in for, not stricter."""
    dep = _deployment()
    derive_claims(dep)
    AssuranceClaim.objects.filter(deployment=dep).update(input_fingerprint="")
    system_before = compute_system_fingerprint(_prefetched(dep))

    _undeclare_tool(dep)
    assert compute_system_fingerprint(_prefetched(dep)) == system_before, "the premise"
    check_invalidations(dep)

    bom = AssuranceClaim.objects.filter(deployment=dep, claim_type=BOM).current().get()
    assert bom.status == Status.STALE
    assert RetestRequirement.objects.filter(claim=bom, resolved_at__isnull=True).exists()


def test_a_legacy_row_whose_reading_moved_is_versioned_not_rewritten():
    """A legacy row is bound in place only if it already reads what the deriver reads
    now. Otherwise binding it would rewrite the old version's verdict under it."""
    dep = _deployment()
    derive_claims(dep)
    AssuranceClaim.objects.filter(deployment=dep, claim_type=BOUNDARY).update(
        input_fingerprint="", contradicting_summary="a reading this state does not produce"
    )

    derive_claims(dep)

    versions = AssuranceClaim.objects.filter(deployment=dep, claim_type=BOUNDARY)
    assert versions.count() == 2
    assert versions.filter(status=Status.SUPERSEDED).count() == 1


# --------------------------------------------------------------- what an adversary found


def _add_same_named_vector_store(dep):
    """A second provider called "openai" -- a vector store, not the model provider.
    ``Provider`` is unique on (name, kind), so this is a different provider."""
    store = Provider.objects.create(name="openai", kind=Provider.Kind.VECTOR_DB, region="eu-west-1")
    for field, value in (("region", "eu-west-1"), ("trains_on_data", "No"), ("subprocessors", "None")):
        ProviderAssertion.objects.create(
            provider=store, field=field, value=value,
            evidence_class=EvidenceClass.CONFIGURATION_VERIFIED,
        )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.VECTOR_DB, name="vectors", identifier="vectors",
        provider=store, classification=Asset.Classification.KNOWN,
    )
    DeclaredComponent.objects.create(deployment=dep, kind=Asset.Kind.VECTOR_DB, name="vectors", identifier="vectors")
    return store


def test_a_second_provider_with_the_same_name_is_not_invisible():
    """Providers were described once per NAME, so a vector store called "openai"
    was folded into the model provider called "openai". It could start training on
    customer data, the boundary claim would read CONTRADICTED, and no fingerprint --
    per claim or system -- moved."""
    dep = _deployment()
    store = _add_same_named_vector_store(dep)
    readings_before, fps_before = _readings(dep), _fps(dep)
    system_before = compute_system_fingerprint(_prefetched(dep))

    assertion = ProviderAssertion.objects.get(provider=store, field="trains_on_data")
    assertion.value = "Yes - trains on customer data"
    assertion.evidence_class = EvidenceClass.VENDOR_ASSERTED
    assertion.save(update_fields=["value", "evidence_class"])

    readings_after, fps_after = _readings(dep), _fps(dep)
    assert readings_before[BOUNDARY] != readings_after[BOUNDARY], "the premise: the boundary reading moved"
    assert fps_before[BOUNDARY] != fps_after[BOUNDARY]
    assert fps_before[BOM] != fps_after[BOM]
    assert fps_before[ACCESS] == fps_after[ACCESS]
    assert compute_system_fingerprint(_prefetched(dep)) != system_before


def _two_stores_named_db(dep):
    """Two data stores with one name: one managed, one not. The agent names "db"."""
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.DATA_STORE, name="db", identifier="db-a",
        classification=Asset.Classification.KNOWN,
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.DATA_STORE, name="db", identifier="db-b",
        classification=Asset.Classification.UNMANAGED,
    )
    agent = _asset(dep, "agent")
    agent.metadata = {**agent.metadata, "tools": ["reader", "db"]}
    agent.save(update_fields=["metadata"])


def _recreate(asset_id):
    """Delete an asset and create it again, identically: same state, new pk."""
    asset = Asset.objects.get(pk=asset_id)
    fields = {
        f: getattr(asset, f)
        for f in ("deployment", "kind", "name", "identifier", "classification", "provider", "metadata")
    }
    asset.delete()
    return Asset.objects.create(**fields)


def test_a_name_two_components_share_is_read_the_same_whatever_the_row_order():
    """Both graph readers resolved a name with ``setdefault`` over the rows in
    database order, so a shared name meant whichever row came first -- a primary-key
    tie-break no fingerprint can see. Deleting the managed store and recreating it
    identically turned a VERIFIED effective-access claim CONTRADICTED with no input
    moving. A reference that could mean two components is now followed to both and
    reported as ambiguous, identically by both readers."""
    dep = _deployment()
    _two_stores_named_db(dep)
    readings_before, fps_before = _readings(dep), _fps(dep)

    _recreate(Asset.objects.get(deployment=dep, identifier="db-a").pk)

    assert _readings(dep) == readings_before
    assert _fps(dep) == fps_before

    fresh = _prefetched(dep)
    access_rows = assess_effective_access(fresh)["unresolved"]
    route_rows = build_route_map(fresh)["unresolved"]
    assert access_rows == route_rows
    assert [(r["reference"], r["reason"]) for r in access_rows if r["reference"] == "db"] == [
        ("db", UNRESOLVED_AMBIGUOUS)
    ]


def test_a_second_component_with_the_same_name_cannot_launder_a_contradiction():
    """Resolving an ambiguous name to NEITHER candidate let a duplicate hide a reach:
    one unmanaged ``warehouse`` behind the tool read as ungoverned reach, two of them
    read as nothing reached at all, and the claim eased from CONTRADICTED to
    PARTIALLY_VERIFIED. Every candidate is followed, so the reading is never milder
    than any way the reference could be resolved."""
    dep = _deployment()
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.DATA_STORE, name="warehouse", identifier="wh-1",
        classification=Asset.Classification.UNMANAGED,
    )
    one = _readings(dep)[ACCESS]
    assert one["status"] == Status.CONTRADICTED, "the premise"

    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.DATA_STORE, name="warehouse", identifier="wh-2",
        classification=Asset.Classification.UNMANAGED,
    )
    two = _readings(dep)[ACCESS]

    assert two["status"] == Status.CONTRADICTED
    fresh = _prefetched(dep)
    for rows in (assess_effective_access(fresh)["unresolved"], build_route_map(fresh)["unresolved"]):
        assert ("warehouse", UNRESOLVED_AMBIGUOUS) in [(r["reference"], r["reason"]) for r in rows]


def test_an_identifier_two_kinds_share_is_ambiguous_not_first_wins():
    """The identifier is unique only within a kind. Two kinds carrying it are as
    ambiguous as a shared name, never settled by which kind sorts first."""
    dep = _deployment()
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.DATA_STORE, name="warehouse-store", identifier="warehouse",
        classification=Asset.Classification.KNOWN,
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.API, name="warehouse-api", identifier="warehouse",
        classification=Asset.Classification.KNOWN,
    )
    fresh = _prefetched(dep)
    for rows in (assess_effective_access(fresh)["unresolved"], build_route_map(fresh)["unresolved"]):
        assert ("warehouse", UNRESOLVED_AMBIGUOUS) in [(r["reference"], r["reason"]) for r in rows]


def test_a_padded_reference_resolves_like_the_bare_one():
    dep = _deployment()
    agent = _asset(dep, "agent")
    before = _readings(dep)[ACCESS]
    agent.metadata = {**agent.metadata, "tools": ["  reader  "]}
    agent.save(update_fields=["metadata"])
    assert _readings(dep)[ACCESS] == before
    assert not [r for r in assess_effective_access(_prefetched(dep))["unresolved"] if r["reference"] == "reader"]


def test_a_provider_rows_own_evidence_class_moves_no_claim():
    """No deriver reads the provider row's evidence class -- each ASSERTION's class
    is graded -- so changing it versions no claim. It still moves the system
    fingerprint, which is the whole descriptor."""
    dep = _deployment()
    before, system_before = _fps(dep), compute_system_fingerprint(_prefetched(dep))
    provider = Provider.objects.get(name="openai")
    other = next(c for c in EvidenceClass.values if c != provider.evidence_class)
    Provider.objects.filter(pk=provider.pk).update(evidence_class=other)
    assert _fps(dep) == before
    assert compute_system_fingerprint(_prefetched(dep)) != system_before


def test_a_provider_region_is_not_an_access_input():
    """The access graph never reads which provider a component resolves to, so a
    provider moving region is a boundary and BOM change, not an access change."""
    dep = _deployment()
    before = _fps(dep)
    Provider.objects.filter(name="openai").update(region="us-east-1")
    after = _fps(dep)
    assert {t for t in before if before[t] != after[t]} == {BOUNDARY, BOM}


def test_a_served_route_fact_no_deriver_reads_moves_no_claim():
    """The served route is in the system fingerprint (a decision is fenced on it)
    and in no claim's inputs, because no claim deriver reads it."""
    dep = _deployment()
    before, system_before = _fps(dep), compute_system_fingerprint(_prefetched(dep))
    model = _asset(dep, "gpt")
    model.metadata = {**model.metadata, "quantization": "int8"}
    model.save(update_fields=["metadata"])
    assert _fps(dep) == before
    assert compute_system_fingerprint(_prefetched(dep)) != system_before


def test_an_unmapped_claim_type_is_compared_on_the_whole_system():
    claim = SimpleNamespace(claim_type="not_a_mapped_type", input_fingerprint="a" * 64, system_fingerprint="")
    assert claim_state_moved(claim, system_fp="a" * 64, input_fps={}) is False
    assert claim_state_moved(claim, system_fp="b" * 64, input_fps={}) is True


def _reopen(req):
    req.resolved_at = None
    req.resolving_claim = None
    req.save(update_fields=["resolved_at", "resolving_claim", "updated_at"])


def test_a_retest_is_resolved_by_a_version_bound_to_its_own_inputs_not_the_whole_system():
    """A change to another claim's inputs moves the system fingerprint. It is no
    reason to keep this claim's retest open."""
    dep = _deployment()
    derive_claims(dep)
    _widen_boundary(dep)
    check_invalidations(dep)
    derive_claims(dep)
    req = RetestRequirement.objects.get(deployment=dep)
    _reopen(req)

    _grant_permission(dep)
    resolve_satisfied_requirements(_prefetched(dep))

    req.refresh_from_db()
    assert req.resolved_at is not None
    assert req.resolving_claim.claim_type == BOUNDARY


def test_a_retest_is_not_resolved_by_a_version_that_has_itself_drifted():
    dep = _deployment()
    derive_claims(dep)
    _widen_boundary(dep)
    check_invalidations(dep)
    derive_claims(dep)
    req = RetestRequirement.objects.get(deployment=dep)
    _reopen(req)

    boundary = DataBoundary.objects.get(deployment=dep)
    boundary.training_allowed = True
    boundary.save(update_fields=["training_allowed"])
    resolve_satisfied_requirements(_prefetched(dep))

    req.refresh_from_db()
    assert req.resolved_at is None


def test_a_reverted_change_is_answered_by_the_next_derive():
    """A retest opened on a change that was then reverted used to stay open, because
    only a DIFFERENT version could answer it and the derive refreshed the same one
    in place. The claim sat capped at NEEDS_MORE_EVIDENCE until some unrelated
    change superseded it."""
    dep = _deployment()
    derive_claims(dep)
    _widen_boundary(dep)
    check_invalidations(dep)
    req = RetestRequirement.objects.get(deployment=dep)

    boundary = DataBoundary.objects.get(deployment=dep)
    boundary.allowed_regions = ["eu-west-1"]
    boundary.save(update_fields=["allowed_regions"])

    # A check alone is not a retest: nothing has re-read the claim.
    check_invalidations(dep)
    req.refresh_from_db()
    assert req.resolved_at is None

    counts = derive_claims(dep)
    req.refresh_from_db()
    assert counts["superseded"] == 0
    assert req.resolved_at is not None
    assert req.resolving_claim_id == req.claim_id
    assert req.claim.status != Status.STALE


@pytest.mark.parametrize("malformed", ["", {}], ids=["empty-string", "empty-mapping"])
def test_an_empty_tools_value_on_an_agent_that_had_none_moves_the_access_claim(malformed):
    """An agent with no ``tools`` key, given ``tools: ""`` or ``{}``. The access graph
    reads that as a malformed declaration -- one unresolved reference, a lower
    reading -- and a descriptor that dropped empty values saw no change at all."""
    dep = _deployment()
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.AGENT, name="idle", identifier="idle",
        classification=Asset.Classification.KNOWN, metadata={"identity": "svc-idle"},
    )
    readings_before, fps_before = _readings(dep), _fps(dep)

    idle = _asset(dep, "idle")
    idle.metadata = {**idle.metadata, "tools": malformed}
    idle.save(update_fields=["metadata"])

    assert _readings(dep)[ACCESS] != readings_before[ACCESS], "the premise: the reading moved"
    assert _fps(dep)[ACCESS] != fps_before[ACCESS]


def test_the_order_regions_were_stored_in_is_not_a_change():
    """The descriptor sorts the approved regions and the violation text printed them
    as stored, so reordering the same regions changed the boundary claim's reading
    and moved no fingerprint. The text is written from the sorted list now."""
    dep = _deployment()
    _move_provider_region(dep)
    _widen_boundary(dep)
    readings_before, fps_before = _readings(dep), _fps(dep)
    assert readings_before[BOUNDARY]["status"] == Status.CONTRADICTED, "the premise"

    boundary = DataBoundary.objects.get(deployment=dep)
    boundary.allowed_regions = list(reversed(boundary.allowed_regions))
    boundary.save(update_fields=["allowed_regions"])

    assert _readings(dep) == readings_before
    assert _fps(dep) == fps_before


def test_two_same_named_providers_are_reported_in_an_order_the_rows_cannot_change():
    """Two providers called "openai", both violating, behind two models both called
    "gpt". The flows tied on provider name and fell to row order, which decided whose
    violations the summary named: deleting one model and recreating it identically
    rewrote the claim's reading in place."""
    dep = _deployment()
    _move_provider_region(dep)
    store = _add_same_named_vector_store(dep)
    ProviderAssertion.objects.filter(provider=store, field="region").update(value="ap-south-1")
    first = Asset.objects.create(
        deployment=dep, kind=Asset.Kind.MODEL, name="gpt", identifier="gpt-b",
        provider=store, classification=Asset.Classification.KNOWN,
    )
    before = _readings(dep)[BOUNDARY]
    assert before["status"] == Status.CONTRADICTED, "the premise"

    _recreate(_asset_by_identifier(dep, "gpt").pk)
    after_one = _readings(dep)[BOUNDARY]
    _recreate(first.pk)
    after_both = _readings(dep)[BOUNDARY]

    assert after_one == before
    assert after_both == before


def test_re_pointing_a_component_at_a_same_named_provider_moves_the_boundary_claim():
    """Both "openai" providers stay referenced, so the providers family does not
    move; only which one the model resolves to does. The boundary reads the
    difference, so asset_provider must be one of its inputs."""
    dep = _deployment()
    store = _add_same_named_vector_store(dep)
    ProviderAssertion.objects.filter(provider=store, field="region").update(value="us-east-1")
    # Neither holder is a data destination, so neither forms a boundary flow; they
    # only keep BOTH providers referenced, so the providers family cannot move.
    Asset.objects.filter(deployment=dep, name="vectors").update(kind=Asset.Kind.AGENT)
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.AGENT, name="holder", identifier="holder",
        provider=Provider.objects.get(name="openai", kind=Provider.Kind.MODEL_PROVIDER),
        classification=Asset.Classification.KNOWN,
    )
    families_before = _families(_prefetched(dep))
    readings_before, fps_before = _readings(dep), _fps(dep)

    Asset.objects.filter(deployment=dep, name="gpt").update(provider=store)

    families_after = _families(_prefetched(dep))
    assert [k for k in families_before if families_before[k] != families_after[k]] == [
        "asset_provider"
    ], "the premise: only which provider the model resolves to moved"

    assert _readings(dep)[BOUNDARY] != readings_before[BOUNDARY], "the premise"
    assert _fps(dep)[BOUNDARY] != fps_before[BOUNDARY]


def test_any_reading_that_moved_with_no_input_is_versioned_and_says_so():
    """A reading the deriver produces differently while every input it is bound to
    holds is what a gap in CLAIM_INPUTS looks like from the reconciler. It is a new
    version with a note naming that, never an in-place rewrite."""
    dep = _deployment()
    derive_claims(dep)
    AssuranceClaim.objects.filter(deployment=dep, claim_type=ACCESS).update(
        contradicting_summary="a reading this state does not produce"
    )

    counts = derive_claims(dep)

    assert counts["superseded"] == 1
    old = AssuranceClaim.objects.get(deployment=dep, claim_type=ACCESS, status=Status.SUPERSEDED)
    assert "no input this claim is bound to" in old.events.order_by("-pk").first().note


def test_an_expired_claim_is_refreshed_in_place_not_versioned():
    """STALE is a lifecycle mark, not a reading: evidence that expired and is read
    again the same is the same version, re-verified."""
    dep = _deployment()
    derive_claims(dep)
    AssuranceClaim.objects.filter(deployment=dep, claim_type=ACCESS).update(status=Status.STALE)

    counts = derive_claims(dep)

    assert counts["superseded"] == 0
    assert AssuranceClaim.objects.get(deployment=dep, claim_type=ACCESS).status != Status.STALE


def test_a_contradicted_claims_retest_is_not_answered_without_a_derive():
    """The invalidation never softens a CONTRADICTED claim, so it is not marked
    STALE; a reverted change followed by a check -- no derivation -- must not read
    as the retest being answered."""
    dep = _deployment()
    _move_provider_region(dep)
    derive_claims(dep)
    boundary = AssuranceClaim.objects.filter(deployment=dep, claim_type=BOUNDARY).current().get()
    assert boundary.status == Status.CONTRADICTED, "the premise"

    region = ProviderAssertion.objects.get(provider__name="openai", field="region")
    region.value = "ap-south-1"
    region.save(update_fields=["value"])
    check_invalidations(dep)
    region.value = "us-east-1"
    region.save(update_fields=["value"])

    check_invalidations(dep)
    assert RetestRequirement.objects.filter(
        deployment=dep, claim__claim_type=BOUNDARY, resolved_at__isnull=True
    ).exists()

    derive_claims(dep)
    assert not RetestRequirement.objects.filter(
        deployment=dep, claim__claim_type=BOUNDARY, resolved_at__isnull=True
    ).exists()


def test_a_backdated_check_is_not_answered_by_the_derive_before_it():
    dep = _deployment()
    derive_claims(dep)
    seen = AssuranceClaim.objects.get(deployment=dep, claim_type=BOUNDARY).last_seen
    _widen_boundary(dep)
    check_invalidations(dep, now=seen - timedelta(hours=1))
    boundary = DataBoundary.objects.get(deployment=dep)
    boundary.allowed_regions = ["eu-west-1"]
    boundary.save(update_fields=["allowed_regions"])
    AssuranceClaim.objects.filter(deployment=dep, claim_type=BOUNDARY).update(status=Status.VERIFIED)

    resolve_satisfied_requirements(_prefetched(dep))

    assert RetestRequirement.objects.filter(deployment=dep, resolved_at__isnull=True).exists()


# --------------------------------------------------------------- round three


def _person():
    return get_user_model().objects.create_user(username=f"reviewer{get_user_model().objects.count()}", password="x")


def test_a_persons_verdict_stands_on_its_version_through_a_re_derive():
    """A reviewer moves the boundary claim to CONTRADICTED -- "we know it leaks".
    Nothing the claim rests on changed, so re-deriving must neither overwrite that
    verdict in place nor supersede it as though the fingerprint had a gap."""
    from assurance.claims import apply_claim_transition

    dep = _deployment()
    derive_claims(dep)
    claim = AssuranceClaim.objects.filter(deployment=dep, claim_type=BOUNDARY).current().get()
    apply_claim_transition(claim, Status.CONTRADICTED, actor=_person(), note="we know it leaks")

    counts = derive_claims(dep)

    assert counts["superseded"] == 0
    claim.refresh_from_db()
    assert claim.valid_to is None
    assert claim.status == Status.CONTRADICTED
    assert not claim.events.filter(note__contains="no input this claim is bound to").exists()


def test_a_persons_verdict_ends_with_the_state_it_was_about():
    from assurance.claims import apply_claim_transition

    dep = _deployment()
    derive_claims(dep)
    claim = AssuranceClaim.objects.filter(deployment=dep, claim_type=BOUNDARY).current().get()
    apply_claim_transition(claim, Status.CONTRADICTED, actor=_person(), note="we know it leaks")
    _widen_boundary(dep)

    counts = derive_claims(dep)

    assert counts["superseded"] == 1
    current = AssuranceClaim.objects.filter(deployment=dep, claim_type=BOUNDARY).current().get()
    assert current.pk != claim.pk
    assert current.status != Status.CONTRADICTED


def test_a_status_the_machine_did_not_derive_and_no_person_set_is_versioned():
    """The other side of the person's verdict: a status nobody attributed differs
    from the reading, and that is a new version."""
    dep = _deployment()
    derive_claims(dep)
    AssuranceClaim.objects.filter(deployment=dep, claim_type=BOUNDARY).update(status=Status.UNKNOWN)

    assert derive_claims(dep)["superseded"] == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evidence_class", EvidenceClass.VENDOR_ASSERTED),
        ("vendor_asserted", True),
        ("supporting_summary", "a reading this state does not produce"),
        ("contradicting_summary", "a reading this state does not produce"),
    ],
)
def test_every_part_of_the_reading_is_compared(field, value):
    dep = _deployment()
    derive_claims(dep)
    claim = AssuranceClaim.objects.filter(deployment=dep, claim_type=BOUNDARY).current().get()
    assert getattr(claim, field) != value, "the premise"
    AssuranceClaim.objects.filter(pk=claim.pk).update(**{field: value})

    assert derive_claims(dep)["superseded"] == 1


def test_a_backend_that_shares_a_name_with_an_agent_does_not_make_the_agent_a_hop():
    """A ``server`` is a backend, never a principal. Resolving it to an agent put
    that agent's tools inside another agent's reach, and an agent that gained no
    power was named privileged."""
    dep = _deployment()
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.DATA_STORE, name="warehouse", identifier="wh",
        classification=Asset.Classification.KNOWN,
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.AGENT, name="ops", identifier="ops",
        classification=Asset.Classification.KNOWN, metadata={"tools": ["shell"]},
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="shell", identifier="shell",
        classification=Asset.Classification.KNOWN, metadata={"permissions": ["code_execution"]},
    )
    before = _readings(dep)[ACCESS]

    Asset.objects.filter(deployment=dep, identifier="ops").update(name="warehouse")

    after = _readings(dep)[ACCESS]
    # The renamed agent is still the one privileged principal; nobody else is.
    assert before["contradicting_summary"].rsplit("on: ", 1)[1] == "ops"
    assert after["contradicting_summary"].rsplit("on: ", 1)[1] == "warehouse"
    principals = {p["name"]: p for p in assess_effective_access(_prefetched(dep))["principals"]}
    reach = [" > ".join(r["via"]) for r in principals["agent"]["effective_reach"]]
    assert not any("shell" in via for via in reach)


def test_a_backend_reference_that_names_only_a_principal_is_unresolved_and_says_so():
    from assurance.graph_refs import UNRESOLVED_NAMES_A_PRINCIPAL

    dep = _deployment()
    tool = _asset(dep, "reader")
    tool.metadata = {**tool.metadata, "server": "agent"}
    tool.save(update_fields=["metadata"])
    fresh = _prefetched(dep)
    for rows in (assess_effective_access(fresh)["unresolved"], build_route_map(fresh)["unresolved"]):
        assert ("agent", UNRESOLVED_NAMES_A_PRINCIPAL) in [(r["reference"], r["reason"]) for r in rows]


def test_the_graph_modules_agree_on_what_a_principal_is():
    from assurance.graph_refs import PRINCIPAL_KINDS

    assert PRINCIPAL_KINDS == {Asset.Kind.AGENT.value, Asset.Kind.SERVICE_ACCOUNT.value}


def test_an_ambiguous_backend_is_followed_to_the_ungoverned_candidate_too():
    """Two stores named ``warehouse``, one managed, created first, and one not. Following
    only the first candidate would read the reach as governed."""
    dep = _deployment()
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.DATA_STORE, name="warehouse", identifier="wh-managed",
        classification=Asset.Classification.KNOWN,
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.DATA_STORE, name="warehouse", identifier="wh-shadow",
        classification=Asset.Classification.UNMANAGED,
    )
    assert _readings(dep)[ACCESS]["status"] == Status.CONTRADICTED
    fresh = _prefetched(dep)
    route_pairs = {
        (e["source"], e["target"]) for e in build_route_map(fresh)["edges"] if e.get("declared")
    }
    targets = {str(a.uuid) for a in Asset.objects.filter(deployment=dep, name="warehouse")}
    reader = str(_asset(dep, "reader").uuid)
    assert {(reader, t) for t in targets} <= route_pairs


def test_shadow_destinations_are_listed_in_an_order_the_rows_cannot_change():
    from assurance.boundary import assess_boundary

    dep = _deployment()
    for identifier in ("s-b", "s-a"):
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.VECTOR_DB, name="shadow", identifier=identifier,
            classification=Asset.Classification.UNMANAGED,
        )
    before = assess_boundary(_prefetched(dep))
    _recreate(_asset_by_identifier(dep, "s-b").pk)
    after = assess_boundary(_prefetched(dep))
    key = next(k for k, v in before.items() if isinstance(v, list) and v and "asset_name" in v[0])
    assert [s["identifier"] for s in after[key]] == ["s-a", "s-b"] == [s["identifier"] for s in before[key]]


def test_any_re_derive_after_the_retest_opened_answers_it_whatever_its_clock():
    """The requirement records when its claim was last derived as of the opening, and
    any later derive answers it -- including one whose own `now` reads earlier than
    the opening's, because what is being asked is whether the claim was read again."""
    dep = _deployment()
    derive_claims(dep)
    seen = AssuranceClaim.objects.get(deployment=dep, claim_type=BOUNDARY).last_seen
    _widen_boundary(dep)
    check_invalidations(dep, now=seen + timedelta(hours=2))
    boundary = DataBoundary.objects.get(deployment=dep)
    boundary.allowed_regions = ["eu-west-1"]
    boundary.save(update_fields=["allowed_regions"])

    derive_claims(dep, now=seen + timedelta(hours=1))

    assert not RetestRequirement.objects.filter(deployment=dep, resolved_at__isnull=True).exists()


def test_a_version_still_marked_stale_does_not_answer_its_retest():
    dep = _deployment()
    derive_claims(dep)
    _widen_boundary(dep)
    check_invalidations(dep)
    claim = AssuranceClaim.objects.get(deployment=dep, claim_type=BOUNDARY)
    boundary = DataBoundary.objects.get(deployment=dep)
    boundary.allowed_regions = ["eu-west-1"]
    boundary.save(update_fields=["allowed_regions"])
    AssuranceClaim.objects.filter(pk=claim.pk).update(
        status=Status.STALE, last_seen=claim.last_seen + timedelta(hours=1)
    )

    resolve_satisfied_requirements(_prefetched(dep))

    assert RetestRequirement.objects.filter(deployment=dep, resolved_at__isnull=True).exists()
