"""Phase 2 items 2 and 3 — served-route identity, and the receipt that carries it.

The roadmap's bar, in its own words:

> every receipt binds its verdict to a served-route fingerprint; unobservable
> fields are explicitly ``unknown``, never fabricated; a change in any captured
> field flips the fingerprint and triggers targeted revalidation

> a receipt alone answers "what configuration passed, and what was not covered";
> the schema is versioned and backward-readable; signing still verifies

Three things are being asserted here and each is a different kind of claim.

**The unknowns are in the record.** ``_salient_metadata`` omits an empty key,
which is right for an open-ended bag and wrong for a fixed roster: under omission
"nobody reported the quantization" and "quantization does not apply here" are the
same absence. Every test below that counts fields counts sixteen, never "however
many happened to be recorded".

**Nothing is inferred.** A field is read from its own source or it is
``unknown``. Once a value is in the hash, an inferred one is indistinguishable
from an observed one, and a receipt binding a verdict to an inferred route
attests to a system nobody saw.

**The receipt answers both halves alone.** "Which configuration passed" is the
route; "what was not covered" is the coverage manifest. Neither is recoverable
from the evidence root -- a clean test and an absent test leave the same silence
-- so both are hashed into the receipt.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from assurance import receipt as receipt_mod
from assurance.fingerprint import compute_system_fingerprint
from assurance.models import Asset, DeclaredComponent, Deployment, Provider
from assurance.served_route import (
    _METADATA_KEY,
    ROUTE_FIELDS,
    ROUTE_VERSION,
    UNKNOWN,
    deployment_served_routes,
    route_fingerprint,
    served_route,
    served_route_fingerprint,
    serves_inference,
)

pytestmark = pytest.mark.django_db

User = get_user_model()


def _deployment(name="checkout-assistant"):
    owner = User.objects.create_user(
        username=f"u-{Deployment.objects.count()}",
        password="x",
        role=User.Roles.ANALYST,
    )
    return Deployment.objects.create(name=name, owner=owner)


def _model_asset(
    dep, *, metadata=None, provider=None, name="gpt-x", kind=Asset.Kind.MODEL
):
    return Asset.objects.create(
        deployment=dep,
        kind=kind,
        name=name,
        identifier=f"urn:{name}",
        provider=provider,
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------------
# Every field is present, observed or explicitly unknown
# ---------------------------------------------------------------------------


def test_an_uninstrumented_route_reports_every_field_as_unknown():
    """The case the whole design turns on. Nothing was observed, so the route says
    so sixteen times -- rather than being an empty dict a reader would take for a
    component with no configuration."""
    dep = _deployment()
    route = served_route(_model_asset(dep))

    assert set(route) == set(ROUTE_FIELDS)
    assert len(route) == len(ROUTE_FIELDS)
    assert all(value == UNKNOWN for value in route.values())


def test_an_observed_field_is_carried_and_the_rest_stay_unknown():
    dep = _deployment()
    route = served_route(_model_asset(dep, metadata={"model": "gpt-x-2026-03"}))

    assert route["model"] == "gpt-x-2026-03"
    assert route["quantization"] == UNKNOWN
    assert route["tokenizer"] == UNKNOWN
    # The roster did not shrink because one field was filled.
    assert len(route) == len(ROUTE_FIELDS)


def test_an_empty_value_is_not_an_observation():
    """A metadata writer that emitted `"region": ""` has not told us the region,
    and carrying that as an observed empty value would put a fabricated fact in
    the hash."""
    dep = _deployment()
    route = served_route(
        _model_asset(dep, metadata={"region": "", "tools": [], "retrieval_config": {}})
    )
    assert route["region"] == UNKNOWN
    assert route["tool_schema"] == UNKNOWN
    assert route["retrieval_config"] == UNKNOWN


def test_every_field_in_the_roster_has_a_reader():
    """A field with no reader would be permanently unknown -- honest, and useless.
    This is what notices when a field is added to the roster and forgotten."""
    dep = _deployment()
    for field in ROUTE_FIELDS:
        if field in ("provider", "region"):
            continue  # read from the Provider row as well; covered separately
        # A distinct name per asset: (deployment, kind, identifier) is unique.
        asset = _model_asset(
            dep, name=field, metadata={_METADATA_KEY[field]: "sentinel-value"}
        )
        assert served_route(asset)[field] != UNKNOWN, f"{field} has no reader"


# ---------------------------------------------------------------------------
# Nothing is inferred from anything else
# ---------------------------------------------------------------------------


def test_a_known_model_does_not_fill_in_the_tokenizer_or_the_engine():
    """The sharpest honesty rule here. Every deployment of this model may use the
    same tokenizer; that is a fact about the world, not an observation of this
    route, and once it is hashed nobody can tell the two apart."""
    dep = _deployment()
    route = served_route(_model_asset(dep, metadata={"model": "gpt-x"}))
    assert route["tokenizer"] == UNKNOWN
    assert route["inference_engine"] == UNKNOWN
    assert route["model_revision"] == UNKNOWN
    assert route["quantization"] == UNKNOWN


def test_a_provider_row_is_an_observation_and_fills_provider_and_region():
    """Reading a recorded relationship is observation, not inference: the FK says
    this asset resolves to this provider, and the provider's region is where it
    is."""
    dep = _deployment()
    provider = Provider.objects.create(
        name="OpenAI", kind="model_api", region="us-east-1"
    )
    route = served_route(_model_asset(dep, provider=provider))
    assert route["provider"] == "OpenAI"
    assert route["region"] == "us-east-1"


def test_the_assets_own_region_wins_over_the_providers():
    """A provider may serve several regions. The asset's own recorded region is
    the more specific observation, so it is the one taken."""
    dep = _deployment()
    provider = Provider.objects.create(
        name="OpenAI", kind="model_api", region="us-east-1"
    )
    route = served_route(
        _model_asset(dep, provider=provider, metadata={"region": "eu-west-1"})
    )
    assert route["region"] == "eu-west-1"


def test_a_provider_with_no_region_leaves_the_region_unknown():
    dep = _deployment()
    provider = Provider.objects.create(name="OpenAI", kind="model_api", region="")
    assert served_route(_model_asset(dep, provider=provider))["region"] == UNKNOWN


# ---------------------------------------------------------------------------
# The sensitive fields travel as digests
# ---------------------------------------------------------------------------


def test_the_system_template_is_carried_as_a_digest_and_not_as_text():
    """The receipt is built to travel to an external party. It must be able to
    prove the template changed without shipping the template."""
    dep = _deployment()
    secret = "You are the internal finance assistant. The override code is HUNTER2."
    route = served_route(_model_asset(dep, metadata={"system_prompt": secret}))

    assert route["system_template"].startswith("sha256:")
    assert "HUNTER2" not in route["system_template"]
    assert secret not in str(route)


def test_the_tool_schema_and_retrieval_config_are_digested_too():
    dep = _deployment()
    route = served_route(
        _model_asset(
            dep,
            metadata={
                "tools": [{"name": "payments.release", "args": ["id"]}],
                "retrieval_config": {"index": "internal-kb", "k": 8},
            },
        )
    )
    assert route["tool_schema"].startswith("sha256:")
    assert route["retrieval_config"].startswith("sha256:")
    assert "payments.release" not in str(route)
    assert "internal-kb" not in str(route)


def test_editing_a_digested_field_moves_its_digest():
    dep = _deployment()
    before = served_route(_model_asset(dep, metadata={"system_prompt": "v1"}))[
        "system_template"
    ]
    after = served_route(_model_asset(dep, metadata={"system_prompt": "v2"}, name="b"))[
        "system_template"
    ]
    assert before != after


# ---------------------------------------------------------------------------
# The fingerprint
# ---------------------------------------------------------------------------


def test_the_same_route_fingerprints_identically():
    dep = _deployment()
    one = served_route(_model_asset(dep, metadata={"model": "gpt-x"}))
    two = served_route(_model_asset(dep, metadata={"model": "gpt-x"}, name="b"))
    assert route_fingerprint(one) == route_fingerprint(two)


@pytest.mark.parametrize("field", sorted(set(ROUTE_FIELDS) - {"provider", "region"}))
def test_a_change_in_any_captured_field_flips_the_fingerprint(field):
    """The quality bar, walked over every field rather than spot-checked. A field
    that silently did not participate in the hash would be a field a verdict is
    not actually bound to."""
    dep = _deployment()
    key = _METADATA_KEY[field]
    before = route_fingerprint(served_route(_model_asset(dep, metadata={key: "a"})))
    after = route_fingerprint(
        served_route(_model_asset(dep, metadata={key: "b"}, name="b"))
    )
    assert before != after, f"{field} does not participate in the fingerprint"


def test_learning_a_previously_unknown_field_flips_the_fingerprint():
    """Deliberate. A verdict taken against a route whose quantization was unknown
    is not the same verdict as one taken against a route known to be int8: the
    claim was bound to a state that included the not-knowing."""
    dep = _deployment()
    blind = route_fingerprint(
        served_route(_model_asset(dep, metadata={"model": "gpt-x"}))
    )
    seeing = route_fingerprint(
        served_route(
            _model_asset(
                dep, metadata={"model": "gpt-x", "quantization": "int8"}, name="b"
            )
        )
    )
    assert blind != seeing


def test_the_roster_version_is_inside_the_fingerprint():
    """Adding a field to the roster changes every route fingerprint. The version
    is what lets a consumer tell 'the route changed' from 'the roster grew'."""
    dep = _deployment()
    route = served_route(_model_asset(dep))
    assert route_fingerprint(route) != receipt_mod._digest({"route": route})
    assert route_fingerprint(route) == receipt_mod._digest(
        {"version": ROUTE_VERSION, "route": route}
    )


# ---------------------------------------------------------------------------
# Which assets have a route
# ---------------------------------------------------------------------------


def test_a_model_and_a_gateway_serve_and_a_data_store_does_not():
    """A data store does not serve a request, and giving it sixteen unknowns would
    inflate the unknown count with fields that were never applicable -- making the
    coverage number mean less, not more."""
    dep = _deployment()
    assert serves_inference(_model_asset(dep, kind=Asset.Kind.MODEL))
    assert serves_inference(_model_asset(dep, kind=Asset.Kind.GATEWAY, name="gw"))
    assert not serves_inference(
        _model_asset(dep, kind=Asset.Kind.DATA_STORE, name="pg")
    )
    assert not serves_inference(
        _model_asset(dep, kind=Asset.Kind.SERVICE_ACCOUNT, name="sa")
    )


def test_an_asset_of_any_kind_that_names_a_model_is_serving_something():
    """Observation over catalogue. Without this an agent carrying `model` in its
    metadata would report no route at all, and the manifest would read 'nothing
    serves' -- the silent zero arriving through the back door."""
    dep = _deployment()
    agent = _model_asset(
        dep, kind=Asset.Kind.AGENT, name="planner", metadata={"model": "gpt-x"}
    )
    assert serves_inference(agent)


def test_an_agent_with_no_model_named_is_not_a_route():
    dep = _deployment()
    assert not serves_inference(
        _model_asset(
            dep, kind=Asset.Kind.AGENT, name="planner", metadata={"role": "planner"}
        )
    )


# ---------------------------------------------------------------------------
# The deployment manifest
# ---------------------------------------------------------------------------


def _fully_observed_metadata():
    return {key: f"value-for-{key}" for key in _METADATA_KEY.values()}


def test_the_manifest_names_the_unobserved_fields_rather_than_only_counting_them():
    dep = _deployment()
    _model_asset(dep, metadata={"model": "gpt-x"})
    manifest = deployment_served_routes(dep)

    assert manifest["route_count"] == 1
    assert manifest["fully_observed_count"] == 0
    assert manifest["complete"] is False
    assert "quantization" in manifest["unknown_fields"]
    assert "model" not in manifest["unknown_fields"]
    # And the same list is on the route itself, so a reader can tell WHICH
    # component is uninstrumented, not just that something is.
    assert manifest["routes"][0]["unknown_fields"] == manifest["unknown_fields"]


def test_a_fully_observed_route_reports_complete():
    dep = _deployment()
    provider = Provider.objects.create(
        name="OpenAI", kind="model_api", region="us-east-1"
    )
    _model_asset(dep, provider=provider, metadata=_fully_observed_metadata())
    manifest = deployment_served_routes(dep)

    assert manifest["fully_observed_count"] == 1
    assert manifest["complete"] is True
    assert manifest["unknown_fields"] == []
    assert manifest["routes"][0]["observed_fields"] == len(ROUTE_FIELDS)


def test_a_deployment_with_nothing_serving_is_not_complete():
    """Nothing served is not everything observed. A vacuous true here is the exact
    reading this module exists to prevent."""
    dep = _deployment()
    _model_asset(dep, kind=Asset.Kind.DATA_STORE, name="pg")
    manifest = deployment_served_routes(dep)

    assert manifest["route_count"] == 0
    assert manifest["complete"] is False
    assert manifest["summary"].startswith("0 served route(s)")


def test_the_manifest_is_stable_whatever_order_the_rows_come_back():
    dep = _deployment()
    _model_asset(dep, name="b-model", metadata={"model": "b"})
    _model_asset(dep, name="a-model", metadata={"model": "a"})
    first = deployment_served_routes(dep)
    second = deployment_served_routes(dep)
    assert [r["name"] for r in first["routes"]] == ["a-model", "b-model"]
    assert first["fingerprint"] == second["fingerprint"]


def test_two_components_on_the_same_route_do_not_collapse_into_one():
    """The count is inside the deployment fingerprint. Two components serving the
    same route produce the same per-route fingerprint -- the route descriptor
    carries no asset identity -- so without the count the second one would vanish
    into the sorted set and a deployment running it twice would be
    indistinguishable from one running it once."""
    dep_one = _deployment("one")
    _model_asset(dep_one, name="primary", metadata={"model": "gpt-x"})

    dep_two = _deployment("two")
    _model_asset(dep_two, name="primary", metadata={"model": "gpt-x"})
    _model_asset(dep_two, name="secondary", metadata={"model": "gpt-x"})

    manifest = deployment_served_routes(dep_two)
    assert manifest["route_count"] == 2
    one, two = manifest["routes"]
    assert one["fingerprint"] == two["fingerprint"], "the routes really are identical"

    # A sorted LIST, not a set: the multiplicity is what separates these two.
    assert served_route_fingerprint(dep_one) != served_route_fingerprint(dep_two)


def test_the_deployment_fingerprint_is_over_a_list_and_not_a_set():
    """The mechanism behind the test above, pinned directly. A set would collapse
    two components on one route into a single digest and the two deployments would
    collide — and the assertion above would then be passing for a reason that no
    longer held."""
    from assurance.served_route import deployment_route_fingerprint

    once = deployment_route_fingerprint([{"fingerprint": "X"}])
    twice = deployment_route_fingerprint([{"fingerprint": "X"}, {"fingerprint": "X"}])
    assert once != twice


# ---------------------------------------------------------------------------
# Drift: the route moves the system fingerprint, which is what opens retests
# ---------------------------------------------------------------------------


def test_a_route_change_moves_the_system_fingerprint():
    """Targeted revalidation is not a new mechanism: the invalidation layer already
    supersedes a claim whose bound system fingerprint has moved. Folding the route
    in is what makes 'what served changed' reach it."""
    dep = _deployment()
    asset = _model_asset(dep, metadata={"model": "gpt-x"})
    before = compute_system_fingerprint(dep)

    asset.metadata = {"model": "gpt-x", "quantization": "int8"}
    asset.save(update_fields=["metadata"])
    dep.refresh_from_db()

    assert compute_system_fingerprint(dep) != before


def test_a_route_field_the_asset_descriptor_does_not_watch_still_moves_it():
    """The load-bearing case. `_salient_metadata` carries a curated key list;
    `quantization`, `tokenizer` and `inference_engine` are not on it. Without the
    served route folded in, changing what actually served would leave the system
    fingerprint untouched and no claim would be re-opened."""
    from assurance.fingerprint import _SALIENT_METADATA_KEYS

    dep = _deployment()
    asset = _model_asset(dep, metadata={"model": "gpt-x"})
    before = compute_system_fingerprint(dep)

    unwatched = "tokenizer"
    assert unwatched not in _SALIENT_METADATA_KEYS, (
        "pick a key the asset descriptor ignores"
    )

    asset.metadata = {"model": "gpt-x", unwatched: "cl100k_base"}
    asset.save(update_fields=["metadata"])
    dep.refresh_from_db()

    assert compute_system_fingerprint(dep) != before


def test_the_system_fingerprint_is_still_stable_under_no_change():
    dep = _deployment()
    _model_asset(dep, metadata={"model": "gpt-x"})
    assert compute_system_fingerprint(dep) == compute_system_fingerprint(dep)


# ---------------------------------------------------------------------------
# The receipt carries both halves
# ---------------------------------------------------------------------------


def test_the_receipt_binds_its_verdict_to_a_served_route_fingerprint():
    dep = _deployment()
    _model_asset(dep, metadata={"model": "gpt-x"})
    built = receipt_mod.build_assurance_receipt(dep)

    assert built["served_route"]["fingerprint"] == served_route_fingerprint(dep)
    assert built["served_route"]["route_count"] == 1
    assert built["served_route"]["complete"] is False
    assert "tokenizer" in built["served_route"]["unknown_fields"]


def test_the_receipt_answers_what_was_not_covered():
    dep = _deployment()
    DeclaredComponent.objects.create(
        deployment=dep, kind=Asset.Kind.MODEL, name="gpt-x"
    )
    _model_asset(dep, metadata={"model": "gpt-x"})
    built = receipt_mod.build_assurance_receipt(dep)

    assert built["coverage"]["expected"] == 1
    assert built["coverage"]["observed"] == 1
    assert built["coverage"]["assessed"] == 0
    assert built["coverage"]["verdict"] == "incomplete"
    assert built["coverage"]["critical_gap"] is True


def test_an_undeclared_architecture_reads_as_undeclared_and_not_as_complete():
    dep = _deployment()
    _model_asset(dep, metadata={"model": "gpt-x"})
    assert (
        receipt_mod.build_assurance_receipt(dep)["coverage"]["verdict"] == "undeclared"
    )


def test_the_route_and_coverage_are_inside_the_signed_digest():
    """Carried but unhashed, they would be decoration: a payload a signature does
    not cover can be edited without breaking the signature."""
    dep = _deployment()
    asset = _model_asset(dep, metadata={"model": "gpt-x"})
    before = receipt_mod.build_assurance_receipt(dep)["digest"]

    asset.metadata = {"model": "gpt-x", "quantization": "int8"}
    asset.save(update_fields=["metadata"])
    dep.refresh_from_db()

    assert receipt_mod.build_assurance_receipt(dep)["digest"] != before


def test_the_receipt_does_not_carry_the_prompt_or_the_tool_schema():
    """It travels to an external party. The summary answers 'which configuration
    passed' without shipping the configuration."""
    dep = _deployment()
    _model_asset(
        dep,
        metadata={
            "system_prompt": "override code HUNTER2",
            "tools": [{"name": "payments.release"}],
        },
    )
    built = receipt_mod.build_assurance_receipt(dep)
    assert "HUNTER2" not in str(built)
    assert "payments.release" not in str(built)
    # Nor the per-route detail, which is retrievable and unbounded.
    assert "routes" not in built["served_route"]


def test_the_receipt_is_still_deterministic_and_timestamp_free():
    dep = _deployment()
    _model_asset(dep, metadata={"model": "gpt-x"})
    one = receipt_mod.build_assurance_receipt(dep)
    two = receipt_mod.build_assurance_receipt(dep)
    assert one["digest"] == two["digest"]
    assert one["computed_at"] != "" and "computed_at" not in receipt_mod._digest.__doc__


# ---------------------------------------------------------------------------
# Versioned and backward-readable
# ---------------------------------------------------------------------------


def test_the_receipt_declares_the_new_major_version():
    dep = _deployment()
    built = receipt_mod.build_assurance_receipt(dep)
    assert built["receipt_version"] == receipt_mod.RECEIPT_VERSION
    # 3.0 since the coverage block began carrying checks_gap_fingerprint and
    # checks_reported_at. Both are new HASHED content, so every 2.0 digest differs
    # from the 3.0 digest of the same state, and a minor bump would have told a
    # consumer the shapes were compatible when the digests are not.
    #
    # 3.1 added signed/signature/unsigned_reason, which are NOT hashed. The digest
    # is byte-identical to 3.0's for the same state, so this step is minor by the
    # same rule that made the earlier ones major.
    assert receipt_mod.RECEIPT_VERSION == "mythos.assurance.receipt/3.1"


def test_the_schema_requires_the_two_new_blocks():
    schema = receipt_mod.receipt_schema()
    assert "served_route" in schema["required"]
    assert "coverage" in schema["required"]
    assert "served_route" in schema["properties"]


def test_the_previous_versions_schema_is_still_obtainable():
    """'Versioned' is worth nothing if the previous version's shape is only
    recoverable from git history. An auditor holding a 1.1 receipt needs the schema
    that reads it."""
    old = receipt_mod.receipt_schema("mythos.assurance.receipt/1.1")
    assert old["$id"] == "mythos.assurance.receipt/1.1"
    assert "served_route" not in old["properties"]
    assert "served_route" not in old["required"]
    # And the fields 1.1 did have are all still described.
    assert {"receipt_version", "policy_version", "system", "result", "policy"} <= set(
        old["properties"]
    )


def test_the_old_schema_pins_the_old_version_and_not_the_current_one():
    """The current schema pins `receipt_version` to the CURRENT version. Copying
    that into the 1.1 schema would hand an auditor a schema requiring the string
    "2.0" — one that rejects the very receipts it exists to read."""
    old = receipt_mod.receipt_schema("mythos.assurance.receipt/1.1")
    assert (
        old["properties"]["receipt_version"]["const"] == "mythos.assurance.receipt/1.1"
    )
    current = receipt_mod.receipt_schema()
    assert (
        current["properties"]["receipt_version"]["const"] == receipt_mod.RECEIPT_VERSION
    )


def test_no_two_versions_schemas_claim_the_same_id():
    """A registry whose entries disagree with their own `$id` would send a reader
    to the wrong shape while looking correct."""
    for version in (receipt_mod.RECEIPT_VERSION, *receipt_mod.SUPERSEDED_VERSIONS):
        assert receipt_mod.receipt_schema(version)["$id"] == version


def test_an_unknown_version_raises_rather_than_handing_back_the_current_schema():
    """A wrong schema is worse than no schema: falling back would tell a consumer
    their receipt has a served route and a coverage block, and those are exactly
    the fields whose absence matters."""
    with pytest.raises(receipt_mod.UnknownReceiptVersion) as excinfo:
        receipt_mod.receipt_schema("mythos.assurance.receipt/0.9")
    assert "mythos.assurance.receipt/1.1" in str(excinfo.value)


def test_every_superseded_version_has_a_schema():
    """The list and the registry cannot drift apart: a version named as superseded
    with no schema behind it is a promise of backward-readability that is not
    kept."""
    for version in receipt_mod.SUPERSEDED_VERSIONS:
        assert receipt_mod.receipt_schema(version)["$id"] == version


def test_the_schema_describes_every_key_the_receipt_actually_emits():
    """The documented half of 'documented + machine-readable'. A block added to the
    payload and not to the schema is a field no consumer can read."""
    dep = _deployment()
    built = receipt_mod.build_assurance_receipt(dep)
    described = set(receipt_mod.receipt_schema()["properties"])
    assert set(built) <= described, sorted(set(built) - described)


# ---------------------------------------------------------------------------
# The two multi-source fields may not infer
# ---------------------------------------------------------------------------
#
# `provider` and `region` are the only two readers with a fallback chain, and
# they were the only two with no test forbidding inference. An audit made
# `_provider_value` return "openai" whenever the model name contained "gpt" and
# nothing had observed a provider, and made `_region_value` read a region out of
# the provider's name. Both mutations survived the ENTIRE suite -- 1262 passed,
# not one failure.
#
# That is the worst available shape for this defect. A fabricated provider or
# region is a plain string, indistinguishable from an observed one, and it is
# hashed into the route fingerprint and from there into the signed receipt. The
# rest of this module is careful about exactly this; these two fields simply had
# nothing holding them to it.
#
# The asset fixture's default name is "gpt-x" and the deployment's is
# "checkout-assistant", which is convenient here: a reader that guessed from the
# model name would have everything it needed to guess.


def test_a_model_with_no_provider_anywhere_reports_provider_unknown():
    """No Provider row, no `provider` metadata key -- and a model name that names
    its vendor to anyone reading it. Nothing observed the provider, so the only
    honest answer is that nobody said."""
    dep = _deployment()
    asset = _model_asset(dep, name="gpt-4o", metadata={"model": "gpt-4o"})
    assert asset.provider is None
    assert served_route(asset)["provider"] == UNKNOWN


def test_a_provider_row_with_a_blank_region_reports_region_unknown():
    """The provider is recorded and its region is not. A region read out of the
    provider's NAME would be an inference dressed as an observation -- and the
    name here would give one up readily."""
    dep = _deployment()
    provider = Provider.objects.create(name="eu-central-hosted-llm", region="")
    asset = _model_asset(dep, provider=provider)
    route = served_route(asset)
    assert route["provider"] == "eu-central-hosted-llm"
    assert route["region"] == UNKNOWN


def test_neither_field_is_guessed_from_any_other_observed_field():
    """A route where everything else is observed is where an inference would be
    easiest to justify and hardest to notice."""
    dep = _deployment()
    asset = _model_asset(
        dep,
        name="claude-sonnet-eu",
        metadata={
            "model": "claude-sonnet-eu",
            "model_version": "2026-01-01",
            "endpoint": "https://api.eu-west-1.example/v1/messages",
            "deployment_kind": "managed",
        },
    )
    route = served_route(asset)
    assert route["provider"] == UNKNOWN, "the provider was guessed from another field"
    assert route["region"] == UNKNOWN, "the region was guessed from an endpoint or a name"


# -- the negative controls: an observation still arrives, from either source ---


def test_an_observed_provider_arrives_from_the_recorded_relationship():
    dep = _deployment()
    provider = Provider.objects.create(name="Anthropic", region="us-east-1")
    route = served_route(_model_asset(dep, provider=provider))
    assert route["provider"] == "Anthropic"
    assert route["region"] == "us-east-1"


def test_an_observed_provider_arrives_from_the_assets_own_metadata():
    dep = _deployment()
    route = served_route(
        _model_asset(dep, metadata={"provider": "Anthropic", "region": "eu-west-1"})
    )
    assert route["provider"] == "Anthropic"
    assert route["region"] == "eu-west-1"


def test_the_two_sources_are_read_in_the_order_the_docstrings_state():
    """Both are observations, so when they disagree the order decides, and the
    order is deliberate and opposite for the two fields: the provider comes from
    the recorded relationship first (an FK is a relationship somebody recorded,
    the metadata key is the asset's self-report), the region from the asset's own
    metadata first (the provider's region is where the PROVIDER is, which is the
    fallback, not the first answer). Pinned so a reordering is a decision rather
    than a diff nobody read."""
    dep = _deployment()
    provider = Provider.objects.create(name="FromTheRow", region="row-region")
    route = served_route(
        _model_asset(
            dep,
            provider=provider,
            metadata={"provider": "FromTheMetadata", "region": "metadata-region"},
        )
    )
    assert route["provider"] == "FromTheRow"
    assert route["region"] == "metadata-region"
