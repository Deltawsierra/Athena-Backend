"""Served Route Identity — the exact system that actually ran (Phase 2 item 2).

A model *name* does not tell you what served the request. "GPT-X passed" is a far
weaker claim than "this exact served route and configuration passed", and only the
second makes a retest meaningful: without the route, a verdict cannot say whether
the thing it was taken against is the thing running now.

So this module records the route, field by field, and it is built around one rule
that the rest of the fingerprint layer does not keep:

**Every field is always present. A field nothing observed is the string
``unknown``, never absent and never guessed.**

:func:`~assurance.fingerprint._salient_metadata` omits a key whose value is empty,
which is right for an open-ended metadata bag and wrong for a fixed roster. Under
omission, "nobody reported the quantization" and "quantization is not a concept
for this component" are the same absence, and a reader cannot tell a route that
was fully observed from one where twelve of fifteen fields were never looked at.
That is the silent zero, in the record whose whole job is to say what ran.

Never guessed also means **never cross-filled**. A field is read from its own
source or it is ``unknown``: the tokenizer is not inferred from the model, the
region is not inferred from the provider's name, the inference engine is not
inferred from the adapter. An inferred value is indistinguishable from an observed
one once it is in the hash, and a receipt that binds a verdict to an inferred route
is attesting to a system nobody saw.

What is hashed, and what is not carried
---------------------------------------
Three fields — the system template, the tool schema and the retrieval config — are
carried as a **digest of their content**, not the content. They are the largest
and the most sensitive things on the route: a system template is the customer's
prompt, a tool schema is their internal API surface. A receipt is meant to travel
to an external party, so the route must be able to prove *that the template
changed* without shipping the template. The digest flips on any edit, which is
exactly what the fingerprint needs, and discloses nothing.

Drift
-----
The deployment's route fingerprint folds into
:func:`assurance.fingerprint.compute_system_fingerprint`, so a route change moves
the system fingerprint, which is what the existing invalidation layer already
watches: a claim bound to the old fingerprint is superseded and a retest
obligation opens. Targeted revalidation is therefore not a new mechanism here --
it is the one that already exists, now reachable by a change in what served.

Learning a previously-``unknown`` field moves the fingerprint too, and that is
deliberate. A verdict taken against a route whose quantization was unknown is not
the same verdict as one taken against a route known to be int8. The claim was
bound to a state that included the not-knowing.

What this does NOT detect
-------------------------
The fingerprint moves when **what we recorded** changes. It does not move when
**what is running** changes and nobody records it: a provider that silently
reroutes to a fallback model, or swaps a quantization behind the same model name,
leaves this fingerprint exactly where it was. Closing that needs an active
measurement -- the engine's behavioural attestation prober, which measures a route
now and compares it to a baseline -- and that is a separate round trip with its
own contract, not something this module can infer from the stored graph.

Saying so here rather than leaving it to be discovered: a reader who takes "the
fingerprint detects route drift" at face value would believe this layer watches
the live system, and it watches the record of it. The two coincide exactly as
often as discovery runs.
"""

from __future__ import annotations

from .receipt import ALGORITHM, _digest

# The literal a field carries when nothing observed it. A string rather than
# ``None`` so it survives JSON, sorts predictably, and reads the same in a
# receipt as it does here -- and so that a consumer who sees it cannot mistake it
# for a missing key their parser dropped.
UNKNOWN = "unknown"

# The version of the served-route descriptor. The roster below is part of the
# hashed content, so adding a field changes every route fingerprint; the version
# is what lets a consumer tell "the route changed" from "the roster grew".
ROUTE_VERSION = "mythos.assurance.served-route/1"

# The fields the roadmap names, in a fixed order, each read from ONE source.
# Adding a field here means adding its reader below -- a field with no reader
# would be permanently `unknown`, which is honest but useless, so the pairing is
# asserted by the tests rather than left to review.
ROUTE_FIELDS: tuple[str, ...] = (
    "provider",
    "model",
    "model_revision",
    "routing_layer",
    "fallback_model",
    "adapter",
    "quantization",
    "inference_engine",
    "inference_engine_version",
    "tokenizer",
    "system_template",
    "tool_schema",
    "retrieval_config",
    "cache_isolation",
    "region",
    "orchestration_version",
)

# The three fields carried as a digest of their content rather than the content.
# See the module docstring: they are the customer's prompt, their internal API
# surface, and their retrieval topology, and a receipt has to be able to travel.
_DIGESTED_FIELDS = frozenset({"system_template", "tool_schema", "retrieval_config"})

# Each route field's ONE metadata key. A field is read from its own key or it is
# unknown; nothing here falls back to a neighbouring key, because a value that
# arrived by inference is indistinguishable from an observed one once hashed.
_METADATA_KEY: dict[str, str] = {
    "provider": "provider",
    "model": "model",
    "model_revision": "model_revision",
    "routing_layer": "routing_layer",
    "fallback_model": "fallback_model",
    "adapter": "adapter",
    "quantization": "quantization",
    "inference_engine": "inference_engine",
    "inference_engine_version": "inference_engine_version",
    "tokenizer": "tokenizer",
    "system_template": "system_prompt",
    "tool_schema": "tools",
    "retrieval_config": "retrieval_config",
    "cache_isolation": "cache_isolation",
    "region": "region",
    "orchestration_version": "orchestration_version",
}

# The asset kinds that sit on an inference path and therefore have a served route.
# A data store, a service account or a skill does not serve a request, and giving
# one a route of sixteen `unknown`s would inflate the unknown count with fields
# that were never applicable -- making the route coverage number mean less, not
# more.
_SERVING_KINDS = frozenset({"model", "gateway"})


def _observed(metadata, key: str):
    """The value at ``key``, or ``None`` when nothing usable is there.

    Empty string, empty list and empty dict are all "nothing observed": a metadata
    writer that emitted ``"region": ""`` has not told us the region, and treating
    that as an observed empty value would put a fabricated fact in the hash.
    """
    if not isinstance(metadata, dict):
        return None
    value = metadata.get(key)
    if value in (None, "", [], {}):
        return None
    return value


def serves_inference(asset) -> bool:
    """Whether this asset sits on an inference path and so has a served route.

    Kind first, then observation: an asset of any kind whose metadata actually
    names a model is serving something, whatever it was catalogued as. Without the
    second half, a deployment whose only agent carries ``model`` in its metadata
    would report zero routes and the manifest would read as "nothing serves" --
    which is the silent zero this module exists to remove, arriving through the
    back door.
    """
    if asset.kind in _SERVING_KINDS:
        return True
    return _observed(asset.metadata, "model") is not None


def _provider_value(asset) -> str:
    """The provider that served, from the resolved Provider row or the asset's own
    metadata -- in that order, because the FK is a recorded relationship and the
    metadata key is a self-report. Both are observations; neither is a guess."""
    provider = getattr(asset, "provider", None)
    if provider is not None and provider.name:
        return provider.name
    value = _observed(asset.metadata, "provider")
    return str(value) if value is not None else UNKNOWN


def _region_value(asset) -> str:
    """The region, from the asset's own metadata or the resolved provider's region.

    The provider's region is where the provider is, and for a resolved asset that
    IS the region it was served from -- a recorded fact, not an inference from the
    provider's name.
    """
    value = _observed(asset.metadata, "region")
    if value is not None:
        return str(value)
    provider = getattr(asset, "provider", None)
    if provider is not None and provider.region:
        return str(provider.region)
    return UNKNOWN


def _field_value(asset, field: str) -> str:
    """One route field, observed or ``unknown``. Never inferred from another field."""
    if field == "provider":
        return _provider_value(asset)
    if field == "region":
        return _region_value(asset)

    value = _observed(asset.metadata, _METADATA_KEY[field])
    if value is None:
        return UNKNOWN
    if field in _DIGESTED_FIELDS:
        # The content never leaves; its digest does. Prefixed with the algorithm
        # so a reader is never left wondering whether a 64-hex string is a hash or
        # a value that happens to look like one.
        return f"{ALGORITHM}:{_digest({'content': value})}"
    return str(value)


def served_route(asset) -> dict:
    """The complete served route for one asset: every field in
    :data:`ROUTE_FIELDS`, observed or ``unknown``.

    Deterministic and timestamp-free, like every other descriptor in this layer.
    The unknowns are IN the descriptor, not omitted from it, so the route is a
    statement about what was and was not observed rather than a list of whatever
    happened to be recorded.
    """
    return {field: _field_value(asset, field) for field in ROUTE_FIELDS}


def route_fingerprint(route: dict) -> str:
    """A deterministic SHA-256 over a complete route descriptor, roster version
    included.

    The unknowns are hashed. A field moving from ``unknown`` to a value is a
    change in the captured state and must flip the fingerprint: the claim it was
    bound to was bound to the not-knowing.
    """
    return _digest({"version": ROUTE_VERSION, "route": route})


def _route_entry(asset) -> dict:
    """One asset's route, with the identity to find it again and the fields that
    were never observed named rather than merely counted. A reader who can only
    see "11 unknown" cannot act; one who can see *which* eleven can go and
    instrument them."""
    route = served_route(asset)
    unknown_fields = sorted(f for f, v in route.items() if v == UNKNOWN)
    return {
        "asset_uuid": str(asset.uuid),
        "kind": asset.kind,
        "name": asset.name,
        "identifier": asset.identifier,
        "route": route,
        "fingerprint": route_fingerprint(route),
        "observed_fields": len(ROUTE_FIELDS) - len(unknown_fields),
        "unknown_fields": unknown_fields,
    }


def deployment_served_routes(deployment) -> dict:
    """Every served route in the deployment, and how much of them was observed.

    Pure and read-only. ``routes`` is sorted by (kind, name, identifier) so the
    output is stable for a given state whatever order the ORM returned.

    ``fully_observed`` is deliberately not a percentage on its own: a percentage
    with nothing named is a number a reader cannot act on, so every route carries
    its own ``unknown_fields`` list. And a deployment with no serving asset
    reports ``route_count: 0`` rather than an empty success -- nothing served is
    not the same as everything observed, and ``complete`` stays false for it.
    """
    assets = [a for a in deployment.assets.all() if serves_inference(a)]
    routes = sorted(
        (_route_entry(a) for a in assets),
        key=lambda r: (r["kind"], r["name"], r["identifier"]),
    )
    fully_observed = [r for r in routes if not r["unknown_fields"]]

    # The union of what was never observed anywhere. A field unknown on every
    # route is an instrumentation gap in the platform; one unknown on a single
    # route is a gap at that component.
    unknown_anywhere = sorted({f for r in routes for f in r["unknown_fields"]})

    return {
        "route_version": ROUTE_VERSION,
        "algorithm": ALGORITHM,
        "fields": list(ROUTE_FIELDS),
        "route_count": len(routes),
        "fully_observed_count": len(fully_observed),
        # False with no routes at all: "nothing serves" is not "everything
        # observed", and a vacuous true here would be the exact reading this
        # module exists to prevent.
        "complete": bool(routes) and len(fully_observed) == len(routes),
        "unknown_fields": unknown_anywhere,
        "routes": routes,
        "fingerprint": deployment_route_fingerprint(routes),
        "summary": (
            f"{len(routes)} served route(s), {len(fully_observed)} fully observed; "
            f"{len(unknown_anywhere)} field(s) unknown somewhere"
        ),
    }


def deployment_route_fingerprint(routes) -> str:
    """One fingerprint over every route in the deployment.

    Takes the already-built entries so the manifest and the fingerprint cannot
    disagree about what was in them. Over the SORTED per-route fingerprints, so
    the value is independent of ORM ordering.

    A LIST, deliberately, not a set: two components on the same route produce the
    same per-route fingerprint -- the route descriptor carries no asset identity --
    and a set would collapse them, making a deployment that runs the route twice
    indistinguishable from one that runs it once.

    It carried a separate ``count`` until a mutation check showed removing the
    count changed no test and no value: a sorted list already preserves
    multiplicity, so ``["X"]`` and ``["X", "X"]`` can never hash alike. It was a
    control that read as one and enforced nothing, which is worse than its
    absence -- a reader would take it for the thing standing between them and a
    collision. The list is that thing.
    """
    return _digest(
        {"version": ROUTE_VERSION, "routes": sorted(r["fingerprint"] for r in routes)}
    )


def served_route_fingerprint(deployment) -> str:
    """The deployment's served-route fingerprint, computed from the graph.

    The value :func:`assurance.fingerprint.compute_system_fingerprint` folds in,
    so a change in what served moves the system fingerprint and the existing
    invalidation layer supersedes the claims bound to it.
    """
    routes = sorted(
        (_route_entry(a) for a in deployment.assets.all() if serves_inference(a)),
        key=lambda r: (r["kind"], r["name"], r["identifier"]),
    )
    return deployment_route_fingerprint(routes)
