"""The scenario builder: SPINE effects and the findings that enable them, built into
causal loss events (``docs/economics/spec-v1.md``, section 24).

Given a deployment, the effects a build declares -- each a SPINE observed effect or
a hypothetical effect, bound to an asset and a business process, with the
attributes it states -- the findings that enable them, and a customer parameter-set
version, :func:`build`:

1. resolves every reference IN THE DEPLOYMENT, and only there: a finding, an asset,
   an observed effect or a parameter-set version of another deployment is not found
   (and says nothing about whether it exists elsewhere). An observed effect must
   stand: its signature verifies now, it is an observed-effect key's, and its
   evidence is the document the signature names;
2. assigns each effect to ONE template (:func:`assurance.economics.engine.templates.select`,
   by precedence);
3. groups them into causal loss events by the GROUPING KEY (:func:`grouping_key`,
   :data:`GROUPING_VERSION`): the template (which encodes the effect type), the
   asset and the business process. Every observation of one SPINE effect joins ONE
   event, however far apart; an observed effect within :data:`GROUPING_WINDOW` of
   ANY member of an event joins it, so a key's events are the connected components
   of "within the window"; a hypothetical effect takes part in EVERY event of its
   key, and is PRICED in one of them (:func:`price`): the others list it and read
   none of its figures. Findings enabling one effect join that effect's events. The
   key never names a finding, so a finding never makes an event of its own;
4. reads, for each attribute an event's template reads, the value that gives the
   LARGER loss across the event's effects, at each point
   (:func:`assurance.economics.engine.templates.larger_loss`): joined effects never
   understate, and never depend on how their keys are spelled;
5. makes the scenario version, its build record, each effect's attributes as the
   scenario's parameters (each with the distribution it states, if it states one,
   held to the simulation's own range test of its figures, as the parameter
   set's are: spec, sections 19.2 and 25.1), each event's larger-loss values, the
   loss events, the
   effects and the findings they rest on, and each event's components through
   #146's models, CHECKS every row before its transaction, then writes them in one
   that only inserts (:func:`assurance.economics.models.check_build_rows`). The
   version records the deployment's SPINE system fingerprint as it is when it is
   built (:func:`current_system_fingerprint`), read before the transaction; one
   that cannot be computed is recorded as none, with the reason, and never fails
   the build.

IDEMPOTENT. A build's identity is the content digest of everything it is built from
(:func:`build_document`, :func:`build_digest`): the builder, grouping and pack
versions, the deployment, the parameter-set version and its digest, the currency,
the as-of date, every effect as resolved and every finding link. Building the same
inputs again returns the scenario already built, and never a second one; two builds
of the same inputs racing are refused by the database (the digest is unique per
deployment), and the later writes nothing. The system fingerprint is not in the
digest: it is the state the version was built in, observed, not something it is
built from, so a rebuild returns the version with the fingerprint it recorded.

Not on any stop path: only :mod:`assurance.economics.scenario_api` imports this
module, and :mod:`assurance.urls` imports that GUARDED (spec, section 2).
"""

from __future__ import annotations

import hashlib
import json
import uuid as _uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta
from datetime import timezone as dt_timezone

from django.db import transaction
from django.db.models import F

from assurance import composition, consequential, observed_effects, observed_outcomes
from assurance.authority_chain_records import effect_digest
from assurance.models import Asset, Finding, WorkflowChainOutcome

from .engine import formulas, governance, pack_registry
from .engine import loss as engine_loss
from .engine import money
from .engine import parameter_set as pset
from .engine import templates as tpl
from .engine.pack_inputs import PACK_INPUT_PREFIX
from .engine.parameters import POINTS, Parameter, ParameterRefused, Point
from .models import (
    BuildRows,
    CausalEffect,
    CustomerParameterSet,
    EffectFinding,
    FinancialParameter,
    FinancialScenario,
    LossComponent,
    LossEvent,
    ScenarioBuild,
    ScenarioReview,
    check_build_rows,
    insert_checked_rows,
)

#: The builder. A change to what a build writes from its inputs is a new version.
#: v2 writes grouping v2's events (spec, section 24.9, decision 12).
BUILDER_VERSION = "mythos.economics.scenario-builder/v2"
#: The grouping key (:func:`grouping_key`) and its window. A change to either is a
#: new version, so a build recorded under this one reads as it was built. v2 (the
#: owner's decision of 12 Oct 2026, options (a) and (b) of section 24.9): an
#: effect within the window of ANY member of an event joins it, and a hypothetical
#: effect takes part in every event of its key, priced in ONE (:func:`price`). v1
#: joined an effect within the window of an event's FIRST observation, and a
#: hypothetical effect to the key's first event only, so adding an effect could
#: split or move an event.
GROUPING_VERSION = "mythos.economics.grouping/v2"
#: The first grouping, whose builds list a hypothetical effect in one event only.
GROUPING_V1 = "mythos.economics.grouping/v1"
GROUPING_WINDOW = timedelta(hours=24)

#: The most effects and finding links one build declares. The body's size bounds
#: them too; these keep a build's writes small.
MAX_EFFECTS = 50
MAX_LINKS = 500

_REQUEST_REQUIRED = frozenset({"title", "parameter_set", "currency", "as_of", "effects"})
_REQUEST_OPTIONAL = frozenset({"findings", "supersedes", "pack"})
_SET_REQUIRED = frozenset({"set_key", "version"})
_EFFECT_REQUIRED = frozenset({"key", "origin", "effect_type", "asset", "business_process"})
_EFFECT_OPTIONAL = frozenset({"attributes", "observed_effect"})
_LINK_REQUIRED = frozenset({"finding", "effect", "role"})
_TITLE_MAX = 255
_EPOCH = datetime.min.replace(tzinfo=dt_timezone.utc)


# ===================================================================== pure part


@dataclass(frozen=True)
class EffectInput:
    """One effect as a build resolved it: its key, origin, type, asset (a uuid),
    business process and attributes; for an observed effect, the SPINE row's uuid,
    the digest its signature covers, the effect as the receipt names it, and when it
    was observed."""

    key: str
    origin: tpl.Origin
    effect_type: tpl.EffectType
    asset: str
    business_process: tpl.BusinessProcess
    attributes: Mapping[str, Parameter] = field(default_factory=dict)
    observed_effect: str = ""
    observation: str = ""
    spine_effect: str = ""
    occurred_at: datetime | None = None
    #: The distribution each attribute states, by attribute name, in its stored
    #: spelling; an attribute that states none is absent.
    distributions: Mapping[str, dict] = field(default_factory=dict)

    def canonical(self) -> dict:
        def attribute(name: str, parameter: Parameter) -> dict:
            row = parameter.as_dict()
            del row["name"], row["parameter_id"]
            # Only where one is stated: a build whose attributes state none keeps
            # the document, and the digest, it had before one could be stated.
            if name in self.distributions:
                row["distribution"] = self.distributions[name]
            return row

        return {
            "key": self.key,
            "origin": self.origin.value,
            "effect_type": self.effect_type.value,
            "asset": self.asset,
            "business_process": self.business_process.value,
            "observed_effect": self.observed_effect,
            "observation": self.observation,
            "spine_effect": self.spine_effect,
            "occurred_at": _instant_text(self.occurred_at),
            "attributes": {name: attribute(name, p) for name, p in sorted(self.attributes.items())},
        }


@dataclass(frozen=True)
class LinkInput:
    """One finding enabling one effect, in one role."""

    finding: str
    effect: str
    role: tpl.FindingRole

    def canonical(self) -> list:
        return [self.finding, self.effect, self.role.value]


@dataclass(frozen=True)
class Member:
    """One unit the grouping key is applied to: a finding enabling an effect, or an
    effect no finding enables (an observed effect, which rests on its observation)."""

    effect: EffectInput
    selection: tpl.Selection
    link: LinkInput | None = None


def grouping_key(member: Member) -> tuple[str, ...]:
    """The grouping key, :data:`GROUPING_VERSION`: the template the effect is
    assigned to (id and version), its asset and its business process. The effect
    type is not in it: the template encodes it, and two effect types one template
    takes on one asset and process are one loss (an approval bypass that moves money
    on ``payments`` IS the payment loss). The finding is NOT part of it: every
    finding that enables one effect has that effect's key, so findings never make
    events of their own."""
    chosen = member.selection.template
    effect = member.effect
    return (chosen.template_id, str(chosen.version), effect.asset, effect.business_process.value)


def _instant_text(instant: datetime | None) -> str | None:
    if instant is None:
        return None
    return instant.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def event_key(key: tuple[str, ...], anchor: datetime | None) -> str:
    """An event's key: stable for its grouping key and its earliest observation
    (``undated`` for one of hypothetical effects only), whatever findings it has."""
    material = json.dumps([GROUPING_VERSION, *key, _instant_text(anchor) or "undated"], separators=(",", ":"))
    return "ev-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


@dataclass(frozen=True)
class EventPlan:
    """One loss event to write: its key, template, grouping key, its earliest
    observation (``anchor``), every effect taking part in it (by when they occurred,
    the hypothetical ones last) and the findings that enable them. Its components
    read, for each attribute, the larger loss across ALL its effects: no effect
    leads.

    ``joined`` names the effects that take part in this event -- it lists them, with
    their findings -- but are RECORDED and PRICED in another: a hypothetical effect
    takes part in every event of its key, and its one
    :class:`~assurance.economics.models.CausalEffect` row (and its findings') is in
    the ONE event that reads its figures (:func:`price`; :func:`group` puts it in the
    key's first until then). An event reads no figure of an effect it joins: a
    hypothetical effect is never an occurrence of its own, and its loss is never
    counted once per event."""

    event_key: str
    template: tpl.Template
    grouping_key: tuple[str, ...]
    anchor: datetime | None
    effects: tuple[EffectInput, ...]
    selections: Mapping[str, tpl.Selection]
    links: tuple[LinkInput, ...]
    joined: tuple[str, ...] = ()

    @property
    def spine_effect(self) -> str:
        """The SPINE effect of the event's earliest observation; blank for an event
        of hypothetical effects only."""
        return self.effects[0].spine_effect if self.anchor is not None else ""

    @property
    def read(self) -> tuple[EffectInput, ...]:
        """The effects whose figures the event reads: every one taking part but those
        it only joins."""
        return tuple(e for e in self.effects if e.key not in self.joined)

    @property
    def trigger(self) -> str:
        """The event's effect types, sorted, joined by ``+``."""
        return "+".join(sorted({e.effect_type.value for e in self.effects}))


def _order(effect: EffectInput):
    return (effect.occurred_at is None, effect.occurred_at or _EPOCH, effect.spine_effect, effect.key)


def check_spine_declarations(effects: Iterable[EffectInput]) -> None:
    """Every observation of one SPINE effect is declared with one effect type, asset
    and business process (``spine_effect_inconsistent``): declaring it two ways
    would put one real effect in two loss events."""
    declared: dict[str, EffectInput] = {}
    for effect in sorted(effects, key=lambda e: e.key):
        if not effect.spine_effect:
            continue
        first = declared.setdefault(effect.spine_effect, effect)
        if (first.effect_type, first.asset, first.business_process) != (
            effect.effect_type,
            effect.asset,
            effect.business_process,
        ):
            raise tpl.BuildRefused("spine_effect_inconsistent", f"{first.key} and {effect.key}: {effect.spine_effect}")


def _connected(units: Mapping[str, list[EffectInput]]) -> list[list[EffectInput]]:
    """The events one key's units make (grouping v2): the connected components of
    "within :data:`GROUPING_WINDOW` of each other" over every observation of every
    unit, a unit (every observation of one SPINE effect) held together whatever the
    window. Ordered by their earliest observation.

    On a line, two observations within the window are joined through every
    observation between them, each within the window of the next: so it is enough
    to join each observation, in time order, to the one before it when they are
    within the window."""
    names = sorted(units)
    parent = {name: name for name in names}

    def root(name: str) -> str:
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    observations = sorted((e.occurred_at, name, e.key) for name in names for e in units[name])
    for (before, earlier, _), (after, later, _) in zip(observations, observations[1:]):
        if after - before <= GROUPING_WINDOW:
            a, b = root(earlier), root(later)
            if a != b:
                parent[max(a, b)] = min(a, b)
    events: dict[str, list[EffectInput]] = {}
    for name in names:
        events.setdefault(root(name), []).extend(units[name])
    return sorted(events.values(), key=lambda members: min(e.occurred_at for e in members))


def group(
    effects: Iterable[EffectInput], links: Iterable[LinkInput], *, pack: pack_registry.Pack | None = None
) -> tuple[EventPlan, ...]:
    """The causal loss events ``effects`` and the findings enabling them (``links``)
    make, under ``pack`` (the banking pack unless an industry pack is given: spec,
    section 37). Pure and deterministic: the same inputs give the same events in the
    same order, whatever order they are given in.

    Each effect is assigned to one template (by precedence); the members -- every
    finding link, and every effect no finding enables -- are bucketed by
    :func:`grouping_key`. Within a bucket, the observed effects are first gathered by
    their SPINE effect: every observation of one effect is ONE unit, however far
    apart they are (one effect is one event). A unit with an observation within
    :data:`GROUPING_WINDOW` of an observation of ANY member of an event joins that
    event: a bucket's events are the connected components of "within the window"
    (:func:`_connected`), so adding an effect can merge events but never split one or
    move an effect from one to another. An effect with no instant (a hypothetical
    one) cannot be placed in a window and is never counted as an occurrence of its
    own: it takes part in EVERY event of its bucket -- recorded in the first, and
    ``joined`` to the rest, until :func:`price` moves it to the event where it adds
    the most -- so which event is first never decides what it adds; in a bucket with
    no observed effect, the hypothetical effects make one event together. One SPINE
    effect declared two ways is refused (:func:`check_spine_declarations`)."""
    effects = tuple(effects)
    links = tuple(links)
    pack = pack_registry.BANKING if pack is None else pack
    check_spine_declarations(effects)
    by_key = {e.key: e for e in effects}
    selections = {e.key: pack.select(e.effect_type, e.business_process) for e in effects}
    members: list[Member] = []
    linked: set[str] = set()
    for link in links:
        members.append(Member(by_key[link.effect], selections[link.effect], link))
        linked.add(link.effect)
    for effect in effects:
        if effect.key not in linked:
            members.append(Member(effect, selections[effect.key]))
    buckets: dict[tuple[str, ...], list[Member]] = {}
    for member in members:
        buckets.setdefault(grouping_key(member), []).append(member)
    plans: list[EventPlan] = []
    for key in sorted(buckets):
        bucket = buckets[key]
        distinct = sorted({m.effect.key: m.effect for m in bucket}.values(), key=_order)
        units: dict[str, list[EffectInput]] = {}
        undated: list[EffectInput] = []
        for effect in distinct:
            if effect.occurred_at is None:
                undated.append(effect)
            else:
                units.setdefault(effect.spine_effect or f"effect:{effect.key}", []).append(effect)
        windows = _connected(units)
        # Every hypothetical effect takes part in every event of the key; its row is
        # recorded in the first (the earliest), and it is joined to the others, until
        # price() records it where it adds the most.
        recorded_elsewhere = tuple(sorted(e.key for e in undated)) if windows else ()
        for window in windows:
            window.extend(undated)
        if not windows and undated:
            windows.append(list(undated))
        for index, window in enumerate(windows):
            window.sort(key=_order)
            keys = {e.key for e in window}
            window_links = tuple(
                sorted(
                    (m.link for m in bucket if m.link is not None and m.effect.key in keys),
                    key=lambda link: (link.effect, link.finding),
                )
            )
            anchor = window[0].occurred_at
            plans.append(
                EventPlan(
                    event_key=event_key(key, anchor),
                    template=selections[window[0].key].template,
                    grouping_key=key,
                    anchor=anchor,
                    effects=tuple(window),
                    selections={e.key: selections[e.key] for e in window},
                    links=window_links,
                    joined=recorded_elsewhere if index else (),
                )
            )
    return tuple(sorted(plans, key=lambda p: p.event_key))


def gross_cash(plan: EventPlan, effects: Iterable[EffectInput], variables: Mapping[str, Parameter], *,
               currency: str, as_of: date, inputs: Mapping[str, Parameter] | None = None) -> tuple:
    """The gross cash loss (low, base, high, as decimals) ``plan``'s template makes
    of ``effects``: each attribute it reads at the larger loss across them
    (:func:`~assurance.economics.engine.templates.larger_loss`), each component by
    its formula from those and the parameter set's ``variables`` (and, under an
    industry pack, its ``inputs``), the components summed, gross of insurance and
    apart from market value. An unknown component adds nothing, as in the event's own
    total. Pure: what the build would write for an event of exactly ``effects``."""
    effects = tuple(effects)
    attributes: dict[str, Parameter] = {}
    for name, reading in sorted(tpl.readings(plan.template).items()):
        stated = {e.key: e.attributes[name] for e in effects if name in e.attributes}
        if stated:
            attributes[name] = tpl.larger_loss(reading, stated, event_key=plan.event_key).parameter
    components = tuple(
        formulas.evaluate(
            planned.spec.component_key,
            planned.spec.family,
            planned.spec.formula_id,
            planned.spec.formula_version,
            planned.bindings(),
            as_of=as_of,
        )
        for planned in tpl.plan(plan.template, variables, attributes, inputs)
    )
    total = engine_loss.assess(engine_loss.LossEvent(plan.event_key, currency, components), None).gross.total
    return tuple(total.at(point).amount for point in POINTS)


def price(plans: Iterable[EventPlan], variables: Mapping[str, Parameter], *, currency: str,
          as_of: date, inputs: Mapping[str, Parameter] | None = None) -> tuple[EventPlan, ...]:
    """``plans`` with each key's hypothetical effects PRICED in ONE event (grouping
    v2; the lead's call of 12 Oct 2026 on the owner's decision 12, spec 24.9).

    A hypothetical effect takes part in every event of its key, but its figures are
    read by one: the event where the key's hypothetical effects add the most gross
    cash loss at BASE -- the event's loss with them, less its loss without them --
    ties going to the larger gain at high, then at low, then to the earliest event.
    That event records them (their rows and their findings') and reads their
    figures; every other event of the key lists them, ``joined``, and reads none.
    So a hypothetical effect's loss is counted once, never once per event. A key with
    one event, or with no hypothetical effect, is as :func:`group` made it."""
    plans = tuple(plans)
    by_key: dict[tuple[str, ...], list[EventPlan]] = {}
    for plan in plans:
        by_key.setdefault(plan.grouping_key, []).append(plan)
    priced: dict[str, EventPlan] = {}
    for events in by_key.values():
        hypothetical = tuple(sorted(e.key for e in events[0].effects if e.occurred_at is None))
        if not hypothetical or len(events) == 1:
            priced.update((p.event_key, replace(p, joined=())) for p in events)
            continue
        events.sort(key=lambda p: p.anchor)

        def gain(index: int, events=events) -> tuple:
            plan = events[index]
            observed = [e for e in plan.effects if e.occurred_at is not None]
            alone = gross_cash(plan, observed, variables, currency=currency, as_of=as_of, inputs=inputs)
            joined = gross_cash(plan, plan.effects, variables, currency=currency, as_of=as_of, inputs=inputs)
            low, base, high = (j - a for j, a in zip(joined, alone, strict=True))
            return (base, high, low, -index)

        chosen = max(range(len(events)), key=gain)
        priced.update(
            (p.event_key, replace(p, joined=() if index == chosen else hypothetical)) for index, p in enumerate(events)
        )
    return tuple(priced[p.event_key] for p in plans)


def build_document(
    *,
    deployment_uuid: str,
    parameter_set: Mapping[str, object],
    currency: str,
    as_of: date,
    effects: Iterable[EffectInput],
    links: Iterable[LinkInput],
    pack: pack_registry.Pack | None = None,
) -> dict:
    """Everything a build is built from, canonical: what its digest is taken over
    and what its record keeps. A title and the scenario superseded are not here:
    they name the draft and do not change its events. The pack is the build's ONE
    pack, its id and version and every template of it (the banking pack's unless an
    industry pack is given): a banking build's document is the one it was before E7,
    byte for byte (spec, section 37)."""
    pack = pack_registry.BANKING if pack is None else pack
    return {
        "builder": BUILDER_VERSION,
        "grouping": GROUPING_VERSION,
        "grouping_window_hours": int(GROUPING_WINDOW.total_seconds() // 3600),
        "pack": pack.pack_id,
        "templates": [[t.template_id, t.version] for t in pack.templates],
        "deployment": deployment_uuid,
        "parameter_set": dict(parameter_set),
        "currency": currency,
        "as_of": as_of.isoformat(),
        "effects": [e.canonical() for e in sorted(effects, key=lambda e: e.key)],
        "findings": sorted(link.canonical() for link in links),
    }


def build_digest(document: Mapping) -> str:
    """``sha256:`` + hex over the build document's canonical JSON."""
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ============================================================= the request


@dataclass(frozen=True)
class EffectRequest:
    key: str
    origin: tpl.Origin
    effect_type: tpl.EffectType  # or the build's industry pack's effect type
    asset: str
    business_process: tpl.BusinessProcess  # or the build's industry pack's process
    attributes: Mapping[str, Parameter]
    observed_effect: str
    distributions: Mapping[str, dict] = field(default_factory=dict)


@dataclass(frozen=True)
class BuildRequest:
    """A build request read exactly, before anything is resolved."""

    title: str
    set_key: str
    set_version: int
    currency: str
    as_of: date
    effects: tuple[EffectRequest, ...]
    links: tuple[LinkInput, ...]
    supersedes: str | None
    #: The ONE pack the build is under (spec, section 37): the banking pack unless the
    #: request names an industry pack.
    pack: pack_registry.Pack = pack_registry.BANKING


def _uuid_text(value, path: str) -> str:
    """A uuid as text, in its one spelling (lowercase, hyphenated)."""
    try:
        parsed = _uuid.UUID(value) if isinstance(value, str) else None
    except ValueError:
        parsed = None
    if parsed is None or str(parsed) != value:
        raise ParameterRefused("field_malformed", f"{path} is not a uuid in its lowercase, hyphenated spelling")
    return value


def _list(value, path: str, most: int) -> list:
    if not isinstance(value, list):
        raise ParameterRefused("field_malformed", f"{path} is not a list")
    if len(value) > most:
        raise ParameterRefused("field_malformed", f"{path} holds more than {most}")
    return value


def parse_request(body) -> BuildRequest:
    """A build request read from ``body``, or refused with the engine's or the
    builder's code and the field's path. Exactly the fields, at every level. A body
    that names no ``pack`` is under the banking pack; one that names an industry
    pack is read against that pack's vocabularies and attributes (spec, section 37)."""
    body = pset._object(body, "body", _REQUEST_REQUIRED, _REQUEST_OPTIONAL)
    pack = pack_registry.pack_of(body.get("pack"), "pack")
    title = body["title"]
    if not isinstance(title, str) or not title.strip() or len(title) > _TITLE_MAX:
        raise ParameterRefused("field_malformed", f"title is text of 1 to {_TITLE_MAX} characters")
    chosen = pset._object(body["parameter_set"], "parameter_set", _SET_REQUIRED, frozenset())
    set_key = pset.check_set_key(chosen["set_key"])
    version = chosen["version"]
    if type(version) is not int or version < 1:
        raise ParameterRefused("field_malformed", "parameter_set.version is a whole number from 1")
    currency = money.check_reporting_currency(body["currency"], "currency")
    as_of = pset._date(body["as_of"], "as_of")

    effects: list[EffectRequest] = []
    seen: set[str] = set()
    raw_effects = _list(body["effects"], "effects", MAX_EFFECTS)
    if not raw_effects:
        raise ParameterRefused("field_missing", "effects: a build declares at least one effect")
    for index, raw in enumerate(raw_effects):
        path = f"effects[{index}]"
        raw = pset._object(raw, path, _EFFECT_REQUIRED, _EFFECT_OPTIONAL)
        key = tpl.check_effect_key(raw["key"])
        if key in seen:
            raise ParameterRefused("duplicate_id", f"{path}: effect {key!r} twice in one build")
        seen.add(key)
        origin = tpl.check_origin(raw["origin"], f"{path}.origin")
        observed = raw.get("observed_effect")
        if origin is tpl.Origin.OBSERVED:
            if observed is None:
                raise ParameterRefused("field_missing", f"{path}: ['observed_effect']")
            observed = _uuid_text(observed, f"{path}.observed_effect")
        elif observed is not None:
            raise ParameterRefused("field_unrecognised", f"{path}: ['observed_effect'] on a hypothetical effect")
        raw_attributes = raw.get("attributes", {})
        attributes = pack.parse_attributes(key, raw_attributes, f"{path}.attributes", origin=origin)
        # The distribution an attribute states, read as the parameter set reads one
        # (pset.stated_distribution); it is held to its figures when its row is checked.
        distributions = {}
        for name in sorted(attributes):
            stated = pset.stated_distribution(raw_attributes[name], f"{path}.attributes.{name}")
            if stated is not None:
                distributions[name] = stated
        effects.append(
            EffectRequest(
                key=key,
                origin=origin,
                effect_type=pack.check_effect_type(raw["effect_type"], f"{path}.effect_type"),
                asset=_uuid_text(raw["asset"], f"{path}.asset"),
                business_process=pack.check_business_process(raw["business_process"], f"{path}.business_process"),
                attributes=attributes,
                observed_effect=observed or "",
                distributions=distributions,
            )
        )
    observed_twice = [e.observed_effect for e in effects if e.observed_effect]
    if len(set(observed_twice)) != len(observed_twice):
        raise ParameterRefused("duplicate_id", "one observed effect declared as two effects")

    links: list[LinkInput] = []
    pairs: set[tuple[str, str]] = set()
    for index, raw in enumerate(_list(body.get("findings", []), "findings", MAX_LINKS)):
        path = f"findings[{index}]"
        raw = pset._object(raw, path, _LINK_REQUIRED, frozenset())
        finding = _uuid_text(raw["finding"], f"{path}.finding")
        effect = raw["effect"]
        if not isinstance(effect, str) or effect not in seen:
            raise tpl.BuildRefused("effect_not_declared", f"{path}.effect {effect!r}")
        if (finding, effect) in pairs:
            raise ParameterRefused("duplicate_id", f"{path}: finding {finding} enables effect {effect!r} twice")
        pairs.add((finding, effect))
        links.append(LinkInput(finding, effect, tpl.check_role(raw["role"], f"{path}.role")))
    enabled = {link.effect for link in links}
    for effect in effects:
        if effect.origin is tpl.Origin.HYPOTHETICAL and effect.key not in enabled:
            raise tpl.BuildRefused("effect_without_finding", effect.key)

    supersedes = body.get("supersedes")
    if supersedes is not None:
        supersedes = _uuid_text(supersedes, "supersedes")
    return BuildRequest(
        title=title,
        set_key=set_key,
        set_version=version,
        currency=currency,
        as_of=as_of,
        effects=tuple(effects),
        links=tuple(links),
        supersedes=supersedes,
        pack=pack,
    )


# ====================================================== resolving, in the tenant


def observed_identity(deployment, row: WorkflowChainOutcome) -> tuple[str, str]:
    """``(observation, spine_effect)`` for a SPINE observed effect that stands -- the
    digest its signature covers, and the effect as a receipt names it (workflow and
    tool, ``sha256:`` + hex) -- or ``observed_effect_not_in_force``. A
    ``MYTHOS_OBSERVED`` attribute's evidence is bound to the second
    (:func:`~assurance.economics.engine.templates.names_observed_effect`)."""
    deployment_uuid = str(deployment.uuid)
    basis = observed_outcomes.basis_in_force(row, observed_outcomes.trusted_keyring(), deployment_uuid=deployment_uuid)
    document = observed_effects.evidence_in_force(row, deployment_uuid)
    if (
        row.status != composition.HELD
        or composition.evidence_kind(basis, row.observer_engine) != composition.EVIDENCE_OBSERVED_EFFECT
        or document is None
    ):
        raise tpl.BuildRefused("observed_effect_not_in_force", str(row.uuid))
    tool = document["tool"]
    effect = consequential.Effect(
        workflow=document["workflow"],
        kind=tool["kind"],
        identifier=tool["identifier"],
        effect_class=None,
        klass=consequential.UNKNOWN,
        status=consequential.UNKNOWN,
        reasons=(),
    )
    return row.evidence_digest, effect_digest(effect, deployment_uuid)


@dataclass(frozen=True)
class Resolved:
    """A request resolved in its deployment: the parameter-set version and its
    variables, every effect, the findings, and the scenario superseded."""

    request: BuildRequest
    parameter_set: CustomerParameterSet
    variables: Mapping[str, Parameter]
    set_rows: tuple[FinancialParameter, ...]
    effects: tuple[EffectInput, ...]
    supersedes: FinancialScenario | None
    document: dict
    digest: str
    #: The industry pack's inputs the parameter set states, by input name (none for
    #: a banking build).
    inputs: Mapping[str, Parameter] = field(default_factory=dict)


def check_set_distributions(rows: Iterable[FinancialParameter]) -> None:
    """Each distribution the named parameter-set version states, held again to the
    rule a run applies NOW (spec, sections 19.4 and 25.1; review round 1, LOW-3): a
    version recorded under an earlier rule or floor is refused here, with the run's
    code and detail word for word, never built and then refused by its run. A version
    that states none never imports the probabilistic engine; one that does while the
    engine will not import is :class:`~.engine.parameter_set.ProbabilisticEngineUnavailable`
    (503), and nothing is built."""
    stated = sorted((row for row in rows if row.distribution is not None), key=lambda row: (row.name, row.id))
    if not stated:
        return
    pset.probabilistic_engine("the parameter set's distributions")
    for row in stated:
        row.checked_distribution(row.as_engine())


def resolve(deployment, request: BuildRequest) -> Resolved:
    """Resolve every reference of ``request`` in ``deployment``, and only there."""
    version = CustomerParameterSet.objects.filter(
        deployment=deployment, set_key=request.set_key, version=request.set_version
    ).first()
    if version is None:
        raise tpl.BuildRefused("parameter_set_not_found", f"{request.set_key} version {request.set_version}")
    rows = version.parameter_rows()
    if not version.intact(rows):
        raise tpl.BuildRefused("parameter_set_not_found", f"{request.set_key} version {request.set_version} is not intact")
    # One pack per build: the version answers the build's pack, and states every input
    # the pack requires (spec, section 37).
    request.pack.check_set(version.pack)
    check_set_distributions(rows)
    content = version.content(rows)
    variables = content.variables
    inputs = content.pack_inputs
    request.pack.check_inputs(inputs)

    wanted = {e.asset for e in request.effects}
    found = {str(u) for u in Asset.objects.filter(deployment=deployment, uuid__in=wanted).values_list("uuid", flat=True)}
    missing = sorted(wanted - found)
    if missing:
        raise tpl.BuildRefused("asset_not_found", ", ".join(missing))

    wanted = {link.finding for link in request.links}
    found = {
        str(u) for u in Finding.objects.filter(deployment=deployment, uuid__in=wanted).values_list("uuid", flat=True)
    }
    missing = sorted(wanted - found)
    if missing:
        raise tpl.BuildRefused("finding_not_found", ", ".join(missing))

    wanted = {e.observed_effect for e in request.effects if e.observed_effect}
    rows_by_uuid = {
        str(row.uuid): row
        for row in WorkflowChainOutcome.objects.filter(
            deployment=deployment, uuid__in=wanted, effect_evidence__isnull=False
        )
    }
    missing = sorted(wanted - set(rows_by_uuid))
    if missing:
        raise tpl.BuildRefused("observed_effect_not_found", ", ".join(missing))

    effects = []
    for request_effect in request.effects:
        observation = spine_effect = ""
        occurred_at = None
        if request_effect.origin is tpl.Origin.OBSERVED:
            row = rows_by_uuid[request_effect.observed_effect]
            observation, spine_effect = observed_identity(deployment, row)
            occurred_at = row.observed_at
            tpl.check_observed_evidence(request_effect.key, request_effect.attributes, spine_effect)
        effects.append(
            EffectInput(
                key=request_effect.key,
                origin=request_effect.origin,
                effect_type=request_effect.effect_type,
                asset=request_effect.asset,
                business_process=request_effect.business_process,
                attributes=request_effect.attributes,
                observed_effect=request_effect.observed_effect,
                observation=observation,
                spine_effect=spine_effect,
                occurred_at=occurred_at,
                distributions=request_effect.distributions,
            )
        )
    observations = [e.observation for e in effects if e.observation]
    if len(set(observations)) != len(observations):
        raise ParameterRefused("duplicate_id", "one SPINE observation declared as two effects")
    check_spine_declarations(effects)
    # Every pack input a template the build uses reads is stated: refused, never
    # defaulted and never left unknown (spec, section 37). No banking template reads one.
    if not request.pack.banking:
        for effect in sorted(effects, key=lambda e: e.key):
            chosen = request.pack.select(effect.effect_type, effect.business_process).template
            request.pack.check_template_inputs(chosen, inputs)

    supersedes = None
    if request.supersedes is not None:
        supersedes = FinancialScenario.objects.filter(deployment=deployment, uuid=request.supersedes).first()
        if supersedes is None:
            raise tpl.BuildRefused("scenario_not_found", request.supersedes)

    document = build_document(
        deployment_uuid=str(deployment.uuid),
        parameter_set={"set_key": version.set_key, "version": version.version, "content_digest": version.content_digest},
        currency=request.currency,
        as_of=request.as_of,
        effects=effects,
        links=request.links,
        pack=request.pack,
    )
    return Resolved(
        request, version, variables, tuple(rows), tuple(effects), supersedes, document, build_digest(document), inputs
    )


# ================================================================ writing it


def existing(deployment, digest: str) -> FinancialScenario | None:
    """The scenario a build of these inputs already made in ``deployment``."""
    row = ScenarioBuild.objects.filter(deployment=deployment, build_digest=digest).first()
    return None if row is None else FinancialScenario.objects.get(pk=row.scenario_id)


#: Why a version records no system fingerprint, in fixed words: the reason is shown
#: on the card, the customer's, so a fault is named by its type alone -- its message
#: can carry a SQL fragment, a path or a value -- and a value not in SPINE's form is
#: never echoed.
FINGERPRINT_NOT_COMPUTED = "the system fingerprint could not be computed ({fault})"
FINGERPRINT_NOT_IN_FORM = "the system fingerprint computed is not in SPINE's form (64 lowercase hex)"


def current_system_fingerprint(deployment_id) -> tuple[str, str]:
    """The deployment's SPINE system fingerprint as it stands now
    (:func:`assurance.fingerprint.compute_system_fingerprint`), in the form a scenario
    version holds it -- 64 lowercase hex, the ``system_fingerprint`` form of
    :data:`~assurance.economics.engine.governance.REFERENCE_FORMS` -- and ``""``; or
    ``""`` and why there is none, in fixed words: it could not be computed
    (:data:`FINGERPRINT_NOT_COMPUTED`, naming the fault's type and never its message),
    or what was computed is not in that form (:data:`FINGERPRINT_NOT_IN_FORM`, never
    echoing it). Never one made up, and never raises: a build never fails over its
    fingerprint. Reads only; the card reads the deployment's at issue through it too,
    where a version records none."""
    try:
        from assurance.fingerprint import compute_system_fingerprint
        from assurance.models import Deployment

        deployment = (
            Deployment.objects.prefetch_related("assets__provider__assertions")
            .select_related("data_boundary")
            .get(pk=deployment_id)
        )
        value = compute_system_fingerprint(deployment)
    except Exception as error:  # noqa: BLE001 - none, with the fault's type: never a failed build
        return "", FINGERPRINT_NOT_COMPUTED.format(fault=type(error).__name__)
    if governance.spine_reference_refusal("system_fingerprint", value) is not None:
        return "", FINGERPRINT_NOT_IN_FORM
    return value, ""


def build_rows(deployment, resolved: Resolved, *, author, fingerprint: tuple[str, str]) -> BuildRows:
    """Every row the build of ``resolved`` writes, made (not saved): the scenario
    version, its build record, each effect's attributes, each event's larger-loss
    values, the events, the effects, the findings they rest on and the components.
    The version records ``fingerprint``, :func:`current_system_fingerprint`'s pair:
    the deployment's system fingerprint when it was built, or none and why. Pure but
    for the ids each row is given; nothing is read or written."""
    request = resolved.request
    plans = price(
        group(resolved.effects, request.links, pack=request.pack),
        resolved.variables,
        currency=request.currency,
        as_of=request.as_of,
        inputs=resolved.inputs,
    )
    value, unavailable = fingerprint
    scenario = FinancialScenario(
        deployment=deployment,
        title=request.title,
        author=author,
        supersedes=resolved.supersedes,
        system_fingerprint=value,
        system_fingerprint_unavailable=unavailable,
    )
    build_row = ScenarioBuild(
        scenario=scenario,
        deployment=deployment,
        parameter_set=resolved.parameter_set,
        build_digest=resolved.digest,
        builder_version=BUILDER_VERSION,
        grouping_version=GROUPING_VERSION,
        pack=request.pack.pack_id,
        currency=request.currency,
        as_of=request.as_of,
        inputs=resolved.document,
    )
    parameters: list[FinancialParameter] = []
    stored: dict[str, dict[str, FinancialParameter]] = {}
    for effect in resolved.effects:
        stored[effect.key] = {}
        for name, parameter in sorted(effect.attributes.items()):
            row = FinancialParameter.from_engine(
                parameter, scenario=scenario, distribution=effect.distributions.get(name)
            )
            parameters.append(row)
            stored[effect.key][name] = row
    events: list[LossEvent] = []
    effects: list[CausalEffect] = []
    links: list[EffectFinding] = []
    components: list[LossComponent] = []
    for plan in plans:
        event = LossEvent(
            scenario=scenario,
            event_key=plan.event_key,
            currency=request.currency,
            effect=plan.spine_effect,
            business_process=plan.effects[0].business_process.value,
            trigger=plan.trigger,
        )
        events.append(event)
        for effect in plan.effects:
            if effect.key in plan.joined:
                # Recorded, with its findings, and priced in the one event of its key
                # that reads its figures: here it is listed (describe), never read.
                continue
            selection = plan.selections[effect.key]
            row = CausalEffect(
                scenario=scenario,
                loss_event=event,
                effect_key=effect.key,
                origin=effect.origin.value,
                observed_effect=effect.observed_effect,
                observation=effect.observation,
                spine_effect=effect.spine_effect,
                effect_type=effect.effect_type.value,
                asset=effect.asset,
                business_process=effect.business_process.value,
                occurred_at=effect.occurred_at,
                template_id=selection.template.template_id,
                template_version=selection.template.version,
                in_scope_of=[[t.template_id, t.version] for t in selection.in_scope_of],
            )
            effects.append(row)
            links.extend(
                EffectFinding(effect=row, finding=link.finding, role=link.role.value)
                for link in plan.links
                if link.effect == effect.key
            )
        # Each attribute the template reads, at the larger loss across ALL the effects
        # the event reads -- never one it only joins: one effect stating it is read as
        # itself; more make a parameter of the scenario that cites each (derived_from).
        attributes: dict[str, Parameter] = {}
        for name, reading in sorted(tpl.readings(plan.template).items()):
            stated = {e.key: stored[e.key][name] for e in plan.read if name in stored[e.key]}
            if not stated:
                continue
            merged = tpl.larger_loss(reading, {k: r.as_engine() for k, r in stated.items()}, event_key=plan.event_key)
            if merged.derived:
                row = FinancialParameter.from_engine(merged.parameter, scenario=scenario)
                row.derived_from = [str(stated[k].uuid) for k in merged.contributors]
                parameters.append(row)
                attributes[name] = row.as_engine()
            else:
                attributes[name] = merged.parameter
        for planned in tpl.plan(plan.template, resolved.variables, attributes, resolved.inputs):
            components.append(
                LossComponent(
                    loss_event=event,
                    component_key=planned.spec.component_key,
                    family=planned.spec.family,
                    formula_id=planned.spec.formula_id,
                    formula_version=planned.spec.formula_version,
                    as_of=request.as_of,
                    cited_parameters={name: p.parameter_id for name, p in planned.bindings().items()},
                )
            )
    return BuildRows(
        scenario=scenario,
        build=build_row,
        parameters=parameters,
        events=events,
        effects=effects,
        links=links,
        components=components,
        set_parameters={str(row.uuid): row for row in resolved.set_rows},
    )


def build(deployment, body, *, author) -> tuple[FinancialScenario, bool]:
    """Build the scenario ``body`` describes in ``deployment``, authored by
    ``author``: ``(scenario, created)``. The same inputs return the scenario they
    built before (``created`` false), never a second. Refused whole, with the engine's
    or the builder's code, or written whole, in one transaction; a race with a build
    of the same inputs is the database's ``IntegrityError``, and nothing is written.

    Every row is made, and every check of every row run, BEFORE the transaction
    (:func:`assurance.economics.models.check_build_rows`): the transaction only
    inserts, so the write lock it holds on SQLite, which a stop's write waits for,
    is held for the inserts alone (spec, section 24.6). The deployment's system
    fingerprint is read before it too, and the version records it, or none and why."""
    resolved = resolve(deployment, parse_request(body))
    already = existing(deployment, resolved.digest)
    if already is not None:
        return already, False
    rows = build_rows(deployment, resolved, author=author, fingerprint=current_system_fingerprint(deployment.pk))
    check_build_rows(rows)
    with transaction.atomic():
        insert_checked_rows(rows)
    return rows.scenario, True


# ================================================================ reading it


def _total(totals: Iterable[engine_loss.Total], currency: str, unknown: list[str]) -> dict:
    totals = tuple(totals)
    sums = {
        point: money.Money.total((t.at(point) for t in totals), currency) for point in POINTS
    }
    complete = all(t.complete for t in totals) and not unknown
    total = engine_loss.Total(currency, sums[Point.LOW], sums[Point.BASE], sums[Point.HIGH], complete, tuple(unknown))
    return total.as_dict()


def scenario_totals(assessments: Iterable[engine_loss.Assessment], currency: str) -> dict:
    """The scenario's events summed: gross cash loss, each event's loss once (the
    events are distinct causal losses; this is each happening once, not an annual
    figure), and the market-value line apart, never added to cash."""
    assessments = tuple(assessments)
    gross = _total(
        (a.gross.total for a in assessments),
        currency,
        [f"{a.event.loss_event_id}/{c}" for a in assessments for c in a.gross.total.unknown],
    )
    market = _total(
        (a.market_value for a in assessments),
        currency,
        [f"{a.event.loss_event_id}/{c}" for a in assessments for c in a.market_value.unknown],
    )
    return {
        "events": len(assessments),
        "gross_cash": gross,
        "market_value": {**market, "never_added_to_cash": True},
        "reads_as": "each event's loss once, given it happens; not an annual figure",
    }


def _source(
    row: FinancialParameter | None,
    versions: Mapping[int, CustomerParameterSet],
    derived: Mapping[str, FinancialParameter],
) -> dict | None:
    if row is None:
        return None
    if row.parameter_set_id is not None:
        version = versions.get(row.parameter_set_id)
        kind, name = tpl.SourceKind.PARAMETER_SET.value, row.name
        if row.name.startswith(PACK_INPUT_PREFIX):
            # An industry pack's input, stated in the set beside its variables (section 37).
            kind, name = tpl.SourceKind.PACK_INPUT.value, row.name[len(PACK_INPUT_PREFIX):]
        return {
            "from": kind,
            "name": name,
            "parameter_set": {"set_key": version.set_key, "version": version.version} if version else None,
        }
    if row.derived_from:
        event, _, attribute = row.name.partition(":")
        taken = [derived[u] for u in row.derived_from if u in derived]
        return {
            "from": tpl.SourceKind.EFFECT_ATTRIBUTE.value,
            "name": attribute,
            "event": event,
            "rule": tpl.MERGE_RULE,
            "derived_from": [
                {"effect": r.name.partition(".")[0], "parameter": str(r.uuid), "source_type": r.source_type}
                for r in sorted(taken, key=lambda r: r.name)
            ],
        }
    effect, _, attribute = row.name.partition(".")
    return {"from": tpl.SourceKind.EFFECT_ATTRIBUTE.value, "name": attribute, "effect": effect}


def review_status(scenario: FinancialScenario) -> dict:
    """The scenario version's review state as its reviews record it: ``draft`` until
    one is recorded, then the latest one's verdict (``approved`` or ``returned``),
    with every review."""
    reviews = list(ScenarioReview.objects.filter(scenario=scenario).order_by("reviewed_at", "id"))
    return {
        "status": reviews[-1].verdict if reviews else "draft",
        "reviews": [
            {"reviewer": r.reviewer_username or None, "verdict": r.verdict, "reviewed_at": r.reviewed_at.isoformat()}
            for r in reviews
        ],
    }


def describe(scenario: FinancialScenario) -> dict:
    """The scenario's events as built: each with its template, grouping key, effects
    (by when they occurred) and the findings enabling them, its components with the
    formula and, for every input, the parameter it read and where that came from (the
    parameter set's variable, the effect's attribute, or the larger loss across the
    event's effects, citing each), its gross cash loss, its
    loss net of the parameter set's insurance where the set states a policy, and the
    market-value line apart; and the scenario's totals.

    From grouping v2 on, an event lists every effect taking part in it: a
    hypothetical effect of its key, recorded and priced in one event of the key, is
    listed in every other, with its findings, and marked ``joined`` there (its figures
    are read only where it is recorded). A build recorded under v1 reads as it was
    built: there it took part in one event only."""
    build_row = ScenarioBuild.objects.filter(scenario=scenario).first()
    joins = build_row is not None and build_row.grouping_version != GROUPING_V1
    policy = None
    versions: dict[int, CustomerParameterSet] = {}
    if build_row is not None:
        version = CustomerParameterSet.objects.get(pk=build_row.parameter_set_id)
        versions[version.pk] = version
        policy = version.content().insurance_policy()
    currency = build_row.currency if build_row is not None else None
    events = []
    assessments = []
    for event in LossEvent.objects.filter(scenario=scenario).order_by("event_key"):
        currency = currency or event.currency
        engine_event = event.as_engine()
        assessment = engine_loss.assess(engine_event, policy)
        assessments.append(assessment)
        effects = list(
            CausalEffect.objects.filter(loss_event=event).order_by(
                F("occurred_at").asc(nulls_last=True), "spine_effect", "effect_key"
            )
        )
        first = effects[0] if effects else None
        if joins and first is not None:
            # The hypothetical effects of the event's key recorded (and priced) in
            # another of its events: each takes part in this one too (grouping v2),
            # after its observed effects, by key, as the plan ordered them.
            effects += list(
                CausalEffect.objects.filter(
                    scenario=scenario,
                    origin=tpl.Origin.HYPOTHETICAL.value,
                    template_id=first.template_id,
                    template_version=first.template_version,
                    asset=first.asset,
                    business_process=first.business_process,
                )
                .exclude(loss_event=event)
                .order_by("effect_key")
            )
        links = list(EffectFinding.objects.filter(effect__in=effects).order_by("finding", "id"))
        findings = {
            str(f.uuid): f
            for f in Finding.objects.filter(deployment_id=scenario.deployment_id, uuid__in={x.finding for x in links})
        }
        chosen = pack_registry.template(first.template_id, first.template_version) if first else None
        specs = {c.component_key: c for c in chosen.components} if chosen else {}
        component_rows = list(LossComponent.objects.filter(loss_event=event).order_by("id"))
        cited = {
            str(row.uuid): row
            for row in FinancialParameter.objects.filter(
                uuid__in=[v for c in component_rows for v in c.cited_parameters.values()]
            )
        }
        for row in cited.values():
            if row.parameter_set_id is not None and row.parameter_set_id not in versions:
                versions[row.parameter_set_id] = CustomerParameterSet.objects.get(pk=row.parameter_set_id)
        derived = {
            str(row.uuid): row
            for row in FinancialParameter.objects.filter(
                scenario=scenario, uuid__in=[u for row in cited.values() for u in row.derived_from]
            )
        }
        components = []
        for row, component in zip(component_rows, engine_event.components, strict=True):
            spec = specs.get(row.component_key)
            sources = {}
            for name in (spec.sources if spec else row.cited_parameters):
                read = cited.get(row.cited_parameters.get(name, ""))
                sources[name] = {
                    "template": spec.sources[name].as_dict() if spec else None,
                    "read": _source(read, versions, derived),
                    "parameter": str(read.uuid) if read else None,
                }
            components.append({**component.as_dict(), "sources": sources})
        record = assessment.as_dict()
        record["components"] = components
        events.append(
            {
                "event_key": event.event_key,
                "currency": event.currency,
                "effect": event.effect or None,
                "business_process": event.business_process,
                "trigger": event.trigger,
                "template": chosen.as_dict() if chosen else None,
                "grouping": {
                    "version": build_row.grouping_version if build_row else None,
                    "key": {
                        "template": [first.template_id, first.template_version],
                        "asset": first.asset,
                        "business_process": first.business_process,
                    }
                    if first
                    else None,
                },
                "effects": [
                    {
                        "key": e.effect_key,
                        "origin": e.origin,
                        "observed_effect": e.observed_effect or None,
                        "observation": e.observation or None,
                        "spine_effect": e.spine_effect or None,
                        "effect_type": e.effect_type,
                        "asset": e.asset,
                        "business_process": e.business_process,
                        "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
                        "template": [e.template_id, e.template_version],
                        "in_scope_of": e.in_scope_of,
                        "joined": e.loss_event_id != event.pk,
                        "attributes": {
                            row.name.partition(".")[2]: {**row.as_engine().as_dict(), "distribution": row.distribution}
                            for row in e.attribute_rows()
                        },
                        "findings": [
                            {
                                "finding": x.finding,
                                "role": x.role,
                                "title": findings[x.finding].title if x.finding in findings else None,
                                "found": x.finding in findings,
                            }
                            for x in links
                            if x.effect_id == e.pk
                        ],
                    }
                    for e in effects
                ],
                "findings": sorted({x.finding for x in links}),
                **record,
            }
        )
    return {
        "scenario": {
            "uuid": str(scenario.uuid),
            "title": scenario.title,
            "author": scenario.author_username or None,
            "recorded_at": scenario.recorded_at.isoformat(),
            "supersedes": str(FinancialScenario.objects.get(pk=scenario.supersedes_id).uuid)
            if scenario.supersedes_id
            else None,
            "system_fingerprint": scenario.system_fingerprint or None,
            "system_fingerprint_unavailable": scenario.system_fingerprint_unavailable or None,
            **review_status(scenario),
        },
        "build": None
        if build_row is None
        else {
            "digest": build_row.build_digest,
            "builder": build_row.builder_version,
            "grouping": build_row.grouping_version,
            "pack": build_row.pack,
            "currency": build_row.currency,
            "as_of": build_row.as_of.isoformat(),
            "parameter_set": build_row.inputs.get("parameter_set"),
        },
        "events": events,
        "totals": scenario_totals(assessments, currency) if currency else None,
    }


__all__ = [
    "BUILDER_VERSION",
    "GROUPING_VERSION",
    "GROUPING_WINDOW",
    "BuildRequest",
    "EffectInput",
    "EventPlan",
    "LinkInput",
    "Member",
    "build",
    "build_digest",
    "build_document",
    "build_rows",
    "check_spine_declarations",
    "current_system_fingerprint",
    "describe",
    "event_key",
    "gross_cash",
    "group",
    "grouping_key",
    "observed_identity",
    "parse_request",
    "price",
    "resolve",
    "review_status",
    "scenario_totals",
]
