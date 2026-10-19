"""What every industry pack is made of (Economic Exposure E7;
``docs/economics/spec-v1.md``, section 37): the :class:`Pack` itself, and the
statements a vertical pack carries -- the physical-world caution and what no pack
prices. The registry (:mod:`.pack_registry`) holds the packs; each industry pack's
module (``pack_<vertical>.py``) builds its :class:`Pack` from these.

Pure: no Django, no database, no clock and no randomness.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from functools import cached_property
from types import MappingProxyType

from . import pack_inputs as schemas
from . import templates as tpl
from .parameters import Parameter, ParameterRefused

#: What a physical-world template's figures are read with (the owner's specification,
#: sections 32 and 37): it travels with the template wherever its figures are shown.
PHYSICAL_WORLD_CAUTION = (
    "a physical-world effect (owner's specification, sections 32 and 37): the evidence shows the effect is "
    "technically plausible, not that it happens at the size these figures state; they are ranges for decision "
    "support, never a prediction (false precision), and a benchmark among them is a prior, never the customer's "
    "truth; physical damage is its own heavy-tail component, never folded into the operational loss; harm to a "
    "person is never priced here (safety_monetisation_refused): it is excluded, and listed as such"
)

#: What no industry pack prices, stated with every vertical pack.
HARM_EXCLUDED = (
    "harm to a person -- an injury, a death, a patient's or the public's safety -- is never priced: no "
    "owner-approved model of it exists (spec, section 37, choices for the owner); an effect type, attribute or "
    "input that names it is refused (safety_monetisation_refused)"
)


@dataclass(frozen=True)
class Pack:
    """One pack: its id (with its version), vertical and name; its vocabularies --
    effect types (an enum, each code with its meaning) and business processes (an
    enum) -- the attributes an effect may state, its templates in precedence order,
    its customer-input schema (none for banking), and what it never prices. Its
    :attr:`digest` is taken over all of that (:meth:`as_dict`): the registry holds
    each pack version with the digest it was released with, and a version's content
    never changes under its id (:mod:`.pack_registry`)."""

    pack_id: str
    vertical: str
    name: str
    effect_type_codes: type[StrEnum]
    effect_types: Mapping[str, str]
    business_process_codes: type[StrEnum]
    attributes: Mapping[str, tpl.Attribute]
    templates: tuple[tpl.Template, ...]
    inputs: Mapping[str, schemas.PackInput] = field(default_factory=dict)
    excluded: tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "effect_types", MappingProxyType(dict(self.effect_types)))
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))
        object.__setattr__(self, "inputs", MappingProxyType(dict(self.inputs)))
        object.__setattr__(self, "templates", tuple(sorted(self.templates, key=lambda t: t.precedence)))

    # ------------------------------------------------------------ identity

    @property
    def banking(self) -> bool:
        return self.pack_id == tpl.PACK

    @property
    def catalogue(self) -> Mapping[tuple[str, int], tpl.Template]:
        return MappingProxyType({t.key: t for t in self.templates})

    @property
    def families(self) -> tuple[str, ...]:
        """The loss families the pack's templates price (market value apart), sorted."""
        return tuple(sorted({c.family for t in self.templates for c in t.components}))

    @property
    def business_processes(self) -> tuple[str, ...]:
        return tuple(p.value for p in self.business_process_codes)

    @property
    def cautions(self) -> tuple[str, ...]:
        """Every caution any of the pack's templates carries, once each, in order."""
        found: list[str] = []
        for chosen in self.templates:
            found.extend(c for c in chosen.cautions if c not in found)
        return tuple(found)

    @property
    def required_by(self) -> Mapping[str, tuple[str, ...]]:
        """Each input of the schema, with the templates whose builds require it -- the
        templates that read it -- in precedence order (choice 2: an input is required
        only by a build that reads it). An input only an optional component reads is
        required by none: stated, the component is made; not stated, it is absent."""
        return MappingProxyType(
            {
                name: tuple(
                    t.template_id
                    for t in self.templates
                    if any(
                        not c.optional and s.kind is tpl.SourceKind.PACK_INPUT and s.name == name
                        for c in t.components
                        for s in c.sources.values()
                    )
                )
                for name in self.inputs
            }
        )

    @cached_property
    def digest(self) -> str:
        """``sha256:`` + hex over the pack's canonical document (:meth:`as_dict`): its
        templates, vocabularies, attributes, schema, cautions and exclusions. The
        registry refuses a pack whose digest is not the one its version was released
        with (:data:`.pack_registry.RELEASED`)."""
        canonical = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def statements(self, chosen: Iterable[tpl.Template]) -> dict:
        """What a build of this pack whose effects were assigned to the templates
        ``chosen`` is read with, as the build records it (spec, section 37.3): the
        cautions those templates carry, once each, in order, and what the pack never
        prices. Recorded, so a report and a card state them even when a later release
        no longer holds the pack."""
        cautions: list[str] = []
        for template in chosen:
            cautions.extend(c for c in template.cautions if c not in cautions)
        return {"cautions": cautions, "excluded": list(self.excluded)}

    # ------------------------------------------------------------ the checks

    def _refuse_harm(self, value, path: str) -> None:
        # The banking pack is unchanged: its vocabulary names no physical effect, and its
        # refusals stay exactly what they were.
        if not self.banking:
            schemas.refuse_harm(value, path)

    def check_effect_type(self, value, what: str = "effect_type") -> StrEnum:
        self._refuse_harm(value, what)
        return tpl._code(self.effect_type_codes, value, "effect_type_unrecognised", what)

    def check_business_process(self, value, what: str = "business_process") -> StrEnum:
        return tpl._code(self.business_process_codes, value, "business_process_unrecognised", what)

    def parse_attributes(self, effect_key: str, raw, path: str, *, origin: tpl.Origin) -> dict[str, Parameter]:
        """An effect's attributes read as :func:`.templates.parse_attributes` reads
        them, against this pack's attributes; one that names harm to a person is
        ``safety_monetisation_refused`` (a vertical pack's rule)."""
        if isinstance(raw, dict):
            for name in sorted(str(k) for k in raw):
                self._refuse_harm(name, f"{path}:")
        if self.banking:
            return tpl.parse_attributes(effect_key, raw, path, origin=origin)
        return tpl.parse_attributes(effect_key, raw, path, origin=origin, attributes=self.attributes)

    def in_scope(self, effect_type: str, business_process: str) -> tuple[tpl.Template, ...]:
        """Every template of the pack that covers ``effect_type`` on
        ``business_process``, in precedence order."""
        if self.banking:
            return tpl.in_scope(effect_type, business_process)
        self.check_effect_type(effect_type)
        self.check_business_process(business_process)
        return tuple(t for t in self.templates if t.covers(effect_type, business_process))

    def select(self, effect_type: str, business_process: str) -> tpl.Selection:
        """The ONE template ``effect_type`` on ``business_process`` is assigned to:
        the covering template of lowest precedence (banking's rule,
        :func:`.templates.select`); ``effect_out_of_scope`` when none covers it."""
        if self.banking:
            return tpl.select(effect_type, business_process)
        candidates = self.in_scope(effect_type, business_process)
        if not candidates:
            raise tpl.BuildRefused("effect_out_of_scope", f"{effect_type} on {business_process} in {self.pack_id}")
        return tpl.Selection(candidates[0], candidates)

    def check_set(self, set_pack: str) -> None:
        """``pack_mismatch`` unless the parameter-set version answers this pack: a
        banking build reads a version that names no pack, an industry pack's build a
        version that names it."""
        expected = "" if self.banking else self.pack_id
        if set_pack != expected:
            named = set_pack or "no pack (the banking pack's)"
            raise ParameterRefused("pack_mismatch", f"the build is under {self.pack_id}; the parameter set answers {named}")

    def check_template_inputs(self, chosen: tpl.Template, inputs: Mapping[str, Parameter]) -> None:
        """``pack_input_missing`` unless the parameter set holds every pack input
        ``chosen`` reads: never defaulted, never read as zero, never left unknown. This
        is the ONE check of a pack's inputs, at build (choice 2): a set is never pushed
        to state an input none of its builds reads. An optional component's input is not
        required: without it the component is not made
        (:meth:`.templates.ComponentSpec.switched_off`)."""
        missing = sorted(
            {
                source.name
                for spec in chosen.components
                if not spec.optional
                for source in spec.sources.values()
                if source.kind is tpl.SourceKind.PACK_INPUT and source.name not in inputs
            }
        )
        if missing:
            raise ParameterRefused("pack_input_missing", f"{chosen.template_id} reads {missing}")

    # ------------------------------------------------------------ the document

    def as_dict(self) -> dict:
        """The pack as data: its library, its schema and its limits."""
        return {
            "pack": self.pack_id,
            "vertical": self.vertical,
            "name": self.name,
            "templates": [t.as_dict() for t in self.templates],
            "loss_families": list(self.families),
            "attributes": {name: a.as_dict() for name, a in sorted(self.attributes.items())},
            "effect_types": dict(self.effect_types),
            "business_processes": list(self.business_processes),
            "customer_inputs": {
                name: {**entry.as_dict(), "required_by": list(self.required_by[name])}
                for name, entry in sorted(self.inputs.items())
            },
            "parameter_set_variables": "the thirty shared variables (spec, section 19.1)",
            "cautions": list(self.cautions),
            "excluded": list(self.excluded),
        }


def shared(*names: str) -> dict[str, tpl.Attribute]:
    """The banking pack's attributes ``names``, as they are: an industry pack states
    the same attribute with the same unit, meaning and observability, or a new one of
    its own."""
    return {name: tpl.ATTRIBUTES[name] for name in names}


def attributes(*found: tpl.Attribute) -> dict[str, tpl.Attribute]:
    """``found`` by name; a name twice is a defect (``ValueError``)."""
    table: dict[str, tpl.Attribute] = {}
    for attribute in found:
        if attribute.name in table:
            raise ValueError(f"the attribute {attribute.name} is stated twice")
        table[attribute.name] = attribute
    return table


__all__ = ["HARM_EXCLUDED", "PHYSICAL_WORLD_CAUTION", "Pack", "attributes", "shared"]
