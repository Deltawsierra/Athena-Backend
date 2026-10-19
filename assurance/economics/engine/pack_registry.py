"""The industry-pack registry: banking and the packs beyond it (Economic Exposure E7;
``docs/economics/spec-v1.md``, section 37; the owner's specification, section 23).

A PACK is one vertical's scenario library: its effect types and business processes,
the attributes an effect of it may state, its templates -- each the same versioned
mapping from an effect's type and process to the components of the ONE loss event it
causes, with the same precedence model as the banking pack (:mod:`.templates`) -- the
loss families those templates price, and its customer-input SCHEMA, the special data
of section 23 the templates read beyond the thirty shared variables
(:mod:`.pack_inputs`). A pack is versioned in its id,
``mythos.economics.<vertical>-pack/v<n>``, and pinned by its digest: the registry
holds every pack version beside the digest it was released with (:data:`RELEASED`),
and refuses one whose content is not that digest (``ValueError``). A changed
template, schema or vocabulary is a NEW version of the pack, which stands beside the
old one; an old version stays, so a recorded build is read exactly, and a scenario
records the digest of the pack it was built under.

A scenario builds under exactly ONE pack (:func:`pack_of`), the pack its
parameter-set version answers (``pack_mismatch`` otherwise), and the build records
the pack's id and version beside every template it used. A build that names no pack
is the banking pack's, exactly as every build before E7 was: the banking pack is
:mod:`.templates`, unchanged, and a banking build is byte for byte the build it was.

The rules every pack keeps, each pinned by ``tests/test_economics_packs.py``:

- **No figure of its own.** A template's source is a kind and a name; every value a
  component reads is a recorded parameter with its ``source_type`` and evidence.
- **No geographic or company-size weight** (the owner's specification, section 27,
  "Bias/fairness"): no pack holds a multiplier, a penalty or a constant keyed by a
  place or a size; a figure of a place or a size is read only as a customer input of
  the schema, which the customer states with its provenance. A static test scans
  every pack's module and data for one.
- **A missing input is refused, never defaulted**: a build is refused unless the
  parameter set states every input a template the build uses reads
  (:meth:`Pack.check_template_inputs`; ``pack_input_missing``); nothing is required
  at record time, so no set is pushed to state a zero (choice 2).
- **One effect, one event**: an effect two templates of the pack cover is assigned to
  the one of lower precedence, and only it (:meth:`Pack.select`).
- **Harm to a person is never priced** (``safety_monetisation_refused``); a
  physical-world template carries :data:`PHYSICAL_WORLD_CAUTION` wherever its figures
  are shown.

Pure: no Django, no database, no clock and no randomness. Nothing on Django's load
path imports this module: the builder does, and only route modules imported GUARDED
import the builder (spec, section 2).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType

from . import (
    pack_government,
    pack_healthcare,
    pack_insurance,
    pack_manufacturing,
    pack_mobility,
    pack_regulated_enterprise,
    pack_saas,
)
from . import pack_inputs as schemas
from . import templates as tpl
from .pack_base import HARM_EXCLUDED, PHYSICAL_WORLD_CAUTION, Pack
from .parameters import ParameterRefused


def _banking() -> Pack:
    return Pack(
        pack_id=tpl.PACK,
        vertical="banking",
        name="Banking and financial services",
        effect_type_codes=tpl.EffectType,
        effect_types={t.value: meaning for t, meaning in tpl.EFFECT_TYPES.items()},
        business_process_codes=tpl.BusinessProcess,
        attributes=tpl.ATTRIBUTES,
        templates=tpl.TEMPLATES,
    )


def _packs() -> tuple[Pack, ...]:
    return (
        _banking(),
        pack_insurance.PACK,
        pack_healthcare.PACK,
        pack_saas.PACK,
        pack_regulated_enterprise.PACK,
        pack_government.PACK,
        pack_manufacturing.PACK,
        pack_mobility.PACK,
    )


#: Every pack version the registry holds, by id, with the digest of its content
#: (:attr:`.pack_base.Pack.digest`) as it was released. A pack whose content is not its
#: released digest is refused when the registry is built: a released version's
#: content never changes under its id, and a change is a new version
#: (``mythos.economics.<vertical>-pack/v<n+1>``), released beside the old one with its
#: own digest here. ``tests/test_economics_packs.py`` pins these digests again.
RELEASED: Mapping[str, str] = MappingProxyType(
    {
        "mythos.economics.banking-pack/v1": "sha256:fcdd2f17987866c66d1d4f3597adb7518443cdf35d7fead689540c20a39afd1d",
        "mythos.economics.insurance-pack/v1": "sha256:4e1700e81775337c1c21474d582daad8a8730a87805def937ea7ee481c7ba19a",
        "mythos.economics.healthcare-pack/v1": "sha256:9ebc335e1c902db504afa4cbcad4c45c9a3c64584fcf02804156ea55054667d9",
        "mythos.economics.saas-pack/v1": "sha256:a7e9242a22206623f3bce6b7b567998544109985a5c70c80e8303c8956b6d6eb",
        "mythos.economics.regulated-enterprise-pack/v1": "sha256:c0b35e526d26a9f9c04e9e34d7f6297f797570d5316e18e7dbe08096e35d4903",
        "mythos.economics.government-pack/v1": "sha256:8b6247641ce46caf8c4d8922ce7543d83b902017c5f5a5addc07f4a26f957915",
        "mythos.economics.manufacturing-pack/v1": "sha256:64530894de42cbcfe75119c38ae600840638f7e6deae290b616a1adcd8aa533f",
        "mythos.economics.mobility-pack/v1": "sha256:ef790093d9d98c778496b2813fee1fc7605e3223f9c737a843edf00405e61198",
    }
)

_PACK_ID = re.compile(r"mythos\.economics\.(?P<vertical>[a-z][a-z-]*)-pack/v(?P<version>[1-9][0-9]*)")


def _content(template: tpl.Template) -> dict:
    """A template as data, apart from the pack version that holds it: what two versions
    of a pack holding one template id and version must agree on."""
    document = template.as_dict()
    del document["pack"]
    return document


def _index(
    packs: tuple[Pack, ...], released: Mapping[str, str] = RELEASED
) -> tuple[Mapping[str, Pack], Mapping[tuple[str, int], tpl.Template]]:
    """The packs by id and every template by ``(template_id, version)``, each checked
    (``ValueError`` for a defect, never one silently kept):

    - a pack's id is ``mythos.economics.<vertical>-pack/v<n>``, of its own vertical, and
      registered once;
    - its content is the digest it was released with (``released``): a version's
      content never changes under its id;
    - every template names the pack version that holds it;
    - a template id is ONE vertical's: the versions of its pack may hold it, no other
      pack may;
    - a template id and version two versions of a pack hold has ONE content in both: a
      changed template is a new template version.

    A template two versions hold is indexed as the earliest holds it; a build reads it
    from its own pack (:func:`template` with ``pack_id``)."""
    by_id: dict[str, Pack] = {}
    templates: dict[tuple[str, int], tpl.Template] = {}
    vertical_of: dict[str, str] = {}
    for pack in packs:
        named = _PACK_ID.fullmatch(pack.pack_id)
        if named is None or named["vertical"] != pack.vertical:
            raise ValueError(f"the pack id {pack.pack_id} is not mythos.economics.{pack.vertical}-pack/v<n>")
        if pack.pack_id in by_id:
            raise ValueError(f"the pack {pack.pack_id} is registered twice")
        if released.get(pack.pack_id) != pack.digest:
            raise ValueError(
                f"the pack {pack.pack_id} is {pack.digest}, not the digest it was released with "
                f"({released.get(pack.pack_id)}): a released version never changes; release a new version beside it"
            )
        by_id[pack.pack_id] = pack
        for chosen in pack.templates:
            if chosen.pack != pack.pack_id:
                raise ValueError(f"{chosen.template_id} names {chosen.pack}, not its pack {pack.pack_id}")
            if vertical_of.setdefault(chosen.template_id, pack.vertical) != pack.vertical:
                raise ValueError(f"the template id {chosen.template_id} is in two verticals' packs")
            held = templates.setdefault(chosen.key, chosen)
            if _content(held) != _content(chosen):
                raise ValueError(
                    f"the template {chosen.template_id} version {chosen.version} differs between {held.pack} and "
                    f"{pack.pack_id}: a changed template is a new template version"
                )
    return MappingProxyType(by_id), MappingProxyType(templates)


#: Every pack, by id; and every template of every pack, by ``(template_id, version)``.
PACKS, TEMPLATES = _index(_packs())
#: The banking pack.
BANKING = PACKS[tpl.PACK]


def pack_of(value, path: str = "pack") -> Pack:
    """The pack a build or a parameter set names: the banking pack where it names
    none (``None``), an industry pack by its id; ``pack_unrecognised`` for anything
    else, the banking pack's id included (it is named by naming no pack, so a banking
    build has one spelling, the one it had before E7)."""
    if value is None:
        return BANKING
    found = PACKS.get(value) if isinstance(value, str) else None
    if found is None or found.banking:
        schemas.schema(value, path)  # raises pack_unrecognised, saying why
        raise ParameterRefused("pack_unrecognised", f"{path} {str(value)!r}: the registry does not hold it")
    return found


def template(template_id: str, version: int, pack_id: str | None = None) -> tpl.Template | None:
    """The template ``template_id`` at ``version``: as the pack ``pack_id`` holds it
    where that pack is held and holds it, as the registry indexes it otherwise; or
    ``None``."""
    held = PACKS.get(pack_id) if isinstance(pack_id, str) else None
    if held is not None and (template_id, version) in held.catalogue:
        return held.catalogue[(template_id, version)]
    return TEMPLATES.get((template_id, version))


def packs_of_template(template_id: str, version: int) -> tuple[Pack, ...]:
    """Every pack version that holds ``template_id`` at ``version``, in order."""
    return tuple(pack for pack in PACKS.values() if (template_id, version) in pack.catalogue)


def registry_document() -> dict:
    """Every pack as data, banking first, each with the digest it was released with:
    what the packs route serves."""
    return {"packs": [{**pack.as_dict(), "digest": pack.digest} for pack in PACKS.values()]}


__all__ = [
    "BANKING",
    "HARM_EXCLUDED",
    "PACKS",
    "PHYSICAL_WORLD_CAUTION",
    "RELEASED",
    "TEMPLATES",
    "Pack",
    "pack_of",
    "packs_of_template",
    "registry_document",
    "template",
]
