"""The industry-pack registry: banking and the packs beyond it (Economic Exposure E7;
``docs/economics/spec-v1.md``, section 37; the owner's specification, section 23).

A PACK is one vertical's scenario library: its effect types and business processes,
the attributes an effect of it may state, its templates -- each the same versioned
mapping from an effect's type and process to the components of the ONE loss event it
causes, with the same precedence model as the banking pack (:mod:`.templates`) -- the
loss families those templates price, and its customer-input SCHEMA, the special data
of section 23 the templates read beyond the thirty shared variables
(:mod:`.pack_inputs`). A pack is versioned in its id,
``mythos.economics.<vertical>-pack/v<n>``: a changed template, schema or vocabulary
is a new version of the pack, and an old one stays, so a recorded build is read
exactly.

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
- **A missing input is refused, never defaulted**: every input the pack requires is
  stated in the parameter set, and every input a template the build uses reads
  (:meth:`Pack.check_template_inputs`; ``pack_input_missing``).
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

from collections.abc import Mapping
from types import MappingProxyType

from . import pack_healthcare, pack_insurance, pack_saas
from . import pack_inputs as schemas
from . import templates as tpl
from .pack_base import HARM_EXCLUDED, PHYSICAL_WORLD_CAUTION, Pack


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
    return (_banking(), pack_insurance.PACK, pack_healthcare.PACK, pack_saas.PACK)


def _index(packs: tuple[Pack, ...]) -> tuple[Mapping[str, Pack], Mapping[tuple[str, int], tpl.Template]]:
    """The packs by id and every template by ``(template_id, version)``. A template
    id is the registry's, not only its pack's: one id in two packs is a defect
    (``ValueError``), never one silently kept."""
    by_id: dict[str, Pack] = {}
    templates: dict[tuple[str, int], tpl.Template] = {}
    for pack in packs:
        if pack.pack_id in by_id:
            raise ValueError(f"the pack {pack.pack_id} is registered twice")
        by_id[pack.pack_id] = pack
        for chosen in pack.templates:
            if chosen.pack != pack.pack_id:
                raise ValueError(f"{chosen.template_id} names {chosen.pack}, not its pack {pack.pack_id}")
            if any(key[0] == chosen.template_id for key in templates):
                raise ValueError(f"the template id {chosen.template_id} is in two packs")
            templates[chosen.key] = chosen
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
    return found


def template(template_id: str, version: int) -> tpl.Template | None:
    """The template ``template_id`` at ``version`` in any pack, or ``None``."""
    return TEMPLATES.get((template_id, version))


def pack_of_template(template_id: str, version: int) -> Pack | None:
    found = template(template_id, version)
    return None if found is None else PACKS[found.pack]


def registry_document() -> dict:
    """Every pack as data, banking first: what the packs route serves."""
    return {"packs": [pack.as_dict() for pack in PACKS.values()]}


__all__ = [
    "BANKING",
    "HARM_EXCLUDED",
    "PACKS",
    "PHYSICAL_WORLD_CAUTION",
    "TEMPLATES",
    "Pack",
    "pack_of",
    "pack_of_template",
    "registry_document",
    "template",
]
