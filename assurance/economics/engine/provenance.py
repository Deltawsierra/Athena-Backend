"""Where a number came from: a parameter's ``source_type``, a source's license
class and its trust tier.

Customer-specific data should dominate an estimate wherever it exists, and an
external feed is evidence, not unquestioned truth (owner's specification,
sections 10 and 14). These three vocabularies are what make that checkable: every
parameter says what kind of source it rests on, and every recorded source says
whether anyone has reviewed its terms and how far it is trusted. The values are
the stable codes stored rows carry; ``tests/test_economics_engine.py`` pins them.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType


class SourceType(StrEnum):
    """What kind of source one financial parameter rests on (section 14), spelled
    as the specification spells them."""

    CUSTOMER_PROVIDED = "CUSTOMER_PROVIDED"
    MYTHOS_OBSERVED = "MYTHOS_OBSERVED"
    CALCULATED = "CALCULATED"
    OFFICIAL_PUBLIC = "OFFICIAL_PUBLIC"
    LICENSED_MARKET = "LICENSED_MARKET"
    INDUSTRY_BENCHMARK = "INDUSTRY_BENCHMARK"
    EXPERT_ESTIMATE = "EXPERT_ESTIMATE"
    UNKNOWN = "UNKNOWN"


#: What each source type means, published beside it.
SOURCE_TYPES: Mapping[SourceType, str] = MappingProxyType(
    {
        SourceType.CUSTOMER_PROVIDED: "the customer supplied the value from its own records",
        SourceType.MYTHOS_OBSERVED: "Mythos observed it: an effect, a count or a duration seen in an assessment",
        SourceType.CALCULATED: "derived by a recorded formula from other parameters, each with its own source",
        SourceType.OFFICIAL_PUBLIC: "an official public publisher: a central bank, a statistics office, a regulator, "
        "a company's own filing",
        SourceType.LICENSED_MARKET: "a commercial market-data vendor, under a reviewed license",
        SourceType.INDUSTRY_BENCHMARK: "an industry study or survey: a prior or context, never customer-specific truth",
        SourceType.EXPERT_ESTIMATE: "a person's estimate, recorded as one",
        SourceType.UNKNOWN: "nothing says where the value came from",
    }
)


class LicenseClass(StrEnum):
    """Whether anyone has reviewed a source's terms, and what they allow.

    ``unreviewed`` is the default and the only class a production run refuses: a
    source nobody has read the terms of is usable for a test or a fixture, never for
    a run whose output leaves the building (:func:`.governance.production_use_refusal`).
    Each production data source needs its own licensing review before its adapter
    lands (FREEZE.md, owner exception 9)."""

    UNREVIEWED = "unreviewed"
    OPEN = "open"
    RESTRICTED = "restricted"
    LICENSED = "licensed"
    CUSTOMER = "customer"


LICENSE_CLASSES: Mapping[LicenseClass, str] = MappingProxyType(
    {
        LicenseClass.UNREVIEWED: "nobody has reviewed the provider's terms; no production run may use it",
        LicenseClass.OPEN: "reviewed: the terms allow storing it, deriving figures from it and redistributing it",
        LicenseClass.RESTRICTED: "reviewed: the terms allow storing it and deriving figures from it, not "
        "redistributing the raw data",
        LicenseClass.LICENSED: "reviewed: a paid license governs its use, on the terms recorded with that license",
        LicenseClass.CUSTOMER: "the customer's own data, used on the engagement's terms",
    }
)


class TrustTier(StrEnum):
    """How far a source is trusted, strongest first. ``unverified`` is the default:
    a source is not trusted until someone says why it should be."""

    AUTHORITATIVE = "authoritative"
    CUSTOMER = "customer"
    LICENSED_VENDOR = "licensed_vendor"
    BENCHMARK = "benchmark"
    UNVERIFIED = "unverified"


TRUST_TIERS: Mapping[TrustTier, str] = MappingProxyType(
    {
        TrustTier.AUTHORITATIVE: "the official publisher of the figure",
        TrustTier.CUSTOMER: "the customer's own records, about the customer",
        TrustTier.LICENSED_VENDOR: "a commercial vendor that aggregates or redistributes the figure",
        TrustTier.BENCHMARK: "an industry study or survey: a prior, not a measurement of this customer",
        TrustTier.UNVERIFIED: "nothing yet establishes how reliable it is",
    }
)
