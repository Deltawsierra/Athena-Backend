"""The banking pack: six scenario templates that turn an effect into a loss event.

A template is a versioned, named mapping from an EFFECT -- its type, the business
process it touches, and the attributes it states -- to the components of the loss
event it causes (owner's specification, sections 6 and 22;
``docs/economics/spec-v1.md``, section 24). For each component it says which of the
fifteen loss families it is (or ``market_value``), which formula of the catalogue
computes it (:mod:`.formulas`), and where each of the formula's inputs comes from:

- a variable of the customer parameter set (:data:`.parameter_set.VARIABLES`), the
  customer's own figures, or
- an attribute the effect states (:data:`ATTRIBUTES`): the observed success rate,
  the affected customers, a lump-sum range its evidence gives.

**A template never invents a number.** It holds no figure at all: a source is a kind
and a name, nothing else. Every value a component reads is a parameter the customer
or the effect's declaration recorded, with its ``source_type`` and evidence; an input
whose source is missing is left unbound, and the formula makes the component
``unknown``, never zero (:func:`plan`).

**Scope and precedence.** A template covers the effect types it names, on any
business process or only on those it names. Where two templates cover one effect, the
one with the lower :attr:`Template.precedence` takes it, and only that one
(:func:`select`): an effect is assigned to exactly ONE template, so it is in exactly
one loss event. The precedence is a total order, stated in :data:`TEMPLATES` and
pinned by ``tests/test_economics_builder.py``.

Pure: no Django, no database, no clock and no randomness. Nothing here runs at import
but building constants; nothing on Django's load path imports this module (the
builder does, and only its route module imports the builder, guarded).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from . import parameter_set as pset
from .formulas import MARKET_VALUE, Direction, formula
from .money import UNAVAILABLE_REASONS, Money, MoneyRefused
from .parameters import POINTS, Parameter, Point, Unit
from .provenance import SourceType
from .taxonomy import LossFamily

#: The pack these templates make up. A changed template is a new version of it; an
#: old version stays in :data:`CATALOGUE`, so a recorded build is read exactly.
PACK = "mythos.economics.banking-pack/v1"

#: What each refusal of the scenario builder means (``BuildRefused``). A code the
#: money or scenario engine already publishes is raised as that engine's.
REFUSALS: Mapping[str, str] = MappingProxyType(
    {
        "effect_type_unrecognised": "an effect's type is one of the pack's effect types",
        "business_process_unrecognised": "an effect's business process is one of the pack's business processes",
        "origin_unrecognised": "an effect is observed (a SPINE observed effect) or hypothetical (declared)",
        "finding_role_unrecognised": "a finding enables an effect as a prerequisite, an amplifier or an alternate path",
        "attribute_unrecognised": "an effect states only the pack's attributes, each in its unit",
        "effect_key_malformed": (
            "an effect's key is 1 to 60 characters: lowercase ASCII letters and digits, '-' and '_', starting with "
            "a letter or digit"
        ),
        "effect_out_of_scope": "no template of the pack covers the effect's type on its business process",
        "effect_not_declared": "a finding names an effect the build does not declare",
        "effect_without_finding": (
            "a hypothetical effect rests on at least one finding that enables it; an observed effect rests on its "
            "signed observation"
        ),
        "observed_source_on_hypothetical": (
            "an attribute of a hypothetical effect is never MYTHOS_OBSERVED: nothing was observed; declare the "
            "effect observed, naming the SPINE observed effect, or give the attribute's real source"
        ),
        "observed_source_not_observable": (
            "MYTHOS_OBSERVED is only a rate, a count or a duration an assessment observes; a money amount or a "
            "market figure is CUSTOMER_PROVIDED, EXPERT_ESTIMATE or another source that is not an observation"
        ),
        "observed_source_unbound": (
            "a MYTHOS_OBSERVED attribute's evidence_ref is the observed effect it came from: its SPINE effect "
            "digest, alone or followed by a space and a note (a digest that is only mentioned, or that follows "
            "other text, binds nothing)"
        ),
        "spine_effect_inconsistent": (
            "every observation of one SPINE effect is declared with one effect type, asset and business process: "
            "one effect is one loss event"
        ),
        "observed_effect_not_found": "the observed effect is not one of this deployment's SPINE observed effects",
        "observed_effect_not_in_force": (
            "the SPINE observed effect does not stand: its signature does not verify now, it is not signed by an "
            "observed-effect key, or its evidence is not the document its signature names"
        ),
        "finding_not_found": "the finding is not one of this deployment's findings",
        "asset_not_found": "the asset is not one of this deployment's assets",
        "parameter_set_not_found": "the customer parameter-set version is not one of this deployment's",
        "scenario_not_found": "the scenario superseded is not one of this deployment's",
        # A figure a build normalizes (spec, section 36): never a number the policy does
        # not allow, so a normalization the books cannot make refuses the build.
        "rate_missing": UNAVAILABLE_REASONS["rate_missing"],
        "index_missing": UNAVAILABLE_REASONS["index_missing"],
        "index_primary_unset": UNAVAILABLE_REASONS["index_primary_unset"],
        "normalization_policy_not_found": (
            "the normalization policy a build names is not a stored policy of its deployment or of the platform: a "
            "build names a stored policy by its key, and never states one"
        ),
        "distribution_not_normalizable": (
            "a figure the build normalizes into its currency states a distribution in its own currency: a "
            "distribution is not rescaled by a conversion, so state the figure in the build's currency at its as-of "
            "date, or state it without a distribution"
        ),
    }
)


class BuildRefused(MoneyRefused):
    """A build the scenario builder refuses. ``code`` is one of :data:`REFUSALS`;
    ``detail`` says what was refused. A :class:`.money.MoneyRefused`, so one
    ``except`` catches every refusal of the engine and the builder."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        ValueError.__init__(self, f"{code}: {REFUSALS[code]}{suffix}")


# ------------------------------------------------------------------ vocabularies


class EffectType(StrEnum):
    """What an effect does: the concrete mutation, transfer, disclosure or
    interruption (specification, section 6). The value is the stable code."""

    FUNDS_TRANSFER_ALTERED = "funds_transfer_altered"
    APPROVAL_BYPASSED = "approval_bypassed"
    CROSS_CUSTOMER_DISCLOSURE = "cross_customer_disclosure"
    CUSTOMER_MISSTATEMENT = "customer_misstatement"
    FRAUD_AML_CONTROL_FAILURE = "fraud_aml_control_failure"
    PROVIDER_OUTAGE = "provider_outage"


EFFECT_TYPES: Mapping[EffectType, str] = MappingProxyType(
    {
        EffectType.FUNDS_TRANSFER_ALTERED: (
            "an agent initiated a payment, wire or ACH transfer, or changed one (its destination, its amount), "
            "outside its authority"
        ),
        EffectType.APPROVAL_BYPASSED: "an agent's action took effect without the approval it needed",
        EffectType.CROSS_CUSTOMER_DISCLOSURE: "one customer's data reached another customer",
        EffectType.CUSTOMER_MISSTATEMENT: (
            "a customer-service AI told customers something false about a fee, a rate, a product or a policy"
        ),
        EffectType.FRAUD_AML_CONTROL_FAILURE: (
            "a fraud or AML workflow missed, closed or failed to escalate cases it should have caught"
        ),
        EffectType.PROVIDER_OUTAGE: "a third-party model or provider a critical operation depends on was unavailable",
    }
)


class BusinessProcess(StrEnum):
    """The business process an effect touches, for the banking pack."""

    PAYMENTS = "payments"
    LENDING = "lending"
    ACCOUNT_SERVICING = "account_servicing"
    CUSTOMER_SERVICE = "customer_service"
    FRAUD_AML = "fraud_aml"
    OPERATIONS = "operations"


class Origin(StrEnum):
    """Where an effect comes from: a SPINE observed effect (a signed observation of
    the effect happening, ``mythos.observed-effect``), or a hypothetical effect an
    analyst declares, resting on the findings that enable it."""

    OBSERVED = "observed"
    HYPOTHETICAL = "hypothetical"


class FindingRole(StrEnum):
    """How a finding relates to the effect it enables (specification, section 6)."""

    PREREQUISITE = "prerequisite"
    AMPLIFIER = "amplifier"
    ALTERNATE_PATH = "alternate_path"


@dataclass(frozen=True)
class Attribute:
    """One attribute an effect may state: its name, unit and meaning, and whether an
    assessment OBSERVES it -- a rate, a count or a duration seen when the effect
    happened -- so that it may rest on ``MYTHOS_OBSERVED``. A money amount and a
    market figure never do: they are the customer's, an expert's or a market's."""

    name: str
    unit: Unit
    meaning: str
    observable: bool = False

    def as_dict(self) -> dict:
        return {"unit": self.unit.value, "meaning": self.meaning, "observable": self.observable}


def _attributes() -> tuple[Attribute, ...]:
    U = Unit
    return (
        # Observable: a rate, a count or a duration an assessment sees when the effect
        # happens. Nothing else may rest on MYTHOS_OBSERVED (observed_source_not_observable).
        Attribute(
            "success_rate", U.RATIO, "the share of attempts that produced the effect, as tested", observable=True
        ),
        Attribute(
            "exploitable_window_hours",
            U.HOURS,
            "how long the condition stays exploitable before detection",
            observable=True,
        ),
        Attribute("incident_response_cost", U.MONEY, "incident response, as a range its evidence gives"),
        Attribute("legal_response_cost", U.MONEY, "legal and regulatory response, as one range its evidence gives"),
        Attribute("affected_customers", U.COUNT, "customers the effect reaches", observable=True),
        Attribute("contact_rate", U.RATIO, "the share of affected customers who contact support"),
        Attribute("handling_hours", U.HOURS, "average handling time per contact"),
        Attribute("forensics_fixed_cost", U.MONEY, "the fixed part of forensics or investigation"),
        Attribute("investigation_hours", U.HOURS, "hours of forensics or investigation"),
        Attribute("counsel_hours", U.HOURS, "hours of external counsel"),
        Attribute(
            "regulatory_response_cost",
            U.MONEY,
            "regulatory response, as scenario bounds its evidence grounds (never a predicted penalty)",
        ),
        Attribute("churn_rate", U.RATIO, "the extra share of affected customers who leave, from the customer's own data"),
        Attribute("margin_per_customer_per_year", U.MONEY_PER_UNIT, "recurring margin per customer per year"),
        Attribute("churn_recovery_years", U.YEARS, "years until lost margin is won back"),
        Attribute("market_capitalisation", U.MONEY, "the company's market capitalisation (public-company analysis)"),
        Attribute("share_price_decline", U.RATIO, "the share-price decline attributed to the effect"),
        Attribute("restitution_per_customer", U.MONEY_PER_UNIT, "the amount owed to each affected customer"),
        Attribute("missed_cases", U.COUNT, "fraud or AML cases the workflow missed", observable=True),
        Attribute("loss_per_missed_case", U.MONEY_PER_UNIT, "the fraud loss per missed case"),
        Attribute("rework_cost", U.MONEY, "reworking and reprocessing the cases, as a range"),
        Attribute("repeat_count", U.COUNT, "how many times the unauthorized effect repeats", observable=True),
        Attribute("loss_per_event", U.MONEY_PER_UNIT, "the amount one unauthorized effect moves or loses"),
        Attribute("recovery_fixed_cost", U.MONEY, "the fixed part of restoring the control or the service"),
        Attribute("recovery_hours", U.HOURS, "engineering hours to restore the control or the service"),
        Attribute("outage_hours", U.HOURS, "how long the provider is unavailable", observable=True),
        Attribute("sla_credit_per_hour", U.MONEY_PER_HOUR, "SLA credits owed to customers per hour of outage"),
        Attribute("sla_credit_cap", U.MONEY, "the contracts' cap on those credits"),
    )


#: Every attribute an effect may state, by name. Read-only.
ATTRIBUTES: Mapping[str, Attribute] = MappingProxyType({a.name: a for a in _attributes()})


# -------------------------------------------------------------------- templates


class SourceKind(StrEnum):
    """Where one formula input's value comes from: a variable of the parameter set,
    an attribute of the effect, or (an industry pack's template, E7) an input of the
    pack's customer-input schema, which the parameter set states beside its
    variables (spec, section 37). No banking template reads a pack input."""

    PARAMETER_SET = "parameter_set"
    EFFECT_ATTRIBUTE = "effect_attribute"
    PACK_INPUT = "pack_input"


@dataclass(frozen=True)
class Source:
    """One input's source: a parameter-set variable or an effect attribute, by name.
    No value, ever: the value is the recorded parameter's."""

    kind: SourceKind
    name: str

    def as_dict(self) -> dict:
        return {"from": self.kind.value, "name": self.name}


def P(name: str) -> Source:
    return Source(SourceKind.PARAMETER_SET, name)


def A(name: str) -> Source:
    return Source(SourceKind.EFFECT_ATTRIBUTE, name)


def I(name: str) -> Source:
    # The pack-input counterpart of P and A.
    return Source(SourceKind.PACK_INPUT, name)


@dataclass(frozen=True)
class ComponentSpec:
    """One component a template makes: its key within the event, its family, the
    formula and version that compute it, and each formula input's source. (A
    component an industry template makes only where its pack inputs are stated is
    named by the template: :attr:`Template.optional_components`.)"""

    component_key: str
    family: str
    formula_id: str
    formula_version: int
    sources: Mapping[str, Source]

    def __post_init__(self):
        object.__setattr__(self, "family", str(self.family))
        object.__setattr__(self, "sources", MappingProxyType(dict(self.sources)))

    def as_dict(self) -> dict:
        chosen = formula(self.formula_id, self.formula_version)
        return {
            "component_key": self.component_key,
            "family": self.family,
            "formula_id": self.formula_id,
            "formula_version": self.formula_version,
            "expression": chosen.expression,
            "inputs": {
                spec.name: {**self.sources[spec.name].as_dict(), "direction": spec.direction.value}
                for spec in chosen.inputs
            },
        }


@dataclass(frozen=True)
class Scope:
    """One effect type a template covers: on every business process (``None``), or
    only on those named."""

    effect_type: EffectType
    business_processes: frozenset[BusinessProcess] | None = None

    def covers(self, effect_type: str, business_process: str) -> bool:
        if effect_type != self.effect_type:
            return False
        return self.business_processes is None or business_process in self.business_processes

    def as_dict(self) -> dict:
        processes = None if self.business_processes is None else sorted(p.value for p in self.business_processes)
        return {"effect_type": self.effect_type.value, "business_processes": processes}


@dataclass(frozen=True)
class Template:
    """One template: its id and version, the specification's scenario family it
    models, its precedence, what it covers, its components, and the notes that say
    which way the uncertain inputs move the loss."""

    template_id: str
    version: int
    name: str
    precedence: int
    scope: tuple[Scope, ...]
    components: tuple[ComponentSpec, ...]
    direction_notes: tuple[str, ...]
    #: The pack the template belongs to (an industry pack's, E7); the banking pack's
    #: unless one is named.
    pack: str = PACK
    #: What the template's figures must be read with (an industry pack's physical-world
    #: caution, spec section 37); none for a banking template.
    cautions: tuple[str, ...] = ()
    #: The components, by key, the template makes only where the parameter set states
    #: every pack input they read (an industry pack's, E7, spec section 37.2): absent
    #: otherwise -- never zero, never unknown, never refused. It is how a pack prices a
    #: loss only some customers have (choice 8: usage-billed revenue). Each names a
    #: component of the template that reads a pack input (``ValueError`` otherwise);
    #: no banking template has one.
    optional_components: frozenset[str] = frozenset()

    def __post_init__(self):
        object.__setattr__(self, "optional_components", frozenset(self.optional_components))
        for key in self.optional_components:
            spec = next((c for c in self.components if c.component_key == key), None)
            if spec is None or not any(s.kind is SourceKind.PACK_INPUT for s in spec.sources.values()):
                raise ValueError(f"the optional component {key} of {self.template_id} reads no pack input to be stated")

    @property
    def key(self) -> tuple[str, int]:
        return (self.template_id, self.version)

    def is_optional(self, spec: ComponentSpec) -> bool:
        return spec.component_key in self.optional_components

    def switched_off(self, spec: ComponentSpec, inputs: Mapping[str, object]) -> bool:
        """Whether ``spec`` is optional here and the parameter set does not state every
        pack input it reads (``inputs``, by input name): then it is not made."""
        return self.is_optional(spec) and any(
            s.kind is SourceKind.PACK_INPUT and s.name not in inputs for s in spec.sources.values()
        )

    def covers(self, effect_type: str, business_process: str) -> bool:
        return any(s.covers(effect_type, business_process) for s in self.scope)

    def as_dict(self) -> dict:
        document = {
            "template_id": self.template_id,
            "version": self.version,
            "name": self.name,
            "pack": self.pack,
            "precedence": self.precedence,
            "scope": [s.as_dict() for s in self.scope],
            # An optional component says so (an industry pack's only): a banking template
            # is served as it was.
            "components": [
                {**c.as_dict(), "optional": True} if self.is_optional(c) else c.as_dict() for c in self.components
            ],
            "direction_notes": list(self.direction_notes),
        }
        # Only where there is one: a banking template is served as it was before a
        # caution could be stated.
        if self.cautions:
            document["cautions"] = list(self.cautions)
        return document


F = LossFamily
E = EffectType
B = BusinessProcess


def _templates() -> tuple[Template, ...]:
    recovery_note = "recovery_rate decreases the loss: the LOW result reads the HIGHEST recovery, the HIGH the lowest"
    lump_note = (
        "a lump-sum range is read as its evidence gives it, low, base and high; where the evidence gives a range "
        "and no base, the declaration's base is its midpoint (spec, section 22, decision 5)"
    )
    remediation_note = (
        "remediation of the finding is a mitigation's price, never a component of this event (spec, section 22, "
        "decision 2)"
    )
    return (
        Template(
            "payment_agent_misuse",
            1,
            "Payment / wire / ACH agent misuse",
            1,
            (
                Scope(E.FUNDS_TRANSFER_ALTERED),
                # An approval bypass that moves money is a payment loss: this template, not
                # agent_approval_bypass, takes it (precedence 1 against 5).
                Scope(E.APPROVAL_BYPASSED, frozenset({B.PAYMENTS})),
            ),
            (
                ComponentSpec(
                    "direct-loss",
                    F.DIRECT_FINANCIAL,
                    "repeat_in_window",
                    1,
                    {
                        "transactions_per_day": P("transactions_per_day"),
                        "window_hours": A("exploitable_window_hours"),
                        "success_rate": A("success_rate"),
                        "value_per_transaction": P("average_transaction_value"),
                        "recovery_rate": P("recovery_rate"),
                    },
                ),
                ComponentSpec("incident-response", F.INCIDENT_RESPONSE, "lump_sum", 1, {"amount": A("incident_response_cost")}),
                ComponentSpec(
                    "legal-regulatory-response", F.LEGAL, "lump_sum", 1, {"amount": A("legal_response_cost")}
                ),
            ),
            (
                recovery_note,
                "the exploitable window is the largest uncertainty (specification, section 30); a longer window "
                "never lowers the loss",
                "the success rate is the tested proportion (7 of 20 in section 30), a point; its interval is the "
                "probabilistic engine's",
                "transactions per day and the average transfer are the customer's own figures, never the test's "
                "amounts",
                lump_note,
                remediation_note,
            ),
        ),
        Template(
            "cross_customer_data_exposure",
            1,
            "Cross-customer data exposure",
            2,
            (Scope(E.CROSS_CUSTOMER_DISCLOSURE),),
            (
                ComponentSpec(
                    "notification",
                    F.NOTIFICATION,
                    "per_affected_plus_fixed",
                    1,
                    {
                        "affected": A("affected_customers"),
                        "unit_cost": P("notification_unit_cost"),
                        "fixed_cost": P("notification_fixed_cost"),
                    },
                ),
                ComponentSpec(
                    "support",
                    F.NOTIFICATION,
                    "support_contacts",
                    1,
                    {
                        "affected": A("affected_customers"),
                        "contact_rate": A("contact_rate"),
                        "handling_hours": A("handling_hours"),
                        "loaded_rate": P("support_agent_hourly_rate"),
                    },
                ),
                ComponentSpec(
                    "forensics",
                    F.INCIDENT_RESPONSE,
                    "fixed_plus_hours",
                    1,
                    {
                        "fixed_cost": A("forensics_fixed_cost"),
                        "hourly_rate": P("security_responder_hourly_rate"),
                        "hours": A("investigation_hours"),
                    },
                ),
                ComponentSpec(
                    "legal",
                    F.LEGAL,
                    "fixed_plus_hours",
                    1,
                    {
                        "fixed_cost": P("legal_retainer"),
                        "hourly_rate": P("external_counsel_hourly_rate"),
                        "hours": A("counsel_hours"),
                    },
                ),
                ComponentSpec(
                    "regulatory", F.REGULATORY_COMPLIANCE, "lump_sum", 1, {"amount": A("regulatory_response_cost")}
                ),
                ComponentSpec(
                    "customer-loss",
                    F.CUSTOMER_LOSS,
                    "churned_margin",
                    1,
                    {
                        "customers": A("affected_customers"),
                        "churn_rate": A("churn_rate"),
                        "margin_per_customer_per_year": A("margin_per_customer_per_year"),
                        "recovery_years": A("churn_recovery_years"),
                    },
                ),
                ComponentSpec(
                    "share-price-reaction",
                    MARKET_VALUE,
                    "share_price_reaction",
                    1,
                    {"market_capitalisation": A("market_capitalisation"), "price_decline": A("share_price_decline")},
                ),
            ),
            (
                "the affected population drives notification, support and customer loss alike: one parameter, read "
                "by each in the same direction",
                "customer loss is computed only from the customer's own churn figure (CUSTOMER_PROVIDED); any other "
                "source makes it unknown (specification, section 31)",
                "regulatory response is scenario bounds its evidence grounds, never a predicted penalty",
                "the share-price reaction is market value: reported on its own line and never added to cash loss; "
                "unknown unless the effect states the market capitalisation and the decline",
                remediation_note,
            ),
        ),
        Template(
            "customer_service_ai_misstatement",
            1,
            "Customer-service AI misstatement",
            3,
            (Scope(E.CUSTOMER_MISSTATEMENT),),
            (
                ComponentSpec(
                    "restitution",
                    F.CUSTOMER_RESTITUTION,
                    "per_affected",
                    1,
                    {"affected": A("affected_customers"), "amount_per_affected": A("restitution_per_customer")},
                ),
                ComponentSpec(
                    "complaint-handling",
                    F.NOTIFICATION,
                    "support_contacts",
                    1,
                    {
                        "affected": A("affected_customers"),
                        "contact_rate": A("contact_rate"),
                        "handling_hours": A("handling_hours"),
                        "loaded_rate": P("support_agent_hourly_rate"),
                    },
                ),
                ComponentSpec(
                    "legal",
                    F.LEGAL,
                    "fixed_plus_hours",
                    1,
                    {
                        "fixed_cost": P("legal_retainer"),
                        "hourly_rate": P("external_counsel_hourly_rate"),
                        "hours": A("counsel_hours"),
                    },
                ),
                ComponentSpec(
                    "compliance-review", F.REGULATORY_COMPLIANCE, "lump_sum", 1, {"amount": A("regulatory_response_cost")}
                ),
            ),
            (
                "the customers told the misstatement drive restitution and complaint handling alike",
                "complaint handling is the call-center work the misstatement causes (the notification family, which "
                "holds call-center cost)",
                remediation_note,
            ),
        ),
        Template(
            "fraud_aml_workflow_failure",
            1,
            "Fraud/AML workflow failure",
            4,
            (
                Scope(E.FRAUD_AML_CONTROL_FAILURE),
                # An agent closing a fraud or AML case without the review it needed is the
                # workflow failing: this template, not agent_approval_bypass, takes it.
                Scope(E.APPROVAL_BYPASSED, frozenset({B.FRAUD_AML})),
            ),
            (
                ComponentSpec(
                    "missed-fraud",
                    F.DIRECT_FINANCIAL,
                    "repeat_loss",
                    1,
                    {
                        "repeat_count": A("missed_cases"),
                        "loss_per_event": A("loss_per_missed_case"),
                        "recovery_rate": P("recovery_rate"),
                    },
                ),
                ComponentSpec("case-rework", F.RECOVERY, "lump_sum", 1, {"amount": A("rework_cost")}),
                ComponentSpec(
                    "investigation",
                    F.INCIDENT_RESPONSE,
                    "fixed_plus_hours",
                    1,
                    {
                        "fixed_cost": A("forensics_fixed_cost"),
                        "hourly_rate": P("security_responder_hourly_rate"),
                        "hours": A("investigation_hours"),
                    },
                ),
                ComponentSpec(
                    "regulatory-response",
                    F.REGULATORY_COMPLIANCE,
                    "lump_sum",
                    1,
                    {"amount": A("regulatory_response_cost")},
                ),
            ),
            (
                recovery_note,
                "missed cases are the cases the workflow should have caught, not every case it saw",
                "regulatory response is scenario bounds its evidence grounds, never a predicted penalty",
                remediation_note,
            ),
        ),
        Template(
            "agent_approval_bypass",
            1,
            "Agent approval bypass",
            5,
            (Scope(E.APPROVAL_BYPASSED),),
            (
                ComponentSpec(
                    "unauthorized-effect",
                    F.DIRECT_FINANCIAL,
                    "repeat_loss",
                    1,
                    {
                        "repeat_count": A("repeat_count"),
                        "loss_per_event": A("loss_per_event"),
                        "recovery_rate": P("recovery_rate"),
                    },
                ),
                ComponentSpec(
                    "control-recovery",
                    F.RECOVERY,
                    "fixed_plus_hours",
                    1,
                    {
                        "fixed_cost": A("recovery_fixed_cost"),
                        "hourly_rate": P("engineering_hourly_rate"),
                        "hours": A("recovery_hours"),
                    },
                ),
                ComponentSpec("incident-response", F.INCIDENT_RESPONSE, "lump_sum", 1, {"amount": A("incident_response_cost")}),
            ),
            (
                recovery_note,
                "the size of one unauthorized effect is the effect's own, stated with its source (an amount is never "
                "MYTHOS_OBSERVED: the signed observation carries none); the repeat count is how often it recurs "
                "before the approval control is restored",
                remediation_note,
            ),
        ),
        Template(
            "third_party_provider_outage",
            1,
            "Third-party model/provider outage",
            6,
            (Scope(E.PROVIDER_OUTAGE),),
            (
                ComponentSpec(
                    "interruption",
                    F.BUSINESS_INTERRUPTION,
                    "interruption",
                    1,
                    {"interruption_hours": A("outage_hours"), "value_per_hour": P("margin_per_hour")},
                ),
                ComponentSpec(
                    "failover-recovery",
                    F.RECOVERY,
                    "fixed_plus_hours",
                    1,
                    {
                        "fixed_cost": A("recovery_fixed_cost"),
                        "hourly_rate": P("engineering_hourly_rate"),
                        "hours": A("recovery_hours"),
                    },
                ),
                ComponentSpec(
                    "sla-credits",
                    F.CONTRACTUAL,
                    "capped_credit",
                    1,
                    {
                        "credit_per_hour": A("sla_credit_per_hour"),
                        "breach_hours": A("outage_hours"),
                        "contract_cap": A("sla_credit_cap"),
                    },
                ),
            ),
            (
                "the outage's length drives the interruption and the SLA credits alike: one parameter, read by both "
                "in the same direction",
                "the interruption is read at the critical service's MARGIN per hour, not its revenue: revenue lost "
                "is not all loss",
                "the customer's recovery time objective is a target, never read as the outage's length",
                "SLA credits are capped by the contracts' cap; a higher cap never lowers the loss",
            ),
        ),
    )


#: Every template, by ``(template_id, version)``. Read-only. A changed template is
#: a new version; an old one stays.
CATALOGUE: Mapping[tuple[str, int], Template] = MappingProxyType({t.key: t for t in _templates()})

#: The templates a build chooses from now, in precedence order (the lowest first).
TEMPLATES: tuple[Template, ...] = tuple(sorted(CATALOGUE.values(), key=lambda t: t.precedence))


def template(template_id: str, version: int) -> Template:
    found = CATALOGUE.get((template_id, version))
    if found is None:
        raise BuildRefused("effect_out_of_scope", f"no template {template_id!r} version {version!r}")
    return found


# ------------------------------------------------------------------ the checks

_EFFECT_KEY = re.compile(r"[a-z0-9][a-z0-9_-]{0,59}")


def check_effect_key(value) -> str:
    if not isinstance(value, str) or not _EFFECT_KEY.fullmatch(value):
        raise BuildRefused("effect_key_malformed", repr(value)[:120])
    return value


def _code(enum, value, refusal: str, what: str):
    if not isinstance(value, str):
        raise BuildRefused(refusal, f"{what} {value!r}")
    try:
        return enum(value)
    except ValueError:
        raise BuildRefused(refusal, f"{what} {value!r}") from None


def check_effect_type(value, what: str = "effect_type") -> EffectType:
    return _code(EffectType, value, "effect_type_unrecognised", what)


def check_business_process(value, what: str = "business_process") -> BusinessProcess:
    return _code(BusinessProcess, value, "business_process_unrecognised", what)


def check_origin(value, what: str = "origin") -> Origin:
    return _code(Origin, value, "origin_unrecognised", what)


def check_role(value, what: str = "role") -> FindingRole:
    return _code(FindingRole, value, "finding_role_unrecognised", what)


def parse_attributes(
    effect_key: str, raw, path: str, *, origin: Origin, attributes: Mapping[str, Attribute] | None = None
) -> dict[str, Parameter]:
    """An effect's attributes read from ``raw`` (``{name: entry}``, each entry in the
    parameter-set document's form: unit, low, base, high, currency for money,
    source_type, evidence_ref, effective_date, and optionally fresh_until and the
    distribution it states, which the builder reads with
    :func:`.parameter_set.stated_distribution`), or refused. Each becomes a
    :class:`.parameters.Parameter` named ``<effect>.<name>``,
    so every rule of a parameter holds. An attribute the pack does not hold is
    ``attribute_unrecognised``; a unit that is not its unit is ``unit_mismatch``.
    ``MYTHOS_OBSERVED`` is never on a hypothetical effect's attribute
    (``observed_source_on_hypothetical``), and on an observed effect's only where the
    attribute is :attr:`Attribute.observable` (``observed_source_not_observable``);
    that its evidence names the observed effect is checked once the effect is
    resolved (:func:`check_observed_evidence`). ``attributes`` is the pack's table
    of attributes: this pack's (:data:`ATTRIBUTES`) unless an industry pack's is
    given."""
    table = ATTRIBUTES if attributes is None else attributes
    if not isinstance(raw, dict):
        raise BuildRefused("attribute_unrecognised", f"{path} is not an object of attributes")
    found: dict[str, Parameter] = {}
    for name in sorted(raw):
        attribute = table.get(name) if isinstance(name, str) else None
        if attribute is None:
            raise BuildRefused("attribute_unrecognised", f"{path}: [{str(name)!r}]")
        parameter = pset._parameter(f"{effect_key}.{name}", attribute.unit, raw[name], f"{path}.{name}")
        if parameter.source_type is SourceType.MYTHOS_OBSERVED:
            if origin is Origin.HYPOTHETICAL:
                raise BuildRefused("observed_source_on_hypothetical", f"{path}.{name}")
            if not attribute.observable:
                raise BuildRefused("observed_source_not_observable", f"{path}.{name}")
        found[name] = parameter
    return found


def names_observed_effect(evidence_ref: str, spine_effect: str) -> bool:
    """Whether ``evidence_ref`` is bound to the observed effect ``spine_effect`` (its
    SPINE effect digest): it IS the digest, or it STARTS with the digest and a space
    (the digest, then a note). A digest that is only somewhere in the text binds
    nothing -- "NOT observed; estimated by hand; unrelated to <digest>" is not an
    observation of that effect -- and an evidence_ref naming two digests binds only
    the first."""
    return bool(spine_effect) and (evidence_ref == spine_effect or evidence_ref.startswith(spine_effect + " "))


def check_observed_evidence(effect_key: str, attributes: Mapping[str, Parameter], spine_effect: str) -> None:
    """Every ``MYTHOS_OBSERVED`` attribute of an observed effect is bound, by its
    ``evidence_ref``, to the observed effect it came from: ``spine_effect``, the SPINE
    effect digest the effect resolved to (:func:`names_observed_effect`;
    ``observed_source_unbound`` otherwise). An observation of one effect is never
    evidence for a figure of another."""
    for name, parameter in sorted(attributes.items()):
        if parameter.source_type is SourceType.MYTHOS_OBSERVED and not names_observed_effect(
            parameter.evidence_ref, spine_effect
        ):
            raise BuildRefused("observed_source_unbound", f"{effect_key}.{name}")


# ------------------------------------------------------- scope and precedence


@dataclass(frozen=True)
class Selection:
    """The template an effect is assigned to, and every template that covers it."""

    template: Template
    in_scope_of: tuple[Template, ...]

    def as_dict(self) -> dict:
        return {
            "template": [self.template.template_id, self.template.version],
            "in_scope_of": [[t.template_id, t.version] for t in self.in_scope_of],
            "chosen_by": "precedence" if len(self.in_scope_of) > 1 else "only_template_in_scope",
        }


def in_scope(effect_type: str, business_process: str) -> tuple[Template, ...]:
    """Every current template that covers ``effect_type`` on ``business_process``,
    in precedence order."""
    check_effect_type(effect_type)
    check_business_process(business_process)
    return tuple(t for t in TEMPLATES if t.covers(effect_type, business_process))


def select(effect_type: str, business_process: str) -> Selection:
    """The ONE template ``effect_type`` on ``business_process`` is assigned to: the
    covering template of lowest precedence; ``effect_out_of_scope`` when none covers
    it. An effect two templates cover is assigned to one of them, never both."""
    candidates = in_scope(effect_type, business_process)
    if not candidates:
        raise BuildRefused("effect_out_of_scope", f"{effect_type} on {business_process}")
    return Selection(candidates[0], candidates)


# ------------------------------------------------------------- the binding


@dataclass(frozen=True)
class PlannedComponent:
    """One component a template makes for one event: its spec, each input bound to
    the parameter its source holds, and the inputs whose source holds none (left
    unbound, so the formula makes the component unknown, never zero)."""

    spec: ComponentSpec
    bound: Mapping[str, tuple[Source, Parameter]]
    missing: Mapping[str, Source]

    def bindings(self) -> dict[str, Parameter]:
        return {name: parameter for name, (_source, parameter) in self.bound.items()}


def plan(
    chosen: Template,
    variables: Mapping[str, Parameter],
    attributes: Mapping[str, Parameter],
    inputs: Mapping[str, Parameter] | None = None,
) -> tuple[PlannedComponent, ...]:
    """Every component ``chosen`` makes, each input bound to the parameter its
    source names -- the parameter set's ``variables``, the effect's
    ``attributes``, or (an industry pack's template) the pack's ``inputs`` the
    parameter set states, by input name -- or left unbound when that source holds
    none. Nothing is bound that a recorded parameter does not hold: no default, no
    zero. (A build refuses a pack input a template it uses reads and the set does not
    state before it plans: :func:`.pack_registry.Pack.check_template_inputs`.) An
    optional component whose pack inputs the set does not state is not made
    (:meth:`Template.switched_off`)."""
    held_by = {
        SourceKind.PARAMETER_SET: variables,
        SourceKind.EFFECT_ATTRIBUTE: attributes,
        SourceKind.PACK_INPUT: {} if inputs is None else inputs,
    }
    planned = []
    for spec in chosen.components:
        if chosen.switched_off(spec, held_by[SourceKind.PACK_INPUT]):
            continue
        bound: dict[str, tuple[Source, Parameter]] = {}
        missing: dict[str, Source] = {}
        for name, source in spec.sources.items():
            held = held_by[source.kind]
            parameter = held.get(source.name)
            if parameter is None:
                missing[name] = source
                continue
            bound[name] = (source, parameter)
        planned.append(PlannedComponent(spec, MappingProxyType(bound), MappingProxyType(missing)))
    return tuple(planned)


# ------------------------------------------- an event's effects: the larger loss

#: The rule :func:`larger_loss` follows, named in the evidence of what it makes.
MERGE_RULE = "mythos.economics.larger-loss/v1"


@dataclass(frozen=True)
class Reading:
    """How a template reads one effect attribute: the ONE direction every formula
    input that reads it moves the loss in, and the sources those inputs accept
    (``None`` when none restricts them)."""

    attribute: str
    direction: Direction
    accepted_sources: frozenset[SourceType] | None


def readings(chosen: Template) -> Mapping[str, Reading]:
    """Every effect attribute ``chosen`` reads, by name. An attribute two inputs read
    in opposite directions would have no larger loss: that template is a defect
    (``ValueError``), and ``tests/test_economics_templates.py`` holds every template
    of the pack free of it."""
    found: dict[str, Reading] = {}
    for spec in chosen.components:
        inputs = {i.name: i for i in formula(spec.formula_id, spec.formula_version).inputs}
        for input_name, source in spec.sources.items():
            if source.kind is not SourceKind.EFFECT_ATTRIBUTE:
                continue
            read = inputs[input_name]
            accepted = read.accepted_sources
            prior = found.get(source.name)
            if prior is not None:
                if prior.direction is not read.direction:
                    raise ValueError(f"{chosen.template_id} reads {source.name} in two directions")
                if prior.accepted_sources is not None:
                    accepted = prior.accepted_sources if accepted is None else prior.accepted_sources & accepted
            found[source.name] = Reading(source.name, read.direction, accepted)
    return MappingProxyType(found)


@dataclass(frozen=True)
class Merged:
    """One attribute of one loss event, as its components read it: the parameter,
    the effects that took part (by key, sorted), which effect's value each point is,
    and whether it is CALCULATED from more than one (``derived``) or is the one
    effect's own parameter."""

    parameter: Parameter
    reading: Reading
    contributors: tuple[str, ...]
    supplied: Mapping[Point, str]
    derived: bool


def _amount(value):
    return value.amount if isinstance(value, Money) else value


def larger_loss(reading: Reading, stated: Mapping[str, Parameter], *, event_key: str) -> Merged:
    """The value an event reads for ``reading.attribute`` when its effects state it
    (``stated``: effect key to parameter, at least one): for each point SEPARATELY --
    low, base and high -- the value that gives the LARGER loss, by the direction of
    the formula inputs that read it (the highest where the input increases the loss,
    the lowest where it decreases it). Effects observed and hypothetical take part
    alike. Joined effects never understate: adding an effect never lowers the
    event's loss, and the result never depends on how the effects' keys are spelled
    (an exact tie is one value; the effect cited for it is the lowest key).

    Where the inputs accept only some sources (a churn rate only the customer's
    own), an effect whose source they refuse cannot supply the value and does not
    take part, unless none can, and then all do and the component is unknown as it
    is for any one of them. One effect taking part is read as itself. Two or more
    make a parameter named ``<event key>:<attribute>``, ``CALCULATED`` (or, where
    the inputs accept one source and every effect taking part rests on it, that
    source: each point is one of those figures, unchanged), holding from the latest
    date any effect SUPPLYING a point holds from and fresh no longer than the stalest
    of those (an effect supplying no point sets neither date; where the suppliers'
    latest date is after their earliest ``fresh_until`` the value was never fresh
    while it held, and a parameter cannot be fresh before it holds, so it is fresh
    until the day it holds from); the caller records which effects it was derived
    from."""
    if not stated:
        raise ValueError(f"no effect states {reading.attribute}")
    taking_part = dict(stated)
    if reading.accepted_sources is not None:
        eligible = {k: p for k, p in stated.items() if p.source_type in reading.accepted_sources}
        if eligible:
            taking_part = eligible
    keys = tuple(sorted(taking_part))
    currencies = {taking_part[k].currency for k in keys}
    if len(currencies) > 1:
        raise MoneyRefused(
            "currency_mismatch", f"{reading.attribute} of event {event_key} spans {sorted(map(str, currencies))}"
        )
    larger = (lambda a, b: a > b) if reading.direction is Direction.INCREASES else (lambda a, b: a < b)
    supplied: dict[Point, str] = {}
    for point in POINTS:
        best = keys[0]
        for key in keys[1:]:
            if larger(_amount(taking_part[key].at(point)), _amount(taking_part[best].at(point))):
                best = key
        supplied[point] = best
    if len(keys) == 1:
        return Merged(taking_part[keys[0]], reading, keys, MappingProxyType(supplied), False)
    sources = {taking_part[k].source_type for k in keys}
    if reading.accepted_sources is not None and len(sources) == 1 and sources <= reading.accepted_sources:
        (source_type,) = sources
    else:
        source_type = SourceType.CALCULATED
    # The dates are those of the effects that SUPPLY a point of the value, not of every
    # effect that took part: an effect whose figure is nowhere in the value says nothing
    # of when the value holds from or how long it is fresh (review round 2: a later,
    # fresher effect supplying nothing made a stale figure read as fresh).
    suppliers = sorted(set(supplied.values()))
    effective = [taking_part[k].effective_date for k in suppliers if taking_part[k].effective_date is not None]
    fresh = [taking_part[k].fresh_until for k in suppliers if taking_part[k].fresh_until is not None]
    effective_date = max(effective) if effective else None
    fresh_until = min(fresh) if fresh else None
    if fresh_until is not None and effective_date is not None and fresh_until < effective_date:
        fresh_until = effective_date
    first = taking_part[keys[0]]
    parameter = Parameter(
        name=f"{event_key}:{reading.attribute}",
        unit=first.unit,
        source_type=source_type,
        low=taking_part[supplied[Point.LOW]].low,
        base=taking_part[supplied[Point.BASE]].base,
        high=taking_part[supplied[Point.HIGH]].high,
        evidence_ref=(
            f"{MERGE_RULE}: at each point, the value of the {len(keys)} effects of loss event {event_key} stating "
            f"{reading.attribute} that gives the larger loss (the loss {reading.direction.value} with it); "
            "derived_from cites each, and an exact tie cites the lowest effect key"
        ),
        effective_date=effective_date,
        fresh_until=fresh_until,
    )
    return Merged(parameter, reading, keys, MappingProxyType(supplied), True)



def catalogue_document() -> dict:
    """The pack as data, for the spec and a reader: every template, attribute,
    effect type, business process, origin and finding role."""
    return {
        "pack": PACK,
        "templates": [t.as_dict() for t in TEMPLATES],
        "attributes": {name: a.as_dict() for name, a in ATTRIBUTES.items()},
        "effect_types": {t.value: meaning for t, meaning in EFFECT_TYPES.items()},
        "business_processes": [p.value for p in BusinessProcess],
        "origins": [o.value for o in Origin],
        "finding_roles": [r.value for r in FindingRole],
    }

