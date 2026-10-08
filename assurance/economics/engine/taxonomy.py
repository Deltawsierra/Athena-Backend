"""The loss taxonomy: fifteen loss families, each with a stable code.

Every scenario's cost is split into components, and every component names one of
these families, so scenarios can be compared, aggregated, back-tested and
recalibrated against each other (owner's specification, section 5). A code is
what a stored row, a fixture, a receipt and a report carry; the label is for a
reader. A code is never renamed or reused: a family that has to change is a new
code, and ``tests/test_economics_engine.py`` pins the list exactly.

The names are Mythos's own. They are not the Open FAIR loss forms, and nothing
here claims Open FAIR conformance (``docs/economics/spec-v1.md``, section 9).

A market-value reaction (a share price falling after an incident) is not a loss
family. It is never cash loss, and it is never added to a family's total (spec,
section 3).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType


class LossFamily(StrEnum):
    """The fifteen families, in the order the owner's specification lists them.
    The value is the stable code."""

    DIRECT_FINANCIAL = "direct_financial"
    BUSINESS_INTERRUPTION = "business_interruption"
    INCIDENT_RESPONSE = "incident_response"
    RECOVERY = "recovery"
    LEGAL = "legal"
    REGULATORY_COMPLIANCE = "regulatory_compliance"
    NOTIFICATION = "notification"
    CUSTOMER_RESTITUTION = "customer_restitution"
    CONTRACTUAL = "contractual"
    DATA_AND_IP = "data_and_ip"
    CUSTOMER_LOSS = "customer_loss"
    THIRD_PARTY_DOWNSTREAM = "third_party_downstream"
    INSURANCE = "insurance"
    REMEDIATION_INVESTMENT = "remediation_investment"
    PHYSICAL_OPERATIONAL = "physical_operational"


@dataclass(frozen=True)
class Family:
    """One family as a reader sees it: its label, what it covers, and the inputs it
    typically needs (section 5's columns)."""

    code: LossFamily
    label: str
    examples: str
    typical_inputs: str


#: Every family, keyed by its code. Read-only.
FAMILIES: Mapping[LossFamily, Family] = MappingProxyType(
    {
        f.code: f
        for f in (
            Family(
                LossFamily.DIRECT_FINANCIAL,
                "Direct financial loss",
                "Fraud, theft, unauthorized transfer, erroneous disbursement",
                "Transaction count, value, recoverability, fraud controls",
            ),
            Family(
                LossFamily.BUSINESS_INTERRUPTION,
                "Business interruption",
                "Lost revenue or margin, missed transactions, degraded service",
                "Revenue per hour, transactions per hour, outage duration, backlog",
            ),
            Family(
                LossFamily.INCIDENT_RESPONSE,
                "Incident response",
                "Forensics, external responders, war room, communications",
                "Retainer and rates, labor hours, vendor pricing",
            ),
            Family(
                LossFamily.RECOVERY,
                "Recovery",
                "Restore, rebuild, reissue credentials, infrastructure replacement",
                "Cloud and infrastructure prices, engineering labor, recovery time",
            ),
            Family(
                LossFamily.LEGAL,
                "Legal",
                "External counsel, discovery, litigation, settlement defense",
                "Hourly rates, matter complexity, jurisdictions",
            ),
            Family(
                LossFamily.REGULATORY_COMPLIANCE,
                "Regulatory and compliance",
                "Investigation, mandatory remediation, penalties where legally grounded",
                "Jurisdiction, regulator, precedent, statutory range",
            ),
            Family(
                LossFamily.NOTIFICATION,
                "Notification",
                "Customer and regulator notices, call center, monitoring services",
                "Affected count, jurisdiction, unit cost",
            ),
            Family(
                LossFamily.CUSTOMER_RESTITUTION,
                "Customer restitution",
                "Credits, reimbursements, identity protection, reversed fees",
                "Affected customers, per-customer amount",
            ),
            Family(
                LossFamily.CONTRACTUAL,
                "Contractual",
                "SLA credits, indemnification, partner claims",
                "Contract terms, caps, counterparties",
            ),
            Family(
                LossFamily.DATA_AND_IP,
                "Data and intellectual property",
                "Trade secrets, model assets, proprietary data, training corpus",
                "Replacement cost, license value, lost advantage",
            ),
            Family(
                LossFamily.CUSTOMER_LOSS,
                "Customer loss",
                "Churn, reduced acquisition, lost recurring margin",
                "Customer value, churn delta, recovery period",
            ),
            Family(
                LossFamily.THIRD_PARTY_DOWNSTREAM,
                "Third-party and downstream",
                "Vendor remediation, partner losses, pass-through liability",
                "Vendor relationships, contracts, dependency graph",
            ),
            Family(
                LossFamily.INSURANCE,
                "Insurance",
                "Deductible, uninsured portion, premium impact",
                "Policy limits, deductible, exclusions, retention",
            ),
            Family(
                LossFamily.REMEDIATION_INVESTMENT,
                "Remediation investment",
                "Engineering, controls, licenses, operational change",
                "Labor, vendor, cloud, implementation schedule",
            ),
            Family(
                LossFamily.PHYSICAL_OPERATIONAL,
                "Physical and operational",
                "Equipment, fleet, plant, cyber-physical downtime",
                "Asset value, downtime, repair, replacement, safety response",
            ),
        )
    }
)


def loss_family(code: str) -> LossFamily:
    """The family a stored code names. An unknown code raises ``ValueError``: a
    component whose family nobody can read is never filed under a guess."""
    return LossFamily(code)
