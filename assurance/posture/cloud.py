"""3.2 Cloud Assurance — the cloud posture behind an AI deployment.

The checks a cloud read would make once credentials are granted, framed as *paths
into the AI deployment*: what is publicly exposed, where identity is
over-permissioned, which storage is reachable or unencrypted, what the network
actually lets through, and where the running estate has drifted from its declared
baseline. Every check is evaluated against the fetched (or, in tests, fixture)
cloud posture data — this module reads that data and reasons over it; it never
scans a live account itself (the :class:`~assurance.posture.base.Fetcher` does the
reading, and only when configured).

Honesty, per the framework: a check with no data reads ``unknown``, never
``pass``; observed configuration is ``configuration_verified``; a *measured*
network reachability probe (an actual connection result the data carries) is
``technically_verified``; nothing is ever reported "secure". No account id, ARN,
IP, or credential value is emitted — only presence/hygiene facts and counts.
"""

from __future__ import annotations

from django.conf import settings

from ..capability import RISK_ELEVATED, RISK_HIGH
from .base import (
    PostureAssessment,
    PostureCheck,
    PostureConfig,
    _as_dict,
    config_gap,
    config_pass,
    measured_gap,
    measured_pass,
    unknown,
)
from dataclasses import dataclass


@dataclass(frozen=True)
class CloudPostureConfig(PostureConfig):
    """What a live cloud read needs: which account/project to read and a token to
    read it with, plus the base URL of the posture source. All from settings/env;
    no source default, so an unconfigured environment is inert."""

    account: str | None = None
    base_url: str | None = None
    token: str | None = None

    def is_configured(self) -> bool:
        return bool(self.account and self.base_url and self.token)


# ---------------------------------------------------------------------------
# Evaluators — pure functions of one fetched resource payload
# ---------------------------------------------------------------------------


def _eval_public_exposure(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "public_endpoints" not in d:
        return unknown("no public-exposure data was read for this account")
    endpoints = d.get("public_endpoints") or []
    if not isinstance(endpoints, list):
        return unknown("public-exposure data was malformed")
    if endpoints:
        return config_gap(
            f"{len(endpoints)} internet-facing endpoint(s) front the deployment"
        )
    return config_pass("no internet-facing endpoints were observed in the read scope")


def _eval_unrestricted_ingress(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "security_groups" not in d:
        return unknown("no network security-group configuration was read")
    groups = d.get("security_groups") or []
    if not isinstance(groups, list):
        return unknown("network security-group data was malformed")
    open_groups = [
        g.get("name", "?")
        for g in groups
        if isinstance(g, dict) and g.get("ingress_cidr") in ("0.0.0.0/0", "::/0")
    ]
    if open_groups:
        return config_gap(
            f"{len(open_groups)} security group(s) allow ingress from any address"
        )
    return config_pass("no security group was observed open to any address")


def _eval_network_reachability(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "probes" not in d:
        return unknown("no network reachability was measured for this account")
    probes = d.get("probes") or []
    if not isinstance(probes, list):
        return unknown("network reachability data was malformed")
    # Only a probe carrying an actual measured result is treated as verified
    # behaviour; a probe without ``measured`` is configuration, not observation.
    measured = [p for p in probes if isinstance(p, dict) and p.get("measured")]
    if not measured:
        return unknown("network probes were listed but none carried a measured result")
    reachable = [p.get("target", "?") for p in measured if p.get("reachable")]
    if reachable:
        return measured_gap(
            f"{len(reachable)} sensitive target(s) were reachable when probed"
        )
    return measured_pass("no probed sensitive target was reachable")


def _eval_iam_wildcard(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "principals" not in d:
        return unknown("no IAM principal data was read for this account")
    principals = d.get("principals") or []
    if not isinstance(principals, list):
        return unknown("IAM principal data was malformed")
    wildcard = [
        p.get("name", "?")
        for p in principals
        if isinstance(p, dict) and p.get("wildcard_actions")
    ]
    if wildcard:
        return config_gap(
            f"{len(wildcard)} principal(s) hold wildcard ('*') action permissions"
        )
    return config_pass("no principal was observed holding wildcard action permissions")


def _eval_iam_admin_sprawl(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "principals" not in d:
        return unknown("no IAM principal data was read for this account")
    principals = d.get("principals") or []
    if not isinstance(principals, list):
        return unknown("IAM principal data was malformed")
    admins = [p.get("name", "?") for p in principals if isinstance(p, dict) and p.get("admin")]
    if admins:
        return config_gap(f"{len(admins)} principal(s) hold administrator-equivalent access")
    return config_pass("no principal was observed holding administrator-equivalent access")


def _eval_storage_public(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "buckets" not in d:
        return unknown("no storage-bucket configuration was read for this account")
    buckets = d.get("buckets") or []
    if not isinstance(buckets, list):
        return unknown("storage-bucket data was malformed")
    public = [b.get("name", "?") for b in buckets if isinstance(b, dict) and b.get("public")]
    if public:
        return config_gap(f"{len(public)} storage bucket(s) are publicly readable")
    return config_pass("no storage bucket was observed to be publicly readable")


def _eval_storage_encryption(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "buckets" not in d:
        return unknown("no storage-bucket configuration was read for this account")
    buckets = d.get("buckets") or []
    if not isinstance(buckets, list):
        return unknown("storage-bucket data was malformed")
    # A bucket with no ``encrypted`` field is unknown-per-bucket; only an explicit
    # ``encrypted: false`` is a gap, so an absent field never reads as encrypted.
    unencrypted = [
        b.get("name", "?")
        for b in buckets
        if isinstance(b, dict) and b.get("encrypted") is False
    ]
    undeclared = [
        b.get("name", "?")
        for b in buckets
        if isinstance(b, dict) and "encrypted" not in b
    ]
    if unencrypted:
        return config_gap(
            f"{len(unencrypted)} storage bucket(s) have encryption-at-rest disabled"
        )
    if undeclared:
        return unknown(
            f"{len(undeclared)} storage bucket(s) did not report an encryption-at-rest state"
        )
    return config_pass("every read bucket reported encryption-at-rest enabled")


def _eval_drift(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "baseline_present" not in d:
        return unknown("no infrastructure baseline was available to compare against")
    if not d.get("baseline_present"):
        return unknown("no declared baseline exists for the running estate")
    drifted = d.get("drifted_resources") or []
    if not isinstance(drifted, list):
        return unknown("drift data was malformed")
    if drifted:
        return config_gap(
            f"{len(drifted)} running resource(s) have drifted from the declared baseline"
        )
    return config_pass("no drift from the declared baseline was observed")


# ---------------------------------------------------------------------------
# The domain
# ---------------------------------------------------------------------------


class CloudPosture(PostureAssessment):
    """3.2 Cloud Assurance posture over the cloud estate behind a deployment."""

    name = "cloud"
    label = "Cloud Assurance"
    config_class = CloudPostureConfig
    secret_field = "token"
    settings_fields = ("account", "base_url")

    CHECKS = (
        PostureCheck(
            key="cloud_public_exposure",
            title="Public internet exposure",
            severity=RISK_HIGH,
            resource="public_exposure",
            category="network",
            description="Internet-facing endpoints that front the AI deployment.",
            evaluate=_eval_public_exposure,
        ),
        PostureCheck(
            key="cloud_unrestricted_ingress",
            title="Unrestricted network ingress",
            severity=RISK_HIGH,
            resource="network",
            category="network",
            description="Security groups that allow ingress from any address (0.0.0.0/0).",
            evaluate=_eval_unrestricted_ingress,
        ),
        PostureCheck(
            key="cloud_network_reachability",
            title="Sensitive network reachability",
            severity=RISK_ELEVATED,
            resource="network",
            category="network",
            description="Whether a probe actually reached a sensitive internal target.",
            evaluate=_eval_network_reachability,
        ),
        PostureCheck(
            key="cloud_iam_wildcard",
            title="Wildcard IAM permissions",
            severity=RISK_HIGH,
            resource="iam",
            category="identity",
            description="Principals granted wildcard ('*') actions — over-permissioning.",
            evaluate=_eval_iam_wildcard,
        ),
        PostureCheck(
            key="cloud_iam_admin_sprawl",
            title="Administrator access sprawl",
            severity=RISK_ELEVATED,
            resource="iam",
            category="identity",
            description="Principals holding administrator-equivalent access.",
            evaluate=_eval_iam_admin_sprawl,
        ),
        PostureCheck(
            key="cloud_storage_public",
            title="Publicly readable storage",
            severity=RISK_HIGH,
            resource="storage",
            category="storage",
            description="Object-storage buckets exposed to public read.",
            evaluate=_eval_storage_public,
        ),
        PostureCheck(
            key="cloud_storage_encryption",
            title="Storage encryption at rest",
            severity=RISK_ELEVATED,
            resource="storage",
            category="storage",
            description="Object-storage buckets without encryption-at-rest enabled.",
            evaluate=_eval_storage_encryption,
        ),
        PostureCheck(
            key="cloud_drift",
            title="Infrastructure drift",
            severity=RISK_ELEVATED,
            resource="drift",
            category="drift",
            description="Running resources that have drifted from the declared baseline.",
            evaluate=_eval_drift,
        ),
    )

    @classmethod
    def config_from_settings(cls) -> CloudPostureConfig:
        return CloudPostureConfig(
            account=getattr(settings, "POSTURE_CLOUD_ACCOUNT", None),
            base_url=getattr(settings, "POSTURE_CLOUD_URL", None),
            token=getattr(settings, "POSTURE_CLOUD_TOKEN", None),
        )
