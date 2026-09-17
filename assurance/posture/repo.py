"""3.4 Repository / SDLC — the source-control and delivery-pipeline posture.

The checks a repository/SDLC read would make once credentials are granted: whether
the default branch is protected and reviewed, whether CI/CD runners and workflow
token permissions are over-exposed, whether dependencies carry known
vulnerabilities, whether infrastructure-as-code is misconfigured, whether secrets
are embedded in the repository, and whether the pipeline configuration has drifted.
Evaluated against fetched (or fixture) posture data — never a live scan here.

Honesty, per the framework: a check with no data reads ``unknown``, never
``pass``. Repository/SDLC posture is read from configuration and scan output — an
observed fact about *config*, not a measured runtime behaviour — so every finding
here is ``configuration_verified`` when observed and ``unknown`` /
``not_documented`` when the datum is absent. This domain deliberately never claims
``technically_verified``: it did not execute anything to verify behaviour. As with
the secrets domain, an embedded-secret indicator is surfaced as a count and
type/location fact only — never the credential value.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.conf import settings

from ..capability import RISK_ELEVATED, RISK_HIGH
from .base import (
    PostureAssessment,
    PostureCheck,
    PostureConfig,
    _as_dict,
    config_gap,
    config_pass,
    unknown,
)


@dataclass(frozen=True)
class RepoPostureConfig(PostureConfig):
    """What a live repository/SDLC read needs: which organisation/project to read,
    the base URL of the SCM/CI posture source, and a token. From settings/env only;
    no source default, so an unconfigured environment is inert."""

    organization: str | None = None
    base_url: str | None = None
    token: str | None = None

    def is_configured(self) -> bool:
        return bool(self.organization and self.base_url and self.token)


# ---------------------------------------------------------------------------
# Evaluators
# ---------------------------------------------------------------------------


def _default_branches(d: dict) -> list:
    branches = d.get("branches") or []
    return branches if isinstance(branches, list) else []


def _eval_branch_protection(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "branches" not in d:
        return unknown("no branch-protection configuration was read")
    branches = _default_branches(d)
    defaults = [b for b in branches if isinstance(b, dict) and b.get("default")]
    if not defaults:
        return unknown("no default branch was identified in the read scope")
    unprotected = [b.get("name", "?") for b in defaults if b.get("protected") is not True]
    if unprotected:
        return config_gap(
            f"the default branch ({', '.join(unprotected)}) has no branch protection"
        )
    return config_pass("the default branch has branch protection enabled")


def _eval_required_reviews(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "branches" not in d:
        return unknown("no branch-protection configuration was read")
    branches = _default_branches(d)
    defaults = [b for b in branches if isinstance(b, dict) and b.get("default")]
    if not defaults:
        return unknown("no default branch was identified in the read scope")
    declared = [b for b in defaults if isinstance(b.get("required_reviews"), int)]
    if not declared:
        return unknown("the default branch did not report a required-review count")
    unreviewed = [b.get("name", "?") for b in declared if b["required_reviews"] < 1]
    if unreviewed:
        return config_gap(
            f"the default branch ({', '.join(unreviewed)}) requires no pull-request review"
        )
    return config_pass("the default branch requires at least one pull-request review")


def _eval_runner_exposure(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "runners" not in d:
        return unknown("no CI/CD runner inventory was read")
    runners = d.get("runners") or []
    if not isinstance(runners, list):
        return unknown("CI/CD runner data was malformed")
    exposed = [
        r.get("name", "?")
        for r in runners
        if isinstance(r, dict) and r.get("self_hosted") and r.get("public_repo")
    ]
    if exposed:
        return config_gap(
            f"{len(exposed)} self-hosted runner(s) are attached to public repositories"
        )
    return config_pass("no self-hosted runner is exposed to a public repository")


def _eval_workflow_permissions(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "workflows" not in d:
        return unknown("no CI/CD workflow configuration was read")
    workflows = d.get("workflows") or []
    if not isinstance(workflows, list):
        return unknown("CI/CD workflow data was malformed")
    overbroad = [
        w.get("name", "?")
        for w in workflows
        if isinstance(w, dict) and w.get("token_permissions") == "write-all"
    ]
    if overbroad:
        return config_gap(
            f"{len(overbroad)} workflow(s) grant the pipeline token write-all permissions"
        )
    return config_pass("no workflow grants the pipeline token write-all permissions")


def _eval_dependency_risk(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "assessed" not in d:
        return unknown("no dependency scan was read")
    if not d.get("assessed"):
        return unknown("dependencies have not been scanned for known vulnerabilities")
    vulnerable = d.get("vulnerable") or []
    if not isinstance(vulnerable, list):
        return unknown("dependency scan data was malformed")
    if vulnerable:
        return config_gap(
            f"{len(vulnerable)} dependency/dependencies carry known vulnerabilities"
        )
    return config_pass("the dependency scan reported no known-vulnerable dependencies")


def _eval_iac_misconfig(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "assessed" not in d:
        return unknown("no infrastructure-as-code scan was read")
    if not d.get("assessed"):
        return unknown("infrastructure-as-code has not been scanned for misconfiguration")
    misconfigs = d.get("misconfigurations") or []
    if not isinstance(misconfigs, list):
        return unknown("infrastructure-as-code scan data was malformed")
    if misconfigs:
        return config_gap(
            f"{len(misconfigs)} infrastructure-as-code misconfiguration(s) were found"
        )
    return config_pass("the infrastructure-as-code scan reported no misconfiguration")


def _eval_embedded_secrets(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "indicators" not in d:
        return unknown("no source scan for embedded-secret indicators was read")
    indicators = d.get("indicators") or []
    if not isinstance(indicators, list):
        return unknown("embedded-secret indicator data was malformed")
    if indicators:
        # Count and kind only — never the secret value.
        kinds = sorted({str(i.get("type", "unknown")) for i in indicators if isinstance(i, dict)})
        return config_gap(
            f"{len(indicators)} embedded-secret indicator(s) present in the repository "
            f"(kinds: {', '.join(kinds)})"
        )
    return config_pass("no embedded-secret indicator was found in the read scope")


def _eval_repo_drift(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "baseline_present" not in d:
        return unknown("no pipeline-configuration baseline was available to compare against")
    if not d.get("baseline_present"):
        return unknown("no declared baseline exists for the pipeline configuration")
    drifted = d.get("drifted") or []
    if not isinstance(drifted, list):
        return unknown("pipeline drift data was malformed")
    if drifted:
        return config_gap(
            f"{len(drifted)} pipeline setting(s) have drifted from the declared baseline"
        )
    return config_pass("no drift from the declared pipeline baseline was observed")


# ---------------------------------------------------------------------------
# The domain
# ---------------------------------------------------------------------------


class RepoPosture(PostureAssessment):
    """3.4 Repository / SDLC posture over source control and the delivery pipeline."""

    name = "repo"
    label = "Repository / SDLC"
    config_class = RepoPostureConfig

    CHECKS = (
        PostureCheck(
            key="repo_branch_protection",
            title="Default-branch protection",
            severity=RISK_HIGH,
            resource="branch_protection",
            category="source_control",
            description="Whether the default branch has branch protection enabled.",
            evaluate=_eval_branch_protection,
        ),
        PostureCheck(
            key="repo_required_reviews",
            title="Required pull-request review",
            severity=RISK_ELEVATED,
            resource="branch_protection",
            category="source_control",
            description="Whether the default branch requires at least one review.",
            evaluate=_eval_required_reviews,
        ),
        PostureCheck(
            key="repo_runner_exposure",
            title="CI/CD runner exposure",
            severity=RISK_HIGH,
            resource="cicd",
            category="pipeline",
            description="Self-hosted runners attached to public repositories.",
            evaluate=_eval_runner_exposure,
        ),
        PostureCheck(
            key="repo_workflow_permissions",
            title="Pipeline token permissions",
            severity=RISK_ELEVATED,
            resource="cicd",
            category="pipeline",
            description="Workflows granting the pipeline token write-all permissions.",
            evaluate=_eval_workflow_permissions,
        ),
        PostureCheck(
            key="repo_dependency_risk",
            title="Dependency vulnerability risk",
            severity=RISK_HIGH,
            resource="dependencies",
            category="supply_chain",
            description="Dependencies with known vulnerabilities.",
            evaluate=_eval_dependency_risk,
        ),
        PostureCheck(
            key="repo_iac_misconfig",
            title="Infrastructure-as-code misconfiguration",
            severity=RISK_ELEVATED,
            resource="iac",
            category="supply_chain",
            description="Misconfigurations found in infrastructure-as-code.",
            evaluate=_eval_iac_misconfig,
        ),
        PostureCheck(
            key="repo_embedded_secrets",
            title="Embedded repository secrets",
            severity=RISK_HIGH,
            resource="embedded_secrets",
            category="secrets",
            description="Indicators of secrets embedded in the repository (presence only).",
            evaluate=_eval_embedded_secrets,
        ),
        PostureCheck(
            key="repo_drift",
            title="Pipeline configuration drift",
            severity=RISK_ELEVATED,
            resource="repo_drift",
            category="drift",
            description="Pipeline settings that have drifted from the declared baseline.",
            evaluate=_eval_repo_drift,
        ),
    )

    @classmethod
    def config_from_settings(cls) -> RepoPostureConfig:
        return RepoPostureConfig(
            organization=getattr(settings, "POSTURE_REPO_ORG", None),
            base_url=getattr(settings, "POSTURE_REPO_URL", None),
            token=getattr(settings, "POSTURE_REPO_TOKEN", None),
        )
