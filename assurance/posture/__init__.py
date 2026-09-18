"""Credential-gated Phase 3 posture assessments (3.2 / 3.3 / 3.4).

A shared, read-oriented posture framework and three domains that, once live, read
a customer's cloud account, secret store, or source-control / CI system through
credentials the customer grants:

- **3.2 Cloud Assurance** (:class:`~assurance.posture.cloud.CloudPosture`) — public
  exposure, IAM over-permissioning, storage/bucket exposure, network reachability,
  drift.
- **3.3 Secrets / Crypto** (:class:`~assurance.posture.secrets.SecretsPosture`) —
  TLS/cert validity, KMS/key rotation, secret-store hygiene, committed-secret
  indicators, encryption at rest.
- **3.4 Repository / SDLC** (:class:`~assurance.posture.repo.RepoPosture`) — branch
  protection, CI/CD runner exposure, dependency risk, IaC misconfig, embedded
  secrets, drift.

Built adapter-only behind a clean, **read-only** transport-injected interface
(:class:`~assurance.posture.base.Fetcher`): production-quality checks exercised
against a recording fake fetcher in tests. **Inert by default** — with no
configured credentials a domain makes no fetch and reports
``{"connected": false, ...}`` with the catalog of checks it *would* run. Live
wiring is now in place: a per-tenant :class:`~assurance.models.PostureBinding`
(resource URL + read-credential encrypted at rest via :mod:`assurance.crypto`)
points a domain at a real resource for a deployment, and the read then fetches and
evaluates against it. With no binding and no encryption key, the domain stays inert
exactly as before. See :mod:`assurance.posture.base` for the interface and the
honesty contract.
"""

from __future__ import annotations

from .base import (
    Fetcher,
    PostureAssessment,
    PostureCheck,
    PostureConfig,
    PostureFinding,
    RequestsFetcher,
    Response,
    STATUS_GAP,
    STATUS_PASS,
    STATUS_UNKNOWN,
)
from .cloud import CloudPosture, CloudPostureConfig
from .registry import (
    UnknownPostureDomain,
    available_domains,
    build_assessment,
    get_assessment_class,
)
from .repo import RepoPosture, RepoPostureConfig
from .secrets import SecretsPosture, SecretsPostureConfig

__all__ = [
    "CloudPosture",
    "CloudPostureConfig",
    "Fetcher",
    "PostureAssessment",
    "PostureCheck",
    "PostureConfig",
    "PostureFinding",
    "RepoPosture",
    "RepoPostureConfig",
    "RequestsFetcher",
    "Response",
    "STATUS_GAP",
    "STATUS_PASS",
    "STATUS_UNKNOWN",
    "SecretsPosture",
    "SecretsPostureConfig",
    "UnknownPostureDomain",
    "available_domains",
    "build_assessment",
    "get_assessment_class",
]
