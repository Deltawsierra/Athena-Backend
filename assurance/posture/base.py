"""Credential-gated posture assessments — the shared, read-oriented framework.

Phase 3 grows the assurance layer past the signals a deployment already declares
into the **credential-gated posture assessments** (3.2 Cloud Assurance, 3.3
Secrets / Crypto, 3.4 Repository / SDLC): checks that would, once live, read a
customer's cloud account, secret store, or source-control / CI system through
credentials the customer grants. This package is the framework the three domains
share. It combines two patterns already proven in this codebase:

- **The inert-by-default adapter pattern** (:mod:`assurance.connectors`). The one
  thing that ever touches the network — here a *read-only* :class:`Fetcher`, a
  ``fetch(resource, *, params)`` call — is **injected**: a real HTTP fetcher in
  production, a recording fake in tests. No domain imports an HTTP client, nothing
  reaches the network at import, and a :class:`PostureConfig` read from
  settings/env (with **no source default and no committed secret or URL**) answers
  one question — :meth:`~PostureConfig.is_configured`. When a domain is not
  configured it is **inert**: :meth:`PostureAssessment.assess` returns an honest
  ``{"connected": false, ...}`` report and **makes no fetch at all**, exactly like
  a connector returns ``"<name> not configured"``.
- **The computed-assessment pattern** (:mod:`assurance.compliance`,
  :mod:`assurance.capability`, :mod:`assurance.boundary`). A report is a pure,
  deterministic function of its input — here the fetched (or, in tests, fixture)
  posture data — with no new model, no migration, and no timestamp in its
  identity. It reuses the risk-band vocabulary (:data:`RISK_HIGH` /
  :data:`RISK_ELEVATED` / :data:`RISK_BASELINE`) and the
  :class:`~assurance.models.EvidenceClass` taxonomy rather than inventing its own.

The honesty discipline the assurance layer holds everywhere is enforced here:

- **A check with no data reads ``unknown`` — never ``pass``.** A ``pass`` is only
  ever the *observed* absence of a gap; missing data is a gap to close, surfaced as
  ``unknown``, and nothing is ever reported "secure" or "compliant".
- **Evidence honesty.** Every finding carries the
  :class:`~assurance.models.EvidenceClass` that reflects *how it was actually
  determined*. Observed configuration is ``configuration_verified``; a measured
  behaviour (a probe/handshake result the data carries) is
  ``technically_verified``; data nobody supplied is ``unknown`` /
  ``not_documented``. A domain never claims ``technically_verified`` for data it
  did not observe.
- **Inert when unconfigured.** No credentials → no fetch → ``connected: false`` and
  the catalog of checks it *would* run, never a fabricated "all clear".

**Live wiring is now in place**: a per-tenant
:class:`~assurance.models.PostureBinding` binds a real read-only :class:`Fetcher`
to a resource URL and a read-credential encrypted at rest, and a configured domain
then fetches and evaluates against it. A domain with no binding and no key stays
inert, exactly as before — ``connected: false`` and the catalog only.
"""

from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

# Reuse — never redefine — the risk-band vocabulary and the evidence taxonomy.
from ..capability import RISK_BASELINE, RISK_ELEVATED, RISK_HIGH, _RISK_ORDER, _max_risk
from ..models import EvidenceClass, evidence_strength

# ---------------------------------------------------------------------------
# Status vocabulary — the honest verdict of a single check
# ---------------------------------------------------------------------------

#: The check observed data that shows no gap for it. NOT "secure" — only the
#: observed absence of the specific gap this check looks for.
STATUS_PASS = "pass"
#: The check observed data that shows a gap — the finding to act on.
STATUS_GAP = "gap"
#: The check had no data to judge (nothing was fetched for it, or the datum was
#: absent). An honest not-known — never silently a pass.
STATUS_UNKNOWN = "unknown"

# gap first (act on it), then unknown (close the gap in knowledge), then pass.
_STATUS_ORDER = {STATUS_GAP: 0, STATUS_UNKNOWN: 1, STATUS_PASS: 2}


# ---------------------------------------------------------------------------
# The read-only transport seam — the only thing that ever touches the network
# ---------------------------------------------------------------------------


@runtime_checkable
class Response(Protocol):
    """The minimal response shape a domain reads back from a fetch: a status code
    and a JSON body. ``requests.Response`` satisfies it, and so does the tiny fake
    the tests inject — the domains depend on this protocol, never on a concrete
    HTTP library."""

    status_code: int

    def json(self) -> Any: ...


@runtime_checkable
class Fetcher(Protocol):
    """The single **read-only** I/O primitive a domain is given. One ``fetch``
    call, naming the resource to read and optional query params. The real one wraps
    an HTTP client; the test one records the call and returns a canned
    :class:`Response`. Injecting it is what keeps the domains free of any hardcoded
    network access — and lets a test prove an inert domain fetched nothing at all."""

    def fetch(self, resource: str, *, params: dict | None = None) -> Response: ...


class RequestsFetcher:
    """The production :class:`Fetcher`: a thin, read-only wrapper over
    ``requests.get``.

    It is **never constructed at import** and **never invoked unless a caller both
    builds it and passes it to a *configured* domain** — an unconfigured domain
    short-circuits in :meth:`PostureAssessment.assess` before any fetcher is
    touched. It carries a (connect, read) timeout so a hung upstream cannot pin a
    worker, mirroring the connector transport. No base URL lives here: the URL is
    always the one a domain formats from its injected config.

    A per-tenant :class:`~assurance.models.PostureBinding` supplies the base URL and
    the read-credential (as an ``Authorization`` header) for a configured domain;
    with no binding and no key, no domain is configured, so this class is never
    exercised against a live service.
    """

    def __init__(self, base_url: str | None = None, headers: dict | None = None,
                 timeout: tuple[float, float] = (3.05, 10.0)) -> None:
        self.base_url = base_url
        self.headers = headers or {}
        self.timeout = timeout

    def fetch(self, resource: str, *, params: dict | None = None) -> Response:
        # Imported lazily so merely importing this package pulls in no HTTP client
        # and nothing here can be mistaken for a call site.
        import requests

        base = (self.base_url or "").rstrip("/")
        url = f"{base}/{resource.lstrip('/')}" if base else resource
        return requests.get(url, headers=self.headers, params=params, timeout=self.timeout)


# ---------------------------------------------------------------------------
# Config — read from settings/env, never from source defaults
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PostureConfig:
    """Base for a domain's configuration. A concrete config names the fields a
    domain needs to reach its source (an account/base URL and a token) and answers
    one question: :meth:`is_configured`. It is built from settings/env by the
    domain's ``config_from_settings`` classmethod — **no field carries a source
    default**, so an unconfigured environment yields a config that reports
    not-configured rather than a plausible-looking live target. The base is
    conservative: never configured, so a subclass must state its own requirement
    explicitly and can never accidentally look ready."""

    def is_configured(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# A check — one curated posture question, and a finding — its honest answer
# ---------------------------------------------------------------------------


# An evaluator reads the resource payload a domain fetched (a dict, or ``None`` when
# nothing was fetched for the resource) and returns ``(status, evidence_class,
# detail)``. It is a pure function of its input: deterministic, side-effect-free,
# and honest — it returns ``unknown`` when the datum it needs is absent, and it
# only ever claims ``technically_verified`` when the payload carries a measured
# behaviour (a probe/handshake result), never for plain configuration.
Evaluator = Callable[[Any], "tuple[str, str, str]"]


@dataclass(frozen=True)
class PostureCheck:
    """One curated posture check — a code constant. ``key`` is its stable id,
    ``severity`` the risk band a *gap* on it carries (reusing the capability
    vocabulary), ``resource`` the read it is evaluated against, ``category`` its
    grouping, ``description`` what it looks for, and ``evaluate`` the pure
    evaluator that turns the fetched datum into ``(status, evidence_class,
    detail)``."""

    key: str
    title: str
    severity: str
    resource: str
    category: str
    description: str
    evaluate: Evaluator = field(compare=False, repr=False, default=lambda _data: (
        STATUS_UNKNOWN, EvidenceClass.NOT_DOCUMENTED.value, "no evaluator"))

    def catalog_dict(self) -> dict:
        """The check as it appears in a catalog (what a domain *would* assess) —
        no result, so it is safe to surface even when the domain is inert."""
        return {
            "check": self.key,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "resource": self.resource,
            "description": self.description,
        }


@dataclass(frozen=True)
class PostureFinding:
    """The honest answer to one check over observed data: its ``status``
    (``pass`` / ``gap`` / ``unknown``), the ``severity`` band it carries, the
    :class:`~assurance.models.EvidenceClass` that reflects *how it was determined*,
    a human-readable ``detail`` free of any secret value, and the ``resource`` and
    ``category`` it belongs to."""

    check: str
    title: str
    status: str
    severity: str
    evidence_class: str
    detail: str
    resource: str
    category: str

    def as_dict(self) -> dict:
        try:
            evidence_label = EvidenceClass(self.evidence_class).label
        except ValueError:
            evidence_label = self.evidence_class
        return {
            "check": self.check,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "evidence_class": self.evidence_class,
            "evidence_class_label": evidence_label,
            "detail": self.detail,
            "resource": self.resource,
            "category": self.category,
        }


# ---------------------------------------------------------------------------
# Evaluator helpers — the shared honesty of turning a datum into a verdict
# ---------------------------------------------------------------------------


def unknown(detail: str) -> "tuple[str, str, str]":
    """A check with no data to judge: ``unknown``, at the weakest evidence class
    (``not_documented``). The single honest answer when a resource was not fetched
    or the datum it needs is absent — never a pass."""
    return STATUS_UNKNOWN, EvidenceClass.NOT_DOCUMENTED.value, detail


def config_pass(detail: str) -> "tuple[str, str, str]":
    """Observed configuration shows no gap for this check: ``pass`` at
    ``configuration_verified``. A pass is the observed absence of *this* gap, not a
    claim the system is secure."""
    return STATUS_PASS, EvidenceClass.CONFIGURATION_VERIFIED.value, detail


def config_gap(detail: str) -> "tuple[str, str, str]":
    """Observed configuration shows a gap: ``gap`` at ``configuration_verified`` —
    we saw the misconfiguration in the data we read."""
    return STATUS_GAP, EvidenceClass.CONFIGURATION_VERIFIED.value, detail


def measured_pass(detail: str) -> "tuple[str, str, str]":
    """A measured behaviour shows no gap: ``pass`` at ``technically_verified`` —
    reserved for a payload that carries an actual probe/handshake result, not mere
    configuration."""
    return STATUS_PASS, EvidenceClass.TECHNICALLY_VERIFIED.value, detail


def measured_gap(detail: str) -> "tuple[str, str, str]":
    """A measured behaviour shows a gap: ``gap`` at ``technically_verified`` — the
    behaviour was actually observed to fail, not merely configured badly."""
    return STATUS_GAP, EvidenceClass.TECHNICALLY_VERIFIED.value, detail


def _as_dict(data: Any) -> dict | None:
    return data if isinstance(data, dict) else None


# ---------------------------------------------------------------------------
# The assessment interface
# ---------------------------------------------------------------------------


class PostureAssessment(ABC):
    """The stable, read-oriented posture interface for one domain. A concrete
    domain declares a curated list of :class:`PostureCheck` constants and evaluates
    them against the data an injected :class:`Fetcher` reads.

    The inert-by-default contract lives in :meth:`assess` so every domain gets it
    for free: when :attr:`config` is not configured, :meth:`assess` returns the
    ``connected: false`` report — the catalog of checks it *would* run, no findings
    fabricated — and the fetcher is **never touched**, so no fetch is made.
    Subclasses provide :attr:`CHECKS` (and may override :meth:`_resource_params`);
    they never re-implement the guard."""

    #: The stable registry name for this domain (e.g. ``"cloud"``).
    name: str = "posture"
    #: A human-readable label for the domain.
    label: str = "Posture"
    #: The concrete config dataclass this domain reads.
    config_class: type[PostureConfig] = PostureConfig
    #: The curated posture checks this domain runs. A subclass sets this.
    CHECKS: tuple[PostureCheck, ...] = ()

    #: The config field that carries the secret read-credential. A per-tenant
    #: binding stores this one field encrypted at rest, the rest in the clear.
    secret_field: str = "token"

    #: The non-secret config fields a per-tenant binding stores in the clear (the
    #: account/URL/scoping fields). The secret field is deliberately NOT listed.
    settings_fields: tuple[str, ...] = ()

    def __init__(self, config: PostureConfig) -> None:
        self.config = config

    @property
    def configured(self) -> bool:
        return self.config.is_configured()

    @classmethod
    def config_from_settings(cls) -> PostureConfig:
        """Build this domain's config from Django settings/env. Subclasses override
        to read their own keys; the base returns a never-configured config so a
        domain with no override is inert rather than crashing."""
        return cls.config_class()

    @classmethod
    def config_from_binding(
        cls, settings_values: dict, secret: str | None
    ) -> PostureConfig:
        """Build this domain's frozen config from a per-tenant binding: the
        non-secret ``settings_values`` (account/URL/scoping) plus the decrypted
        ``secret`` (or ``None`` when the binding has no usable read-credential —
        the config then reports not-configured, so the domain stays inert). No
        secret ever appears in ``settings_values``; it arrives only here, in
        memory, at build time."""
        kwargs = {
            field: settings_values.get(field)
            for field in cls.settings_fields
            if settings_values.get(field) not in (None, "")
        }
        if secret:
            kwargs[cls.secret_field] = secret
        return cls.config_class(**kwargs)

    # -- resources ---------------------------------------------------------

    def resources(self) -> tuple[str, ...]:
        """The distinct resources this domain reads — one fetch each — derived from
        its checks, in stable first-seen order."""
        seen: dict[str, None] = {}
        for check in self.CHECKS:
            seen.setdefault(check.resource, None)
        return tuple(seen)

    def _resource_params(self, resource: str) -> dict | None:
        """Optional query params for a resource fetch. The base sends none; a
        domain overrides if a read needs scoping."""
        return None

    # -- the inert-by-default guard ---------------------------------------

    def assess(self, *, fetcher: Fetcher | None = None) -> dict:
        """Assess this domain and return a computed, JSON-safe report.

        The inert-by-default guard lives here: an **unconfigured** domain returns
        :meth:`_not_connected_report` immediately and **never touches** the
        fetcher — no read is made. When configured, the injected fetcher (a real
        one supplied by the caller, or, if the caller passed none, a
        :class:`RequestsFetcher` built lazily) performs one read per resource, and
        the checks are evaluated against what came back. A fetch that fails is
        treated as *no data* — the checks over it read ``unknown``, never a crash.
        """
        if not self.configured:
            return self._not_connected_report()
        if fetcher is None:
            # Only reached for a *configured* domain when the caller passed no
            # fetcher. The view always injects one (built from the per-tenant
            # binding), so this default is the fallback path, not the norm.
            fetcher = RequestsFetcher()
        data = self._fetch_all(fetcher)
        return self._connected_report(data)

    # -- reports -----------------------------------------------------------

    def _not_connected_report(self) -> dict:
        """The honest inert report: not connected, no findings fabricated, and the
        catalog of checks this domain *would* run once credentials are supplied."""
        catalog = sorted(
            (c.catalog_dict() for c in self.CHECKS),
            key=lambda c: (_RISK_ORDER.index(c["severity"]), c["check"]),
        )
        return {
            "domain": self.name,
            "domain_label": self.label,
            "connected": False,
            "detail": f"{self.name} posture source not configured",
            "checks": catalog,
            "findings": [],
            "summary": {
                "connected": False,
                "planned": len(catalog),
                "total": 0,
                "pass": 0,
                "gap": 0,
                "unknown": 0,
                "gaps_by_severity": {RISK_HIGH: 0, RISK_ELEVATED: 0, RISK_BASELINE: 0},
                "max_risk": RISK_BASELINE,
            },
        }

    def _fetch_all(self, fetcher: Fetcher) -> dict[str, Any]:
        """Read every resource once. A failed or non-2xx read yields ``None`` for
        that resource, so its checks read ``unknown`` rather than crashing."""
        out: dict[str, Any] = {}
        for resource in self.resources():
            out[resource] = self._fetch_one(fetcher, resource)
        return out

    def _fetch_one(self, fetcher: Fetcher, resource: str) -> Any:
        try:
            response = fetcher.fetch(resource, params=self._resource_params(resource))
        except Exception:  # noqa: BLE001 — a read failure is missing data, not a crash
            return None
        try:
            if not (200 <= int(response.status_code) < 300):
                return None
            return response.json()
        except Exception:  # noqa: BLE001 — an unreadable body is missing data
            return None

    def _connected_report(self, data: dict[str, Any]) -> dict:
        """Evaluate every check against the fetched data into an honest report."""
        findings: list[PostureFinding] = []
        for check in self.CHECKS:
            payload = data.get(check.resource)
            status, evidence_class, detail = check.evaluate(payload)
            findings.append(
                PostureFinding(
                    check=check.key,
                    title=check.title,
                    status=status,
                    severity=check.severity,
                    evidence_class=evidence_class,
                    detail=detail,
                    resource=check.resource,
                    category=check.category,
                )
            )
        # Most actionable first: gap, then unknown, then pass; within a status, the
        # more concerning severity band first; then the check key for stability.
        findings.sort(
            key=lambda f: (_STATUS_ORDER.get(f.status, 3), _RISK_ORDER.index(f.severity), f.check)
        )

        gaps_by_severity = {RISK_HIGH: 0, RISK_ELEVATED: 0, RISK_BASELINE: 0}
        max_risk = RISK_BASELINE
        for f in findings:
            if f.status == STATUS_GAP:
                gaps_by_severity[f.severity] = gaps_by_severity.get(f.severity, 0) + 1
                max_risk = _max_risk(max_risk, f.severity)

        summary = {
            "connected": True,
            "planned": len(self.CHECKS),
            "total": len(findings),
            "pass": sum(1 for f in findings if f.status == STATUS_PASS),
            "gap": sum(1 for f in findings if f.status == STATUS_GAP),
            "unknown": sum(1 for f in findings if f.status == STATUS_UNKNOWN),
            "gaps_by_severity": gaps_by_severity,
            "max_risk": max_risk,
            # The weakest evidence behind any finding — the honest confidence floor,
            # in the same spirit as the evidence taxonomy elsewhere.
            "weakest_evidence": _weakest_evidence(findings),
        }
        return {
            "domain": self.name,
            "domain_label": self.label,
            "connected": True,
            "checks": sorted(
                (c.catalog_dict() for c in self.CHECKS),
                key=lambda c: (_RISK_ORDER.index(c["severity"]), c["check"]),
            ),
            "findings": [f.as_dict() for f in findings],
            "summary": summary,
        }


def _weakest_evidence(findings: list[PostureFinding]) -> str | None:
    """The weakest evidence class among findings — the honest floor. ``None`` when
    there are no findings."""
    if not findings:
        return None
    return max((f.evidence_class for f in findings), key=evidence_strength)
