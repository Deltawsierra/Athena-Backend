"""Credential-gated Phase 3 posture assessments (3.2 / 3.3 / 3.4), proven WITHOUT
network.

Every assessment here runs against an injected fetcher; no test ever constructs a
real fetcher or reaches a live service. Two fakes carry the whole surface:

- :class:`RecordingFetcher` records every ``fetch`` and **raises** if it is ever
  called — so an *inert* (unconfigured) domain is proven to make zero reads: its
  ``calls`` stay empty and no exception fires.
- :class:`FixtureFetcher` returns canned posture data per resource and records the
  reads, so a *configured* domain is exercised over a fixture dataset with nothing
  on the wire.

The honesty invariants the framework promises are exercised directly: an
unconfigured domain returns ``connected: false`` and fetches nothing; a check with
no data reads ``unknown`` (never ``pass``); every finding's ``evidence_class``
reflects how it was actually determined (``configuration_verified`` for observed
config, ``technically_verified`` only for a measured behaviour the data carried);
nothing is reported "secure"/"compliant"; and the assessments are deterministic.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.models import Deployment, EvidenceClass
from assurance.posture import (
    CloudPosture,
    CloudPostureConfig,
    RepoPosture,
    RepoPostureConfig,
    SecretsPosture,
    SecretsPostureConfig,
    UnknownPostureDomain,
    available_domains,
    build_assessment,
    get_assessment_class,
)
from assurance.posture.base import STATUS_GAP, STATUS_PASS, STATUS_UNKNOWN
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


# ---------------------------------------------------------------------------
# Fakes — the ONLY fetchers in these tests
# ---------------------------------------------------------------------------


class _Resp:
    def __init__(self, body: Any, status_code: int = 200):
        self._body = body if body is not None else {}
        self.status_code = status_code

    def json(self) -> Any:
        return self._body


class RecordingFetcher:
    """Records every ``fetch`` and RAISES if called. An inert domain must never
    reach it, so ``calls == []`` (and no exception) is the proof no read was made."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def fetch(self, resource: str, *, params: dict | None = None) -> _Resp:
        self.calls.append(resource)
        raise AssertionError(f"an inert domain must not fetch (asked for {resource!r})")


class FixtureFetcher:
    """Returns canned posture data per resource and records the reads. A resource
    absent from the map yields an empty body — the domain then reads its checks as
    ``unknown``, exactly like a real read that returned nothing."""

    def __init__(self, fixture: dict[str, Any]):
        self.fixture = fixture
        self.calls: list[str] = []

    def fetch(self, resource: str, *, params: dict | None = None) -> _Resp:
        self.calls.append(resource)
        return _Resp(self.fixture.get(resource, {}))


# ---------------------------------------------------------------------------
# Fixture datasets — mixed gap / pass / unknown per domain
# ---------------------------------------------------------------------------

CLOUD_FIXTURE = {
    "public_exposure": {"public_endpoints": []},  # pass (observed none)
    "network": {
        "security_groups": [{"name": "sg-open", "ingress_cidr": "0.0.0.0/0"}],  # gap (config)
        "probes": [{"target": "db:5432", "reachable": True, "measured": True}],  # gap (measured)
    },
    "iam": {
        "principals": [
            {"name": "svc", "wildcard_actions": True},  # wildcard gap
            {"name": "ops", "admin": True},  # admin gap
        ]
    },
    "storage": {"buckets": [{"name": "assets", "public": True, "encrypted": True}]},  # public gap, enc pass
    # "drift" omitted -> unknown
}

SECRETS_FIXTURE = {
    "tls": {"certificates": [{"host": "api", "valid": True, "days_to_expiry": 5, "measured": True}]},
    "kms": {"keys": [{"id": "k1", "rotation_enabled": False}]},  # rotation gap
    "secret_store": {"secrets": [{"name": "db", "last_rotated_days": 200, "managed": False}]},
    "committed_secrets": {"indicators": [{"type": "aws_key", "path": "settings.py"}]},
    # "encryption_at_rest" omitted -> unknown
}

REPO_FIXTURE = {
    "branch_protection": {
        "branches": [{"name": "main", "default": True, "protected": False, "required_reviews": 0}]
    },
    "cicd": {
        "runners": [{"name": "r1", "self_hosted": True, "public_repo": True}],  # runner gap
        "workflows": [{"name": "deploy", "token_permissions": "write-all"}],  # workflow gap
    },
    "dependencies": {"assessed": True, "vulnerable": [{"package": "lodash", "severity": "high"}]},
    "iac": {"assessed": True, "misconfigurations": []},  # pass
    "embedded_secrets": {"indicators": []},  # pass
    # "repo_drift" omitted -> unknown
}


def _configured_cloud() -> CloudPosture:
    return CloudPosture(CloudPostureConfig(account="acct-1", base_url="https://cloud.local", token="t"))


def _configured_secrets() -> SecretsPosture:
    return SecretsPosture(SecretsPostureConfig(base_url="https://vault.local", token="t"))


def _configured_repo() -> RepoPosture:
    return RepoPosture(RepoPostureConfig(organization="org", base_url="https://scm.local", token="t"))


def _by_check(report: dict) -> dict[str, dict]:
    return {f["check"]: f for f in report["findings"]}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_maps_names_to_classes():
    assert get_assessment_class("cloud") is CloudPosture
    assert get_assessment_class("secrets") is SecretsPosture
    assert get_assessment_class("repo") is RepoPosture
    assert available_domains() == ["cloud", "repo", "secrets"]


def test_build_assessment_returns_the_right_class():
    assert isinstance(build_assessment("cloud"), CloudPosture)
    assert isinstance(build_assessment("secrets"), SecretsPosture)
    assert isinstance(build_assessment("repo"), RepoPosture)


def test_unknown_domain_errors_clearly():
    with pytest.raises(UnknownPostureDomain) as exc:
        get_assessment_class("kubernetes")
    assert "kubernetes" in str(exc.value)
    assert "cloud" in str(exc.value)  # names what IS available
    with pytest.raises(UnknownPostureDomain):
        build_assessment("nope")


# ---------------------------------------------------------------------------
# Inert by default — the safety property (no credentials -> no fetch)
# ---------------------------------------------------------------------------


def test_every_domain_from_settings_is_unconfigured_in_this_repo():
    # No POSTURE_* settings in this repo -> every domain reads not-configured.
    for name in available_domains():
        assert build_assessment(name).configured is False


def test_unconfigured_domain_is_inert_and_makes_no_fetch():
    for name in available_domains():
        assessment = build_assessment(name)
        recorder = RecordingFetcher()
        report = assessment.assess(fetcher=recorder)
        assert report["connected"] is False
        assert report["domain"] == name
        assert report["detail"] == f"{name} posture source not configured"
        # No finding is fabricated when inert...
        assert report["findings"] == []
        # ...but the catalog of checks it WOULD run is surfaced honestly.
        assert len(report["checks"]) == len(assessment.CHECKS)
        assert report["summary"]["planned"] == len(assessment.CHECKS)
        assert report["summary"]["gap"] == 0 and report["summary"]["pass"] == 0
        # The proof: the fetcher was NEVER called.
        assert recorder.calls == []


def test_inert_catalog_carries_no_url_or_credential():
    # The inert report advertises the checks it would run, never a target URL or a
    # credential — the config (base URL, token) never leaks into the output.
    for name in available_domains():
        report = build_assessment(name).assess(fetcher=RecordingFetcher())
        blob = repr(report).lower()
        assert "://" not in blob  # no base URL of any scheme
        assert "t0k" not in blob and "bearer " not in blob


# ---------------------------------------------------------------------------
# Cloud (3.2) over a fixture dataset
# ---------------------------------------------------------------------------


def test_cloud_fixture_produces_expected_findings():
    fetcher = FixtureFetcher(CLOUD_FIXTURE)
    report = _configured_cloud().assess(fetcher=fetcher)
    assert report["connected"] is True
    # Only the distinct resources are read, once each (network backs two checks).
    assert fetcher.calls == ["public_exposure", "network", "iam", "storage", "drift"]

    f = _by_check(report)
    assert f["cloud_public_exposure"]["status"] == STATUS_PASS
    assert f["cloud_public_exposure"]["evidence_class"] == EvidenceClass.CONFIGURATION_VERIFIED.value

    assert f["cloud_unrestricted_ingress"]["status"] == STATUS_GAP
    assert f["cloud_unrestricted_ingress"]["severity"] == "high"
    assert f["cloud_unrestricted_ingress"]["evidence_class"] == EvidenceClass.CONFIGURATION_VERIFIED.value

    # A MEASURED probe result is technically verified — behaviour actually observed.
    assert f["cloud_network_reachability"]["status"] == STATUS_GAP
    assert f["cloud_network_reachability"]["evidence_class"] == EvidenceClass.TECHNICALLY_VERIFIED.value

    assert f["cloud_iam_wildcard"]["status"] == STATUS_GAP
    assert f["cloud_iam_admin_sprawl"]["status"] == STATUS_GAP
    assert f["cloud_storage_public"]["status"] == STATUS_GAP
    assert f["cloud_storage_encryption"]["status"] == STATUS_PASS  # encrypted: True observed

    # The omitted resource -> honest unknown, never a pass.
    assert f["cloud_drift"]["status"] == STATUS_UNKNOWN
    assert f["cloud_drift"]["evidence_class"] == EvidenceClass.NOT_DOCUMENTED.value

    s = report["summary"]
    assert s["gap"] == 5 and s["pass"] == 2 and s["unknown"] == 1
    assert s["total"] == 8
    assert s["gaps_by_severity"]["high"] == 3  # ingress, iam_wildcard, storage_public
    assert s["gaps_by_severity"]["elevated"] == 2  # reachability, admin_sprawl
    assert s["max_risk"] == "high"


# ---------------------------------------------------------------------------
# Secrets (3.3) over a fixture dataset
# ---------------------------------------------------------------------------


def test_secrets_fixture_produces_expected_findings():
    fetcher = FixtureFetcher(SECRETS_FIXTURE)
    report = _configured_secrets().assess(fetcher=fetcher)
    assert report["connected"] is True

    f = _by_check(report)
    # Measured handshake -> technically verified, both directions.
    assert f["secrets_tls_validity"]["status"] == STATUS_PASS
    assert f["secrets_tls_validity"]["evidence_class"] == EvidenceClass.TECHNICALLY_VERIFIED.value
    assert f["secrets_tls_expiry"]["status"] == STATUS_GAP  # 5 <= 21 days
    assert f["secrets_tls_expiry"]["evidence_class"] == EvidenceClass.TECHNICALLY_VERIFIED.value

    assert f["secrets_kms_rotation"]["status"] == STATUS_GAP
    assert f["secrets_store_hygiene"]["status"] == STATUS_GAP
    assert f["secrets_unmanaged_secrets"]["status"] == STATUS_GAP
    assert f["secrets_committed_indicators"]["status"] == STATUS_GAP
    assert f["secrets_committed_indicators"]["evidence_class"] == EvidenceClass.CONFIGURATION_VERIFIED.value

    # Omitted resource -> unknown.
    assert f["secrets_encryption_at_rest"]["status"] == STATUS_UNKNOWN
    assert f["secrets_encryption_at_rest"]["evidence_class"] == EvidenceClass.NOT_DOCUMENTED.value


def test_committed_secret_indicator_never_emits_a_value():
    # The fixture indicator carries type + path only; assert the finding surfaces a
    # count and kind, never a credential value, and the whole report is value-free.
    report = _configured_secrets().assess(fetcher=FixtureFetcher(SECRETS_FIXTURE))
    finding = _by_check(report)["secrets_committed_indicators"]
    assert "aws_key" in finding["detail"]  # kind is fine to name
    assert "1 committed-secret indicator" in finding["detail"]
    # No path or value leaks into the surfaced detail.
    assert "settings.py" not in finding["detail"]


# ---------------------------------------------------------------------------
# Repo (3.4) over a fixture dataset
# ---------------------------------------------------------------------------


def test_repo_fixture_produces_expected_findings():
    fetcher = FixtureFetcher(REPO_FIXTURE)
    report = _configured_repo().assess(fetcher=fetcher)
    assert report["connected"] is True

    f = _by_check(report)
    assert f["repo_branch_protection"]["status"] == STATUS_GAP
    assert f["repo_branch_protection"]["severity"] == "high"
    assert f["repo_required_reviews"]["status"] == STATUS_GAP
    assert f["repo_runner_exposure"]["status"] == STATUS_GAP
    assert f["repo_workflow_permissions"]["status"] == STATUS_GAP
    assert f["repo_dependency_risk"]["status"] == STATUS_GAP
    assert f["repo_iac_misconfig"]["status"] == STATUS_PASS
    assert f["repo_embedded_secrets"]["status"] == STATUS_PASS

    # Omitted resource -> unknown.
    assert f["repo_drift"]["status"] == STATUS_UNKNOWN
    assert f["repo_drift"]["evidence_class"] == EvidenceClass.NOT_DOCUMENTED.value


def test_repo_domain_never_claims_technically_verified():
    # Repository/SDLC posture is read from configuration, not measured behaviour:
    # no finding may claim technically_verified — that would be dishonest.
    report = _configured_repo().assess(fetcher=FixtureFetcher(REPO_FIXTURE))
    for finding in report["findings"]:
        assert finding["evidence_class"] != EvidenceClass.TECHNICALLY_VERIFIED.value


# ---------------------------------------------------------------------------
# Honesty invariants that hold across every domain
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "assessment,fixture",
    [
        (_configured_cloud(), CLOUD_FIXTURE),
        (_configured_secrets(), SECRETS_FIXTURE),
        (_configured_repo(), REPO_FIXTURE),
    ],
)
def test_missing_data_reads_unknown_never_pass(assessment, fixture):
    # An EMPTY read for every resource -> every check is unknown, nothing passes.
    report = assessment.assess(fetcher=FixtureFetcher({}))
    statuses = {f["status"] for f in report["findings"]}
    assert statuses == {STATUS_UNKNOWN}
    assert report["summary"]["pass"] == 0
    assert report["summary"]["gap"] == 0
    for finding in report["findings"]:
        assert finding["evidence_class"] == EvidenceClass.NOT_DOCUMENTED.value


@pytest.mark.parametrize(
    "assessment,fixture",
    [
        (_configured_cloud(), CLOUD_FIXTURE),
        (_configured_secrets(), SECRETS_FIXTURE),
        (_configured_repo(), REPO_FIXTURE),
    ],
)
def test_nothing_reads_secure_or_compliant(assessment, fixture):
    report = assessment.assess(fetcher=FixtureFetcher(fixture))
    for finding in report["findings"]:
        text = finding["detail"].lower()
        assert "secure" not in text
        assert "compliant" not in text


@pytest.mark.parametrize(
    "assessment,fixture",
    [
        (_configured_cloud(), CLOUD_FIXTURE),
        (_configured_secrets(), SECRETS_FIXTURE),
        (_configured_repo(), REPO_FIXTURE),
    ],
)
def test_evidence_class_reflects_how_it_was_determined(assessment, fixture):
    report = assessment.assess(fetcher=FixtureFetcher(fixture))
    for finding in report["findings"]:
        ec = finding["evidence_class"]
        if finding["status"] == STATUS_UNKNOWN:
            # An unknown never claims verified evidence.
            assert ec in (EvidenceClass.NOT_DOCUMENTED.value, EvidenceClass.UNKNOWN.value)
        else:
            # A pass/gap was observed -> config- or technically-verified only.
            assert ec in (
                EvidenceClass.CONFIGURATION_VERIFIED.value,
                EvidenceClass.TECHNICALLY_VERIFIED.value,
            )


@pytest.mark.parametrize(
    "assessment,fixture",
    [
        (_configured_cloud(), CLOUD_FIXTURE),
        (_configured_secrets(), SECRETS_FIXTURE),
        (_configured_repo(), REPO_FIXTURE),
    ],
)
def test_assessment_is_deterministic(assessment, fixture):
    a = assessment.assess(fetcher=FixtureFetcher(fixture))
    b = assessment.assess(fetcher=FixtureFetcher(fixture))
    assert a == b


def test_a_failed_read_is_treated_as_unknown_not_a_crash():
    # A non-2xx response for a resource -> that resource is missing data.
    class FailingFetcher:
        def __init__(self):
            self.calls = []

        def fetch(self, resource, *, params=None):
            self.calls.append(resource)
            return _Resp({}, status_code=503)

    report = _configured_cloud().assess(fetcher=FailingFetcher())
    assert report["connected"] is True
    assert {f["status"] for f in report["findings"]} == {STATUS_UNKNOWN}


# ---------------------------------------------------------------------------
# API — the DeploymentViewSet reads (mirror the connectors list/read tests)
# ---------------------------------------------------------------------------


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _deployment(owner):
    return Deployment.objects.create(
        name="checkout-assistant", owner=owner, environment=Deployment.Environment.PRODUCTION
    )


@pytest.fixture()
def deployment():
    return _deployment(_user("owner", role=User.Roles.ADMIN))


def test_posture_catalog_endpoint_lists_domains(deployment):
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "posture"})
    analyst = _user("ana", role=User.Roles.ANALYST)
    request = factory.get(f"/api/assurance/deployments/{deployment.uuid}/posture/")
    force_authenticate(request, user=analyst)
    resp = view(request, uuid=str(deployment.uuid))
    assert resp.status_code == 200
    names = {d["name"] for d in resp.data["domains"]}
    assert names == set(available_domains())
    # All inert in this repo (live wiring deferred).
    assert all(d["configured"] is False for d in resp.data["domains"])
    assert {d["label"] for d in resp.data["domains"]} == {
        "Cloud Assurance",
        "Secrets / Crypto",
        "Repository / SDLC",
    }


@pytest.mark.parametrize(
    "action,url_path,domain",
    [
        ("cloud_posture", "cloud-posture", "cloud"),
        ("secrets_posture", "secrets-posture", "secrets"),
        ("repo_posture", "repo-posture", "repo"),
    ],
)
def test_posture_read_is_open_and_inert_without_credentials(deployment, action, url_path, domain):
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": action})
    analyst = _user(f"ana-{domain}", role=User.Roles.ANALYST)
    request = factory.get(f"/api/assurance/deployments/{deployment.uuid}/{url_path}/")
    force_authenticate(request, user=analyst)
    resp = view(request, uuid=str(deployment.uuid))
    # House idiom: 200, read `connected`. No credentials in this repo -> inert.
    assert resp.status_code == 200
    assert resp.data["connected"] is False
    assert resp.data["domain"] == domain
    assert resp.data["findings"] == []
    assert len(resp.data["checks"]) >= 5  # the catalog it would run


def test_posture_read_requires_authentication(deployment):
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "cloud_posture"})
    request = factory.get(f"/api/assurance/deployments/{deployment.uuid}/cloud-posture/")
    resp = view(request, uuid=str(deployment.uuid))  # no force_authenticate
    assert resp.status_code in (401, 403)


@override_settings(
    POSTURE_CLOUD_ACCOUNT="acct-1",
    POSTURE_CLOUD_URL="https://cloud.local",
    POSTURE_CLOUD_TOKEN="t0k",
)
def test_cloud_posture_api_configured_via_fixture(deployment, monkeypatch):
    # With settings configured, the domain is live. Swap the real fetcher the view
    # builds for a fixture one so the API path is exercised with nothing on the wire.
    import assurance.posture as posture_pkg

    monkeypatch.setattr(posture_pkg, "RequestsFetcher", lambda *a, **k: FixtureFetcher(CLOUD_FIXTURE))

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "cloud_posture"})
    analyst = _user("ana-cfg", role=User.Roles.ANALYST)
    request = factory.get(f"/api/assurance/deployments/{deployment.uuid}/cloud-posture/")
    force_authenticate(request, user=analyst)
    resp = view(request, uuid=str(deployment.uuid))

    assert resp.status_code == 200
    assert resp.data["connected"] is True
    assert resp.data["domain"] == "cloud"
    f = {x["check"]: x for x in resp.data["findings"]}
    assert f["cloud_storage_public"]["status"] == STATUS_GAP
    assert f["cloud_drift"]["status"] == STATUS_UNKNOWN
    assert resp.data["summary"]["max_risk"] == "high"
