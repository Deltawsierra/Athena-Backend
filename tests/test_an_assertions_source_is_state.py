"""#343, round 3: an assertion's SOURCE is state.

#343 made the source decide the evidence class an assertion carries
(``effective_evidence_class``). The system and per-claim input fingerprints still
hashed only the declared LABEL, so withdrawing the trust root -- ``measured`` ->
``self_declared``, label kept -- was no change at all: no drift, no retest,
nothing marked stale, and the DATA_BOUNDARY claim kept reading VERIFIED 0.88 until
some later full re-derive happened to run (round-3 script F). A label change of
the same size was drift.

Now the fingerprint hashes the effective class wherever it differs from the
label. Withdrawing ``measured`` invalidates and opens retests exactly as a
relabel does. An assertion whose source does not cap its label hashes as it did
before (the one-time upgrade effect is stated in the PR body).
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from assurance.claims import derive_claims
from assurance.fingerprint import _provider_descriptor, claim_input_fingerprints, compute_system_fingerprint
from assurance.models import (
    Asset,
    AssuranceClaim,
    DataBoundary,
    Deployment,
    EvidenceClass,
    Provider,
    ProviderAssertion,
    RetestRequirement,
)

pytestmark = pytest.mark.django_db

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType
Source = ProviderAssertion.Source
FIELDS = (("region", "eu-west-1"), ("trains_on_data", "No"), ("subprocessors", "none"))


def _build(name, *, source=Source.MEASURED, label=EvidenceClass.CONFIGURATION_VERIFIED):
    owner = User.objects.create_user(username=f"owner-src-{name}", password=None, role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name=name, owner=owner)
    provider = Provider.objects.create(name=f"EU Model Co {name}", kind=Provider.Kind.MODEL_PROVIDER)
    for field, value in FIELDS:
        ProviderAssertion.objects.create(provider=provider, field=field, value=value, evidence_class=label, source=source)
    Asset.objects.create(
        deployment=dep, provider=provider, kind=Asset.Kind.MODEL, name="gpt", identifier="gpt",
        classification=Asset.Classification.APPROVED,
    )
    DataBoundary.objects.create(
        deployment=dep, allowed_regions=["eu"], training_allowed=False, third_party_sharing_allowed=False
    )
    derive_claims(dep)
    return dep, provider


def _boundary(dep):
    return AssuranceClaim.objects.filter(deployment=dep, claim_type=ClaimType.DATA_BOUNDARY).current().get()


def _admin_client():
    client = APIClient()
    client.force_authenticate(
        user=User.objects.create_user(username="admin-src", password=None, role=User.Roles.ADMIN)
    )
    return client


@pytest.mark.parametrize(
    "change",
    [
        pytest.param({"source": Source.SELF_DECLARED}, id="source-withdrawn"),
        pytest.param({"source": Source.CONTRACT}, id="source-weakened"),
        pytest.param({"evidence_class": EvidenceClass.VENDOR_ASSERTED}, id="label-control"),
    ],
)
def test_withdrawing_the_trust_root_is_drift_exactly_as_a_relabel_is(change):
    dep, provider = _build(f"drift-{next(iter(change))}-{next(iter(change.values()))}")
    claim = _boundary(dep)
    assert (claim.status, claim.confidence) == (Status.VERIFIED, 0.88)
    system_before, inputs_before = compute_system_fingerprint(dep), claim_input_fingerprints(dep)

    client = _admin_client()
    for assertion in provider.assertions.all():
        response = client.patch(f"/api/assurance/provider-assertions/{assertion.uuid}/", change, format="json")
        assert response.status_code == 200, response.content

    assert compute_system_fingerprint(dep) != system_before
    assert claim_input_fingerprints(dep)[ClaimType.DATA_BOUNDARY] != inputs_before[ClaimType.DATA_BOUNDARY]
    checked = client.post(f"/api/assurance/deployments/{dep.uuid}/check-invalidations/", {}, format="json")
    assert checked.status_code == 200, checked.content
    assert checked.json()["invalidated"] >= 1
    assert checked.json()["retests_opened"] >= 1
    claim.refresh_from_db()
    assert claim.status == Status.STALE
    assert RetestRequirement.objects.filter(deployment=dep, resolved_at__isnull=True).exists()
    detail = client.get(f"/api/assurance/claims/{claim.uuid}/").json()
    assert detail["status"] != Status.VERIFIED


def test_a_source_change_that_leaves_the_effective_class_where_it_was_is_no_change():
    """A vendor's word stays the vendor's word, whatever it says its source is: no
    fingerprint moves, nothing is invalidated."""
    dep, provider = _build("same-effective", source=Source.CONTRACT, label=EvidenceClass.VENDOR_ASSERTED)
    system_before = compute_system_fingerprint(dep)
    for assertion in provider.assertions.all():
        assertion.source = Source.SELF_DECLARED
        assertion.save()
    assert compute_system_fingerprint(dep) == system_before


@pytest.mark.parametrize(
    "source, label",
    [
        (Source.MEASURED, EvidenceClass.CONFIGURATION_VERIFIED),
        (Source.MEASURED, EvidenceClass.TECHNICALLY_VERIFIED),
        (Source.CONTRACT, EvidenceClass.CONTRACTUALLY_STATED),
        (Source.SELF_DECLARED, EvidenceClass.VENDOR_ASSERTED),
    ],
)
def test_an_assertion_its_source_does_not_cap_hashes_as_it_did_before(source, label):
    """The one-time upgrade effect is only on assertions whose source caps their
    label -- the ones that already read differently since #343. Every other
    assertion's descriptor is exactly the pre-#343 one."""
    _dep, provider = _build(f"uncapped-{source}-{label}", source=source, label=label)
    descriptor = _provider_descriptor(provider)
    assert all(set(a) == {"field", "value", "evidence_class"} for a in descriptor["assertions"])
    assert {a["evidence_class"] for a in descriptor["assertions"]} == {label}


def test_a_capped_assertion_hashes_its_effective_class_beside_its_label():
    _dep, provider = _build("capped", source=Source.SELF_DECLARED, label=EvidenceClass.CONFIGURATION_VERIFIED)
    descriptor = _provider_descriptor(provider)
    assert {a["evidence_class"] for a in descriptor["assertions"]} == {EvidenceClass.CONFIGURATION_VERIFIED}
    assert {a["effective_evidence_class"] for a in descriptor["assertions"]} == {EvidenceClass.VENDOR_ASSERTED}
