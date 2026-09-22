"""The chain birth registry: the one check an engine cannot run on itself.

The engine's chain integrity is good, and every part of it reads the same SQLite
file. That is the whole problem. Delete the scans, the head and the watermark,
restart, and the engine re-seeds: a fresh watermark at sequence zero and a
genesis head carrying a GENUINE mac. Every check inside then agrees that an empty
table is an intact chain, because from inside the file there is nothing left to
disagree with.

So the birth is held here instead, by something with different credentials on a
different machine. These tests pin the three properties that make that worth
having:

1. the ORIGINAL birth is never overwritten by a later one -- overwriting would
   destroy the only evidence that anything happened;
2. "never registered" is reported apart from "verified", because no disagreement
   on file over an empty file is the silent zero in registry clothing;
3. it claims detection and not prevention, and says so in the payload.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from assurance.chain_registry import (
    REBIRTH_SUBJECT,
    ChainBirthRefused,
    register_birth,
    registry_posture,
)
from assurance.models import ChainBirth, Deployment, Unknown
from assurance.unknowns import derive_unknowns

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="owner"):
    return User.objects.create_user(
        username=f"{name}-{User.objects.count()}", password="x", role=User.Roles.ANALYST
    )


def _deployment(name="checkout-assistant"):
    return Deployment.objects.create(name=name, owner=_user())


def _register(dep, birth_id="birth-a", chain="chain_head", **kw):
    return register_birth(dep, chain=chain, birth_id=birth_id, **kw)


# ---------------------------------------------------------------------------
# First birth, and what it is not
# ---------------------------------------------------------------------------


def test_the_first_birth_is_registered_and_not_called_verified():
    """The first report establishes the baseline and proves nothing about what
    came before it. Calling it verified would let an engine that was erased
    before it ever reported read as vouched for."""
    result = _register(_deployment(), born_at="2026-01-01T00:00:00+00:00", seq=4)

    assert result["status"] == "registered"
    assert result["matched"] is False
    assert result["birth"].highest_seq == 4


def test_the_same_birth_again_matches():
    dep = _deployment()
    _register(dep, seq=4)
    result = _register(dep, seq=9)

    assert result["status"] == "matched"
    assert result["matched"] is True
    assert result["birth"].highest_seq == 9


def test_a_lower_sequence_never_lowers_the_high_water_mark():
    """A chain reporting a sequence below one we have already seen is a restored
    older state. Recording it as the new high would erase our ability to notice."""
    dep = _deployment()
    _register(dep, seq=9)
    result = _register(dep, seq=2)

    assert result["status"] == "matched"
    assert result["birth"].highest_seq == 9


# ---------------------------------------------------------------------------
# The re-birth
# ---------------------------------------------------------------------------


def test_a_different_birth_is_a_rebirth():
    dep = _deployment()
    _register(dep, birth_id="birth-a")

    result = _register(dep, birth_id="birth-b")

    assert result["status"] == "rebirth"
    assert result["matched"] is False


def test_the_original_birth_is_kept_not_overwritten():
    """The edit this exists to survive. A registry that accepted the new value
    would be a more expensive way of trusting the engine, and the first birth is
    the only evidence that anything changed."""
    dep = _deployment()
    _register(dep, birth_id="birth-a", born_at="2026-01-01T00:00:00+00:00")
    _register(dep, birth_id="birth-b")

    row = ChainBirth.objects.get(deployment=dep, chain="chain_head")
    assert row.birth_id == "birth-a"
    assert row.born_at == "2026-01-01T00:00:00+00:00"
    assert row.rebirth_birth_id == "birth-b"
    assert row.rebirth_seen_at is not None


def test_a_rebirth_is_one_row_not_two():
    dep = _deployment()
    _register(dep, birth_id="birth-a")
    _register(dep, birth_id="birth-b")
    _register(dep, birth_id="birth-c")

    assert ChainBirth.objects.filter(deployment=dep, chain="chain_head").count() == 1
    row = ChainBirth.objects.get(deployment=dep, chain="chain_head")
    assert row.rebirth_count == 2
    assert row.birth_id == "birth-a"


def test_a_rebirth_raises_an_unknown_that_names_both_births():
    dep = _deployment()
    _register(dep, birth_id="birth-a")
    _register(dep, birth_id="birth-b")

    gap = Unknown.objects.get(deployment=dep, subject=REBIRTH_SUBJECT)
    assert gap.status == Unknown.Status.OPEN
    assert gap.deployment_impact == Unknown.Impact.HIGH
    assert "birth-b" in gap.evidence_needed
    assert "born once" in gap.why_it_matters


def test_the_rebirth_gap_is_a_gap_and_not_a_confirmed_tampering():
    """A re-born chain is not proof that anything was hidden, it is proof that we
    can no longer say. Calling it a confirmed finding would be the same overreach
    in the other direction."""
    dep = _deployment()
    _register(dep, birth_id="birth-a")
    _register(dep, birth_id="birth-b")

    gap = Unknown.objects.get(deployment=dep, subject=REBIRTH_SUBJECT)
    assert gap.question.endswith("?")
    assert dep.findings.count() == 0


def test_the_rebirth_gap_survives_a_later_derive_unknowns():
    """The integration hazard this design had to dodge, asserted directly.

    `derive_unknowns` auto-resolves every machine-owned gap whose fingerprint is
    not in its live set. Filed under DERIVED, this gap would be quietly resolved
    by the next ingest -- the one alert the whole mechanism exists to raise,
    closed by an unrelated job. Source.CHAIN is deliberately outside that sweep,
    because a re-born chain is an EVENT and not a condition: nothing the engine
    does later un-does it.
    """
    dep = _deployment()
    _register(dep, birth_id="birth-a")
    _register(dep, birth_id="birth-b")

    derive_unknowns(dep)
    derive_unknowns(dep)

    gap = Unknown.objects.get(deployment=dep, subject=REBIRTH_SUBJECT)
    assert gap.status == Unknown.Status.OPEN
    assert gap.auto_resolved is False


def test_a_rebirth_on_one_chain_is_not_a_rebirth_on_another():
    """An engine keeps several chains. A registry that collapsed them could not
    say which one was replaced."""
    dep = _deployment()
    _register(dep, chain="chain_head", birth_id="a1")
    _register(dep, chain="authority_head", birth_id="b1")

    _register(dep, chain="chain_head", birth_id="a2")

    assert ChainBirth.objects.get(deployment=dep, chain="chain_head").rebirth_count == 1
    assert (
        ChainBirth.objects.get(deployment=dep, chain="authority_head").rebirth_count
        == 0
    )


def test_the_per_chain_uniqueness_is_declared_on_the_model_too():
    """The test database is built from the MIGRATION, so deleting the constraint
    from the model changes nothing in a DB-level test and every one of them still
    passes. Asserting it on the model is what stops the two drifting apart;
    `makemigrations --check` in CI catches the other direction. Same trap Phase
    2.5 and 2.9 each closed the same way."""
    names = {c.name for c in ChainBirth._meta.constraints}
    assert "uq_chain_birth_per_chain" in names
    constraint = next(
        c for c in ChainBirth._meta.constraints if c.name == "uq_chain_birth_per_chain"
    )
    assert tuple(constraint.fields) == ("deployment", "chain")


def test_the_same_chain_name_on_two_deployments_is_two_registrations():
    a, b = _deployment("a"), _deployment("b")
    _register(a, birth_id="a1")
    result = _register(b, birth_id="b1")

    assert result["status"] == "registered"
    assert ChainBirth.objects.count() == 2


# ---------------------------------------------------------------------------
# A row that matches everything is worse than no row
# ---------------------------------------------------------------------------


def test_a_birth_with_no_id_is_refused():
    """An engine reporting no birth_id has no watermark to report, which is itself
    the condition this watches for. Filing it would create a row that matches the
    next empty report forever."""
    with pytest.raises(ChainBirthRefused) as exc:
        _register(_deployment(), birth_id="   ")
    assert "birth_id" in str(exc.value)
    assert ChainBirth.objects.count() == 0


def test_a_birth_with_no_chain_is_refused():
    with pytest.raises(ChainBirthRefused) as exc:
        _register(_deployment(), chain="  ")
    assert "chain" in str(exc.value)
    assert ChainBirth.objects.count() == 0


# ---------------------------------------------------------------------------
# Never registered is not clean
# ---------------------------------------------------------------------------


def test_the_posture_of_a_deployment_that_never_registered_is_empty_not_clean():
    """No disagreement on file, over an empty file. The count is zero registered,
    and the note says a chain absent from the registry has not been checked."""
    posture = registry_posture(_deployment())

    assert posture["chains_registered"] == 0
    assert posture["chains_reborn"] == 0
    # Each clause pinned separately. A version of this test that checked one
    # phrase let a mutation rewrite the rest of the note and survive.
    note = posture["note"]
    assert "has not been checked rather than passed" in note
    assert "matches the first one we saw" in note
    assert "detects a replaced chain; it cannot prevent one" in note


def test_the_posture_counts_registered_and_reborn_separately():
    dep = _deployment()
    _register(dep, chain="chain_head", birth_id="a1")
    _register(dep, chain="authority_head", birth_id="b1")
    _register(dep, chain="chain_head", birth_id="a2")

    posture = registry_posture(dep)

    assert posture["chains_registered"] == 2
    assert posture["chains_reborn"] == 1
    assert posture["reborn"][0]["chain"] == "chain_head"
    assert posture["reborn"][0]["original_birth_id"] == "a1"
    assert posture["reborn"][0]["reported_birth_id"] == "a2"


def test_the_posture_never_reports_a_single_score():
    dep = _deployment()
    _register(dep, birth_id="a1")
    posture = registry_posture(dep)

    assert "score" not in posture
    assert "percent" not in posture
    assert "compliant" not in posture


def test_the_posture_carries_last_seen_so_a_silent_engine_is_visible():
    """Somebody who can delete the engine's database can also stop it reporting,
    and no row here makes an engine talk. A chain that stopped reporting is the
    fact a reader acts on, which only a registry keeping both timestamps can
    show."""
    dep = _deployment()
    _register(dep, birth_id="a1")

    posture = registry_posture(dep)
    assert "chain_head" in posture["last_seen"]
    assert "stops being checked" in posture["note"]


def test_a_match_says_it_is_not_a_statement_about_the_contents():
    """The registry answers "is this the chain we first saw". It does not answer
    "is what is in it true", and a reader who conflated the two would take a
    matching birth as a clean bill of health."""
    dep = _deployment()
    _register(dep, birth_id="a1")
    posture = registry_posture(dep)
    assert "not a statement about the chain's contents" in posture["note"]


# ---------------------------------------------------------------------------
# The endpoint
# ---------------------------------------------------------------------------


def _post(dep, user, payload):
    from rest_framework.test import APIRequestFactory, force_authenticate

    from assurance.views import DeploymentViewSet

    view = DeploymentViewSet.as_view({"post": "chain_birth"})
    request = APIRequestFactory().post(
        f"/api/assurance/deployments/{dep.uuid}/chain-birth/", payload, format="json"
    )
    force_authenticate(request, user=user)
    return view(request, uuid=str(dep.uuid))


def _get(dep, user):
    from rest_framework.test import APIRequestFactory, force_authenticate

    from assurance.views import DeploymentViewSet

    view = DeploymentViewSet.as_view({"get": "chain_birth"})
    request = APIRequestFactory().get(
        f"/api/assurance/deployments/{dep.uuid}/chain-birth/"
    )
    force_authenticate(request, user=user)
    return view(request, uuid=str(dep.uuid))


def _admin():
    return User.objects.create_user(
        username=f"boss-{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )


def test_the_endpoint_registers_a_first_birth():
    admin = _admin()
    dep = Deployment.objects.create(name="d", owner=admin)

    resp = _post(dep, admin, {"chain": "chain_head", "birth_id": "a1", "seq": 3})

    assert resp.status_code == 201
    assert resp.data["status"] == "registered"
    assert ChainBirth.objects.get(deployment=dep).highest_seq == 3


def test_the_endpoint_reports_a_rebirth_without_losing_the_original():
    admin = _admin()
    dep = Deployment.objects.create(name="d", owner=admin)
    _post(dep, admin, {"chain": "chain_head", "birth_id": "a1"})

    resp = _post(dep, admin, {"chain": "chain_head", "birth_id": "a2"})

    assert resp.status_code == 200
    assert resp.data["status"] == "rebirth"
    assert resp.data["birth_id"] == "a1"
    assert resp.data["rebirth_count"] == 1


def test_writing_the_registry_is_admin_only():
    """A caller who could overwrite this could launder exactly the erasure it
    exists to catch."""
    dep = Deployment.objects.create(name="d", owner=_admin())
    analyst = User.objects.create_user(
        username="ana", password="x", role=User.Roles.ANALYST
    )

    # Asserted on the RESPONSE, not the exception: DRF turns PermissionDenied
    # into a 403, and a caller sees the status. A test that caught the exception
    # would pass even if the view stopped being routed through DRF's handler.
    resp = _post(dep, analyst, {"chain": "chain_head", "birth_id": "a1"})
    assert resp.status_code == 403
    assert ChainBirth.objects.count() == 0


def test_reading_the_registry_is_open_to_an_analyst():
    admin = _admin()
    dep = Deployment.objects.create(name="d", owner=admin)
    _post(dep, admin, {"chain": "chain_head", "birth_id": "a1"})
    analyst = User.objects.create_user(
        username="ana2", password="x", role=User.Roles.ANALYST
    )

    resp = _get(dep, analyst)
    assert resp.status_code == 200
    assert resp.data["chains_registered"] == 1


def test_a_refused_birth_is_a_400_and_stores_nothing():
    admin = _admin()
    dep = Deployment.objects.create(name="d", owner=admin)

    resp = _post(dep, admin, {"chain": "chain_head", "birth_id": ""})

    assert resp.status_code == 400
    assert ChainBirth.objects.count() == 0


def test_an_unreadable_sequence_is_absent_rather_than_zero():
    """Zero is a real sequence -- a freshly seeded chain -- so coercing an
    unreadable value to it would forge the one number that says a chain went
    backwards."""
    admin = _admin()
    dep = Deployment.objects.create(name="d", owner=admin)

    _post(dep, admin, {"chain": "chain_head", "birth_id": "a1", "seq": "tampered"})

    assert ChainBirth.objects.get(deployment=dep).highest_seq is None


def test_every_answer_says_a_match_is_not_a_statement_about_contents():
    admin = _admin()
    dep = Deployment.objects.create(name="d", owner=admin)
    first = _post(dep, admin, {"chain": "chain_head", "birth_id": "a1"})
    second = _post(dep, admin, {"chain": "chain_head", "birth_id": "a1"})

    for resp in (first, second):
        # Each clause pinned. Asserting one phrase let a mutation rewrite the
        # rest of the disclaimer and survive -- twice in this session, in two
        # different files, which is the argument for pinning rather than
        # spot-checking prose that exists to stop a misreading.
        note = resp.data["note"]
        assert "the chain we first saw" in note
        assert "says nothing about what is in it" in note
        assert "has not been checked rather than passed" in note
