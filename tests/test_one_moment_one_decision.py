"""A decision and the claims behind it must come from one moment.

``decision_support`` is the artifact the "no torn read" bar is about: it returns
the decision AND the reasoning -- which claims support it, which hold it back --
so it is precisely the pair that must not be stitched from two moments. It was the
one place in the module doing exactly that.

It read each input once for the payload and then called ``compute_decision``,
which read all of them again. Five facts, ten reads, and a writer can land between
any pair. The result is an answer that looks ordinary and describes a state the
database never held.

Reproduced against unmutated code before this change. 81 samples against a writer
whose every write was wrapped in ``transaction.atomic()`` -- so any inconsistent
sample can only have come from stitching -- returned four distinct shapes, two of
them unreachable:

    decision=None               supporting=0 contradicted=3   <- impossible
    decision=needs_remediation  supporting=3 contradicted=0   <- impossible

Three contradicted claims force a cap of NEEDS_REMEDIATION, so ``None`` cannot
stand beside them; and a clean claim set with no retest imposes no cap at all, so
NEEDS_REMEDIATION has nothing to come from.

The fix is structural, not a lock: read each fact exactly ONCE and derive the
answer from that read. A transaction narrows the window but does not close it --
under READ COMMITTED a second read of the same row inside one transaction is still
a second moment -- so "read it once" is the half that carries the guarantee, and
the transaction is belt and braces around the several queries one read makes.
"""

from __future__ import annotations

import pytest
from assurance import decision as decision_module
from assurance.composition import compose as compose_chains
from assurance.decision import (
    DecisionParts,
    compute_decision,
    decide,
    decision_support,
    read_decision_parts,
)
from assurance.models import AssuranceClaim, Deployment, Finding
from assurance.revision import accept_transition
from assurance.serializers import DeploymentSerializer
from tests.decision_surfaces import stamped_under_the_rules_in_force
from django.contrib.auth import get_user_model
from django.db import connection
from django.utils import timezone

User = get_user_model()

D = Deployment.Decision


def _deployment(name="checkout-assistant"):
    owner = User.objects.create_user(
        username=f"u-{Deployment.objects.count()}", password="x", role=User.Roles.ANALYST
    )
    return Deployment.objects.create(name=name, owner=owner)


def _claim(dep, *, status, fingerprint):
    now = timezone.now()
    return AssuranceClaim.objects.create(
        deployment=dep,
        claim_type=AssuranceClaim.ClaimType.DATA_BOUNDARY,
        statement="destinations are inside the approved boundary",
        fingerprint=fingerprint,
        system_fingerprint="sysfp",
        policy_version="pol",
        environment=dep.environment,
        status=status,
        evidence_class=AssuranceClaim._meta.get_field("evidence_class").choices[0][0],
        valid_from=now,
        effective_from=now,
    )


# ---------------------------------------------------------------------------
# The negative control, first: the decision itself did not change
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_the_same_deployment_still_reaches_the_same_decision():
    """Splitting the read from the arithmetic must not move a single answer. A
    refactor that made every deployment read `None` would satisfy every
    consistency assertion below and have destroyed the product."""
    dep = _deployment()
    assert compute_decision(dep) is None  # assessed by nothing at all

    Finding.objects.create(
        deployment=dep,
        fingerprint="fp-1",
        finding_type="prompt_injection",
        title="T",
        severity="critical",
        status=Finding.Status.OPEN,
    )
    assert compute_decision(dep) == D.NOT_RECOMMENDED

    _claim(dep, status=AssuranceClaim.ClaimStatus.CONTRADICTED, fingerprint="fp-c")
    # A critical finding still outranks the claim cap.
    assert compute_decision(dep) == D.NOT_RECOMMENDED


@pytest.mark.django_db
def test_paused_still_short_circuits_without_reading_anything():
    """`paused` is the operator failsafe and no fact about the deployment can
    change it, so it must not cost a query either."""
    dep = _deployment()
    with connection.execute_wrapper(_Counter()) as _:
        pass
    counter = _Counter()
    with connection.execute_wrapper(counter):
        assert compute_decision(dep, paused=True) == D.PAUSED
    assert counter.count == 0, "a paused decision read the database"


class _Counter:
    def __init__(self) -> None:
        self.count = 0

    def __call__(self, execute, sql, params, many, context):
        self.count += 1
        return execute(sql, params, many, context)


# ---------------------------------------------------------------------------
# Read once
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_decision_support_reads_the_claim_signal_exactly_once(monkeypatch):
    """The defect in one assertion. Two reads of the same fact are two moments;
    a function reporting both the decision and its reasoning must report one."""
    dep = _deployment()
    _claim(dep, status=AssuranceClaim.ClaimStatus.CONTRADICTED, fingerprint="fp-c")

    calls: list[int] = []
    real = decision_module.claim_decision_signal

    def counting(deployment):
        calls.append(1)
        return real(deployment)

    monkeypatch.setattr(decision_module, "claim_decision_signal", counting)
    decision_support(dep)
    assert len(calls) == 1, f"the claim signal was read {len(calls)} times, not once"


@pytest.mark.django_db
def test_the_decision_in_the_payload_is_the_one_its_own_parts_imply():
    """Not merely equal to `compute_decision` run again -- derived from the very
    parts the payload reports. Running it again is how the tear got in."""
    dep = _deployment()
    _claim(dep, status=AssuranceClaim.ClaimStatus.CONTRADICTED, fingerprint="fp-c")
    support = decision_support(dep)
    parts = read_decision_parts(dep)
    assert support["decision"] == decide(parts)
    assert support["claim_cap"] == parts.claim_signal["cap"]
    assert support["from_findings"] == parts.from_findings


@pytest.mark.django_db
def test_a_caller_that_already_read_the_parts_is_not_made_to_read_again():
    """`parts=` is the seam the fix rests on, so it is asserted directly: the
    handed-over parts decide, and nothing goes back to the database."""
    dep = _deployment()
    Finding.objects.create(
        deployment=dep,
        fingerprint="fp-1",
        finding_type="prompt_injection",
        title="T",
        severity="critical",
        status=Finding.Status.OPEN,
    )
    parts = read_decision_parts(dep)
    counter = _Counter()
    with connection.execute_wrapper(counter):
        assert compute_decision(dep, parts=parts) == D.NOT_RECOMMENDED
    assert counter.count == 0, "compute_decision re-read the database despite being given parts"


@pytest.mark.django_db
def test_parts_handed_in_are_the_parts_used_and_not_a_hint():
    """A `parts` argument that were quietly ignored would leave the double read in
    place while looking fixed. Hand it parts that say something the database does
    not, and the answer must follow the parts."""
    dep = _deployment()
    assert compute_decision(dep) is None
    invented = DecisionParts(
        from_findings=D.NOT_RECOMMENDED,
        completed_scan=None,
        complete_audit=None,
        claim_signal={"cap": None},
        scan_cap=None,
        coverage_cap=None,
        # Spelled out rather than defaulted. `DecisionParts.composition` has no
        # default on purpose: a decision input a caller can silently omit is a
        # signal that reads as "nothing to say" when it was never asked, which is
        # the one failure mode this whole dataclass exists to prevent. The cost is
        # that adding a signal breaks every direct construction, and that is the
        # point -- each one has to say what it means by it.
        composition=compose_chains([]),
        # Spelled out for the same reason, and it means: this invented read saw
        # no outcomes, so there is no provenance to report. Distinct from a
        # census nobody took -- `recorded: 0` is a count, and the field is
        # required precisely so that distinction cannot be skipped.
        chain_provenance={
            "sources": {},
            "distinct": 0,
            "recorded": 0,
            "truncated": False,
            "not_shown": 0,
        },
    )
    assert compute_decision(dep, parts=invented) == D.NOT_RECOMMENDED


# ---------------------------------------------------------------------------
# The revision, reachable at last
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_the_payload_names_the_revision_it_was_read_at():
    """Before this the fence existed only for in-process Python callers: a
    consumer over HTTP could read a decision and had no way to tell a fresh one
    from one superseded between its read and its action."""
    dep = _deployment()
    assert decision_support(dep)["revision"] == 0
    accept_transition(dep, to_decision=D.READY)
    support = decision_support(dep)
    assert support["revision"] == 1
    assert support["revision"] == Deployment.objects.get(pk=dep.pk).decision_revision


@pytest.mark.django_db
def test_the_serializer_serves_the_revision():
    dep = stamped_under_the_rules_in_force(_deployment())
    accept_transition(dep, to_decision=D.READY)
    data = DeploymentSerializer(Deployment.objects.get(pk=dep.pk)).data
    assert data["decision_revision"] == 1


# ---------------------------------------------------------------------------
# The race itself
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_a_writer_landing_between_two_reads_cannot_splice_the_answer(monkeypatch):
    """The tear itself, deterministically.

    A thread racing a writer was the obvious way to write this and it is the wrong
    one: I wrote it, and restoring the double read left it green. SQLite serialised
    the writer against the reader often enough that the window never landed in 120
    samples, so the test proved nothing about the defect it was named after.

    So the writer lands exactly where it has to: in the gap between the first read
    of the claim signal and any second one. No thread, no sleep, no luck. Under one
    read there is no gap to land in, and the payload describes the state it read.
    Under two, the claims block comes from before the flip and the cap from after,
    and the answer is a state that never existed.
    """
    dep = _deployment()
    claim = _claim(dep, status=AssuranceClaim.ClaimStatus.SUPPORTED, fingerprint="fp-race")

    real = decision_module.claim_decision_signal
    reads: list[int] = []

    def flipping(deployment):
        reads.append(1)
        result = real(deployment)
        if len(reads) == 1:
            # The writer, in the gap.
            AssuranceClaim.objects.filter(pk=claim.pk).update(
                status=AssuranceClaim.ClaimStatus.CONTRADICTED
            )
        return result

    monkeypatch.setattr(decision_module, "claim_decision_signal", flipping)
    support = decision_support(dep)

    contradicted = len(support["claims"]["contradicted"])
    cap = support["claim_cap"]
    # Every state the database held was self-consistent: a contradicted claim
    # carries the cap, a supported one does not. So the payload disagreeing with
    # itself can only mean it was assembled from two moments.
    assert (contradicted > 0) == (cap == D.NEEDS_REMEDIATION), (
        f"the payload reports {contradicted} contradicted claim(s) beside "
        f"claim_cap={cap!r} -- no single database state produces that pair"
    )
    assert support["decision"] == (
        D.NEEDS_REMEDIATION if contradicted else None
    ), "the decision does not follow from the claims reported beside it"
