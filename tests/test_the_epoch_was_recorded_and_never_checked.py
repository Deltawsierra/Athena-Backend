"""The authority a dispatch was made under was written down and never consulted.

``DispatchAttempt.policy_epoch`` carries its own rule, on the field itself:

    The policy epoch this was authorized under. A retry after the epoch moved is
    being executed under an authority that no longer holds, and that is a
    different decision from the one that was made.

Nothing enforced it. The field was written in exactly two places and read in
**zero** conditions -- and the retry path did worse than ignore it, it destroyed
it: ``_record`` overwrote the stored epoch with the one in force now, so after a
retry there was no longer any record that the authority had moved.

The reachable sequence, all of it ordinary operation:

1. A finding is dispatched while the deployment's decision is READY. The answer is
   lost in transit, so the attempt is UNKNOWN and ``blocks_retry`` holds it.
2. An operator moves the deployment to NOT_RECOMMENDED. The authority under which
   that push was made no longer exists.
3. Reconciliation reaches the provider, which does not have it. The attempt
   resolves to FAILED -- which is neither terminal nor uncertain, so
   ``blocks_retry`` is now False.
4. The next qualifying trigger retries. **The push happens**, under an authority
   that was withdrawn, and the evidence that it moved is overwritten in the same
   save.

Step 4 is the defect. Steps 1-3 are the system working exactly as designed, which
is what makes it worth a test rather than a comment. Measured before the fix:

    1. after lost answer : unknown | epoch: ready            | blocks_retry: True
    2. after reconcile   : failed  | epoch: ready            | blocks_retry: False
    3. authority withdrawn -> deployment.decision = not_recommended
    4. after RETRY       : sent    | epoch: not_recommended  | PUSHES: 1
       detail: jira issue SEC-1 created

A real ticket, on the customer's system, under a decision that says the deployment
is not recommended -- and a row that now claims it was authorized that way.

**Only the automatic triggers are held.** A MANUAL dispatch is a person choosing to
push under the authority in force now, which is what re-authorization IS. Without
that, the refusal would be permanent: the recorded epoch and the current one would
disagree forever and nothing could ever clear it. A block nobody can lift is a
worse failure than the one this closes, so the escape hatch is part of the fix
rather than a concession to it.

Every test here has a control beside it, because "refuse every retry" would satisfy
the enforcement tests on its own while breaking the retry the FAILED outcome exists
to license.
"""

from __future__ import annotations

import pytest
import requests.exceptions as rex
from assurance.dispatch import dispatch_finding, policy_epoch, reconcile_attempt
from assurance.models import ConnectorBinding, Deployment, DispatchAttempt, Finding
from assurance.revision import accept_transition
from django.contrib.auth import get_user_model
from tests.decision_surfaces import stamped_under_the_rules_in_force

User = get_user_model()

CONNECTOR = "jira"

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("_credential_key")]


@pytest.fixture()
def _credential_key(settings):
    from cryptography.fernet import Fernet

    settings.ASSURANCE_CREDENTIAL_KEY = Fernet.generate_key().decode()
    yield


def _deployment(decision=Deployment.Decision.READY):
    user = User.objects.create_user(
        username=f"epoch-{Deployment.objects.count()}", password="x", role=User.Roles.ANALYST
    )
    # Stamped: these tests are about the epoch a hand-written decision gives a
    # dispatch, not about recomputing it.
    return stamped_under_the_rules_in_force(
        Deployment.objects.create(name="d", owner=user, decision=decision)
    )


def _finding(dep):
    return Finding.objects.create(
        deployment=dep,
        fingerprint=f"fp-{Finding.objects.count()}",
        finding_type="t",
        title="T",
        severity="critical",
    )


def _binding(dep):
    binding = ConnectorBinding(
        deployment=dep,
        connector=CONNECTOR,
        enabled=True,
        endpoint={"base_url": "https://jira.example", "project_key": "SEC"},
    )
    binding.set_secret("jira-tok")
    binding.save()
    return binding


class _Timeout:
    """The request goes out and the answer never comes back."""

    def post(self, url, *, headers, json):
        raise rex.ReadTimeout("the answer never came back")


class _Accepting:
    """A provider that accepts everything, and counts what it was asked to do."""

    pushes = 0

    def post(self, url, *, headers, json):
        type(self).pushes += 1

        class _Response:
            status_code = 201
            text = '{"key": "SEC-1"}'

            @staticmethod
            def json():
                return {"key": "SEC-1", "id": "1"}

            @staticmethod
            def raise_for_status():
                return None

        return _Response()


@pytest.fixture(autouse=True)
def _reset_pushes():
    _Accepting.pushes = 0
    yield


def _lost_then_reconciled(dep, finding):
    """Steps 1 and 3: an answer lost in transit, then resolved as never committed.

    This is the ordinary, correct operation of the UNKNOWN outcome. Nothing here is
    the defect -- it is the state the defect needs, and building it through the real
    functions rather than by writing rows keeps it honest.
    """
    attempt = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.MANUAL, transport_factory=_Timeout
    )[0]
    assert attempt.outcome == DispatchAttempt.Outcome.UNKNOWN, attempt.outcome
    assert attempt.blocks_retry, "an unresolved uncertain attempt must hold the retry"

    reconcile_attempt(attempt, readback=lambda _op: False)
    attempt.refresh_from_db()
    assert attempt.outcome == DispatchAttempt.Outcome.FAILED, attempt.outcome
    assert not attempt.blocks_retry, "a reconciled FAILED attempt is retryable again"
    return attempt


# ---------------------------------------------------------------------------
# The defect.
# ---------------------------------------------------------------------------


def test_an_automatic_retry_after_the_authority_was_withdrawn_does_not_push():
    """The whole point. The epoch moved between the attempt and the retry."""
    dep = _deployment(Deployment.Decision.READY)
    finding = _finding(dep)
    _binding(dep)

    first = _lost_then_reconciled(dep, finding)
    assert first.policy_epoch == "ready"

    # The operator withdraws the authority this dispatch was made under.
    accept_transition(dep, to_decision=Deployment.Decision.NOT_RECOMMENDED)

    retry = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=_Accepting
    )[0]

    assert _Accepting.pushes == 0, "nothing may be pushed under a withdrawn authority"
    assert retry.outcome == DispatchAttempt.Outcome.SKIPPED_EPOCH_MOVED, retry.outcome


def test_the_epoch_it_was_authorized_under_survives_the_retry():
    """The evidence must not be destroyed by the thing it is evidence about.

    `_record` used to overwrite policy_epoch on every retry, so after the retry the
    row said the attempt had been made under the CURRENT authority -- the one it had
    not been authorized under. A reader could no longer tell that anything moved.
    """
    dep = _deployment(Deployment.Decision.READY)
    finding = _finding(dep)
    _binding(dep)

    _lost_then_reconciled(dep, finding)
    accept_transition(dep, to_decision=Deployment.Decision.NOT_RECOMMENDED)

    retry = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=_Accepting
    )[0]

    assert retry.policy_epoch == "ready", "the authorizing epoch is not overwritten"
    assert "ready" in retry.detail and "not_recommended" in retry.detail, (
        f"the refusal must name both epochs, not just refuse: {retry.detail!r}"
    )


def test_the_refusal_is_recorded_rather_than_silently_skipped():
    """A dispatch that did not happen, and why, is itself a fact worth keeping.

    Returning None or leaving the row untouched would make "refused because the
    authority moved" indistinguishable from "never attempted".
    """
    dep = _deployment(Deployment.Decision.READY)
    finding = _finding(dep)
    _binding(dep)

    _lost_then_reconciled(dep, finding)
    accept_transition(dep, to_decision=Deployment.Decision.NOT_RECOMMENDED)

    dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=_Accepting
    )
    row = DispatchAttempt.objects.get(finding=finding, connector=CONNECTOR)
    assert row.outcome == DispatchAttempt.Outcome.SKIPPED_EPOCH_MOVED
    assert row.blocks_retry is False, (
        "a re-authorization under the new epoch must still be possible; this is a "
        "refusal of THIS retry, not a permanent block"
    )


def test_a_manual_dispatch_is_a_fresh_authorization_under_the_epoch_now():
    """The escape hatch, and it must be a real one.

    Without this the refusal is permanent: the recorded epoch and the current one
    would disagree forever, and no operator action could ever clear it. A person
    dispatching manually while the deployment reads NOT_RECOMMENDED is making that
    decision themselves, which is what re-authorization means -- so the push
    happens AND the recorded epoch advances to the one it was authorized under.
    """
    dep = _deployment(Deployment.Decision.READY)
    finding = _finding(dep)
    _binding(dep)

    _lost_then_reconciled(dep, finding)
    accept_transition(dep, to_decision=Deployment.Decision.NOT_RECOMMENDED)

    # First the automatic retry is refused...
    refused = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=_Accepting
    )[0]
    assert refused.outcome == DispatchAttempt.Outcome.SKIPPED_EPOCH_MOVED
    assert _Accepting.pushes == 0

    # ...then a person dispatches it deliberately.
    manual = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.MANUAL, transport_factory=_Accepting
    )[0]

    assert _Accepting.pushes == 1
    assert manual.outcome == DispatchAttempt.Outcome.SENT
    assert manual.policy_epoch == "not_recommended", (
        "the manual dispatch IS the authorization, so the epoch it was authorized "
        "under is the one in force when the person made that call"
    )


# ---------------------------------------------------------------------------
# The controls. Each fails under a different wrong "fix".
# ---------------------------------------------------------------------------


def test_a_retry_under_the_same_authority_still_pushes():
    """Fails if the fix refuses every retry.

    The FAILED outcome exists precisely to license a retry. An epoch check that
    blocked them all would undo the reconciliation work it sits on top of.
    """
    dep = _deployment(Deployment.Decision.READY)
    finding = _finding(dep)
    _binding(dep)

    _lost_then_reconciled(dep, finding)
    # The authority has NOT moved.

    retry = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=_Accepting
    )[0]

    assert _Accepting.pushes == 1
    assert retry.outcome == DispatchAttempt.Outcome.SENT, retry.outcome
    assert retry.policy_epoch == "ready"


def test_a_first_dispatch_is_never_refused_for_a_moved_epoch():
    """There is nothing to compare against. Fails if the fix compares an absent
    stored epoch to the current one and calls the difference a move."""
    dep = _deployment(Deployment.Decision.NOT_RECOMMENDED)
    finding = _finding(dep)
    _binding(dep)

    attempt = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.MANUAL, transport_factory=_Accepting
    )[0]

    assert _Accepting.pushes == 1
    assert attempt.outcome == DispatchAttempt.Outcome.SENT
    assert attempt.policy_epoch == "not_recommended", (
        "a first dispatch records the epoch in force; it does not judge it"
    )


def test_an_attempt_with_no_recorded_epoch_is_not_treated_as_moved():
    """Rows predating the field have policy_epoch="". Blank is not an epoch that
    moved -- it is an epoch nobody wrote down, and refusing on it would block every
    retry of every historical attempt."""
    dep = _deployment(Deployment.Decision.READY)
    finding = _finding(dep)
    _binding(dep)

    attempt = _lost_then_reconciled(dep, finding)
    DispatchAttempt.objects.filter(pk=attempt.pk).update(policy_epoch="")

    retry = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=_Accepting
    )[0]

    assert _Accepting.pushes == 1
    assert retry.outcome == DispatchAttempt.Outcome.SENT
    assert retry.policy_epoch == "ready", "and it is backfilled, like operation_id"


def test_the_epoch_is_still_what_the_deployment_decision_says():
    """The control on policy_epoch itself: an unset decision is "unassessed", not
    blank, so the enforcement above never sees a blank for a live deployment."""
    dep = _deployment(decision="")
    assert policy_epoch(dep) == "unassessed"
