"""Phase 3 item 8: an outcome nobody knows, said out loud.

`DispatchAttempt.Outcome` was SENT or FAILED, and every transport error became
FAILED. A read timeout *after* the provider created the ticket is a transport
error, so:

- recording it FAILED licensed a retry that created the ticket a second time;
- recording it SENT would have claimed a ticket that may not exist.

Neither is true. These cover the third state, the durable operation identity that
makes it resolvable, and the retry it blocks in the meantime.
"""

from __future__ import annotations

import pytest
import requests.exceptions as rex
from assurance.connectors.base import (
    ConnectorResult,
    NotSent,
    OutcomeUnknown,
    classify_transport_error,
)
from assurance.dispatch import dispatch_finding, operation_id, policy_epoch, reconcile_attempt
from assurance.models import ConnectorBinding, Deployment, DispatchAttempt, Finding
from django.contrib.auth import get_user_model
from urllib3.exceptions import NameResolutionError, NewConnectionError

User = get_user_model()


# ---------------------------------------------------------------------------
# Classifying a transport error
# ---------------------------------------------------------------------------


def test_a_connect_timeout_certainly_never_reached_the_provider():
    assert classify_transport_error(rex.ConnectTimeout("no connection")) is NotSent


def test_a_name_that_never_resolved_certainly_never_reached_the_provider():
    pool_error = NameResolutionError("host", None, Exception("nxdomain"))
    wrapper = type("MaxRetry", (Exception,), {})()
    wrapper.reason = pool_error
    assert classify_transport_error(rex.ConnectionError(wrapper)) is NotSent


def test_a_connection_that_was_never_established_is_not_sent():
    pool_error = NewConnectionError(None, "connection refused")
    wrapper = type("MaxRetry", (Exception,), {})()
    wrapper.reason = pool_error
    assert classify_transport_error(rex.ConnectionError(wrapper)) is NotSent


def test_a_read_timeout_may_have_been_committed():
    """The canonical case: the request went out and the answer never came back."""
    assert classify_transport_error(rex.ReadTimeout("timed out")) is OutcomeUnknown


def test_a_connection_dying_mid_request_may_have_been_committed():
    """A ConnectionError with no "never connected" cause could be a reset after the
    request was already on the wire."""
    assert classify_transport_error(rex.ConnectionError("broken pipe")) is OutcomeUnknown


def test_an_unrecognised_error_defaults_to_may_have_been_committed():
    """Fail-closed: the other default -- assuming nothing was sent -- is the one
    that licenses a duplicate effect on the customer's system."""
    assert classify_transport_error(RuntimeError("something new")) is OutcomeUnknown


def test_a_result_is_certain_unless_it_says_otherwise():
    """Every existing result -- a parsed response, an inert connector -- is a case
    where the client does know, so the default must not change their meaning."""
    result = ConnectorResult(ok=False, external_ref=None, detail="refused", connector="c")
    assert result.certain is True
    assert result.uncertain is False


# ---------------------------------------------------------------------------
# The attempt records it
# ---------------------------------------------------------------------------


def _deployment():
    user = User.objects.create_user(
        username=f"disp-{Deployment.objects.count()}", password="x", role=User.Roles.ANALYST
    )
    return Deployment.objects.create(name="d", owner=user)


def _finding(dep):
    return Finding.objects.create(
        deployment=dep,
        fingerprint=f"fp-{Finding.objects.count()}",
        finding_type="t",
        title="T",
        severity="critical",
    )


class _Timeout:
    """A transport that gets the request out and then loses the answer."""

    def __init__(self):
        self.posts = 0

    def post(self, url, *, headers, json):
        self.posts += 1
        raise rex.ReadTimeout("the answer never came back")


class _Refused:
    """A transport whose connection is never established."""

    def post(self, url, *, headers, json):
        wrapper = type("MaxRetry", (Exception,), {})()
        wrapper.reason = NewConnectionError(None, "connection refused")
        raise rex.ConnectionError(wrapper)


CONNECTOR = "jira"


def _binding(dep):
    """A configured, operational binding. Built exactly as the existing dispatch
    tests build one, so these exercise the real path rather than a shape of my own."""
    binding = ConnectorBinding(
        deployment=dep,
        connector=CONNECTOR,
        enabled=True,
        endpoint={"base_url": "https://jira.example", "project_key": "SEC"},
    )
    binding.set_secret("jira-tok")  # requires the key below to be in scope
    binding.save()
    return binding


# A real Fernet key for the whole module: a binding's credential cannot be written
# or read without one, and these tests are about the OUTCOME of a push, not about
# the key. Applied via settings so the suite's default (no key) posture is untouched.
pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("_credential_key")]


@pytest.fixture()
def _credential_key(settings):
    from cryptography.fernet import Fernet

    settings.ASSURANCE_CREDENTIAL_KEY = Fernet.generate_key().decode()
    yield


def test_a_lost_answer_is_recorded_as_unknown_and_not_as_failed():
    dep = _deployment()
    finding = _finding(dep)
    _binding(dep)

    attempts = dispatch_finding(finding, trigger=DispatchAttempt.Trigger.MANUAL, transport_factory=_Timeout)
    assert len(attempts) == 1
    attempt = attempts[0]
    assert attempt.outcome == DispatchAttempt.Outcome.UNKNOWN
    assert "may have been received" in attempt.detail


def test_a_refused_connection_is_still_recorded_as_failed():
    """The fix must not make every failure uncertain -- a connection that was never
    made certainly did not commit anything, and retrying it is safe."""
    dep = _deployment()
    finding = _finding(dep)
    _binding(dep)

    attempt = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.MANUAL, transport_factory=_Refused
    )[0]
    assert attempt.outcome == DispatchAttempt.Outcome.FAILED
    assert "nothing was sent" in attempt.detail


def test_an_unresolved_unknown_blocks_the_retry_that_would_double_execute():
    """The defect end to end: the second trigger created a second ticket."""
    dep = _deployment()
    finding = _finding(dep)
    _binding(dep)

    transport = _Timeout()
    dispatch_finding(finding, trigger=DispatchAttempt.Trigger.MANUAL, transport_factory=lambda: transport)
    assert transport.posts == 1

    # A second qualifying trigger. Before this change the attempt was FAILED, which
    # read as "safe to retry", and the provider got the same finding twice.
    dispatch_finding(finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=lambda: transport)
    assert transport.posts == 1, "an uncertain attempt was retried and may have double-executed"

    attempt = DispatchAttempt.objects.get(finding=finding, connector=CONNECTOR)
    assert attempt.blocks_retry is True
    assert attempt.is_terminal is False, "uncertain is not accepted"


def test_a_failed_attempt_is_still_retried():
    """Blocking a retry is the new behaviour for UNCERTAIN only. A genuine failure
    must still be retried, or the fix has broken ordinary operation."""
    dep = _deployment()
    finding = _finding(dep)
    _binding(dep)

    posts = []

    class Counting(_Refused):
        def post(self, url, *, headers, json):
            posts.append(url)
            return super().post(url, headers=headers, json=json)

    transport = Counting()
    dispatch_finding(finding, trigger=DispatchAttempt.Trigger.MANUAL, transport_factory=lambda: transport)
    dispatch_finding(finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=lambda: transport)
    assert len(posts) == 2

    attempt = DispatchAttempt.objects.get(finding=finding, connector=CONNECTOR)
    assert attempt.attempts == 2


# ---------------------------------------------------------------------------
# Durable operation identity
# ---------------------------------------------------------------------------


def test_every_attempt_carries_a_durable_operation_id_and_the_epoch_it_ran_under():
    dep = _deployment()
    finding = _finding(dep)
    _binding(dep)

    attempt = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.MANUAL, transport_factory=_Timeout
    )[0]
    assert attempt.operation_id == operation_id(finding, CONNECTOR)
    assert len(attempt.operation_id) == 32
    assert attempt.policy_epoch == policy_epoch(dep)


def test_the_operation_id_is_the_same_for_a_retry_and_different_per_operation():
    """Same operation retried is the same operation, so a provider can deduplicate
    it; a different finding is never mistaken for it."""
    dep = _deployment()
    one, two = _finding(dep), _finding(dep)

    assert operation_id(one, CONNECTOR) == operation_id(one, CONNECTOR)
    assert operation_id(one, CONNECTOR) != operation_id(two, CONNECTOR)
    assert operation_id(one, CONNECTOR) != operation_id(one, "servicenow")


def test_an_unassessed_deployment_has_a_named_epoch_and_not_an_empty_one():
    dep = _deployment()
    assert dep.decision is None
    assert policy_epoch(dep) == "unassessed"


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------


def _uncertain_attempt():
    dep = _deployment()
    finding = _finding(dep)
    _binding(dep)
    return dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.MANUAL, transport_factory=_Timeout
    )[0]


def test_a_readback_that_finds_the_operation_resolves_it_to_sent():
    attempt = _uncertain_attempt()
    seen = []

    def readback(op_id):
        seen.append(op_id)
        return True

    reconcile_attempt(attempt, readback=readback)
    attempt.refresh_from_db()
    assert seen == [attempt.operation_id], "the readback was not asked by operation id"
    assert attempt.outcome == DispatchAttempt.Outcome.SENT
    assert attempt.reconciled_at is not None
    assert attempt.is_uncertain is False


def test_a_readback_that_does_not_find_it_resolves_it_to_failed():
    attempt = _uncertain_attempt()
    reconcile_attempt(attempt, readback=lambda op_id: False)
    attempt.refresh_from_db()
    assert attempt.outcome == DispatchAttempt.Outcome.FAILED
    assert attempt.blocks_retry is False, "a resolved failure is retryable again"


def test_a_readback_that_cannot_say_leaves_it_unknown():
    """A reconciliation that learned nothing must not write an answer -- that is the
    failure this whole state exists to prevent."""
    attempt = _uncertain_attempt()
    reconcile_attempt(attempt, readback=lambda op_id: None)
    attempt.refresh_from_db()
    assert attempt.outcome == DispatchAttempt.Outcome.UNKNOWN
    assert attempt.reconciled_at is None


def test_no_readback_at_all_leaves_it_unknown():
    attempt = _uncertain_attempt()
    reconcile_attempt(attempt)
    attempt.refresh_from_db()
    assert attempt.outcome == DispatchAttempt.Outcome.UNKNOWN


def test_a_readback_that_raises_leaves_it_unknown():
    attempt = _uncertain_attempt()

    def boom(op_id):
        raise RuntimeError("the provider is down too")

    reconcile_attempt(attempt, readback=boom)
    attempt.refresh_from_db()
    assert attempt.outcome == DispatchAttempt.Outcome.UNKNOWN


def test_reconciliation_is_not_a_way_to_move_a_settled_attempt():
    """A SENT attempt is not re-openable by a readback, and a FAILED one is not
    quietly promoted."""
    attempt = _uncertain_attempt()
    attempt.outcome = DispatchAttempt.Outcome.SENT
    attempt.save(update_fields=["outcome"])

    reconcile_attempt(attempt, readback=lambda op_id: False)
    attempt.refresh_from_db()
    assert attempt.outcome == DispatchAttempt.Outcome.SENT
