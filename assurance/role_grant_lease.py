"""How long a record of one of this backend's role grants proves anything: one lease.

#181 (:mod:`assurance.identity_emitter`) signs each promotion of an operator as a
``mythos.delegation/v1`` record -- the granter delegated the account the scope
``athena-backend:role:<role>`` -- and it signed every one with no end
(``not_after`` 9999-12-31), while a demotion, a deactivation or a removal emitted no
revocation. So once an operator lost a role, the record of its grant still read
``proven`` for every later effect, for ever: a false proof of authority (the
IDP-DESIGN report, suggestion 3; #181's open item).

THE LEASE. A role grant's record now proves only within one lease of the instant its
window opens: ``[not_before, not_before + ROLE_GRANT_LEASE_SECONDS)``. The emitter
writes that window into every grant record it signs, re-asserts it -- a new record,
a new window, a new digest -- only while the role is still held
(:func:`assurance.identity_emitter.reconcile`), and signs a revocation the moment
the role is withdrawn. A record that says otherwise is read to the lease all the
same (:func:`lease_end`): the open-ended records #181 already signed, which are
append-only and cannot be rewritten, close one lease after they opened. So a record
nothing re-asserted lapses to ``unproven`` (``delegation_expired``) whatever else
failed -- the emitter's key withdrawn, the reconcile never scheduled, the database
down, a demotion made by a path that told nobody: what is unknown never reads as
held.

WHY 24 HOURS. It is the bound the design gives an identity provider's grant (the
IDP-DESIGN report, sections 5 and 5.5, slice 4: ``not_after = observed_at + lease``,
24 h) and the window a sign-in proves an effect in
(:data:`assurance.authority_chain.AUTHENTICATION_WINDOW_SECONDS`), so the two person
hops of a chain go stale on the same clock. Shorter means more signed records and
decision refreshes for a held role (each one recomputes under the row lock a pause
takes); longer means a missed revocation proves for longer. A revocation is still
signed at once on a withdrawal (:mod:`assurance.identity_emitter`), so the lease is
the bound on what goes WRONG -- a revocation that could not be signed -- not the
usual delay.

WHICH RECORDS. A grant whose every action is a role of this backend's
(:data:`ROLE_SCOPE_PREFIX`): no customer's tool performs such an action, and only
this backend names one. Every other delegation is read exactly as before.

A leaf: this module imports nothing of the backend's, so the read side, the emitter
and the policy pin can all read it, and no stop handler does.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

#: The lease a role grant's record proves for, from the instant its window opens.
ROLE_GRANT_LEASE_SECONDS = 24 * 60 * 60
#: How a role of this backend's is named as an action: ``athena-backend:role:<role>``
#: (:func:`assurance.identity_emitter.role_scope`).
ROLE_SCOPE_PREFIX = "athena-backend:role:"


def lease() -> timedelta:
    """One lease, read from :data:`ROLE_GRANT_LEASE_SECONDS` at every call."""
    return timedelta(seconds=ROLE_GRANT_LEASE_SECONDS)


def is_role_grant(actions) -> bool:
    """Whether a grant of ``actions`` is a grant of this backend's roles: every action
    one of them, and at least one."""
    actions = list(actions)
    return bool(actions) and all(isinstance(a, str) and a.startswith(ROLE_SCOPE_PREFIX) for a in actions)


def lease_end(actions, not_before: datetime, not_after: datetime) -> datetime:
    """When a grant of ``actions`` over ``[not_before, not_after)`` stops proving: its
    own end, and for a role grant no later than one lease after it opened."""
    if is_role_grant(actions):
        return min(not_after, not_before + lease())
    return not_after


def leased(delegations):
    """``delegations`` (:class:`assurance.authority_chain.Delegation`), each role grant
    read to its lease: what the chain rule judges a ``delegates_to`` hop with."""
    return tuple(
        replace(d, not_after=lease_end(d.actions, d.not_before, d.not_after))
        if is_role_grant(d.actions)
        else d
        for d in delegations
    )


__all__ = ["ROLE_GRANT_LEASE_SECONDS", "ROLE_SCOPE_PREFIX", "is_role_grant", "lease", "lease_end", "leased"]
