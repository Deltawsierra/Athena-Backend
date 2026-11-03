import logging

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.dispatch import Signal
from django.utils import timezone

from assurance.append_only import HistoryQuerySet, insert_only

logger = logging.getLogger(__name__)

#: Sent, with ``account_pk``, when an existing account loses something it held: its
#: role changed (the role it had is no longer its role), the superuser flag taken away,
#: or the account deactivated. A removal is the account's own ``post_delete``. This
#: module reads and writes nothing for it and imports nothing that listens: the
#: identity emitter (assurance.identity_emitter) listens, notes the account, and signs
#: the revocation of the grant it no longer holds only once the change is ANSWERED --
#: so a demotion, which is a stop, never waits on it. Sent robustly: no receiver can
#: refuse or undo the change.
role_withdrawn = Signal()


def withdraws(before, after) -> bool:
    """Whether an existing account moving from ``before`` to ``after`` -- each
    ``(role, is_superuser, is_active)`` -- loses something it held: the role it had,
    the superuser flag, or being active."""
    (role, superuser, active), (new_role, new_superuser, new_active) = before, after
    return role != new_role or (bool(superuser) and not new_superuser) or (bool(active) and not new_active)


def announce_withdrawal(account_pk) -> None:
    """Say that account ``account_pk`` lost something it held (:data:`role_withdrawn`).
    Never raises, and never holds the change back."""
    try:
        role_withdrawn.send_robust(sender=CustomUser, account_pk=account_pk)
    except Exception:  # noqa: BLE001 - the withdrawal stands; only its revocation record is missing
        logger.exception("account %s's withdrawal could not be announced", account_pk)


class CustomUser(AbstractUser):
    class Roles(models.TextChoices):
        ADMIN = "admin", "Admin"
        ANALYST = "analyst", "Analyst"
        VIEWER = "viewer", "Viewer"

    role = models.CharField(
        max_length=20,
        choices=Roles.choices,
        default=Roles.VIEWER,
    )

    @property
    def is_admin(self):
        # A Django superuser had no rights in this API at all, because role
        # defaults to viewer and nothing consulted is_superuser. That left two
        # disjoint privilege systems: createsuperuser produced an account that
        # could not read the user list, while a role=admin account with
        # is_staff False controlled the user API but could not reach /admin/.
        return self.role == self.Roles.ADMIN or self.is_superuser

    @property
    def is_analyst(self):
        return self.role == self.Roles.ANALYST

    @property
    def is_viewer(self):
        return self.role == self.Roles.VIEWER

    def grant_role_as(self, granter) -> None:
        """Name ``granter`` (the signed-in account making the change) as the one who
        granted the role this NEW account is saved with (:class:`RoleGrant`).
        Nothing is read."""
        self._role_granted_by = granter

    def save(self, *args, **kwargs):
        adding = self._state.adding
        super().save(*args, **kwargs)
        # A new account above viewer was granted its role as it was created
        # (spec-v1, section 35.6). An existing account's promotion is recorded by
        # whatever promoted it (:func:`change_role`, the admin site), which holds the
        # role it had. Nothing is recorded or read here for an existing account, so
        # saving one -- a demotion, a deactivation, a sign-in -- is exactly as before.
        if adding and rank(self.role, self.is_superuser) > 0:
            RoleGrant.record(self, getattr(self, "_role_granted_by", None))
        self._role_granted_by = None

    def change_role(self, role, *, by) -> None:
        """Set this account's role, as ``by``: the one UPDATE it always was. Only a
        PROMOTION then records who granted it and when (:class:`RoleGrant`); a
        demotion records nothing, reads nothing more, and is never refused: it is a
        revoke. Any change of role then announces that the role it had is withdrawn
        (:data:`role_withdrawn`), which reads and writes nothing here."""
        had = self.role
        before = rank(self.role, self.is_superuser)
        self.role = role
        self.save(update_fields=["role"])
        if rank(self.role, self.is_superuser) > before:
            RoleGrant.record(self, by)
        if self.role != had:
            announce_withdrawal(self.pk)

    def __str__(self):
        return f"{self.username} ({self.role})"


#: Each role's rank: a move up is a promotion. A superuser ranks as an admin.
_RANKS = {CustomUser.Roles.VIEWER: 0, CustomUser.Roles.ANALYST: 1, CustomUser.Roles.ADMIN: 2}


def rank(role, is_superuser) -> int:
    """The rank ``role`` (and the superuser flag) gives an account."""
    if is_superuser is True:
        return _RANKS[CustomUser.Roles.ADMIN]
    return _RANKS.get(role, 0)


class RoleGrantQuerySet(HistoryQuerySet):
    """Refuses a bulk update or delete and an upsert of a recorded grant, as a grant's
    ``save`` and ``delete`` refuse one (:mod:`assurance.append_only`)."""

    refused = ValueError
    rewritten = "A role grant is history and is never rewritten; record a new one."
    deleted = "A role grant is history and is never deleted."


class RoleGrant(models.Model):
    """One promotion of one account: who granted it the role, and when (section 28
    hardening, T9b; docs/economics/spec-v1.md, section 35.6). An approval reads the
    approver's latest: someone promoted by the person who asked, by themselves, or
    after the request was made is not a second person.

    Its own table, never a column of the account: loading an account -- every
    request does, stops included -- reads nothing new. Accounts are named by id and
    username, never a foreign key, so removing an operator (a stop) neither cascades
    here nor writes anything. Written only on a promotion, never on a demotion, a
    deactivation or a removal; append-only: its ``save`` writes a new grant and nothing
    else, its ``delete`` is refused, and its queryset refuses a bulk update or delete and
    an upsert. An account given its role before grants were recorded has none, and no
    approval is refused for it by this rule.

    A grant that names its granter is also emitted, once it commits, as a signed
    delegation record of one lease (assurance.identity_emitter, authority chain short
    2, which listens for this model's ``post_save``: nothing here imports it); a record
    that cannot be made never refuses the promotion."""

    id = models.BigAutoField(primary_key=True)
    account_pk = models.BigIntegerField(db_index=True)
    account_username = models.CharField(max_length=150)
    role = models.CharField(max_length=20)
    is_superuser = models.BooleanField(default=False)
    granted_by_pk = models.BigIntegerField(null=True, blank=True)
    granted_by_username = models.CharField(max_length=150, blank=True, default="")
    granted_at = models.DateTimeField(default=timezone.now)

    objects = RoleGrantQuerySet.as_manager()

    class Meta:
        ordering = ["account_pk", "granted_at", "id"]

    @classmethod
    def record(cls, account, granter) -> "RoleGrant":
        named = granter is not None and getattr(granter, "pk", None) is not None
        grant = cls.objects.create(
            account_pk=account.pk,
            account_username=(account.get_username() or "")[:150],
            role=account.role,
            is_superuser=bool(account.is_superuser),
            granted_by_pk=granter.pk if named else None,
            granted_by_username=(granter.get_username() or "")[:150] if named else "",
            granted_at=timezone.now(),
        )
        # Signed, once the promotion commits, as a delegation record of the grant, by
        # the identity emitter's post_save receiver (assurance.identity_emitter,
        # authority chain short 2). Only a promotion reaches here; the promotion stands
        # whatever happens to its record. A grant that names nobody was delegated by
        # nobody, and has no delegation record.
        return grant

    @classmethod
    def latest_for(cls, account_id, at=None) -> "RoleGrant | None":
        """The account's latest recorded promotion -- where ``at`` is given, its latest
        at or before ``at`` (the role it held then) -- or ``None``."""
        if account_id is None:
            return None
        grants = cls.objects.filter(account_pk=account_id)
        if at is not None:
            grants = grants.filter(granted_at__lte=at)
        return grants.order_by("-granted_at", "-id").first()

    def save(self, *args, **kwargs):
        refusal = ValueError("A role grant is history and is never rewritten; record a new one.")
        # An INSERT and nothing else (assurance.append_only): a new instance carrying a
        # recorded grant's key fails on the key rather than overwriting that grant.
        super().save(*args, **insert_only(self, kwargs, refusal))

    def delete(self, *args, **kwargs):
        raise ValueError("A role grant is history and is never deleted.")

    def __str__(self):
        return f"{self.account_username} made {self.role} by {self.granted_by_username or 'nobody'}"
