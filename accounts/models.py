from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


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
        revoke."""
        before = rank(self.role, self.is_superuser)
        self.role = role
        self.save(update_fields=["role"])
        if rank(self.role, self.is_superuser) > before:
            RoleGrant.record(self, by)

    def __str__(self):
        return f"{self.username} ({self.role})"


#: Each role's rank: a move up is a promotion. A superuser ranks as an admin.
_RANKS = {CustomUser.Roles.VIEWER: 0, CustomUser.Roles.ANALYST: 1, CustomUser.Roles.ADMIN: 2}


def rank(role, is_superuser) -> int:
    """The rank ``role`` (and the superuser flag) gives an account."""
    if is_superuser is True:
        return _RANKS[CustomUser.Roles.ADMIN]
    return _RANKS.get(role, 0)


class RoleGrant(models.Model):
    """One promotion of one account: who granted it the role, and when (section 28
    hardening, T9b; docs/economics/spec-v1.md, section 35.6). An approval reads the
    approver's latest: someone promoted by the person who asked, by themselves, or
    after the request was made is not a second person.

    Its own table, never a column of the account: loading an account -- every
    request does, stops included -- reads nothing new. Accounts are named by id and
    username, never a foreign key, so removing an operator (a stop) neither cascades
    here nor writes anything. Written only on a promotion, never on a demotion, a
    deactivation or a removal; append-only. An account given its role before grants
    were recorded has none, and no approval is refused for it by this rule."""

    id = models.BigAutoField(primary_key=True)
    account_pk = models.BigIntegerField(db_index=True)
    account_username = models.CharField(max_length=150)
    role = models.CharField(max_length=20)
    is_superuser = models.BooleanField(default=False)
    granted_by_pk = models.BigIntegerField(null=True, blank=True)
    granted_by_username = models.CharField(max_length=150, blank=True, default="")
    granted_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["account_pk", "granted_at", "id"]

    @classmethod
    def record(cls, account, granter) -> "RoleGrant":
        named = granter is not None and getattr(granter, "pk", None) is not None
        return cls.objects.create(
            account_pk=account.pk,
            account_username=(account.get_username() or "")[:150],
            role=account.role,
            is_superuser=bool(account.is_superuser),
            granted_by_pk=granter.pk if named else None,
            granted_by_username=(granter.get_username() or "")[:150] if named else "",
            granted_at=timezone.now(),
        )

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
        if not self._state.adding:
            raise ValueError("A role grant is history and is never rewritten; record a new one.")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.account_username} made {self.role} by {self.granted_by_username or 'nobody'}"
