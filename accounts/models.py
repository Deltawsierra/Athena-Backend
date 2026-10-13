from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

#: The grant fields a promotion writes (spec, section 35: who granted an account the
#: role it holds, and when).
GRANT_FIELDS = ("role_granted_at", "role_granted_by_account", "role_granted_by_username")


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
    # Who gave the account the role it holds, and when (section 28 hardening, T9b;
    # docs/economics/spec-v1.md, section 35). Written by save() on a PROMOTION only --
    # a new account above viewer, a higher role, or the superuser flag set -- never by
    # a demotion, a deactivation or a removal, which are revokes and are never held
    # back by anything here. An approval reads it: someone promoted by the person who
    # asked, by themselves, or after the request was made is not a second person.
    # Empty on an account given its role before grants were recorded. The granter is
    # named by the account's id and username, never a foreign key: removing an
    # operator (a stop) writes nothing to the accounts they promoted.
    role_granted_at = models.DateTimeField(null=True, blank=True, editable=False)
    role_granted_by_account = models.BigIntegerField(null=True, blank=True, editable=False)
    role_granted_by_username = models.CharField(max_length=150, blank=True, default="", editable=False)

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

    @classmethod
    def from_db(cls, db, field_names, values):
        instance = super().from_db(db, field_names, values)
        # What the stored row granted, read from the row as it was loaded: a save
        # compares against it and reads nothing more.
        loaded = dict(zip(field_names, values, strict=False))
        instance._loaded_rank = _rank(loaded.get("role"), loaded.get("is_superuser"))
        return instance

    def grant_role_as(self, granter) -> None:
        """Name ``granter`` (the signed-in account making the change) as the one who
        granted a promotion this instance's next save makes. Nothing is read."""
        self._role_granted_by = granter

    def save(self, *args, **kwargs):
        # A promotion records who granted it and when; nothing else changes, nothing
        # is read, and nothing is refused: a demotion (a revoke) leaves the record as
        # it was and is never held back.
        before = 0 if self._state.adding else getattr(self, "_loaded_rank", 0)
        after = _rank(self.role, self.is_superuser)
        if after > before:
            granter = getattr(self, "_role_granted_by", None)
            named = granter is not None and getattr(granter, "pk", None) is not None
            self.role_granted_at = timezone.now()
            self.role_granted_by_account = granter.pk if named else None
            self.role_granted_by_username = (granter.get_username() or "")[:150] if named else ""
            update_fields = kwargs.get("update_fields")
            if update_fields is not None:
                kwargs["update_fields"] = sorted(set(update_fields) | set(GRANT_FIELDS))
        super().save(*args, **kwargs)
        self._loaded_rank = after
        self._role_granted_by = None

    def __str__(self):
        return f"{self.username} ({self.role})"


#: Each role's rank: a move up is a promotion. A superuser ranks as an admin.
_RANKS = {CustomUser.Roles.VIEWER: 0, CustomUser.Roles.ANALYST: 1, CustomUser.Roles.ADMIN: 2}


def _rank(role, is_superuser) -> int:
    if is_superuser is True:
        return _RANKS[CustomUser.Roles.ADMIN]
    return _RANKS.get(role, 0)
