from django.db import models


class SignInCount(models.Model):
    """The sign-in attempts counted under one key in one window
    (safety.sign_in). One row per key and window, incremented in the database
    by one atomic ``UPDATE ... SET count = count + 1`` before any password is
    hashed, so every worker process -- and every thread -- counts against the
    same number."""

    #: SHA-256 of the scope and what it counts: an address, or an address and
    #: a username. Neither is stored.
    key = models.CharField(max_length=64)
    #: The window's number: seconds since the epoch, divided by its length.
    window = models.BigIntegerField()
    count = models.PositiveIntegerField(default=0)
    #: When the row stops mattering (the end of the window after this one), in
    #: seconds since the epoch: rows past it are removed.
    until = models.BigIntegerField(db_index=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["key", "window"], name="safety_signin_key_window")]

    def __str__(self):
        return f"{self.key[:12]} window {self.window}: {self.count}"
