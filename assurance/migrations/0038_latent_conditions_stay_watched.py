import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models
from django.utils import timezone

#: ``LatentCondition.State`` values when this migration was written. Spelled here,
#: not imported: a migration records what it did.
LIVE = ("pending", "fired", "unobservable", "evaluation_failed")
FIRED = "fired"
WITHDRAWN = "withdrawn"


def _current_version(AssuranceClaim, claim):
    """The current version of ``claim``'s chain (``superseded_by`` to the end), or
    None if the chain ends on a closed version or loops."""
    seen = set()
    while claim.superseded_by_id is not None and claim.pk not in seen:
        seen.add(claim.pk)
        claim = AssuranceClaim.objects.filter(pk=claim.superseded_by_id).first()
        if claim is None:
            return None
    return claim if claim.valid_to is None else None


def carry_watches_forward(apps, schema_editor):
    """Every live latent condition left on a version a re-derive closed, brought to
    the current version of the same claim.

    Until now a re-derive opened the new version without the watches declared on the
    old one. Left on the closed version, a watch was evaluated never again -- only
    current versions are -- while the posture counted it watched; and a FIRED one
    stopped holding its claim, which the re-derive read back to a pass, resolving its
    retest, while the precondition was still true. The code now carries every live
    watch at the re-derive; this carries what was left behind before it did. Run
    here, after the declaration constraint is made live-only, so a watch a person
    withdrew is a record beside the one carried, not a collision with it.

    One watch -- a declaration (kind, subject, expected) on one claim -- can have
    been stated more than once along a chain: an operator who saw it left behind
    re-declared it on the new version. Every live statement of it is read at once,
    the one on the current version included, and:

    - one is kept on the current version: the newest that FIRED, if any did, else
      the newest -- the person's latest statement of it. A FIRED statement already on
      the current version stays there;
    - every other statement that did not fire is withdrawn, with a note naming the
      one kept, so one watch is not counted as two;
    - a FIRED statement is never withdrawn. Withdrawing a fired watch accepts the
      state it fired on, and only a person may; a merge that withdrew the newer,
      FIRED statement in favour of an older pending one left the precondition broken
      and the deployment reading READY. One that is not the one kept stays FIRED
      where it is, holding the claim -- the hold is on the claim, on every version
      of it -- until a person withdraws it.

    A withdrawn statement is not read at all: nothing is merged into it, and nothing
    about it is rewritten.
    """
    AssuranceClaim = apps.get_model("assurance", "AssuranceClaim")
    LatentCondition = apps.get_model("assurance", "LatentCondition")

    now = timezone.now()
    watches: dict = {}
    for condition in LatentCondition.objects.filter(state__in=LIVE).select_related("claim").order_by("pk"):
        current = _current_version(AssuranceClaim, condition.claim)
        if current is None:
            continue
        key = (current.pk, condition.kind, condition.subject, condition.expected)
        watches.setdefault(key, []).append(condition)

    for (current_pk, *_declaration), statements in watches.items():
        if len(statements) == 1 and statements[0].claim_id == current_pk:
            continue
        kept = _kept(statements, current_pk)
        for statement in statements:
            if statement is kept or statement.state == FIRED:
                continue
            statement.state = WITHDRAWN
            statement.withdrawn_at = now
            statement.withdrawn_note = (
                f"Merged into the same declaration on the claim's current version ({kept.uuid}, "
                f"{kept.state}) when migration 0038 carried forward the watches a re-derive had "
                "left behind; withdrawn here so one watch is not counted as two. The one kept is "
                "the newest statement of it that fired, or the newest statement of it: a fired "
                "watch is never withdrawn by a migration, since only a person can accept the "
                "state it fired on."
            )
            statement.save(update_fields=["state", "withdrawn_at", "withdrawn_note"])
        if kept.claim_id != current_pk:
            kept.claim_id = current_pk
            kept.save(update_fields=["claim"])


def _kept(statements, current_pk):
    """The statement of one watch that stands on the claim's current version."""
    on_current = [s for s in statements if s.claim_id == current_pk]
    if on_current and on_current[0].state == FIRED:
        return on_current[0]
    fired = [s for s in statements if s.state == FIRED]
    return max(fired or statements, key=lambda s: (s.declared_at, s.pk))


class Migration(migrations.Migration):
    """A latent condition stays watched: an unobservable one is read again, a fired
    one holds its claim across re-derives, a failed evaluation is recorded on the
    condition, the same watch can be declared again once the first is withdrawn, and
    every watch a re-derive left on a closed version is carried to the current one."""

    dependencies = [
        ("assurance", "0037_carry_watches_and_legal_rulings"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name="latentcondition",
            name="state",
            field=models.CharField(
                choices=[
                    ("pending", "Declared, not yet true"),
                    ("fired", "Became true; claim invalidated"),
                    ("unobservable", "Subject can no longer be observed"),
                    ("evaluation_failed", "Its evaluation failed; not watched"),
                    ("withdrawn", "Withdrawn"),
                ],
                db_index=True,
                default="pending",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="latentcondition",
            name="last_error_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="latentcondition",
            name="last_error",
            field=models.CharField(blank=True, db_default="", default="", max_length=200),
        ),
        migrations.AddField(
            model_name="latentcondition",
            name="withdrawn_by",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="withdrawn_latent_conditions",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="latentcondition",
            name="withdrawn_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="latentcondition",
            name="withdrawn_note",
            field=models.TextField(blank=True, db_default="", default=""),
        ),
        # Unique among the LIVE declarations only. Unconditional, a withdrawn watch
        # kept as a record meant the same watch could never be declared again on
        # that claim: an IntegrityError, which the route answered with a 500.
        migrations.RemoveConstraint(
            model_name="latentcondition",
            name="uq_latent_condition_declaration",
        ),
        migrations.AddConstraint(
            model_name="latentcondition",
            constraint=models.UniqueConstraint(
                condition=models.Q(state__in=["pending", "fired", "unobservable", "evaluation_failed"]),
                fields=("claim", "kind", "subject", "expected"),
                name="uq_latent_condition_declaration",
            ),
        ),
        # Irreversible. Moving a watch back onto a closed version would recreate the
        # defect this repairs; and the reverse of the constraint above makes the
        # declaration unique on every row again, which a watch withdrawn and declared
        # again violates -- a reverse that claimed to be a no-op failed part-way on it.
        migrations.RunPython(carry_watches_forward),
    ]
