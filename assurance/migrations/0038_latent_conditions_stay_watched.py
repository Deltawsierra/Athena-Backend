import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models
from django.utils import timezone

#: ``LatentCondition.State`` values when this migration was written. Spelled here,
#: not imported: a migration records what it did.
LIVE = ("pending", "fired", "unobservable", "evaluation_failed")
WITHDRAWN = "withdrawn"


def _current_version(AssuranceClaim, claim):
    """The current version of ``claim``'s chain (``superseded_by`` to the end), or
    None if the chain ends on a closed version or loops. As 0037 reads it."""
    seen = set()
    while claim.superseded_by_id is not None and claim.pk not in seen:
        seen.add(claim.pk)
        claim = AssuranceClaim.objects.filter(pk=claim.superseded_by_id).first()
        if claim is None:
            return None
    return claim if claim.valid_to is None else None


def carry_fired_forward(apps, schema_editor):
    """A FIRED condition left on a version a re-derive closed, brought to the current
    version of the same claim.

    A fired condition now holds its claim at STALE, with its retest open, until a
    re-evaluation finds the subject back at its baseline or a person withdraws it;
    it follows the claim to each new version as a watched one does. Until now a
    re-derive left it on the version it closed -- and refreshed the claim back to a
    pass, and resolved its retest, while the precondition was still true. Carried
    here, the next evaluation reads it again: it re-arms if the subject is back at
    its baseline, and otherwise holds the claim and re-opens the retest.

    Where the current version already carries a live declaration of the same watch
    -- an operator re-declared it there -- that one stands and this row is withdrawn
    with a note saying so: a re-declaration took a new baseline, which is a person
    accepting the state this one fired on.
    """
    AssuranceClaim = apps.get_model("assurance", "AssuranceClaim")
    LatentCondition = apps.get_model("assurance", "LatentCondition")

    now = timezone.now()
    orphaned = list(
        LatentCondition.objects.filter(state__in=LIVE, claim__valid_to__isnull=False)
        .select_related("claim")
        .order_by("-declared_at", "-pk")
    )
    for condition in orphaned:
        current = _current_version(AssuranceClaim, condition.claim)
        if current is None or current.pk == condition.claim_id:
            continue
        already = (
            LatentCondition.objects.filter(
                claim_id=current.pk,
                kind=condition.kind,
                subject=condition.subject,
                expected=condition.expected,
                state__in=LIVE,
            )
            .exclude(pk=condition.pk)
            .first()
        )
        if already is not None:
            condition.state = WITHDRAWN
            condition.withdrawn_at = now
            condition.withdrawn_note = (
                f"Merged into the same declaration on the claim's current version "
                f"({already.uuid}, {already.state}) when migration 0038 carried forward "
                "the conditions a re-derive had left behind; withdrawn here so one watch "
                "is not counted as two."
            )
            condition.save(update_fields=["state", "withdrawn_at", "withdrawn_note"])
            continue
        condition.claim = current
        condition.save(update_fields=["claim"])


class Migration(migrations.Migration):
    """A latent condition stays watched: an unobservable one is read again, a fired
    one holds its claim across re-derives, a failed evaluation is recorded on the
    condition, and the same watch can be declared again once the first is withdrawn."""

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
            field=models.CharField(blank=True, max_length=200),
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
            field=models.TextField(blank=True),
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
        # Not reversed: moving a fired condition back onto a closed version would
        # recreate the defect this repairs.
        migrations.RunPython(carry_fired_forward, migrations.RunPython.noop),
    ]
