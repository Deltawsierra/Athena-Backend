"""The claim's stored evidence audit becomes a bounded summary, with the whole
per-item weighing kept in its own table (#333 round 3).

``evidence_audit`` listed every item recorded against the claim, every claim read
served it whole, and a stop rewrote it. Forward, each stored audit's per-item
lists move to a ``ClaimAuditWeighing`` row and the summary keeps the first
entries of each with their counts, as ``assurance.evidence_audit.audit_summary``
writes it. Backward, the whole lists are put back on ``evidence_audit`` before
the table is dropped: nothing is lost either way.
"""

import django.db.models.deletion
from django.db import migrations, models

_LISTS = ("admitted", "refused", "contradictions", "supersessions", "residual_uncertainty")
_LIMIT = 20  # assurance.evidence_audit.AUDIT_LIST_LIMIT, frozen here as this step wrote it


def _split(apps, schema_editor):
    AssuranceClaim = apps.get_model("assurance", "AssuranceClaim")
    ClaimAuditWeighing = apps.get_model("assurance", "ClaimAuditWeighing")
    for claim in AssuranceClaim.objects.only("pk", "evidence_audit").iterator():
        audit = dict(claim.evidence_audit or {})
        if not audit or "counts" in audit:
            continue
        items = {key: list(audit.get(key) or []) for key in _LISTS}
        counts = {key: len(value) for key, value in items.items()}
        for key in _LISTS:
            audit[key] = items[key][:_LIMIT]
        audit["counts"] = counts
        audit["lists_truncated"] = any(n > _LIMIT for n in counts.values())
        claim.evidence_audit = audit
        claim.save(update_fields=["evidence_audit"])
        ClaimAuditWeighing.objects.update_or_create(claim_id=claim.pk, defaults={"items": items})


def _merge(apps, schema_editor):
    AssuranceClaim = apps.get_model("assurance", "AssuranceClaim")
    ClaimAuditWeighing = apps.get_model("assurance", "ClaimAuditWeighing")
    weighings = dict(ClaimAuditWeighing.objects.values_list("claim_id", "items"))
    for claim in AssuranceClaim.objects.only("pk", "evidence_audit").iterator():
        audit = dict(claim.evidence_audit or {})
        if not audit:
            continue
        items = weighings.get(claim.pk) or {}
        for key in _LISTS:
            if key in items:
                audit[key] = list(items[key])
        audit.pop("counts", None)
        audit.pop("lists_truncated", None)
        claim.evidence_audit = audit
        claim.save(update_fields=["evidence_audit"])


class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0045_claim_evidence_invalidated_by_username"),
    ]

    operations = [
        migrations.CreateModel(
            name="ClaimAuditWeighing",
            fields=[
                (
                    "claim",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        primary_key=True,
                        related_name="audit_weighing",
                        serialize=False,
                        to="assurance.assuranceclaim",
                    ),
                ),
                ("items", models.JSONField(blank=True, default=dict)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.RunPython(_split, _merge),
    ]
