"""Recompute every believed-now claim's confidence from its status and evidence class.

Roadmap P2.7. A claim's confidence is mythos-core's strength for its evidence class
while its status stands on supporting evidence (SUPPORTED, PARTIALLY_VERIFIED,
VERIFIED), and None under every other status (``assurance.claim_confidence``).
Before, a claim carried the DERIVER's confidence for the deriver's status, and a
writer that set another status left it there:

- a person's SUPPORTED, PARTIALLY_VERIFIED or VERIFIED over a deriver's UNKNOWN or
  CONTRADICTED read None;
- a person's UNKNOWN over a deriver's pass kept the deriver's number;
- a STALE mark -- evidence expired, an input drifted, a declared condition fired --
  kept the number the claim carried before it;
- a withdrawal made before a stop carried none kept its number.

This writes, on every row still believed (``valid_to`` null: the current version of
each claim, and any retroactive one), the confidence its status and class give --
and, on a row an evidence audit holds, the confidence the reading under the hold
carries (``base_confidence``), which is what a release lands on. The table's numbers
are the ones the old formula gave each class, so a row whose status stands on
supporting evidence and already carried a number keeps it.

A superseded version (``valid_to`` set) is closed history, and keeps what it carried
when it was closed: history is append-only.

Reversible in the only honest way available: going back does nothing. What this
replaces is a number for a status the claim no longer had, or none for a status that
carries one; writing either again would re-create the defect.
"""

from django.db import migrations
from mythos_core.evidence import strength_from_evidence_class

#: The statuses that stand on supporting evidence, as of this migration.
_SUPPORTING = frozenset({"supported", "partially_verified", "verified"})


def _confidence(status, evidence_class):
    if status not in _SUPPORTING:
        return None
    return strength_from_evidence_class(evidence_class)


def _held(audit, status):
    """Whether the row stands where its evidence audit holds it (as
    ``evidence_audit._held_by_audit`` reads it)."""
    return bool(audit.get("held") and status == audit.get("status") and audit.get("base_status"))


def _recompute_the_confidence_of_every_believed_claim(apps, schema_editor):
    AssuranceClaim = apps.get_model("assurance", "AssuranceClaim")
    fixed = 0
    for claim in AssuranceClaim.objects.filter(valid_to__isnull=True).iterator():
        fields = []
        confidence = _confidence(claim.status, claim.evidence_class)
        if claim.confidence != confidence:
            claim.confidence = confidence
            fields.append("confidence")
        audit = claim.evidence_audit if isinstance(claim.evidence_audit, dict) else {}
        if _held(audit, claim.status):
            base = _confidence(audit["base_status"], claim.evidence_class)
            if audit.get("base_confidence") != base:
                claim.evidence_audit = {**audit, "base_confidence": base}
                fields.append("evidence_audit")
        if fields:
            claim.save(update_fields=fields)
            fixed += 1
    if fixed:
        print(f"  recomputed the confidence of {fixed} claim(s) from the status each one reads")


def _do_not_put_it_back(apps, schema_editor):
    """Deliberately a no-op. See this migration's docstring."""


class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0047_claim_event_person_snapshot"),
    ]

    operations = [
        migrations.RunPython(_recompute_the_confidence_of_every_believed_claim, _do_not_put_it_back),
    ]
