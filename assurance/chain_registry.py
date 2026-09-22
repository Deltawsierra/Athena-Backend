"""The chain birth registry — the engine's memory of itself, held somewhere the
engine cannot reach.

The engine's own chain checks are good and they all read the same SQLite file.
That is the whole problem. Delete the scans, the head and the watermark, restart
the engine, and it re-seeds: a fresh watermark at sequence zero and a genesis
head carrying a **genuine** mac. Every check inside the engine then agrees that
an empty table is an intact chain, because from inside the file there is nothing
left to disagree with. The chain key cannot help; a genesis mac over an empty
chain is exactly what the real key computes.

So the birth has to be remembered by something with different credentials on a
different machine. :func:`register_birth` records it the first time and compares
every time after. A chain reporting a ``birth_id`` different from the one on file
was born twice, and a chain is born once.

Three properties this holds to
------------------------------
**The original is never overwritten.** A re-birth is recorded *beside* the first
birth, never in place of it. Overwriting would destroy the only evidence that
anything happened, which is the edit this exists to survive -- and a registry
that quietly accepted the new value would be a more expensive way of trusting
the engine.

**Never registered is not the same as clean.** A deployment with no row here has
not been vouched for; it has not been *asked*. :func:`registry_posture` reports
those separately from the verified ones and never nets them off, because "no
disagreement on file" over an empty file is the silent zero in registry clothing.

**Detection, not prevention.** Somebody who can delete the engine's database can
also stop the engine reporting, and no row here makes an engine talk. That is why
``last_seen_at`` is kept apart from ``first_registered_at``: a chain that stopped
reporting is a fact a reader can act on, and only a registry that records both
can show it.
"""

from __future__ import annotations

import hashlib

from django.db import transaction
from django.utils import timezone

from . import observability as obs
from .models import ChainBirth, Deployment, Unknown

# The subject slug a re-birth raises its gap under. A label a consumer outside
# this database can name without carrying a hash around.
REBIRTH_SUBJECT = "chain-rebirth"


class ChainBirthRefused(ValueError):
    """A registration was rejected rather than stored in a shape that would lie."""


@transaction.atomic
def register_birth(
    deployment: Deployment,
    *,
    chain: str,
    birth_id: str,
    born_at: str = "",
    seq: int | None = None,
) -> dict:
    """Record an engine's chain birth, or compare it against the one on file.

    Returns ``{"status": ..., "birth": ChainBirth, "matched": bool}`` where
    ``status`` is one of:

    - ``registered`` -- first birth for this chain; nothing to compare against,
      and deliberately NOT called "verified". The first report establishes the
      baseline and proves nothing about what came before it.
    - ``matched`` -- same birth as the one on file.
    - ``rebirth`` -- a different birth arrived. The original is kept, the event
      is recorded on the row, and an Unknown is raised.

    Refuses an empty ``chain`` or ``birth_id``: a registry row that matches
    everything is worse than no row, because it reports "matched" forever.
    """
    chain = (chain or "").strip()
    birth_id = (birth_id or "").strip()
    if not chain:
        raise ChainBirthRefused(
            "a birth must name its chain: an engine keeps several and a re-birth "
            "of one is not a re-birth of all"
        )
    if not birth_id:
        raise ChainBirthRefused(
            "a birth must carry a birth_id. An engine reporting none has no "
            "watermark to report, which is itself the condition this watches for "
            "-- it is not a birth and must not be filed as one"
        )

    now = timezone.now()
    with obs.span(obs.PLAN, component="register_birth", subject=str(deployment.pk)):
        existing = (
            ChainBirth.objects.select_for_update()
            .filter(deployment=deployment, chain=chain)
            .first()
        )
        if existing is None:
            birth = ChainBirth.objects.create(
                deployment=deployment,
                chain=chain,
                birth_id=birth_id,
                born_at=(born_at or "").strip(),
                last_seen_at=now,
                highest_seq=seq,
            )
            return {"status": "registered", "birth": birth, "matched": False}

        if existing.birth_id == birth_id:
            existing.last_seen_at = now
            # Advanced only upward. A chain reporting a lower sequence than we
            # have already seen is a restored older state, which the engine's own
            # watermark catches -- recording it as the new high would erase our
            # ability to notice.
            if seq is not None and (
                existing.highest_seq is None or seq > existing.highest_seq
            ):
                existing.highest_seq = seq
            existing.save(update_fields=["last_seen_at", "highest_seq"])
            return {"status": "matched", "birth": existing, "matched": True}

        # A different birth for a chain we already know. Keep the first.
        existing.rebirth_seen_at = now
        existing.rebirth_birth_id = birth_id
        existing.rebirth_count = (existing.rebirth_count or 0) + 1
        existing.last_seen_at = now
        existing.save(
            update_fields=[
                "rebirth_seen_at",
                "rebirth_birth_id",
                "rebirth_count",
                "last_seen_at",
            ]
        )
        _raise_rebirth_unknown(deployment, existing)
        return {"status": "rebirth", "birth": existing, "matched": False}


def _raise_rebirth_unknown(deployment: Deployment, birth: ChainBirth) -> Unknown:
    """Put the re-birth in front of a person, in the register they already read.

    A gap rather than a finding: a re-born chain is not proof that anything was
    hidden, it is proof that we can no longer say. Which is exactly what an
    Unknown is for, and calling it a confirmed tampering would be the same
    overreach in the other direction.
    """
    from .unknowns import _slug, _upsert

    fingerprint = hashlib.sha256(f"chain-rebirth|{birth.chain}".encode()).hexdigest()
    return _upsert(
        deployment,
        fingerprint,
        {
            "subject": _slug(REBIRTH_SUBJECT),
            "question": (
                f"The engine's {birth.chain!r} chain reports a different birth "
                f"from the one on file. What happened to the original chain, and "
                f"what was "
                f"in it?"
            ),
            "why_it_matters": (
                "A chain is born once. A second birth means the engine's record "
                "was replaced rather than extended, so every check the engine runs "
                "against it now describes a chain that began after whatever it "
                "used to hold. The engine cannot detect this itself: a re-seeded "
                "chain is internally consistent and carries a genuine mac."
            ),
            "evidence_needed": (
                f"The original chain database, or an explanation of why it was "
                f"replaced and by whom. First birth recorded "
                f"{birth.first_registered_at} (born_at "
                f"{birth.born_at or 'unrecorded'}); the birth now reported is "
                f"{birth.rebirth_birth_id}."
            ),
            "deployment_impact": Unknown.Impact.HIGH,
            # Source.CHAIN, not DERIVED. See the model: DERIVED sits in the
            # auto-resolve sweep, which would close this gap on the next ingest.
            "source": Unknown.Source.CHAIN,
        },
        timezone.now(),
    )


def registry_posture(deployment: Deployment) -> dict:
    """What the registry can and cannot vouch for on this deployment.

    Three counts, never one. A chain that has never registered has not been
    vouched for -- it has not been asked -- and netting it against the verified
    ones would let an engine that simply never reported read as clean.
    """
    births = list(ChainBirth.objects.filter(deployment=deployment))
    reborn = [b for b in births if b.rebirth_seen_at is not None]
    return {
        "deployment": str(deployment.uuid),
        "chains_registered": len(births),
        "chains_reborn": len(reborn),
        "reborn": [
            {
                "chain": b.chain,
                "first_registered_at": b.first_registered_at.isoformat(),
                "original_birth_id": b.birth_id,
                "reported_birth_id": b.rebirth_birth_id,
                "rebirth_count": b.rebirth_count,
                "rebirth_seen_at": b.rebirth_seen_at.isoformat(),
            }
            for b in reborn
        ],
        "last_seen": {b.chain: b.last_seen_at.isoformat() for b in births},
        "note": (
            "A registered chain is one whose birth matches the first one we saw. "
            "That is not a statement about the chain's contents, and a chain "
            "absent from this registry has not been checked rather than passed. "
            "This detects a replaced chain; it cannot prevent one, and an engine "
            "that stops reporting stops being checked -- read last_seen."
        ),
    }
