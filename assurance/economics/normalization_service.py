"""Normalizing an amount for a deployment, from the sources a run of it may use (MVP
step 12; ``docs/economics/spec-v1.md``, section 12.8).

:func:`normalize_for` builds the books a normalization reads from the USABLE source
versions on its valuation date (:func:`usable_versions`): for each source key, the
version a run of the deployment uses on that date (:func:`.feeds.used_version`: the
newest that passes the production gate for the deployment, is superseded by no raise
of the same payload, and covers the date), platform-wide and the deployment's own. A
version the gate refuses, or one that does not cover the date, is not in the books,
so its provider has no rate a normalization may use: the policy's first provider is
then unavailable, and a later one's rate carries ``primary_unavailable``. Every other
usable source is compared with the rate or value used (``source_disagreement``,
``conflicts``). Another deployment's versions are never read.

Runs do not normalize their figures yet (section 24.9): a run's figures are stated in
one reporting currency. When they do, the card inherits the record's downgrades and
conflicts. Reads only; nothing here is on a stop path.
"""

from __future__ import annotations

from datetime import date

from . import feeds, snapshots
from .engine import normalization
from .engine.money import Money
from .models import FinancialSource


def usable_versions(deployment, as_of: date) -> list[FinancialSource]:
    """For each source key, platform-wide and ``deployment``'s own, the version a run
    of ``deployment`` dated ``as_of`` uses (:func:`.feeds.used_version`), in key order;
    a key with none is left out. Deterministic for the stored rows and the date."""
    platform = sorted(
        set(FinancialSource.objects.filter(deployment__isnull=True).values_list("source_key", flat=True))
    )
    own = (
        sorted(set(FinancialSource.objects.filter(deployment=deployment).values_list("source_key", flat=True)))
        if deployment is not None
        else []
    )
    found = [feeds.used_version(key, deployment, as_of) for key in platform]
    found += [feeds.used_version(key, deployment, as_of, own=True) for key in own]
    return [version for version in found if version is not None]


def normalize_for(
    deployment,
    native: Money,
    *,
    event_date: date,
    valuation_date: date,
    policy: normalization.NormalizationPolicy,
    holidays=None,
) -> normalization.Normalization:
    """``native``, recorded on ``event_date``, in the policy's reporting currency at
    ``valuation_date``, for a run of ``deployment``, as of the valuation date: the
    engine's normalization (section 12.4) over the books of :func:`usable_versions`.
    The record (``as_dict``) carries its downgrades, its ``conflicts`` and the steps
    that fell back past the primary (``primary_unavailable``). Raises what the engine
    refuses (``MoneyRefused``); a rate or index value it lacks is ``unavailable``."""
    versions = usable_versions(deployment, valuation_date)
    return normalization.normalize(
        native,
        event_date=event_date,
        valuation_date=valuation_date,
        policy=policy,
        fx_book=snapshots.fx_book(versions, deployment=deployment, holidays=holidays),
        index_book=snapshots.index_book(versions, deployment=deployment),
    )


__all__ = ["normalize_for", "usable_versions"]
