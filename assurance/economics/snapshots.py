"""Registering a committed observation snapshot, and reading it back as books.

The MVP's only writer of FX and cost-index observations (``docs/economics/spec-v1.md``,
section 6): an operator registers a committed snapshot file, and
:func:`register_snapshot` writes, in one transaction, the
:class:`~assurance.economics.models.FinancialSource` version the file says it is
(its snapshot hash the SHA-256 of the file's bytes) and every observation in it,
each through its model's checks. A file already registered under that hash is
not written again. Nothing fetches a feed.

:data:`SYNTHETIC_SNAPSHOT` is the snapshot committed for tests: SYNTHETIC TEST
DATA, not real rates or indices, registered with licence class ``open`` and trust
tier ``unverified``.

Nothing calls this module but the tests and an operator: no route, command or
signal imports it, and it is on no stop path.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import date
from pathlib import Path

from django.db import transaction

from .engine import money
from .engine import snapshot as _snapshot
from .engine.cost_index import IndexBook
from .engine.fx import FXBook
from .models import CostIndexObservation, EconomicsRefused, FinancialSource, FXObservation

#: The committed synthetic snapshot. Its hash is pinned by the tests and the spec.
SYNTHETIC_SNAPSHOT = Path(__file__).resolve().parent / "snapshots" / "synthetic-fx-and-cost-index-v1.json"


def read_snapshot(path: Path = SYNTHETIC_SNAPSHOT) -> _snapshot.Snapshot:
    """The snapshot at ``path``, checked; the engine's refusal as an
    :class:`~assurance.economics.models.EconomicsRefused`."""
    try:
        return _snapshot.parse_snapshot(Path(path).read_bytes())
    except money.MoneyRefused as refused:
        raise EconomicsRefused(refused.code, refused.detail) from None


def register_snapshot(path: Path = SYNTHETIC_SNAPSHOT, *, deployment=None, recorded_by=None) -> FinancialSource:
    """Register the snapshot at ``path`` as a source version of ``deployment``
    (``None``: platform-wide), with every observation it holds. Returns the source
    version; one already registered with the file's hash is returned as it is."""
    snapshot = read_snapshot(path)
    source = snapshot.source
    with transaction.atomic():
        existing = (
            FinancialSource._base_manager.filter(
                deployment=deployment, source_key=source["source_key"], snapshot_hash=snapshot.snapshot_hash
            )
            .order_by("version")
            .first()
        )
        if existing is not None:
            return existing
        registered = FinancialSource.objects.create(
            deployment=deployment,
            source_key=source["source_key"],
            provider=source["provider"],
            dataset=source["dataset"],
            url=source["url"],
            license_class=source["license_class"],
            trust_tier=source["trust_tier"],
            retrieved_at=source["retrieved_at"],
            snapshot_hash=snapshot.snapshot_hash,
            schema_version=source["schema_version"],
            synthetic=snapshot.synthetic,
            recorded_by=recorded_by,
        )
        for rate in snapshot.fx_rates:
            FXObservation.objects.create(
                source=registered,
                base_currency=rate.base,
                quote_currency=rate.quote,
                rate=rate.rate,
                rate_type=rate.rate_type,
                provider=rate.provider,
                observed_at=rate.observed_at,
                effective_date=rate.effective_date,
                source_snapshot_hash=rate.source_snapshot_hash,
            )
        for point in snapshot.index_points:
            CostIndexObservation.objects.create(
                source=registered,
                series_id=point.series_id,
                geography=point.geography,
                category=point.category,
                base=point.base,
                period=point.period,
                value=point.value,
                vintage_date=point.vintage_date,
            )
    return registered


def fx_book(sources: Iterable[FinancialSource], holidays: Mapping[str, Iterable[date]] | None = None) -> FXBook:
    """The stored FX observations of ``sources`` as the engine reads them.

    No model stores a provider's holidays yet: pass them (a snapshot's
    ``holidays``). Without them, a holiday is a day the provider publishes on, so a
    rate missing on it is unavailable -- never filled in."""
    rows = FXObservation.objects.filter(source__in=list(sources)).select_related("source")
    return FXBook((row.as_engine() for row in rows), holidays)


def index_book(sources: Iterable[FinancialSource]) -> IndexBook:
    """The stored cost-index observations of ``sources`` as the engine reads them."""
    rows = CostIndexObservation.objects.filter(source__in=list(sources)).select_related("source")
    return IndexBook(row.as_engine() for row in rows)
