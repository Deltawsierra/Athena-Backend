"""Registering a committed observation snapshot, and reading it back as books.

The MVP's only writer of FX and cost-index observations (``docs/economics/spec-v1.md``,
section 6): an operator registers a committed snapshot file, and
:func:`register_snapshot` writes, in one transaction, the
:class:`~assurance.economics.models.FinancialSource` version the file says it is
(its snapshot hash the SHA-256 of the file's bytes) and every observation in it,
each through its model's checks. A file already registered under that hash is
not written again. A live feed's answer is registered the same way
(:func:`register`), deduplicated on its normalised payload hash.

:data:`SYNTHETIC_SNAPSHOT` is the snapshot committed for tests: SYNTHETIC TEST
DATA, not real rates or indices, registered with licence class ``open`` and trust
tier ``unverified``.

A snapshot never states ``authoritative``: that tier is recorded only by a raise
one admin requested and another approved (``second_person_required``; spec, section
6.1). A file stating it is refused before anything is written.

A source version's observations are read from the version the loader registered
under the same tenant, key and snapshot hash (:func:`fx_book`, :func:`index_book`):
a raised version copies the hash and holds no rows of its own, and nothing copies
them, which would hold the database's write lock for as long as the copy took and
delay every stop's write behind it.

The loader records, with the version, a digest of the FX and of the cost-index
observations it writes (:func:`observations_digests`, computed before the
transaction), and every book read checks the rows it read against them
(``source_observations_changed``; spec, section 36.2): a rate changed past the model
after it was registered is never used, so never pinned by a normalization record. A
version written before the digests is read as it was. Beside them, and checked first,
each row records its own digest and the version a digest over those
(``snapshot_rows_mismatch``: :func:`_check_rows`; section 35, T2c): the two never
replace each other, and a row has to pass both to be read.

Nothing calls this module but the tests, an operator, and (MVP step 10) the feed
fetch an operator runs (:mod:`assurance.economics.feeds`, ``manage.py
fetch_financial_source``), which registers a feed's parsed answer through
:func:`register`: no route or signal imports it, and it is on no stop path.

MVP step 11 (spec, section 31): a catalog's answer -- cloud prices, a company's
facts or filing watch, enforcement records -- is registered the same way, its
records as ONE :class:`~assurance.economics.models.FinancialSourceRecords` row of the
new version, checked whole before the transaction opens; :func:`records_of` reads
them back (a raised version reads its holder's). The step-11 context and prefill
readers read records through :func:`records_of` only (the precedent route, the
suggestion route, and the EDGAR segment fetch, which reads a stored filing watch).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable, Mapping
from datetime import UTC, date
from pathlib import Path

from django.db import transaction
from django.db.models import Q

from .engine import governance, money
from .engine import snapshot as _snapshot
from .engine.cost_index import IndexBook
from .engine.fx import FXBook
from .models import (
    CostIndexObservation,
    EconomicsRefused,
    FinancialSource,
    FinancialSourceRecords,
    FXObservation,
    canonical_digest,
    observation_rows_digest,
    observation_rows_refusal,
)

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
    version; one already registered with the file's hash is returned as it is.

    A file is not signed, so it earns no trust by saying so (section 28 hardening,
    T2a; spec, section 35): a file that is not synthetic is registered at the
    licence class the reviewed feed registry gives its source key (step 10's and
    step 11's registries, :func:`registered_terms`; ``unreviewed`` for a key they do
    not hold) and at trust tier ``unverified``, whatever it states, as a live feed's
    fetched versions are. Licence and trust then come only from the registry and
    from an admin's raise. A synthetic file is made-up data that no production run
    ever uses (``synthetic_source``), and keeps the licence it states."""
    version, _created = register(registered_terms(read_snapshot(path)), deployment=deployment, recorded_by=recorded_by)
    return version


def registered_terms(snapshot: _snapshot.Snapshot) -> _snapshot.Snapshot:
    """``snapshot`` as the file loader registers it (spec, section 35): a file
    stating ``authoritative`` is still refused at registration
    (``second_person_required``); any other non-synthetic file takes the licence
    class of its source key's line in the feed registry (``unreviewed`` for a key
    the registry does not hold) and trust tier ``unverified``, whatever the file
    says. A synthetic snapshot is returned as it is."""
    stated = snapshot.source
    if snapshot.synthetic or governance.needs_second_person(stated["trust_tier"]):
        return snapshot
    from .engine import catalogs
    from .engine import feeds as feed_rules
    from .engine.provenance import LicenseClass, TrustTier

    key = stated["source_key"]
    line = feed_rules.REGISTRY.get(key) or catalogs.known(key)
    licence = line.license_class if line is not None else LicenseClass.UNREVIEWED.value
    return dataclasses.replace(
        snapshot, source={**stated, "license_class": licence, "trust_tier": TrustTier.UNVERIFIED.value}
    )


def register(
    snapshot: _snapshot.Snapshot, *, deployment=None, recorded_by=None, records=None
) -> tuple[FinancialSource, bool]:
    """Register ``snapshot`` -- a committed file's, or a live feed's answer parsed by
    its adapter (:mod:`assurance.economics.engine.feeds`, whose snapshot hash is the
    answer's normalised payload hash) -- as a source version of ``deployment``
    (``None``: platform-wide), with every observation it holds, in one transaction.
    Returns ``(version, created)``: a snapshot already registered under its hash, for
    the same tenant and key, is the version that holds it, and nothing is written.
    A snapshot stating ``authoritative`` is refused before anything is written.
    ``records``: the snapshot's records row as :func:`records_row` prepared it, where
    the caller holds a transaction of its own (the fetch: review round 1, LOW-3)."""
    source = snapshot.source
    if governance.needs_second_person(source["trust_tier"]):
        raise EconomicsRefused(
            "second_person_required",
            f"the snapshot states trust tier {source['trust_tier']}: register it at a lower tier and raise it "
            "with POST /api/assurance/economics/sources/<uuid>/trust-raises/, which a second admin approves",
        )
    # A catalog's records (step 11) are one row, checked whole before ANY
    # transaction (the caller's, when it passes the row): inside it, two inserts and
    # no loop over the records, no serialising and no digest.
    held = records if records is not None else records_row(snapshot)
    # The observations' digests, before the transaction: inside it, inserts only. Two
    # kinds, each with its own job: the FX and the cost-index observations as the
    # engine reads them (section 36.2, checked by every book read), and below, every
    # row's own digest and the version's over them (section 35, T2c).
    fx_digest, index_digest = observations_digests(snapshot.fx_rates, snapshot.index_points)
    # Every observation row, and the digest the version records over them (spec,
    # section 35), made and checked before the transaction, which then only reads
    # whether the snapshot is held already and inserts.
    fx_rows = [
        FXObservation(
            base_currency=rate.base,
            quote_currency=rate.quote,
            rate=rate.rate,
            rate_type=rate.rate_type,
            provider=rate.provider,
            observed_at=rate.observed_at,
            effective_date=rate.effective_date,
            source_snapshot_hash=rate.source_snapshot_hash,
        )
        for rate in snapshot.fx_rates
    ]
    index_rows = [
        CostIndexObservation(
            series_id=point.series_id,
            geography=point.geography,
            category=point.category,
            base=point.base,
            period=point.period,
            value=point.value,
            vintage_date=point.vintage_date,
        )
        for point in snapshot.index_points
    ]
    rows_digest = observation_rows_digest(row.computed_digest() for row in (*fx_rows, *index_rows))
    with transaction.atomic():
        existing = (
            FinancialSource._base_manager.filter(
                deployment=deployment, source_key=source["source_key"], snapshot_hash=snapshot.snapshot_hash
            )
            .order_by("version")
            .first()
        )
        if existing is not None:
            return existing, False
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
            fx_observations_digest=fx_digest,
            index_observations_digest=index_digest,
            schema_version=source["schema_version"],
            synthetic=snapshot.synthetic,
            observations_digest=rows_digest,
            recorded_by=recorded_by,
        )
        for row in (*fx_rows, *index_rows):
            row.source = registered
            row.save()
        if held is not None:
            held.source = registered
            held.save()
    return registered, True


def _fx_spelling(rate) -> list[str]:
    """One FX observation in its one spelling, the same whether it is the snapshot's
    (read from the file) or the row's (read from the column): its stored fields, the
    rate as :func:`money.decimal_text` writes it, the instant in UTC."""
    return [
        rate.base,
        rate.quote,
        money.decimal_text(rate.rate),
        rate.rate_type,
        rate.provider,
        rate.observed_at.astimezone(UTC).isoformat(),
        rate.effective_date.isoformat(),
        rate.source_snapshot_hash,
    ]


def _index_spelling(point) -> list[str]:
    """One cost-index observation in its one spelling (:func:`_fx_spelling`)."""
    return [
        point.series_id,
        point.geography,
        point.category,
        point.base,
        point.period,
        money.decimal_text(point.value),
        point.vintage_date.isoformat(),
    ]


def observations_digests(fx_rates: Iterable, index_points: Iterable) -> tuple[str, str]:
    """``(fx, index)``: the digest of a version's FX observations and of its
    cost-index observations, each over every one in its one spelling, in order --
    the engine's (a snapshot's) or the rows' read back (:meth:`FXObservation.as_engine`),
    which give the same digest exactly when they hold the same observations."""
    return (
        canonical_digest(sorted(_fx_spelling(rate) for rate in fx_rates)),
        canonical_digest(sorted(_index_spelling(point) for point in index_points)),
    )


def _check_observations(read_as: Mapping[int, FinancialSource], held: Iterable[tuple[int, object]], kind: str) -> None:
    """Refuse (``source_observations_changed``) unless the observations read of each
    holder ``read_as`` names -- ``held``, ``(holder id, engine observation)`` -- give
    the digest the loader recorded with it (``kind``: ``fx`` or ``index``). One read
    of the holders' digests; a holder with none (written before them) is read as it
    was. Every holder is checked, one whose rows were all removed among them."""
    field, spelling = (
        ("fx_observations_digest", _fx_spelling) if kind == "fx" else ("index_observations_digest", _index_spelling)
    )
    recorded = dict(FinancialSource._base_manager.filter(pk__in=list(read_as)).values_list("pk", field))
    rows: dict[int, list] = {pk: [] for pk in read_as}
    for holder, observation in held:
        rows[holder].append(spelling(observation))
    for holder, digest in sorted(recorded.items()):
        if digest and canonical_digest(sorted(rows[holder])) != digest:
            named = read_as[holder]
            raise EconomicsRefused(
                "source_observations_changed",
                f"the {'FX' if kind == 'fx' else 'cost-index'} observations of {named.source_key} version "
                f"{named.version} are not the ones it was registered with; none of them is used",
            )


def records_row(snapshot: _snapshot.Snapshot) -> FinancialSourceRecords | None:
    """The unsaved records row of ``snapshot``'s records, checked whole
    (:meth:`FinancialSourceRecords.prepare`): never inside a transaction. ``None``
    for a snapshot that holds no records."""
    from .engine import catalogs

    if not getattr(snapshot, "records", ()):
        return None
    entries = catalogs.records_json(snapshot.records)
    row = FinancialSourceRecords(
        kind=snapshot.record_kind,
        schema_version=catalogs.RECORDS_SCHEMA,
        records=entries,
        record_count=len(entries),
        records_digest=catalogs.records_digest(entries),
    )
    row.prepare()
    return row


def records_of(version: FinancialSource) -> tuple:
    """The records ``version`` holds, as the engine reads them: those of the version
    of the same tenant, key and snapshot hash that the fetch registered (a raised
    version holds none of its own). ``()`` for a version that holds none. One read."""
    holder = (
        FinancialSource._base_manager.filter(
            deployment_id=version.deployment_id, source_key=version.source_key, snapshot_hash=version.snapshot_hash
        )
        .order_by("version")
        .values_list("pk", flat=True)
        .first()
    )
    row = FinancialSourceRecords._base_manager.filter(source_id=holder).first()
    return () if row is None else row.as_engine()


def _tenant_sources(sources: Iterable[FinancialSource], deployment) -> list[int]:
    """The ids of ``sources``, each of them platform-wide or ``deployment``'s own
    (``None``: a run for no deployment, platform-wide sources only), read from the
    STORED rows, never from the objects passed. Any other is refused
    (``cross_tenant_reference``): one tenant's observations never reach another's
    run."""
    ids = [getattr(source, "pk", source) for source in sources]
    if any(pk is None for pk in ids):
        raise EconomicsRefused("cross_tenant_reference", "a source that is not stored")
    tenant = getattr(deployment, "pk", deployment)
    stored = dict(FinancialSource._base_manager.filter(pk__in=ids).values_list("pk", "deployment_id"))
    for pk in ids:
        if pk not in stored:
            raise EconomicsRefused("cross_tenant_reference", f"source {pk} is not stored")
        if stored[pk] is not None and stored[pk] != tenant:
            raise EconomicsRefused("cross_tenant_reference", f"source {pk} belongs to another deployment")
    return ids


def _observation_holders(ids: list[int]) -> dict[int, FinancialSource]:
    """For the source versions ``ids``: ``{the version holding the observations: the
    version to name}``. A version's observations are the rows of the EARLIEST version
    of the same tenant, key and snapshot hash -- the one the loader registered, since
    a raise copies the hash and holds no rows of its own. Two versions handed in that
    share a holder are read once, named by the later of them. One read, no write."""
    asked = list(FinancialSource._base_manager.filter(pk__in=ids).order_by("version"))
    if not asked:
        return {}
    shared = Q()
    for version in asked:
        shared |= Q(
            deployment_id=version.deployment_id, source_key=version.source_key, snapshot_hash=version.snapshot_hash
        )
    holders: dict[tuple, int] = {}
    for row in (
        FinancialSource._base_manager.filter(shared)
        .order_by("version")
        .values("pk", "deployment_id", "source_key", "snapshot_hash")
    ):
        holders.setdefault((row["deployment_id"], row["source_key"], row["snapshot_hash"]), row["pk"])
    return {holders[(v.deployment_id, v.source_key, v.snapshot_hash)]: v for v in asked}


def fx_book(
    sources: Iterable[FinancialSource], *, deployment, holidays: Mapping[str, Iterable[date]] | None = None
) -> FXBook:
    """The stored FX observations of ``sources`` as the engine reads them, for a
    run of ``deployment``: every source platform-wide or that deployment's own.

    No model stores a provider's holidays yet: pass them (a snapshot's
    ``holidays``). Without them, a holiday is a day the provider publishes on, so a
    rate missing on it is unavailable -- never filled in.

    A raised version's rows are the ones the loader registered under its snapshot
    hash (:func:`_observation_holders`), and each rate names the version handed in
    as ``source_version`` and the version holding the row as
    ``observations_version``.

    Two checks, each with its own job: before any row is read, every stored row gives
    its own digest and the version's rows the digest recorded over them
    (``snapshot_rows_mismatch``: :func:`_check_rows`; section 35, T2c); and the
    observations read, as the engine reads them, give the digest the loader recorded
    with them (``source_observations_changed``: :func:`_check_observations`; section
    36.2)."""
    ids = _tenant_sources(sources, deployment)
    _check_rows(ids)
    read_as = _observation_holders(ids)
    rows = FXObservation.objects.filter(source_id__in=read_as).select_related("source")
    held = [(row.source_id, row.as_engine(read_as[row.source_id])) for row in rows]
    _check_observations(read_as, held, "fx")
    return FXBook((rate for _, rate in held), holidays)


def index_book(sources: Iterable[FinancialSource], *, deployment) -> IndexBook:
    """The stored cost-index observations of ``sources`` as the engine reads them,
    for a run of ``deployment``: every source platform-wide or that deployment's own,
    a raised version's read, and every row checked by both checks, as :func:`fx_book`
    reads them."""
    ids = _tenant_sources(sources, deployment)
    _check_rows(ids)
    read_as = _observation_holders(ids)
    rows = CostIndexObservation.objects.filter(source_id__in=read_as).select_related("source")
    held = [(row.source_id, row.as_engine(read_as[row.source_id])) for row in rows]
    _check_observations(read_as, held, "index")
    return IndexBook(point for _, point in held)


def _check_rows(ids: list[int]) -> None:
    """Refuse (``snapshot_rows_mismatch``) a book over a source version whose stored
    observation rows no longer give the digests recorded when it was registered
    (spec, section 35): a rewritten row is never read as a rate or an index value."""
    refused = observation_rows_refusal(ids)
    if refused is not None:
        raise EconomicsRefused(*refused)
