"""Fetch one live feed source into the snapshot store, from the operator's shell
(MVP step 10; ``docs/economics/spec-v1.md``, section 29):

    manage.py fetch_financial_source <source> [--as-of YYYY-MM-DD]

``<source>`` is a key of the feed registry (``--list`` prints them). The fetch is
:func:`assurance.economics.feeds.fetch`: it sends nothing and writes nothing unless
the source is in the registry, its provider's key is set where it needs one
(``source_key_missing``), live fetching is switched on (``live_feeds_disabled``) and
the date is one the provider can be asked for; then one request through the
platform's outbound client, the answer parsed all or nothing, and a new platform-wide
version at trust tier ``unverified`` recorded -- or none, where the payload was
recorded already -- with the fetch's own record.

It prints the source's key, what came of the fetch, the version and the payload hash;
a refusal is a CommandError naming its code. It never prints, logs or records a key,
nor the answer's text. It is on no stop path, reads nothing a stop reads, and no
first-party module imports it.

MVP step 11 (spec, section 30): it fetches step 11's sources the same way -- the AWS,
Azure and GCP price catalogs, a company's SEC EDGAR filing watch, facts and segment
revenue (``sec-edgar-<submissions|companyfacts|segments>-cik<CIK>``), and the
regulators' enforcement listings -- each as known today only, every page of a
paginated catalog read before anything is written.
"""

from __future__ import annotations

from datetime import date

from django.core.management.base import BaseCommand, CommandError

from assurance.economics import feeds
from assurance.economics.engine import catalogs
from assurance.economics.engine import feeds as engine


def _as_of(value: str | None) -> date | None:
    if value is None:
        return None
    try:
        if len(value) != 10:
            raise ValueError
        return date.fromisoformat(value)
    except ValueError:
        raise CommandError(f"refused, nothing was sent or written: --as-of {value!r} is not YYYY-MM-DD") from None


class Command(BaseCommand):
    help = (
        "Fetch one live feed source (ECB SDMX, Fed H.10, FRED/ALFRED, BLS) or catalog (AWS, Azure and GCP prices, SEC "
        "EDGAR, regulators' enforcement listings) into the financial snapshot store."
    )

    def add_arguments(self, parser):
        parser.add_argument("source", nargs="?", help="a key of the feed registry")
        parser.add_argument(
            "--as-of",
            dest="as_of",
            help=(
                "the date the values are as known on (YYYY-MM-DD; default today, UTC). FRED reads that date's "
                "vintage; ECB and H.10 the rates through it; BLS and every step-11 catalog serve current values "
                "only, so only today, in UTC or in Washington"
            ),
        )
        parser.add_argument("--list", action="store_true", help="print the feed registry's keys and stop")

    def handle(self, *args, **options):
        if options["list"]:
            for key, feed in sorted(engine.REGISTRY.items()):
                needs = f"needs {feed.key_setting}" if feed.key_setting else "needs no key"
                self.stdout.write(f"{key}: {feed.provider}, {feed.kind}, {feed.cadence}, SLA {feed.sla_days} days, {needs}")
            for key, feed in sorted(catalogs.CATALOG_REGISTRY.items()):
                needs = f"needs {feed.key_setting}" if feed.key_setting else "needs no key"
                self.stdout.write(
                    f"{key}: {feed.provider}, {feed.kind}, {feed.use} only, {feed.cadence}, SLA {feed.sla_days} days "
                    f"({feed.freshness}), {needs}"
                )
            for family in catalogs.EDGAR_FAMILIES:
                feed = catalogs.edgar_source(family, "0" * 10)
                self.stdout.write(
                    f"sec-edgar-{family}-cik<10-digit CIK>: {feed.provider}, {feed.kind}, {feed.use} only, "
                    f"{feed.cadence}, SLA {feed.sla_days} day ({feed.freshness}), needs {feed.key_setting}"
                )
            return
        if not options["source"]:
            raise CommandError("refused, nothing was sent or written: name a source (--list prints them)")
        outcome = feeds.fetch(options["source"], as_of=_as_of(options["as_of"]))
        if outcome.code is not None:
            recorded = "the fetch was recorded as refused" if outcome.row is not None else "nothing was written"
            raise CommandError(f"{outcome.code}: {outcome.meaning} ({outcome.source_key}; {recorded})")
        version = outcome.version
        self.stdout.write(
            f"{outcome.source_key}: {outcome.outcome}, version {version.version} ({version.trust_tier}), payload "
            f"{outcome.payload_hash}, {outcome.observations} observation(s)"
        )
