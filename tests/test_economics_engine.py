"""Economic Exposure's pure core, exercised with no database and no Django.

:mod:`assurance.economics.engine` holds the vocabularies every later step reads
(the fifteen loss families, ``source_type``, the confidence grades, the license
classes and trust tiers), the adapter over mythos-core's ISO 4217 currency table,
the governance rules, and (phase E1) money, FX and cost-index normalization,
whose own tests are ``tests/test_economics_money.py``. Pinned here:

- the engine imports with Django poisoned and with every part of mythos-core but
  its currency table poisoned, and no module of it names Django;
- every code is pinned exactly, so a rename or a reuse is a reviewed change here;
- the currency table is core's, the ONE table (Mythos-Core#49): JPY 0, USD 2,
  KWD 3, the retired HRK, GRD and PTE and their successor, as #141 pinned them,
  now against core's table; core's entries digest equals the value pinned here
  and in the adapter, and core's file digest is pinned too, so a core bump that
  changes the table, or what it says about its sources, fails until the pins move;
- each governance rule, and that every refusal anything gives is a published code;
- nothing but :mod:`assurance.models` imports the package, so no economics code
  sits on a stop, pause or revoke path;
- the spec (``docs/economics/spec-v1.md``) states the policy and every code.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from assurance.economics.engine import (
    confidence,
    cost_index,
    currency,
    formulas,
    fx,
    governance,
    loss,
    money,
    normalization,
    parameter_set,
    parameters,
    provenance,
    taxonomy,
)
from assurance.economics.engine.governance import Person

REPO = Path(__file__).resolve().parent.parent
ENGINE = REPO / "assurance" / "economics" / "engine"
SPEC = REPO / "docs" / "economics" / "spec-v1.md"


# ------------------------------------------------------------- free of Django


def test_the_engine_imports_with_django_poisoned():
    """A fresh interpreter in which importing Django, the REST framework, or any
    part of mythos-core but its currency table raises, and no settings module is
    named: every engine module still imports, nothing outside the engine package is
    loaded, and of mythos-core only the package and its currency table are.

    Phase E0 poisoned mythos-core whole; phase E1 reads core's ONE currency table
    (Mythos-Core#49) instead of a copy of its own, so exactly that module is let
    through, and everything else in core stays poisoned. Importing the engine loads
    none of mythos-core; the first use loads the currency module alone."""
    script = textwrap.dedent(
        """
        import importlib, pkgutil, sys

        POISONED = {"django", "rest_framework"}
        CORE_ALLOWED = {"mythos_core", "mythos_core.currency"}

        class Poison:
            def find_spec(self, name, path=None, target=None):
                root = name.split(".")[0]
                if root in POISONED or (root == "mythos_core" and name not in CORE_ALLOWED):
                    raise ImportError("poisoned: " + name)
                return None

        sys.meta_path.insert(0, Poison())
        for name in POISONED:
            sys.modules[name] = None

        import assurance.economics.engine as engine

        names = [engine.__name__] + [engine.__name__ + "." + m.name for m in pkgutil.iter_modules(engine.__path__)]
        for name in names:
            importlib.import_module(name)
        outside = sorted(
            m for m in sys.modules
            if m.startswith("assurance.") and not m.startswith("assurance.economics")
        )
        assert not outside, outside
        # Importing loads no part of mythos-core (review round 1 of #146, H2): core's
        # currency module is imported on the first economics use, and then only it.
        core = sorted(m for m in sys.modules if m.split(".")[0] == "mythos_core")
        assert core == [], core
        from assurance.economics.engine import currency
        assert currency.minor_units("USD") == 2
        core = sorted(m for m in sys.modules if m.split(".")[0] == "mythos_core")
        assert core == sorted(CORE_ALLOWED), core
        print("imported", len(names))
        """
    )
    env = {k: v for k, v in os.environ.items() if k != "DJANGO_SETTINGS_MODULE"}
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=REPO, env=env, capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 0, result.stderr
    # The package and its sixteen modules: E1's ten, the scenario engine's four
    # (parameters, formulas, loss and parameter_set), and the probabilistic
    # engine's two (distributions and simulation, which import numpy as well).
    assert result.stdout.strip() == "imported 17", result.stdout


def _imports(path: Path, package: str):
    """Every module ``path`` imports, as an absolute dotted name (``package`` is the
    package the file sits in), with ``from X import y`` also listed as ``X.y``."""
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")
                base = base[: len(base) - (node.level - 1)]
                module = ".".join(base + ([node.module] if node.module else []))
            else:
                module = node.module or ""
            found.append(module)
            found.extend(f"{module}.{alias.name}" for alias in node.names)
    return found


def test_no_engine_module_names_django_or_the_rest_of_the_app():
    """Read, not run: an import inside a function would pass the poisoned import and
    fail here. Of mythos-core, only the currency adapter imports anything, and only
    the currency table."""
    files = sorted(ENGINE.glob("*.py"))
    assert {f.name for f in files} == {
        "__init__.py",
        "confidence.py",
        "cost_index.py",
        "currency.py",
        "distributions.py",
        "formulas.py",
        "fx.py",
        "governance.py",
        "loss.py",
        "money.py",
        "normalization.py",
        "parameter_set.py",
        "parameters.py",
        "provenance.py",
        "simulation.py",
        "snapshot.py",
        "taxonomy.py",
    }
    core_importers = set()
    for path in files:
        for module in _imports(path, "assurance.economics.engine"):
            root = module.split(".")[0]
            assert root not in {"django", "rest_framework"}, (path.name, module)
            if root == "mythos_core":
                assert module in {"mythos_core", "mythos_core.currency"}, (path.name, module)
                core_importers.add(path.name)
            if root == "assurance":
                assert module.startswith("assurance.economics.engine"), (path.name, module)
    assert core_importers == {"currency.py"}


# ------------------------------------------------------------------ the codes


def test_the_fifteen_loss_families_and_their_codes():
    assert [f.value for f in taxonomy.LossFamily] == [
        "direct_financial",
        "business_interruption",
        "incident_response",
        "recovery",
        "legal",
        "regulatory_compliance",
        "notification",
        "customer_restitution",
        "contractual",
        "data_and_ip",
        "customer_loss",
        "third_party_downstream",
        "insurance",
        "remediation_investment",
        "physical_operational",
    ]
    assert list(taxonomy.FAMILIES) == list(taxonomy.LossFamily)
    for code, family in taxonomy.FAMILIES.items():
        assert family.code is code and family.label and family.examples and family.typical_inputs
    assert taxonomy.loss_family("legal") is taxonomy.LossFamily.LEGAL
    with pytest.raises(ValueError):
        taxonomy.loss_family("market_value_reaction")


def test_source_types_grades_license_classes_and_trust_tiers():
    assert [s.value for s in provenance.SourceType] == [
        "CUSTOMER_PROVIDED",
        "MYTHOS_OBSERVED",
        "CALCULATED",
        "OFFICIAL_PUBLIC",
        "LICENSED_MARKET",
        "INDUSTRY_BENCHMARK",
        "EXPERT_ESTIMATE",
        "UNKNOWN",
    ]
    assert [g.value for g in confidence.ConfidenceGrade] == ["A", "B", "C", "D", "Unknown"]
    assert [c.value for c in provenance.LicenseClass] == ["unreviewed", "open", "restricted", "licensed", "customer"]
    assert [t.value for t in provenance.TrustTier] == [
        "authoritative",
        "customer",
        "licensed_vendor",
        "benchmark",
        "unverified",
    ]
    # Every value has its words published beside it.
    assert set(provenance.SOURCE_TYPES) == set(provenance.SourceType)
    assert set(confidence.GRADES) == set(confidence.ConfidenceGrade)
    assert set(provenance.LICENSE_CLASSES) == set(provenance.LicenseClass)
    assert set(provenance.TRUST_TIERS) == set(provenance.TrustTier)


# ------------------------------------------------------------- the currencies

#: mythos-core's entries digest (mythos_core.currency.entries_digest): the 216
#: entries athena-backend #141 reviewed, carried into core by Mythos-Core#49. It is
#: also the adapter's PINNED_ENTRIES_SHA256, which refuses any other table at
#: import. A core bump that changes an entry moves it: change it here and in the
#: adapter, in the same reviewed change, and say what moved.
CORE_ENTRIES_SHA256 = "00cb16d39eea4ed912c1f8fb9d43b58e19d96328090a3ad766f9cf03a868038a"
#: The SHA-256 of core's table file: its entries and its source and review records
#: (what #141's whole-document digest covered). A core bump that changes what the
#: table says about where its entries came from, or how far they are checked, moves
#: it.
CORE_TABLE_SHA256 = "b23e144243e33946633529178e494ce7a43ef332408a3fd4271eceeefeaa2f9a"


def test_the_engine_reads_cores_one_table():
    """Mythos-Core#49 made core's table the single table: the adapter holds core's
    own objects, and the engine carries no table file of its own."""
    import mythos_core.currency as core

    assert currency.CURRENCIES is core.CURRENCIES
    assert currency.RECORDS is core.RECORDS
    assert currency.REPORTABLE_MINOR_UNITS is core.REPORTABLE_MINOR_UNITS
    assert currency.Currency is core.Currency
    assert len(currency.CURRENCIES) == 216
    assert not (ENGINE / "data").exists()
    assert not list(REPO.joinpath("assurance").rglob("iso4217*.json"))


def test_cores_entries_digest_is_the_one_pinned_here():
    import mythos_core.currency as core

    assert core.entries_digest(core.CURRENCIES) == CORE_ENTRIES_SHA256
    assert currency.PINNED_ENTRIES_SHA256 == CORE_ENTRIES_SHA256
    assert currency.entries_digest() == CORE_ENTRIES_SHA256
    assert core.TABLE_SHA256 == currency.TABLE_SHA256 == CORE_TABLE_SHA256
    assert hashlib.sha256(core.TABLE_PATH.read_bytes()).hexdigest() == CORE_TABLE_SHA256


def test_the_adapter_refuses_a_table_it_has_not_pinned():
    import mythos_core.currency as core

    currency.check_pinned(core.CURRENCIES)
    changed = dict(core.CURRENCIES)
    changed["KWD"] = dataclasses.replace(changed["KWD"], minor_units=2)
    dropped = {code: c for code, c in core.CURRENCIES.items() if code != "GRD"}
    renamed = dict(core.CURRENCIES)
    renamed["USD"] = dataclasses.replace(renamed["USD"], name="Dollar")
    for table in (changed, dropped, renamed):
        with pytest.raises(currency.CurrencyTableInvalid):
            currency.check_pinned(table)


def test_a_core_bump_that_changes_the_table_refuses_economics_use_not_import():
    """A fresh interpreter whose mythos-core table has one entry changed, as a core
    bump might. Review round 1, M2: importing the adapter must NOT raise -- Django
    imports it while loading ``assurance.models``, and a refusal there took every
    route down, the scan's Stop with them. The pin is recorded at import, and every
    economics use of the table refuses instead."""
    script = textwrap.dedent(
        """
        import dataclasses, types
        from decimal import Decimal
        import mythos_core.currency as core

        table = dict(core.CURRENCIES)
        table["USD"] = dataclasses.replace(table["USD"], minor_units=3)
        core.CURRENCIES = types.MappingProxyType(table)
        from assurance.economics.engine import currency, money
        print("imported", "athena-backend pinned" in (currency.PIN_REFUSAL or ""))
        refused = []
        for name, use in (
            ("currency", lambda: currency.currency("USD")),
            ("minor_units", lambda: currency.minor_units("USD")),
            ("current_successor", lambda: currency.current_successor("HRK")),
            ("reporting_refusal", lambda: currency.reporting_refusal("USD")),
            ("Money", lambda: money.Money(Decimal("1"), "USD")),
        ):
            try:
                use()
            except core.CurrencyTableInvalid:
                refused.append(name)
        print("refused", len(refused))
        """
    )
    env = {k: v for k, v in os.environ.items() if k != "DJANGO_SETTINGS_MODULE"}
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=REPO, env=env, capture_output=True, text=True, timeout=60, check=False
    )
    assert result.stdout.split() == ["imported", "True", "refused", "5"], (result.stdout, result.stderr)


def test_the_pin_also_holds_cores_reportable_set_to_its_entries():
    """Review round 1, L3: the codes core says an amount may be reported in are
    exactly the codes its entries make reportable (active, with a minor unit). A
    core whose two disagree is refused on use, like a changed entry."""
    script = textwrap.dedent(
        """
        import types
        import mythos_core.currency as core

        core.REPORTABLE_MINOR_UNITS = types.MappingProxyType({**core.REPORTABLE_MINOR_UNITS, "HRK": 2})
        from assurance.economics.engine import currency
        try:
            currency.reporting_refusal("HRK")
        except core.CurrencyTableInvalid as refused:
            print("refused", "REPORTABLE_MINOR_UNITS" in str(refused))
        else:
            print("reportable")
        """
    )
    env = {k: v for k, v in os.environ.items() if k != "DJANGO_SETTINGS_MODULE"}
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=REPO, env=env, capture_output=True, text=True, timeout=60, check=False
    )
    assert result.stdout.split() == ["refused", "True"], (result.stdout, result.stderr)

    import mythos_core.currency as core

    assert currency.reportable_from(core.CURRENCIES) == dict(core.REPORTABLE_MINOR_UNITS)
    currency.check_pinned(core.CURRENCIES, core.REPORTABLE_MINOR_UNITS)
    for reportable in (
        {**core.REPORTABLE_MINOR_UNITS, "USD": 3},
        {**core.REPORTABLE_MINOR_UNITS, "HRK": 2},
        {code: units for code, units in core.REPORTABLE_MINOR_UNITS.items() if code != "JPY"},
    ):
        assert currency.pin_refusal(core.CURRENCIES, reportable) is not None
        with pytest.raises(currency.CurrencyTableInvalid):
            currency.check_pinned(core.CURRENCIES, reportable)


def test_the_pin_holds_on_the_table_in_force():
    assert currency.PIN_REFUSAL is None
    currency.require_pinned()


def test_minor_units_are_pinned():
    assert currency.minor_units("JPY") == 0
    assert currency.minor_units("USD") == 2
    assert currency.minor_units("KWD") == 3
    for code in ("JPY", "USD", "KWD"):
        assert currency.currency(code).status == currency.ACTIVE
        assert currency.reporting_refusal(code) is None


def test_a_retired_code_and_its_successor():
    kuna = currency.currency("HRK")
    assert (kuna.status, kuna.minor_units, kuna.successor) == ("retired", 2, "EUR")
    assert currency.current_successor("HRK") is currency.currency("EUR")
    assert currency.current_successor("EUR") is None
    assert currency.reporting_refusal("HRK") == "currency_retired"


def test_the_euros_predecessors_include_the_drachma_and_the_escudo():
    """Review round 1, L6: the table said it held the euro's predecessors and left
    out GRD and PTE. Pinned against core's table now."""
    for code in ("GRD", "PTE"):
        retired = currency.currency(code)
        assert (retired.status, retired.minor_units, retired.successor) == ("retired", 0, "EUR"), code
    euro_legacy = {c.code for c in currency.CURRENCIES.values() if c.successor == "EUR"}
    assert euro_legacy == {
        "ATS", "BEF", "DEM", "ESP", "FIM", "FRF", "GRD", "IEP", "ITL", "LUF", "NLG", "PTE",
        "SIT", "CYP", "MTL", "SKK", "EEK", "LVL", "LTL", "HRK", "BGN",
    }
    # Cross-checked against OpenJDK 21.0.10's table, which corrected it from 2.
    assert currency.minor_units("ROL") == 0


def test_the_table_records_its_source():
    records = currency.RECORDS
    assert "ISO 4217" in records["source"]["standard"]
    assert records["source"]["how_made"] and records["review"]["status"]
    assert {c.status for c in currency.CURRENCIES.values()} == {"active", "retired"}
    # Minor units of N.A. are null, never a guessed zero.
    assert currency.minor_units("XAU") is None and currency.minor_units("XXX") is None
    assert currency.minor_units("CLF") == 4


def test_the_file_digest_covers_the_source_and_review_records(tmp_path):
    """Review round 1, L6, against core's table: what the file says about where its
    entries came from and how far they are checked is reviewed data too, so editing
    it moves the pinned digest, and core refuses the file against the old one."""
    import mythos_core.currency as core

    document = json.loads(core.TABLE_PATH.read_bytes())
    for record, key in (("review", "status"), ("source", "how_made")):
        edited = json.loads(json.dumps(document))
        edited[record][key] = "verified"
        data = core.canonical(edited)
        path = tmp_path / f"{record}.json"
        path.write_bytes(data)
        assert hashlib.sha256(data).hexdigest() != CORE_TABLE_SHA256, record
        with pytest.raises(core.CurrencyTableInvalid):
            core.load_table(path)
        # The entries are unchanged, so their digest is too: only the file pin moves.
        assert core.entries_digest(core.load_table(path, sha256=hashlib.sha256(data).hexdigest())[0]) == (
            CORE_ENTRIES_SHA256
        )


@pytest.mark.parametrize("code", ["usd", "US$", "XYZ", "", None, ["USD"]])
def test_a_code_is_read_exactly_as_written(code):
    with pytest.raises(currency.UnknownCurrency):
        currency.currency(code)
    assert currency.reporting_refusal(code) == "currency_unknown"


def test_a_reporting_currency_is_refused_exactly_as_cores_receipt_refuses_it():
    """The brief's rule: a retired or non-reportable currency is refused as a
    reporting currency, matching core's ``currency_retired``. For every code in the
    table, the adapter refuses exactly the codes core's receipt has no minor unit
    for, with core's spelling."""
    from mythos_core import exposure_receipt as receipt

    assert (currency.CURRENCY_UNKNOWN, currency.CURRENCY_RETIRED, currency.CURRENCY_MISMATCH) == (
        receipt.CURRENCY_UNKNOWN,
        receipt.CURRENCY_RETIRED,
        receipt.CURRENCY_MISMATCH,
    )
    for code in currency.CURRENCIES:
        expected = None if code in receipt.MINOR_UNITS else receipt.CURRENCY_RETIRED
        assert currency.reporting_refusal(code) == expected, code
    assert currency.reporting_refusal("XAU") == "currency_retired"


def _table(tmp_path, entries, **over):
    """A table document in core's canonical form, and its SHA-256, so that core's
    loader reaches the rule under test rather than refusing the digest."""
    import mythos_core.currency as core

    entries = sorted(entries, key=lambda e: str(e.get("code")))
    non_reportable = sorted(
        e["code"] for e in entries
        if isinstance(e, dict) and (e.get("status") != "active" or e.get("minor_units") is None)
    )
    document = {
        "schema": core.TABLE_SCHEMA, "source": {"s": 1}, "review": {"r": 1},
        "non_reportable": non_reportable, "currencies": entries,
    }
    document.update(over)
    data = core.canonical(document)
    path = tmp_path / "table.json"
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


USD = {"code": "USD", "name": "US Dollar", "minor_units": 2, "status": "active", "successor": None}


@pytest.mark.parametrize(
    "entries, over",
    [
        ([USD], {"schema": "something/v2"}),
        ([USD], {"source": {}}),
        ([USD], {"review": None}),
        ([], {}),
        ([USD, USD], {}),
        ([{**USD, "code": "usd"}], {}),
        ([{**USD, "name": " "}], {}),
        ([{**USD, "minor_units": 2.0}], {}),
        ([{**USD, "minor_units": True}], {}),
        ([{**USD, "minor_units": 5}], {}),
        ([{**USD, "minor_units": -1}], {}),
        ([{**USD, "status": "withdrawn"}], {}),
        ([{**USD, "successor": "EUR"}], {}),
        ([{**USD, "extra": 1}], {}),
        ([{**USD, "code": "OLD", "status": "retired", "successor": "NEW"}], {}),
        ([{**USD, "code": "OLD", "status": "retired", "successor": "OLD"}], {}),
        (
            [
                {**USD, "code": "AAA", "status": "retired", "successor": "BBB"},
                {**USD, "code": "BBB", "status": "retired", "successor": "AAA"},
            ],
            {},
        ),
        ([USD], {"non_reportable": ["USD"]}),
    ],
)
def test_a_broken_table_does_not_load(tmp_path, entries, over):
    """#141's table rules, held now by core's loader, which the engine reads."""
    import mythos_core.currency as core

    path, digest = _table(tmp_path, entries, **over)
    with pytest.raises(core.CurrencyTableInvalid):
        core.load_table(path, sha256=digest)


def test_a_well_formed_table_loads(tmp_path):
    import mythos_core.currency as core

    old = {**USD, "code": "OLD", "status": "retired", "successor": "USD"}
    path, digest = _table(tmp_path, [USD, old])
    table, records = core.load_table(path, sha256=digest)
    assert table["OLD"].successor == "USD" and records["review"] == {"r": 1}
    # The same bytes against any other pin are refused.
    with pytest.raises(core.CurrencyTableInvalid):
        core.load_table(path, sha256=CORE_TABLE_SHA256)


# ----------------------------------------------------------------- the rules

ALICE = Person(id=1, username="alice")
BOB = Person(id=2, username="bob")
CAROL = Person(id=3, username="carol")


def test_an_author_never_reviews_their_own_scenario():
    assert governance.review_refusal([ALICE], BOB) is None
    assert governance.review_refusal([ALICE], ALICE) == "author_reviews_own_scenario"
    # The account removed since: the username recorded with the scenario still names them.
    assert governance.review_refusal([Person(None, "alice")], Person(9, "Alice")) == "author_reviews_own_scenario"
    assert governance.review_refusal([ALICE], Person(1, "renamed")) == "author_reviews_own_scenario"
    assert governance.review_refusal([ALICE], Person()) == "reviewer_not_named"


def test_a_reviewer_authored_no_version_of_the_scenario():
    """Review round 1, M1: the authors are every version's -- the one reviewed and
    each it supersedes -- and a line with no named author is not reviewable."""
    # v2 drafted by a machine, superseding alice's v1: alice still may not review it.
    assert governance.review_refusal([Person(), ALICE], ALICE) == "author_reviews_own_scenario"
    # v2 by bob, superseding alice's v1: neither may; carol may.
    assert governance.review_refusal([BOB, ALICE], ALICE) == "author_reviews_own_scenario"
    assert governance.review_refusal([BOB, ALICE], BOB) == "author_reviews_own_scenario"
    assert governance.review_refusal([BOB, ALICE], CAROL) is None
    # No version names an author: nothing shows the reviewer is someone else.
    assert governance.review_refusal([Person(), Person()], CAROL) == "author_not_named"
    assert governance.review_refusal([], CAROL) == "author_not_named"


def test_a_sensitive_override_needs_two_different_approvers():
    assert governance.REQUIRED_OVERRIDE_APPROVERS == 2
    assert governance.override_refusal(ALICE, []) == "override_needs_two_approvers"
    assert governance.override_refusal(ALICE, [BOB]) == "override_needs_two_approvers"
    assert governance.override_refusal(ALICE, [BOB, BOB]) == "override_needs_two_approvers"
    assert governance.override_refusal(ALICE, [BOB, Person(None, "BOB")]) == "override_needs_two_approvers"
    # The requester's own approval never counts.
    assert governance.override_refusal(ALICE, [BOB, ALICE]) == "override_needs_two_approvers"
    assert governance.override_refusal(ALICE, [BOB, Person()]) == "override_needs_two_approvers"
    assert governance.override_refusal(ALICE, [BOB, CAROL]) is None
    assert governance.override_refusal(Person(), [BOB, CAROL]) == "requester_not_named"


def test_who_may_approve_an_override():
    assert governance.approval_refusal(ALICE, [], BOB) is None
    assert governance.approval_refusal(ALICE, [BOB], CAROL) is None
    assert governance.approval_refusal(ALICE, [], ALICE) == "requester_approves_own_override"
    assert governance.approval_refusal(ALICE, [BOB], BOB) == "approver_already_approved"
    assert governance.approval_refusal(ALICE, [BOB], Person(None, "bob")) == "approver_already_approved"
    assert governance.approval_refusal(ALICE, [], Person()) == "approver_not_named"
    assert governance.override_request_refusal(ALICE, "revenue_per_hour", "customer-confirmed figure") is None
    assert governance.override_request_refusal(Person(), "x", "y") == "requester_not_named"
    assert governance.override_request_refusal(ALICE, "x", " ") == "override_incomplete"


def test_an_unreviewed_source_is_never_used_by_a_production_run():
    assert governance.production_use_refusal("unreviewed") == "unreviewed_license"
    assert governance.production_use_refusal("UNREVIEWED") == "license_class_unrecognised"
    assert governance.production_use_refusal("") == "license_class_unrecognised"
    for reviewed in ("open", "restricted", "licensed", "customer"):
        assert governance.production_use_refusal(reviewed) is None
        # Review round 1, M1: synthetic test data, whatever its licence.
        assert governance.production_use_refusal(reviewed, synthetic=True) == "synthetic_source"
    assert governance.production_use_refusal("unreviewed", synthetic=True) == "synthetic_source"


def test_snapshot_hashes_spine_references_and_inventory_entries():
    good = "sha256:" + "ab" * 32
    assert governance.snapshot_hash_refusal(good) is None
    for bad in ("ab" * 32, "sha256:" + "AB" * 32, "sha256:" + "ab" * 31, "md5:" + "ab" * 16, None):
        assert governance.snapshot_hash_refusal(bad) == "snapshot_hash_malformed"
    assert governance.spine_reference_refusal("effect", good) is None
    assert governance.spine_reference_refusal("system_fingerprint", "cd" * 32) is None
    assert governance.spine_reference_refusal("claim", "cd" * 32) is None
    assert governance.spine_reference_refusal("node", "0b9e3a52-6f1c-4d8e-9a7b-2c4d6e8f0a1b") is None
    assert governance.spine_reference_refusal("effect", "refund") == "spine_reference_malformed"
    assert governance.spine_reference_refusal("system_fingerprint", good) == "spine_reference_malformed"
    assert governance.spine_reference_refusal("finding", "cd" * 32) == "spine_reference_malformed"
    entry = {"model_id": "banking-payments", "version": "1.0.0", "owner": "model risk", "intended_use": "u"}
    entry["limitations"] = "l"
    assert governance.inventory_refusal(**entry) is None
    for field in ("model_id", "version", "owner", "intended_use", "limitations"):
        assert governance.inventory_refusal(**{**entry, field: "  "}) == "inventory_entry_incomplete"


def test_codes_and_required_text():
    """Review round 1, L2."""
    assert governance.code_refusal("approved", ["approved", "returned"]) is None
    for bad in ("", "rubber-stamp", "Approved", None):
        assert governance.code_refusal(bad, ["approved", "returned"]) == "code_unrecognised"
    assert governance.required_text_refusal("fed-h10", "Federal Reserve") is None
    for bad in ("", "  ", None):
        assert governance.required_text_refusal("ok", bad) == "required_field_blank"


def _constants(path: Path, calls: set[str], *, returns: bool = False) -> set[str]:
    """The string constants ``path`` passes as the first argument to a call of one
    of ``calls``, and (``returns``) the ones it returns, read off its source."""
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if (
            returns
            and isinstance(node, ast.Return)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            found.add(node.value.value)
        if (
            isinstance(node, ast.Call)
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and getattr(node.func, "id", "") in calls
        ):
            found.add(node.args[0].value)
    return found


def test_every_refusal_a_rule_gives_is_a_published_code():
    """Every code a governance rule returns or a model raises is published, in
    governance.REFUSALS, (phase E1, the money engine) money.REFUSALS or (the
    scenario engine) parameters.REFUSALS; every code the money engine raises is in
    money.REFUSALS, and every code the scenario engine raises as its own is in
    parameters.REFUSALS; and every published code is one something gives. A code
    two tables publish means the same in both, and the scenario engine publishes
    none the money engine already does."""
    economics = REPO / "assurance" / "economics"
    returned = _constants(ENGINE / "governance.py", set(), returns=True)
    raised = _constants(economics / "models.py", {"EconomicsRefused"}) | _constants(
        economics / "snapshots.py", {"EconomicsRefused"}
    )
    engine_raised = set().union(*(_constants(path, {"MoneyRefused"}) for path in ENGINE.glob("*.py")))
    scenario_raised = set().union(*(_constants(path, {"ParameterRefused"}) for path in ENGINE.glob("*.py")))
    assert returned <= set(governance.REFUSALS)
    assert engine_raised <= set(money.REFUSALS)
    assert scenario_raised <= set(parameters.REFUSALS)
    assert not set(parameters.REFUSALS) & set(money.REFUSALS)
    published = set(governance.REFUSALS) | set(money.REFUSALS) | set(parameters.REFUSALS)
    assert returned | raised | engine_raised | scenario_raised == published
    for code in set(governance.REFUSALS) & set(money.REFUSALS):
        assert governance.REFUSALS[code] == money.REFUSALS[code], code
    for code in set(governance.REFUSALS) & set(parameters.REFUSALS):
        assert governance.REFUSALS[code] == parameters.REFUSALS[code], code


# ---------------------------------------------------- off every stop path


def test_a_changed_core_table_never_takes_down_the_scan_stop():
    """Review round 1, M2 (the safety rule). A fresh pytest, under a plugin that
    changes one entry of mythos-core's currency table before Django loads, runs
    ``tests/economics_mismatched_core_cases.py``: Django loads, the scan's Stop
    route resolves and answers, the Stop is saved, and economics use refuses."""
    env = dict(os.environ, DJANGO_SECRET_KEY=os.environ.get("DJANGO_SECRET_KEY", "ci-secret-key-not-used-outside-ci"))
    result = subprocess.run(
        [
            sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-p", "tests.economics_mismatched_core",
            "-q", "tests/economics_mismatched_core_cases.py",
        ],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600, check=False,
    )
    assert result.returncode == 0, (result.stdout[-4000:], result.stderr[-2000:])
    assert "3 passed" in result.stdout, result.stdout[-2000:]


@pytest.mark.parametrize(
    "fault, plugin",
    [("api", "tests.economics_broken_api"), ("core", "tests.economics_missing_core")],
    ids=["route-module-does-not-import", "core-currency-module-does-not-import"],
)
def test_an_economics_fault_never_takes_down_a_stop(fault, plugin):
    """Review round 1 of #146, H1 and H2 (the safety rule). A fresh pytest, under a
    plugin that breaks Economic Exposure before Django loads -- its route module
    does not import (H1), or mythos-core's currency module does not (H2) -- runs
    ``tests/economics_fault_cases.py``: Django loads, the scan's Stop is answered
    (202) and saved, ``deliver_owed_stops`` runs the system checks, the URL check
    among them, and reaches its handler, ``manage.py check`` passes, and only
    economics refuses (its routes are not served, or its use raises
    ``CurrencyTableInvalid`` and its write answers 503)."""
    env = dict(
        os.environ,
        DJANGO_SECRET_KEY=os.environ.get("DJANGO_SECRET_KEY", "ci-secret-key-not-used-outside-ci"),
        ECONOMICS_FAULT=fault,
    )
    result = subprocess.run(
        [
            sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-p", plugin,
            "-q", "tests/economics_fault_cases.py",
        ],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600, check=False,
    )
    assert result.returncode == 0, (result.stdout[-4000:], result.stderr[-2000:])
    assert "4 passed" in result.stdout, result.stdout[-2000:]


def test_the_economics_routes_are_imported_guarded():
    """Read, not run: assurance/urls.py imports the economics route module inside a
    try whose handler logs and serves no economics route, never re-raising."""
    tree = ast.parse((REPO / "assurance" / "urls.py").read_text(encoding="utf-8"))
    guarded = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Try)
        and any(
            isinstance(inner, ast.ImportFrom) and (inner.module or "").startswith("economics")
            for inner in node.body
        )
    ]
    assert len(guarded) == 1, "the economics route module is imported outside a guard"
    (handler,) = guarded[0].handlers
    assert isinstance(handler.type, ast.Name) and handler.type.id == "Exception"
    assert not any(isinstance(node, ast.Raise) for node in ast.walk(handler))
    top_level = [n for n in tree.body if isinstance(n, ast.ImportFrom) and (n.module or "").startswith("economics")]
    assert top_level == []



def test_nothing_but_the_models_registration_imports_economics():
    """No economics code on any stop, pause, stand-down, terminate or revoke path:
    the first-party modules that import the package are the line in
    assurance/models.py that registers its models and (the scenario step) the line
    in assurance/urls.py that mounts its one route module,
    ``assurance.economics.api``, the customer parameter-set routes. None of those
    routes is a stop (``safety.stops.NOT_STOPS``;
    tests/test_economics_scenario_records.py, ``test_no_economics_route_is_a_stop``).
    The import is GUARDED (``test_the_economics_routes_are_imported_guarded``): a
    route module that does not import is logged and not served, and the URLconf,
    every stop and the system checks load without it
    (``test_an_economics_fault_never_takes_down_a_stop``). A later step that serves
    more adds its route module here -- never a stop-path module -- and says so."""
    importers = set()
    skip = {".git", "node_modules", "tests", "__pycache__"}
    for directory, subdirectories, files in os.walk(REPO):
        here = Path(directory)
        subdirectories[:] = [
            d for d in subdirectories if d not in skip and not d.startswith(".") and not (here / d / "pyvenv.cfg").exists()
        ]
        relative = here.relative_to(REPO)
        if relative.parts[:2] == ("assurance", "economics"):
            continue
        for name in files:
            if not name.endswith(".py"):
                continue
            path = here / name
            package = ".".join(relative.parts)
            for module in _imports(path, package):
                if module == "assurance.economics" or module.startswith("assurance.economics."):
                    importers.add(path.relative_to(REPO).as_posix())
    assert importers == {"assurance/models.py", "assurance/urls.py"}
    mounted = _imports(REPO / "assurance" / "urls.py", "assurance")
    assert [m for m in mounted if m.startswith("assurance.economics")] == [
        "assurance.economics.api",
        "assurance.economics.api.urlpatterns",
    ]


# ------------------------------------------------------------- the spec


#: What the spec must say, read with its line breaks folded so a phrase may wrap.
SPEC_PHRASES = (
    "Decimal",
    (
        "native amount, then event-date FX into the base currency, then the cost index to the valuation date, "
        "then valuation-date FX into the reporting currency"
    ),
    "never interpolated silently",
    "never added to cash loss",
    "No Open FAIR conformance is claimed",
    "No economics code is on any stop, pause, stand-down, terminate or revoke path",
    # Review round 1, L5: the two writes from outside economics, and their tests.
    "Removing an operator, which is a stop",
    "Deleting a deployment",
    "test_removing_an_operator_is_never_held_back_by_economics_rows",
    "test_the_records_go_with_their_deployment",
    # L1: what writes past the append-only refusals.
    "Append-only is an ORM guard, not a table guard",
    "`Model._base_manager`",
    "a plain `QuerySet(model)`, raw SQL, and a migration",
    # L4: references are checked for form only.
    "SPINE references are checked for form only",
    # Review round 1, M2: a changed core table never takes a stop down.
    "test_a_changed_core_table_never_takes_down_the_scan_stop",
    # Review round 1 of #146, H2: nothing at import; the pin on first use.
    "imports no part of mythos-core and checks nothing at import",
    "mythos_core.currency cannot be imported",
    "test_an_economics_fault_never_takes_down_a_stop",
    "The scenario builder must resolve every reference within the scenario's own deployment",
    # Phase E1: one currency table, money, FX and normalization, and their limits.
    "`mythos_core.currency` is the one currency table",
    CORE_ENTRIES_SHA256,
    CORE_TABLE_SHA256,
    "A float is refused on entry",
    "60 significant digits",
    "`ROUND_HALF_EVEN`",
    "Two amounts in different currencies never add",
    "the last official rate",
    "A missing rate is unavailable",
    "never interpolated unless the policy says `interpolate`",
    "flagged stale",
    "The original native amount and currency are never overwritten",
    "SYNTHETIC TEST DATA",
    "licence class `open` and trust tier `unverified`",
    "No triangulation",
    "No holiday calendar is stored",
    "Swapping the steps gives a different, wrong answer",
    # The scenario engine (MVP step 4): formulas, insurance, the parameter set.
    (
        "The low result is computed from the low inputs and the high from the high inputs, in the direction each "
        "input moves the loss"
    ),
    "a higher recovery rate lowers loss",
    "A missing input gives an explicit unknown component, never a zero",
    "Unknown is never zero",
    "Insurance is applied once, after the gross components",
    "The retained loss is never negative",
    "Market value is never cash",
    "never_added_to_cash",
    "Money follows section 13's strict decimal-string rule",
    "Unknown fields are refused",
    "a viewer, even the deployment's owner, reads and is refused 403",
    "Its amounts are never taken from the caller",
    "Every reference is tenant-scoped",
    "SYNTHETIC / ILLUSTRATIVE",
    "test_removing_an_operator_is_never_held_back_by_a_parameter_set",
    "test_no_economics_route_is_a_stop",
    "this repository does not use hypothesis",
    "Deterministic ranges, not distributions",
    "Decisions this version takes, which the owner may change",
)


@pytest.mark.parametrize("phrase", SPEC_PHRASES)
def test_the_spec_states_the_policy(phrase):
    assert phrase in " ".join(SPEC.read_text(encoding="utf-8").split())


def test_the_spec_names_every_code():
    text = SPEC.read_text(encoding="utf-8")
    codes = [
        *taxonomy.LossFamily,
        *provenance.SourceType,
        *confidence.ConfidenceGrade,
        *provenance.LicenseClass,
        *provenance.TrustTier,
        *governance.REFUSALS,
        *money.REFUSALS,
        *money.UNAVAILABLE_REASONS,
        *fx.RateType,
        *fx.RULES,
        fx.NO_FALLBACK,
        fx.UNAVAILABLE,
        fx.INTERPOLATE,
        cost_index.EXACT_PERIOD,
        cost_index.LATEST_PUBLISHED_PERIOD,
        *normalization.DOWNGRADES,
        *normalization.ORDER,
        # The scenario engine.
        *parameters.REFUSALS,
        *parameters.Unit,
        *formulas.Direction,
        *formulas.UNKNOWN_REASONS,
        formulas.MARKET_VALUE,
        formulas.ESTIMATED,
        formulas.UNKNOWN,
        formulas.GROSS,
        *(formula_id for formula_id, _ in formulas.CATALOGUE),
        *(i.name for f in formulas.CATALOGUE.values() for i in f.inputs),
        *parameter_set.VARIABLES,
        *parameter_set.Domain,
        parameter_set.SCHEMA_VERSION,
        "deployment-economics-parameter-set",
        "deployment-economics-parameter-set-versions",
        *loss.TERM_DIRECTIONS,
    ]
    missing = [str(code) for code in codes if f"`{code}`" not in text]
    assert not missing, missing
