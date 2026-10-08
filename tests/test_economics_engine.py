"""Economic Exposure's pure core, exercised with no database and no Django.

:mod:`assurance.economics.engine` holds the vocabularies every later step reads
(the fifteen loss families, ``source_type``, the confidence grades, the license
classes and trust tiers), the ISO 4217 currency table, and the governance rules.
Pinned here:

- the engine imports with Django poisoned, and no module of it names Django;
- every code is pinned exactly, so a rename or a reuse is a reviewed change here;
- the currency table: JPY 0, USD 2, KWD 3, the retired HRK and its successor, and
  the digest of every entry, so an edit to the table fails until the pin moves;
- each governance rule, and that every refusal it gives is a published code;
- nothing but :mod:`assurance.models` imports the package, so no economics code
  sits on a stop, pause or revoke path;
- the spec (``docs/economics/spec-v1.md``) states the policy and every code.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from assurance.economics.engine import (
    confidence,
    currency,
    governance,
    provenance,
    taxonomy,
)
from assurance.economics.engine.governance import Person

REPO = Path(__file__).resolve().parent.parent
ENGINE = REPO / "assurance" / "economics" / "engine"
SPEC = REPO / "docs" / "economics" / "spec-v1.md"


# ------------------------------------------------------------- free of Django


def test_the_engine_imports_with_django_poisoned():
    """A fresh interpreter in which importing Django (or the REST framework, or
    mythos-core) raises, and no settings module is named: every engine module still
    imports, and nothing outside the engine package is loaded."""
    script = textwrap.dedent(
        """
        import importlib, pkgutil, sys

        POISONED = {"django", "rest_framework", "mythos_core"}

        class Poison:
            def find_spec(self, name, path=None, target=None):
                if name.split(".")[0] in POISONED:
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
        print("imported", len(names))
        """
    )
    env = {k: v for k, v in os.environ.items() if k != "DJANGO_SETTINGS_MODULE"}
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=REPO, env=env, capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 0, result.stderr
    # The package and its five modules.
    assert result.stdout.strip() == "imported 6", result.stdout


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
    fail here."""
    files = sorted(ENGINE.glob("*.py"))
    assert {f.name for f in files} == {
        "__init__.py",
        "confidence.py",
        "currency.py",
        "governance.py",
        "provenance.py",
        "taxonomy.py",
    }
    for path in files:
        for module in _imports(path, "assurance.economics.engine"):
            root = module.split(".")[0]
            assert root not in {"django", "rest_framework", "mythos_core"}, (path.name, module)
            if root == "assurance":
                assert module.startswith("assurance.economics.engine"), (path.name, module)


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

#: The digest of every entry in data/iso4217.json. An edit to any entry moves it:
#: change it here, in the same reviewed change, and say what moved.
TABLE_DIGEST = "23e6b9dcf024522bec5e53b6ba92a6636aed2e8a43218c49c062e7ef0cf296d9"


def test_minor_units_are_pinned():
    assert currency.minor_units("JPY") == 0
    assert currency.minor_units("USD") == 2
    assert currency.minor_units("KWD") == 3
    for code in ("JPY", "USD", "KWD"):
        assert currency.currency(code).active


def test_a_retired_code_and_its_successor():
    kuna = currency.currency("HRK")
    assert (kuna.status, kuna.minor_units, kuna.successor) == ("retired", 2, "EUR")
    assert not kuna.active
    assert currency.current_successor("HRK") is currency.currency("EUR")
    assert currency.current_successor("EUR") is None


def test_the_table_is_the_reviewed_file_and_records_its_source():
    assert currency.TABLE_DIGEST == TABLE_DIGEST
    records = currency.TABLE_RECORDS
    assert "ISO 4217" in records["source"]["standard"]
    assert records["source"]["how_made"] and records["review"]["status"]
    statuses = {c.status for c in currency.CURRENCIES.values()}
    assert statuses == {"active", "retired"}
    # Minor units of N.A. are null, never a guessed zero.
    assert currency.minor_units("XAU") is None and currency.minor_units("XXX") is None
    assert currency.minor_units("CLF") == 4


@pytest.mark.parametrize("code", ["usd", "US$", "XYZ", "", None, ["USD"]])
def test_a_code_is_read_exactly_as_written(code):
    with pytest.raises(currency.UnknownCurrency):
        currency.currency(code)


def _table(tmp_path, entries, **over):
    document = {"schema": currency.TABLE_SCHEMA, "source": {"s": 1}, "review": {"r": 1}, "currencies": entries}
    document.update(over)
    path = tmp_path / "table.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


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
    ],
)
def test_a_broken_table_does_not_load(tmp_path, entries, over):
    with pytest.raises(currency.CurrencyTableInvalid):
        currency.load_table(_table(tmp_path, entries, **over))


def test_a_well_formed_table_loads(tmp_path):
    old = {**USD, "code": "OLD", "status": "retired", "successor": "USD"}
    table, records, digest = currency.load_table(_table(tmp_path, [USD, old]))
    assert table["OLD"].successor == "USD" and records["review"] == {"r": 1}
    assert digest == currency.table_digest([USD, old])


# ----------------------------------------------------------------- the rules

ALICE = Person(id=1, username="alice")
BOB = Person(id=2, username="bob")
CAROL = Person(id=3, username="carol")


def test_an_author_never_reviews_their_own_scenario():
    assert governance.review_refusal(ALICE, BOB) is None
    assert governance.review_refusal(ALICE, ALICE) == "author_reviews_own_scenario"
    # The account removed since: the username recorded with the scenario still names them.
    assert governance.review_refusal(Person(None, "alice"), Person(9, "Alice")) == "author_reviews_own_scenario"
    assert governance.review_refusal(ALICE, Person(1, "renamed")) == "author_reviews_own_scenario"
    assert governance.review_refusal(ALICE, Person()) == "reviewer_not_named"
    # A scenario a machine drafted has no author: any named person may review it.
    assert governance.review_refusal(Person(), BOB) is None


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


def test_every_refusal_a_rule_gives_is_a_published_code():
    """Every code a rule returns is in REFUSALS, read off the module's source, and
    every published code is one something gives."""
    source = (ENGINE / "governance.py").read_text(encoding="utf-8")
    returned = {
        node.value.value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
    }
    models_source = (REPO / "assurance" / "economics" / "models.py").read_text(encoding="utf-8")
    raised = {
        node.args[0].value
        for node in ast.walk(ast.parse(models_source))
        if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant)
        and getattr(node.func, "id", "") == "EconomicsRefused"
    }
    assert returned | raised == set(governance.REFUSALS)


# ---------------------------------------------------- off every stop path


def test_nothing_but_the_models_registration_imports_economics():
    """No economics code on any stop, pause, stand-down, terminate or revoke path:
    the only first-party module that imports the package is the line in
    assurance/models.py that registers its models. A later step that serves it adds
    its route module here -- never a stop-path module -- and says so."""
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
    assert importers == {"assurance/models.py"}


# ------------------------------------------------------------- the spec


def test_the_spec_states_the_policy_and_every_code():
    text = SPEC.read_text(encoding="utf-8")
    for phrase in (
        "Decimal",
        (
            "native amount, then event-date FX into the base currency, then the cost index to the valuation date, "
            "then valuation-date FX into the reporting currency"
        ),
        "never interpolated silently",
        "never added to cash loss",
        "No Open FAIR conformance is claimed",
        "No economics code is on any stop, pause, stand-down, terminate or revoke path",
    ):
        assert phrase in text, phrase
    codes = [
        *taxonomy.LossFamily,
        *provenance.SourceType,
        *confidence.ConfidenceGrade,
        *provenance.LicenseClass,
        *provenance.TrustTier,
        *governance.REFUSALS,
    ]
    missing = [str(code) for code in codes if f"`{code}`" not in text]
    assert not missing, missing

