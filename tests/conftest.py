import os
import pathlib

import pytest

from tests.pin_bootstrap import enforce  # Mythos-Core's templates/pin_bootstrap.py, byte for byte

ROOT = pathlib.Path(__file__).resolve().parent.parent
#: (distribution, import name, pin files): every dependency this repo git-pins.
PINNED_DEPENDENCIES = (
    ("mythos-core", "mythos_core", ("requirements.txt", "requirements-dev.txt")),
)
PIN_GUARD = enforce(ROOT, PINNED_DEPENDENCIES, refusal=pytest.UsageError)


def pytest_terminal_summary(terminalreporter):
    # pytest hides what a conftest prints while it is imported, so the verdict
    # (and, in a report-only run, every finding) is shown here, at the end.
    for line in PIN_GUARD.lines:
        terminalreporter.write_line(line)


# The guard above is Mythos-Core's shared pin guard (mythos_core.pinguard; see "The
# shared pin guard" in Mythos-Core's README), run before anything else this file
# imports. The ordering is load-bearing, not tidiness: a mythos-core that is not the
# pinned one breaks the imports below, and anything scheduled for later -- a pytest
# hook, a fixture, a test -- never runs to say why. The guard refuses the run itself
# instead, before collection, naming each check that failed, the pinned and the
# imported commit, and what to do. tests/test_pin_guard.py pins the ordering, the
# roster and the stub.

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings_test")

# Imports that a wrong pinned dependency can break, deliberately BELOW
# the guard call above.
import django


def pytest_configure():
    django.setup()


@pytest.fixture(autouse=True, scope="session")
def _sqlite_wal(django_db_setup, django_db_blocker):
    """
    WAL on the test database.

    Without it a reader blocks a writer, and the concurrency tests spend their
    time serialising rather than testing anything.
    """
    with django_db_blocker.unblock():
        from django.db import connection

        if connection.vendor == "sqlite":
            with connection.cursor() as cursor:
                cursor.execute("PRAGMA journal_mode=WAL")


@pytest.fixture(autouse=True, scope="session")
def _economics_run_slots(tmp_path_factory):
    """A directory of this run's own for the economics run slots
    (``assurance.economics.capacity``), so two test runs on one machine never hold
    each other's slots. A nested pytest inherits it."""
    directory = tmp_path_factory.mktemp("economics-run-slots")
    before = os.environ.get("ATHENA_ECONOMICS_SLOT_DIR")
    os.environ["ATHENA_ECONOMICS_SLOT_DIR"] = str(directory)
    yield directory
    if before is None:
        os.environ.pop("ATHENA_ECONOMICS_SLOT_DIR", None)
    else:
        os.environ["ATHENA_ECONOMICS_SLOT_DIR"] = before


@pytest.fixture(autouse=True, scope="session")
def _worker_reports(tmp_path_factory):
    """A directory of this run's own for the workers' reports
    (``assurance.worker_reports``), so ``/api/health/`` in one test run never reads a
    report another run on the machine left. A nested pytest inherits it."""
    directory = tmp_path_factory.mktemp("worker-reports")
    before = os.environ.get("ATHENA_WORKER_REPORT_DIR")
    os.environ["ATHENA_WORKER_REPORT_DIR"] = str(directory)
    yield directory
    if before is None:
        os.environ.pop("ATHENA_WORKER_REPORT_DIR", None)
    else:
        os.environ["ATHENA_WORKER_REPORT_DIR"] = before


#: The row key every test runs with (review round 1 of #169, M1; spec, section 35.9):
#: SYNTHETIC, for tests only, as the tests' receipt keys are. A test of the key-less
#: behaviour unsets it with monkeypatch.
TEST_ECONOMICS_ROW_KEY = "synthetic-test-row-key-for-ci-only-0000"


@pytest.fixture(autouse=True, scope="session")
def _economics_row_key():
    """The economics row key (``ATHENA_ECONOMICS_ROW_KEY``) set for the whole run, as
    a deployment that signs receipts sets it: result and card rows are bound by their
    MAC under it, and a receipt is signed only with it. A nested pytest inherits it."""
    before = os.environ.get("ATHENA_ECONOMICS_ROW_KEY")
    os.environ["ATHENA_ECONOMICS_ROW_KEY"] = TEST_ECONOMICS_ROW_KEY
    yield TEST_ECONOMICS_ROW_KEY
    if before is None:
        os.environ.pop("ATHENA_ECONOMICS_ROW_KEY", None)
    else:
        os.environ["ATHENA_ECONOMICS_ROW_KEY"] = before


#: The engine receipt-signer key every test runs with (s28 audit, T10): SYNTHETIC, for
#: tests only. A deployment that signs receipts sets ``CYBERENGINE_ECONOMICS_SIGNER_KEY``
#: beside ``CYBERENGINE_OPERATOR_KEY``, and every test runs with the operator key set,
#: so every test runs with this one set too. A receipt is signed with this key and
#: never with the operator key. A test of the key-less behaviour overrides it to "".
TEST_ECONOMICS_SIGNER_KEY = "synthetic-test-receipt-signer-key-for-ci-only-0000"


@pytest.fixture(autouse=True, scope="session")
def _economics_signer_key():
    """``CYBERENGINE_ECONOMICS_SIGNER_KEY`` set for the whole run, as a deployment that
    signs receipts sets it. It is a Django setting, read by its literal name
    (``CyberEngineClient.for_receipt_signing``), so it is set as an override of the
    test settings, under every override a test makes of its own."""
    from django.test import override_settings

    signer = override_settings(CYBERENGINE_ECONOMICS_SIGNER_KEY=TEST_ECONOMICS_SIGNER_KEY)
    signer.enable()
    yield TEST_ECONOMICS_SIGNER_KEY
    signer.disable()


@pytest.fixture
def engine_keyring(tmp_path, monkeypatch):
    """Configure an outcome keyring that trusts :data:`tests.signed_chains.ENGINE_KEYS`,
    so rows written by :func:`tests.signed_chains.record_signed` read as demonstrated."""
    from assurance import observed_outcomes
    from tests.signed_chains import write_keyring

    path = tmp_path / "engine-keyring.json"
    write_keyring(path)
    monkeypatch.setenv(observed_outcomes.KEYRING_ENV, str(path))
    return path
