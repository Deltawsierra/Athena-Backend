import importlib
import importlib.metadata
import os
import pathlib
import sys

import pytest

from tests.mythos_core_provenance import (
    OPT_OUT_ENV,
    complaint,
    declared_pin,
    provenance_from_direct_url,
    shadow_complaint,
    remedy,
)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings_test")

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _installed_direct_url():
    """pip's record of where the installed mythos-core came from, or None."""
    try:
        return importlib.metadata.distribution("mythos-core").read_text(
            "direct_url.json"
        )
    except importlib.metadata.PackageNotFoundError:
        return None
    except OSError:
        return None


def _dist_base() -> str | None:
    """The directory pip's metadata for mythos-core sits in, or None.

    For an ordinary install the package is beside the ``.dist-info``; for an
    editable one it is not, which is why this is one candidate and not the test.
    """
    try:
        return str(importlib.metadata.distribution("mythos-core").locate_file(""))
    except (importlib.metadata.PackageNotFoundError, OSError, AttributeError):
        return None


def _imported_file() -> str | None:
    """Where Python actually loads ``mythos_core`` from, or None.

    A real import, because that is the whole point: every other input to this
    guard comes from metadata, and metadata is what a shadowing checkout leaves
    untouched. Broad except on purpose -- any failure to import means the guard
    cannot show the pinned core was loaded, which `shadow_complaint` reports
    rather than swallowing.
    """
    try:
        module = importlib.import_module("mythos_core")
    except BaseException:  # noqa: BLE001 - see docstring
        return None
    path = getattr(module, "__file__", None)
    return str(path) if path else None


def enforce_dependency_pins() -> None:
    """Refuse to run the suite against a mythos-core that is not the pinned one.

    This aborts the session instead of failing a test, because the failure is not
    about any one test: every result in the run is measured against a foundation
    the repo did not ask for. One legible line beats several hundred tracebacks
    pointing anywhere but the cause.

    It runs before `django.setup()` below for the same reason -- the drift shows
    up as import-time explosions once Django starts pulling the app in.
    NOT A ``pytest_sessionstart`` HOOK ANY MORE, and that is the whole point of
    this function existing under its own name.

    ``pytest_sessionstart`` fires after every conftest has been IMPORTED (and
    after ``pytest_configure``). A wrong pinned dependency does not politely
    wait for that: it breaks the imports at the top of this very file, pytest
    reports a conftest ImportError, and the hook written to explain exactly this
    failure is the one thing that never runs. Reproduced in Athena-Engine with a
    `mythos_core` on `PYTHONPATH` that lacks what the engine imports::

        ImportError while loading conftest '.../tests/conftest.py'
        E   ImportError: cannot import name 'pinned_dns' from 'mythos_core.http'

    A reader sees a missing symbol and goes looking for a bug in the engine. The
    guard knew: it had the pinned commit, the loaded path, the remedy and the
    opt-out, and said none of it. Minotaur-Engine hit the same shape for real --
    a checkout at one commit against a pin at another stopped collection
    entirely, and the guard could not report it.

    So it is called at IMPORT time, from the line below, above every import in
    this file that a wrong dependency can break.
    """
    if os.environ.get(OPT_OUT_ENV, "").strip().lower() in {"off", "0", "false", "no"}:
        # Loud on purpose, and on every run. See OPT_OUT_ENV.
        print(
            f"\n*** {OPT_OUT_ENV}=off: the mythos-core pin guard is DISABLED for "
            "this run. Results are not evidence about the pinned core. ***\n",
            file=sys.stderr,
        )
        return

    try:
        pin = declared_pin((ROOT / "requirements.txt").read_text())
    except OSError:
        pin = None

    found = provenance_from_direct_url(_installed_direct_url())
    problems = []
    grievance = complaint(pin, found)
    if grievance:
        problems.append(grievance + "\n  " + remedy(found))

    # Asked separately, and asked even when the pin matched: every check above this
    # line reads pip's metadata, and a checkout earlier on sys.path satisfies all of
    # them while Python loads something else entirely. This module's own docstring
    # is about "what is actually imported"; nothing in it looked at the import.
    shadow = shadow_complaint(_imported_file(), found, dist_base=_dist_base())
    if shadow:
        problems.append(shadow)

    if not problems:
        return

    raise pytest.UsageError("mythos-core pin guard: " + "\n".join(problems))


# Run the guard HERE, at conftest import, before the imports below.
#
# The ordering is load-bearing, not tidiness: a wrong pinned dependency breaks
# those imports, and anything scheduled for later -- a pytest hook, a fixture,
# a test -- never runs to say why. `enforce_dependency_pins` explains this at
# length, and `test_the_guard_runs_before_the_imports_it_is_about` pins the
# ordering so it cannot be undone by a later tidy-up of this file.
enforce_dependency_pins()

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
