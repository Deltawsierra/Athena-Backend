"""
Settings for the test suite.

Reuses the real settings so the tests exercise the real permission classes,
serializers and querysets, and overrides only what a test run must not touch:
the database, the mail backend, and the outbound engine.
"""

import atexit
import os
import shutil
import sys
import tempfile

from django.core.exceptions import ImproperlyConfigured

os.environ.setdefault("DJANGO_DEBUG", "1")
os.environ.setdefault("DJANGO_SECRET_KEY", "test-secret-key-not-used-outside-tests")

from config.settings import *  # noqa: F401,F403

# The one name this file READS from the base settings rather than sets, imported
# explicitly beside the star. Relying on the star for a read is what F405 objects
# to, and it is right to: if the base settings ever stopped defining this, the
# override below would fail at import with a bare NameError and no hint that a
# setting had moved.
from config.settings import REST_FRAMEWORK as BASE_REST_FRAMEWORK

# A file, not ":memory:". The in-memory backend uses a shared cache, and a
# second thread writing to it raises "database table is locked" immediately
# rather than waiting, so the concurrency tests could not run at all. A file
# with WAL and a timeout behaves the way the deployed database does.
#
# ONE DIRECTORY PER PROCESS, and that is the whole point of the next few lines.
#
# This used to be a fixed name in the system temp directory. Every checkout,
# every worktree and every concurrent run on one machine therefore shared ONE
# database file. Two pytest processes would create, migrate and drop the same
# schema underneath each other, and the result was not a clean error: it was
# `sqlite3.OperationalError: disk I/O error`, `no such table:
# accounts_customuser`, and `Save with update_fields did not affect any rows`,
# scattered across whichever tests happened to be running. Measured here: 1415
# of 1418 tests errored in one worktree while another process held the file with
# `--create-db`; the same run alone was clean.
#
# That is worse than a slow suite. It reads as flaky concurrency tests, so the
# concurrency tests -- the ones this file went to a real file FOR -- are exactly
# the ones whose failures get waved away. Every thread in one run still shares
# one file, which is what those tests need; a second run cannot touch it.
#
# The `-wal` and `-shm` siblings live in the same directory, so one rmtree takes
# all three, and the directory name says who owns it.
_TEST_DB_DIR = tempfile.mkdtemp(prefix=f"athena-tests-{os.getpid()}-")
_TEST_DB = os.path.join(_TEST_DB_DIR, "cybersecurity_ai_platform_tests.sqlite3")
atexit.register(shutil.rmtree, _TEST_DB_DIR, True)

# `--reuse-db` cannot work with a per-process name: it would find no database to
# reuse, silently create a fresh one, and report nothing -- a flag that says it
# skipped the migrations while paying for them every time. Refuse instead of
# no-op. `--create-db` is unaffected and stays the way to force a rebuild.
if "--reuse-db" in sys.argv:
    raise ImproperlyConfigured(
        "--reuse-db cannot be honoured: the test database is named per process so "
        "two runs on one machine cannot corrupt each other (see tests/settings_test.py). "
        "There is nothing to reuse, and pretending otherwise would hide that. Drop the "
        "flag, or give the database a stable name and accept that a second concurrent "
        "run will destroy this one's schema."
    )

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": _TEST_DB,
        "TEST": {"NAME": _TEST_DB},
        # The same options the deployed database uses, so a locking problem
        # shows up here rather than only in production.
        "OPTIONS": DATABASES["default"]["OPTIONS"],  # noqa: F405
    }
}

# RequestFactory sends Host: testserver.
ALLOWED_HOSTS = ["*"]

EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
CYBERENGINE_URL = "http://127.0.0.1:8001"
CYBERENGINE_OPERATOR_KEY = "test-operator-key"

# The defender middleware makes an outbound call per request; the tests here
# drive views directly, but leave it in monitor mode regardless.
DEFENDER_MONITOR_ONLY = True

# Throttling would make the ordering of tests significant.
REST_FRAMEWORK = {
    **BASE_REST_FRAMEWORK,
    "DEFAULT_THROTTLE_RATES": {"anon": None, "user": None},
}
