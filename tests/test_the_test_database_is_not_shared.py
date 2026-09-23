"""Two runs of this suite must not be able to destroy each other.

``tests/settings_test.py`` deliberately uses a real sqlite FILE rather than
``:memory:``, because the concurrency tests need WAL and a busy timeout and the
in-memory backend raises "database table is locked" instead of waiting. For a
long time that file had a FIXED name in the system temp directory, so every
checkout, every worktree and every concurrent run on one machine shared it.

Two pytest processes then created, migrated and dropped the same schema
underneath each other. The result was not a clean error. It was ``disk I/O
error``, ``no such table: accounts_customuser`` and ``Save with update_fields
did not affect any rows``, scattered across whichever tests happened to be
running -- which reads as flaky concurrency tests, so the concurrency tests were
exactly the ones whose failures got waved away. Measured: 1415 of 1418 tests
errored in one worktree while another process held the file with ``--create-db``;
the same run alone was clean.

A suite that cannot be trusted to say what it measured is worse than a slow one,
so the name is now per process. These tests are what keep it that way.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

from django.conf import settings

#: One fast, database-backed module, used as the payload for the concurrent runs
#: below. It has to touch the database -- a test that never opens a connection
#: would pass under the shared-file bug and prove nothing.
_PAYLOAD = "tests/test_assurance_unknowns.py"

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _pytest_env() -> dict:
    """A clean environment for a nested pytest, without this run's settings.

    ``DJANGO_SETTINGS_MODULE`` is deliberately NOT forwarded: ``pytest.ini``
    points the child at ``tests.settings_test``, and inheriting
    ``config.settings`` instead turns ``SECURE_SSL_REDIRECT`` on and makes every
    request in the child a 301.
    """
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"DJANGO_SETTINGS_MODULE", "PYTEST_CURRENT_TEST"}
    }
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.setdefault("DJANGO_SECRET_KEY", "nested-run-secret-key-not-used-outside-tests")
    return env


def test_the_test_database_is_named_for_this_process():
    """The property the whole file rests on, asserted directly.

    Not a proxy for it: the path itself has to carry this process's identity, or
    a second run lands on the same file.
    """
    name = str(settings.DATABASES["default"]["NAME"])
    assert str(os.getpid()) in name, name
    # And it is still a file on disk, not ":memory:" -- the concurrency tests
    # need a real file, so uniqueness must not have been bought by giving that up.
    assert name.endswith(".sqlite3"), name
    assert ":memory:" not in name


def test_reuse_db_is_refused_rather_than_silently_ignored():
    """A per-process name means there is nothing to reuse.

    ``--reuse-db`` would find no database, silently build a fresh one, and report
    nothing -- a flag that claims to skip the migrations while paying for them
    every time. The settings raise instead, and the message says why.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--reuse-db", "--collect-only", "-q", _PAYLOAD],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        env=_pytest_env(),
        timeout=300,
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0, output[-2000:]
    assert "--reuse-db cannot be honoured" in output, output[-2000:]


def test_two_concurrent_runs_do_not_destroy_each_other():
    """The regression test proper, and the one that fails on the old settings.

    Two real pytest processes over the same module at the same time. Measured
    against the fixed name, this does not merely error: both processes BLOCK on
    the sqlite lock and neither finishes. Ten minutes in, all three tests in this
    file had failed and this one was still waiting. A deadlock is the worst shape
    the defect takes, because a suite that hangs gets killed by a CI timeout and
    reported as "the runner died".

    So the wait is bounded well under any CI timeout, and a process that has not
    finished is killed and reported AS A HANG rather than raised as a
    ``TimeoutExpired`` error -- the hang is the finding, so the test has to be
    able to say so.

    Deliberately two full subprocesses rather than a simulation: the collision
    happened in the ``CREATE``/``DROP`` that pytest-django's own setup issues,
    which is the part a simulation would have to stub out and therefore the part
    that would stop being tested.
    """
    # The payload alone takes a couple of seconds; two at once, a few. This is
    # ~25x headroom for a slow runner and still fails inside a minute a side.
    per_process_timeout = 60

    procs = [
        subprocess.Popen(
            [sys.executable, "-m", "pytest", "--override-ini=addopts=", "-q", "-p",
             "no:cacheprovider", _PAYLOAD],
            cwd=_REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=_pytest_env(),
        )
        for _ in range(2)
    ]

    results = []
    for proc in procs:
        timed_out = False
        try:
            proc.wait(timeout=per_process_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            proc.wait(timeout=30)
        output = proc.stdout.read()
        proc.stdout.close()
        results.append((proc.returncode, output, timed_out))

    for index, (code, output, timed_out) in enumerate(results):
        assert not timed_out, (
            f"concurrent run {index} did not finish within {per_process_timeout}s. Two "
            f"runs of this suite on one machine are blocking on the same database file; "
            f"that is the defect this test exists for, and it deadlocks rather than "
            f"failing cleanly.\n{output[-3000:]}"
        )
        assert code == 0, (
            f"concurrent run {index} failed with exit {code}; two runs of this suite "
            f"on one machine must not be able to touch each other's database.\n"
            f"{output[-3000:]}"
        )
        # The specific corruption signatures, named so a future failure here is
        # recognisable as this defect returning rather than as a new flake.
        for signature in ("disk I/O error", "no such table", "did not affect any rows"):
            assert signature not in output, f"run {index} shows '{signature}'"
