"""A test-only allowlist opts specific hosts past the backend's scope guard.

The backend refuses loopback and internal targets (``target_is_out_of_bounds``),
so the assurance flow cannot run against a deliberately vulnerable test target
(Minotaur) that is reachable only on loopback. An operator may name specific
hosts in the ``ATHENA_PENTEST_TEST_TARGETS`` environment variable -- a
comma-separated list of ``host`` or ``host:port`` entries -- to permit exactly
those. It is a testing affordance: EMPTY by default (so every check is unchanged
and loopback/internal stay refused), never widening scope for a host not named,
and every permitted target is logged.

These tests hold the shipped default behaviour (loopback and internal refused)
and pin the opt-in: only the listed host, only logged, never anything else.

Hermetic: the refusals are literal IPs (no DNS), and a permitted target returns
before any resolution, so nothing leaves the process.
"""

import logging

import pytest

from pentest import views

LOOPBACK = "http://127.0.0.1:8100/"


@pytest.fixture(autouse=True)
def _default_is_empty(monkeypatch):
    """Every test starts from the shipped default: the env var unset."""
    monkeypatch.delenv(views.TEST_TARGETS_ENV, raising=False)


def test_loopback_and_internal_are_refused_by_default():
    """With no allowlist (the default), the guard is exactly as before."""
    assert views.target_is_out_of_bounds(LOOPBACK)
    assert views.target_is_out_of_bounds("http://10.0.0.5/")
    assert views.target_is_out_of_bounds("http://169.254.169.254/")
    assert views.target_is_out_of_bounds("http://[::1]/")


def test_an_opted_in_host_port_is_permitted(monkeypatch):
    monkeypatch.setenv(views.TEST_TARGETS_ENV, "127.0.0.1:8100")
    assert views.target_is_out_of_bounds(LOOPBACK) is None


def test_an_opted_in_host_is_permitted_on_any_port(monkeypatch):
    monkeypatch.setenv(views.TEST_TARGETS_ENV, "127.0.0.1")
    assert views.target_is_out_of_bounds("http://127.0.0.1:8100/") is None
    assert views.target_is_out_of_bounds("http://127.0.0.1:9100/") is None


def test_a_host_not_on_the_allowlist_is_still_refused(monkeypatch):
    """The opt-in is exact: a different port, a different host, or another
    spelling of loopback that the operator did not list is refused as before."""
    monkeypatch.setenv(views.TEST_TARGETS_ENV, "127.0.0.1:8100")
    assert views.target_is_out_of_bounds("http://127.0.0.1:9999/")  # wrong port
    assert views.target_is_out_of_bounds("http://10.0.0.5/")        # other internal host
    assert views.target_is_out_of_bounds("http://[::1]/")           # loopback not listed


def test_the_allowlist_is_whitespace_and_case_tolerant(monkeypatch):
    monkeypatch.setenv(views.TEST_TARGETS_ENV, "  127.0.0.1:8100 , Minotaur.Local  ")
    assert views.target_is_out_of_bounds("http://127.0.0.1:8100/") is None
    assert views.target_is_out_of_bounds("http://minotaur.local/") is None


def test_a_blank_allowlist_changes_nothing(monkeypatch):
    monkeypatch.setenv(views.TEST_TARGETS_ENV, "   ,  , ")
    assert views.target_is_out_of_bounds(LOOPBACK)


def test_a_malformed_port_is_refused_not_opted_in(monkeypatch):
    """A host-only allowlist must not opt in a URL whose port cannot be parsed
    (``:99999``, ``:+80``, a non-ASCII digit): accessing the port raises, and the
    URL falls through to the guard, which refuses it -- it is never permitted."""
    monkeypatch.setenv(views.TEST_TARGETS_ENV, "127.0.0.1")
    for bad in ("http://127.0.0.1:99999/", "http://127.0.0.1:+80/", "http://127.0.0.1:8٠/"):
        assert views.target_is_out_of_bounds(bad), bad


def test_a_permitted_target_is_logged(monkeypatch, caplog):
    monkeypatch.setenv(views.TEST_TARGETS_ENV, "127.0.0.1:8100")
    with caplog.at_level(logging.WARNING, logger="pentest.views"):
        assert views.target_is_out_of_bounds(LOOPBACK) is None
    assert any(
        views.TEST_TARGETS_ENV in record.getMessage() for record in caplog.records
    ), "a permitted test target must be logged with the env var that permitted it"
