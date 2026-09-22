"""The suite must know when it is testing a mythos-core the repo did not pin.

The case that motivated this: an editable install of a developer checkout shadowed
the pin, the checkout was parked on a commit predating a keyword argument the
backend passes, and the run produced 174 failures whose real cause appeared in
none of them. The run was not *wrong* about those tests -- it simply was not
measuring the software the repo describes, and said nothing about that.

So the property under test throughout is: **an absence of knowledge never reads
as agreement.** A provenance that could not be established is a finding, not a
pass, and the tests below enumerate the shapes that absence can take rather than
spot-checking the one that happened to occur.
"""

from __future__ import annotations

import pytest

from tests import conftest as tests_conftest
from tests.mythos_core_provenance import (
    OPT_OUT_ENV,
    Provenance,
    complaint,
    declared_pin,
    provenance_from_direct_url,
    remedy,
)

PIN = "5bb35e266a436e99430aff3cce9e3b5e1f90a749"
OTHER = "2710605ba57a0000000000000000000000000000"


# ---------------------------------------------------------------------------
# Reading the declared pin
# ---------------------------------------------------------------------------


def test_the_pin_is_read_from_a_requirements_line():
    text = "django==5.0\nmythos-core @ git+https://github.com/x/y@" + PIN + "\n"
    assert declared_pin(text) == PIN


def test_no_pin_line_reads_as_none_not_as_a_match():
    assert declared_pin("django==5.0\n") is None


# ---------------------------------------------------------------------------
# Establishing what is installed
# ---------------------------------------------------------------------------


def _direct_url(payload: str) -> Provenance:
    return provenance_from_direct_url(payload, git=lambda *a, **k: None)


def test_a_git_install_yields_the_resolved_commit():
    found = _direct_url(
        '{"url": "https://github.com/x/y", "vcs_info": {"vcs": "git", '
        '"commit_id": "' + PIN + '"}}'
    )

    assert found.kind == "vcs"
    assert found.commit == PIN


def test_an_editable_checkout_is_read_from_its_git_head():
    calls = []

    def fake_git(repo, *args):
        calls.append(args)
        return PIN if args[0] == "rev-parse" else ""

    found = provenance_from_direct_url(
        '{"url": "file:///home/user/mythos-core", "dir_info": {"editable": true}}',
        git=fake_git,
    )

    assert found.kind == "local"
    assert found.commit == PIN
    assert found.location == "/home/user/mythos-core"
    assert not found.dirty
    # The working tree is consulted, not just HEAD -- see the dirty test below.
    assert ("status", "--porcelain") in calls


def test_an_editable_checkout_with_uncommitted_changes_is_marked_dirty():
    found = provenance_from_direct_url(
        '{"url": "file:///src/mythos-core", "dir_info": {"editable": true}}',
        git=lambda repo, *args: PIN if args[0] == "rev-parse" else " M src/x.py",
    )

    assert found.dirty is True


# ---------------------------------------------------------------------------
# The property: not knowing is never agreeing
# ---------------------------------------------------------------------------


UNKNOWABLE = {
    "no direct_url.json at all": None,
    "unparseable json": "{not json",
    "json that is not an object": '["a list"]',
    "a vcs install with no commit recorded": '{"url": "https://x/y", "vcs_info": {"vcs": "git"}}',
    "a local path that is not a git checkout": '{"url": "file:///src/x", "dir_info": {}}',
    "somewhere this guard does not recognise": '{"url": "https://example.invalid/x.whl"}',
}


@pytest.mark.parametrize("label", sorted(UNKNOWABLE))
def test_every_unknowable_provenance_reports_no_commit_and_says_why(label):
    """Enumerated, not spot-checked: each of these is a distinct way for pip's
    record to tell us nothing, and any one of them silently returning a commit
    would let the comparison below pass against a package nobody identified."""
    found = _direct_url(UNKNOWABLE[label])

    assert found.commit is None, label
    assert found.why, f"{label}: a provenance with no commit must say what stopped it"


@pytest.mark.parametrize("label", sorted(UNKNOWABLE))
def test_an_unestablished_provenance_is_a_complaint_not_a_pass(label):
    """The whole point. If this returned None for any of these, a run against an
    unidentifiable mythos-core would report exactly what a correct one does."""
    grievance = complaint(PIN, _direct_url(UNKNOWABLE[label]))

    assert grievance is not None, label
    assert "proves nothing" in grievance


# ---------------------------------------------------------------------------
# The comparison
# ---------------------------------------------------------------------------


def test_the_pinned_commit_installed_from_git_is_the_only_silent_case():
    assert complaint(PIN, Provenance(kind="vcs", commit=PIN)) is None


def test_a_different_commit_is_named_in_full_on_both_sides():
    grievance = complaint(
        PIN, Provenance(kind="vcs", commit=OTHER, location="https://x/y")
    )

    assert grievance is not None
    # Both halves, because "mythos-core is wrong" sends the reader nowhere.
    assert OTHER[:12] in grievance
    assert PIN[:12] in grievance


def test_an_editable_mismatch_explains_that_it_shadows_the_pin():
    """The detail that cost the time: a reinstall does not fix an editable
    install, so "reinstall the requirements" is advice that silently does
    nothing. The message has to say so."""
    grievance = complaint(
        PIN, Provenance(kind="local", commit=OTHER, location="/home/user/mythos-core")
    )

    assert "shadows the pin" in grievance
    assert "/home/user/mythos-core" in grievance


def test_the_right_commit_with_a_dirty_tree_is_still_not_that_commit():
    """A checkout at the pin plus uncommitted edits imports code that is no
    commit at all. Passing here would be the same silent zero one level down."""
    grievance = complaint(
        PIN, Provenance(kind="local", commit=PIN, location="/src/mc", dirty=True)
    )

    assert grievance is not None
    assert "uncommitted" in grievance


def test_a_repo_that_pins_nothing_cannot_check_anything_and_says_so():
    grievance = complaint(None, Provenance(kind="vcs", commit=PIN))

    assert grievance is not None
    assert "does not pin" in grievance


def test_the_remedy_names_the_checkout_and_the_opt_out():
    """A guard that only refuses gets deleted. Both escape routes are stated."""
    text = remedy(
        Provenance(kind="local", commit=OTHER, location="/home/user/mythos-core")
    )

    assert "/home/user/mythos-core" in text
    assert OPT_OUT_ENV in text


# ---------------------------------------------------------------------------
# The wiring: a guard nothing calls is not a guard
# ---------------------------------------------------------------------------


def test_the_session_hook_aborts_when_the_installed_core_is_not_the_pinned_one(
    monkeypatch,
):
    """`pytest_sessionstart` is the only thing that makes any of the above run.
    Without this test the module could be perfect and unreferenced -- which is
    the exact failure this repo keeps finding in its own controls."""
    monkeypatch.delenv(OPT_OUT_ENV, raising=False)
    monkeypatch.setattr(
        tests_conftest,
        "_installed_direct_url",
        lambda: (
            '{"url": "https://x/y", "vcs_info": {"vcs": "git", "commit_id": "'
            + OTHER
            + '"}}'
        ),
    )

    with pytest.raises(pytest.UsageError) as refusal:
        tests_conftest.pytest_sessionstart(session=None)

    assert "mythos-core pin guard" in str(refusal.value)
    assert OTHER[:12] in str(refusal.value)


def test_the_session_hook_is_silent_when_the_installed_core_is_the_pinned_one(
    monkeypatch,
):
    """The other half: a guard that refuses every run is not distinguishable from
    a broken one, and would be switched off within a day."""
    monkeypatch.delenv(OPT_OUT_ENV, raising=False)
    pin = tests_conftest.declared_pin(
        (tests_conftest.ROOT / "requirements.txt").read_text()
    )
    monkeypatch.setattr(
        tests_conftest,
        "_installed_direct_url",
        lambda: (
            '{"url": "https://x/y", "vcs_info": {"vcs": "git", "commit_id": "'
            + pin
            + '"}}'
        ),
    )

    assert tests_conftest.pytest_sessionstart(session=None) is None


@pytest.mark.parametrize("value", ["off", "0", "false", "no", "OFF", "  Off  "])
def test_the_opt_out_is_honoured_in_the_spellings_it_claims(value, monkeypatch):
    monkeypatch.setenv(OPT_OUT_ENV, value)
    monkeypatch.setattr(
        tests_conftest,
        "_installed_direct_url",
        lambda: (
            '{"url": "https://x/y", "vcs_info": {"vcs": "git", "commit_id": "'
            + OTHER
            + '"}}'
        ),
    )

    assert tests_conftest.pytest_sessionstart(session=None) is None


def test_an_unrecognised_opt_out_value_does_not_disable_the_guard(monkeypatch):
    """ "maybe" is not "off". A typo in the escape hatch must fail closed, or the
    guard is disabled by accident exactly when someone was trying to be careful."""
    monkeypatch.setenv(OPT_OUT_ENV, "maybe")
    monkeypatch.setattr(
        tests_conftest,
        "_installed_direct_url",
        lambda: (
            '{"url": "https://x/y", "vcs_info": {"vcs": "git", "commit_id": "'
            + OTHER
            + '"}}'
        ),
    )

    with pytest.raises(pytest.UsageError):
        tests_conftest.pytest_sessionstart(session=None)
