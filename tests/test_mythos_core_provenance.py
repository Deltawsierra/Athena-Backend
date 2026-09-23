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

import pathlib

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

    # The faked provenance says "installed from git", which puts the package in
    # site-packages; the real environment has an editable checkout elsewhere. So the
    # import location has to be faked consistently, or this test asserts silence
    # against an input no real install produces -- and the new shadow check rightly
    # complains about it. `shadow_complaint` has its own tests below; this one is
    # about the pin match.
    monkeypatch.setattr(
        tests_conftest,
        "_imported_file",
        lambda: str(
            pathlib.Path(tests_conftest._dist_base()) / "mythos_core" / "__init__.py"
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


# ---------------------------------------------------------------------------
# The question the guard never asked: where did the module actually come from?
#
# Everything above reads pip's `direct_url.json`. That is pip's RECORD of where it
# put a distribution, and it is not the module Python imports. The two are found by
# independent searches -- `importlib.metadata` looks for a `*.dist-info` directory
# on sys.path, `import mythos_core` looks for a `mythos_core` package -- so any
# directory carrying the package and no dist-info wins the second without touching
# the first.
#
# Demonstrated across every repo sharing this guard, with one environment variable:
# with PYTHONPATH pointing at a checkout of the PREVIOUS pin (missing the
# Mythos-Core #25 egress fix), `import mythos_core` loaded that checkout and every
# suite passed with the pin guard silent. No file edited, no metadata forged, no
# opt-out set.
# ---------------------------------------------------------------------------

from tests.mythos_core_provenance import shadow_complaint  # noqa: E402


def _vcs(location="https://github.com/o/r", commit="a" * 40):
    return Provenance(kind="vcs", commit=commit, location=location)


def _local(location):
    return Provenance(kind="local", commit="a" * 40, location=location)


def test_a_core_loaded_from_beside_its_metadata_is_the_pinned_one():
    """The ordinary install: the package sits next to the `.dist-info`. This is the
    control -- a check that complained here would refuse every normal run."""
    assert (
        shadow_complaint(
            "/srv/site-packages/mythos_core/__init__.py",
            _vcs(),
            dist_base="/srv/site-packages",
        )
        is None
    )


def test_an_editable_install_may_load_from_its_checkout():
    """An editable install deliberately leaves the package OUTSIDE site-packages,
    at the path the `.pth` names. Refusing that would refuse the normal development
    setup and the guard would be turned off in its first week."""
    assert (
        shadow_complaint(
            "/work/core/src/mythos_core/__init__.py",
            _local("/work/core"),
            dist_base="/srv/site-packages",
        )
        is None
    )


def test_a_core_loaded_from_somewhere_else_entirely_is_a_complaint():
    """The finding. Neither beside the metadata nor inside the recorded checkout."""
    grievance = shadow_complaint(
        "/tmp/some-other-checkout/src/mythos_core/__init__.py",
        _local("/work/core"),
        dist_base="/srv/site-packages",
    )
    assert grievance is not None
    # It has to name all three, or nobody can act on it.
    assert "/tmp/some-other-checkout/src/mythos_core/__init__.py" in grievance
    assert "/work/core" in grievance
    assert "/srv/site-packages" in grievance
    assert "PYTHONPATH" in grievance


def test_a_vcs_url_is_not_offered_as_a_filesystem_candidate():
    """A VCS provenance's `location` is a URL. Treating it as a path would have
    `pathlib` resolve it against the CWD -- `./https:/github.com/o/r` -- and a
    module could then be "inside" it by accident of where pytest was run."""
    grievance = shadow_complaint(
        "/tmp/elsewhere/mythos_core/__init__.py",
        _vcs(location="https://github.com/o/r"),
        dist_base="/srv/site-packages",
    )
    assert grievance is not None
    assert "https://github.com/o/r" not in grievance


def test_a_sibling_directory_with_a_shared_prefix_is_not_inside():
    """`/srv/core-evil` is not inside `/srv/core`. A bare `startswith` would say it
    was, and a shadow one directory over would pass as the pinned install."""
    assert (
        shadow_complaint(
            "/srv/core-evil/src/mythos_core/__init__.py",
            _local("/srv/core"),
            dist_base=None,
        )
        is not None
    )


def test_a_core_that_cannot_be_imported_at_all_is_a_complaint():
    """`None` means the import produced no file. The distribution is recorded as
    installed and the code cannot be shown to have loaded, which is exactly the
    state this module calls a finding rather than a default."""
    grievance = shadow_complaint(None, _vcs())
    assert grievance is not None
    assert "import mythos_core" in grievance


def test_nothing_to_compare_against_is_not_a_second_verdict():
    """With no dist_base and a URL-only location there is no candidate path.
    `complaint` already reports an unestablished provenance; saying it again here in
    different words would make one problem look like two."""
    assert (
        shadow_complaint(
            "/anywhere/mythos_core/__init__.py",
            _vcs(location="https://github.com/o/r"),
            dist_base=None,
        )
        is None
    )


def test_the_session_hook_catches_a_shadow_the_metadata_cannot_see():
    """End to end through the real hook, with the pin matching perfectly.

    This is the shape that shipped: provenance correct, pin correct, complaint
    None -- and the core coming from somewhere else. The hook must still abort.
    """
    import os

    from tests.mythos_core_provenance import declared_pin

    ct = tests_conftest
    pin = declared_pin((ct.ROOT / "requirements.txt").read_text())

    saved = {
        "direct_url": ct._installed_direct_url,
        "imported_file": ct._imported_file,
        "dist_base": ct._dist_base,
        "env": os.environ.get("ATHENA_MYTHOS_CORE_PIN_GUARD"),
    }
    os.environ.pop("ATHENA_MYTHOS_CORE_PIN_GUARD", None)
    ct._installed_direct_url = lambda: (
        '{"url": "https://h/r", "vcs_info": {"vcs": "git", '
        f'"commit_id": "{pin}", "requested_revision": "{pin}"}}}}'
    )
    ct._dist_base = lambda: "/srv/site-packages"
    ct._imported_file = lambda: "/tmp/a-shadow/mythos_core/__init__.py"
    try:
        with pytest.raises(pytest.UsageError) as refusal:
            ct.pytest_sessionstart(session=None)
        assert "shadowing" in str(refusal.value)
        assert "/tmp/a-shadow/mythos_core/__init__.py" in str(refusal.value)
    finally:
        ct._installed_direct_url = saved["direct_url"]
        ct._imported_file = saved["imported_file"]
        ct._dist_base = saved["dist_base"]
        if saved["env"] is not None:
            os.environ["ATHENA_MYTHOS_CORE_PIN_GUARD"] = saved["env"]

