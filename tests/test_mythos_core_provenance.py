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

import functools
import ntpath
import os
import pathlib
import posixpath

import pytest

from tests import conftest as tests_conftest
from tests.mythos_core_provenance import _content_differs as _differs
from tests.mythos_core_provenance import unwatched_paths as conftest_module_unwatched
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
        tests_conftest.enforce_dependency_pins()

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
        "_imported_locations",
        lambda: {
            "mythos_core.__file__": str(
                pathlib.Path(tests_conftest._dist_base()) / "mythos_core" / "__init__.py"
            ),
            "mythos_core.__path__[0]": str(
                pathlib.Path(tests_conftest._dist_base()) / "mythos_core"
            ),
        },
    )

    assert tests_conftest.enforce_dependency_pins() is None


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

    assert tests_conftest.enforce_dependency_pins() is None


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
        tests_conftest.enforce_dependency_pins()


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
            {"mythos_core.__file__": "/srv/site-packages/mythos_core/__init__.py"},
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
            {"mythos_core.__file__": "/work/core/src/mythos_core/__init__.py"},
            _local("/work/core"),
            dist_base="/srv/site-packages",
        )
        is None
    )


def test_a_core_loaded_from_somewhere_else_entirely_is_a_complaint():
    """The finding. Neither beside the metadata nor inside the recorded checkout."""
    grievance = shadow_complaint(
        {"mythos_core.__file__": "/tmp/some-other-checkout/src/mythos_core/__init__.py"},
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
        {"mythos_core.__file__": "/tmp/elsewhere/mythos_core/__init__.py"},
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
            {"mythos_core.__file__": "/srv/core-evil/src/mythos_core/__init__.py"},
            _local("/srv/core"),
            dist_base=None,
        )
        is not None
    )


def test_a_core_that_cannot_be_imported_at_all_is_a_complaint():
    """`None` means the import produced no file. The distribution is recorded as
    installed and the code cannot be shown to have loaded, which is exactly the
    state this module calls a finding rather than a default."""
    grievance = shadow_complaint({}, _vcs())
    assert grievance is not None
    assert "import mythos_core" in grievance


def test_nothing_to_compare_against_is_not_a_second_verdict():
    """With no dist_base and a URL-only location there is no candidate path.
    `complaint` already reports an unestablished provenance; saying it again here in
    different words would make one problem look like two."""
    assert (
        shadow_complaint(
            {"mythos_core.__file__": "/anywhere/mythos_core/__init__.py"},
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
        "imported_locations": ct._imported_locations,
        "dist_base": ct._dist_base,
        "env": os.environ.get("ATHENA_MYTHOS_CORE_PIN_GUARD"),
    }
    os.environ.pop("ATHENA_MYTHOS_CORE_PIN_GUARD", None)
    ct._installed_direct_url = lambda: (
        '{"url": "https://h/r", "vcs_info": {"vcs": "git", '
        f'"commit_id": "{pin}", "requested_revision": "{pin}"}}}}'
    )
    ct._dist_base = lambda: "/srv/site-packages"
    ct._imported_locations = lambda: {
        "mythos_core.__file__": "/tmp/a-shadow/mythos_core/__init__.py"
    }
    try:
        with pytest.raises(pytest.UsageError) as refusal:
            ct.enforce_dependency_pins()
        assert "shadowing" in str(refusal.value)
        assert "/tmp/a-shadow/mythos_core/__init__.py" in str(refusal.value)
    finally:
        ct._installed_direct_url = saved["direct_url"]
        ct._imported_locations = saved["imported_locations"]
        ct._dist_base = saved["dist_base"]
        if saved["env"] is not None:
            os.environ["ATHENA_MYTHOS_CORE_PIN_GUARD"] = saved["env"]


# ---------------------------------------------------------------------------
# WHEN the guard runs. A guard that runs too late is a guard that does not run.
# ---------------------------------------------------------------------------

#: Does this repo's conftest import anything a wrong pinned dependency can
#: break? Written down rather than inferred, so the ordering assertion below
#: cannot quietly become vacuous.
CONFTEST_HAS_BREAKABLE_IMPORTS = True
#:
#: True here: the conftest imports ``import django`` below the guard.


def _conftest_source() -> str:
    return pathlib.Path(tests_conftest.__file__).read_text()


def _module_level_imports(source: str):
    """Every module-level import in a source file, as (line, root module name)."""
    import ast

    for node in ast.parse(source).body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.lineno, node.module.split(".")[0]


def _guard_call_line(source: str) -> int:
    import ast

    lines = [
        node.lineno
        for node in ast.parse(source).body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and getattr(node.value.func, "id", None) == "enforce_dependency_pins"
    ]
    assert len(lines) == 1, f"expected exactly one module-level guard call, found {lines}"
    return lines[0]


def test_the_guard_runs_before_the_imports_it_is_about():
    """The ordering IS the fix, so the ordering is what this pins.

    The guard used to be a ``pytest_sessionstart`` hook, which fires only after
    every conftest has been imported and after ``pytest_configure``. A wrong
    pinned dependency breaks those imports first: pytest reports a conftest
    ImportError naming a missing symbol, and the guard written to explain
    exactly that failure never runs. Reproduced in Athena-Engine with a
    shadowing `mythos_core` on ``PYTHONPATH`` before the change:
    ``ImportError: cannot import name 'pinned_dns'``, and not one word about the
    pin. After: the guard's own diagnosis, naming the loaded path.

    So the call sits above every non-stdlib import in the conftest, and a later
    tidy-up that moves an import above it fails here rather than silently
    restoring the hole.
    """
    import sys

    source = _conftest_source()
    guard_line = _guard_call_line(source)
    # `pytest` and the pin module the guard itself needs are allowed above it;
    # everything else is something a wrong dependency can break.
    allowed = set(sys.stdlib_module_names) | {
        "pytest",
        "tests",
        "dependency_pins",
        "mythos_core_provenance",
    }
    above = [
        (line, module)
        for line, module in _module_level_imports(source)
        if line < guard_line and module not in allowed
    ]
    assert not above, (
        f"these imports run before the dependency pin guard at line {guard_line}, so a "
        f"wrong pinned dependency breaks them first and the guard never reports why: {above}"
    )
    below = [
        (line, module)
        for line, module in _module_level_imports(source)
        if line > guard_line and module not in allowed
    ]
    # Not vacuous by accident: whether there is anything below to protect is
    # asserted against what this repo declares, so deleting the last such import
    # fails here instead of turning the assertion above into a tautology.
    assert bool(below) == CONFTEST_HAS_BREAKABLE_IMPORTS, (
        f"CONFTEST_HAS_BREAKABLE_IMPORTS says {CONFTEST_HAS_BREAKABLE_IMPORTS}, "
        f"but the conftest's imports below the guard are {below}"
    )


_GUARD_MESSAGE = "dependency pin guard: the pinned dependency is not the installed one"

_BROKEN_IMPORT = (
    "raise ImportError(\"cannot import name 'pinned_dns' from 'mythos_core.http'\")\n"
)

_GUARD_FIRST = f'''import pytest


def enforce_dependency_pins():
    raise pytest.UsageError({_GUARD_MESSAGE!r})


enforce_dependency_pins()

{_BROKEN_IMPORT}'''

_GUARD_LAST = f'''import pytest

{_BROKEN_IMPORT}

def pytest_sessionstart(session):
    raise pytest.UsageError({_GUARD_MESSAGE!r})
'''


@pytest.mark.parametrize(
    "name,conftest_source,reaches_the_reader",
    [
        ("guard_first", _GUARD_FIRST, True),
        ("guard_after_the_import", _GUARD_LAST, False),
    ],
    ids=["guard_first", "guard_after_the_import"],
)
def test_only_a_guard_above_the_broken_import_reaches_the_reader(
    tmp_path, name, conftest_source, reaches_the_reader
):
    """End to end, in a real pytest subprocess, with the wrong order as a control.

    The ``guard_after_the_import`` case is not a leftover: it is the version this
    repo shipped, and it is here so that this test proves the ORDER does the
    work rather than merely that a guard exists. If both cases reported the
    guard's message, the reordering would be decorative.
    """
    import os
    import subprocess
    import sys

    project = tmp_path / name
    (project / "tests").mkdir(parents=True)
    (project / "tests" / "conftest.py").write_text(conftest_source)
    (project / "tests" / "test_x.py").write_text("def test_ok():\n    assert True\n")

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "-p", "no:cacheprovider"],
        cwd=project,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"},
    )
    output = result.stdout + result.stderr

    assert result.returncode != 0, "the run must not pass; it is measuring the wrong thing"
    assert (_GUARD_MESSAGE in output) is reaches_the_reader, output[:2000]
    if not reaches_the_reader:
        # What the reader gets instead: a missing symbol, pointing at the engine
        # rather than at the dependency.
        assert "cannot import name 'pinned_dns'" in output

# ---------------------------------------------------------------------------
# "Clean" must mean clean, not "git was told not to look"
# ---------------------------------------------------------------------------


def _repo(tmp_path, content="original\n"):
    """A one-commit git checkout, standing in for a pinned dependency."""
    import subprocess

    repo = tmp_path / "dep"
    repo.mkdir()

    def run(*args):
        subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            text=True,
        )

    run("init", "-q", ".")
    (repo / "f.py").write_text(content)
    run("add", "f.py")
    run("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-qm", "init")
    return repo


def test_an_ordinary_clean_checkout_flags_nothing():
    """The control. If every checkout looked unwatched, the check would say
    nothing about the one that is."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        repo = _repo(pathlib.Path(tmp))
        assert conftest_module_unwatched(repo) == ()


def test_a_modified_file_marked_assume_unchanged_is_reported():
    """The hole this closes.

    `git status --porcelain` is EMPTY for a file marked assume-unchanged, however
    thoroughly the file has been rewritten -- and so is `git diff-index --quiet
    HEAD`, which is what this fix first reached for. The bypass is the index, not
    the command.
    """
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        repo = _repo(pathlib.Path(tmp))
        (repo / "f.py").write_text("TAMPERED\n")
        subprocess.run(
            ["git", "-C", str(repo), "update-index", "--assume-unchanged", "f.py"],
            check=True,
            capture_output=True,
        )

        # The two commands a reader would trust, both silent:
        status = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain"],
            capture_output=True,
            text=True,
        )
        assert status.stdout.strip() == "", "the premise of this test no longer holds"
        assert (
            subprocess.run(
                ["git", "-C", str(repo), "diff-index", "--quiet", "HEAD"],
                capture_output=True,
            ).returncode
            == 0
        ), "the premise of this test no longer holds"

        # The guard is not:
        assert conftest_module_unwatched(repo) == ("f.py",)
        assert _differs(repo, "f.py") is True


def test_skip_worktree_hides_a_file_the_same_way_and_is_also_reported():
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        repo = _repo(pathlib.Path(tmp))
        (repo / "f.py").write_text("TAMPERED\n")
        subprocess.run(
            ["git", "-C", str(repo), "update-index", "--skip-worktree", "f.py"],
            check=True,
            capture_output=True,
        )
        assert conftest_module_unwatched(repo) == ("f.py",)
        assert _differs(repo, "f.py") is True


def test_an_unwatched_file_that_was_not_altered_is_still_a_complaint():
    """Reported even when the content happens to match.

    The bit means git has been told to stop looking, so from here on the guard
    cannot establish what is on disk. "Cannot establish" is a finding in this
    module, never a pass -- the same rule it applies to an unresolvable
    provenance.
    """
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        repo = _repo(pathlib.Path(tmp))
        subprocess.run(
            ["git", "-C", str(repo), "update-index", "--assume-unchanged", "f.py"],
            check=True,
            capture_output=True,
        )
        assert conftest_module_unwatched(repo) == ("f.py",)
        assert _differs(repo, "f.py") is False

        found = Provenance(kind="local", commit=PIN, location=str(repo), unwatched=("f.py",))
        message = complaint(PIN, found)
        assert message and "told not to watch" in message
        assert "no-assume-unchanged" in message


def test_an_altered_unwatched_file_is_named_as_altered_not_merely_unwatched():
    """The two states are different facts and get different sentences: one says
    the guard cannot tell, the other says it can and the answer is no."""
    found = Provenance(
        kind="local",
        commit=PIN,
        location="/srv/dep",
        unwatched=("a.py", "b.py"),
        unwatched_altered=("b.py",),
    )
    message = complaint(PIN, found)
    assert message and "have been altered while marked" in message
    assert "b.py" in message


def test_the_guard_does_not_write_to_the_checkout_it_judges():
    """`git update-index --really-refresh` DOES re-stat past the bit -- and it
    clears the bit and writes the dependency's index to do it. A read-only guard
    must not mutate what it is judging, and clearing the bit would destroy the
    evidence that someone set it. So the index must be byte-identical afterwards.
    """
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        repo = _repo(pathlib.Path(tmp))
        (repo / "f.py").write_text("TAMPERED\n")
        subprocess.run(
            ["git", "-C", str(repo), "update-index", "--assume-unchanged", "f.py"],
            check=True,
            capture_output=True,
        )
        before = (repo / ".git" / "index").read_bytes()

        conftest_module_unwatched(repo)
        _differs(repo, "f.py")

        assert (repo / ".git" / "index").read_bytes() == before, (
            "the guard wrote to the dependency's git index"
        )
        # ...and the bit is still there to be reported.
        listing = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "-v"],
            capture_output=True,
            text=True,
        ).stdout
        assert listing.startswith("h "), listing


# ---------------------------------------------------------------------------
# The guard checked the front door
#
# `shadow_complaint` verified the package's `__file__` and nothing else, while
# every test in this repo imports SUBMODULES of mythos_core. A package whose
# `__file__` is the pinned install and whose `__path__` is elsewhere passed, and
# then loaded each submodule from elsewhere. Found by an adversarial pass against
# the merged guard and reproduced end to end before being fixed.
# ---------------------------------------------------------------------------


def test_a_path_entry_outside_the_install_is_caught_even_when_the_file_is_right():
    """THE FINDING. `__file__` is the pinned install; `__path__` is not.

    This is the exact state the old guard passed. Every submodule import would
    have come from the attacker's directory while the guard reported nothing."""
    grievance = shadow_complaint(
        {
            "mythos_core.__file__": "/srv/site-packages/mythos_core/__init__.py",
            "mythos_core.__path__[0]": "/tmp/evil/mythos_core",
        },
        _vcs(),
        dist_base="/srv/site-packages",
    )
    assert grievance is not None, (
        "the package's __file__ was right and its __path__ was not, and the "
        "guard said nothing -- the defect this test exists for"
    )
    assert "__path__[0]" in grievance
    assert "/tmp/evil/mythos_core" in grievance
    assert "1 of 2" in grievance


def test_an_already_imported_submodule_from_elsewhere_is_caught():
    """A submodule loaded before the guard ran is the harm itself, not a route to
    it. A `.pth` or an early plugin can import one before pytest reaches conftest."""
    grievance = shadow_complaint(
        {
            "mythos_core.__file__": "/srv/site-packages/mythos_core/__init__.py",
            "mythos_core.__path__[0]": "/srv/site-packages/mythos_core",
            "mythos_core.http.__file__": "/tmp/evil/mythos_core/http.py",
        },
        _vcs(),
        dist_base="/srv/site-packages",
    )
    assert grievance is not None
    assert "mythos_core.http.__file__" in grievance


def test_every_stray_is_listed_not_just_the_first():
    """An operator who fixes the one location named and re-runs, only to be told
    about the next one, learns to distrust the message. All of them, once."""
    grievance = shadow_complaint(
        {
            "mythos_core.__file__": "/tmp/a/mythos_core/__init__.py",
            "mythos_core.__path__[0]": "/tmp/b/mythos_core",
            "mythos_core.http.__file__": "/tmp/c/mythos_core/http.py",
        },
        _vcs(),
        dist_base="/srv/site-packages",
    )
    assert grievance is not None
    assert "3 of 3" in grievance
    for stray in ("/tmp/a/mythos_core", "/tmp/b/mythos_core", "/tmp/c/mythos_core"):
        assert stray in grievance


def test_a_normal_package_with_its_path_beside_its_file_is_silent():
    """THE CONTROL. An ordinary install has `__path__` pointing at the package
    directory inside `dist_base`. If that complained, the guard would refuse every
    normal run and be switched off within a week."""
    assert (
        shadow_complaint(
            {
                "mythos_core.__file__": "/srv/site-packages/mythos_core/__init__.py",
                "mythos_core.__path__[0]": "/srv/site-packages/mythos_core",
                "mythos_core.http.__file__": "/srv/site-packages/mythos_core/http.py",
            },
            _vcs(),
            dist_base="/srv/site-packages",
        )
        is None
    )


def test_an_editable_installs_path_and_submodules_are_still_allowed():
    """The development setup, in full: package, path entry and submodules all
    inside the recorded checkout."""
    failsafe = "/work/core/src/mythos_core/failsafe/__init__.py"
    assert (
        shadow_complaint(
            {
                "mythos_core.__file__": "/work/core/src/mythos_core/__init__.py",
                "mythos_core.__path__[0]": "/work/core/src/mythos_core",
                "mythos_core.failsafe.__file__": failsafe,
            },
            _local("/work/core"),
            dist_base="/srv/site-packages",
        )
        is None
    )


def test_the_collector_reports_the_path_and_the_loaded_submodules(monkeypatch):
    """`_imported_locations` must actually gather the three kinds, against a real
    module object. A collector that returned only `__file__` would leave the check
    above with nothing to catch."""
    import sys
    import types

    package = types.ModuleType("mythos_core")
    package.__file__ = "/srv/pkg/__init__.py"
    package.__path__ = ["/srv/pkg", "/tmp/extra"]
    submodule = types.ModuleType("mythos_core.child")
    submodule.__file__ = "/tmp/evil/child.py"

    monkeypatch.setitem(sys.modules, "mythos_core", package)
    monkeypatch.setitem(sys.modules, "mythos_core.child", submodule)
    found = tests_conftest._imported_locations()

    assert found["mythos_core.__file__"] == "/srv/pkg/__init__.py"
    assert found["mythos_core.__path__[0]"] == "/srv/pkg"
    assert found["mythos_core.__path__[1]"] == "/tmp/extra", (
        "only the first __path__ entry was collected; a namespace package has "
        "several and every one is a place code comes from"
    )
    assert found["mythos_core.child.__file__"] == "/tmp/evil/child.py"


def test_a_sibling_package_name_is_not_mistaken_for_a_submodule(monkeypatch):
    """`mythos_core_extras` is not inside `mythos_core`. Collecting it would make
    an unrelated package's location a finding against this one."""
    import sys
    import types

    package = types.ModuleType("mythos_core")
    package.__file__ = "/srv/pkg/__init__.py"
    package.__path__ = ["/srv/pkg"]
    sibling = types.ModuleType("mythos_core_extras")
    sibling.__file__ = "/tmp/unrelated/__init__.py"

    monkeypatch.setitem(sys.modules, "mythos_core", package)
    monkeypatch.setitem(sys.modules, "mythos_core_extras", sibling)
    found = tests_conftest._imported_locations()

    assert not any("extras" in label for label in found), found


def test_the_hook_refuses_a_path_shadow_end_to_end():
    """Through the real hook, with the pin and the provenance both perfect and the
    package's own file in the right place -- the shape that passed before."""
    import os

    from tests.mythos_core_provenance import declared_pin

    ct = tests_conftest
    pin = declared_pin((ct.ROOT / "requirements.txt").read_text())

    saved = {
        "direct_url": ct._installed_direct_url,
        "imported_locations": ct._imported_locations,
        "dist_base": ct._dist_base,
        "env": os.environ.get("ATHENA_MYTHOS_CORE_PIN_GUARD"),
    }
    os.environ.pop("ATHENA_MYTHOS_CORE_PIN_GUARD", None)
    ct._installed_direct_url = lambda: (
        '{"url": "https://h/r", "vcs_info": {"vcs": "git", '
        f'"commit_id": "{pin}", "requested_revision": "{pin}"}}}}'
    )
    ct._dist_base = lambda: "/srv/site-packages"
    ct._imported_locations = lambda: {
        "mythos_core.__file__": "/srv/site-packages/mythos_core/__init__.py",
        "mythos_core.__path__[0]": "/tmp/a-path-shadow/mythos_core",
    }
    try:
        with pytest.raises(pytest.UsageError) as refusal:
            ct.enforce_dependency_pins()
        assert "__path__[0]" in str(refusal.value)
        assert "/tmp/a-path-shadow/mythos_core" in str(refusal.value)
    finally:
        ct._installed_direct_url = saved["direct_url"]
        ct._imported_locations = saved["imported_locations"]
        ct._dist_base = saved["dist_base"]
        if saved["env"] is not None:
            os.environ["ATHENA_MYTHOS_CORE_PIN_GUARD"] = saved["env"]


# ---------------------------------------------------------------------------
# The same questions, asked about Windows paths
#
# The guard runs at conftest import. Where it cannot recognise the pinned
# install it does not fail a test: it stops pytest before one is collected. It
# used to compare paths as strings with a hard-coded "/", so on Windows
# (`C:\...`, backslashes, either case) the genuine install was reported as a
# shadow and the suite could not start.
#
# CI runs on Linux. These hand the guard Windows-SPELLED paths and tell it to
# judge them by Windows rules (`ospath=ntpath`), which is the code path a Windows
# runner takes, so pinning it needs no Windows machine. Every case that must be
# accepted has a twin that must still be refused: a guard that stopped raising on
# Windows by also stopping to look would pass the first half of this section and
# fail the second.
# ---------------------------------------------------------------------------

from tests.mythos_core_provenance import _file_url_to_path, _under  # noqa: E402

WIN_MODULE = "mythos_core"
WIN_SITE = r"C:\Users\dsmit\venv\Lib\site-packages"
WIN_CHECKOUT = r"C:\Users\dsmit\Documents\Coding\Mythos-Core"
WIN_CHECKOUT_URL = "file:///C:/Users/dsmit/Documents/Coding/Mythos-Core"


@pytest.fixture
def windows_paths(monkeypatch):
    """Windows path RULES without a Windows filesystem.

    `ntpath.realpath` asks the disk what a path really is. On a Windows runner
    that would go looking for `C:\\Users\\dsmit` and `\\\\fileserver`, which are
    made up, so it is replaced by its pure-string half (`abspath`) -- which is also
    all a Linux runner has. The rules under test (separators, drive letters, case,
    UNC roots, `..`) are the same either way."""
    monkeypatch.setattr(ntpath, "realpath", ntpath.abspath)


def _win_pkg(root, *rest):
    return ntpath.join(root, WIN_MODULE, *rest)


def _win(locations, found, dist_base=WIN_SITE):
    return shadow_complaint(locations, found, dist_base=dist_base, ospath=ntpath)


# -- one directory, many spellings: all inside ---------------------------------

WINDOWS_INSIDE = {
    "the ordinary install": (
        r"C:\Users\dsmit\venv\Lib\site-packages\pkg\__init__.py",
        r"C:\Users\dsmit\venv\Lib\site-packages",
    ),
    "the same directory in another case": (
        r"C:\Users\dsmit\venv\Lib\site-packages\pkg\__init__.py",
        r"c:\USERS\DSmit\venv\lib\SITE-PACKAGES",
    ),
    "forward slashes on one side": (
        "C:/Users/dsmit/venv/Lib/site-packages/pkg/__init__.py",
        r"C:\Users\dsmit\venv\Lib\site-packages",
    ),
    "a trailing separator on the parent": (
        r"C:\Users\dsmit\venv\Lib\site-packages\pkg\__init__.py",
        "C:\\Users\\dsmit\\venv\\Lib\\site-packages\\",
    ),
    "doubled separators": (
        r"C:\Users\dsmit\\venv\Lib\\site-packages\pkg\__init__.py",
        r"C:\Users\dsmit\venv\Lib\site-packages",
    ),
    "a dot-dot that stays inside": (
        r"C:\Users\dsmit\venv\Lib\Scripts\..\site-packages\pkg\__init__.py",
        r"C:\Users\dsmit\venv\Lib\site-packages",
    ),
    "the directory itself": (
        r"C:\Users\dsmit\venv\Lib\site-packages",
        r"C:\Users\dsmit\venv\Lib\site-packages",
    ),
    "a UNC share": (
        r"\\fileserver\tools\site-packages\pkg\__init__.py",
        r"\\FILESERVER\Tools\site-packages",
    ),
}

WINDOWS_OUTSIDE = {
    "another directory entirely": (
        r"C:\Users\dsmit\Downloads\Mythos-Core\src\pkg\__init__.py",
        r"C:\Users\dsmit\venv\Lib\site-packages",
    ),
    "the same path on another drive": (
        r"D:\Users\dsmit\venv\Lib\site-packages\pkg\__init__.py",
        r"C:\Users\dsmit\venv\Lib\site-packages",
    ),
    "a sibling that shares a prefix": (
        r"C:\Users\dsmit\venv\Lib\site-packages-evil\pkg\__init__.py",
        r"C:\Users\dsmit\venv\Lib\site-packages",
    ),
    "a sibling that shares a prefix, differing in case": (
        r"C:\Users\dsmit\venv\Lib\SITE-PACKAGES-evil\pkg\__init__.py",
        r"C:\Users\dsmit\venv\Lib\site-packages",
    ),
    "a dot-dot that leaves": (
        r"C:\Users\dsmit\venv\Lib\site-packages\..\Evil\pkg\__init__.py",
        r"C:\Users\dsmit\venv\Lib\site-packages",
    ),
    "the parent of the parent": (
        r"C:\Users\dsmit\venv\Lib",
        r"C:\Users\dsmit\venv\Lib\site-packages",
    ),
    "another UNC server": (
        r"\\evil\tools\site-packages\pkg\__init__.py",
        r"\\fileserver\tools\site-packages",
    ),
    "another UNC share on the same server": (
        r"\\fileserver\evil\site-packages\pkg\__init__.py",
        r"\\fileserver\tools\site-packages",
    ),
    "a local path against a UNC parent": (
        r"C:\tools\site-packages\pkg\__init__.py",
        r"\\fileserver\tools\site-packages",
    ),
}


@pytest.mark.parametrize("case", WINDOWS_INSIDE)
def test_windows_spellings_of_one_directory_are_inside_it(case, windows_paths):
    child, parent = WINDOWS_INSIDE[case]
    assert _under(child, parent, ospath=ntpath), f"{child} is inside {parent}"


@pytest.mark.parametrize("case", WINDOWS_OUTSIDE)
def test_windows_paths_that_are_not_inside_are_refused(case, windows_paths):
    """The twin of the test above, case for case. A drive letter, a UNC share, a
    shared prefix and a `..` each look like containment to a careless comparison."""
    child, parent = WINDOWS_OUTSIDE[case]
    assert not _under(child, parent, ospath=ntpath), f"{child} is not inside {parent}"


def test_short_names_are_resolved_on_both_sides_before_comparing(
    windows_paths, monkeypatch
):
    """On Windows `realpath` is what turns `PROGRA~1` into `Program Files`; a
    comparison that skipped it would read one place as two (refusing the pinned
    install) or two as one. Stood in for here, because a Linux runner has no 8.3
    names: the property is that BOTH sides go through it, and that its answer
    decides."""
    expansions = {
        r"C:\PROGRA~1\CORE": r"C:\Program Files\Core",
        r"C:\EVIL~1": r"C:\evil",
    }
    real = ntpath.realpath

    def expanding(path):
        for short, long in expansions.items():
            if path.upper().startswith(short):
                path = long + path[len(short) :]
        return real(path)

    monkeypatch.setattr(ntpath, "realpath", expanding)

    assert _under(
        r"C:\PROGRA~1\Core\pkg\__init__.py", r"C:\Program Files\Core", ospath=ntpath
    )
    assert _under(r"C:\Program Files\Core\pkg", r"C:\PROGRA~1\Core", ospath=ntpath)
    assert not _under(r"C:\EVIL~1\pkg", r"C:\Program Files\Core", ospath=ntpath)


# -- the shadow check itself, in Windows spelling -------------------------------


def test_a_windows_install_beside_its_metadata_is_the_pinned_one(windows_paths):
    """THE CONTROL, and the state that stopped pytest from starting: the package
    file, its `__path__` entry and a submodule all inside site-packages."""
    assert (
        _win(
            {
                f"{WIN_MODULE}.__file__": _win_pkg(WIN_SITE, "__init__.py"),
                f"{WIN_MODULE}.__path__[0]": _win_pkg(WIN_SITE),
                f"{WIN_MODULE}.http.__file__": _win_pkg(WIN_SITE, "http.py"),
            },
            _vcs(),
        )
        is None
    )


@pytest.mark.parametrize("case", WINDOWS_INSIDE)
def test_the_shadow_check_accepts_every_windows_spelling_of_the_pinned_location(
    case, windows_paths
):
    child, parent = WINDOWS_INSIDE[case]
    assert _win({f"{WIN_MODULE}.__file__": child}, _vcs(), dist_base=parent) is None


@pytest.mark.parametrize("case", WINDOWS_OUTSIDE)
def test_the_shadow_check_still_refuses_a_windows_shadow(case, windows_paths):
    """THE FINDING, in Windows spelling. Not one of these may come back None."""
    child, parent = WINDOWS_OUTSIDE[case]
    grievance = _win({f"{WIN_MODULE}.__file__": child}, _vcs(), dist_base=parent)
    assert grievance is not None, f"{child} was let through as if inside {parent}"
    assert "shadowing" in grievance
    # Named as the path resolves, so the reader can act on it.
    assert ntpath.normpath(child) in grievance


def test_a_windows_path_entry_outside_the_install_is_caught_though_the_file_is_right(
    windows_paths,
):
    grievance = _win(
        {
            f"{WIN_MODULE}.__file__": _win_pkg(WIN_SITE, "__init__.py"),
            f"{WIN_MODULE}.__path__[0]": r"C:\Users\dsmit\AppData\Local\Temp\evil\pkg",
        },
        _vcs(),
    )
    assert grievance is not None
    assert "__path__[0]" in grievance
    assert "1 of 2" in grievance


def test_a_windows_submodule_loaded_from_elsewhere_is_caught(windows_paths):
    grievance = _win(
        {
            f"{WIN_MODULE}.__file__": _win_pkg(WIN_SITE, "__init__.py"),
            f"{WIN_MODULE}.__path__[0]": _win_pkg(WIN_SITE),
            f"{WIN_MODULE}.http.__file__": r"D:\evil\pkg\http.py",
        },
        _vcs(),
    )
    assert grievance is not None
    assert f"{WIN_MODULE}.http.__file__" in grievance
    assert "1 of 3" in grievance


def test_every_windows_stray_is_listed_not_just_the_first(windows_paths):
    grievance = _win(
        {
            f"{WIN_MODULE}.__file__": r"C:\a\pkg\__init__.py",
            f"{WIN_MODULE}.__path__[0]": r"D:\b\pkg",
            f"{WIN_MODULE}.http.__file__": r"\\c\share\pkg\http.py",
        },
        _vcs(),
    )
    assert grievance is not None
    assert "3 of 3" in grievance
    for stray in (r"C:\a\pkg", r"D:\b\pkg", r"\\c\share\pkg"):
        assert stray in grievance


# -- an editable install names its checkout by a file:// URL ----------------


def test_a_windows_editable_install_may_load_from_the_checkout_its_url_names(
    windows_paths,
):
    """The development setup on Windows: pip records `file:///C:/...`, and the
    package lives in that checkout rather than in site-packages."""
    assert (
        _win(
            {
                f"{WIN_MODULE}.__file__": ntpath.join(
                    WIN_CHECKOUT, "src", WIN_MODULE, "__init__.py"
                ),
                f"{WIN_MODULE}.__path__[0]": ntpath.join(
                    WIN_CHECKOUT, "src", WIN_MODULE
                ),
            },
            _local(WIN_CHECKOUT_URL),
        )
        is None
    )


@pytest.mark.parametrize(
    "where",
    [
        r"C:\Users\dsmit\Documents\Coding\Mythos-Core-old\src\pkg\__init__.py",
        r"C:\Users\dsmit\Documents\Coding\Other\src\pkg\__init__.py",
        r"D:\Users\dsmit\Documents\Coding\Mythos-Core\src\pkg\__init__.py",
        r"C:\Users\dsmit\Documents\Coding\Mythos-Core\..\Other\pkg\__init__.py",
    ],
    ids=["shared prefix", "another checkout", "another drive", "dot-dot out"],
)
def test_a_windows_module_beside_the_named_checkout_is_still_a_shadow(
    where, windows_paths
):
    grievance = _win({f"{WIN_MODULE}.__file__": where}, _local(WIN_CHECKOUT_URL))
    assert grievance is not None


def test_a_file_url_in_another_spelling_names_the_same_checkout(windows_paths):
    """Lower-case drive, a percent-escaped space: the URL is pip's, not the
    operator's, and pip escapes."""
    assert (
        _win(
            {f"{WIN_MODULE}.__file__": r"C:\Users\Jo Smith\Core\src\pkg\__init__.py"},
            _local("file:///c:/users/jo%20smith/core"),
        )
        is None
    )


def test_an_unreadable_file_url_offers_no_candidate_and_so_admits_nothing():
    """`file://` names no path. It used to become the empty path, which pathlib
    reads as the current directory -- so the CWD was a place the pinned package
    could live. Neither the CWD nor the raw text of the URL read as a path may
    stand in for it: fewer candidates is stricter, never looser."""
    for where in (
        os.path.join(os.getcwd(), "pkg", "__init__.py"),
        os.path.join(os.getcwd(), "file:", "pkg", "__init__.py"),
    ):
        grievance = shadow_complaint(
            {f"{WIN_MODULE}.__file__": where},
            _local("file://"),
            dist_base="/srv/site-packages",
        )
        assert grievance is not None, f"{where} was admitted by a URL that names no path"


FILE_URLS = [
    (ntpath, "file:///C:/Users/dsmit/dep", r"C:\Users\dsmit\dep"),
    (ntpath, "file:///c:/Users/dsmit/dep", r"C:\Users\dsmit\dep"),
    (ntpath, "file:///C:/Users/Jo%20Smith/dep", r"C:\Users\Jo Smith\dep"),
    (ntpath, "file://localhost/C:/dep", r"C:\dep"),
    (ntpath, "file://server/share/dep", r"\\server\share\dep"),
    (posixpath, "file:///srv/dep", "/srv/dep"),
    (posixpath, "file:///srv/my%20dep", "/srv/my dep"),
    (posixpath, "file://localhost/srv/dep", "/srv/dep"),
]


@pytest.mark.parametrize(("ospath", "url", "expected"), FILE_URLS)
def test_a_file_url_is_read_as_the_path_its_platform_spells(ospath, url, expected):
    assert _file_url_to_path(url, ospath=ospath) == expected


@pytest.mark.parametrize("ospath", [ntpath, posixpath], ids=["nt", "posix"])
@pytest.mark.parametrize("url", ["file://", "file://localhost"])
def test_a_file_url_naming_no_path_is_none_not_the_current_directory(ospath, url):
    assert _file_url_to_path(url, ospath=ospath) is None


def test_provenance_reads_a_windows_editable_checkout_from_its_url(windows_paths):
    seen = []

    def fake_git(repo, *args):
        seen.append(str(repo))
        return PIN if args[0] == "rev-parse" else ""

    found = provenance_from_direct_url(
        f'{{"url": "{WIN_CHECKOUT_URL}", "dir_info": {{"editable": true}}}}',
        git=fake_git,
        ospath=ntpath,
    )

    assert found.kind == "local"
    assert found.commit == PIN
    assert found.location == WIN_CHECKOUT, (
        "the URL's /C:/... was not turned into C:\\..."
    )
    assert seen and set(seen) == {WIN_CHECKOUT}


def test_provenance_from_a_file_url_that_names_no_path_is_unknown_not_a_pass(
    windows_paths,
):
    found = provenance_from_direct_url(
        '{"url": "file://", "dir_info": {"editable": true}}',
        git=lambda *a, **k: PIN,
        ospath=ntpath,
    )
    assert found.kind == "unknown"
    assert found.commit is None
    assert complaint(PIN, found) is not None


def test_a_windows_editable_install_end_to_end_from_the_json_pip_wrote(windows_paths):
    """pip's `direct_url.json` -> provenance -> shadow check, with nothing handed
    to the shadow check by the test but the two Windows strings pip and Python
    would each have produced."""
    found = provenance_from_direct_url(
        f'{{"url": "{WIN_CHECKOUT_URL}", "dir_info": {{"editable": true}}}}',
        git=lambda repo, *a: PIN if a[0] == "rev-parse" else "",
        ospath=ntpath,
    )
    inside = ntpath.join(WIN_CHECKOUT, "src", WIN_MODULE, "__init__.py")
    elsewhere = ntpath.join(
        r"C:\Users\dsmit\Downloads", "src", WIN_MODULE, "__init__.py"
    )

    assert _win({f"{WIN_MODULE}.__file__": inside}, found) is None
    assert _win({f"{WIN_MODULE}.__file__": elsewhere}, found) is not None


# -- POSIX is unchanged ---------------------------------------------------------


def test_posix_paths_are_still_judged_case_sensitively():
    """Windows folds case; POSIX does not, and must not start to. `/srv/Core` is
    a different directory from `/srv/core`."""
    grievance = shadow_complaint(
        {f"{WIN_MODULE}.__file__": f"/srv/Site-Packages/{WIN_MODULE}/__init__.py"},
        _vcs(),
        dist_base="/srv/site-packages",
        ospath=posixpath,
    )
    assert grievance is not None


def test_a_backslash_is_an_ordinary_character_in_a_posix_path():
    """`/srv/site-packages\\pkg` is ONE entry in `/srv`, a sibling of
    `site-packages`, not a directory inside it."""
    grievance = shadow_complaint(
        {
            f"{WIN_MODULE}.__file__": "/srv/site-packages\\"
            + WIN_MODULE
            + "\\__init__.py"
        },
        _vcs(),
        dist_base="/srv/site-packages",
        ospath=posixpath,
    )
    assert grievance is not None


def test_a_posix_drive_letter_is_just_a_directory_name():
    assert not _under("/srv/D:/core/pkg", "/srv/C:/core", ospath=posixpath)
    assert _under("/srv/C:/core/pkg", "/srv/C:/core", ospath=posixpath)


# -- through the real hook ------------------------------------------------------


def _windows_hook(monkeypatch, imported):
    """Wire the real `enforce_dependency_pins` to Windows-spelled inputs: pip's
    record, the dist-info directory and the imported locations. The pin matches
    perfectly, so the only thing left to decide is where the module came from."""
    monkeypatch.delenv(OPT_OUT_ENV, raising=False)
    pin = declared_pin(
        (tests_conftest.ROOT / "requirements.txt").read_text(encoding="utf-8")
    )
    monkeypatch.setattr(
        tests_conftest,
        "_installed_direct_url",
        lambda: (
            '{"url": "https://h/r", "vcs_info": {"vcs": "git", '
            f'"commit_id": "{pin}", "requested_revision": "{pin}"}}}}'
        ),
    )
    monkeypatch.setattr(tests_conftest, "_dist_base", lambda: WIN_SITE)
    monkeypatch.setattr(tests_conftest, "_imported_locations", lambda: imported)
    monkeypatch.setattr(
        tests_conftest,
        "shadow_complaint",
        functools.partial(shadow_complaint, ospath=ntpath),
    )


def test_the_hook_lets_a_windows_pinned_install_through(windows_paths, monkeypatch):
    """The sentence this PR exists for: on Windows the guard must not stop pytest
    from starting when the module IS the pinned one."""
    _windows_hook(
        monkeypatch,
        {
            f"{WIN_MODULE}.__file__": _win_pkg(WIN_SITE, "__init__.py"),
            f"{WIN_MODULE}.__path__[0]": _win_pkg(WIN_SITE),
        },
    )

    assert tests_conftest.enforce_dependency_pins() is None


def test_the_hook_still_refuses_a_windows_shadow(windows_paths, monkeypatch):
    """...and must still stop it when it is not. Same pin, same provenance."""
    _windows_hook(
        monkeypatch,
        {
            f"{WIN_MODULE}.__file__": _win_pkg(WIN_SITE, "__init__.py"),
            f"{WIN_MODULE}.__path__[0]": r"C:\Users\dsmit\AppData\Local\Temp\a-shadow\pkg",
        },
    )

    with pytest.raises(pytest.UsageError) as refusal:
        tests_conftest.enforce_dependency_pins()

    assert "shadowing" in str(refusal.value)
    assert r"C:\Users\dsmit\AppData\Local\Temp\a-shadow\pkg" in str(refusal.value)
