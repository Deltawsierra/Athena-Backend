"""The shared pin guard is wired into this suite, and it bites.

Before a single test is collected, tests/conftest.py runs Mythos-Core's pin guard
(``mythos_core.pinguard``) through tests/pin_bootstrap.py: is the mythos-core this
interpreter imports exactly the commit requirements.txt and requirements-dev.txt
pin, from the install pip recorded? The guard's own checks are tested in Mythos-Core
(tests/test_pinguard.py and tests/test_pin_bootstrap.py, on Linux and on
windows-latest). What only this repository can get wrong is the wiring, so that is
what these four tests hold:

1. the guard runs above every import in the conftest that a wrong core can break,
   ``import django`` among them;
2. its roster names every git pin in this repository's pin files, in each file that
   holds one;
3. tests/pin_bootstrap.py is, byte for byte, the stub the installed guard pins;
4. end to end, through that stub and the installed guard, a pin the install is not
   at is refused, and this repository's own pins pass.

Nothing here sets a pin-guard switch, in this process or any other: the end-to-end
test hands the guard an empty environment of its own, so a switch in the caller's
environment can neither weaken it nor be needed by it.
"""

from __future__ import annotations

import ast
import hashlib
import pathlib
import re
import sys

import pytest

from tests import conftest
from tests.pin_bootstrap import enforce, load_guard

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFTEST = ROOT / "tests" / "conftest.py"
STUB = ROOT / "tests" / "pin_bootstrap.py"

#: Where the guard's call may be preceded by an import: the standard library, pytest
#: (whose UsageError is the refusal) and the stub itself, which is standard library
#: only. Everything else is something a wrong core can break before the guard speaks.
_ALLOWED_ABOVE_THE_GUARD = frozenset({"pytest", "tests.pin_bootstrap"})


def _runs_at_import(body):
    """Every statement that runs when the module is imported: function bodies do not."""
    for node in body:
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for field in ("body", "orelse", "finalbody", "handlers"):
            yield from _runs_at_import(getattr(node, field, ()) or ())


def _imports(tree):
    """(line, module) for every import the conftest makes while it is imported."""
    for node in _runs_at_import(tree.body):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name
        elif isinstance(node, ast.ImportFrom):
            yield node.lineno, "." * node.level + (node.module or "")


def _is_enforce(node) -> bool:
    return (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "enforce"
    )


def _guard_call_line(tree):
    """The line of ``PIN_GUARD = enforce(...)``, a statement of the module itself: not
    under an ``if``, a ``try`` or a function, where it could be kept from running."""
    calls = [node.lineno for node in ast.walk(tree) if _is_enforce(node)]
    top = [
        node.lineno
        for node in tree.body
        if isinstance(node, ast.Assign)
        and [getattr(target, "id", None) for target in node.targets] == ["PIN_GUARD"]
        and _is_enforce(node.value)
    ]
    assert len(calls) == 1 and top == calls, (
        f"expected one call of the pin guard's enforce, as the module-level statement "
        f"`PIN_GUARD = enforce(...)`; enforce is called at {calls}, and assigned to "
        f"PIN_GUARD at module level at {top}"
    )
    return top[0]


def _may_precede_the_guard(module: str) -> bool:
    return module in _ALLOWED_ABOVE_THE_GUARD or (
        not module.startswith(".") and module.split(".")[0] in sys.stdlib_module_names
    )


def test_the_guard_runs_above_every_import_a_wrong_core_can_break():
    """The ordering is the point. A guard that runs after ``import django`` (or after
    any import that pulls the app in) never runs when the core is wrong: the import
    fails first, naming a missing symbol in this repository, and the guard that knew
    why says nothing. So the call is above every import that is not the standard
    library, pytest or the stub, ``enforce`` is the stub's, never a name a
    ``mythos_core`` import supplied, and the call ran when the conftest was imported."""
    tree = ast.parse(CONFTEST.read_text(encoding="utf-8"))
    guard = _guard_call_line(tree)
    imports = list(_imports(tree))

    above = [
        (line, module)
        for line, module in imports
        if line < guard and not _may_precede_the_guard(module)
    ]
    assert not above, (
        f"these imports run before the pin guard at tests/conftest.py line {guard}, so a "
        f"wrong mythos-core breaks them first and the guard never says why: {above}"
    )

    binders = [
        (node.lineno, node.module, node.level)
        for node in _runs_at_import(tree.body)
        if isinstance(node, ast.ImportFrom)
        and any((alias.asname or alias.name) == "enforce" for alias in node.names)
    ]
    assert len(binders) == 1 and binders[0][1:] == ("tests.pin_bootstrap", 0), (
        f"enforce must come from tests.pin_bootstrap alone, and it is bound by {binders}"
    )
    assert binders[0][0] < guard

    # Not vacuous: there is something below the guard for it to protect, and
    # `import django`, which pulls the app and so the core in, is part of it.
    below = {module for line, module in imports if line > guard}
    assert "django" in below, (
        f"`import django` is not below the pin guard; below it: {sorted(below)}"
    )

    # And it ran, at import: the conftest holds its verdict, a line per roster entry.
    verdicts = [line for line in conftest.PIN_GUARD.lines if line.startswith("pin guard ")]
    assert len(verdicts) == len(conftest.PINNED_DEPENDENCIES), conftest.PIN_GUARD.lines


_GIT_PIN = re.compile(
    r"\s*(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*@\s*git\+"
)


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pin_files():
    """Every file pip could install this repository's Python dependencies from."""
    found = sorted(ROOT.glob("requirements*.txt"))
    for name in ("pyproject.toml", "setup.cfg", "setup.py"):
        if (ROOT / name).is_file():
            found.append(ROOT / name)
    return found


def test_the_roster_names_every_git_pin_in_every_file_that_holds_one():
    """A git pin the roster does not name is a dependency nothing checks, and a pin
    file the roster does not name for its distribution is a pin never compared with
    the others. Read here by a parser of this test's own, not the guard's, so the
    guard's reading is not the only one (the guard's own roster-complete check also
    refuses every run that breaks this)."""
    pinned: dict[str, set[str]] = {}
    for path in _pin_files():
        lines = path.read_text(encoding="utf-8-sig").splitlines()
        for number, line in enumerate(lines, start=1):
            if line.lstrip().startswith("#") or "git+" not in line.lower():
                continue
            match = _GIT_PIN.match(line)
            assert match, (
                f"{path.name} line {number} has a git+ URL that is not a "
                f"`name @ git+<url>@<sha>` requirement, so no roster entry can cover it: {line!r}"
            )
            pinned.setdefault(_normalise(match["name"]), set()).add(path.name)

    roster = {
        _normalise(distribution): set(files)
        for distribution, _module, files in conftest.PINNED_DEPENDENCIES
    }
    assert roster == pinned, (
        f"the pin guard's roster in tests/conftest.py is {roster}, but the pin files "
        f"git-pin {pinned}"
    )
    # Not vacuous: this repository git-pins mythos-core in both requirements files, and
    # the roster names both, so the guard also refuses the two drifting apart.
    assert pinned.get("mythos-core") == {"requirements.txt", "requirements-dev.txt"}, pinned


def test_the_stub_is_byte_for_byte_the_one_the_installed_guard_pins():
    """The installed guard is read from pip's hash-checked record of the install, and
    it pins the sha256 of the one stub every engine copies. A drifted copy, or a CRLF
    checkout of it on Windows, is a different sha256 and refuses every run, so the
    file is held to LF by .gitattributes too."""
    guard = load_guard()
    assert hashlib.sha256(STUB.read_bytes()).hexdigest() == guard.BOOTSTRAP_SHA256

    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    attributes = [line.strip() for line in attributes]
    assert "tests/pin_bootstrap.py text eol=lf" in attributes


class _Refused(Exception):
    """The refusal type this test asks the stub for, so nothing else can pass for it."""


def _the_pin() -> str:
    text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    found = re.findall(r"^mythos-core @ git\+\S+@([0-9a-f]{40})\s*$", text, re.M)
    assert len(found) == 1, found
    return found[0]


def _a_checkout_pinned_at(tmp_path: pathlib.Path, pin: str, other: str) -> pathlib.Path:
    """This repository's pin files, byte for byte but for one change: they pin ``other``."""
    for _distribution, _module, files in conftest.PINNED_DEPENDENCIES:
        for name in files:
            data = (ROOT / name).read_bytes()
            assert data.count(pin.encode()) == 1, name
            (tmp_path / name).write_bytes(data.replace(pin.encode(), other.encode()))
    return tmp_path


def test_an_install_that_is_not_at_the_pin_is_refused_end_to_end(tmp_path):
    """The real stub, the real guard it loads from the install this suite runs on, and
    this repository's own roster, the way tests/conftest.py calls them. Against this
    repository's pin files the install passes; against the same files pinning another
    commit it is refused, by the commit check alone, naming both commits. So the
    refusal is the pin's doing and nothing else's."""
    pin = _the_pin()
    other = format(int(pin, 16) ^ 1, "040x")  # a different full sha, one bit away

    verdict = enforce(ROOT, conftest.PINNED_DEPENDENCIES, environ={}, refusal=_Refused)
    assert verdict.ok, verdict.findings
    assert any(
        line.endswith(": OK") and f"pinned {pin[:7]}, imported {pin[:7]} from " in line
        for line in verdict.lines
    ), verdict.lines

    elsewhere = _a_checkout_pinned_at(tmp_path, pin, other)
    with pytest.raises(_Refused) as refused:
        enforce(elsewhere, conftest.PINNED_DEPENDENCIES, environ={}, refusal=_Refused)

    message = str(refused.value)
    assert message.startswith("pin guard: refused this run (1 finding(s)):"), message
    assert (
        f"[recorded-commit] the installed mythos-core is {pin}, but this repo pins {other}."
        in message
    ), message
    assert f"mythos-core pinned {other[:7]}, imported {pin[:7]} from " in message
    assert message.rstrip().endswith("REFUSED (1 finding(s))"), message
