"""The two mythos-core pins must name the same commit.

`requirements.txt` and `requirements-dev.txt` each pin mythos-core, and CI
installs one or the other depending on the job. Nothing made them agree. Two files
that can drift apart install two different foundations for the same service --
and the failure is silent in the worst way: the light job goes green against a
core the deployed job never sees, which is exactly the shape of "a check that
passed against something other than what shipped".

There is no test here that the pin is any *particular* commit. That would be a
constant restating a constant, green whenever someone edits both in the same
motion and useless otherwise. What can actually go wrong is the two drifting, and
that this file will catch.
"""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent

# `mythos-core @ git+https://...@<ref>` -- the ref is what must match. Deliberately
# tolerant of the URL's spelling (case, .git suffix, host) so a cosmetic edit to
# one file does not fail the suite; it is the resolved commit that decides what
# gets installed.
_PIN = re.compile(
    r"^\s*mythos-core\s*@\s*git\+(?P<url>[^@\s]+)@(?P<ref>\S+)\s*$",
    re.MULTILINE,
)


def _pins(name: str) -> list[str]:
    text = (ROOT / name).read_text()
    return [m.group("ref") for m in _PIN.finditer(text)]


def test_each_requirements_file_pins_mythos_core_exactly_once():
    """Zero matches would make the comparison below vacuous -- it would pass by
    finding nothing to compare. Two would mean pip resolves whichever it reads
    last, which is not a thing anyone should have to know."""
    for name in ("requirements.txt", "requirements-dev.txt"):
        assert len(_pins(name)) == 1, f"{name}: {_pins(name)}"


def test_the_runtime_and_dev_pins_are_the_same_commit():
    runtime = _pins("requirements.txt")[0]
    dev = _pins("requirements-dev.txt")[0]
    assert runtime == dev, (
        "requirements.txt and requirements-dev.txt pin different mythos-core "
        f"refs ({runtime} vs {dev}). The light CI job and the full one would "
        "install different foundations for the same service."
    )


def test_the_pin_is_an_immutable_commit_and_not_a_branch():
    """`@main` would make every install a different build of this service, and a
    mutable tag is the same hazard with a version number on it -- mythos-core's own
    v0.1.0 was moved once already."""
    for name in ("requirements.txt", "requirements-dev.txt"):
        ref = _pins(name)[0]
        assert re.fullmatch(r"[0-9a-f]{40}", ref), (
            f"{name} pins mythos-core at {ref!r}, which is not a full commit sha. "
            "A branch or tag can move under CI and under production separately."
        )
