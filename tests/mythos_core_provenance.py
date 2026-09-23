"""What mythos-core is actually imported, versus what this repo pins.

`test_mythos_core_pin.py` checks that the two requirements files agree with each
other. Nothing checked that the module Python actually imports is the one they
name, and the gap is not theoretical: a developer checkout installed with
``pip install -e`` shadows the pin permanently and silently. A run in that state
produced 174 failures whose real cause was one keyword argument that the pinned
commit has and the shadowing checkout did not -- 174 tracebacks pointing at
everything except the thing that was wrong.

The hazard is the one this codebase keeps naming: a local verification run that
disagrees with CI *and does not say so*. Green here then means nothing about
green there, and the direction of the error is the bad one -- the drifted core
can be missing a guard the pinned one has, and every test of that guard passes
vacuously because the code under test never loads.

So this reports three outcomes and never folds the third into the first:

- **match** -- the imported distribution resolves to the pinned commit.
- **drift** -- it resolves to something else, named in full.
- **unreadable** -- provenance could not be established at all, which is NOT a
  match. This repo installs mythos-core from a git pin in every environment it
  supports, so "I cannot tell what this is" is itself the finding.

Everything here is a pure function over injected inputs so it can be tested
without a drifted checkout to hand; `conftest.py` wires it to the session.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
from dataclasses import dataclass

#: Opt out for deliberate local mythos-core development. It announces itself on
#: every run rather than passing quietly: a guard you can silence invisibly is a
#: guard that is off, and nobody would know which runs it covered.
OPT_OUT_ENV = "ATHENA_MYTHOS_CORE_PIN_GUARD"

_PIN = re.compile(
    r"^\s*mythos-core\s*@\s*git\+(?P<url>[^@\s]+)@(?P<ref>\S+)\s*$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class Provenance:
    """Where the imported mythos-core came from, as far as it can be established.

    ``commit`` is None whenever it could not be resolved, and ``why`` then says
    what stopped it. A caller must not read ``commit is None`` as agreement.
    """

    kind: str  # "vcs" | "local" | "unknown"
    commit: str | None = None
    location: str = ""
    dirty: bool = False
    #: Tracked files git has been told not to watch, and whether any of them is
    #: actually altered. Separate from `dirty` because they are different facts:
    #: `dirty` is "git says this changed", `unwatched` is "git was told not to
    #: say". See `unwatched_paths` for why the second cannot be folded into the
    #: first.
    unwatched: tuple[str, ...] = ()
    unwatched_altered: tuple[str, ...] = ()
    why: str = ""


def declared_pin(text: str) -> str | None:
    """The commit a requirements file pins mythos-core at, or None."""
    match = _PIN.search(text)
    return match.group("ref") if match else None


def _git(repo: pathlib.Path, *args: str) -> str | None:
    try:
        done = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def unwatched_paths(repo: pathlib.Path, *, git=_git) -> tuple[str, ...]:
    """Tracked files git has been TOLD not to look at, in ``repo``.

    ``git update-index --assume-unchanged`` and ``--skip-worktree`` both make a
    modified file invisible to the commands that ask whether a checkout is clean.
    Measured, on a one-file repo with the file rewritten:

        git status --porcelain      ->  (empty)      # reads clean
        git diff-index --quiet HEAD ->  exit 0       # reads clean
        git ls-files -v             ->  "h f.py"     # the bit, still visible
        index blob vs worktree blob ->  differ       # the tamper, still visible

    So the bypass is the index, not the command, and swapping `status` for
    `diff-index` -- which is what this fix first tried -- changes nothing. The one
    command that re-stats past the bit is ``git update-index --really-refresh``,
    and it does so by CLEARING the bit and writing the dependency's index: a
    read-only guard must not mutate the checkout it is judging, and doing it would
    destroy the evidence that someone set the bit at all.

    So the bits are reported as themselves. A pinned dependency with a file git
    has been told to ignore is a checkout whose contents this guard CANNOT
    establish -- and "cannot establish" is a finding here, never a pass. That is
    the same rule the rest of this module applies to an unresolvable provenance.
    """
    listing = git(repo, "ls-files", "-v")
    if not listing:
        return ()
    flagged = []
    for line in listing.splitlines():
        # `-v` prefixes each path with a status letter. Upper case H is the
        # ordinary "cached" state; lower case means assume-unchanged, and S/s
        # mean skip-worktree. Anything that is not H is a file git was told to
        # stop watching.
        if len(line) > 2 and line[0] != "H" and line[1] == " ":
            flagged.append(line[2:])
    return tuple(sorted(flagged))


def _content_differs(repo: pathlib.Path, path: str, *, git=_git) -> bool:
    """Does ``path``'s worktree content differ from what the index records?

    Flag-blind on purpose: it compares blob hashes and never asks git whether the
    file is "modified", so an assume-unchanged bit cannot hide the answer. Used
    only on the handful of paths `unwatched_paths` flagged, because a hash per
    tracked file would be too slow to run on every suite start.
    """
    recorded = git(repo, "rev-parse", f":{path}")
    actual = git(repo, "hash-object", path)
    return bool(recorded) and bool(actual) and recorded != actual


def provenance_from_direct_url(raw: str | None, *, git=_git) -> Provenance:
    """Read pip's ``direct_url.json`` for the installed distribution.

    pip writes this for anything installed from a URL or a path (PEP 610). A git
    install carries ``vcs_info.commit_id``, which is the resolved commit and
    exactly what we want. A path install -- the editable developer checkout --
    carries only a directory, so the commit has to come from the checkout's own
    git HEAD, and an uncommitted edit there means the imported code is not any
    commit at all.
    """
    if raw is None:
        return Provenance(
            kind="unknown",
            why=(
                "the installed mythos-core has no direct_url.json, so pip did not "
                "record where it came from (it was not installed from the git pin)"
            ),
        )
    try:
        info = json.loads(raw)
    except (ValueError, TypeError):
        return Provenance(
            kind="unknown",
            why="the installed mythos-core has an unreadable direct_url.json",
        )
    if not isinstance(info, dict):
        return Provenance(
            kind="unknown",
            why="the installed mythos-core has an unreadable direct_url.json",
        )

    url = info.get("url") or ""
    vcs = info.get("vcs_info")
    if isinstance(vcs, dict):
        commit = vcs.get("commit_id")
        if isinstance(commit, str) and commit:
            return Provenance(kind="vcs", commit=commit, location=url)
        return Provenance(
            kind="unknown",
            location=url,
            why="installed from version control, but pip recorded no commit_id",
        )

    if isinstance(info.get("dir_info"), dict) or url.startswith("file://"):
        path = (
            pathlib.Path(url[len("file://") :]) if url.startswith("file://") else None
        )
        if path is None:
            return Provenance(
                kind="unknown",
                location=url,
                why="installed from a local path that could not be resolved",
            )
        head = git(path, "rev-parse", "HEAD")
        if head is None:
            return Provenance(
                kind="local",
                location=str(path),
                why=f"{path} is not a readable git checkout, so its commit is unknown",
            )
        status = git(path, "status", "--porcelain")
        unwatched = unwatched_paths(path, git=git)
        return Provenance(
            kind="local",
            commit=head,
            location=str(path),
            dirty=bool(status),
            unwatched=unwatched,
            unwatched_altered=tuple(
                name for name in unwatched if _content_differs(path, name, git=git)
            ),
        )

    return Provenance(
        kind="unknown",
        location=url,
        why="the installed mythos-core came from somewhere this guard does not recognise",
    )


def complaint(pin: str | None, found: Provenance) -> str | None:
    """The reason this run cannot be trusted against the pin, or None.

    None means the imported distribution *is* the pinned commit. Every other
    state returns text, including the states where nothing could be established:
    an unreadable provenance is not a passing one.
    """
    if pin is None:
        return (
            "requirements.txt does not pin mythos-core to a git commit, so there "
            "is nothing to check the imported package against"
        )

    if found.commit is None:
        return (
            f"the imported mythos-core cannot be traced to a commit, so this run "
            f"proves nothing about the pinned one ({pin[:12]}). "
            f"{found.why or 'no reason was recorded'}."
        )

    if found.commit != pin:
        where = found.location or "an unrecorded location"
        editable = (
            f"\n  It is an editable/local install from {where}, which shadows the "
            "pin permanently: pip will not replace it on a later install."
            if found.kind == "local"
            else f"\n  It was installed from {where}."
        )
        return (
            f"the imported mythos-core is commit {found.commit[:12]}, but this repo "
            f"pins {pin[:12]}.{editable}"
        )

    if found.dirty:
        return (
            f"the imported mythos-core is at the pinned commit {pin[:12]} but its "
            f"checkout at {found.location} has uncommitted changes, so the code "
            "being imported is not that commit."
        )

    if found.unwatched_altered:
        return (
            f"the imported mythos-core is at the pinned commit {pin[:12]}, and "
            f"{len(found.unwatched_altered)} file(s) in {found.location} have been "
            "altered while marked assume-unchanged or skip-worktree, so `git status` "
            f"reports the checkout clean and it is not: {', '.join(found.unwatched_altered[:5])}."
        )

    if found.unwatched:
        return (
            f"the imported mythos-core is at the pinned commit {pin[:12]}, but git has "
            f"been told not to watch {len(found.unwatched)} file(s) in {found.location} "
            "(assume-unchanged or skip-worktree), so this guard cannot establish that "
            f"what is on disk is that commit: {', '.join(found.unwatched[:5])}. Clear the "
            "bits with `git update-index --no-assume-unchanged --no-skip-worktree <path>`."
        )

    return None


def remedy(found: Provenance) -> str:
    """What to actually do about it. A guard that only says no gets switched off."""
    if found.kind == "local" and found.location:
        return (
            f"Either point the checkout back at the pin "
            f"(git -C {found.location} checkout <pinned sha>), or reinstall from it "
            f"(pip install --force-reinstall -r requirements-dev.txt). "
            f"To run anyway while working on mythos-core itself, set "
            f"{OPT_OUT_ENV}=off -- the opt-out announces itself on every run."
        )
    return (
        "Reinstall from the pin (pip install --force-reinstall -r requirements-dev.txt). "
        f"To run anyway, set {OPT_OUT_ENV}=off -- the opt-out announces itself on "
        "every run."
    )


# ---------------------------------------------------------------------------
# Where the module actually came from
#
# Everything above this line reads pip's `direct_url.json` -- pip's RECORD of
# where it put a distribution. That record is not the module Python imports, and
# the two are found by independent searches: `importlib.metadata` scans
# `sys.path` for a `*.dist-info` directory, while `import mythos_core` scans
# `sys.path` for a `mythos_core` package. Any directory carrying the package and
# no dist-info wins the second search without touching the first.
#
# A src-layout checkout on PYTHONPATH is exactly such a directory, and it defeats
# everything above with one environment variable -- no file edited, no metadata
# forged, no opt-out set. Demonstrated in hermes-engine: the suite went green
# against the PREVIOUS pin, missing an egress fix the current pin carries, and
# the guard printed nothing.
#
# This module's first sentence is "What is actually imported, versus what this
# repo pins", and its third says "Nothing checked that the module Python imports
# is the one the pin names". That was still true of this file.
# ---------------------------------------------------------------------------


def _under(child: str, parent: str) -> bool:
    """Is ``child`` inside ``parent``? Both already absolute and resolved.

    String prefixing with an explicit separator rather than `Path.is_relative_to`
    alone, so that ``/srv/core-evil`` is not read as living inside ``/srv/core``.
    """
    if child == parent:
        return True
    return child.startswith(parent.rstrip("/") + "/")


def shadow_complaint(
    module_file: str | None,
    found: Provenance,
    *,
    dist_base: str | None = None,
) -> str | None:
    """Why the imported module is not the one the provenance describes, or None.

    The question the rest of this file never asked. Two places the module may
    legitimately live, and a shadow is in neither:

    * ``dist_base`` -- the directory pip's own metadata sits in. For an ordinary
      install the package is right there beside the ``.dist-info``.
    * ``found.location`` -- the checkout a local or editable install points at.
      An editable install deliberately leaves the package OUTSIDE site-packages,
      so refusing that case would refuse the normal development setup.

    A VCS ``location`` is a URL, not a path, so it is not offered as a candidate;
    for that install shape ``dist_base`` is the answer and is sufficient.

    Returns None when there is nothing to compare against rather than inventing a
    verdict -- an unestablished provenance is already `complaint`'s finding, and
    reporting it twice in different words would make one problem look like two.
    """
    if module_file is None:
        return (
            "mythos-core is recorded as installed, but `import mythos_core` "
            "does not yield a module with a file on disk, so this run cannot be "
            "shown to have loaded the pinned code at all"
        )

    candidates = []
    if dist_base:
        candidates.append(str(pathlib.Path(dist_base).resolve()))
    if found.location and not found.location.startswith(("http://", "https://", "git+")):
        location = found.location
        if location.startswith("file://"):
            location = location[len("file://") :]
        candidates.append(str(pathlib.Path(location).resolve()))

    if not candidates:
        return None

    resolved = str(pathlib.Path(module_file).resolve())
    if any(_under(resolved, candidate) for candidate in candidates):
        return None

    return (
        f"pip records mythos-core at {' or '.join(candidates)}, but "
        f"`import mythos_core` loaded {resolved}, which is inside neither. "
        "Something earlier on sys.path is shadowing the pinned install -- most "
        "often a checkout on PYTHONPATH -- so the pin describes one copy of this "
        "dependency and the tests exercised another."
    )
