"""The advisory register (advisories.toml), read and checked.

Pure functions over injected inputs -- the register, what is installed, what the
repository declares -- so the check can be shown to fail without installing a
vulnerable version, and so CI needs no network: what is installed is read from
the environment's own metadata (`importlib.metadata`), what is declared from
this repository's requirement files.

A dependency is on an affected version when its installed version, or any
version a declared requirement admits, falls inside one of the advisory's
affected ranges. A declared requirement is judged by probing it with the
boundary versions of each range -- the range's own lower bounds, the version just
below each upper bound, and the oldest release -- so ``requests>=2.31`` admits
2.32.3 and fails against ``<2.32.4``, while ``requests>=2.32.4`` passes.
"""

from __future__ import annotations

import ast
import importlib.metadata
import re
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

_ID = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}")


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class Advisory:
    id: str
    dependencies: tuple[str, ...]
    summary: str
    affected: tuple[str, ...]
    fixed: tuple[str, ...]
    installed: bool
    use: str
    tests: tuple[str, ...]


def load(path: Path) -> list[Advisory]:
    data = tomllib.loads(path.read_text())
    out = []
    for entry in data.get("advisory", []):
        out.append(
            Advisory(
                id=entry["id"],
                dependencies=tuple(canonical(d) for d in entry["dependency"]),
                summary=entry["summary"],
                affected=tuple(entry["affected"]),
                fixed=tuple(entry["fixed"]),
                installed=bool(entry["installed"]),
                use=entry["use"],
                tests=tuple(entry["tests"]),
            )
        )
    return out


def malformed(advisories: Iterable[Advisory], root: Path) -> list[str]:
    """What is wrong with the register itself: an id that is not an advisory id,
    a fixed version inside the range it fixes, a range whose upper bound fixes
    nothing listed, or a named test that is not there."""
    problems = []
    for adv in advisories:
        if not _ID.fullmatch(adv.id):
            problems.append(f"{adv.id}: not a GHSA id")
        if not adv.dependencies or not adv.affected or not adv.fixed or not adv.tests:
            problems.append(f"{adv.id}: an entry needs dependencies, ranges, fixes and tests")
        ranges = [SpecifierSet(r) for r in adv.affected]
        for fixed in adv.fixed:
            if any(r.contains(Version(fixed), prereleases=True) for r in ranges):
                problems.append(f"{adv.id}: {fixed} is listed as fixed and is in an affected range")
        uppers = {s.version for r in ranges for s in r if s.operator in ("<", "<=")}
        if not uppers <= set(adv.fixed):
            problems.append(
                f"{adv.id}: affected ranges end at {sorted(uppers)}, fixed lists {adv.fixed}"
            )
        for test in adv.tests:
            file, _, name = test.partition("::")
            path = root / file
            if not path.is_file():
                problems.append(f"{adv.id}: {file} does not exist")
            elif not re.search(rf"^def {re.escape(name)}\(", path.read_text(), re.MULTILINE):
                problems.append(f"{adv.id}: {file} has no test {name}")
    return problems


def _predecessor(version: Version) -> Version:
    release = list(version.release)
    for i in range(len(release) - 1, -1, -1):
        if release[i] > 0:
            release[i] -= 1
            release[i + 1 :] = [999] * (len(release) - i - 1)
            return Version(".".join(str(part) for part in release))
    return Version("0")


def _bounds(specifiers: SpecifierSet) -> set[Version]:
    """The versions at the edges of `specifiers`: each bound, the version just
    below an exclusive upper bound, just above an exclusive lower one."""
    bounds: set[Version] = set()
    for spec in specifiers:
        try:
            bound = Version(spec.version.removesuffix(".*"))
        except InvalidVersion:
            continue
        if spec.operator in (">=", "==", "===", "~=", "<=", "!="):
            bounds.add(bound)
        if spec.operator == ">" or spec.operator == "!=":
            bounds.add(Version(f"{bound.base_version}.post1"))
        if spec.operator in ("<", "!="):
            bounds.add(_predecessor(bound))
    return bounds


def _probes(affected: SpecifierSet, admitted: SpecifierSet | None = None) -> list[Version]:
    """Versions inside `affected` -- and, given `admitted`, inside it too -- found
    at the edges of either. Two version ranges that overlap overlap at an edge of
    one of them, so an exact pin inside the affected range (``==2.31.0``) is
    found as well as a floor below its upper bound (``>=2.31``)."""
    probes = {Version("0.0.1"), *_bounds(affected)}
    if admitted is not None:
        probes |= _bounds(admitted)
    return sorted(
        v
        for v in probes
        if affected.contains(v, prereleases=True)
        and (admitted is None or admitted.contains(v, prereleases=True))
    )


def violations(
    advisories: Iterable[Advisory],
    installed: Mapping[str, str | None],
    declared: Mapping[str, list[str]],
) -> list[str]:
    """Every way the environment or the repository sits on an affected version.

    `installed` maps a canonical distribution name to its installed version, or
    None; `declared` maps it to the specifier strings this repository declares
    for it (an unversioned requirement is the empty string).
    """
    found = []
    for adv in advisories:
        ranges = [SpecifierSet(r) for r in adv.affected]
        for dep in adv.dependencies:
            version = installed.get(dep)
            if version is not None:
                if not adv.installed:
                    found.append(
                        f"{adv.id}: {dep} {version} is installed, and the register says "
                        "it is not a dependency: review its use against the advisory, "
                        "record it, and set installed = true"
                    )
                if any(r.contains(Version(version), prereleases=True) for r in ranges):
                    found.append(
                        f"{adv.id}: {dep} {version} is installed, inside {list(adv.affected)}; "
                        f"fixed in {list(adv.fixed)}"
                    )
            elif adv.installed:
                found.append(
                    f"{adv.id}: the register says {dep} is installed and it is not: "
                    "set installed = false if it was dropped"
                )
            for spec in declared.get(dep, []):
                admitted = SpecifierSet(spec)
                for r in ranges:
                    hit = next(iter(_probes(r, admitted)), None)
                    if hit is not None:
                        found.append(
                            f"{adv.id}: this repository declares {dep}{spec or ' (any version)'}, "
                            f"which admits {hit}, inside {r}; fixed in {list(adv.fixed)}"
                        )
    return found


def installed_versions(names: Iterable[str]) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for name in names:
        try:
            out[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            out[name] = None
    return out


class RequirementsUnreadable(Exception):
    """A requirement this repository declares could not be read, so what it admits
    cannot be judged. Raised rather than skipped: a register that passes a line it
    could not read passes the very line that lowers a pin."""


def _requirement(text: str) -> tuple[str, str] | None:
    """One requirement (no comment, no option) as (distribution, specifier), or
    None for a direct reference, which declares no range. InvalidRequirement for
    text that is not one."""
    req = Requirement(text)
    if req.url:
        return None
    return canonical(req.name), str(req.specifier)


#: An option line that names another file whose requirements count as declared
#: here: ``-r``/``--requirement`` and ``-c``/``--constraint``.
_INCLUDE = re.compile(r"(?:-r|--requirement|-c|--constraint)(?:\s*=\s*|\s+|(?=[^\s-]))(\S+)")
#: A per-requirement option pip reads after the requirement (``--hash=...``,
#: ``--config-settings ...``): it starts the first token that begins with ``--``.
_TRAILING_OPTIONS = re.compile(r"\s--\S.*$")
#: Where pip's comment starts: a ``#`` at the start of a line or after whitespace
#: (a ``#`` inside a URL's fragment is not one).
_COMMENT = re.compile(r"(?:^|\s)#.*$")


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Each line as pip reads it: comments dropped, then a line ending in ``\\``
    joined with the next. Numbered by the line it starts on."""
    out: list[tuple[int, str]] = []
    pending: list[str] = []
    start = 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = _COMMENT.sub("", raw).rstrip()
        if not pending:
            start = number
        if line.endswith("\\"):
            pending.append(line[:-1])
            continue
        pending.append(line)
        out.append((start, " ".join(part.strip() for part in pending).strip()))
        pending = []
    if pending:
        out.append((start, " ".join(part.strip() for part in pending).strip()))
    return out


def _requirements_file(path: Path, add, problems: list[str], seen: set[Path], root: Path) -> None:
    """Every requirement in a requirements or constraints file, following its
    ``-r`` and ``-c`` includes."""
    resolved = path.resolve()
    if resolved in seen:
        return
    seen.add(resolved)
    try:
        text = path.read_text()
    except OSError as exc:
        problems.append(f"{_shown(path, root)}: cannot be read ({type(exc).__name__})")
        return
    for number, line in _logical_lines(text):
        where = f"{_shown(path, root)}:{number}"
        if not line:
            continue
        include = _INCLUDE.fullmatch(line)
        if include:
            _requirements_file(path.parent / include.group(1), add, problems, seen, root)
            continue
        if line.startswith("-"):
            # Every other option (an index, a find-links, -e for an editable
            # checkout) names where to install from, not a version range.
            continue
        text = _TRAILING_OPTIONS.sub("", line).strip()
        try:
            add(_requirement(text))
        except InvalidRequirement:
            problems.append(f"{where}: {line!r} is not a requirement this check can read")


def _shown(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _setup_requirements(path: Path, root: Path) -> tuple[list[str], list[str]]:
    """``install_requires`` and ``extras_require`` from setup.py, read as Python
    (``ast``) and never run: (the requirement strings, what could not be read)."""
    shown = _shown(path, root)
    try:
        tree = ast.parse(path.read_text())
    except (OSError, SyntaxError) as exc:
        return [], [f"{shown}: cannot be read ({type(exc).__name__})"]
    names: dict[str, ast.expr] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                names[target.id] = node.value

    def strings(node: ast.expr, what: str) -> list[str]:
        if isinstance(node, ast.Name) and node.id in names:
            node = names[node.id]
        try:
            value = ast.literal_eval(node)
        except ValueError:
            problems.append(f"{shown}: {what} is not a literal this check can read")
            return []
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) for v in value):
            problems.append(f"{shown}: {what} is not a list of requirement strings")
            return []
        return list(value)

    found: list[str] = []
    problems: list[str] = []
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id == "setup")
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "setup")
        )
    ]
    if not calls:
        problems.append(f"{shown}: no setup() call to read")
    for call in calls:
        for keyword in call.keywords:
            if keyword.arg is None:
                problems.append(f"{shown}: setup() takes **arguments this check cannot read")
            elif keyword.arg == "install_requires":
                found.extend(strings(keyword.value, "install_requires"))
            elif keyword.arg == "extras_require":
                extras = keyword.value
                if isinstance(extras, ast.Name) and extras.id in names:
                    extras = names[extras.id]
                if not isinstance(extras, ast.Dict):
                    problems.append(f"{shown}: extras_require is not a dict this check can read")
                    continue
                for value in extras.values:
                    found.extend(strings(value, "an extras_require entry"))
    return found, problems


def declared_requirements(root: Path) -> dict[str, list[str]]:
    """Every version specifier this repository declares, by distribution: in
    requirements*.txt and constraints*.txt (with every file they include through
    ``-r`` or ``-c``, ``\\`` continuations joined and ``--hash`` options dropped),
    setup.py's ``install_requires`` and ``extras_require`` (read with ``ast``),
    and pyproject.toml's dependency lists. A direct reference (a git URL)
    declares no range. Anything that cannot be read raises
    RequirementsUnreadable, naming it."""
    found: dict[str, list[str]] = {}
    problems: list[str] = []

    def add(item: tuple[str, str] | None) -> None:
        if item is not None:
            found.setdefault(item[0], []).append(item[1])

    def add_text(text: str, where: str) -> None:
        try:
            add(_requirement(text))
        except InvalidRequirement:
            problems.append(f"{where}: {text!r} is not a requirement this check can read")

    seen: set[Path] = set()
    for path in sorted([*root.glob("requirements*.txt"), *root.glob("constraints*.txt")]):
        _requirements_file(path, add, problems, seen, root)
    setup = root / "setup.py"
    if setup.is_file():
        texts, unread = _setup_requirements(setup, root)
        problems.extend(unread)
        for text in texts:
            add_text(text, "setup.py")
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        project = tomllib.loads(pyproject.read_text()).get("project", {})
        for item in project.get("dependencies", []):
            add_text(item, "pyproject.toml")
        for extra in project.get("optional-dependencies", {}).values():
            for item in extra:
                add_text(item, "pyproject.toml")
    if problems:
        raise RequirementsUnreadable("\n".join(problems))
    return found
