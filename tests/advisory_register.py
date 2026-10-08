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
        uppers = {
            s.version for r in ranges for s in r if s.operator in ("<", "<=")
        }
        if not uppers <= set(adv.fixed):
            problems.append(f"{adv.id}: affected ranges end at {sorted(uppers)}, fixed lists {adv.fixed}")
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


def _probes(affected: SpecifierSet) -> list[Version]:
    probes = {Version("0.0.1")}
    for spec in affected:
        try:
            bound = Version(spec.version)
        except InvalidVersion:
            continue
        if spec.operator in (">=", "==", "~="):
            probes.add(bound)
        elif spec.operator == ">":
            probes.add(Version(f"{bound.base_version}.post1"))
        elif spec.operator in ("<", "<="):
            probes.add(_predecessor(bound) if spec.operator == "<" else bound)
    return sorted(v for v in probes if affected.contains(v, prereleases=True))


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
                    hit = next(
                        (v for v in _probes(r) if admitted.contains(v, prereleases=True)),
                        None,
                    )
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


def _requirement(text: str) -> tuple[str, str] | None:
    text = text.split("#", 1)[0].strip()
    if not text or text.startswith("-"):
        return None
    try:
        req = Requirement(text)
    except InvalidRequirement:
        return None
    if req.url:
        return None
    return canonical(req.name), str(req.specifier)


def declared_requirements(root: Path) -> dict[str, list[str]]:
    """Every version specifier this repository declares, by distribution: in
    requirements*.txt and constraints*.txt, setup.py's quoted requirements and
    pyproject.toml's dependency lists. A direct reference (a git URL) declares
    no range."""
    found: dict[str, list[str]] = {}

    def add(item: tuple[str, str] | None) -> None:
        if item is not None:
            found.setdefault(item[0], []).append(item[1])

    for path in sorted([*root.glob("requirements*.txt"), *root.glob("constraints*.txt")]):
        for line in path.read_text().splitlines():
            add(_requirement(line))
    setup = root / "setup.py"
    if setup.is_file():
        block = re.search(r"install_requires\s*=\s*\[(.*?)\]", setup.read_text(), re.DOTALL)
        for quoted in re.findall(r"""["']([^"']+)["']""", block.group(1) if block else ""):
            add(_requirement(quoted))
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        project = tomllib.loads(pyproject.read_text()).get("project", {})
        for item in project.get("dependencies", []):
            add(_requirement(item))
        for extra in project.get("optional-dependencies", {}).values():
            for item in extra:
                add(_requirement(item))
    return found
