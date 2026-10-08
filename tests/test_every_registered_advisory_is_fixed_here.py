"""Every advisory in the register (advisories.toml) is fixed here, in CI, with no
network: no registered dependency is installed at an affected version, no
requirement this repository declares admits one, a dependency recorded as absent
is absent, and every test the register names exists.

The register is the standing regression source the collector-hardening roadmap
item asks for: an advisory against a dependency on the path from a scan to its
record -- here, the HTTP client every engine call, connector and posture read
goes through, and the telemetry its spans go through -- is entered once, with
the test of this service's own that pins its behaviour, and a later change that lowers a requirement below the fix, or
installs the dependency at an affected version, fails here.
"""

from __future__ import annotations

from pathlib import Path

from tests.advisory_register import (
    declared_requirements,
    installed_versions,
    load,
    malformed,
    violations,
)

ROOT = Path(__file__).resolve().parent.parent
REGISTER = ROOT / "advisories.toml"


def _register():
    advisories = load(REGISTER)
    assert advisories, "the register is empty"
    return advisories


def test_the_register_is_well_formed_and_names_tests_that_exist():
    assert malformed(_register(), ROOT) == []


def test_no_registered_dependency_is_installed_or_declared_at_an_affected_version():
    advisories = _register()
    names = {dep for adv in advisories for dep in adv.dependencies}
    found = violations(advisories, installed_versions(names), declared_requirements(ROOT))
    assert found == [], "\n".join(found)


def test_the_check_fails_on_each_way_a_fix_can_be_lost():
    """The guard can fail: each of these is what a lowered pin, a vulnerable
    install or a newly added dependency looks like to it."""
    advisories = _register()
    names = {dep for adv in advisories for dep in adv.dependencies}
    fine = installed_versions(names)
    assert violations(advisories, fine, declared_requirements(ROOT)) == []

    by_id = {adv.id: adv for adv in advisories}
    # Installed below the fix.
    assert violations([by_id["GHSA-9hjg-9r4m-mvj7"]], {**fine, "requests": "2.32.3"}, {})
    assert violations([by_id["GHSA-pq67-6m6q-mj2v"]], {**fine, "urllib3": "2.4.0"}, {})
    # A declared requirement lowered so that it admits an affected version.
    assert violations([by_id["GHSA-9hjg-9r4m-mvj7"]], fine, {"requests": [">=2.31"]})
    assert violations([by_id["GHSA-9hjg-9r4m-mvj7"]], fine, {"requests": [""]})
    # The motivating advisory's dependency installed: at an affected version on
    # either line, and even at a fixed one while the register says it is absent.
    for version in ("1.107.5", "2.43.0", "2.0.0b3"):
        assert violations(
            [by_id["GHSA-4x9p-g9wm-8q7f"]], {**fine, "pydantic-ai": version}, {}
        ), version
    assert violations([by_id["GHSA-22h6-qm39-v87j"]], {**fine, "pydantic-ai-slim": "1.107.6"}, {})
    # And the fixed versions themselves are not flagged once recorded as used.
    used = [
        type(adv)(**{**adv.__dict__, "installed": True})
        for adv in (by_id["GHSA-4x9p-g9wm-8q7f"], by_id["GHSA-22h6-qm39-v87j"])
    ]
    for version in ("1.107.6", "2.44.0"):
        assert violations(used, {"pydantic-ai": version, "pydantic-ai-slim": version}, {}) == []
