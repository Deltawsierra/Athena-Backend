"""Regenerate the old-version Assurance Receipt vectors from the code that emitted them.

Every ``assurance-receipt.json`` beside this script is the body athena-backend's own
``GET /api/assurance/deployments/<uuid>/assurance-receipt/`` answered, at a named
commit, rendered to bytes as an auditor saves them. Nothing in them is written by
hand: the versions a reader must still be able to read (docs/receipt-spec/v4.1.md,
section 8) are held to what those commits actually emitted, not to what anybody
remembers they emitted.

Three commits are recorded, one directory each:

  pr27-673a40b/  #27 673a40b8aae052f13ccb95340fe84ae48bd42031
                 ``mythos.assurance.receipt/1.0``: no ``policy_version``, no served
                 route, no coverage, no chains, and no word on signatures.
  pr56-fdf77bf/  #56 fdf77bf768f210797b991de45eae64dbe32df2f0
                 ``mythos.assurance.receipt/2.0`` as #56 emitted it: a five-member
                 ``coverage``.
  pr67-87e83e7/  #67 87e83e73344241d4c3c36fe878fd59a8c3ec39ec
                 ``mythos.assurance.receipt/2.0`` as #67 emitted it, under the same
                 version string: a nine-member ``coverage``, the check axis added.

Usage, with THIS script (from a newer checkout) and a checkout or worktree of
athena-backend at one of those commits, its dependencies importable and the
mythos-core its requirements pin on ``PYTHONPATH``:

    python -B tests/fixtures/receipts/generate.py <old checkout> <output directory>

The old checkout is the only athena-backend code imported. The script refuses any
other commit and a checkout with uncommitted changes, so a vector directory always
says which commit produced it; ``provenance.json`` beside each vector records that
commit, the mythos-core that was imported, and the SHA-256 of the vector's bytes.

The state is the one ``tests/test_receipt_spec_conformance.py`` builds for the
current version: two findings, three evidence rows, a provider asserting a region,
an approved model asset, and a deployment name outside ASCII. The rows are written
with each commit's own models, and a test database is made with its own
migrations. Uuids and ``computed_at`` differ on every run; the tests read them from
the files rather than assuming them.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

#: The commits this script generates from: full sha -> (directory, PR, version, shape).
COMMITS = {
    "673a40b8aae052f13ccb95340fe84ae48bd42031": ("pr27-673a40b", "#27", "mythos.assurance.receipt/1.0", None),
    "fdf77bf768f210797b991de45eae64dbe32df2f0": ("pr56-fdf77bf", "#56", "mythos.assurance.receipt/2.0", "#56"),
    "87e83e73344241d4c3c36fe878fd59a8c3ec39ec": ("pr67-87e83e7", "#67", "mythos.assurance.receipt/2.0", "#67"),
}

VECTOR = "assurance-receipt.json"


def _git(checkout: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(checkout), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def _tree_sha256(package: Path) -> str:
    """One digest over every file of the imported mythos-core package: its relative
    path and its bytes, sorted. It matches a ``git archive`` of the commit it came
    from, whatever directory that was unpacked into."""
    digest = hashlib.sha256()
    for path in sorted(p for p in package.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        digest.update(path.relative_to(package).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode() + b"\n")
    return digest.hexdigest()


def _pinned_core(checkout: Path) -> str | None:
    for line in (checkout / "requirements.txt").read_text().splitlines():
        if line.startswith("mythos-core"):
            return line.split("@", 1)[-1].strip()
    return None


def _state(models, user_model):
    """The conformance suite's state, written with this commit's own models."""
    owner = user_model.objects.create_user(username="auditor", password="x", role=user_model.Roles.ADMIN)
    dep = models.Deployment.objects.create(
        name="Kundenservice-Assistent (Zürich)",
        owner=owner,
        environment=models.Deployment.Environment.PRODUCTION,
        decision=models.Deployment.Decision.NEEDS_MORE_EVIDENCE,
    )
    first = models.Finding.objects.create(
        deployment=dep, fingerprint="fp-first", finding_type="xss", title="F", severity="high"
    )
    models.Evidence.objects.create(
        finding=first,
        classification=models.EvidenceClass.VENDOR_ASSERTED,
        source="vendor_doc",
        content_hash="a" * 64,
    )
    models.Evidence.objects.create(
        finding=first,
        classification=models.EvidenceClass.PARTIALLY_VERIFIED,
        source="engine_scan",
        content_hash="1" * 64,
    )
    second = models.Finding.objects.create(
        deployment=dep, fingerprint="fp-second", finding_type="xss", title="G", severity="medium"
    )
    models.Evidence.objects.create(
        finding=second,
        classification=models.EvidenceClass.CONFIGURATION_VERIFIED,
        source="config",
        content_hash="2" * 64,
    )
    provider = models.Provider.objects.create(name="Acme Model Co", kind=models.Provider.Kind.MODEL_PROVIDER)
    models.ProviderAssertion.objects.create(
        provider=provider, field=models.ProviderAssertion.Field.REGION, value="us-east-1"
    )
    models.Asset.objects.create(
        deployment=dep,
        kind=models.Asset.Kind.MODEL,
        name="gpt-x",
        provider=provider,
        classification=models.Asset.Classification.APPROVED,
    )
    return dep, owner


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    checkout, out = Path(argv[0]).resolve(), Path(argv[1]).resolve()
    sha = _git(checkout, "rev-parse", "HEAD")
    if sha not in COMMITS:
        print(f"refusing {sha}: this script generates from {', '.join(sorted(COMMITS))} only", file=sys.stderr)
        return 2
    if _git(checkout, "status", "--porcelain"):
        print(f"refusing {checkout}: it has uncommitted changes, so it is not {sha}", file=sys.stderr)
        return 2
    directory, pr, version, shape = COMMITS[sha]

    sys.path.insert(0, str(checkout))
    os.chdir(checkout)
    os.environ["DJANGO_SETTINGS_MODULE"] = "tests.settings_test"
    import django

    django.setup()
    import mythos_core
    from django.contrib.auth import get_user_model
    from django.db import connection
    from django.test.utils import setup_test_environment, teardown_test_environment
    from rest_framework.test import APIRequestFactory, force_authenticate

    from assurance import models
    from assurance.views import DeploymentViewSet

    here = Path(models.__file__).resolve()
    if checkout not in here.parents:
        print(f"refusing: assurance was imported from {here}, not from {checkout}", file=sys.stderr)
        return 2

    setup_test_environment()
    old_name = connection.creation.create_test_db(verbosity=0, autoclobber=True, serialize=False)
    try:
        dep, reader = _state(models, get_user_model())
        request = APIRequestFactory().get(
            f"/api/assurance/deployments/{dep.uuid}/assurance-receipt/", HTTP_ACCEPT="application/json"
        )
        force_authenticate(request, user=reader)
        response = DeploymentViewSet.as_view({"get": "assurance_receipt"})(request, uuid=str(dep.uuid))
        response.render()
        body = response.content
    finally:
        connection.creation.destroy_test_db(old_name, verbosity=0)
        teardown_test_environment()

    if response.status_code != 200:
        print(f"the route answered {response.status_code}", file=sys.stderr)
        return 1
    emitted = json.loads(body)["receipt_version"]
    if emitted != version:
        print(f"{sha} emitted {emitted!r}, not {version!r}", file=sys.stderr)
        return 1

    target = out / directory
    target.mkdir(parents=True, exist_ok=True)
    (target / VECTOR).write_bytes(body)
    core_package = Path(mythos_core.__file__).resolve().parent
    provenance = {
        "vector": VECTOR,
        "sha256": hashlib.sha256(body).hexdigest(),
        "receipt_version": version,
        "shape": shape,
        "emitted_by": {"pr": pr, "commit": sha},
        "route": "GET /api/assurance/deployments/<uuid>/assurance-receipt/",
        "generated_by": "tests/fixtures/receipts/generate.py",
        "mythos_core": {
            "pinned_by_requirements": _pinned_core(checkout),
            "imported_tree_sha256": _tree_sha256(core_package),
        },
        "django": django.get_version(),
        "python": sys.version.split()[0],
    }
    (target / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    print(f"{directory}: {version}{'' if shape is None else ' as ' + shape + ' emitted it'} -> {target / VECTOR}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
