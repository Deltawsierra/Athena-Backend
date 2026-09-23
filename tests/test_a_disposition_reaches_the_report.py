"""P2.8's claim is "in any report". Three ways to break it left the suite green.

``CONTAINED`` and ``INVALIDATED`` were added because the existing states were
being stretched to cover them, and the model carries each one's wrong reading as
data so every surface shows the same caveat instead of inventing its own. The
serializer was tested. Nothing else was.

An audit of the bar applied three mutations and the whole 1172-test suite stayed
green for all of them:

1. ``CONTAINED``'s label set to "Remediating" and ``INVALIDATED``'s to "Open" --
   the labels the Django admin shows and the incident pack carries.
2. The incident pack's ``status_label`` hardcoded to "Open".
3. The dashboard mapping ``contained`` to ``remediating`` (a sibling repo, fixed
   there, and asserted there).

The first is the whole failure in one line: the choice labels ARE the words a
report prints, and nothing asserted they say different things. So the tests here
assert the roster, not one pair -- a label collision anywhere is the same defect,
and enumerating pairs would only ever catch the pair somebody thought of.

The two reports that had the state but not its caveat -- the incident pack and
the compliance bundle -- carry it now, and it is asserted where it is rendered.
"""

from __future__ import annotations

import pytest
from assurance.bundle import assurance_bundle
from assurance.incident import INCIDENT_PACK_SCHEMA, assemble_incident_pack
from assurance.models import Deployment, Finding
from assurance.serializers import FindingSerializer
from django.contrib.auth import get_user_model

pytestmark = pytest.mark.django_db

User = get_user_model()


def _dep(name="acme-chatbot"):
    return Deployment.objects.create(
        name=name,
        environment=Deployment.Environment.PRODUCTION,
        owner=User.objects.create_user(username=f"an-{name}", password="x"),
    )


def _only(dep):
    """`assurance_bundle` takes a queryset -- it scopes and prefetches through it,
    because the caller is what decides who may see what."""
    return Deployment.objects.filter(pk=dep.pk)


def _finding(dep, *, status, fp=None, location="/chat"):
    return Finding.objects.create(
        deployment=dep,
        fingerprint=fp or f"fp-{status}-{Finding.objects.count()}",
        finding_type="prompt_injection",
        title="Prompt injection may be possible",
        severity="high",
        status=status,
        location=location,
    )


# ---------------------------------------------------------------------------
# The negative control first: the ordinary path still reads as it did
# ---------------------------------------------------------------------------


def test_a_status_with_no_wrong_reading_worth_naming_says_so():
    """The caveat is None for OPEN, not an empty string and not a sentence
    invented to fill the field. A guard that attaches a caveat to everything
    devalues the four that mean something."""
    dep = _dep()
    data = FindingSerializer(_finding(dep, status=Finding.Status.OPEN)).data
    assert data["status"] == "open"
    assert data["status_label"] == "Open"
    assert data["status_must_not_imply"] is None


# ---------------------------------------------------------------------------
# The roster: no two dispositions may print the same words
# ---------------------------------------------------------------------------


def test_no_two_dispositions_share_a_label():
    """The mutation that survived. `get_status_display()` is what the admin list,
    the incident pack and the bundle print; two states with one label are one
    state as far as every reader is concerned."""
    labels = [str(s.label) for s in Finding.Status]
    duplicated = {lab for lab in labels if labels.count(lab) > 1}
    assert not duplicated, f"two dispositions print the same words: {duplicated}"


def test_contained_and_invalidated_do_not_print_as_the_states_they_were_stretched_from():
    """Named explicitly on top of the roster check, because these are the two the
    item is about and the two whose misreading is the reason they exist."""
    assert str(Finding.Status.CONTAINED.label) != str(Finding.Status.REMEDIATING.label)
    assert str(Finding.Status.INVALIDATED.label) != str(Finding.Status.OPEN.label)
    # And each label carries its own distinction in words, so a reader who sees
    # only the label -- an admin changelist, a CSV export -- still gets it.
    assert "not removed" in str(Finding.Status.CONTAINED.label)
    assert "no longer holds" in str(Finding.Status.INVALIDATED.label)


def test_every_caveat_is_keyed_to_a_real_disposition():
    """A key that is not a Status would never match, and MUST_NOT_IMPLY.get()
    would return None for it forever -- a caveat written, reviewed, merged and
    never once served."""
    known = {str(s.value) for s in Finding.Status}
    for key in Finding.MUST_NOT_IMPLY:
        assert str(key) in known, f"MUST_NOT_IMPLY key {key!r} is not a Finding.Status"


def test_no_two_dispositions_share_a_caveat():
    """Distinct states with identical caveats would pass every per-state assertion
    while telling a reader the same thing about both."""
    caveats = [v for v in Finding.MUST_NOT_IMPLY.values()]
    assert len(set(caveats)) == len(caveats)


# ---------------------------------------------------------------------------
# The API
# ---------------------------------------------------------------------------


def test_the_api_serves_the_disposition_in_words_and_not_only_as_a_slug():
    """Without a label a consumer has only "contained", and the only way to render
    that for a human is to write a label of its own -- which is how two surfaces
    end up disagreeing about a state whose wrong reading is the easy one."""
    dep = _dep()
    data = FindingSerializer(_finding(dep, status=Finding.Status.CONTAINED)).data
    assert data["status_label"] == "Contained (defect not removed)"
    assert "not been removed" in data["status_must_not_imply"]


def test_the_api_distinguishes_contained_from_remediating_in_every_served_field():
    dep = _dep()
    contained = FindingSerializer(_finding(dep, status=Finding.Status.CONTAINED)).data
    remediating = FindingSerializer(_finding(dep, status=Finding.Status.REMEDIATING)).data
    for field in ("status", "status_label", "status_must_not_imply"):
        assert contained[field] != remediating[field], f"{field} does not distinguish them"


# ---------------------------------------------------------------------------
# The incident pack -- a report headed "incident evidence"
# ---------------------------------------------------------------------------


def test_the_incident_pack_carries_the_caveat_beside_the_disposition():
    """An INVALIDATED finding in a pack headed "incident evidence pack" reads as a
    confirmed incident unless the pack itself says otherwise. It is exactly the
    reading that state was added to prevent, and the pack had the state and not
    the caveat."""
    dep = _dep()
    pack = assemble_incident_pack(_finding(dep, status=Finding.Status.INVALIDATED))
    finding = pack["identity"]["finding"]
    assert finding["status"] == "invalidated"
    assert finding["status_label"] == "Invalidated (premise no longer holds)"
    assert "not a confirmed incident" in finding["status_must_not_imply"]


def test_the_incident_pack_of_a_contained_finding_does_not_imply_a_fix():
    dep = _dep()
    pack = assemble_incident_pack(_finding(dep, status=Finding.Status.CONTAINED))
    assert "not been removed" in pack["identity"]["finding"]["status_must_not_imply"]
    assert "no fix is implied" in pack["identity"]["finding"]["status_must_not_imply"]


def test_a_pack_for_a_status_with_no_caveat_says_null_rather_than_omitting_it():
    """Absent and null are different facts. A consumer that sees the key missing
    cannot tell "this status has no caveat" from "this pack predates caveats"."""
    dep = _dep()
    pack = assemble_incident_pack(_finding(dep, status=Finding.Status.OPEN))
    assert "status_must_not_imply" in pack["identity"]["finding"]
    assert pack["identity"]["finding"]["status_must_not_imply"] is None


def test_the_pack_schema_declares_the_caveat_so_a_validator_does_not_reject_it():
    props = INCIDENT_PACK_SCHEMA["properties"]["identity"]["properties"]["finding"]["properties"]
    assert "status_must_not_imply" in props
    # Nullable in the schema, because null is a value it really carries.
    assert "null" in props["status_must_not_imply"]["type"]


def test_the_caveat_is_inside_the_packs_digest(monkeypatch):
    """A caveat outside the hash is a caveat that can be stripped from a pack
    without breaking its seal.

    Comparing a contained pack against a remediating one would NOT test this --
    `status` and `status_label` were already hashed, so those digests differed
    before the caveat existed. The only honest way to ask the question is to change
    the caveat and nothing else."""
    dep = _dep()
    finding = _finding(dep, status=Finding.Status.CONTAINED)
    before = assemble_incident_pack(finding)["digest"]

    table = dict(Finding.MUST_NOT_IMPLY)
    table[Finding.Status.CONTAINED] = "Something else entirely."
    monkeypatch.setattr(Finding, "MUST_NOT_IMPLY", table)

    after = assemble_incident_pack(Finding.objects.get(pk=finding.pk))
    assert after["identity"]["finding"]["status_must_not_imply"] == "Something else entirely."
    assert after["digest"] != before


# ---------------------------------------------------------------------------
# The compliance bundle -- the other report that had a slug and nothing else
# ---------------------------------------------------------------------------


def test_the_bundle_row_says_what_the_status_means_and_what_it_does_not():
    """`status: "contained"` on its own leaves an auditor to decide whether that
    means handled."""
    dep = _dep()
    _finding(dep, status=Finding.Status.CONTAINED)
    row = assurance_bundle(_only(dep))["findings"][0]
    assert row["status"] == "contained"
    assert row["status_label"] == "Contained (defect not removed)"
    assert "not been removed" in row["status_must_not_imply"]


def test_the_bundle_keeps_contained_and_remediating_apart():
    dep = _dep()
    _finding(dep, status=Finding.Status.CONTAINED, fp="c", location="/a")
    _finding(dep, status=Finding.Status.REMEDIATING, fp="r", location="/b")
    rows = {r["status"]: r for r in assurance_bundle(_only(dep))["findings"]}
    assert set(rows) == {"contained", "remediating"}
    assert rows["contained"]["status_label"] != rows["remediating"]["status_label"]
    assert rows["contained"]["status_must_not_imply"] != rows["remediating"]["status_must_not_imply"]


def test_a_bundle_row_for_a_status_with_no_caveat_carries_null():
    dep = _dep()
    _finding(dep, status=Finding.Status.OPEN)
    row = assurance_bundle(_only(dep))["findings"][0]
    assert row["status_label"] == "Open"
    assert row["status_must_not_imply"] is None
