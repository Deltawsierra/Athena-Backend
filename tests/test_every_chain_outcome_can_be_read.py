"""Every chain outcome can be read, a page at a time.

``GET .../chain-outcomes/`` answered the newest hundred outcomes and took no
parameter that asked for the rest. Outcomes append for the life of a deployment,
so the hundred-and-first was recorded, counted (``recorded_count``), and could be
read by nobody through the API. An observed effect older than the newest hundred
outcomes of any kind was among them.

What holds now, and is proved here against the real route:

* a keyset cursor (``next``, ``?before=``) walks every outcome once, in order,
  whatever arrives between pages;
* ``?recorded_as=observed_effect`` reads only the rows recorded as observed
  effects, and each row still says for itself what it is in force;
* a cursor or a filter the read does not know is a ``400`` with a code, never a
  page that looks like "no more";
* a row reads the same on whichever page it falls;
* a page costs the same number of statements whatever it holds.

:mod:`assurance.outcome_pages` is the rule; the route is
``DeploymentViewSet.chain_outcomes``.
"""

from __future__ import annotations

import json
from datetime import timedelta
from urllib.parse import urlencode

import pytest
from django.contrib.auth import get_user_model
from django.core import signing
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework.test import APIClient

from assurance import composition as comp
from assurance import outcome_pages
from assurance.models import Deployment, WorkflowChainOutcome
from assurance.views import DeploymentViewSet
from tests.signed_chains import ENGINE_KEYS, record_observed_effect, record_signed, write_keyring

pytestmark = pytest.mark.django_db

User = get_user_model()

SIZE = DeploymentViewSet.CHAIN_OUTCOME_PAGE_SIZE
#: Long enough ago that nothing below is dated in the future, recent enough that a
#: signed outcome dated from it is taken in.
T0 = timezone.now() - timedelta(hours=6)

#: What the answer held before this change, and what it holds now.
KEYS_BEFORE = {"outcomes", "returned", "truncated", "page_size", "recorded_count", "composition"}
KEYS_NOW = KEYS_BEFORE | {"next", "matching_count"}


@pytest.fixture(autouse=True)
def _trusted_engines(engine_keyring):
    """A keyring the signed rows below verify against."""
    return engine_keyring


def _user(role=None):
    return User.objects.create_user(
        username=f"reader{User.objects.count()}", password="x", role=role or User.Roles.ADMIN
    )


def _client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _deployment(owner=None):
    owner = owner or _user()
    return Deployment.objects.create(name=f"paged-{Deployment.objects.count()}", owner=owner)


def _url(dep_or_uuid, **params):
    uuid = getattr(dep_or_uuid, "uuid", dep_or_uuid)
    query = f"?{urlencode(params, doseq=True)}" if params else ""
    return f"/api/assurance/deployments/{uuid}/chain-outcomes/{query}"


def _typed(dep, count, *, first=T0, step=timedelta(seconds=1), dated=True, **columns):
    """``count`` typed-in outcomes, each a second after the last (or undated)."""
    start = WorkflowChainOutcome.objects.count()
    return WorkflowChainOutcome.objects.bulk_create(
        WorkflowChainOutcome(
            deployment=dep,
            workflow=f"wf-{start + n}",
            status=comp.HELD,
            observed_at=first + n * step if dated else None,
            **columns,
        )
        for n in range(count)
    )


def _effect(dep, n, *, minutes_ago):
    """One observed effect, signed and taken in the way one is, for a workflow of its
    own: the gate decision Achilles signed, then the effect its dispatch saw."""
    at = timezone.now() - timedelta(minutes=minutes_ago)
    permit = record_signed(dep, f"effect-wf-{n}", comp.HELD, at - timedelta(seconds=1), engine="achilles")
    return record_observed_effect(dep, f"effect-wf-{n}", permit.outcome_id, at)


def _in_order(rows):
    """The walk's order, computed here and not by the query under test: newest
    exercise first, undated last, then newest recorded, then highest id."""
    rows = sorted(rows, key=lambda row: row.id, reverse=True)
    rows = sorted(rows, key=lambda row: row.created_at, reverse=True)
    dated = sorted((row for row in rows if row.observed_at is not None), key=lambda row: row.observed_at, reverse=True)
    return dated + [row for row in rows if row.observed_at is None]


def _uuids(rows):
    return [str(row.uuid) for row in rows]


def _served(page):
    return [row["uuid"] for row in page["outcomes"]]


def _walk(client, dep, **params):
    """Every page from the first, following ``next``. Each page is held to what every
    page must say about itself; the walk stops at the first ``next`` of null."""
    pages = []
    cursor = None
    for _ in range(50):
        asked = dict(params, before=cursor) if cursor else params
        response = client.get(_url(dep, **asked))
        assert response.status_code == 200, response.content[:300]
        page = response.json()
        assert set(page) == KEYS_NOW
        assert page["returned"] == len(page["outcomes"]) <= page["page_size"]
        # `truncated` is true exactly when a further page exists, and that is
        # exactly when `next` is a cursor.
        assert page["truncated"] is (page["next"] is not None)
        pages.append(page)
        cursor = page["next"]
        if cursor is None:
            return pages
    raise AssertionError("the walk did not end: `next` was never null")


# --------------------------------------------------------------------------
# The defect: the hundred-and-first outcome.
# --------------------------------------------------------------------------


def test_the_hundred_and_first_outcome_can_be_read():
    """It was recorded and counted, and no request could read it."""
    dep = _deployment()
    rows = _typed(dep, SIZE + 1)
    oldest = str(rows[0].uuid)
    client = _client(dep.owner)

    first = client.get(_url(dep)).json()
    assert first["recorded_count"] == SIZE + 1 and first["returned"] == SIZE
    assert oldest not in _served(first)
    assert first["truncated"] is True

    second = client.get(_url(dep, before=first["next"]))
    assert second.status_code == 200
    assert _served(second.json()) == [oldest]
    assert second.json()["next"] is None and second.json()["truncated"] is False


# --------------------------------------------------------------------------
# The walk.
# --------------------------------------------------------------------------


def _two_hundred_and_fifty(dep):
    """250 outcomes whose page boundaries fall where a cursor is hardest to get right:
    the first inside a run of rows that share both instants (only the id tells them
    apart), the second inside the undated rows, which also share when they were
    recorded."""
    dated = _typed(dep, 190)
    undated = _typed(dep, 60, dated=False)
    shared = T0 + timedelta(seconds=85)
    recorded = timezone.now()
    # Dated rows 85..94 are places 95..104 of the walk: one exercise instant, one
    # recorded instant.
    WorkflowChainOutcome.objects.filter(pk__in=[row.pk for row in dated[85:95]]).update(
        observed_at=shared, created_at=recorded
    )
    # The undated rows are places 190..249, in two runs of one recorded instant each.
    WorkflowChainOutcome.objects.filter(pk__in=[row.pk for row in undated[:30]]).update(
        created_at=recorded - timedelta(minutes=5)
    )
    WorkflowChainOutcome.objects.filter(pk__in=[row.pk for row in undated[30:]]).update(
        created_at=recorded - timedelta(minutes=1)
    )
    expected = _in_order(dep.chain_outcomes.all())
    # The boundaries are where this says they are, or the test proves less than it claims.
    a, b = expected[SIZE - 1], expected[SIZE]
    assert (a.observed_at, a.created_at) == (b.observed_at, b.created_at) and a.id > b.id
    c, d = expected[2 * SIZE - 1], expected[2 * SIZE]
    assert c.observed_at is None and d.observed_at is None and c.created_at == d.created_at and c.id > d.id
    return expected


def test_two_hundred_and_fifty_outcomes_are_walked_in_three_pages_each_seen_once_in_order():
    dep = _deployment()
    expected = _two_hundred_and_fifty(dep)

    pages = _walk(_client(dep.owner), dep)

    assert [page["returned"] for page in pages] == [100, 100, 50]
    assert [page["truncated"] for page in pages] == [True, True, False]
    assert [page["next"] is None for page in pages] == [False, False, True]
    seen = [uuid for page in pages for uuid in _served(page)]
    assert len(seen) == len(set(seen)) == 250
    assert seen == _uuids(expected)
    for page in pages:
        assert page["page_size"] == SIZE
        # The whole count on every page, and with no filter the filter matches all.
        assert page["recorded_count"] == page["matching_count"] == 250
        # The composition is of every outcome, on whichever page it is read.
        assert page["composition"]["workflows_assessed"] == 250


def test_a_last_page_that_is_exactly_full_says_it_is_the_last():
    """Two hundred outcomes are two full pages and no third: a full page is not, by
    itself, a further one."""
    dep = _deployment()
    _typed(dep, 2 * SIZE)

    pages = _walk(_client(dep.owner), dep)

    assert [page["returned"] for page in pages] == [SIZE, SIZE]
    assert pages[-1]["next"] is None and pages[-1]["truncated"] is False


def test_a_deployment_with_no_outcomes_answers_one_empty_last_page():
    dep = _deployment()
    (page,) = _walk(_client(dep.owner), dep)
    assert page["outcomes"] == [] and page["next"] is None
    assert page["recorded_count"] == page["matching_count"] == 0


def test_the_first_page_with_no_parameters_answers_as_it_did_apart_from_the_new_keys():
    """The same rows in the same order as the model's own ordering gives, the same
    keys with the same meaning, and two new ones."""
    dep = _deployment()
    _typed(dep, SIZE + 3)
    _typed(dep, 2, dated=False)
    as_before = list(dep.chain_outcomes.all()[:SIZE])

    page = _client(dep.owner).get(_url(dep)).json()

    assert set(page) - KEYS_BEFORE == {"next", "matching_count"}
    assert _served(page) == _uuids(as_before)
    assert (page["returned"], page["truncated"], page["page_size"], page["recorded_count"]) == (
        SIZE,
        True,
        SIZE,
        SIZE + 5,
    )
    assert page["matching_count"] == SIZE + 5 and isinstance(page["next"], str)


def test_an_outcome_recorded_between_pages_is_neither_skipped_nor_served_twice():
    """A reader holds page one's cursor while four outcomes are recorded: one newer
    than everything, one sharing the cursor row's exercise instant (recorded later,
    so it sorts before that row), one older than everything and one undated.

    No row is served twice and none that was still to come is passed over. The two
    that sort after the cursor are read where they sort. The two that sort before
    it belong to the part already read: they head the next walk from the first
    page. An offset would have moved every later page by the two that arrived at
    the head, and served the cursor row's neighbours again.
    """
    dep = _deployment()
    _typed(dep, 150)
    client = _client(dep.owner)
    before = _in_order(dep.chain_outcomes.all())
    first = client.get(_url(dep)).json()
    assert _served(first) == _uuids(before[:SIZE])
    last_served = before[SIZE - 1]

    (newer,) = _typed(dep, 1, first=T0 + timedelta(hours=1))
    (beside,) = _typed(dep, 1, first=last_served.observed_at)
    (older,) = _typed(dep, 1, first=T0 - timedelta(hours=1))
    (undated,) = _typed(dep, 1, dated=False)

    second = client.get(_url(dep, before=first["next"])).json()

    assert _served(second) == _uuids(before[SIZE:]) + [str(older.uuid), str(undated.uuid)]
    assert second["next"] is None
    assert not set(_served(first)) & set(_served(second))
    # The counts are of the record as it now stands.
    assert second["recorded_count"] == second["matching_count"] == 154
    # The same cursor reads the same page again: it names a place, not a moment.
    assert client.get(_url(dep, before=first["next"])).json()["outcomes"] == second["outcomes"]
    # The two that arrived before the cursor's place are where a new walk begins.
    again = _walk(client, dep)
    everything = [uuid for page in again for uuid in _served(page)]
    assert everything[0] == str(newer.uuid)
    assert everything == _uuids(_in_order(dep.chain_outcomes.all()))
    assert everything.index(str(beside.uuid)) == everything.index(str(last_served.uuid)) - 1
    assert len(everything) == len(set(everything)) == 154


def test_a_cursor_holds_nothing_the_page_did_not_already_serve():
    """A cursor is signed, not sealed: whoever holds it can read what it names. It
    names the last row served by that row's two instants and its uuid, all three on
    the page already. Never its id, which is one counter over every deployment's
    outcomes: read from a cursor it would tell one deployment's reader how many
    outcomes the others have recorded."""
    other = _deployment()
    _typed(other, 500)
    dep = _deployment()
    _typed(dep, SIZE + 1)
    page = _client(dep.owner).get(_url(dep)).json()
    last = page["outcomes"][-1]
    row = WorkflowChainOutcome.objects.get(uuid=last["uuid"])
    assert row.id > 500

    named = signing.Signer(salt=f"assurance.outcome_pages.cursor|{dep.uuid}|").unsign_object(page["next"])

    assert named == [row.observed_at.isoformat(), row.created_at.isoformat(), row.uuid.hex]
    served = {last["uuid"].replace("-", ""), *(parse_datetime(last[key]) for key in ("observed_at", "recorded_at"))}
    assert {named[2], *(parse_datetime(value) for value in named[:2])} == served
    assert row.id not in named and str(row.id) not in named


def test_a_cursor_whose_row_is_gone_serves_its_neighbours_again_and_never_passes_them_over(monkeypatch):
    """Six rows that share both instants, two to a page, and the row the first
    cursor names is deleted behind the reader. Which of its neighbours came before
    it can no longer be told, so all of them are served: the one already read is
    read twice, and none of the four still to come is missed."""
    dep = _deployment()
    rows = _typed(dep, 6, step=timedelta(0))
    WorkflowChainOutcome.objects.filter(deployment=dep).update(created_at=timezone.now())
    monkeypatch.setattr(DeploymentViewSet, "CHAIN_OUTCOME_PAGE_SIZE", 2)
    client = _client(dep.owner)
    first = client.get(_url(dep)).json()
    assert _served(first) == [str(rows[5].uuid), str(rows[4].uuid)]

    WorkflowChainOutcome.objects.filter(pk=rows[4].pk).delete()

    rest, cursor = [], first["next"]
    while cursor:
        page = client.get(_url(dep, before=cursor)).json()
        rest += _served(page)
        cursor = page["next"]
    assert rest == [str(rows[n].uuid) for n in (5, 3, 2, 1, 0)]


# --------------------------------------------------------------------------
# The filter: what a row was recorded as.
# --------------------------------------------------------------------------


def test_the_filter_names_exactly_the_signers_the_composition_maps_to_an_observed_effect(monkeypatch):
    assert outcome_pages.effect_signers() == ("achilles-effect",)
    assert set(outcome_pages.FILTERS) == {comp.EVIDENCE_OBSERVED_EFFECT}
    # Read from the composition's map each time, never from a copy of it.
    monkeypatch.setitem(comp.SIGNER_EVIDENCE, "a-second-effect-signer", comp.EVIDENCE_OBSERVED_EFFECT)
    assert outcome_pages.effect_signers() == ("a-second-effect-signer", "achilles-effect")


def _mixed(dep):
    """A deployment's record with every kind of row in it: typed-in rows, a scan,
    three observed effects (each with the gate decision it cites, an authorization
    check), a row typed in to LOOK like an effect, and a row that names the effect
    signer without saying it was demonstrated."""
    _typed(dep, 4)
    record_signed(dep, "scanned", comp.HELD, timezone.now() - timedelta(minutes=30), engine="athena")
    effects = [_effect(dep, n, minutes_ago=20 - n) for n in range(3)]
    (typed_as_effect,) = _typed(
        dep, 1, first=T0 + timedelta(minutes=1), basis=comp.BASIS_DEMONSTRATED, observer_engine="achilles-effect"
    )
    (names_the_signer,) = _typed(
        dep, 1, first=T0 + timedelta(minutes=2), basis=comp.BASIS_ATTESTED, observer_engine="achilles-effect"
    )
    return effects, typed_as_effect, names_the_signer


def test_the_filter_serves_only_rows_recorded_as_observed_effects_and_counts_both_ways():
    dep = _deployment()
    effects, typed_as_effect, names_the_signer = _mixed(dep)
    client = _client(dep.owner)
    total = dep.chain_outcomes.count()
    assert total == 4 + 1 + 3 * 2 + 1 + 1

    (everything,) = _walk(client, dep)
    (page,) = _walk(client, dep, recorded_as="observed_effect")

    recorded_as = _in_order([*effects, typed_as_effect])
    assert _served(page) == _uuids(recorded_as)
    # What the filter matched, beside every outcome of the deployment: the filter
    # moves the first and never the second.
    assert page["matching_count"] == 4
    assert page["recorded_count"] == everything["recorded_count"] == total
    assert everything["matching_count"] == total
    # A row that names the effect signer and was never recorded as demonstrated is
    # no effect to any reader, and is not matched.
    assert str(names_the_signer.uuid) not in _served(page)
    # The composition is the deployment's, not the filter's.
    assert page["composition"] == everything["composition"]


def test_every_filtered_row_still_says_for_itself_what_it_is_in_force():
    """The filter matches what a row was RECORDED as. What it IS follows from a
    signature checked on this read, and each row carries that reading: a row
    recorded as an effect that no envelope backs is served, as ``attested``, with no
    effect reading."""
    dep = _deployment()
    effects, typed_as_effect, _ = _mixed(dep)
    client = _client(dep.owner)

    (page,) = _walk(client, dep, recorded_as="observed_effect")
    by_uuid = {row["uuid"]: row for row in page["outcomes"]}

    for effect in effects:
        row = by_uuid[str(effect.uuid)]
        assert row["evidence_kind"] == comp.EVIDENCE_OBSERVED_EFFECT and row["signed"] is True
        assert row["effect_reading"]["schema"] == "mythos.observed-effect/v2"
    unbacked = by_uuid[str(typed_as_effect.uuid)]
    assert unbacked["basis"] == comp.BASIS_DEMONSTRATED
    assert unbacked["basis_in_force"] == unbacked["evidence_kind"] == comp.EVIDENCE_ATTESTED
    assert unbacked["signed"] is False and unbacked["effect_reading"] is None


def test_an_effect_whose_key_is_no_longer_trusted_is_still_matched_and_reads_null(_trusted_engines):
    dep = _deployment()
    effect = _effect(dep, 0, minutes_ago=5)
    client = _client(dep.owner)
    (trusted,) = _walk(client, dep, recorded_as="observed_effect")
    assert trusted["outcomes"][0]["effect_reading"] is not None

    write_keyring(_trusted_engines, {name: key for name, key in ENGINE_KEYS.items() if name != "achilles-effect"})

    (page,) = _walk(client, dep, recorded_as="observed_effect")
    assert page["matching_count"] == 1 and _served(page) == [str(effect.uuid)]
    (row,) = page["outcomes"]
    assert row["evidence_kind"] == comp.EVIDENCE_ATTESTED and row["effect_reading"] is None


def test_every_observed_effect_in_force_is_among_the_rows_the_filter_serves():
    """The filter can serve a row that is no longer an effect in force. It can never
    leave one out: every row the unfiltered walk reads as an observed effect is in
    the filtered walk, and reads there byte for byte as it does unfiltered."""
    dep = _deployment()
    _mixed(dep)
    client = _client(dep.owner)

    (everything,) = _walk(client, dep)
    (filtered,) = _walk(client, dep, recorded_as="observed_effect")

    in_force = [row for row in everything["outcomes"] if row["evidence_kind"] == comp.EVIDENCE_OBSERVED_EFFECT]
    assert len(in_force) == 3
    served = {row["uuid"]: row for row in filtered["outcomes"]}
    for row in in_force:
        assert json.dumps(served[row["uuid"]]) == json.dumps(row)


def test_the_filter_is_walked_with_its_own_cursor(monkeypatch):
    """Five rows recorded as effects among other rows, two to a page."""
    dep = _deployment()
    _typed(dep, 7)
    effects = [_effect(dep, n, minutes_ago=30 - n) for n in range(5)]
    monkeypatch.setattr(DeploymentViewSet, "CHAIN_OUTCOME_PAGE_SIZE", 2)
    client = _client(dep.owner)

    pages = _walk(client, dep, recorded_as="observed_effect")

    assert [page["returned"] for page in pages] == [2, 2, 1]
    assert [uuid for page in pages for uuid in _served(page)] == _uuids(_in_order(effects))
    total = dep.chain_outcomes.count()
    assert total == 7 + 5 * 2
    for page in pages:
        assert (page["matching_count"], page["recorded_count"]) == (5, total)
        assert all(row["effect_reading"] is not None for row in page["outcomes"])


def test_the_filter_is_walked_at_the_real_page_size():
    """130 rows recorded as effects among 130 that are not: a hundred, then thirty."""
    dep = _deployment()
    _typed(dep, 130)
    recorded_as = _typed(
        dep, 130, first=T0 + timedelta(milliseconds=500), basis=comp.BASIS_DEMONSTRATED, observer_engine="achilles-effect"
    )

    pages = _walk(_client(dep.owner), dep, recorded_as="observed_effect")

    assert [page["returned"] for page in pages] == [100, 30]
    assert [uuid for page in pages for uuid in _served(page)] == _uuids(_in_order(recorded_as))
    assert {(page["matching_count"], page["recorded_count"]) for page in pages} == {(130, 260)}


def test_a_cursor_issued_under_one_filter_is_refused_under_another(monkeypatch):
    """A cursor is a place in ONE walk. Read under another filter it would name a
    place in a walk it was never part of, and the reader would not be told."""
    dep = _deployment()
    for n in range(3):
        _effect(dep, n, minutes_ago=30 - n)
    monkeypatch.setattr(DeploymentViewSet, "CHAIN_OUTCOME_PAGE_SIZE", 2)
    client = _client(dep.owner)
    unfiltered = client.get(_url(dep)).json()["next"]
    filtered = client.get(_url(dep, recorded_as="observed_effect")).json()["next"]
    assert unfiltered and filtered

    for cursor, params in ((unfiltered, {"recorded_as": "observed_effect"}), (filtered, {})):
        refused = client.get(_url(dep, before=cursor, **params))
        assert refused.status_code == 400 and refused.json()["code"] == outcome_pages.BAD_CURSOR


# --------------------------------------------------------------------------
# What is refused, and never answered as an empty page.
# --------------------------------------------------------------------------


def _a_cursor(client, dep):
    cursor = client.get(_url(dep)).json()["next"]
    assert isinstance(cursor, str) and cursor
    return cursor


def _edited(cursor):
    """The cursor with one character of what it names changed, its signature kept."""
    named, signature = cursor.rsplit(":", 1)
    return f"{named[:-1]}{'A' if named[-1] != 'A' else 'B'}:{signature}"


def test_a_bad_cursor_is_a_400_with_a_code_and_never_an_empty_page():
    dep = _deployment()
    _typed(dep, SIZE + 5)
    client = _client(dep.owner)
    cursor = _a_cursor(client, dep)
    salt = f"assurance.outcome_pages.cursor|{dep.uuid}|"
    a_row = dep.chain_outcomes.first().uuid.hex
    # The salt is the one the read signs under: a place signed with it is read.
    good = signing.Signer(salt=salt).sign_object([None, T0.isoformat(), a_row])
    assert client.get(_url(dep, before=good)).status_code == 200
    bad = {
        "nothing at all": "",
        "not a cursor": "100",
        "an offset": "offset:100",
        "what it names edited": _edited(cursor),
        "its signature cut": cursor[:-4],
        "its signature removed": cursor.rsplit(":", 1)[0],
        "longer than any cursor": "A" * (outcome_pages.MAX_CURSOR_CHARS + 1),
        # Signed with this deployment's own salt, and still not a place in the walk.
        "signed, and not a place": signing.Signer(salt=salt).sign_object({"offset": 100}),
        "signed, naming a row by a number": signing.Signer(salt=salt).sign_object([None, T0.isoformat(), 5]),
        "signed, naming no row": signing.Signer(salt=salt).sign_object([None, T0.isoformat(), "z" * 32]),
        "signed, with no instant": signing.Signer(salt=salt).sign_object([None, "yesterday", a_row]),
        "signed, with no zone": signing.Signer(salt=salt).sign_object([None, "2026-01-01T00:00:00", a_row]),
        # The right shape, signed under a salt that names no deployment.
        "signed elsewhere": signing.Signer(salt="assurance.outcome_pages.cursor").sign_object(
            [None, T0.isoformat(), a_row]
        ),
    }
    answers = set()
    for what, value in bad.items():
        response = client.get(_url(dep, before=value))
        assert response.status_code == 400, (what, response.status_code, response.content[:200])
        body = response.json()
        assert body["code"] == outcome_pages.BAD_CURSOR == "bad_cursor", what
        assert "outcomes" not in body and "next" not in body, what
        answers.add(json.dumps(body, sort_keys=True))
    # One refusal for every way a cursor can be wrong.
    assert len(answers) == 1

    twice = client.get(_url(dep, before=[cursor, cursor]))
    assert twice.status_code == 400 and twice.json()["code"] == outcome_pages.BAD_CURSOR
    # And the cursor itself, unedited, reads the rest.
    assert client.get(_url(dep, before=cursor)).json()["returned"] == 5


@pytest.mark.parametrize("value", ["gate", "", "OBSERVED_EFFECT", "observed_effect ", "attested", "authorization_check"])
def test_an_unknown_recorded_as_is_a_400_with_a_code_and_never_every_row_or_none(value):
    dep = _deployment()
    _typed(dep, 3)
    response = _client(dep.owner).get(_url(dep, recorded_as=value))
    assert response.status_code == 400
    body = response.json()
    assert body["code"] == outcome_pages.UNKNOWN_RECORDED_AS == "unknown_recorded_as"
    assert "'observed_effect'" in body["error"] and "outcomes" not in body


def test_a_filter_given_twice_is_refused_even_when_both_are_the_known_value():
    dep = _deployment()
    response = _client(dep.owner).get(_url(dep, recorded_as=["observed_effect", "observed_effect"]))
    assert response.status_code == 400 and response.json()["code"] == outcome_pages.UNKNOWN_RECORDED_AS


# --------------------------------------------------------------------------
# Access: the same as it was, and a cursor opens nothing.
# --------------------------------------------------------------------------


def test_a_cursor_from_one_deployment_is_refused_on_another_with_the_words_any_bad_cursor_gets():
    admin = _user()
    one, other = _deployment(admin), _deployment(admin)
    _typed(one, SIZE + 5)
    _typed(other, SIZE + 5)
    client = _client(admin)
    cursor = _a_cursor(client, one)

    crossed = client.get(_url(other, before=cursor))
    garbage = client.get(_url(other, before="not-a-cursor"))

    assert crossed.status_code == garbage.status_code == 400
    # Exactly the answer a made-up cursor gets: nothing says the cursor was real
    # somewhere else.
    assert crossed.json() == garbage.json() and crossed.json()["code"] == outcome_pages.BAD_CURSOR
    assert str(one.uuid) not in crossed.content.decode()
    # It still reads its own deployment.
    assert client.get(_url(one, before=cursor)).json()["returned"] == 5


def test_a_cursor_changes_nothing_about_who_may_read_a_deployment():
    """A person who cannot see a deployment is told 404 about the deployment, with
    or without a cursor, good or bad, exactly as for a deployment that does not
    exist. And a cursor for a deployment they cannot see, used on their own, is the
    refusal a made-up one gets."""
    theirs = _deployment()
    _typed(theirs, SIZE + 5)
    cursor = _a_cursor(_client(theirs.owner), theirs)
    viewer = _user(User.Roles.VIEWER)
    own = _deployment(viewer)
    _typed(own, 3)
    outsider = _client(viewer)
    nowhere = "00000000-0000-4000-8000-000000000000"

    plain = outsider.get(_url(theirs))
    assert plain.status_code == 404
    for params in ({"before": cursor}, {"before": "not-a-cursor"}, {"recorded_as": "gate"}, {"recorded_as": "observed_effect"}):
        hidden = outsider.get(_url(theirs, **params))
        absent = outsider.get(_url(nowhere, **params))
        assert hidden.status_code == absent.status_code == 404, params
        assert hidden.content == plain.content == absent.content, params

    crossed = outsider.get(_url(own, before=cursor))
    made_up = outsider.get(_url(own, before="not-a-cursor"))
    assert crossed.status_code == 400 and crossed.json() == made_up.json()
    # A viewer reads their own deployment's pages as before.
    assert outsider.get(_url(own)).json()["returned"] == 3
    # And an anonymous request reads none, cursor or no cursor.
    assert APIClient().get(_url(theirs, before=cursor)).status_code in (401, 403)


# --------------------------------------------------------------------------
# The row is one shape on every page.
# --------------------------------------------------------------------------


def test_a_row_reads_byte_for_byte_the_same_on_page_two_as_on_page_one(monkeypatch):
    """Observed effects, a scan and typed-in rows, read once on one page and once
    two to a page. Each row is the same bytes wherever it falls, its
    ``effect_reading`` included."""
    dep = _deployment()
    _mixed(dep)
    client = _client(dep.owner)
    (whole,) = _walk(client, dep)
    on_page_one = {row["uuid"]: json.dumps(row) for row in whole["outcomes"]}
    assert sum(row["effect_reading"] is not None for row in whole["outcomes"]) == 3

    monkeypatch.setattr(DeploymentViewSet, "CHAIN_OUTCOME_PAGE_SIZE", 2)
    pages = _walk(client, dep)

    assert len(pages) == 7 and [uuid for page in pages for uuid in _served(page)] == _served(whole)
    later = [row for page in pages[1:] for row in page["outcomes"]]
    assert sum(row["effect_reading"] is not None for row in later) >= 2
    for row in later:
        assert json.dumps(row) == on_page_one[row["uuid"]]


# --------------------------------------------------------------------------
# What a page costs.
# --------------------------------------------------------------------------


def _statements(client, url):
    with CaptureQueriesContext(connection) as captured:
        response = client.get(url)
    assert response.status_code == 200
    return response.json(), [query["sql"] for query in captured.captured_queries]


def _page_reads(statements, size):
    table = WorkflowChainOutcome._meta.db_table
    return [sql for sql in statements if table in sql and f"LIMIT {size + 1}" in sql]


def test_a_page_is_one_bounded_query_and_costs_the_same_whatever_it_holds():
    """One statement reads the page, for one row more than it serves. And the whole
    request costs the same number of statements for a hundred rows as for three,
    on the first page, a middle one and the last, filtered or not: nothing is read
    once per row."""
    dep = _deployment()
    _typed(dep, 103)
    _typed(dep, 100, first=T0 + timedelta(hours=1), basis=comp.BASIS_DEMONSTRATED, observer_engine="achilles-effect")
    client = _client(dep.owner)

    first, first_sql = _statements(client, _url(dep))
    second, second_sql = _statements(client, _url(dep, before=first["next"]))
    third, third_sql = _statements(client, _url(dep, before=second["next"]))
    filtered, filtered_sql = _statements(client, _url(dep, recorded_as="observed_effect"))

    assert [page["returned"] for page in (first, second, third, filtered)] == [100, 100, 3, 100]
    for statements in (first_sql, second_sql, third_sql, filtered_sql):
        assert len(_page_reads(statements, SIZE)) == 1
    assert len(first_sql) == len(second_sql) == len(third_sql) == len(filtered_sql)
    # The page is not an offset into the walk.
    assert not any("OFFSET" in sql for sql in first_sql + second_sql + third_sql + filtered_sql)


def test_a_page_of_observed_effects_costs_no_more_statements_than_a_page_of_one(monkeypatch):
    """The costly rows: each is verified against the keyring and read from its
    evidence document. One of them to a page and six of them to a page are the same
    number of statements."""
    dep = _deployment()
    for n in range(6):
        _effect(dep, n, minutes_ago=30 - n)
    client = _client(dep.owner)
    url = _url(dep, recorded_as="observed_effect")

    monkeypatch.setattr(DeploymentViewSet, "CHAIN_OUTCOME_PAGE_SIZE", 1)
    one, one_sql = _statements(client, url)
    monkeypatch.setattr(DeploymentViewSet, "CHAIN_OUTCOME_PAGE_SIZE", 6)
    six, six_sql = _statements(client, url)

    assert (one["returned"], six["returned"]) == (1, 6)
    assert all(row["effect_reading"] is not None for row in six["outcomes"])
    assert len(one_sql) == len(six_sql)


# --------------------------------------------------------------------------
# A POST still answers the first page.
# --------------------------------------------------------------------------


def test_a_post_answers_the_first_page_whatever_its_query_string_says():
    dep = _deployment()
    _typed(dep, SIZE + 5)
    client = _client(dep.owner)
    body = {"workflow": "posted", "status": comp.HELD, "observed_at": (timezone.now() - timedelta(minutes=1)).isoformat()}

    posted = client.post(_url(dep, before="not-a-cursor", recorded_as="gate"), body, format="json")

    assert posted.status_code == 200
    answer = posted.json()
    assert set(answer) == KEYS_NOW
    first = client.get(_url(dep)).json()
    assert answer["outcomes"] == first["outcomes"] and answer["outcomes"][0]["workflow"] == "posted"
    assert (answer["returned"], answer["truncated"]) == (SIZE, True)
    assert answer["recorded_count"] == answer["matching_count"] == SIZE + 6
    # Its `next` is the first page's own: the walk goes on from a POST's answer.
    rest = client.get(_url(dep, before=answer["next"])).json()
    assert rest["returned"] == 6 and rest["next"] is None
