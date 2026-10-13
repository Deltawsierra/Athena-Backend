"""The governance rules, as pure functions with a refusal code each.

The owner adopted three on 8 Oct 2026 for Economic Exposure, and the model-risk
discipline of the specification (section 26) adds the inventory's:

- a scenario's reviewer is someone other than the author of any version of it;
- a sensitive override is in force only with two approvals, from two different
  people, neither of them the person who asked for it;
- a source whose license nobody has reviewed is never used by a production run;
- a model inventory entry names its owner, its intended use and its limitations.

The owner added one on 12 Oct 2026, before the first customer run: a production
run never relies on a source whose trust tier is still ``unverified`` (the
default) -- :func:`production_trust_refusal`. And, the same day, how a tier is
raised: only by an admin, only upward, only from the latest version of the source,
and to ``authoritative`` only with a second admin's approval --
:func:`trust_raise_refusal`, :func:`trust_raise_approval_refusal` and the rules
beside them.

Each function returns ``None`` when the rule holds and a code from
:data:`REFUSALS` when it does not, so the Django half
(:mod:`assurance.economics.models`) refuses a write with the same code a test, a
fixture or a later route reads. The codes are what a record carries; the words
beside them are for a reader.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from types import MappingProxyType

from .provenance import LicenseClass, TrustTier

#: How many different people approve a sensitive override before it is in force.
REQUIRED_OVERRIDE_APPROVERS = 2

#: The longest reason a raise of a source's trust tier records, in characters.
TRUST_RAISE_REASON_MAX = 2000

#: How long a pending raise waits for its second admin (the owner's decision of 13 Oct
#: 2026): from its request, to the instant. Past it the request is ``expired`` and is
#: never approved; it is requested again.
TRUST_RAISE_EXPIRES_AFTER = timedelta(days=30)

#: How long a sensitive override counts once it is in force (spec, section 35): from
#: its request, to the instant. Past it the override is ``override_expired`` and
#: counts for nothing; it is requested again.
OVERRIDE_EXPIRES_AFTER = timedelta(days=30)

#: What each refusal code means, published beside it.
REFUSALS: Mapping[str, str] = MappingProxyType(
    {
        "author_reviews_own_scenario": (
            "the reviewer wrote this scenario or a version it supersedes: a scenario is reviewed by someone other "
            "than the author of any of its versions"
        ),
        "author_not_named": (
            "no version of this scenario names its author, so nothing shows the reviewer is someone else: a person "
            "authors a version before it is reviewed"
        ),
        "reviewer_not_named": "the review names no reviewer account: a review is written by a signed-in person",
        "requester_not_named": (
            "the override names no requester account: an override is requested by a signed-in person"
        ),
        "approver_not_named": "the approval names no approver account: an approval is written by a signed-in person",
        "requester_approves_own_override": (
            "the approver asked for this override: its approvals come from people other than the one who asked"
        ),
        "approver_already_approved": (
            "this person has already approved this override: its approvals come from different people"
        ),
        "override_needs_two_approvers": (
            "a sensitive override is in force only once two different people, neither of them the one who asked "
            "for it, have approved it"
        ),
        "unreviewed_license": "nobody has reviewed this source's license terms, so no production run may use it",
        "synthetic_source": (
            "the source is synthetic test data: no production run ever uses it, whatever its licence, and it is "
            "never trusted above unverified"
        ),
        "license_class_unrecognised": "the source's license class is not one this platform knows, so no production "
        "run may use it",
        "source_unverified": (
            "the source's trust tier is still unverified (the default): nothing yet establishes how reliable it is, "
            "so no production run relies on it until a person records a version of it at a tier above unverified"
        ),
        "snapshot_hash_malformed": "a snapshot hash is 'sha256:' followed by 64 lowercase hexadecimal digits",
        "inventory_entry_incomplete": (
            "a model inventory entry names its model, version, owner, intended use and limitations"
        ),
        "override_incomplete": "an override says what it overrides and why",
        "spine_reference_malformed": (
            "a reference into SPINE is in the form SPINE names that thing by (see REFERENCE_FORMS)"
        ),
        "cross_tenant_reference": (
            "the record points at a record of another deployment: one tenant's records never reach another's"
        ),
        "bulk_create_refused": (
            "an economics record is written one at a time, through the checks its model runs when it is saved"
        ),
        "code_unrecognised": "a coded field holds a value outside its codes",
        "required_field_blank": "a required field is blank",
        "customer_source_without_tenant": (
            "a customer's own data belongs to that customer's deployment: a platform-wide source is never licensed "
            "or trusted as customer data"
        ),
        # Raising a source's trust tier (the owner's decision of 12 Oct 2026).
        "admin_required": (
            "only an admin (role admin, or a superuser) requests, approves or withdraws a raise of a source's trust "
            "tier"
        ),
        "trust_not_raised": (
            "a raise moves a source to a tier above the one it has (weakest to strongest: unverified, benchmark, "
            "licensed_vendor, customer, authoritative); the same tier or a lower one is not a raise"
        ),
        "source_superseded": (
            "a raise starts from the latest version of its source, and is approved only while that version is still "
            "the latest: a newer version has been recorded since"
        ),
        "second_person_required": (
            "an authoritative version is recorded only by a raise one admin requested and ANOTHER approved, "
            "through the signed-in route: never by the requester, never by the operator's command, never by a "
            "snapshot or any other write"
        ),
        "trust_raise_not_pending": (
            "the raise is no longer pending: a request is approved or withdrawn once, and a raise that is done, "
            "withdrawn or expired stays as it is"
        ),
        "requester_no_longer_admin": (
            "the admin who requested this raise is no longer an active admin, or their account is gone: it is "
            "not approved, and any admin may withdraw it"
        ),
        "reason_too_long": f"a raise's reason is at most {TRUST_RAISE_REASON_MAX} characters",
        "trust_raise_expired": (
            f"a pending raise expires {TRUST_RAISE_EXPIRES_AFTER.days} days after its request and is never "
            "approved or withdrawn after that: request it again"
        ),
        # The owner's decision of 13 Oct 2026, once the official publishers are wired.
        "source_not_authoritative": (
            "an FX or cost-index source behind a production run's receipt is trusted as authoritative (the official "
            "publisher, raised by two admins): a lower tier may feed a run, never a production receipt"
        ),
        # Section 28 hardening (spec, section 35).
        "approver_role_not_independent": (
            "the approver's role was granted by the person who asked for this (the requester, or an author of the "
            "scenario), by the approver themselves, or after it was asked for: a second person is someone who held "
            "the role independently before the request"
        ),
        "override_expired": (
            f"an override is in force for {OVERRIDE_EXPIRES_AFTER.days} days from its request and no longer: "
            "request it again"
        ),
        "override_revoked": "the override was revoked: it is not in force, and a revocation is never undone",
        "snapshot_rows_mismatch": (
            "a source version's stored observation rows no longer give the digests recorded when it was "
            "registered (a row rewritten, added or removed past the records' rules): the version is demoted, and "
            "no run uses it"
        ),
    }
)

#: The trust tiers, WEAKEST first: the order a tier is raised in. (The enum is
#: written strongest first.)
TRUST_ORDER: tuple[TrustTier, ...] = (
    TrustTier.UNVERIFIED,
    TrustTier.BENCHMARK,
    TrustTier.LICENSED_VENDOR,
    TrustTier.CUSTOMER,
    TrustTier.AUTHORITATIVE,
)

#: The tiers a raise to needs a second person: requested by one admin, approved by
#: another.
TWO_PERSON_TIERS: frozenset[TrustTier] = frozenset({TrustTier.AUTHORITATIVE})

#: The one channel a second person approves through: the signed-in route, where the
#: approver is the account the request authenticated, never a name typed at a shell.
SIGNED_IN_CHANNEL = "api"

#: How SPINE names each thing a financial record may point at. Financial records
#: reference SPINE by these ids and never copy what they name (specification,
#: section 16: no shadow SPINE).
REFERENCE_FORMS: Mapping[str, str] = MappingProxyType(
    {
        # assurance.fingerprint.compute_system_fingerprint, as AssuranceClaim.system_fingerprint holds it
        "system_fingerprint": r"[0-9a-f]{64}",
        # assurance.authority_chain_records.effect_digest: what the receipt names an effect by
        "effect": r"sha256:[0-9a-f]{64}",
        # AssuranceClaim.claim_fingerprint: the identity every version of a claim shares
        "claim": r"[0-9a-f]{64}",
        # Asset.uuid: a node of the assurance graph, as the edge history names it
        "node": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    }
)


@dataclass(frozen=True)
class Person:
    """Who did something, as the record names them: the account's id and the
    username it had then.

    When a record is WRITTEN, the person is the signed-in account and nothing else:
    the Django half builds a Person from the account alone (its id and its own
    username), and an empty Person when there is none, so a typed-in name never
    stands for anyone. When a record is READ, an account removed since is
    ``id=None`` with its username kept, and still names that person. A person named
    by neither is nobody."""

    id: object = None
    username: str = ""

    @property
    def named(self) -> bool:
        return self.id is not None or bool((self.username or "").strip())


def same_person(a: Person, b: Person) -> bool:
    """Whether two records name the same person: the same account, or the same
    username. Matching on the username as well means a removed account's records
    still count as that person's, which can only make a separation rule stricter."""
    if a.id is not None and b.id is not None and a.id == b.id:
        return True
    name_a, name_b = (a.username or "").strip().casefold(), (b.username or "").strip().casefold()
    return bool(name_a) and name_a == name_b


def review_refusal(authors: Iterable[Person], reviewer: Person) -> str | None:
    """Whether ``reviewer`` may review a scenario whose versions -- the one reviewed
    and every one it supersedes, transitively -- were written by ``authors``.

    The reviewer authored none of them. A version a machine drafted names no
    author, and a line of versions in which none names one cannot be reviewed:
    nothing would show the reviewer is someone else."""
    if not reviewer.named:
        return "reviewer_not_named"
    named = [author for author in authors if author.named]
    if not named:
        return "author_not_named"
    if any(same_person(author, reviewer) for author in named):
        return "author_reviews_own_scenario"
    return None


def override_request_refusal(requester: Person, subject: str, reason: str) -> str | None:
    """Whether an override may be recorded: a named person asks for it, and it says
    what it overrides and why. Recording it puts nothing in force."""
    if not requester.named:
        return "requester_not_named"
    if not all(isinstance(v, str) and v.strip() for v in (subject, reason)):
        return "override_incomplete"
    return None


def approval_refusal(requester: Person, approved_by: Iterable[Person], approver: Person) -> str | None:
    """Whether ``approver`` may add an approval to an override ``requester`` asked
    for, which ``approved_by`` have approved already."""
    if not approver.named:
        return "approver_not_named"
    if same_person(requester, approver):
        return "requester_approves_own_override"
    if any(same_person(earlier, approver) for earlier in approved_by):
        return "approver_already_approved"
    return None


def override_refusal(requester: Person, approved_by: Iterable[Person]) -> str | None:
    """Whether an override ``requester`` asked for is in force on the approvals of
    ``approved_by``: two different named people, neither of them the requester."""
    if not requester.named:
        return "requester_not_named"
    distinct: list[Person] = []
    for person in approved_by:
        if not person.named or same_person(person, requester):
            continue
        if not any(same_person(person, counted) for counted in distinct):
            distinct.append(person)
    if len(distinct) < REQUIRED_OVERRIDE_APPROVERS:
        return "override_needs_two_approvers"
    return None


def override_in_force_refusal(
    requester: Person, approved_by: Iterable[Person], *, requested_at, revoked: bool, now
) -> str | None:
    """Whether an override counts NOW (spec, section 35): ``None`` only while it is in
    force. A revocation is final (``override_revoked``); an override counts for
    :data:`OVERRIDE_EXPIRES_AFTER` from its request and no longer, to the instant,
    by the service's own clock (``override_expired``; an override with no request
    time counts for nothing); and it needs its two approvers
    (:func:`override_refusal`)."""
    if revoked is not False:
        return "override_revoked"
    if requested_at is None or now >= requested_at + OVERRIDE_EXPIRES_AFTER:
        return "override_expired"
    return override_refusal(requester, approved_by)


#: Who granted an account the role it holds, and when, as the account's stored row
#: records it (``accounts.CustomUser.role_granted_at`` / ``role_granted_by``): a
#: promotion records it, a demotion never does.
@dataclass(frozen=True)
class RoleGrant:
    at: object = None
    by: Person | None = None


def role_grant_refusal(
    grant: RoleGrant | None, *, asked_by: Iterable[Person], approver: Person, asked_at
) -> str | None:
    """Whether an approver whose role was granted as ``grant`` records may approve
    something ``asked_by`` asked for at ``asked_at`` (the T9b rule, spec section 35).

    Refused (``approver_role_not_independent``) where the grant was made by one of
    ``asked_by`` or by the approver themselves (matched on the account and the
    username, as every separation rule here), or at or after ``asked_at``: a second
    person held the role independently before the request. An account whose grant
    is not recorded (``grant`` is ``None``, or records no instant) held its role
    before grants were recorded, and is not refused by this rule. It reads only who
    APPROVES: a demotion, a deactivation or a removal is never refused by it."""
    if grant is None or grant.at is None:
        return None
    by = grant.by or Person()
    if by.named and (same_person(by, approver) or any(same_person(by, person) for person in asked_by)):
        return "approver_role_not_independent"
    if asked_at is not None and grant.at >= asked_at:
        return "approver_role_not_independent"
    return None


def production_use_refusal(license_class: str, *, synthetic: bool = False) -> str | None:
    """Whether a production run may use a source of ``license_class``. Only a
    reviewed class may; a class this platform does not know is refused as well. A
    synthetic source -- made-up test data, such as the committed fixture snapshot --
    is refused whatever its licence: its licence says who may copy the numbers, not
    that they are true."""
    if synthetic is not False:
        return "synthetic_source"
    try:
        recognised = LicenseClass(license_class)
    except ValueError:
        return "license_class_unrecognised"
    if recognised is LicenseClass.UNREVIEWED:
        return "unreviewed_license"
    return None


def production_trust_refusal(trust_tier: str) -> str | None:
    """Whether a production run may rely on a source trusted as ``trust_tier`` (the
    owner's decision of 12 Oct 2026). ``unverified`` -- the default: nothing yet
    establishes how reliable the source is -- is refused (``source_unverified``), and
    so is a tier this platform does not know, which establishes nothing either. Every
    tier above it may: a person has said why the source is trusted that far.

    Which runs are production runs is the caller's to say
    (:meth:`assurance.economics.models.FinancialSource.production_use_refusal`); a
    test, a fixture or a non-production deployment's run keeps the gate without it."""
    try:
        recognised = TrustTier(trust_tier)
    except ValueError:
        return "source_unverified"
    if recognised is TrustTier.UNVERIFIED:
        return "source_unverified"
    return None


def production_authority_refusal(trust_tier: str) -> str | None:
    """Whether an FX or cost-index source trusted as ``trust_tier`` may stand behind a
    production run's receipt (the owner's decision of 13 Oct 2026): only
    ``authoritative``, the official publisher's tier, which two admins record
    (``source_not_authoritative`` for any other, and for a tier this platform does
    not know). It applies to FX and cost-index observations only, and only where the
    run is a production one: the caller says both, and checks the gate
    (:func:`production_use_refusal`, :func:`production_trust_refusal`) first."""
    if isinstance(trust_tier, str) and trust_tier == TrustTier.AUTHORITATIVE.value:
        return None
    return "source_not_authoritative"


def trust_raise_admin_refusal(is_admin: bool) -> str | None:
    """Whether a person may request, approve or withdraw a raise of a source's trust
    tier: an admin only (role admin, or a superuser), as every write to the
    assurance record is. The Django half says whether the signed-in account is one;
    anything but ``True`` is not."""
    if is_admin is True:
        return None
    return "admin_required"


def trust_raise_refusal(from_tier, to_tier, *, synthetic: bool, has_tenant: bool) -> str | None:
    """Whether a source version trusted as ``from_tier`` may be raised to
    ``to_tier`` (the owner's decision of 12 Oct 2026). Both are tiers this platform
    knows (``code_unrecognised``); a synthetic source is never trusted above
    ``unverified`` (``synthetic_source``); the new tier is strictly above the old
    one in :data:`TRUST_ORDER` (``trust_not_raised``); and a platform-wide source is
    never trusted as ``customer`` data (``customer_source_without_tenant``).

    Whether the version is still the latest of its source (``source_superseded``)
    is read from the stored rows, by the caller."""
    codes = [tier.value for tier in TrustTier]
    if code_refusal(from_tier, codes) is not None or code_refusal(to_tier, codes) is not None:
        return "code_unrecognised"
    if synthetic is not False:
        return "synthetic_source"
    if TRUST_ORDER.index(TrustTier(to_tier)) <= TRUST_ORDER.index(TrustTier(from_tier)):
        return "trust_not_raised"
    if TrustTier(to_tier) is TrustTier.CUSTOMER and has_tenant is not True:
        return "customer_source_without_tenant"
    return None


def needs_second_person(to_tier) -> bool:
    """Whether a raise to ``to_tier`` is requested by one admin and approved by
    another (:data:`TWO_PERSON_TIERS`), rather than recorded in one step."""
    return isinstance(to_tier, str) and to_tier in {tier.value for tier in TWO_PERSON_TIERS}


def trust_raise_reason_refusal(reason) -> str | None:
    """Whether ``reason`` is a raise's reason: text, not blank, and at most
    :data:`TRUST_RAISE_REASON_MAX` characters."""
    if not (isinstance(reason, str) and reason.strip()):
        return "required_field_blank"
    if len(reason) > TRUST_RAISE_REASON_MAX:
        return "reason_too_long"
    return None


def trust_raise_approval_refusal(requester: Person, approver: Person) -> str | None:
    """Whether ``approver`` may approve a raise ``requester`` asked for: a named
    person other than the requester (``second_person_required``), matched on the
    account and on the username, so a requester whose account was removed is still
    the requester."""
    if not approver.named:
        return "approver_not_named"
    if same_person(requester, approver):
        return "second_person_required"
    return None


def trust_raise_approval_channel_refusal(channel) -> str | None:
    """Whether a raise may be approved through ``channel``: only the signed-in route
    (:data:`SIGNED_IN_CHANNEL`). The operator's command never approves one
    (``second_person_required``): a name typed after ``--as`` is not a second person
    signed in."""
    if channel == SIGNED_IN_CHANNEL:
        return None
    return "second_person_required"


def trust_raise_expiry_refusal(requested_at, now) -> str | None:
    """Whether a pending raise requested at ``requested_at`` has expired by ``now``:
    :data:`TRUST_RAISE_EXPIRES_AFTER` after its request, to the instant. Both are the
    service's own times (the request's stored ``requested_at`` and its clock), never
    a time a caller sent."""
    if now >= requested_at + TRUST_RAISE_EXPIRES_AFTER:
        return "trust_raise_expired"
    return None


def trust_raise_requester_refusal(requester_is_admin: bool) -> str | None:
    """Whether a pending raise may still be approved: only while the admin who
    requested it is still an active admin (``requester_no_longer_admin``), so the
    first of the two people is one when the version is recorded."""
    if requester_is_admin is True:
        return None
    return "requester_no_longer_admin"


_SNAPSHOT_HASH = re.compile(r"sha256:[0-9a-f]{64}")


def observation_rows_refusal(rows_hold_their_digests: bool, found: str, recorded: Iterable[str]) -> str | None:
    """Whether a source version's stored observation rows are as it was registered
    with (section 28 hardening, T2c; spec, section 35.3): each row gives its own
    digest (``rows_hold_their_digests``), and ``found``, the digest of the rows read
    now, is every digest the version and its holder ``recorded`` (an empty one
    records nothing). Otherwise ``snapshot_rows_mismatch``: the version is demoted."""
    if rows_hold_their_digests is not True:
        return "snapshot_rows_mismatch"
    if any(digest and digest != found for digest in recorded):
        return "snapshot_rows_mismatch"
    return None


def snapshot_hash_refusal(value: str) -> str | None:
    """Whether ``value`` is a snapshot hash in the form the platform's other digests
    take (``sha256:`` and 64 lowercase hex digits)."""
    if isinstance(value, str) and _SNAPSHOT_HASH.fullmatch(value):
        return None
    return "snapshot_hash_malformed"


def spine_reference_refusal(kind: str, value: str) -> str | None:
    """Whether ``value`` names a SPINE thing of ``kind`` in the form SPINE uses
    (:data:`REFERENCE_FORMS`). A kind that is not listed is refused too."""
    form = REFERENCE_FORMS.get(kind)
    if form is not None and isinstance(value, str) and re.fullmatch(form, value):
        return None
    return "spine_reference_malformed"


def code_refusal(value, codes: Iterable[str]) -> str | None:
    """Whether ``value`` is one of ``codes``, exactly as written."""
    if isinstance(value, str) and value in set(codes):
        return None
    return "code_unrecognised"


def required_text_refusal(*values) -> str | None:
    """Whether every one of ``values`` is text that is not blank."""
    if all(isinstance(v, str) and v.strip() for v in values):
        return None
    return "required_field_blank"


def inventory_refusal(*, model_id: str, version: str, owner: str, intended_use: str, limitations: str) -> str | None:
    """Whether a model inventory entry says everything section 26 asks of one. The
    retirement date may be open; nothing else may be blank."""
    if all(isinstance(v, str) and v.strip() for v in (model_id, version, owner, intended_use, limitations)):
        return None
    return "inventory_entry_incomplete"
