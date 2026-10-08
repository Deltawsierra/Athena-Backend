"""The governance rules, as pure functions with a refusal code each.

The owner adopted three on 8 Oct 2026 for Economic Exposure, and the model-risk
discipline of the specification (section 26) adds the inventory's:

- a scenario's reviewer is someone other than the author of any version of it;
- a sensitive override is in force only with two approvals, from two different
  people, neither of them the person who asked for it;
- a source whose license nobody has reviewed is never used by a production run;
- a model inventory entry names its owner, its intended use and its limitations.

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
from types import MappingProxyType

from .provenance import LicenseClass

#: How many different people approve a sensitive override before it is in force.
REQUIRED_OVERRIDE_APPROVERS = 2

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
        "license_class_unrecognised": "the source's license class is not one this platform knows, so no production "
        "run may use it",
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
    }
)

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


def production_use_refusal(license_class: str) -> str | None:
    """Whether a production run may use a source of ``license_class``. Only a
    reviewed class may; a class this platform does not know is refused as well."""
    try:
        recognised = LicenseClass(license_class)
    except ValueError:
        return "license_class_unrecognised"
    if recognised is LicenseClass.UNREVIEWED:
        return "unreviewed_license"
    return None


_SNAPSHOT_HASH = re.compile(r"sha256:[0-9a-f]{64}")


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
