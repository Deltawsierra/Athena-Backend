# Assurance Receipt specification

The Mythos Assurance Receipt is athena-backend's portable record of a deployment's
assurance state: system, policy, evidence root, coverage, served route, workflow
chains and decision. athena-engine signs it. These files specify it, one file per
receipt version, so that anyone holding a receipt can verify it with the
specification and [`tools/verify_receipt.py`](../../tools/verify_receipt.py) alone.

A receipt attests integrity and provenance: this is the assurance state that was
recorded, unaltered. It never attests that the conclusions are true or the system
secure. From 4.1 a signed receipt carries the time it was issued, `issued_at`,
under the signature: the issuer's clock, not proof of when the state held. A 4.0
signed receipt carries no signing time. From 5.0 a receipt also says which authority
chain produced each consequential effect, and which of its hops nothing proves. From
6.0 it says which consequential effects no authority chain names at all, and which
approved tools declare no effect class.

| Receipt version | Specification | Status |
|---|---|---|
| `mythos.assurance.receipt/6.0` | [v6.0.md](v6.0.md) | Current: what `RECEIPT_VERSION` emits. Adds `consequential_effects`: every effect the approvals cover, its class, and whether an authority chain in force names it. |
| `mythos.assurance.receipt/5.0` | [v5.0.md](v5.0.md), and [v6.0.md, section 8.3](v6.0.md#83-every-version-ever-emitted-and-what-it-lacks) | Superseded, still readable. The verifier reads it and says it lacks `consequential_effects`; the backend's `receipt_schema(version)` still describes it. |
| `mythos.assurance.receipt/4.1` | [v4.1.md](v4.1.md), and [v6.0.md, section 8.3](v6.0.md#83-every-version-ever-emitted-and-what-it-lacks) | Superseded, still readable. The verifier reads it and says it lacks `authority_chains` and `consequential_effects`; the backend's `receipt_schema(version)` still describes it. |
| `mythos.assurance.receipt/4.0` | [v4.0.md](v4.0.md), and [v6.0.md, section 8.3](v6.0.md#83-every-version-ever-emitted-and-what-it-lacks) | Superseded, still readable. The verifier reads it and shows its issue time as not signed; the backend's `receipt_schema(version)` still describes it. v4.0.md's section 5.1 example prints the characters where the canonical bytes are their `\uXXXX` escapes, and its 6.2 names the six characters by the character; v4.1.md's are the bytes. |
| `mythos.assurance.receipt/3.1`, `3.0`, `2.0`, `1.1`, `1.0` | [v6.0.md, section 8.3](v6.0.md#83-every-version-ever-emitted-and-what-it-lacks) | Superseded, still readable: every version ever emitted, 2.0 in both shapes it was emitted in (#56's and #67's), each named. The verifier reads them and says what each lacks; the backend's `receipt_schema(version)` describes them, with what each lacks and whether any route ever signed one. No route signed a receipt before 3.1. |

Each new receipt version adds a file here, and the older files stay
([v6.0.md, section 8.4](v6.0.md#84-the-rule-for-the-next-version)).
`tests/test_receipt_spec_conformance.py` fails while the version the code emits has
no file, or while this index does not list it.
