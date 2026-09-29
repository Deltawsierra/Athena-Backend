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
signed receipt carries no signing time.

| Receipt version | Specification | Status |
|---|---|---|
| `mythos.assurance.receipt/4.1` | [v4.1.md](v4.1.md) | Current: what `RECEIPT_VERSION` emits. |
| `mythos.assurance.receipt/4.0` | [v4.0.md](v4.0.md), and [v4.1.md, section 8](v4.1.md#8-versions) | Superseded, still readable. The verifier reads it and shows its issue time as not signed; the backend's `receipt_schema(version)` still describes it. |
| `mythos.assurance.receipt/3.1`, `3.0`, `2.0`, `1.1` | [v4.1.md, section 8](v4.1.md#8-versions) | Superseded, still readable. The verifier reads them, and the backend's `receipt_schema(version)` still describes them. |
| `mythos.assurance.receipt/1.0` | [v4.1.md, section 10](v4.1.md#10-known-limitations-of-41) | Superseded and not readable: refused as an unknown version. |

Each new receipt version adds a file here, and the older files stay
([v4.1.md, section 8.4](v4.1.md#84-the-rule-for-the-next-version)).
`tests/test_receipt_spec_conformance.py` fails while the version the code emits has
no file, or while this index does not list it.
