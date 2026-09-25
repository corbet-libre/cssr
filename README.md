# cssr

**Zero-knowledge accounting issuer.**

`cssr` is the issuer in the issuer-verifier-holder schema: it accepts a change that `cvfy` has verified and records it permanently. It is unit-agnostic; the unit and its rules live only in the policy. `cblc` is its caller.

Status: name reserved, no implementation yet.

## Boundaries

What it does:

- Accepts verified changes and records the new commitment, version and settlement markers.

What it never does:

- Never knows its holders; never stores balances, counterparts, receipts or history.
- Never verifies proofs itself (that is `cvfy`).

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).
