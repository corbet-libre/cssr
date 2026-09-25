# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Issuer for zero-knowledge accounting: accepts a verified change and records it.
- Accepts verified changes and records the new commitment, version and settlement markers.
- Never knows its holders; never stores balances, counterparts, receipts or history.
- Never verifies proofs itself (that is `cvfy`).
- This crate is LGPL-3.0-only WITH LGPL-3.0-linking-exception. Do not add implementation code available only under the full GPL or AGPL.
- Called only through `cblc`; `cvld` never talks to `cssr` directly.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets` (no warnings),
  `cargo test` — all green before every commit. No local workstation
  builds; use GHA, Crow as fallback.
