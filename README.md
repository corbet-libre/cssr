# cssr

The issuer records already-verified changes through a small `Storage` / `Transaction` trait. `MemoryStore` supplies atomic in-memory transactions; `LibsqlStore` uses [crlt](https://github.com/corbet-foss/crlt), whose API was available on main at `6b94dacd7fa04aa8847c62c6471a1fc5c0f6c9dc`. It deliberately knows neither holders nor policies and never verifies proofs.

Survey (2026-09-30): choose crlt over direct [libsql](https://crates.io/crates/libsql) because it provides the required namespace, migration and index-plan checks. rusqlite would not cover remote Turso; an ORM adds no value for three exact-key queries. Tokio bridges the existing synchronous issuer API; URL handles local file paths.

All records are keyed by `(community_id, key)` in `cssr_records`; reads, updates and deletes use its primary key. Deploy one database per community. An immediate transaction holds the read/write lock until commit; drop rolls back. Only current commitments, configuration and opaque settlement markers belong in these records. The facade is responsible for enforcing that content boundary. No history scans, request logs or credential loading.

Use `LibsqlStore::local` for standalone tests. Services install `SCHEMA` in their complete migration history and call `from_community` with the existing crlt capability and runtime. Synchronous operations must run on a blocking thread outside Tokio. The optional real-Turso test runs only if both `TURSO_URL` and `TURSO_TOKEN` are nonempty, against a disposable database; credentials are not in CI.

GitHub Actions runs stable Rust formatting, clippy with warnings denied, and tests. No workstation builds. See [CONTRACT](docs/CONTRACT.md).

Copyright 2026 Julian Y. Richard Corbet. LGPL-3.0-only WITH LGPL-3.0-linking-exception; see [LICENSE.md](LICENSE.md).
