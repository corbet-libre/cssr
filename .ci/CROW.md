# Crow checks

The manual `ccid` workflow runs the same formatting, lint, test and real HTTPS
libSQL fixture commands as the native GitHub check. It resolves one fresh Cargo
lock, retains it with compiler identity under `$CARGO_HOME/ccid-artifacts/cssr-native/`,
and checks that none of the validation commands changed it. An exact-source `native.json` receipt
records success or failure and file hashes outside disposable source extraction.

Source and original first-party Git transports are bound to verified archives;
the workflow pins the shared executor and reviewed closure consumer. Use the
existing Crow helper with the stable provisioned supplement and an observed-main
dependency closure. The work runs only on the CI worker, with persistent package
and target caches supplied by the executor.

A green `native` selector is partial evidence. The original GitHub coverage,
source inventory, dependency policy and advisory/license gates still apply.
This selector neither accepts an entire G2 integration nor promotes a lockfile.

The `original-suite` selector additionally runs the original dependency metadata,
advisory/license and strict source coverage commands using that same lock. The
coverage compiler setup is an existing provisioned artifact with a checked
SHA-256. LCOV, JSON and annotated text must agree under the unchanged original
checker, which requires every emitted source line and branch. Reports identify
the selected scope; neither selector constitutes Opus or end-to-end G2 acceptance.
