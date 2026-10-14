#!/usr/bin/env bash
set -euo pipefail
exec 2>&1
CSSR_LAST_GATE="init"
trap 'rc=$?; echo "CSSR-DIAG last_gate=$CSSR_LAST_GATE exit=$rc" >&2; exit $rc' EXIT
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"

CSSR_LAST_GATE="resolve-first-party"
python3 .github/check-first-party.py
CSSR_LAST_GATE="toolchain"
rustc --version
CSSR_LAST_GATE="fmt"
bash .ci/update-our-crates.sh
cargo fmt --check || { cargo fmt; git diff > formatting.patch; exit 1; }
CSSR_LAST_GATE="clippy"
cargo clippy --locked --all-targets -- -D warnings
CSSR_LAST_GATE="native-tests"
cargo test --locked
CSSR_LAST_GATE="remote-sqld"
bash .ci/remote-sqld.sh

CSSR_LAST_GATE="metadata"
cargo metadata --locked --format-version 1 > dependency-metadata.json
CSSR_LAST_GATE="advisory-exposure"
node .github/check-advisory-exposure.mjs

CSSR_LAST_GATE="nightly-select"
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
CSSR_LAST_GATE="coverage"
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly --ignore-filename-regex '/tests/' --json --output-path coverage.json
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '/tests/' --lcov --output-path coverage.lcov
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '/tests/' --text --output-path coverage.txt
)
CSSR_LAST_GATE="coverage-check"
python3 .github/test-source-coverage.py
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt
