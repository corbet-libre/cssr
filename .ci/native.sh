#!/usr/bin/env bash
# CI-only source checks; the selected scope and exact artifacts are recorded.
set -euo pipefail
scope=${1:-native}
case "$scope" in native|original-suite) ;; *) exit 2;; esac
export CSSR_CHECK_SCOPE="$scope"
: "${CI:?CI only}" "${CARGO_HOME:?persistent cache required}" "${CI_COMMIT_SHA:?}"
# ccid removes its extracted source after checks; retain evidence outside it.
mkdir -p "$CARGO_HOME/ccid-artifacts/cssr-native"
report_dir=$(mktemp -d "$CARGO_HOME/ccid-artifacts/cssr-native/$CI_COMMIT_SHA.XXXXXXXX")
retain_result() {
    result=$?
    if [[ -f Cargo.lock ]]; then cp Cargo.lock "$report_dir/final-Cargo.lock"; fi
    python3 - "$report_dir" "$result" <<'RECEIPT'
import hashlib, json, os, pathlib, sys
root, code = pathlib.Path(sys.argv[1]), int(sys.argv[2])
files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}
receipt = {'schema': 1, 'scope': os.environ['CSSR_CHECK_SCOPE'], 'status': 'passed' if code == 0 else 'failed',
           'exit_code': code, 'commit': os.environ['CI_COMMIT_SHA'],
           'source_sha256': os.environ['SOURCE_SHA256'],
           'repository': os.environ['CI_REPOSITORY_URL'], 'artifacts': files,
           'product_acceptance': False}
(root / 'native.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps({'native_receipt': str(root / 'native.json'), 'status': receipt['status']}))
RECEIPT
    exit "$result"
}
trap retain_result EXIT
rustc --version --verbose > "$report_dir/rustc.txt"
cargo --version > "$report_dir/cargo.txt"
if [[ -f Cargo.lock ]]; then cp Cargo.lock "$report_dir/baseline-Cargo.lock"; fi
python3 .ci/check-first-party-archive.py
# Resolve once and retain the exact lock used by every check below.
cargo update
date -u +%FT%TZ > "$report_dir/resolved-at.txt"
cp Cargo.lock "$report_dir/Cargo.lock"
sha256sum Cargo.lock > "$report_dir/lock.sha256"
python3 .ci/check-first-party-archive.py
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
# Real libSQL over HTTPS, using the repository's checksum-pinned synthetic fixture.
bash .ci/remote-sqld.sh
if [[ "$scope" == original-suite ]]; then
    cargo metadata --locked --format-version 1 > dependency-metadata.json
    cp dependency-metadata.json "$report_dir/dependency-metadata.json"
    node .github/check-advisory-exposure.mjs
    cargo deny --locked check advisories licenses
    # Use the already provisioned nightly/LLVM toolset; no local installation.
    coverage_setup=/nix/store/hddk15hgahw73wk2hdfir1v0si7vcs61-cmty-wasm-coverage-tools/share/cmty-wasm-coverage-tools/setup.sh
    printf '%s  %s\n' b169bbb42929bbb673f1eda497d98cae1891803c4c6285471f8735d880047e3b "$coverage_setup" | sha256sum --check --strict
    (
        . "$coverage_setup"
        rustc --version --verbose > "$report_dir/coverage-rustc.txt"
        cargo llvm-cov --version > "$report_dir/coverage-tool.txt"
        cargo llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage \
          --no-cfg-coverage-nightly --ignore-filename-regex '/tests/' --json --output-path "$report_dir/coverage.json"
        cargo llvm-cov report --branch --ignore-filename-regex '/tests/' --lcov --output-path "$report_dir/coverage.lcov"
        cargo llvm-cov report --branch --ignore-filename-regex '/tests/' --text --output-path "$report_dir/coverage.txt"
        python3 .github/test-source-coverage.py
        python3 .github/check-source-coverage.py "$report_dir/coverage.lcov" "$report_dir/coverage.json" "$report_dir/coverage.txt"
    )
fi
sha256sum --check --strict "$report_dir/lock.sha256"
printf '%s\n' "Passed $scope checks. Independent review, G2 integration and Opus acceptance remain separate."
