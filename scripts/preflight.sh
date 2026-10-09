#!/usr/bin/env bash
# scripts/preflight.sh — local reproduction of the CI gates before `git push`.
# Every command is the one CI runs. A step this file does not cover is a step
# that can only fail remotely — when a workflow step is added, add it here in
# the same commit. Run `--quick` before every push.
#
# usage: scripts/preflight.sh [--quick]   (--quick skips the test / bench suites)
set -euo pipefail
cd "$(dirname "$0")/.."

quick=0
[[ "${1:-}" == "--quick" ]] && quick=1

step() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
# `cargo clippy` reuses fresh `cargo check` artifacts and then lints nothing;
# touching the crate roots invalidates only this repo's fingerprints.
relint() { git ls-files | grep -E '(^|/)src/(lib|main)\.rs$' | xargs -r touch; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1 ($2)" >&2; exit 1; }; }
has_toolchain() { rustup toolchain list | grep -q "^$1"; }

# Steps CI runs that this file cannot reproduce locally (they can only fail remotely):
#   - ci.yml:lint-frontend:run (no cargo / grep)
#   - ci.yml:lint-frontend:run (no cargo / grep)

need actionlint "brew install actionlint"

step "ci.yml / root-crate: fmt / clippy / test"
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test --no-fail-fast 2>&1 | tee /tmp/datashield-root-test.log
python3 -c "import re,sys; t=sum(int(m) for m in re.findall(r'test result: \w+\. (\d+) passed', open('/tmp/datashield-root-test.log', encoding='utf-8', errors='replace').read())); print('tests passed in total:', t); sys.exit(0 if t > 0 else 1)"

step "ci.yml / test-rust: run [service=core-engine]"
( cd services/core-engine && cargo check )

step "ci.yml / test-rust: run [service=core-engine]"
relint
( cd services/core-engine && cargo clippy -- -D warnings )

step "ci.yml / test-rust: run [service=api-gateway]"
( cd services/api-gateway && cargo check )

step "ci.yml / test-rust: run [service=api-gateway]"
relint
( cd services/api-gateway && cargo clippy -- -D warnings )

step "ci.yml / actionlint: actionlint"
actionlint .github/workflows/*.yml

if [[ $quick -eq 1 ]]; then
  echo; echo "preflight --quick OK (test / bench suites skipped)"; exit 0
fi

echo; echo "preflight OK"
