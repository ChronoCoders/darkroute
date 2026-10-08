#!/usr/bin/env bash
# The gate. Every check this repository has, run in one place, locally.
# ARCHITECTURE 11 forbids GitHub Actions or any automated pipeline, so this
# script and the hooks under scripts/hooks are the whole of the enforcement.
#
# It keeps going after a failure, prints one PASS or FAIL line per step, and
# exits non-zero if any step failed. A missing tool is a failure that names the
# tool, never a silent skip, because a skipped check and a passing check are
# indistinguishable in the output.
#
# Controls come first. A pattern based check that stops matching reports a clean
# tree, so each pattern is proved against the literal it looks for before the
# check that uses it runs.
#
# CK_VERBOSE=1 ./gate.sh also prints the output of the steps that passed.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="$ROOT/scripts/lib/checks.sh"
[ -r "$LIB" ] || { echo "gate: shared check library unreachable at $LIB" >&2; exit 1; }
# shellcheck source=scripts/lib/checks.sh
. "$LIB"

cd "$ROOT" || exit 1

export PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin:$HOME/.cargo/bin"

echo "gate: $(git rev-parse --short HEAD 2>/dev/null || echo 'no HEAD') on $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
echo

ck_step "control: the dash class matches dashes and nothing else" ck_dash_self_test
ck_step "no em dash or en dash in tracked content"                ck_dash_tracked
ck_step "control: the naming patterns match their literals"       ck_naming_self_test
ck_step "no tooling name in tracked content, paths or identity"   ck_naming_tracked
ck_step "control: the crate root attribute check rejects a strip" ck_attr_self_test
ck_step "every crate root carries deny(warnings) and forbid(unsafe_code)" ck_attr_roots
ck_step "control: the path check catches a planted lookup and seed"  ck_path_self_test
ck_step "path code resolves no name and seeds no generator"      ck_path_no_resolution
ck_step "control: the accepted advisory file parses"              ck_accepted_file_self_test
ck_step "the rust and go toolchains are pinned"                   ck_toolchain_pins
ck_step "the git hooks are installed and executable"              ck_hooks_installed
ck_step "control: the identity rule rejects a wrong author"        ck_identity_self_test
ck_step "the configured git identity is the project author"        ck_identity_config

ck_step "cargo fmt"      ck_run cargo fmt --all --check
ck_step "cargo clippy"   ck_run cargo clippy --workspace --all-targets --all-features -- -D warnings
ck_step "cargo test"     ck_run cargo test --workspace
ck_step "cargo audit"    ck_cargo_audit

ck_step "go build"       ck_run_in authority go build ./...
ck_step "go vet"         ck_run_in authority go vet ./...
ck_step "gofmt"          ck_gofmt
ck_step "staticcheck"    ck_run_in authority staticcheck ./...
ck_step "control: the database check fails with no server" ck_test_db_control
ck_step "the test database is reachable with a complete schema" ck_test_db
ck_step "go test"        ck_go_test
ck_step "govulncheck"    ck_run_in authority govulncheck ./...

ck_step "tsc"            ck_run_in dashboard npx --no-install tsc --noEmit
ck_step "eslint"         ck_run_in dashboard npx --no-install eslint . --max-warnings=0
ck_step "next build"     ck_run_in dashboard npm run build
ck_step "npm audit"      ck_npm_audit

echo
if [ "$CK_FAILED" -eq 0 ]; then
	echo "GATE PASS  $CK_STEP steps, 0 failed"
	exit 0
fi
echo "GATE FAIL  $CK_STEP steps, $CK_FAILED failed"
exit 1
