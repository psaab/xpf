#!/usr/bin/env bash
# scripts/test-rust-leg1-selftest.sh -- #19133: `make test-rust` leg 1 reports
# EVERY test target. Without --no-fail-fast cargo stops at the first red test
# binary, so a red unit cell in the userspace-dp binary hid every
# userspace-dp/tests/* target.
#
# The leg-1 command is taken from the real recipe (`make -n test-rust`, the one
# `test --manifest-path userspace-dp/Cargo.toml --release` line) and run, with
# only its manifest path swapped, on a fixture crate: one deliberately red unit
# cell in a bin, and one deliberately red tests/ target that cargo runs after
# it.
#   - both: both failures appear (and the command exits nonzero);
#   - mutation: the same command without --no-fail-fast hides the tests/
#     failure, so this fixture can see the defect at all.
# Needs cargo and the pinned toolchain; exits 77 (SKIP) without them.
set -euo pipefail

top=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/test-rust-leg1-selftest.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS: $*"; }
bad() { fail=$((fail + 1)); echo "FAIL: $*"; }

cargo_bin=${CARGO:-cargo}
if ! command -v "$cargo_bin" >/dev/null 2>&1; then
	echo "SKIP: cargo not installed"
	exit 77
fi
if ! (cd "$top" && sh userspace-dp/build_support/dp-toolchain.sh userspace-dp/rust-toolchain.toml "$cargo_bin" >/dev/null 2>&1); then
	echo "SKIP: the pinned userspace-dp toolchain is not installed"
	exit 77
fi

# The fixture: a bin whose unit cell is red, then a red tests/ target.
fx="$tmp/fixture"
mkdir -p "$fx/src" "$fx/tests"
cat >"$fx/Cargo.toml" <<'TOML'
[package]
name = "leg1-fixture-19133"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]
TOML
cat >"$fx/src/main.rs" <<'RS'
fn main() {}

#[cfg(test)]
mod tests {
    #[test]
    fn red_unit_cell_19133() {
        panic!("deliberately red unit cell (#19133 fixture)");
    }
}
RS
cat >"$fx/tests/red_guard_19133.rs" <<'RS'
#[test]
fn red_tests_target_19133() {
    panic!("deliberately red tests/ target (#19133 fixture)");
}
RS

# Leg 1, exactly as the recipe spells it: continuation lines joined, the one
# line that runs the release suite on userspace-dp/Cargo.toml.
dry=$(make -s -n -C "$top" test-rust 2>/dev/null |
	awk '/\\$/ { sub(/\\$/, ""); printf "%s", $0; next } { print }')
leg1=$(printf '%s\n' "$dry" | grep -F -e 'test --manifest-path userspace-dp/Cargo.toml --release' || true)
if [[ $(printf '%s' "$leg1" | grep -c .) -ne 1 ]]; then
	bad "leg 1: expected exactly one release-suite line in \`make -n test-rust\`, found $(printf '%s' "$leg1" | grep -c .)"
	echo "test-rust leg1 selftest: ${pass} passed, ${fail} failed"
	exit 1
fi
ok "leg 1: one release-suite line found in \`make -n test-rust\`"
on_fixture=${leg1//--manifest-path userspace-dp\/Cargo.toml/--manifest-path $fx\/Cargo.toml}

# run_leg <command> <out>: run a leg-1 command from the repository root (its
# toolchain helpers are repo-relative) against the fixture; print its status.
run_leg() {
	local rc=0
	(cd "$top" && CARGO_TARGET_DIR="$tmp/target" CARGO_NET_OFFLINE=true bash -c "$1") >"$2" 2>&1 || rc=$?
	echo "$rc"
}
failed() { grep -qE "^test (tests::)?$1 \.\.\. FAILED\$" "$2"; }

rc=$(run_leg "$on_fixture" "$tmp/leg1.out")
if failed red_unit_cell_19133 "$tmp/leg1.out" && failed red_tests_target_19133 "$tmp/leg1.out"; then
	ok "both: the red unit cell AND the red tests/ target are reported"
else
	bad "both: missing a failure (unit=$(failed red_unit_cell_19133 "$tmp/leg1.out" && echo yes || echo no) tests=$(failed red_tests_target_19133 "$tmp/leg1.out" && echo yes || echo no)); last lines: $(tail -n 5 "$tmp/leg1.out" | tr '\n' '|')"
fi
if [[ "$rc" -ne 0 ]]; then
	ok "both: leg 1 exits nonzero ($rc) on red cells"
else
	bad "both: leg 1 exited 0 with red cells"
fi

# Mutation: leg 1 without --no-fail-fast must hide the tests/ failure.
if [[ "$on_fixture" != *" --no-fail-fast"* ]]; then
	bad "mutation: leg 1 carries no --no-fail-fast to remove"
else
	run_leg "${on_fixture// --no-fail-fast/}" "$tmp/mutant.out" >/dev/null
	if failed red_unit_cell_19133 "$tmp/mutant.out" && ! failed red_tests_target_19133 "$tmp/mutant.out"; then
		ok "mutation: without --no-fail-fast the red unit cell hides the red tests/ target"
	else
		bad "mutation: the fixture did not reproduce the masking; the 'both' cell proves nothing"
	fi
fi

echo "test-rust leg1 selftest: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
