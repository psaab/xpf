#!/usr/bin/env bash
# scripts/test-rust-leg1-selftest.sh -- #19133: `make test-rust` reports EVERY
# failure, at two levels.
#   1. Inside leg 1: without --no-fail-fast cargo stopped at the first red test
#      binary, so a red unit cell in the userspace-dp binary hid every
#      userspace-dp/tests/* target.
#   2. Across legs: each leg was a recipe line, so a red leg stopped make and
#      the legs after it never ran. Each leg now records its own failure, and
#      the recipe's last line exits nonzero naming every failed leg.
#
# The recipe is taken from the real Makefile (`make -n test-rust`, its two
# prerequisites excluded, continuation lines joined) and run line by line the
# way make runs it, stopping at the first line that exits nonzero. Only the
# manifest path is swapped, to a fixture crate: one bin with a deliberately red
# unit cell, then a deliberately red tests/ target. On that fixture leg 1 is
# red by construction, and leg 2's oracle census fails closed (the fixture
# holds none of the oracle's cells), so leg 2 is red too. Cells:
#   - both: leg 1 reports the red unit cell AND the red tests/ target;
#   - every leg: the recipe reaches its end, names leg 1 AND leg 2 as failed,
#     and exits nonzero;
#   - mutation: leg 1 without --no-fail-fast hides the tests/ failure;
#   - mutation: leg 1 without its failure record stops the recipe there, and
#     leg 2 is never run or reported.
# Needs cargo and the pinned toolchain; exits 77 (SKIP) without them.
set -euo pipefail

top=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/test-rust-leg1-selftest.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS: $*"; }
bad() { fail=$((fail + 1)); echo "FAIL: $*"; }
summary() {
	echo "test-rust selftest: ${pass} passed, ${fail} failed"
	[[ "$fail" -eq 0 ]]
}

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

# The recipe exactly as make would run it, one line per entry, manifest
# swapped to the fixture.
make -s -n -o lint-rust-baseline -o check-userspace-dt-needed -C "$top" test-rust 2>/dev/null |
	awk '/\\$/ { sub(/\\$/, ""); printf "%s", $0; next } { print }' |
	sed "s|--manifest-path userspace-dp/Cargo.toml|--manifest-path $fx/Cargo.toml|g" >"$tmp/recipe"
leg1=$(grep -F -e "test --manifest-path $fx/Cargo.toml --release" "$tmp/recipe" || true)
if [[ $(printf '%s' "$leg1" | grep -c .) -ne 1 ]]; then
	bad "recipe: expected exactly one release-suite (leg 1) line in \`make -n test-rust\`, found $(printf '%s' "$leg1" | grep -c .)"
	summary
	exit 1
fi
ok "recipe: one leg-1 line among $(grep -c . "$tmp/recipe") recipe lines"

# run_recipe <recipe file> <out>: each line in its own `sh -c`, from the
# repository root, stopping at the first nonzero line as make does; prints the
# recipe's status. All lines share this subshell as parent, as make's lines
# share make.
run_recipe() {
	local rc=0
	(
		cd "$top" || exit 2
		export CARGO_TARGET_DIR="$tmp/target" CARGO_NET_OFFLINE=true
		while IFS= read -r line <&3; do
			sh -c "$line" </dev/null || exit $?
		done 3<"$1"
	) >"$2" 2>&1 || rc=$?
	echo "$rc"
}
failed() { grep -qE "^test (tests::)?$1 \.\.\. FAILED\$" "$2"; }

rc=$(run_recipe "$tmp/recipe" "$tmp/recipe.out")
if failed red_unit_cell_19133 "$tmp/recipe.out" && failed red_tests_target_19133 "$tmp/recipe.out"; then
	ok "both: leg 1 reports the red unit cell AND the red tests/ target"
else
	bad "both: leg 1 missed a failure (unit=$(failed red_unit_cell_19133 "$tmp/recipe.out" && echo yes || echo no) tests=$(failed red_tests_target_19133 "$tmp/recipe.out" && echo yes || echo no))"
fi
if [[ "$rc" -ne 0 ]] && grep -q '^test-rust: FAILED legs:' "$tmp/recipe.out" &&
	grep -q '^  Leg 1: ' "$tmp/recipe.out" && grep -q '^  Leg 2: debug-leg census' "$tmp/recipe.out"; then
	ok "every leg: the recipe ran to its end, named leg 1 AND leg 2 as failed, and exited $rc"
else
	bad "every leg: rc=$rc; tail: $(tail -n 8 "$tmp/recipe.out" | tr '\n' '|')"
fi

# Mutation: leg 1 without --no-fail-fast must hide the tests/ failure.
if [[ "$leg1" != *" --no-fail-fast"* ]]; then
	bad "mutation no-fail-fast: leg 1 carries no --no-fail-fast to remove"
else
	printf '%s\n' "${leg1// --no-fail-fast/}" >"$tmp/leg1-only"
	run_recipe "$tmp/leg1-only" "$tmp/m1.out" >/dev/null
	if failed red_unit_cell_19133 "$tmp/m1.out" && ! failed red_tests_target_19133 "$tmp/m1.out"; then
		ok "mutation no-fail-fast: without it the red unit cell hides the red tests/ target"
	else
		bad "mutation no-fail-fast: the fixture did not reproduce the masking; the 'both' cell proves nothing"
	fi
fi

# Mutation: leg 1 without its failure record must stop the recipe at leg 1.
unrecorded=${leg1%%|| echo \"Leg 1:*}
if [[ "$unrecorded" == "$leg1" ]]; then
	bad "mutation unrecorded: leg 1 carries no failure record to remove"
else
	while IFS= read -r line; do
		if [[ "$line" == "$leg1" ]]; then printf '%s\n' "$unrecorded"; else printf '%s\n' "$line"; fi
	done <"$tmp/recipe" >"$tmp/recipe-unrecorded"
	run_recipe "$tmp/recipe-unrecorded" "$tmp/m2.out" >/dev/null
	if ! grep -q '^  Leg 2: ' "$tmp/m2.out" && ! grep -q '^test-rust: FAILED legs:' "$tmp/m2.out"; then
		ok "mutation unrecorded: a leg 1 that does not record its failure stops the recipe; leg 2 is never reported"
	else
		bad "mutation unrecorded: the recipe still reached leg 2; the 'every leg' cell proves nothing"
	fi
fi

summary
