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
# Both parts use the recipe exactly as make runs it: `make -n test-rust`
# (its two prerequisites excluded), continuation lines joined, run line by
# line with each line in its own `sh -c`, stopping at the first line that
# exits nonzero. Both manifest spellings (`--manifest-path`, and the census's
# `--manifest`) are swapped to a fixture crate, and a cell checks that no line
# still names the real crate. Every run keeps its state (TMPDIR, where the
# failed-legs record lives) in a private directory.
#
# Part A, real cargo (leg 1 only), on a fixture crate with a red unit cell and
# a red tests/ target:
#   - both: leg 1 reports both failures, and records itself as failed;
#   - mutation: leg 1 without --no-fail-fast hides the tests/ failure.
# Part B, control flow, the whole recipe with CARGO pointed at a stub cargo,
# the census and the linked-libs stamp replaced by stubs. Every invocation is
# witnessed, and any one leg can be told to fail:
#   - all green: every leg runs, in order, and the recipe passes;
#   - each leg failing alone (leg 0, leg 1, the leg-2 census, the leg-2 debug
#     argv, leg 3): every leg still runs, the summary names exactly that leg,
#     the stub's own diagnostic is there, and the recipe fails;
#   - all failing: all five are named;
#   - mutations: each leg line removed (the all-green witness must notice),
#     each leg's failure record removed (its isolated failure must stop the
#     recipe early and go unnamed), and the summary exiting 0.
# Part B needs only make and sh. Part A needs cargo and the pinned toolchain;
# without them it is reported as SKIP and the script exits 77 after Part B.
set -euo pipefail

top=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/test-rust-leg1-selftest.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS: $*"; }
bad() { fail=$((fail + 1)); echo "FAIL: $*"; }

# The fixture crate: a bin whose unit cell is red, then a red tests/ target.
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

# recipe_for <out> [make VAR=value ...]: the test-rust recipe as make would run
# it, one line per entry, both manifest spellings swapped to the fixture.
recipe_for() {
	local out=$1
	shift
	make -s -n -o lint-rust-baseline -o check-userspace-dt-needed -C "$top" test-rust "$@" 2>/dev/null |
		awk '/\\$/ { sub(/\\$/, ""); printf "%s", $0; next } { print }' |
		sed -e "s|--manifest-path userspace-dp/Cargo.toml|--manifest-path $fx/Cargo.toml|g" \
			-e "s|--manifest userspace-dp/Cargo.toml|--manifest $fx/Cargo.toml|g" >"$out"
}

# run_recipe <recipe> <out> <state dir> [VAR=value ...]: each line in its own
# `sh -c`, from the repository root, stopping at the first nonzero line as
# make does. All lines share this subshell as parent, as make's lines share
# make. Returns the recipe's status.
run_recipe() {
	local recipe=$1 out=$2 state=$3
	shift 3
	mkdir -p "$state"
	(
		cd "$top" || exit 2
		export TMPDIR="$state" CARGO_TARGET_DIR="$tmp/target" CARGO_NET_OFFLINE=true
		for kv in "$@"; do export "${kv?}"; done
		while IFS= read -r line <&3; do
			sh -c "$line" </dev/null || exit $?
		done 3<"$recipe"
	) >"$out" 2>&1
}

# ---------------------------------------------------------------- Part B
stub="$tmp/stub"
mkdir -p "$stub"
cat >"$stub/cargo" <<'STUB'
#!/usr/bin/env bash
# Stub cargo (#19133 selftest): witnesses which leg called it, and fails the
# legs named in STUB_FAIL.
args=" $* "
case "$args" in *" --version "*) echo "cargo 0.0.0 (stub)"; exit 0 ;; esac
if [[ "$args" == *" test "*" --features debug-log "*" --list "* ]]; then leg=leg3-list
elif [[ "$args" == *" test "*" --features debug-log "*" --exact "* ]]; then leg=leg3
elif [[ "$args" == *" check "*" --benches "* ]]; then leg=leg0
elif [[ "$args" == *" test "*" --release "* ]]; then leg=leg1
elif [[ "$args" == *" test "*" --exact "* ]]; then leg=leg2-argv
else
	echo "unclassified" >>"$STUB_WITNESS"
	echo "cargo-stub: unclassified invocation: $*" >&2
	exit 97
fi
echo "$leg" >>"$STUB_WITNESS"
if [[ "$leg" == leg3-list ]]; then
	for cell in $STUB_LIST_CELLS; do echo "$cell: test"; done
fi
if [[ " ${STUB_FAIL:-} " == *" $leg "* ]]; then
	echo "cargo-stub: $leg failing as asked (#19133 selftest)" >&2
	exit 1
fi
exit 0
STUB
cat >"$stub/census" <<'STUB'
#!/usr/bin/env bash
# Stub debug-leg census (#19133 selftest).
echo census >>"$STUB_WITNESS"
if [[ " ${STUB_FAIL:-} " == *" census "* ]]; then
	echo "census-stub: census failing as asked (#19133 selftest)" >&2
	exit 1
fi
exit 0
STUB
chmod +x "$stub/cargo" "$stub/census"

recipe_for "$tmp/recipe-real" CARGO="$stub/cargo"
if grep -q 'userspace-dp/Cargo.toml' "$tmp/recipe-real"; then
	bad "manifest: a recipe line still names userspace-dp/Cargo.toml after both spellings were swapped: $(grep -c 'userspace-dp/Cargo.toml' "$tmp/recipe-real") line(s)"
else
	ok "manifest: no recipe line names the real crate once --manifest-path and --manifest are swapped"
fi
census_re='python3 scripts/debug-leg-census\.py'
stamp_re='sh userspace-dp/build_support/linked-libs-stamp\.sh'
n_census=$(grep -cE "$census_re" "$tmp/recipe-real" || true)
n_stamp=$(grep -cE "$stamp_re" "$tmp/recipe-real" || true)
sed -E -e "s|$census_re|$stub/census|g" -e "s|$stamp_re|echo stub-stamp|g" "$tmp/recipe-real" >"$tmp/recipe"
cells=$(sed -n 's/.*for cell in \([^;]*\); do.*/\1/p' "$tmp/recipe")
if [[ "$n_census" -ne 1 || "$n_stamp" -lt 5 || -z "$cells" ]] ||
	grep -qE "$census_re|$stamp_re" "$tmp/recipe"; then
	bad "stubs: expected 1 census call (found $n_census), a stamp per leg command (found $n_stamp) and the leg-3 cell list; Part B would not be hermetic"
	echo "test-rust selftest: ${pass} passed, ${fail} failed"
	exit 1
fi

all_legs="leg0 leg1 census leg2-argv leg3-list leg3"
declare -A label=(
	[leg0]="Leg 0: cargo check --benches"
	[leg1]="Leg 1: release suite (--bins --tests)"
	[census]="Leg 2: debug-leg census"
	[leg2-argv]="Leg 2: debug argv"
	[leg3]="Leg 3: debug-log cells"
)
failable="leg0 leg1 census leg2-argv leg3"

n=0
# stub_run <recipe> <name> <STUB_FAIL>: runs the recipe under the stubs into
# $tmp/<name>.out / .witness and sets rc.
stub_run() {
	n=$((n + 1))
	: >"$tmp/$2.witness"
	rc=0
	run_recipe "$1" "$tmp/$2.out" "$tmp/state.$n" STUB_WITNESS="$tmp/$2.witness" \
		STUB_FAIL="$3" STUB_LIST_CELLS="$cells" || rc=$?
}
witness() { tr '\n' ' ' <"$tmp/$1.witness" | sed 's/ $//'; }
named() { sed -n 's/^  \(Leg [0-9]: .*\)$/\1/p' "$tmp/$1.out"; }

# all_green_ok <recipe> <name>: true when every leg ran, in order, and the
# recipe passed.
all_green_ok() {
	stub_run "$1" "$2" ""
	[[ "$rc" -eq 0 && "$(witness "$2")" == "$all_legs" ]] &&
		grep -qx 'test-rust: every leg passed' "$tmp/$2.out" && [[ -z "$(named "$2")" ]]
}
# alone_ok <recipe> <name> <leg>: true when, with only <leg> failing, every
# leg still ran, the summary names exactly that leg, the stub's diagnostic is
# there, and the recipe failed.
alone_ok() {
	stub_run "$1" "$2" "$3"
	[[ "$rc" -ne 0 && "$(witness "$2")" == "$all_legs" && "$(named "$2")" == "${label[$3]}" ]] &&
		grep -q "^test-rust: FAILED legs:" "$tmp/$2.out" &&
		grep -q "$3 failing as asked (#19133 selftest)" "$tmp/$2.out"
}

if all_green_ok "$tmp/recipe" green; then
	ok "all green: every leg ran in order ($all_legs) and the recipe passed"
else
	bad "all green: rc=$rc witness=[$(witness green)] tail: $(tail -n 4 "$tmp/green.out" | tr '\n' '|')"
fi
for leg in $failable; do
	if alone_ok "$tmp/recipe" "alone-$leg" "$leg"; then
		ok "alone $leg: every leg still ran, the summary names only \"${label[$leg]}\", the recipe failed (rc=$rc)"
	else
		bad "alone $leg: rc=$rc witness=[$(witness "alone-$leg")] named=[$(named "alone-$leg" | tr '\n' '|')]"
	fi
done
stub_run "$tmp/recipe" all-red "$failable"
want=$(for leg in $failable; do echo "${label[$leg]}"; done)
if [[ "$rc" -ne 0 && "$(witness all-red)" == "$all_legs" && "$(named all-red)" == "$want" ]]; then
	ok "all failing: every leg ran and all five are named, in order"
else
	bad "all failing: rc=$rc witness=[$(witness all-red)] named=[$(named all-red | tr '\n' '|')]"
fi

# Mutations of the recipe text. Each must make its named cell fail.
# leg_line <leg>: the 1-based line number of the leg's command in the recipe.
leg_line() {
	case $1 in
	leg0) grep -n -e ' --benches' "$tmp/recipe" ;;
	leg1) grep -n -e ' --release' "$tmp/recipe" ;;
	census) grep -n -F "$stub/census" "$tmp/recipe" ;;
	leg2-argv) grep -n -e 'debug-leg.tests' "$tmp/recipe" ;;
	leg3) grep -n -e '--features debug-log' "$tmp/recipe" ;;
	esac | cut -d: -f1
}
for leg in $failable; do
	ln=$(leg_line "$leg")
	if [[ $(printf '%s\n' "$ln" | grep -c .) -ne 1 ]]; then
		bad "mutation drop $leg: expected one recipe line, found [$ln]"
		continue
	fi
	sed "${ln}d" "$tmp/recipe" >"$tmp/m-drop-$leg"
	if all_green_ok "$tmp/m-drop-$leg" "m-drop-$leg"; then
		bad "mutation drop $leg: the recipe without that leg still passes the all-green cell"
	else
		ok "mutation drop $leg: without its line the all-green witness is [$(witness "m-drop-$leg")]"
	fi
	sed -E "${ln}s/[[:space:]]*\\|\\| echo \"Leg [0-9]: [^\"]*\" >>.*$//" "$tmp/recipe" >"$tmp/m-unrec-$leg"
	if cmp -s "$tmp/recipe" "$tmp/m-unrec-$leg"; then
		bad "mutation unrecorded $leg: the leg carries no failure record to remove"
	elif alone_ok "$tmp/m-unrec-$leg" "m-unrec-$leg" "$leg"; then
		bad "mutation unrecorded $leg: its isolated failure is still named and every leg still ran"
	else
		ok "mutation unrecorded $leg: its failure stops the recipe (witness [$(witness "m-unrec-$leg")], rc=$rc)"
	fi
done
sed 's/exit 1; fi; rm -f/exit 0; fi; rm -f/' "$tmp/recipe" >"$tmp/m-exit0"
if cmp -s "$tmp/recipe" "$tmp/m-exit0"; then
	bad "mutation summary exit 0: the summary line was not found"
elif alone_ok "$tmp/m-exit0" m-exit0 leg0; then
	bad "mutation summary exit 0: a failed leg still fails the recipe"
else
	ok "mutation summary exit 0: a failed leg no longer fails the recipe (rc=$rc), and the isolated-failure cell sees it"
fi

# ---------------------------------------------------------------- Part A
cargo_bin=${CARGO:-cargo}
part_a=1
if ! command -v "$cargo_bin" >/dev/null 2>&1; then
	echo "SKIP: Part A (real cargo): cargo not installed"
	part_a=0
elif ! (cd "$top" && sh userspace-dp/build_support/dp-toolchain.sh userspace-dp/rust-toolchain.toml "$cargo_bin" >/dev/null 2>&1); then
	echo "SKIP: Part A (real cargo): the pinned userspace-dp toolchain is not installed"
	part_a=0
fi
if [[ "$part_a" -eq 1 ]]; then
	recipe_for "$tmp/recipe-cargo" CARGO="$cargo_bin"
	leg1=$(grep -F -e "test --manifest-path $fx/Cargo.toml --release" "$tmp/recipe-cargo" || true)
	if [[ $(printf '%s' "$leg1" | grep -c .) -ne 1 ]]; then
		bad "leg 1: expected exactly one release-suite line, found $(printf '%s' "$leg1" | grep -c .)"
	else
		failed() { grep -qE "^test (tests::)?$1 \.\.\. FAILED\$" "$2"; }
		printf '%s\n' "$leg1" >"$tmp/leg1"
		rc=0
		run_recipe "$tmp/leg1" "$tmp/a.out" "$tmp/state.a" || rc=$?
		record=$(cat "$tmp"/state.a/xpf-test-rust-failed-legs.* 2>/dev/null || true)
		if failed red_unit_cell_19133 "$tmp/a.out" && failed red_tests_target_19133 "$tmp/a.out" &&
			[[ "$rc" -eq 0 && "$record" == "${label[leg1]}" ]]; then
			ok "both: leg 1 reports the red unit cell AND the red tests/ target, and records \"$record\""
		else
			bad "both: unit=$(failed red_unit_cell_19133 "$tmp/a.out" && echo yes || echo no) tests=$(failed red_tests_target_19133 "$tmp/a.out" && echo yes || echo no) rc=$rc record=[$record]"
		fi
		if [[ "$leg1" != *" --no-fail-fast"* ]]; then
			bad "mutation no-fail-fast: leg 1 carries no --no-fail-fast to remove"
		else
			printf '%s\n' "${leg1// --no-fail-fast/}" >"$tmp/leg1-ff"
			run_recipe "$tmp/leg1-ff" "$tmp/m1.out" "$tmp/state.m1" || true
			if failed red_unit_cell_19133 "$tmp/m1.out" && ! failed red_tests_target_19133 "$tmp/m1.out"; then
				ok "mutation no-fail-fast: without it the red unit cell hides the red tests/ target"
			else
				bad "mutation no-fail-fast: the fixture did not reproduce the masking; the 'both' cell proves nothing"
			fi
		fi
	fi
fi

echo "test-rust selftest: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]] || exit 1
[[ "$part_a" -eq 1 ]] || exit 77
exit 0
