#!/bin/bash
# test/miri-census-selftest.sh -- self-test for scripts/miri-census.sh and
# scripts/miri-leg.sh (#9499 member 2).
#
# WHY A GATE ABOUT A GATE NEEDS ONE
#
#   Both scripts fail INVISIBLY. A census whose matcher is broken reports a
#   CLEAN BOARD, and a leg whose scorer is broken reports a clean run -- every
#   green run of a broken one looks exactly like a healthy one. So each defence
#   is asserted TWICE: a fixture that must score FAIL, and the unmutated tree
#   that must score OK. A mutation that does not flip the verdict is an ESCAPE
#   and fails this target.
#
#   The census cells run against a SANDBOX repo built from scratch, never
#   against the real worktree: a self-test that edits the tree it is checking
#   cannot tell its own mutation from the author's uncommitted work, and a
#   crash mid-run leaves an applied mutant behind.
#
#   The leg cells run the REAL scripts/miri-leg.sh with a stub `cargo` on PATH
#   that replays a fixture log. That exercises the actual parser rather than a
#   reimplementation of it -- the scorer and the thing under test must not be
#   two copies of the same idea.
#
# Hermetic: git, bash, coreutils. No cargo, no Miri, no network, no cluster.
set -u

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CENSUS="$REPO_ROOT/scripts/miri-census.sh"
LEG="$REPO_ROOT/scripts/miri-leg.sh"

# Fail LOUDLY and at the top if the scripts under test are not where this
# expects them. Without this guard a wrong REPO_ROOT does not look like a path
# bug: every cell copies nothing, every sandbox census fails to start, and the
# run reports "0 passed, 18 failed" as if eighteen defences had regressed. That
# is how this file was first written -- it lived at test/ and moved to
# test/incus/, and `dirname/..` silently became the wrong directory.
for f in "$CENSUS" "$LEG"; do
	[ -f "$f" ] || {
		echo "miri census self-test: cannot find $f" >&2
		echo "  REPO_ROOT resolved to $REPO_ROOT -- if this file moved, fix the" >&2
		echo "  \`dirname\` hops above. This is a harness path bug, not 18 failures." >&2
		exit 1
	}
done
PASS=0
FAILN=0

ok()   { PASS=$((PASS + 1));  printf '  ok   %s\n' "$*"; }
bad()  { FAILN=$((FAILN + 1)); printf '  FAIL %s\n' "$*" >&2; }

# --- sandbox -----------------------------------------------------------------
# A minimal repo the census can scan: the two registry files, the control file,
# and one declared file. Built fresh per cell so cells cannot contaminate each
# other.
mk_sandbox() {
	local d
	d=$(mktemp -d "${TMPDIR:-/tmp}/miri-census-cell.XXXXXXXX")
	mkdir -p "$d/scripts" "$d/userspace-dp/src/afxdp/types" "$d/userspace-dp/src/afxdp/frame"
	cp "$CENSUS" "$d/scripts/miri-census.sh"

	printf '// FlowFairState::new_boxed ... verified by cargo +nightly miri.\n' \
		>"$d/userspace-dp/src/afxdp/types/cos.rs"
	printf '// `not(miri)` because proptest case loops are intractable.\n#[cfg(all(test, not(miri)))]\nmod prop_tests;\n' \
		>"$d/userspace-dp/src/afxdp/frame/mod.rs"

	printf '%s\n' \
		'# registry' \
		'afxdp::types::cos::  12  measured clean: 12 passed, 76 s, no unsupported operations.' \
		>"$d/userspace-dp/MIRI.registry"
	printf '%s\n' \
		'# unregistered' \
		'userspace-dp/src/afxdp/frame/mod.rs  afxdp::frame:: costs 1021 s under Miri and stops on an isolation error.' \
		>"$d/userspace-dp/MIRI.unregistered"

	git -C "$d" init -q 2>/dev/null
	git -C "$d" add -A >/dev/null 2>&1
	printf '%s' "$d"
}

run_census() { sh "$1/scripts/miri-census.sh" >"$1/out" 2>&1; printf '%s' "$?"; }

# A cell: apply a mutation to a fresh sandbox, demand the census FAILS, and
# demand the failure names the right thing. A mutation that still passes is an
# ESCAPE -- the defence it targets does not exist.
cell() {
	local name="$1" want_msg="$2"; shift 2
	local d; d=$(mk_sandbox)
	( cd "$d" && "$@" ) >/dev/null 2>&1
	git -C "$d" add -A >/dev/null 2>&1
	local rc; rc=$(run_census "$d")
	if [ "$rc" = "0" ]; then
		bad "ESCAPE: $name -- census still passed after the mutation"
		rm -rf "$d"; return
	fi
	if ! grep -qi -- "$want_msg" "$d/out"; then
		bad "$name -- census failed, but not for the stated reason (wanted /$want_msg/)"
		sed -n '1,12p' "$d/out" | sed 's/^/        /' >&2
		rm -rf "$d"; return
	fi
	ok "$name"
	rm -rf "$d"
}

echo "miri census self-test"
echo ""
echo "positive control -- the unmutated sandbox must PASS:"
d=$(mk_sandbox); rc=$(run_census "$d")
if [ "$rc" = "0" ]; then
	ok "unmutated sandbox: census OK"
else
	bad "unmutated sandbox FAILED -- every cell below is then vacuous"
	sed -n '1,15p' "$d/out" | sed 's/^/        /' >&2
fi
rm -rf "$d"

echo ""
echo "mutation cells -- each must flip the census to FAIL:"

# THE cell #9499 asks for: the registered subset silently shrinking.
cell "registry line DELETED (the subset shrinks)" "uncovered and undeclared" \
	sed -i '/^afxdp::types::cos::/d' userspace-dp/MIRI.registry

cell "registry EMPTIED" "registers NO modules" \
	sh -c ': >userspace-dp/MIRI.registry'

cell "registered module resolves to nothing" "resolves to no file" \
	sed -i 's|^afxdp::types::cos::|afxdp::types::gone::|' userspace-dp/MIRI.registry

cell "registry floor of 0" "not positive" \
	sed -i 's|^\(afxdp::types::cos::\)  12|\1  0|' userspace-dp/MIRI.registry

cell "registry entry with no reason" "has no reason" \
	sed -i 's|^\(afxdp::types::cos::  12\).*|\1|' userspace-dp/MIRI.registry

cell "declared path that IS covered (re-hiding a module)" "IS covered by a registered module" \
	sh -c 'echo "userspace-dp/src/afxdp/types/cos.rs  re-hidden" >>userspace-dp/MIRI.unregistered'

cell "declared path not in the tree" "does not exist in the tree" \
	sh -c 'echo "userspace-dp/src/afxdp/frame/ghost.rs  stale declaration" >>userspace-dp/MIRI.unregistered'

cell "NEW file mentioning Miri, undeclared" "uncovered and undeclared" \
	sh -c 'printf "// this one runs under Miri too.\n" >userspace-dp/src/afxdp/frame/newthing.rs'

cell "declaration DROPPED for an existing claim file" "uncovered and undeclared" \
	sed -i '/frame\/mod.rs/d' userspace-dp/MIRI.unregistered

# The control's own cell: a broken resolver plus a regenerated declaration list
# is a green census over an inverted world, so the control must trip by name.
cell "POSITIVE CONTROL declared instead of covered" "POSITIVE CONTROL" \
	sh -c 'sed -i "/^afxdp::types::cos::/d" userspace-dp/MIRI.registry &&
	       echo "userspace-dp/src/afxdp/frame/mod.rs  x" >userspace-dp/MIRI.unregistered &&
	       echo "userspace-dp/src/afxdp/types/cos.rs  hidden" >>userspace-dp/MIRI.unregistered'

# The matcher itself. If discovery breaks, the census must fail on the empty
# sweep rather than report a clean board.
cell "claim MATCHER broken (discovers nothing)" "ZERO files" \
	sed -i "s|grep -lil 'miri'|grep -lil 'zzz-no-such-token'|" scripts/miri-census.sh

# `git ls-files` cannot see an untracked file, so this cell deliberately does
# NOT stage its mutation -- which is exactly the state a new module is in on
# the machine of whoever just wrote it.
untracked_cell() {
	local name="$1" want_msg="$2"; shift 2
	local d; d=$(mk_sandbox)
	( cd "$d" && "$@" ) >/dev/null 2>&1
	local rc; rc=$(run_census "$d")
	if [ "$rc" = "0" ]; then
		bad "ESCAPE: $name -- census still passed (git ls-files cannot see it)"
	elif ! grep -qi -- "$want_msg" "$d/out"; then
		bad "$name -- census failed, but not for the stated reason (wanted /$want_msg/)"
		sed -n '1,12p' "$d/out" | sed 's/^/        /' >&2
	else
		ok "$name"
	fi
	rm -rf "$d"
}

untracked_cell "UNTRACKED file mentioning Miri (never staged)" "UNTRACKED file mentions Miri" \
	sh -c 'printf "// this also runs under Miri.\n" >userspace-dp/src/afxdp/frame/untracked.rs'

echo ""
echo "miri leg scoring cells -- the real scripts/miri-leg.sh over a stub cargo:"

# Each fixture is a log the stub cargo replays. The leg must judge the LOG, not
# the exit status: every fixture below exits 0, which is what makes them the
# interesting cases.
leg_cell() {
	local name="$1" want_rc="$2" want_msg="$3" log="$4"
	local d; d=$(mktemp -d "${TMPDIR:-/tmp}/miri-leg-cell.XXXXXXXX")
	mkdir -p "$d/scripts" "$d/userspace-dp" "$d/bin"
	cp "$LEG" "$d/scripts/miri-leg.sh"
	printf '%s\n' '# r' 'afxdp::types::cos::  12  reason.' >"$d/userspace-dp/MIRI.registry"
	: >"$d/userspace-dp/Cargo.toml"
	cat >"$d/bin/cargo" <<STUB
#!/bin/sh
case "\$*" in *"miri --version"*) echo "miri 0.1.0"; exit 0;; esac
cat "$d/fixture.log"
exit 0
STUB
	chmod +x "$d/bin/cargo"
	printf '%s\n' "$log" >"$d/fixture.log"
	( cd "$d" && PATH="$d/bin:$PATH" MIRI_LOG_DIR="$d/logs" bash scripts/miri-leg.sh ) >"$d/out" 2>&1
	local rc=$?
	if [ "$rc" != "$want_rc" ]; then
		bad "$name -- leg exited $rc, wanted $want_rc"
		sed -n '1,10p' "$d/out" | sed 's/^/        /' >&2
	elif [ -n "$want_msg" ] && ! grep -qi -- "$want_msg" "$d/out"; then
		bad "$name -- right verdict, wrong reason (wanted /$want_msg/)"
		sed -n '1,10p' "$d/out" | sed 's/^/        /' >&2
	else
		ok "$name"
	fi
	rm -rf "$d"
}

leg_cell "healthy run passes" 0 "ok: afxdp::types::cos::" \
	"test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 5698 filtered out; finished in 76.16s"
leg_cell "NO result line is a FAIL, not a skip" 1 "NO .test result:. line" \
	"   Compiling xpf-userspace-dp v0.1.0"
leg_cell "0 passed is a FAIL" 1 "0 passed" \
	"test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 5710 filtered out; finished in 0.01s"
leg_cell "below the registered floor is a FAIL" 1 "below the registered floor" \
	"test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 5707 filtered out; finished in 9.1s"
leg_cell "a real failure is a FAIL" 1 "failed" \
	"test result: FAILED. 10 passed; 2 failed; 0 ignored; 0 measured; 5698 filtered out"
leg_cell "unsupported operation is VOID, not clean" 1 "UNSUPPORTED OPERATION" \
	"error: unsupported operation: open not available when isolation is enabled"

# MULTI-BINARY logs. `--bins` runs each binary target in turn, so a real log
# carries one result line per binary -- and reading only the FIRST is wrong in
# both directions. Both faces were live in the shipped leg until the first real
# run exposed them; the single-binary fixtures above could not see either.
leg_cell "a LATER binary's passes count (first binary matched nothing)" 0 "ok: afxdp::types::cos::" \
	"     Running unittests src/bin/fairness-eval.rs
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 63 filtered out; finished in 0.37s
     Running unittests src/main.rs
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 5698 filtered out; finished in 46.28s"
leg_cell "a LATER binary's FAILURES are not hidden by an earlier clean line" 1 "failed" \
	"     Running unittests src/bin/fairness-eval.rs
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 63 filtered out; finished in 0.37s
     Running unittests src/main.rs
test result: FAILED. 10 passed; 2 failed; 0 ignored; 0 measured; 5698 filtered out"

echo ""
echo "miri census self-test: $PASS passed, $FAILN failed"
[ "$FAILN" -eq 0 ] || exit 1
