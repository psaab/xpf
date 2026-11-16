#!/usr/bin/env bash
# scripts/vm-test-run-selftest.sh -- #19139: scripts/vm-test-run.sh hands a
# command's stdout and stderr back in WRITE order.
#
# `incus exec` carries the two as separate streams and the workstation merges
# them in arrival order, so cargo's stderr (`Running <target>`, `error: test
# failed ...`) landed in the middle of libtest's stdout result lines. Hermetic:
# a mock `incus` on PATH stands in for the runner. Its transport is the
# worst case of that defect -- the command's stdout is delivered only after the
# command exits, its stderr immediately -- so whatever order survives was
# fixed on the runner side, not by lucky timing.
#
# Every comparison is `cmp` against a fixture file holding the exact expected
# bytes, final newline included. For BOTH legs (runner user, --root):
#   - control: with --separate-stderr the mock really reorders (the stderr line
#     arrives before the stdout written ahead of it). Without this the order
#     cell could pass against a transport that never reorders.
#   - order: by default stdout is the write order, byte for byte, and nothing
#     arrives on stderr.
#   - --separate-stderr: stdout holds exactly the stdout bytes, stderr exactly
#     the stderr bytes.
#   - exit status: the command's status (3) is the script's, in both modes.
# Mutations, each also required to keep status 3 (so the assertion, not a
# crash, is what fails):
#   - `exec 2>&1` removed: the order cell fails on both legs;
#   - the root leg merging unconditionally (ignoring --separate-stderr): the
#     root separation cell fails;
#   - the user leg merging unconditionally: the user separation cell fails.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script="$here/vm-test-run.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/vm-test-run-selftest.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS: $*"; }
bad() { fail=$((fail + 1)); echo "FAIL: $*"; }

mkdir -p "$tmp/bin" "$tmp/work/lane/src" "$tmp/work/lane/tmp" "$tmp/work/lane/target"
# vm-test-run.sh insists on running inside a git worktree; a runner's synced
# tree has no .git, so give it a scratch one.
git init -q "$tmp/repo"
cat >"$tmp/bin/incus" <<'MOCK'
#!/usr/bin/env bash
# Mock incus (#19139 selftest). `info` reports RUNNING; the runner probes
# succeed; the lane command runs locally with /work/ rewritten into the
# sandbox. Transport: stdout is held until the command exits, stderr passes
# straight through.
case "${1:-}" in
info) echo "Status: RUNNING"; exit 0 ;;
exec) shift 2; [[ "${1:-}" == -- ]] && shift ;;
*) exit 90 ;;
esac
case "${1:-}" in
test | find) exit 0 ;;
systemd-detect-virt) echo kvm; exit 0 ;;
su) [[ "${2:-}" == - && "${3:-}" == runner && "${4:-}" == -c ]] || exit 91; body=$5 ;;
bash) [[ "${2:-}" == -lc ]] || exit 92; body=$3 ;;
*) exit 93 ;;
esac
body=${body//\/work\//$MOCK_ROOT/work/}
rc=0
held="$MOCK_ROOT/held.$$"
bash -c "$body" >"$held" || rc=$?
cat "$held"
rm -f "$held"
exit "$rc"
MOCK
chmod +x "$tmp/bin/incus"

# The lane command, shaped like cargo test: libtest writes a result line in
# two parts on stdout, then cargo reports the failure on stderr after the test
# binary exits.
# shellcheck disable=SC2016 # the backticks are cargo's literal text, expanded nowhere
lane_cmd='printf "test cell_one ... "; printf "FAILED\n"; printf "error: test failed, to rerun pass \`--bin x\`\n" >&2; printf "tail\n"; exit 3'
# The exact expected bytes, final newline included.
# shellcheck disable=SC2016 # literal backticks: cargo's own text
printf 'test cell_one ... FAILED\nerror: test failed, to rerun pass `--bin x`\ntail\n' >"$tmp/want.merged"
printf 'test cell_one ... FAILED\ntail\n' >"$tmp/want.stdout"
# shellcheck disable=SC2016 # literal backticks: cargo's own text
printf 'error: test failed, to rerun pass `--bin x`\n' >"$tmp/want.stderr"
: >"$tmp/want.empty"

# run <script> <out> <err|-> [opts...]: run the script under the mock from the
# scratch worktree and print its status. With "-" for <err>, stdout and stderr
# are merged on THIS side (`>out 2>&1`), as callers do: the file then records
# arrival order.
run() {
	local under=$1 out=$2 err=$3 rc=0
	shift 3
	if [[ "$err" == - ]]; then
		(cd "$tmp/repo" && PATH="$tmp/bin:$PATH" MOCK_ROOT="$tmp" \
			bash "$under" --runner mock:runner --name lane --no-sync "$@" -- "$lane_cmd") \
			>"$out" 2>&1 || rc=$?
	else
		(cd "$tmp/repo" && PATH="$tmp/bin:$PATH" MOCK_ROOT="$tmp" \
			bash "$under" --runner mock:runner --name lane --no-sync "$@" -- "$lane_cmd") \
			>"$out" 2>"$err" || rc=$?
	fi
	echo "$rc"
}

leg_opts() {
	if [[ "$1" == root ]]; then echo --root; fi
}

# order_holds <script> <leg> <tag>: default mode; stdout is the write order and
# stderr is empty. Sets order_rc to the script's status.
order_holds() {
	local opts
	opts=$(leg_opts "$2")
	# shellcheck disable=SC2086 # opts is empty or one word
	order_rc=$(run "$1" "$tmp/$3.out" "$tmp/$3.err" $opts)
	cmp -s "$tmp/$3.out" "$tmp/want.merged" && cmp -s "$tmp/$3.err" "$tmp/want.empty"
}

# separation_holds <script> <leg> <tag>: --separate-stderr; each stream holds
# exactly its own bytes. Sets sep_rc to the script's status.
separation_holds() {
	local opts
	opts=$(leg_opts "$2")
	# shellcheck disable=SC2086 # opts is empty or one word
	sep_rc=$(run "$1" "$tmp/$3.out" "$tmp/$3.err" $opts --separate-stderr)
	cmp -s "$tmp/$3.out" "$tmp/want.stdout" && cmp -s "$tmp/$3.err" "$tmp/want.stderr"
}

show() { od -c "$1" | head -4 | tr -s ' ' | tr '\n' '|'; }

for leg in user root; do
	opts=$(leg_opts "$leg")
	# control: the mock reorders when the streams are kept apart.
	# shellcheck disable=SC2086 # opts is empty or one word
	run "$script" "$tmp/c-$leg.arrival" - $opts --separate-stderr >/dev/null
	if ! cmp -s "$tmp/c-$leg.arrival" "$tmp/want.merged" &&
		[[ "$(head -n 1 "$tmp/c-$leg.arrival")" == "error: test failed, to rerun pass \`--bin x\`" ]]; then
		ok "control ($leg leg): with separate streams the transport delivers stderr ahead of the stdout written before it"
	else
		bad "control ($leg leg): the mock transport did not reorder; the order cells prove nothing ($(show "$tmp/c-$leg.arrival"))"
	fi

	if order_holds "$script" "$leg" "o-$leg"; then
		ok "order ($leg leg): stdout is the write order byte for byte (cmp, final newline included); nothing on stderr"
	else
		bad "order ($leg leg): stdout=$(show "$tmp/o-$leg.out") stderr=$(show "$tmp/o-$leg.err")"
	fi
	if [[ "$order_rc" == 3 ]]; then
		ok "order ($leg leg): the command's exit status (3) is the script's"
	else
		bad "order ($leg leg): exit status $order_rc, want 3"
	fi

	if separation_holds "$script" "$leg" "s-$leg"; then
		ok "--separate-stderr ($leg leg): stdout and stderr each hold exactly their own bytes (cmp)"
	else
		bad "--separate-stderr ($leg leg): stdout=$(show "$tmp/s-$leg.out") stderr=$(show "$tmp/s-$leg.err")"
	fi
	if [[ "$sep_rc" == 3 ]]; then
		ok "--separate-stderr ($leg leg): the command's exit status (3) is the script's"
	else
		bad "--separate-stderr ($leg leg): exit status $sep_rc, want 3"
	fi
done

# mutant <name> <sed expression>: a copy of the script with one replacement;
# refuses (FAIL) when the anchor did not match.
mutant() {
	sed "$2" "$script" >"$tmp/$1.sh"
	if cmp -s "$script" "$tmp/$1.sh"; then
		bad "mutation $1: the anchor was not found; the mutant is the script itself"
		return 1
	fi
}

# The runner-side merge removed: the order cell must fail on both legs.
if mutant no-merge 's/stream_prefix="exec 2>&1; "/stream_prefix=""/'; then
	for leg in user root; do
		if ! order_holds "$tmp/no-merge.sh" "$leg" "m1-$leg" && [[ "$order_rc" == 3 ]]; then
			ok "mutation no-merge ($leg leg): the order cell fails, with the status still 3"
		else
			bad "mutation no-merge ($leg leg): the order cell still held (or status $order_rc): it cannot see the defect"
		fi
	done
fi

# The root leg merging unconditionally: --root --separate-stderr must fail.
# shellcheck disable=SC2016 # a sed program: the $ is literal
if mutant root-always-merges 's/bash -lc "${stream_prefix}export HOME=/bash -lc "exec 2>\&1; export HOME=/'; then
	if ! separation_holds "$tmp/root-always-merges.sh" root m2 && [[ "$sep_rc" == 3 ]]; then
		ok "mutation root-always-merges: the root separation cell fails, with the status still 3"
	else
		bad "mutation root-always-merges: the root separation cell still held (or status $sep_rc)"
	fi
fi

# The user leg merging unconditionally: the user separation cell must fail.
# shellcheck disable=SC2016 # a sed program: the $ is literal
if mutant user-always-merges 's/su - runner -c "${stream_prefix}${env_prefix}/su - runner -c "exec 2>\&1; ${env_prefix}/'; then
	if ! separation_holds "$tmp/user-always-merges.sh" user m3 && [[ "$sep_rc" == 3 ]]; then
		ok "mutation user-always-merges: the user separation cell fails, with the status still 3"
	else
		bad "mutation user-always-merges: the user separation cell still held (or status $sep_rc)"
	fi
fi

echo "vm-test-run selftest: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
