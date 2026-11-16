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
# Cells:
#   - control: with --separate-stderr the mock really reorders (the stderr line
#     arrives before the stdout written ahead of it). Without this the order
#     cell below could pass against a transport that never reorders.
#   - order: by default the output is byte-for-byte the write order, for the
#     runner-user leg and the --root leg.
#   - --separate-stderr: stdout carries only stdout, stderr only stderr.
#   - exit status: the command's status is the script's, in both modes.
#   - mutation: the script with its `exec 2>&1` removed fails the order cell.
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
written=$'test cell_one ... FAILED\nerror: test failed, to rerun pass `--bin x`\ntail'

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

# control: the mock reorders when the streams are kept apart.
run "$script" "$tmp/c.arrival" - --separate-stderr >/dev/null
if [[ "$(cat "$tmp/c.arrival")" != "$written" ]] && grep -q '^error: test failed' "$tmp/c.arrival" &&
	[[ $(grep -n '^error: test failed' "$tmp/c.arrival" | cut -d: -f1) -lt $(grep -n '^test cell_one' "$tmp/c.arrival" | cut -d: -f1) ]]; then
	ok "control: with separate streams the transport delivers stderr ahead of the stdout written before it"
else
	bad "control: the mock transport did not reorder; the order cells below prove nothing"
fi

# --separate-stderr: each stream carries only its own lines.
rc=$(run "$script" "$tmp/c.out" "$tmp/c.err" --separate-stderr)
# shellcheck disable=SC2016 # literal backticks: cargo's own text
if [[ "$(cat "$tmp/c.out")" == $'test cell_one ... FAILED\ntail' && "$(cat "$tmp/c.err")" == 'error: test failed, to rerun pass `--bin x`' ]]; then
	ok "--separate-stderr: stdout carries only stdout, stderr only stderr"
else
	bad "--separate-stderr: streams mixed (stdout=$(tr '\n' '|' <"$tmp/c.out") stderr=$(tr '\n' '|' <"$tmp/c.err"))"
fi
if [[ "$rc" == 3 ]]; then
	ok "--separate-stderr: the command's exit status (3) is the script's"
else
	bad "--separate-stderr: exit status $rc, want 3"
fi

# order: one stream, in write order, for both legs.
for leg in user root; do
	opts=()
	[[ "$leg" == root ]] && opts=(--root)
	rc=$(run "$script" "$tmp/$leg.out" "$tmp/$leg.err" "${opts[@]}")
	if [[ "$(cat "$tmp/$leg.out")" == "$written" && ! -s "$tmp/$leg.err" ]]; then
		ok "order ($leg leg): stdout is the write order byte for byte; nothing on stderr"
	else
		bad "order ($leg leg): got stdout=$(tr '\n' '|' <"$tmp/$leg.out") stderr=$(tr '\n' '|' <"$tmp/$leg.err")"
	fi
	if [[ "$rc" == 3 ]]; then
		ok "order ($leg leg): the command's exit status (3) is the script's"
	else
		bad "order ($leg leg): exit status $rc, want 3"
	fi
done

# mutation: without the runner-side merge the order cell must fail.
mutant="$tmp/vm-test-run-mutant.sh"
sed 's/stream_prefix="exec 2>&1; "/stream_prefix=""/' "$script" >"$mutant"
if cmp -s "$script" "$mutant"; then
	bad "mutation: the merge anchor was not found; the mutant is the script itself"
else
	run "$mutant" "$tmp/m.arrival" - >/dev/null
	if [[ "$(cat "$tmp/m.arrival")" != "$written" ]]; then
		ok "mutation: without exec 2>&1 the order cell fails (arrival order differs from write order)"
	else
		bad "mutation: the merge-less mutant still kept write order; the order cell cannot see the defect"
	fi
fi

echo "vm-test-run selftest: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
