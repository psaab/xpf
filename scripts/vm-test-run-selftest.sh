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
#
# #19142, disclosure (the script's own `vm-test-run:` lines are set aside
# before every byte comparison above):
#   - every run ends with exactly one paused-for line, 0s when nothing paused
#     it; every root run prints vm-proof=present, and no user run prints one;
#   - a stall (the mock stops the command's whole process group for 5 s, the
#     guest clock running on) reports paused-for >= 4 and the VOID line;
#   - unseen time (the mock delays the start by 6 s, which the runner never
#     sees: it stands in for a guest clock that stops, and is equally the
#     pre-command-delay false positive docs/testing.md names) reports
#     paused-for >= 3 and the VOID line; a quiet run of the same shape reports
#     0 and no VOID line;
#   - --root with vm-proof absent (or unknown) is refused and the command does
#     not run; --allow-unproven-root runs it with vm-proof=absent disclosed;
#   - the proof predicate itself, run under `unshare -Ur` so a test file is
#     root-owned: present only for a mode-444 root file holding the current
#     boot ID; a stale boot ID, mode 644, a symlink or no file is absent, and
#     so is a file outside the user namespace (not root-owned). SKIP without
#     unshare -Ur.
#   Mutations: the heartbeat term dropped, the wall term dropped (each KILLED
#   only when the run completes normally and its report is well formed, shows
#   the signal measured, and still reads below the threshold), the refusal
#   dropped (the command runs), the boot-ID comparison dropped (a stale proof
#   reads present). None of this pauses a real VM.
#
# #19162, runner state (the mock maps the runner's /var/lib/xpf into the
# sandbox): a --root run with an empty directory runs and prints no #19162
# line; with an entry it is refused (status 2, the entry named) and the
# command never runs; --allow-xpf-state runs it with the entry listed; a
# runner-user run warns and runs; after a --root command the entries it ADDED
# are named (only those: a pre-existing entry is not), and the command's
# status survives. Mutations: the refusal dropped (the command runs), the
# after-run report dropped, and the before/after comparison inverted (names
# the old entry, not the new one).
# Fold (Codex on b7e): a FAILED probe is not a clean directory (a --root run
# is refused, --allow-xpf-state discloses it, and a failed after-probe is
# disclosed with the status kept); two overlapping --root lanes are
# serialized by the per-runner lock (B waits, then is refused over A's
# write, and A's report names only A's entry); a TERM after a write exits 143
# and still names it. Mutations: the lock dropped (A's report also claims
# B's write), the interrupt report dropped.
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
flock)
	# #19162: the per-runner root lock holder, with /run/ in the sandbox.
	[[ "${3:-}" == sh && "${4:-}" == -c ]] || exit 94
	mkdir -p "$MOCK_ROOT/run"
	exec flock "${2//\/run\//$MOCK_ROOT/run/}" sh -c "${5//\/run\//$MOCK_ROOT/run/}" ;;
cat) exec cat "${2//\/run\//$MOCK_ROOT/run/}" ;;
systemd-detect-virt) echo kvm; exit 0 ;;
su) [[ "${2:-}" == - && "${3:-}" == runner && "${4:-}" == -c ]] || exit 91; body=$5 ;;
bash)
	if [[ "${2:-}" == -c ]]; then
		# #19142: the VM-proof probe answers MOCK_VM_PROOF (default present);
		# any other one-shot command (the clock read) runs as it is.
		# #19162: MOCK_XPF_PROBE_FAIL=<n> fails the n-th state probe as an
		# exec error would (a later exec still works).
		if [[ "${3:-}" == *"xpf-state (#19162)"* && -n "${MOCK_XPF_PROBE_FAIL:-}" ]]; then
			n=$(($(cat "$MOCK_ROOT/probe-count" 2>/dev/null || echo 0) + 1))
			echo "$n" >"$MOCK_ROOT/probe-count"
			if [[ "$n" == "$MOCK_XPF_PROBE_FAIL" ]]; then
				echo "Error: mock probe failure" >&2
				exit 1
			fi
		fi
		if [[ "${3:-}" == *"vm-proof (#19142)"* ]]; then
			echo "${MOCK_VM_PROOF:-present}"
			exit 0
		fi
		# #19162: the runner's /var/lib/xpf lives in the sandbox too.
		one=${3//\/work\//$MOCK_ROOT/work/}
		exec bash -c "${one//\/var\/lib\/xpf/$MOCK_ROOT/varlibxpf}"
	fi
	[[ "${2:-}" == -lc ]] || exit 92
	body=$3 ;;
*) exit 93 ;;
esac
body=${body//\/work\//$MOCK_ROOT/work/}
body=${body//\/var\/lib\/xpf/$MOCK_ROOT/varlibxpf}
rc=0
held="$MOCK_ROOT/held.$$"
# #19142: MOCK_PRE_DELAY_S delays the start, time a frozen guest clock never
# sees; MOCK_STALL_S stops the command's whole process group for that long
# after 1 s, a pause the guest clock runs through.
if [[ -n "${MOCK_PRE_DELAY_S:-}" ]]; then
	sleep "$MOCK_PRE_DELAY_S"
fi
if [[ -n "${MOCK_STALL_S:-}" ]]; then
	setsid bash -c "$body" >"$held" &
	pid=$!
	sleep 1
	kill -STOP -- "-$pid" 2>/dev/null || true
	sleep "$MOCK_STALL_S"
	kill -CONT -- "-$pid" 2>/dev/null || true
	wait "$pid" || rc=$?
else
	# A TERM to this client ends the command at once, as closing a real
	# `incus exec` client ends the remote process (#19162).
	bash -c "$body" >"$held" &
	child=$!
	trap 'kill "$child" 2>/dev/null; wait "$child" 2>/dev/null; cat "$held"; rm -f "$held"; exit 143' TERM
	wait "$child" || rc=$?
	trap - TERM
fi
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

# strip_own <file>: <file>.cmd, the file without vm-test-run's own lines
# (#19142 adds a paused-for line to every run, a vm-proof line to root runs).
strip_own() { grep -v '^vm-test-run: ' "$1" >"$1.cmd" || true; }

# order_holds <script> <leg> <tag>: default mode; stdout is the write order and
# stderr is empty. Sets order_rc to the script's status.
order_holds() {
	local opts
	opts=$(leg_opts "$2")
	# shellcheck disable=SC2086 # opts is empty or one word
	order_rc=$(run "$1" "$tmp/$3.out" "$tmp/$3.err" $opts)
	strip_own "$tmp/$3.out"
	strip_own "$tmp/$3.err"
	cmp -s "$tmp/$3.out.cmd" "$tmp/want.merged" && cmp -s "$tmp/$3.err.cmd" "$tmp/want.empty"
}

# separation_holds <script> <leg> <tag>: --separate-stderr; each stream holds
# exactly its own bytes. Sets sep_rc to the script's status.
separation_holds() {
	local opts
	opts=$(leg_opts "$2")
	# shellcheck disable=SC2086 # opts is empty or one word
	sep_rc=$(run "$1" "$tmp/$3.out" "$tmp/$3.err" $opts --separate-stderr)
	strip_own "$tmp/$3.out"
	strip_own "$tmp/$3.err"
	cmp -s "$tmp/$3.out.cmd" "$tmp/want.stdout" && cmp -s "$tmp/$3.err.cmd" "$tmp/want.stderr"
}

show() { od -c "$1" | head -4 | tr -s ' ' | tr '\n' '|'; }

for leg in user root; do
	opts=$(leg_opts "$leg")
	# control: the mock reorders when the streams are kept apart.
	# shellcheck disable=SC2086 # opts is empty or one word
	run "$script" "$tmp/c-$leg.arrival" - $opts --separate-stderr >/dev/null
	strip_own "$tmp/c-$leg.arrival"
	if ! cmp -s "$tmp/c-$leg.arrival.cmd" "$tmp/want.merged" &&
		[[ "$(head -n 1 "$tmp/c-$leg.arrival.cmd")" == "error: test failed, to rerun pass \`--bin x\`" ]]; then
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

# #19142: the disclosure lines of the runs above.
for tag in o-user o-root s-user s-root; do
	n_pause=$(grep -c '^vm-test-run: paused-for=0s ' "$tmp/$tag.err" || true)
	n_proof=$(grep -c '^vm-test-run: vm-proof=present ' "$tmp/$tag.err" || true)
	want_proof=0
	[[ "$tag" == *-root ]] && want_proof=1
	if [[ "$n_pause" == 1 && "$n_proof" == "$want_proof" ]]; then
		ok "disclosure ($tag): one paused-for=0s line; vm-proof=present printed $want_proof time(s)"
	else
		bad "disclosure ($tag): $n_pause paused-for=0s line(s), $n_proof vm-proof=present line(s) (want 1 and $want_proof): $(tr '\n' '|' <"$tmp/$tag.err")"
	fi
done

# pause_run <script> <tag> <command> [opts...] [-- VAR=value ...]: a run of
# <command> under the mock; prints its status. The reported seconds are read
# with paused_of.
pause_run() {
	local under=$1 tag=$2 command=$3 rc=0
	shift 3
	local opts=() envs=()
	while [[ $# -gt 0 && "$1" != -- ]]; do opts+=("$1"); shift; done
	[[ "${1:-}" == -- ]] && shift
	envs=("$@")
	(cd "$tmp/repo" && env PATH="$tmp/bin:$PATH" MOCK_ROOT="$tmp" "${envs[@]}" \
		bash "$under" --runner mock:runner --name lane --no-sync "${opts[@]}" -- "$command") \
		>"$tmp/$tag.out" 2>"$tmp/$tag.err" || rc=$?
	echo "$rc" >"$tmp/$tag.rc"
	echo "$rc"
}
paused_of() { sed -n 's/^vm-test-run: paused-for=\([0-9]*\)s .*/\1/p' "$tmp/$1.err"; }
# report_of <tag>: "<paused> <workstation> <runner monotonic> <heartbeat gaps>"
# from a well-formed report line, or nothing.
report_of() {
	sed -n 's/^vm-test-run: paused-for=\([0-9]*\)s (workstation \([0-9.]*\)s, runner monotonic \([0-9.]*\)s, heartbeat gaps \([0-9.]*\)s) (#19142)$/\1 \2 \3 \4/p' "$tmp/$1.err"
}
# lost_signal <tag> <heartbeat|wall> <threshold>: the run completed normally
# (status 0, "done"), its report is well formed, the named signal was
# MEASURED (>= threshold + 1 s), and paused-for still reads below threshold.
lost_signal() {
	local rec p w g h
	rec=$(report_of "$1")
	[[ "$(cat "$tmp/$1.rc")" == 0 ]] && grep -qx 'done' "$tmp/$1.out" && [[ -n "$rec" ]] || return 1
	read -r p w g h <<<"$rec"
	[[ "$p" -lt "$3" ]] || return 1
	if [[ "$2" == heartbeat ]]; then
		awk -v h="$h" -v t="$3" 'BEGIN { exit !(h >= t + 1) }'
	else
		awk -v w="$w" -v g="$g" -v t="$3" 'BEGIN { exit !(w - g - 2 >= t + 1) }'
	fi
}
voided() { grep -q '^vm-test-run: this run was paused or stalled' "$tmp/$1.err"; }

# stall_shows <script> <tag>: a 5 s stall reads as paused-for >= 4, VOID.
stall_shows() {
	local rc
	rc=$(pause_run "$1" "$2" 'sleep 4; echo done' -- MOCK_STALL_S=5)
	[[ "$rc" == 0 && "$(paused_of "$2")" -ge 4 ]] && voided "$2" && grep -qx 'done' "$tmp/$2.out"
}
# frozen_shows <script> <tag>: 6 s the runner never saw (a start delay standing
# in for a stopped guest clock) reads as >= 3, VOID.
frozen_shows() {
	local rc
	rc=$(pause_run "$1" "$2" 'sleep 1; echo done' -- MOCK_PRE_DELAY_S=6)
	[[ "$rc" == 0 && "$(paused_of "$2")" -ge 3 ]] && voided "$2" && grep -qx 'done' "$tmp/$2.out"
}
if stall_shows "$script" stall; then
	ok "stall: a 5 s stop of the command (guest clock running) reports paused-for=$(paused_of stall)s and the VOID line"
else
	bad "stall: $(tr '\n' '|' <"$tmp/stall.err")"
fi
if frozen_shows "$script" frozen; then
	ok "unseen time: 6 s the runner never saw reports paused-for=$(paused_of frozen)s and the VOID line"
else
	bad "unseen time: $(tr '\n' '|' <"$tmp/frozen.err")"
fi
quiet_rc=$(pause_run "$script" quiet 'sleep 2; echo done')
if [[ "$quiet_rc" == 0 && "$(paused_of quiet)" == 0 ]] && ! voided quiet; then
	ok "quiet: the same shape with no pause reports paused-for=0s and no VOID line"
else
	bad "quiet: rc=$quiet_rc $(tr '\n' '|' <"$tmp/quiet.err")"
fi

# proof_refuses <script> <tag> <MOCK_VM_PROOF>: --root without the proof is
# refused before the command runs (it would create the marker).
marker="$tmp/work/lane/tmp/ran-19142"
proof_refuses() {
	local rc
	rm -f "$marker"
	rc=$(pause_run "$1" "$2" 'touch /work/lane/tmp/ran-19142' --root -- MOCK_VM_PROOF="$3")
	[[ "$rc" == 2 && ! -e "$marker" ]] && grep -q '^vm-test-run: refusing a --root run without the VM proof' "$tmp/$2.err"
}
for answer in absent garbage; do
	shown=$answer
	[[ "$answer" == garbage ]] && shown=unknown
	if proof_refuses "$script" "refuse-$answer" "$answer" && grep -q "^vm-test-run: vm-proof=$shown " "$tmp/refuse-$answer.err"; then
		ok "vm-proof=$shown: the --root run is refused (status 2) and the command never runs"
	else
		bad "vm-proof=$shown: $(tr '\n' '|' <"$tmp/refuse-$answer.err")"
	fi
done
rm -f "$marker"
allow_rc=$(pause_run "$script" allow 'touch /work/lane/tmp/ran-19142' --root --allow-unproven-root -- MOCK_VM_PROOF=absent)
if [[ "$allow_rc" == 0 && -e "$marker" ]] && grep -q '^vm-test-run: vm-proof=absent ' "$tmp/allow.err"; then
	ok "--allow-unproven-root: the command runs, with vm-proof=absent disclosed"
else
	bad "--allow-unproven-root: rc=$allow_rc $(tr '\n' '|' <"$tmp/allow.err")"
fi

# #19162: the runner's /var/lib/xpf, mapped by the mock to $tmp/varlibxpf.
state="$tmp/varlibxpf"
reset_state() { rm -rf "$state" && mkdir -p "$state"; }
# state_refuses <script> <tag>: with an entry present, --root is refused
# before the command runs, and the entry is named.
state_refuses() {
	local rc
	rm -f "$marker"
	rc=$(pause_run "$1" "$2" 'touch /work/lane/tmp/ran-19142' --root)
	[[ "$rc" == 2 && ! -e "$marker" ]] &&
		grep -q '^vm-test-run: refusing a --root run: .*/var/lib/xpf holds state .*ha-peer-epoch.lock' "$tmp/$2.err"
}
# writer_named <script> <tag>: a --root command that adds an entry (and exits
# 3) has exactly that entry named, and its status survives.
writer_named() {
	local rc
	reset_state
	rc=$(pause_run "$1" "$2" 'touch /var/lib/xpf/transit-gate-owned; exit 3' --root)
	[[ "$rc" == 3 ]] &&
		grep -qx 'vm-test-run: this --root command wrote production state to mock:runner:/var/lib/xpf: transit-gate-owned (#19162)' "$tmp/$2.err"
}
# only_new_named <script> <tag>: with a pre-existing entry (allowed), only the
# entry the command added is named.
only_new_named() {
	local rc
	reset_state
	touch "$state/fabric-auth-grace"
	rc=$(pause_run "$1" "$2" 'touch /var/lib/xpf/unkeyed-authority-grace' --root --allow-xpf-state)
	[[ "$rc" == 0 ]] &&
		grep -qx 'vm-test-run: this --root command wrote production state to mock:runner:/var/lib/xpf: unkeyed-authority-grace (#19162)' "$tmp/$2.err"
}
reset_state
rm -f "$marker"
clean_rc=$(pause_run "$script" st-clean 'touch /work/lane/tmp/ran-19142' --root)
if [[ "$clean_rc" == 0 && -e "$marker" ]] && ! grep -q '(#19162)' "$tmp/st-clean.err"; then
	ok "xpf-state empty: a --root run proceeds, with no #19162 line"
else
	bad "xpf-state empty: rc=$clean_rc $(tr '\n' '|' <"$tmp/st-clean.err")"
fi
reset_state
touch "$state/ha-peer-epoch.lock"
if state_refuses "$script" st-refuse; then
	ok "xpf-state present: the --root run is refused (status 2), the entry named, and the command never runs"
else
	bad "xpf-state present: $(tr '\n' '|' <"$tmp/st-refuse.err")"
fi
rm -f "$marker"
st_allow_rc=$(pause_run "$script" st-allow 'touch /work/lane/tmp/ran-19142' --root --allow-xpf-state)
if [[ "$st_allow_rc" == 0 && -e "$marker" ]] && grep -q '^vm-test-run: warning: .*ha-peer-epoch.lock' "$tmp/st-allow.err"; then
	ok "--allow-xpf-state: the --root command runs, with the entry listed"
else
	bad "--allow-xpf-state: rc=$st_allow_rc $(tr '\n' '|' <"$tmp/st-allow.err")"
fi
rm -f "$marker"
st_user_rc=$(pause_run "$script" st-user 'touch /work/lane/tmp/ran-19142')
if [[ "$st_user_rc" == 0 && -e "$marker" ]] && grep -q '^vm-test-run: warning: .*ha-peer-epoch.lock' "$tmp/st-user.err"; then
	ok "xpf-state present, runner-user leg: it runs, with a warning naming the entry"
else
	bad "xpf-state present, runner-user leg: rc=$st_user_rc $(tr '\n' '|' <"$tmp/st-user.err")"
fi
if writer_named "$script" st-writer; then
	ok "xpf-state writer: a --root command that adds an entry has it named, and its status (3) survives"
else
	bad "xpf-state writer: rc=$(cat "$tmp/st-writer.rc") $(tr '\n' '|' <"$tmp/st-writer.err")"
fi
if only_new_named "$script" st-new; then
	ok "xpf-state writer: only the entry the command added is named, not the one already there"
else
	bad "xpf-state only-new: rc=$(cat "$tmp/st-new.rc") $(tr '\n' '|' <"$tmp/st-new.err")"
fi
reset_state

# Fold (7): a failed probe is not a clean directory.
rm -f "$marker" "$tmp/probe-count"
pe_rc=$(pause_run "$script" st-perr 'touch /work/lane/tmp/ran-19142' --root -- MOCK_XPF_PROBE_FAIL=1)
if [[ "$pe_rc" == 2 && ! -e "$marker" ]] && grep -q '^vm-test-run: refusing a --root run: .*could not be inspected' "$tmp/st-perr.err"; then
	ok "xpf-state probe failed: the --root run is refused (status 2), not read as clean, and the command never runs"
else
	bad "xpf-state probe failed: rc=$pe_rc $(tr '\n' '|' <"$tmp/st-perr.err")"
fi
rm -f "$marker" "$tmp/probe-count"
pa_rc=$(pause_run "$script" st-pallow 'touch /work/lane/tmp/ran-19142' --root --allow-xpf-state -- MOCK_XPF_PROBE_FAIL=1)
if [[ "$pa_rc" == 0 && -e "$marker" ]] && grep -q '^vm-test-run: warning: .*could not be inspected' "$tmp/st-pallow.err"; then
	ok "xpf-state probe failed + --allow-xpf-state: the command runs, the unknown state disclosed"
else
	bad "xpf-state probe failed + allow: rc=$pa_rc $(tr '\n' '|' <"$tmp/st-pallow.err")"
fi
reset_state
rm -f "$tmp/probe-count"
pf_rc=$(pause_run "$script" st-pafter 'touch /var/lib/xpf/after-wrote; exit 3' --root -- MOCK_XPF_PROBE_FAIL=2)
if [[ "$pf_rc" == 3 ]] && grep -q '^vm-test-run: could not inspect .*/var/lib/xpf after the --root command' "$tmp/st-pafter.err" &&
	! grep -q '^vm-test-run: this --root command wrote production state' "$tmp/st-pafter.err"; then
	ok "xpf-state after-probe failed: disclosed, and the command's status (3) survives"
else
	bad "xpf-state after-probe failed: rc=$pf_rc $(tr '\n' '|' <"$tmp/st-pafter.err")"
fi
rm -f "$tmp/probe-count"

# Fold (8): two overlapping --root lanes. A sleeps, then writes; B starts
# while A holds the lock, writes too, and marks that it ran.
# two_lanes <script> <tag>: true when B waited, was refused over A's entry
# without running, and A's report names exactly A's entry.
two_lanes() {
	local a_rc b_rc
	reset_state
	rm -f "$tmp/work/lane/tmp/b-ran"
	(pause_run "$1" "$2-a" 'sleep 4; touch /var/lib/xpf/a-wrote' --root >/dev/null) &
	local a_pid=$!
	sleep 1
	b_rc=$(pause_run "$1" "$2-b" 'touch /var/lib/xpf/b-wrote; touch /work/lane/tmp/b-ran' --root)
	wait "$a_pid" || true
	a_rc=$(cat "$tmp/$2-a.rc")
	[[ "$a_rc" == 0 && "$b_rc" == 2 && ! -e "$tmp/work/lane/tmp/b-ran" ]] &&
		grep -q '^vm-test-run: waiting for another --root run on mock:runner' "$tmp/$2-b.err" &&
		grep -qx 'vm-test-run: this --root command wrote production state to mock:runner:/var/lib/xpf: a-wrote (#19162)' "$tmp/$2-a.err"
}
if two_lanes "$script" st-two; then
	ok "two overlapping --root lanes: B waits for A's lock, is refused over A's write without running, and A's report names only a-wrote"
else
	bad "two overlapping --root lanes: A rc=$(cat "$tmp/st-two-a.rc") A=[$(tr '\n' '|' <"$tmp/st-two-a.err")] B=[$(tr '\n' '|' <"$tmp/st-two-b.err")]"
fi
reset_state

# Fold (9): a TERM after the command wrote state still reports it, with 143.
# term_reports <script> <tag>
term_reports() {
	local pid rc=0
	reset_state
	# exec: $pid must be vm-test-run itself, not a subshell around it.
	(cd "$tmp/repo" && exec env PATH="$tmp/bin:$PATH" MOCK_ROOT="$tmp" \
		bash "$1" --runner mock:runner --name lane --no-sync --root -- 'touch /var/lib/xpf/sig-wrote; sleep 20') \
		>"$tmp/$2.out" 2>"$tmp/$2.err" &
	pid=$!
	for _ in $(seq 50); do [[ -e "$state/sig-wrote" ]] && break; sleep 0.1; done
	sleep 0.5
	kill -TERM "$pid"
	wait "$pid" || rc=$?
	echo "$rc" >"$tmp/$2.rc"
	[[ "$rc" == 143 ]] && grep -qx 'vm-test-run: this --root command wrote production state to mock:runner:/var/lib/xpf: sig-wrote (#19162)' "$tmp/$2.err"
}
if term_reports "$script" st-term; then
	ok "TERM after a write: exit 143, and the write is still named"
else
	bad "TERM after a write: rc=$(cat "$tmp/st-term.rc") $(tr '\n' '|' <"$tmp/st-term.err")"
fi
reset_state

# The proof predicate itself, against test files (the probe text is taken from
# the script; only its path is replaced).
probe() { sed -n '/^# vm-proof (#19142)$/,/^fi$/p' "$1" | sed "s|^p=/run/xpf-testguard-vm-boot-id\$|p=$tmp/proof/id|"; }
have_userns=1
unshare -Ur true 2>/dev/null || have_userns=0
# proof_case <probe file> <setup> : prints present/absent under unshare -Ur.
proof_case() {
	rm -rf "$tmp/proof" && mkdir -p "$tmp/proof"
	eval "$2"
	unshare -Ur sh "$1"
}
# shellcheck disable=SC2016,SC2034 # eval'd later, reached as ${!setup_var}
setup_valid='cat /proc/sys/kernel/random/boot_id >"$tmp/proof/id"; chmod 444 "$tmp/proof/id"'
# shellcheck disable=SC2016,SC2034 # eval'd later, reached as ${!setup_var}
setup_stale='echo 00000000-0000-0000-0000-000000000000 >"$tmp/proof/id"; chmod 444 "$tmp/proof/id"'
# shellcheck disable=SC2016,SC2034 # eval'd later, reached as ${!setup_var}
setup_mode='cat /proc/sys/kernel/random/boot_id >"$tmp/proof/id"; chmod 644 "$tmp/proof/id"'
# shellcheck disable=SC2016,SC2034 # eval'd later, reached as ${!setup_var}
setup_link='cat /proc/sys/kernel/random/boot_id >"$tmp/proof/real"; chmod 444 "$tmp/proof/real"; ln -s real "$tmp/proof/id"'
# shellcheck disable=SC2016,SC2034 # eval'd later, reached as ${!setup_var}
setup_none=':'
skip=0
if [[ "$have_userns" -eq 0 ]]; then
	skip=1
	echo "SKIP: the proof predicate cells: unshare -Ur is not available here"
else
	probe "$script" >"$tmp/probe.sh"
	if [[ $(grep -c "p=$tmp/proof/id" "$tmp/probe.sh") -ne 1 ]]; then
		bad "proof predicate: could not take the probe from the script"
	else
		for c in valid:present stale:absent mode:absent link:absent none:absent; do
			setup_var="setup_${c%%:*}"
			got=$(proof_case "$tmp/probe.sh" "${!setup_var}")
			if [[ "$got" == "${c#*:}" ]]; then
				ok "proof predicate (${c%%:*}): ${got}"
			else
				bad "proof predicate (${c%%:*}): got ${got}, want ${c#*:}"
			fi
		done
		if [[ "$(id -u)" -ne 0 ]]; then
			eval "$setup_valid"
			got=$(sh "$tmp/probe.sh")
			if [[ "$got" == absent ]]; then
				ok "proof predicate (not root-owned): a valid proof owned by uid $(id -u) is absent"
			else
				bad "proof predicate (not root-owned): got $got"
			fi
		fi
	fi
fi

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

# #19142 mutations.
if mutant no-heartbeat-term 's/^	p = (h > x) ? h : x$/	p = x/'; then
	stall_shows "$tmp/no-heartbeat-term.sh" m4 || true
	if lost_signal m4 heartbeat 4; then
		ok "mutation no-heartbeat-term: a normal run measured the gap but reported it below threshold ($(report_of m4))"
	else
		bad "mutation no-heartbeat-term: not a clean lost-signal run (rc $(cat "$tmp/m4.rc"), report [$(report_of m4)]): $(tr '\n' '|' <"$tmp/m4.err")"
	fi
fi
if mutant no-wall-term 's/^	p = (h > x) ? h : x$/	p = h/'; then
	frozen_shows "$tmp/no-wall-term.sh" m5 || true
	if lost_signal m5 wall 3; then
		ok "mutation no-wall-term: a normal run measured the unseen time but reported it below threshold ($(report_of m5))"
	else
		bad "mutation no-wall-term: not a clean lost-signal run (rc $(cat "$tmp/m5.rc"), report [$(report_of m5)]): $(tr '\n' '|' <"$tmp/m5.err")"
	fi
fi
# shellcheck disable=SC2016 # a sed program: the $ is literal
if mutant no-proof-refusal 's/if \[\[ "$vm_proof" != present \&\& "$allow_unproven_root" -ne 1 \]\]; then/if false; then/'; then
	rm -f "$marker"
	if ! proof_refuses "$tmp/no-proof-refusal.sh" m6 absent && [[ -e "$marker" ]]; then
		ok "mutation no-proof-refusal: the command runs without the proof (the marker was created)"
	else
		bad "mutation no-proof-refusal: the refusal cell still passes"
	fi
fi
# shellcheck disable=SC2016 # a sed program: the $ is literal
if [[ "$have_userns" -eq 1 ]] &&
	mutant no-boot-check 's/^	\[ "$(cat "$p" 2>\/dev\/null)" = "$b" \]; then$/	true; then/'; then
	probe "$tmp/no-boot-check.sh" >"$tmp/probe-m7.sh"
	if [[ "$(proof_case "$tmp/probe-m7.sh" "$setup_stale")" == present ]]; then
		ok "mutation no-boot-check: a proof from another boot reads present"
	else
		bad "mutation no-boot-check: the stale-proof cell still reads absent"
	fi
fi

# #19162 mutations.
# shellcheck disable=SC2016 # a sed program: the $ is literal
if mutant no-state-refusal 's/if \[\[ "$as_root" -eq 1 \&\& "$allow_xpf_state" -ne 1 \]\]; then/if false; then/'; then
	reset_state
	touch "$state/ha-peer-epoch.lock"
	if ! state_refuses "$tmp/no-state-refusal.sh" m8 && [[ -e "$marker" ]]; then
		ok "mutation no-state-refusal: the --root command runs over the state (the marker was created)"
	else
		bad "mutation no-state-refusal: the refusal cell still passes"
	fi
	reset_state
fi
# shellcheck disable=SC2016 # a sed program: the $ is literal
if mutant no-writer-report 's/if \[\[ -n "$new" \]\]; then/if false; then/'; then
	if ! writer_named "$tmp/no-writer-report.sh" m9 && [[ "$(cat "$tmp/m9.rc")" == 3 ]]; then
		ok "mutation no-writer-report: the writer cell fails, with the status still 3"
	else
		bad "mutation no-writer-report: the writer cell still passes"
	fi
fi
# Each run takes its OWN lock file: everything works, nothing is serialized.
# shellcheck disable=SC2016 # a sed program: the $ is literal
if mutant no-root-lock 's|flock /run/xpf-vm-test-run-root.lock|flock /run/xpf-vm-test-run-root.$$.lock|'; then
	if ! two_lanes "$tmp/no-root-lock.sh" m11; then
		ok "mutation no-root-lock: the two-lane cell fails (unserialized lanes)"
	else
		bad "mutation no-root-lock: the two-lane cell still passes"
	fi
fi
if mutant no-interrupt-report 's/if wait_unfrozen soft; then xpf_state_report || true; fi/:/'; then
	if ! term_reports "$tmp/no-interrupt-report.sh" m12 && [[ "$(cat "$tmp/m12.rc")" == 143 ]]; then
		ok "mutation no-interrupt-report: the TERM cell fails, with the status still 143"
	else
		bad "mutation no-interrupt-report: the TERM cell still passes (rc $(cat "$tmp/m12.rc"))"
	fi
fi
if mutant inverted-compare 's/comm -13 /comm -12 /'; then
	if ! only_new_named "$tmp/inverted-compare.sh" m10 && [[ "$(cat "$tmp/m10.rc")" == 0 ]]; then
		ok "mutation inverted-compare: the only-new cell fails, with the status still 0"
	else
		bad "mutation inverted-compare: the only-new cell still passes"
	fi
fi
reset_state

echo "vm-test-run selftest: ${pass} passed, ${fail} failed, ${skip} skipped"
[[ "$fail" -eq 0 ]]
