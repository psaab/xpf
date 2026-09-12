#!/bin/sh
# Single entry point for the day-0 / image / dist / deploy self-tests
# (fable-165 H-19).
#
# These self-tests (grow-root stamp discipline, bake sign-ordering, the
# signed-distribution roundtrip, and the xpf-deploy pure-function + mixed-base
# HA gate coverage) all pass but were wired into NOTHING: `make test` runs only
# the Go + Rust suites (#4006), there is no CI, and each self-test could only be
# run by hand. A regression re-introducing sign-before-validate (#4017) or
# breaking the grow-root stamp discipline (#2047) merged green.
#
# This runner DISCOVERS and runs every hermetic self-test with one command
# (`make selftest`). It is fast (<a few seconds) and needs no root, no incus, no
# cluster, no network. A leg whose external tool is missing SKIPs (exit 77 from
# a shell leg, or unittest skips) instead of failing, so the runner is green on
# a minimal host and only goes RED on a genuine regression.
#
# Scope: the pure/hermetic self-tests only. The incus/QEMU image boot matrix
# (scripts/image/validate.py) and the loss-cluster smoke targets need a
# hypervisor and are NOT run here — they have their own entry points.
set -u

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1007
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
cd "$ROOT" || { echo "FATAL: cannot cd to repo root $ROOT" >&2; exit 1; }

PASS=0
FAIL=0
SKIP=0
FAILED_LEGS=""

hdr()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
passl() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
skipl() { echo "  SKIP: $*"; SKIP=$((SKIP + 1)); }
faill() { echo "  FAIL: $*" >&2; FAIL=$((FAIL + 1)); FAILED_LEGS="$FAILED_LEGS $1"; }

# run_shell <script> [args...] — run a shell self-test. Exit 0 = PASS,
# exit 77 = SKIP (a leg self-reported a missing tool), anything else = FAIL.
# run_bash: like run_shell, but invokes the script with bash.
#
# run_shell forces `sh` regardless of the script's shebang, which is correct
# for the POSIX self-tests it was written for. A self-test that legitimately
# needs bash (arrays, [[ ]], <<< herestrings, ${var//pat/}) fails under dash
# with "Bad substitution" — a syntax error, not a real result. Rather than
# rewrite a bash library into POSIX so its own test can run, run it with the
# interpreter it is written for, and SKIP rather than fail when bash is absent.
run_bash() {
	script=$1
	shift
	if [ ! -f "$script" ]; then
		skipl "$script (not present)"
		return
	fi
	if ! command -v bash >/dev/null 2>&1; then
		skipl "$script (bash not installed)"
		return
	fi
	out=$(bash "$script" "$@" 2>&1)
	rc=$?
	if [ "$rc" -eq 0 ]; then
		passl "$script"
	elif [ "$rc" -eq 77 ]; then
		skipl "$script ($(echo "$out" | grep -m1 -i skip || echo 'tool unavailable'))"
	else
		faill "$script"
		echo "$out" | sed 's/^/      /'
	fi
}

run_shell() {
	script=$1
	shift
	if [ ! -f "$script" ]; then
		skipl "$script (not present)"
		return
	fi
	out=$(sh "$script" "$@" 2>&1)
	rc=$?
	if [ "$rc" -eq 0 ]; then
		passl "$script"
	elif [ "$rc" -eq 77 ]; then
		skipl "$script ($(echo "$out" | grep -m1 -i skip || echo 'tool unavailable'))"
	else
		faill "$script"
		echo "$out" | sed 's/^/      /'
	fi
}

# run_py <test_file.py> — run a python unittest file directly (each has a
# `unittest.main()` __main__ and resolves its target import relative to its own
# path, so cwd is irrelevant). Skips are reported by unittest itself (exit 0).
run_py() {
	script=$1
	if [ ! -f "$script" ]; then
		skipl "$script (not present)"
		return
	fi
	out=$(python3 "$script" 2>&1)
	rc=$?
	if [ "$rc" -eq 0 ]; then
		# Surface any unittest-level skips in the summary line.
		nskip=$(echo "$out" | grep -c 'skipped=' 2>/dev/null || true)
		if [ "$nskip" -gt 0 ] 2>/dev/null; then
			passl "$script ($(echo "$out" | grep -o 'skipped=[0-9]*' | head -1))"
		else
			passl "$script"
		fi
	else
		faill "$script"
		echo "$out" | sed 's/^/      /'
	fi
}

# ── 1. shell-syntax lint (<interp> -n) over the image/dist/day-0 scripts ──
# The interpreter is chosen from each script's shebang: xpf-day0-config is
# bash (uses arrays), the rest are POSIX sh — linting a bash script with dash
# would false-fail on array syntax.
hdr "shell syntax (parse check)"
SH_SCRIPTS="
scripts/image/xpf-day0-config
scripts/image/xpf-grow-root
scripts/image/xpf-uefi-slots
scripts/image/xpf-kernel-promote
scripts/image/incus-agent-setup
scripts/image/test-grow-root.sh
scripts/dist/selftest.sh
scripts/dist/install.sh
scripts/dist/build-apt-repo.sh
scripts/run-selftests.sh
scripts/mutate-lib.sh
scripts/mutate.sh
scripts/mutate-selftest.sh
scripts/docs/check-upgrade-docs.sh
scripts/docs/check-upgrade-docs-selftest.sh
test/incus/fbf-steering-lib.sh
test/incus/fbf-steering-selftest.sh
test/incus/test-fbf-steering.sh
test/incus/newflow-ceiling-lib.sh
test/incus/newflow-ceiling-selftest.sh
test/incus/newflow-ceiling-harness.sh
test/incus/mouse-elephant-lib.sh
test/incus/mouse-elephant-selftest.sh
scripts/harness-census.sh
test/incus/harness-census-selftest.sh
test/incus/harness-result.sh
test/incus/harness-result-selftest.sh
test/incus/harness-ledger-mutation-selftest.sh
scripts/ignored-cell-census.sh
test/incus/ignored-cell-census-selftest.sh
scripts/go-skip-census.sh
test/incus/go-skip-census-selftest.sh
scripts/close_keyword_lint_ci.sh
scripts/git-hooks/commit-msg
scripts/git-hooks/install.sh
"
for s in $SH_SCRIPTS; do
	[ -f "$s" ] || continue
	case $(head -1 "$s") in
	*bash*) interp="bash" ;;
	*) interp="sh" ;;
	esac
	if ! command -v "$interp" >/dev/null 2>&1; then
		skipl "$interp -n $s ($interp not installed)"
		continue
	fi
	if "$interp" -n "$s" 2>/tmp/xpf-selftest-shn.$$; then
		passl "$interp -n $s"
	else
		faill "$interp -n $s"
		sed 's/^/      /' /tmp/xpf-selftest-shn.$$
	fi
done
rm -f /tmp/xpf-selftest-shn.$$

# ── 2. optional shellcheck lint (SKIP if not installed) ──
hdr "shellcheck (optional)"
if command -v shellcheck >/dev/null 2>&1; then
	for s in $SH_SCRIPTS; do
		[ -f "$s" ] || continue
		if out=$(shellcheck -S warning "$s" 2>&1); then
			passl "shellcheck $s"
		else
			faill "shellcheck $s"
			echo "$out" | sed 's/^/      /'
		fi
	done
else
	skipl "shellcheck not installed (apt-get install shellcheck)"
fi

# ── 3. python unittest self-tests (image / deploy / scripts root) ──
hdr "python self-tests"
for t in scripts/image/test_*.py scripts/dist/test_*.py scripts/deploy/test_*.py scripts/test_*.py; do
	[ -f "$t" ] || continue
	run_py "$t"
done

# ── 3b. python unittest self-tests under test/incus/ (#8278) ──
#
# These were reached by NO target. Section 3 above globs the PREFIX
# convention (test_*.py) in four scripts/ directories; test/incus/ uses
# the SUFFIX convention (*_test.py) and was not in the directory list at
# all -- so even test_mouse_latency_shell_test.py, which satisfies both
# conventions, went unrun. 22 files, 377 cases. That is #7296 repeating
# in the other half: it added a census so an eighth SHELL self-test could
# not accumulate unreached, and that census globs *-selftest.sh only.
#
# Run through `unittest discover` rather than executed directly: two of
# these are pytest-style modules collected by a load_tests shim
# (test/incus/unittest_shim.py, #8136), and a runner that executes a
# file whose collector is installed later measures nothing while
# reporting success. harness_discovery_test.py now asserts the two ways
# agree, so this runner may use either -- discovery is chosen because it
# does not depend on a file having a __main__ block at all.
#
# The file list is a GLOB, not a hand-maintained list, so a 23rd file
# cannot accumulate unreached the way the first 22 did. The census below
# guards the remaining failure: a glob that matches nothing would sweep
# an empty set and report a clean pass.
hdr "test/incus python self-tests"
incus_py_ran=0
incus_py_seen=""
if command -v python3 >/dev/null 2>&1; then
	for t in test/incus/*_test.py test/incus/test_*.py; do
		[ -f "$t" ] || continue
		# test_mouse_latency_shell_test.py matches both globs.
		case " $incus_py_seen " in
		*" $t "*) continue ;;
		esac
		incus_py_seen="$incus_py_seen $t"
		incus_py_ran=$((incus_py_ran + 1))
		out=$(python3 -m unittest discover -s test/incus -p "$(basename "$t")" 2>&1)
		rc=$?
		ran=$(printf '%s\n' "$out" | sed -n 's/^Ran \([0-9][0-9]*\) test.*/\1/p' | head -1)
		if [ "$rc" -eq 5 ]; then
			# unittest's "NO TESTS RAN". A registered file that executes
			# nothing is indistinguishable from a passing one by every
			# signal except this exit code, so it must be a FAIL and not
			# a pass or a skip.
			faill "$t (NO TESTS RAN -- registered but measures nothing)"
		elif [ "$rc" -eq 0 ]; then
			passl "$t (${ran:-?} tests)"
		else
			faill "$t"
			printf '%s\n' "$out" | sed 's/^/      /'
		fi
	done
else
	skipl "test/incus python self-tests (python3 not installed)"
fi

incus_py_on_disk=$(ls test/incus/*_test.py test/incus/test_*.py 2>/dev/null | sort -u | wc -l)
if [ "$incus_py_ran" -eq 0 ] && [ "$incus_py_on_disk" -gt 0 ]; then
	faill "test/incus python census (ran 0 of $incus_py_on_disk files -- the glob matched nothing)"
elif [ "$incus_py_ran" -ne "$incus_py_on_disk" ]; then
	faill "test/incus python census (ran $incus_py_ran of $incus_py_on_disk files on disk)"
else
	passl "test/incus python census ($incus_py_ran files, all invoked)"
fi

# ── 4. shell self-tests ──
hdr "shell self-tests"
run_shell scripts/image/test-grow-root.sh
run_shell scripts/dist/selftest.sh
# #7423: the mutation harness's scoring library. Hermetic (fixture logs). The
# refusal cell is the one that matters -- a runner that gates in one language
# scores every cross-language mutation as an ESCAPE, which is a claim that the
# code is untested.
run_bash scripts/mutate-selftest.sh
run_bash scripts/go-test-json-selftest.sh
run_bash scripts/no-git-stash-selftest.sh
# #9783: the upgrade-docs canary (make docs-check). Hermetic fixture trees via
# DOCS_CHECK_ROOT; the row that matters is the positive control -- the phantom
# symbol in a LIVE doc must still fail once the history archives are excluded.
run_bash scripts/docs/check-upgrade-docs-selftest.sh
# AF_XDP reproducer strict-warning build — fail-on-revert gate for #4906
# (HC-081 uninitialized-counter false PASS). SKIPs on a host without a C
# toolchain / libbpf-dev / libxdp-dev / xxd.
run_shell test/xsk-repro/selftest-compile.sh
# #6289 M2: the selftest-compile.sh SKIP gate must probe a trial LINK (static
# archives), not just header syntax, so a headers-present/static-missing host
# SKIPs cleanly instead of false-RED. Hermetic (fake cc); SKIPs without make/xxd.
run_shell test/xsk-repro/selftest-skipgate_6289.sh
# #6355: selftest-compile.sh must WORD-SPLIT $CC like the Makefile's $(CC) so a
# multi-token wrapper CC (`ccache gcc`, `env cc`) that `make check` accepts runs
# through instead of false-SKIPping. Hermetic (fake cc via `env`); SKIPs without
# make/xxd/env.
run_shell test/xsk-repro/selftest-multitoken-cc_6355.sh
# #6898 A10-b5-F1: BEHAVIOURAL gate (not a strict-warning compile) for the
# reproducer's probe filter. The XDP program redirects every packet on the queue,
# so the receive counters used to count all interface traffic and `rx > 0` was
# satisfiable by an ARP or an IPv6 RA while the tool's own probes never arrived —
# the exact failure the reproducer exists to detect, reported as PASS. SKIPs
# without cargo or offline-buildable deps.
run_shell test/xsk-repro/selftest-probe-filter_6898.sh
# #7796: the FBF DSCP ip-rule APPLY LEG. The defect was invisible to every
# compile-side test — the pre-fix code built a well-formed netlink.Rule and the
# kernel rejected it (FRA_TOS masks to IPTOS_TOS_MASK, so DSCP<<2 is refused from
# dscp 8 up and the whole commit fails). The cells need CAP_NET_ADMIN, so under a
# plain `go test` they SKIP — and a skipped cell reads identically to a passing
# one. This leg runs them under `unshare -rn`. SKIPs without go/unshare or where
# unprivileged user namespaces are unavailable.
run_shell test/routing/selftest-rule-dscp_7796.sh
# #6923: the chokepoint argument for the v6 conntrack publish path rests on
# `refresh_bpf_conntrack_last_seen` being unable to CREATE a key, because it
# updates with BPF_EXIST. "The flag is named EXIST" and "the kernel refuses
# creation under this flag" are different claims; this asks the kernel, with a
# BPF_ANY positive control so an ENOENT cannot come from a broken fixture.
# SKIPs without cc, passwordless sudo, or CAP_BPF.
run_shell test/mutation/selftest-bpf-exist-cannot-create_6923.sh
# #6936: FBF two-upstream steering verdicts. Hermetic — no incus, no cluster,
# no network. Guards a negative cell that used to fail to a HEALTHY value:
# "no leak" and "the probe returned nothing" both scored PASS. Needs bash.
run_bash test/incus/fbf-steering-selftest.sh
# #6962: the new-flow ceiling harness's node selection. Hermetic — no incus, no
# cluster. Guards a grep that matched the PEER's row in `show chassis cluster
# status` and therefore always selected $FW0: it failed to a PLAUSIBLE VALUE
# (a node name), not to an error, so the run completed and was refused three
# layers later by the analyzer as if the dataplane were at fault. Needs bash.
run_bash test/incus/newflow-ceiling-selftest.sh

# #7296: the remaining hermetic test/incus self-tests. Every one was on disk and
# green, and NONE was reached by this runner -- so `make selftest` reported a
# clean pass while 192 cases across seven files never executed. The issue named
# ONE of them; there were seven, which is why the census below exists rather
# than a longer list alone.
run_bash test/incus/deploy-lib-selftest.sh
run_bash test/incus/cluster-build-identity-selftest.sh
run_bash test/incus/cluster-cell-selftest.sh
run_bash test/incus/cluster-env-selftest.sh
run_bash test/incus/cos-apply-lib-selftest.sh
run_bash test/incus/host-inbound-selftest.sh
run_bash test/incus/iperf-throughput-selftest.sh
run_bash test/incus/screen-probe-selftest.sh
run_bash test/incus/target-services-selftest.sh
run_bash test/incus/with-cluster-selftest.sh
# #7159: the mouse-latency elephant generator's remote lifecycle. Hermetic --
# a fake iperf3 plus an unprivileged PID namespace; no incus, no cluster. The
# defect it guards produced a CORRUPT MEASUREMENT, not an error: killing the
# local incus-exec client left the remote 90 s iperf3 running, so the next rep
# shared the shaped class with its own predecessor and the whole cell voided
# with a plausible cwnd-not-settled reason. Needs bash.
run_bash test/incus/mouse-elephant-selftest.sh
# #8302: the harness reachability census's own self-test. Hermetic (fixture
# repos under a mktemp -d). It is a gate ABOUT gates, so every defence is
# asserted twice: a fixture that must score UNREACHED, and a MUTATION of the
# census that must make that same fixture flip to reached. A mutation that does
# NOT flip is an ESCAPE and fails -- a census with a broken matcher reports a
# clean board, and nothing but a mutation can tell it from a healthy one.
run_bash test/incus/harness-census-selftest.sh
# #8302: the harness result ledger. Hermetic -- fixtures only, no cluster.
#
# harness-result-selftest.sh drives the whole adapter table, whose reason for
# existing is that the tree's own tools disagree about what `exit 1` means:
# INVALID ("did not measure") in newflow_ceiling_analyze.py, a measured FAIL in
# mouse_latency_aggregate.py, and iperf-throughput-lib.sh has no void state at
# all. Its load-bearing cell EXTRACTS the real summary line from each of the
# nine gates that carry the shape, so an adapter anchored on a label prefix --
# which silently covers six of eight -- goes red here.
run_bash test/incus/harness-result-selftest.sh
# ...and the mutation gate over the comparator and the adapter table. A
# comparator with a broken band is INDISTINGUISHABLE from a healthy one on
# every green run, and a loop is green almost all the time by construction, so
# no amount of reading separates the two. Each cell removes one guard and
# asserts the suite reds; an ESCAPED mutation is the report.
run_bash test/incus/harness-ledger-mutation-selftest.sh
# #8352: the ignored-cell census's own self-test. Hermetic -- fixture trees and
# a MOCKED issue-state command, so the branch that carries the whole point (an
# issue CLOSES and the census reds) is exercised without a network. Paired
# cells throughout: a fixture that must fail and its nearly-identical twin that
# must pass, because a census that reddened on everything would satisfy every
# failure cell while being useless.
run_bash test/incus/ignored-cell-census-selftest.sh

# -- go-skip census (#9052 item 4) --
#
# The missing sibling of the three censuses above: `go test ./...` prints `ok`
# for a package whose cells all skipped, so 318 skip call sites were invisible
# to every gate in the repo. Its self-test is positive-control shaped — every
# claim is paired with a fixture the census MUST reject — because a census that
# cannot be made to fail is indistinguishable from one that examines nothing,
# which is the defect the whole of #9052 is about.
run_bash test/incus/go-skip-census-selftest.sh

# -- harness reachability census (#8302) --
#
# The three censuses in this runner all guard the SELF-TEST layer. One layer up
# -- the cluster and measurement harnesses under test/incus/ -- there was none,
# and 28 of 41 runnable harnesses were reached by nothing; 15 of them are gates
# the tree built, unit-tested, documented and then ran zero times. This is the
# #7296 shape one layer up, so it gets the #7296 treatment: invoked by a
# Makefile recipe (`make harness-census`) AND folded into this aggregate, red
# on an empty sweep, and carrying a positive control.
#
# `sh` is correct here: scripts/harness-census.sh declares #!/bin/sh and is
# POSIX (the #8153 interpreter census checks this).
hdr "harness reachability census"
run_shell scripts/harness-census.sh

# -- ignored-cell census (#8352) --
#
# An `#[ignore]`d fail-until-fixed cell has no wake-up: `#[ignore]` is invisible
# to `make test-rust`, so when the defect it documents is fixed the cell stays
# ignored, stays green, and guards nothing forever. A green run with the cell
# ignored is byte-identical to a green run with it passing.
#
# Two halves, deliberately. Checks (1) every #[ignore] carries a reason and (2)
# every reason DECLARES its kind with a marker are a pure file scan and always
# run. Check (3) -- the named issue is still OPEN, which is the wake-up -- needs
# `gh`, so without it the script exits 77 and this leg SKIPs. It exits 1 rather
# than 77 when the hermetic half failed, so a machine without gh keeps the
# census instead of losing it to a blanket skip.
#
# `sh` is correct: the script declares #!/bin/sh and is POSIX (the #8153
# interpreter census checks this).
hdr "ignored-cell census"
run_shell scripts/ignored-cell-census.sh --check-issues

# -- interpreter census (#8153) --
#
# run_shell forces `sh` regardless of the script's shebang. That is correct for
# the POSIX legs, and it is a SYNTAX ERROR for a bash script: dash reports
# "Bad substitution" on ${BASH_SOURCE[0]} and the leg fails for a reason that
# has nothing to do with what it tests.
#
# scripts/mutate-selftest.sh was registered with run_shell and had been failing
# that way on every `make selftest`. The doc comment on run_shell above already
# describes this failure by name and run_bash already exists for it, so the
# contract was written down and the registration did not follow it.
#
# The #7296 census below cannot catch this. It globs test/incus/*-selftest.sh,
# and this script lives in scripts/ -- but even inside that glob it asks a
# different question. "Is every self-test INVOKED" and "is every self-test
# invoked with the interpreter it DECLARES" are different properties: a script
# can be listed, be invoked, and execute none of what it tests.
interp_mismatch=""
interp_seen=0
for reg in $(sed 's/#.*//' scripts/run-selftests.sh | sed -n 's/^run_shell \([^ ]*\).*/\1/p'); do
	[ -f "$reg" ] || continue
	interp_seen=$((interp_seen + 1))
	case $(head -1 "$reg") in
	*bash*) interp_mismatch="$interp_mismatch $reg" ;;
	esac
done
if [ "$interp_seen" -eq 0 ]; then
	# Matching no run_shell registrations would report a clean census over an
	# empty set -- the swept-nothing pass #7296 guards against.
	faill "interpreter census (matched NO run_shell registrations -- the sed is wrong)"
elif [ -n "$interp_mismatch" ]; then
	faill "interpreter census (bash-shebang scripts registered with run_shell, which forces sh:$interp_mismatch)"
else
	passl "interpreter census ($interp_seen run_shell legs, none declaring bash)"
fi

# -- self-test census (#7296) --
#
# The defect was not "one script was forgotten" -- it was that NOTHING NOTICED.
# Seven hermetic self-tests accumulated unreached because this runner carries a
# hand-maintained list with no check that the list covers what is on disk.
# Adding the seven without this census would leave the eighth to repeat it.
#
# Matches the `run_bash <path>` CALL form with comments stripped: a bare
# filename mention would otherwise be satisfied by the comment block above that
# names these very scripts -- the shape where a source-scanning gate passes on
# its own documentation.
census_missing=""
census_seen=0
runner_code=$(sed 's/#.*//' scripts/run-selftests.sh)
for st in test/incus/*-selftest.sh; do
	[ -f "$st" ] || continue
	census_seen=$((census_seen + 1))
	case "$runner_code" in
	*"run_bash $st"*) ;;
	*) census_missing="$census_missing $st" ;;
	esac
done
if [ "$census_seen" -eq 0 ]; then
	# A glob matching nothing would otherwise report a complete census over an
	# empty set -- a clean pass that swept nothing.
	faill "self-test census (matched NO test/incus/*-selftest.sh -- the glob is wrong)"
elif [ -n "$census_missing" ]; then
	faill "self-test census (not invoked by this runner:$census_missing)"
else
	passl "self-test census ($census_seen hermetic test/incus self-tests, all invoked)"
fi

# ── 5. ledger lint (#8302 §4.1) ──
#
# test/results/ledger.d/ is git-tracked: one <run_id>.json shard per gate run
# (#8346). Concurrent lanes never touch the same path, so the layout is
# conflict-free by construction rather than by a merge driver -- which is the
# point, because this repo's .git/config shadowed git's built-in `union` with a
# no-op for months (#8348) and silently dropped three real rows.
#
# WHAT THIS LEG CAN AND CANNOT SEE, stated plainly because an overstated
# docstring is how the gap above stayed invisible: ledger-lint reads every
# shard and applies the emitter's own contract, so a hand-edited row, a
# committed conflict marker, a shard whose filename disagrees with its run_id,
# and an EMPTY ledger are all red here. It CANNOT see a row that is simply
# GONE -- a deleted shard leaves a well-formed, internally consistent,
# perfectly lint-clean directory. That is what the separate
# ledger-merge-completeness leg below is for, and neither leg substitutes for
# the other.
hdr "harness ledger"
if command -v python3 >/dev/null 2>&1; then
	out=$(python3 test/incus/ledger_compare.py --lint --ledger test/results/ledger.d 2>&1)
	rc=$?
	if [ "$rc" -eq 0 ]; then
		passl "ledger-lint ($out)"
	else
		faill "ledger-lint"
		echo "$out" | sed 's/^/      /'
	fi
	# #8346: the completeness half. `ledger-lint` above is over the rows that
	# are PRESENT, so a row that is simply MISSING leaves a well-formed,
	# internally consistent, lint-clean file -- it cannot see a drop. Three real
	# gate records were lost to a `merge.union.driver = true` in .git/config
	# that shadowed git's BUILT-IN union with a no-op (no conflict, no warning,
	# and `git check-attr` reporting `merge: union` the whole time), and this
	# leg was green throughout. The check below compares against the merge
	# PARENTS instead of against the file alone, and is a run_id SET check --
	# a count would pass a merge that dropped one row and added another.
	#
	# #9046 widened this twice over. It used to inspect HEAD ONLY, so a merge
	# that dropped a shard was catchable only while HEAD was exactly that
	# merge -- one commit later it was permanently invisible, because plain
	# ledger-lint cannot see a missing row. It now walks the last N merges.
	#
	# And "nothing to check" is no longer a PASS. The previous code returned 0
	# on a non-merge HEAD and put the words "nothing to check" in the PASS
	# label, which was the intended disclosure -- but a PASS line still
	# increments the suite's `passed=` total, and the total is what gets read.
	# rc 3 is "we could not look" and maps to SKIP, so the count never claims
	# a check that did not happen.
	out=$(python3 test/incus/ledger_compare.py --lint-merge 2>&1)
	rc=$?
	if [ "$rc" -eq 0 ]; then
		passl "ledger-merge-completeness ($out)"
	elif [ "$rc" -eq 3 ]; then
		skipl "ledger-merge-completeness ($out)"
	else
		faill "ledger-merge-completeness"
		echo "$out" | sed 's/^/      /'
	fi
else
	skipl "ledger-lint (python3 not installed)"
	skipl "ledger-merge-completeness (python3 not installed)"
fi

# ── summary ──
printf '\n\033[1m== selftest summary ==\033[0m\n'
echo "  passed=$PASS  skipped=$SKIP  failed=$FAIL"
if [ "$FAIL" -ne 0 ]; then
	echo "  FAILED legs:$FAILED_LEGS" >&2
	exit 1
fi
echo "  OK — all self-tests passed (or SKIP-gated on missing tools)"
