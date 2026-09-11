#!/usr/bin/env bash
# Mutation-harness scoring library.
#
# Sourced by scripts/mutate.sh (the driver) and scripts/mutate-selftest.sh (the
# self-test). Every function here is pure text processing over a gate log, so
# the self-test can drive the whole verdict matrix from fixtures without a repo,
# a compiler, or a cluster.
#
# The defects this encodes, each of which has produced a WRONG VERDICT before:
#
#   1. A single-language runner scores every cross-language mutation as an
#      ESCAPE, because nothing it ran could have failed. A cell whose touched
#      files include a language no configured gate covers must be REFUSED, not
#      scored.
#   2. rc != 0 is not "the tests failed". A build break, a panic before
#      collection, and a full disk all produce rc != 0 with no failing test, and
#      a harness that keys on rc scores them as kills; one that keys on "no
#      named FAIL" scores them as escapes. Both are wrong: they are VOID.
#   3. A -race failure has NO `--- FAIL` line. It emits `WARNING: DATA RACE`
#      and a package-level FAIL, so a `^--- FAIL` counter scores a genuine race
#      red as a PASS.
#   4. A HANG prints nothing a `^--- FAIL` scan can see, and its blast radius
#      exceeds its own cell. The other void shapes each leave a trace -- a
#      compiler diagnostic, an unchanged tree, a panic trace, a DATA RACE
#      banner. A mutation that makes a test wait forever leaves none: the run
#      burns its whole time budget and is killed, so the log ends mid-stream
#      with no verdict marker at all. Worse, the budget it consumed belonged to
#      every LATER cell in the batch, and those produce no output either -- so
#      one hang can be recorded as a screen full of escapes nobody earned.
#      (Seen on #7611: a contract change made `Run` retry a bind failure
#      forever, and a test calling it with context.Background() never returned.)
#   5. `^--- FAIL` is an UNSOUND instrument, and it is the one used to detect
#      the four shapes above (#8213). Under parallel `go test -v` the output of
#      concurrently running tests interleaves MID-LINE, so a real
#      `--- FAIL: TestX` can be spliced into another test's failure text and no
#      longer start at column 0. The anchored grep misses it and the cell scores
#      as an ESCAPE -- and an escape reads as "the fix is not bound", which
#      argues for weakening the TEST. It does not merely lose a signal; it
#      manufactures a case for deleting a guard that works.
#
#      Two fixes, because there are two halves:
#        - COUNTING is made splice-tolerant below (unanchored, occurrence-wise).
#          That recovers the missed kill.
#        - ATTRIBUTION cannot be fixed by counting AT ALL. If your cell's
#          `--- FAIL` is spliced but another test in the same package fails
#          cleanly, the count is still >= 1 and the cell scores as a KILL FOR
#          THE WRONG TEST, with rc and count agreeing and nothing looking
#          wrong. Only a NAME can distinguish "my cell's test failed" from
#          "something failed" -- see mutation_go_failed_names_json and
#          mutation_verdict_for_target.

# mutation_lang_of FILE -> go|rust|unknown
# #9158: REFUSE to mutate a file that has uncommitted changes.
#
# THE FAILURE THIS PREVENTS, measured. A mutation driver rewrites the file under
# test and restores it afterwards. If the pre-mutation content lives only in the
# WORKING TREE, that content is one interrupted cell away from gone -- a timeout
# kill, a session death or a Ctrl-C between apply and restore leaves the MUTANT
# on disk and the original nowhere git can reach. `docs/log/` already records the
# sibling shape: a dead lane's worktree carrying an applied mutant.
#
# It is worse than a lost file, because of how it SCORES. A driver that reverts
# with `git checkout --` (as an ad-hoc one did during #9158) restores to HEAD,
# so an uncommitted fix is destroyed by the FIRST cell and every later cell then
# runs against a pristine tree. The matrix comes back all-VOID "not applied" --
# including the CONTROL, which is the tell -- and that reads as "my anchors are
# wrong", which is hours of looking in the wrong place.
#
# `scripts/mutate.sh` restores by `cp` rather than `checkout`, so it does not
# destroy work on the happy path. It carried this rule as a COMMENT ("Commit
# before running: a harness that rewrites files WILL eat uncommitted work"), and
# a comment is not a mechanism: it cannot fire. This is that comment as a gate.
#
# Committing first also makes any interruption recoverable with a single
# `git checkout -- <file>`, which is the property that actually matters.
#
# Takes `git status --porcelain` OUTPUT rather than calling git, so the selftest
# can drive both directions from fixture text with no repo (`make
# test-mutate-lib` is hermetic and must stay that way). Prints the offending
# lines and returns 1 when dirty; prints nothing and returns 0 when clean.
mutation_dirty_targets() {
	local porcelain="$1"
	local dirty
	dirty="$(printf '%s\n' "$porcelain" | sed '/^[[:space:]]*$/d')"
	[ -z "$dirty" ] && return 0
	printf '%s\n' "$dirty"
	return 1
}

mutation_lang_of() {
	case "$1" in
	*.go) printf 'go\n' ;;
	*.rs) printf 'rust\n' ;;
	*) printf 'unknown\n' ;;
	esac
}

# mutation_langs_of FILE... -> sorted unique language set, one per line
mutation_langs_of() {
	local f
	for f in "$@"; do mutation_lang_of "$f"; done | sort -u
}

# mutation_can_score "LANGS" "CONFIGURED" -> 0 if every language in LANGS has a
# configured gate, 1 otherwise. Both arguments are whitespace-separated sets.
#
# This is the refusal gate. It answers "could the gates I am about to run have
# observed this mutation at all", which is a different question from "did any
# test fail".
mutation_can_score() {
	local langs="$1" configured="$2" l c found
	for l in $langs; do
		found=0
		for c in $configured; do
			[ "$l" = "$c" ] && found=1 && break
		done
		[ "$found" = 0 ] && return 1
	done
	return 0
}

# mutation_uncovered "LANGS" "CONFIGURED" -> the languages with no gate
mutation_uncovered() {
	local langs="$1" configured="$2" l c found
	for l in $langs; do
		found=0
		for c in $configured; do
			[ "$l" = "$c" ] && found=1 && break
		done
		[ "$found" = 0 ] && printf '%s\n' "$l"
	done
}

# mutation_infra_broken LOG -> 0 when the run was invalidated by the machine
# rather than by the mutation (full disk is the one that has bitten; it reds
# NAMED tests and reads as a real regression).
#
# #9500: the `injected:` exclusion is LOAD-BEARING, not defensive.
# pkg/configstore/persist_failure_test.go declares
#
#	var errDiskFull = errors.New("injected: no space left on device")
#
# and TestSyncApply_DegradesNotFails deliberately returns it while EXPECTING
# SyncApply to succeed; store.go routes it to noteActivePersistFailureLocked,
# which slog.Errors it. mutate.sh runs its Go gate as
# `GOTESTJSON=... make test-go` with 2>&1 into the cell log, and GOTESTJSON
# selects `go test -json`, which implies -v — so a PASSING run streams that
# literal into the very log this predicate greps.
#
# The consequence was total and silent. mutation_verdict tests infra FIRST, so
# it outranks both KILLED and ESCAPED, and every Go cell scored
# VOID(infrastructure) — turning ESCAPED, the verdict that says "this code is
# untested", into "go look at your disk", which is fine. A detector for a
# broken machine matched a string the healthy machine prints.
#
# Excluding the whole LINE is deliberate: a real ENOSPC arrives on its own line
# (a compiler or linker diagnostic), so dropping fixture lines cannot mask one.
# The memory half has no such collision today — `cannot allocate memory` appears
# in no fixture in this tree — but it is filtered through the same pass so a
# future injected-OOM fixture does not reintroduce this defect.
mutation_infra_broken() {
	grep -viE 'injected:' "$1" | grep -qiE 'no space left on device|cannot allocate memory'
}

# mutation_timed_out LOG -> 0 when the run did not FINISH.
#
# Two spellings, and a harness needs both because they arrive from different
# places:
#
#   - go's own `-timeout` fires INSIDE the run and prints `panic: test timed out
#     after 10m0s` followed by a goroutine dump naming the stuck test. That dump
#     is the only thing that identifies the subject, which is why a cell should
#     always be run under an explicit -timeout rather than left to an external
#     kill: without it you know a cell did not finish and nothing else.
#   - an EXTERNAL kill (the runner's own budget, a CI step limit) leaves no
#     marker at all. The caller detects that from the exit status or the elapsed
#     time and passes timedout=yes to mutation_verdict directly; this function
#     cannot see it, and pretending otherwise would be the same "absence read as
#     evidence" mistake the whole library exists to avoid.
#
# Deliberately NOT keyed on the word "timeout" alone: `--- FAIL` bodies say
# "timeout" constantly (context deadlines, dial timeouts, an assertion message
# about a configured timeout), and matching those would score healthy kills as
# void.
mutation_timed_out() {
	grep -qE '^panic: test timed out after ' "$1"
}

# mutation_go_build_broken / mutation_rust_build_broken LOG
# A Go build break, WITHOUT matching `make`'s own echoed Makefile comments.
#
# `^# ` looks like the header go emits above a package's compile errors, but
# `make test-go` echoes every Makefile comment line in the recipe region, and
# those start with `#` too. Keying on that pattern scored a healthy run as
# VOID(build break) -- which does not produce a false KILLED or ESCAPED, but
# does bury the real verdict. Match a compile DIAGNOSTIC (file.go:line:col:) or
# go's explicit build-failure marker instead; neither appears in prose.
mutation_go_build_broken() {
	grep -qE '\[build failed\]|^[^[:space:]]+\.go:[0-9]+:[0-9]+: ' "$1"
}
mutation_rust_build_broken() {
	grep -qE '^error(\[E[0-9]+\])?:|^error: could not compile' "$1"
}

# mutation_go_collected LOG -> number of PACKAGES the run reported on.
# Deliberately counts package result lines only, never `--- FAIL` lines: mixing
# them makes the collection count move with the failure count, which hides a
# package that failed to build behind another package's extra failures.
mutation_go_collected() { grep -cE '^(ok|FAIL|\?)[[:space:]]' "$1"; }

# mutation_go_failed LOG -> named failing tests, INCLUDING races.
#
# UNANCHORED and counted per OCCURRENCE, not per line (#8213). Parallel `go
# test -v` interleaves output mid-line, so a real `--- FAIL: TestX` can end up
# after other text on its line, and two of them can share one line. `grep -c`
# counts LINES, so even the unanchored form would under-count a doubly-spliced
# line; `grep -o` counts the marker itself.
#
# `--- FAIL: ` with the colon and space, rather than `--- FAIL`, so a log that
# merely discusses the marker in prose does not register. That is a weaker
# guard than anchoring was against prose, and the trade is deliberate: prose
# containing the exact go marker is rare and produces a VOID-shaped over-count,
# while a spliced miss produces an ESCAPE that argues for deleting a real test.
mutation_go_failed() {
	local named races
	named=$(grep -oE -- '--- FAIL: ' "$1" | grep -c . )
	races=$(grep -cE '^WARNING: DATA RACE' "$1")
	printf '%s\n' "$((named + races))"
}

# mutation_go_failed_names_json JSONLOG -> sorted unique failing test names.
#
# The ONLY sound attribution. `go test -json` emits one JSON object per event,
# so a name can never be spliced into another line by construction. Requires
# the driver to run `go test -json`; a `make`-driven gate cannot produce it,
# which is why the count-based path above still exists and is still needed.
mutation_go_failed_names_json() {
	jq -r 'select(.Action=="fail") | select(.Test != null) | .Test' <"$1" |
		sort -u
}

mutation_rust_collected() { grep -cE '^test .* \.\.\. ' "$1"; }
mutation_rust_failed() { grep -cE '^test .* \.\.\. FAILED' "$1"; }

# mutation_verdict APPLIED BUILT COLLECTED FAILED INFRA [TIMEDOUT] -> verdict
#
# Order matters. Each earlier condition makes the later numbers meaningless, so
# a harness that checks them in the wrong order reports a confident verdict
# derived from a number it should not have trusted.
#
# TIMEDOUT sits AFTER the build check and BEFORE the collected/failed numbers,
# and that position is the whole point. A timed-out run has usually collected
# and even failed some tests, so both numbers are non-zero and look scoreable —
# but they describe the PREFIX of a run that never finished. Scoring on them
# turns "we do not know" into a confident KILLED or ESCAPED. It cannot go first:
# a run that also hit a full disk or failed to build has a more specific
# explanation, and reporting the timeout would send the reader after a hang that
# is a symptom rather than the cause.
#
# TIMEDOUT is optional so existing callers keep working; omitted means "the
# caller did not check", which is not the same as "no". A caller that cannot
# distinguish a completed run from a killed one should say so rather than pass
# no.
mutation_verdict() {
	local applied="$1" built="$2" collected="$3" failed="$4" infra="$5" timedout="${6:-no}"
	if [ "$infra" = yes ]; then printf 'VOID(infrastructure: disk or memory)\n'; return; fi
	if [ "$applied" != yes ]; then printf 'VOID(mutation not applied)\n'; return; fi
	if [ "$built" != yes ]; then printf 'VOID(build break)\n'; return; fi
	if [ "$timedout" = yes ]; then printf 'VOID(run did not finish: timeout)\n'; return; fi
	if [ "$collected" -eq 0 ]; then printf 'VOID(no tests collected)\n'; return; fi
	if [ "$failed" -gt 0 ]; then printf 'KILLED\n'; return; fi
	printf 'ESCAPED\n'
}

# mutation_verdict_for_target VERDICT TARGET NAMES... -> refined verdict
#
# The attribution half of #8213, and the reason a count can never close it: a
# spliced `--- FAIL` whose package ALSO contains a cleanly-failing unrelated
# test still counts >= 1, so the cell scores KILLED with rc and count in
# agreement and nothing looking wrong. It is a kill FOR THE WRONG TEST, and it
# certifies coverage the cell never demonstrated.
#
# Given the verdict a counting scorer produced, the test the cell was written
# to kill, and the failing NAMES from a -json run, this reports:
#
#   KILLED                  - the intended test failed. The only real kill.
#   ESCAPED(other tests failed: ...)
#                           - something failed, but not the target. NOT a kill:
#                             the mutation is unbound and the run is also red
#                             for an unrelated reason, which is two findings,
#                             not one.
#
# Only refines a KILLED verdict. A VOID stays VOID — an unfinished or unbuilt
# run has no trustworthy names to compare, and refining it would be the same
# "score the prefix" error the timeout ordering exists to prevent.
mutation_verdict_for_target() {
	local verdict="$1" target="$2"
	shift 2
	if [ "$verdict" != KILLED ]; then printf '%s\n' "$verdict"; return; fi
	local n
	for n in "$@"; do
		if [ "$n" = "$target" ]; then printf 'KILLED\n'; return; fi
	done
	printf 'ESCAPED(other tests failed: %s)\n' "$*"
}

# mutation_target_output_has JSONLOG TARGET EXPECT -> status 0 when EXPECT occurs
# in the DECODED Output of TARGET or one of its subtests (TARGET/...).
#
# Decoded, not grepped: `Output` is a JSON string, so a `"` or `\` in the
# message is escaped on disk, and a raw grep for the operator's text misses it.
# Scoped to the target's own events, not the whole stream: a sibling test's
# message must not satisfy another cell's expectation (#9564).
#
# The output is captured before matching. The selftest runs under pipefail,
# and `jq ... | grep -q` fails with SIGPIPE exactly when grep matches early.
mutation_target_output_has() {
	local out
	out=$(jq -r --arg t "$2" \
		'select(.Action=="output") | select(.Test != null) | select(.Test == $t or (.Test | startswith($t + "/"))) | .Output' \
		<"$1") || return 1
	case "$out" in
	*"$3"*) return 0 ;;
	esac
	return 1
}

# mutation_verdict_for_message VERDICT TARGET EXPECT JSONLOG -> refined verdict
#
# The MESSAGE half of attribution (#9564). mutation_verdict_for_target proves
# the NAMED test failed, which is not the same as failing for the reason the cell
# exists. A guard with a LIVENESS fatal ("the parser found no anchors") and a
# VIOLATION branch scores KILLED by name whichever fired. With an expected
# message:
#
#   KILLED            - the target's own output contains EXPECT.
#   KILLED-WRONG-MSG  - the target failed, but not with EXPECT. It is not KILLED,
#                       because the reason is unproven, and not ESCAPED, because
#                       the target did fail.
#
# Refines only KILLED, and only when EXPECT is non-empty. Every other verdict,
# and every spec without the column, is returned byte-identical.
mutation_verdict_for_message() {
	local verdict="$1" target="$2" expect="$3" jsonlog="$4"
	if [ "$verdict" != KILLED ] || [ -z "$expect" ]; then
		printf '%s\n' "$verdict"
		return
	fi
	if mutation_target_output_has "$jsonlog" "$target" "$expect"; then
		printf 'KILLED\n'
		return
	fi
	printf 'KILLED-WRONG-MSG\n'
}

# mutation_score_log LANG LOG APPLIED -> "BUILT COLLECTED FAILED VERDICT"
# mutation_score_log LANG LOG APPLIED [TIMEDOUT] -> "BUILT COLLECTED FAILED VERDICT"
#
# TIMEDOUT lets a caller report an EXTERNAL kill, which leaves no marker in the
# log for this function to find. Omitted, the log is still checked for go's own
# in-run timeout panic.
mutation_score_log() {
	local lang="$1" log="$2" applied="$3" ext_timedout="${4:-no}" built collected failed infra timedout
	infra=no
	mutation_infra_broken "$log" && infra=yes
	timedout="$ext_timedout"
	mutation_timed_out "$log" && timedout=yes
	case "$lang" in
	go)
		built=yes; mutation_go_build_broken "$log" && built=no
		collected=$(mutation_go_collected "$log")
		failed=$(mutation_go_failed "$log")
		;;
	rust)
		built=yes; mutation_rust_build_broken "$log" && built=no
		collected=$(mutation_rust_collected "$log")
		failed=$(mutation_rust_failed "$log")
		;;
	*)
		printf 'no 0 0 REFUSED(no gate covers this language)\n'; return ;;
	esac
	printf '%s %s %s %s\n' "$built" "$collected" "$failed" \
		"$(mutation_verdict "$applied" "$built" "$collected" "$failed" "$infra" "$timedout")"
}
