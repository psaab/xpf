#!/usr/bin/env bash
# Self-test for the mutation-harness scoring library (scripts/mutate-lib.sh).
#
# Hermetic: fixture logs only. No repo, no compiler, no cluster.
#
# The cell that matters most is the REFUSAL one. A single-language runner scores
# every cross-language mutation as an ESCAPE, because nothing it ran could have
# failed -- and an escape is a claim that the code is untested. The library must
# say "cannot score", never a verdict, for a mutation outside its gates.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/mutate-lib.sh"

fails=0
W="$(mktemp -d "${TMPDIR:-/var/tmp}/xpf-mutate-selftest.XXXXXX")"
trap 'rm -rf "$W"' EXIT

ck() { # ck <desc> <want> <got>
	if [ "$2" = "$3" ]; then
		printf '  ok   %s\n' "$1"
	else
		printf '  FAIL %s\n       want: %s\n       got:  %s\n' "$1" "$2" "$3"
		fails=$((fails + 1))
	fi
}

echo "== language detection =="
ck "go file"      "go"      "$(mutation_lang_of pkg/natshow/source.go)"
ck "rust file"    "rust"    "$(mutation_lang_of userspace-dp/src/session/mod.rs)"
ck "unknown file" "unknown" "$(mutation_lang_of bpf/headers/maps.h)"

echo "== refusal gate (the property this harness exists for) =="
mutation_can_score "go" "go rust" && r=0 || r=1
ck "go cell with both gates configured is scorable" "0" "$r"
mutation_can_score "rust" "go" && r=0 || r=1
ck "RUST cell with only the GO gate configured is NOT scorable" "1" "$r"
ck "uncovered language is named" "rust" "$(mutation_uncovered "rust" "go")"
mutation_can_score "unknown" "go rust" && r=0 || r=1
ck "unknown-language cell is not scorable" "1" "$r"

# The end-to-end refusal: a .rs cell scored by a go-only harness must not
# produce a verdict at all. Before this, it produced ESCAPED.
out="$(mutation_score_log unknown /dev/null yes)"
ck "unscorable cell yields REFUSED, not a verdict" \
	"no 0 0 REFUSED(no gate covers this language)" "$out"

echo "== go scoring =="
cat > "$W/kill.log" <<'EOF'
ok  	github.com/psaab/xpf/pkg/cli	6.409s
--- FAIL: TestSomething (0.01s)
FAIL	github.com/psaab/xpf/pkg/natshow	0.02s
EOF
ck "a named FAIL is a kill" "yes 2 1 KILLED" "$(mutation_score_log go "$W/kill.log" yes)"

cat > "$W/escape.log" <<'EOF'
ok  	github.com/psaab/xpf/pkg/cli	6.409s
ok  	github.com/psaab/xpf/pkg/natshow	0.02s
EOF
ck "no failure with real collection is an escape" "yes 2 0 ESCAPED" \
	"$(mutation_score_log go "$W/escape.log" yes)"

# A build break has rc != 0 and NO named failing test. Keying on rc scores it a
# kill; keying on "no --- FAIL" scores it an escape. It is neither.
cat > "$W/build.log" <<'EOF'
# github.com/psaab/xpf/pkg/natshow
pkg/natshow/source.go:180:5: undefined: armed
FAIL	github.com/psaab/xpf/pkg/natshow [build failed]
EOF
ck "a build break is VOID, not a kill and not an escape" \
	"no 1 0 VOID(build break)" "$(mutation_score_log go "$W/build.log" yes)"

# `make test-go` echoes every Makefile comment in the recipe region, and those
# start with `#`. Keying the build-break detector on `^# ` scored a completely
# healthy run as VOID(build break): not a false kill or escape, but it buries
# the real verdict, which is the same loss. Found by running the harness for
# real, not by reading it.
cat > "$W/make-comments.log" <<'EOF'
# go vet gate scoped to pkg/flowexport (#2224): catches the
# atomic.Uint64-copy regression class (ExportConfig embeds the live
# 1-in-N sampleCounter and must never be copied by value). NOT
# tree-wide yet -- two pre-existing vet diagnostics live outside it.
ok  	github.com/psaab/xpf/pkg/cli	6.409s
ok  	github.com/psaab/xpf/pkg/natshow	0.02s
EOF
ck "make's echoed Makefile comments are NOT a build break" \
	"yes 2 0 ESCAPED" "$(mutation_score_log go "$W/make-comments.log" yes)"

# The complement: a real diagnostic must still register even when the run also
# carries prose, which every `make test-go` log does.
cat > "$W/make-and-break.log" <<'EOF'
# go vet gate scoped to pkg/flowexport (#2224): catches the
pkg/natshow/source.go:180:5: undefined: armed
FAIL	github.com/psaab/xpf/pkg/natshow [build failed]
EOF
ck "a real diagnostic still reads as a build break amid Makefile prose" \
	"no 1 0 VOID(build break)" "$(mutation_score_log go "$W/make-and-break.log" yes)"

# A -race failure emits no `--- FAIL` line at all.
cat > "$W/race.log" <<'EOF'
ok  	github.com/psaab/xpf/pkg/cli	6.409s
WARNING: DATA RACE
Write at 0x00c000180018 by goroutine 12:
FAIL	github.com/psaab/xpf/pkg/cluster	3.1s
EOF
ck "a DATA RACE with no --- FAIL line still scores as a kill" \
	"yes 2 1 KILLED" "$(mutation_score_log go "$W/race.log" yes)"

: > "$W/empty.log"
ck "a run that collected nothing is VOID, not an escape" \
	"yes 0 0 VOID(no tests collected)" "$(mutation_score_log go "$W/empty.log" yes)"

# Collection must not move with the failure count: a package that failed to
# BUILD is hidden if `collected` counts `--- FAIL` lines, because another
# package's extra failures keep the number above zero.
cat > "$W/mixed.log" <<'EOF'
ok  	github.com/psaab/xpf/pkg/cli	6.409s
--- FAIL: TestA (0.01s)
--- FAIL: TestB (0.01s)
FAIL	github.com/psaab/xpf/pkg/natshow	0.02s
EOF
ck "collection counts PACKAGES, not failure lines" "2" \
	"$(mutation_go_collected "$W/mixed.log")"

echo "== infrastructure invalidation =="
cat > "$W/disk.log" <<'EOF'
--- FAIL: TestSomething (0.01s)
    write /tmp/go-build123/b001/x.o: no space left on device
FAIL	github.com/psaab/xpf/pkg/natshow	0.02s
EOF
ck "a full disk is VOID even though it reds a NAMED test" \
	"yes 1 1 VOID(infrastructure: disk or memory)" \
	"$(mutation_score_log go "$W/disk.log" yes)"

# #9500: the infra detector matched a string a HEALTHY run prints.
# pkg/configstore's persist-failure fixture is `injected: no space left on
# device`, and it reaches the cell log because mutate.sh runs its Go gate with
# GOTESTJSON set, which selects `go test -json` (implies -v) and streams a
# PASSING test's output. Because mutation_verdict tests infra FIRST, every Go
# cell scored VOID(infrastructure) and ESCAPED became unreachable — the harness
# reported "your disk is broken" instead of "this code is untested".
cat > "$W/injected-only.log" <<'EOF'
{"Action":"output","Test":"TestSyncApply_DegradesNotFails","Output":"level=ERROR msg=\"active config persist failed\" err=\"injected: no space left on device\"\n"}
{"Action":"pass","Test":"TestSyncApply_DegradesNotFails"}
ok  	github.com/psaab/xpf/pkg/configstore	0.04s
EOF
ck "the configstore ENOSPC FIXTURE on a green run is not infrastructure (#9500)" \
	"yes 1 0 ESCAPED" \
	"$(mutation_score_log go "$W/injected-only.log" yes)"

# THE CONTROL, and the reason the exclusion is a filter rather than a deletion:
# "stop detecting ENOSPC entirely" satisfies the cell above. A REAL full disk
# arriving in the SAME log as the fixture must still be VOID, or the repair has
# bought a false ESCAPED — a claim that code is untested — for a run that
# measured the machine.
cat > "$W/injected-plus-real.log" <<'EOF'
{"Action":"output","Test":"TestSyncApply_DegradesNotFails","Output":"level=ERROR msg=\"active config persist failed\" err=\"injected: no space left on device\"\n"}
{"Action":"pass","Test":"TestSyncApply_DegradesNotFails"}
--- FAIL: TestSomething (0.01s)
    write /tmp/go-build123/b001/x.o: no space left on device
FAIL	github.com/psaab/xpf/pkg/natshow	0.02s
EOF
ck "a REAL full disk alongside the fixture is still VOID (#9500 control)" \
	"yes 1 1 VOID(infrastructure: disk or memory)" \
	"$(mutation_score_log go "$W/injected-plus-real.log" yes)"

echo "== not-applied =="
ck "a mutation that did not apply is VOID, whatever the log says" \
	"yes 2 0 VOID(mutation not applied)" \
	"$(mutation_score_log go "$W/escape.log" no)"

echo "== rust scoring =="
cat > "$W/rust-kill.log" <<'EOF'
test session::tests::reaps_on_time_wait ... FAILED
test session::tests::reaps_on_closing ... ok
EOF
ck "rust named failure is a kill" "yes 2 1 KILLED" \
	"$(mutation_score_log rust "$W/rust-kill.log" yes)"

cat > "$W/rust-build.log" <<'EOF'
error[E0308]: mismatched types
error: could not compile `userspace-dp` (lib test) due to 1 previous error
EOF
ck "rust build break is VOID" "no 0 0 VOID(build break)" \
	"$(mutation_score_log rust "$W/rust-build.log" yes)"

echo "== the HANG (#7611) =="
# The fifth void shape, and the only one that leaves NO trace a `^--- FAIL`
# scan can see. go's own -timeout fires inside the run and prints a panic plus
# the goroutine dump naming the stuck test; the run has by then collected and
# even FAILED real tests, so both numbers look scoreable and are not — they
# describe the prefix of a run that never finished.
cat > "$W/timeout.log" <<'EOF'
ok  	github.com/psaab/xpf/pkg/cli	6.409s
--- FAIL: TestUnrelated (0.01s)
panic: test timed out after 10m0s
running tests:
	TestRunReturnsOnBindFailure (600s)

goroutine 1 [running]:
testing.(*M).startAlarm.func1()
FAIL	github.com/psaab/xpf/pkg/grpcapi	600.005s
EOF
ck "a timed-out run is VOID even though it collected and failed tests" 	"yes 2 1 VOID(run did not finish: timeout)" 	"$(mutation_score_log go "$W/timeout.log" yes)"

# The discriminator that keeps the detector honest: "timeout" appears in
# ordinary failure text constantly. Matching the bare word would score real
# kills as void, which is the same loss in the other direction.
cat > "$W/timeout-word.log" <<'EOF'
ok  	github.com/psaab/xpf/pkg/cli	6.409s
--- FAIL: TestDialDeadline (0.01s)
    dial_test.go:41: context deadline exceeded: dial timeout after 5s
FAIL	github.com/psaab/xpf/pkg/frr	0.30s
EOF
ck "the WORD timeout in a failure body is still a kill" "yes 2 1 KILLED" 	"$(mutation_score_log go "$W/timeout-word.log" yes)"

# An EXTERNAL kill leaves no marker at all, so the caller must report it. This
# is the case that loses a whole BATCH: the budget the hang consumed belonged
# to every later cell, and each of those produces an empty log.
ck "an externally killed run is VOID when the caller reports it" 	"yes 2 0 VOID(run did not finish: timeout)" 	"$(mutation_score_log go "$W/escape.log" yes yes)"
ck "the same log without the caller's flag scores normally" "yes 2 0 ESCAPED" 	"$(mutation_score_log go "$W/escape.log" yes)"

# ORDERING: a build break and a timeout in one log must report the build break.
# The timeout is a symptom there, and naming it sends the reader after a hang
# that is not the cause.
cat > "$W/build-and-timeout.log" <<'EOF'
# github.com/psaab/xpf/pkg/natshow
pkg/natshow/source.go:180:5: undefined: armed
FAIL	github.com/psaab/xpf/pkg/natshow [build failed]
panic: test timed out after 10m0s
EOF
ck "a build break outranks a timeout in the same log" 	"no 1 0 VOID(build break)" "$(mutation_score_log go "$W/build-and-timeout.log" yes)"

echo "== the SPLICE (#8213) =="
# Parallel `go test -v` interleaves output MID-LINE. The anchored `^--- FAIL`
# this library used to count misses a spliced marker entirely, and the cell
# scores as an ESCAPE — which reads as "the fix is not bound" and argues for
# weakening the TEST. The damaging direction.
cat > "$W/spliced.log" <<'EOF'
ok  	github.com/psaab/xpf/pkg/cli	6.409s
    frr_test.go:88: waiting for reload--- FAIL: TestSpliced (0.01s)
FAIL	github.com/psaab/xpf/pkg/frr	0.30s
EOF
ck "a SPLICED --- FAIL is still a kill" "yes 2 1 KILLED" 	"$(mutation_score_log go "$W/spliced.log" yes)"

# grep -c counts LINES; two markers can share one spliced line.
cat > "$W/spliced-double.log" <<'EOF'
ok  	github.com/psaab/xpf/pkg/cli	6.409s
  x--- FAIL: TestA (0.01s)  y--- FAIL: TestB (0.02s)
FAIL	github.com/psaab/xpf/pkg/frr	0.30s
EOF
ck "two markers on one spliced line count as two" "yes 2 2 KILLED" 	"$(mutation_score_log go "$W/spliced-double.log" yes)"

# The complement that keeps the loosened pattern honest: prose ABOUT the marker
# must not register. `--- FAIL: ` with colon and space is what distinguishes a
# real marker from a mention.
cat > "$W/prose.log" <<'EOF'
ok  	github.com/psaab/xpf/pkg/cli	6.409s
# a harness that keys on --- FAIL is unsound under parallel -v
ok  	github.com/psaab/xpf/pkg/natshow	0.02s
EOF
ck "prose mentioning the marker without a name is not a failure" "yes 2 0 ESCAPED" 	"$(mutation_score_log go "$W/prose.log" yes)"

echo "== ATTRIBUTION (#8213, the half counting cannot fix) =="
# A spliced kill whose package ALSO has a clean unrelated failure counts >= 1,
# so rc and count AGREE and the cell scores KILLED — for the wrong test.
ck "a kill naming the intended test is a real kill" "KILLED" 	"$(mutation_verdict_for_target KILLED TestTarget TestTarget TestOther)"
ck "a kill that does NOT name the target is not a kill" 	"ESCAPED(other tests failed: TestOther)" 	"$(mutation_verdict_for_target KILLED TestTarget TestOther)"
# A VOID must not be refined: an unfinished run has no trustworthy names, and
# refining it would repeat the "score the prefix" error the timeout ordering
# exists to prevent.
ck "a VOID verdict is not refined by names" "VOID(build break)" 	"$(mutation_verdict_for_target 'VOID(build break)' TestTarget TestOther)"

echo "== ANCHORING (#8213): every anchor variant fails somewhere =="
# THE FIXTURE IS THE POINT. Three real failing tests in three different
# shapes, including the spliced line captured verbatim from the #8000 matrix
# (note the truncated `TestR` fragment — two goroutines writing at once).
# A hand-written fixture with three tidy top-level lines cannot reproduce
# this and would score every pattern below identically.
cat > "$W/anchor.log" <<'EOF'
ok  	github.com/psaab/xpf/pkg/cli	6.409s
--- FAIL: TestTopLevel (0.01s)
    --- FAIL: TestParent/subtest (0.00s)
        barrier_test.go:171: took 300ms: the singular path left the barrier armed --- FAIL: TestR--- FAIL: TestRemoteFailoverDisarmsSupersededBarrier8000 (0.60s)
FAIL	github.com/psaab/xpf/pkg/cluster	1.2s
EOF

# The two anchors fail in OPPOSITE directions. Pinning both is what stops a
# future "fix" from tightening one and silently reopening the other.
ck "^--- FAIL misses the indented subtest AND the splice" \
	"1" "$(grep -cE '^--- FAIL' "$W/anchor.log")"
ck "^\\s+--- FAIL misses the TOP-LEVEL line (it has no leading whitespace)" \
	"1" "$(grep -cE '^\s+--- FAIL' "$W/anchor.log")"
ck "^\\s*--- FAIL catches both of those and still misses the splice" \
	"2" "$(grep -cE '^\s*--- FAIL' "$W/anchor.log")"

# The landed mitigation. Sound for the VERDICT because the decision is only
# "was anything named" — 3 real failures, and the count is >= 1 either way.
# FOUR, not three: the spliced line carries TWO markers (the truncated
# `TestR` fragment and the real name), so the count OVER-reports by one.
# That is the correct trade and it is why the counter is only used for the
# verdict — over-counting cannot turn a kill into an escape, while the
# anchored under-count could and did.
ck "the production unanchored counter sees every failure (and over-counts the splice)" \
	"4" "$(mutation_go_failed "$W/anchor.log")"
ck "the spliced log scores as a KILL, not an escape" \
	"yes 2 4 KILLED" "$(mutation_score_log go "$W/anchor.log" yes)"

# NEGATIVE CONTROL. Without this, a counter that returned a constant >= 1
# would satisfy every positive check above. A genuinely un-killed mutation
# must still score ESCAPED.
cat > "$W/anchor-clean.log" <<'EOF'
ok  	github.com/psaab/xpf/pkg/cli	6.409s
ok  	github.com/psaab/xpf/pkg/cluster	1.2s
EOF
ck "NEGATIVE CONTROL: a run with no failures still scores ESCAPED" \
	"yes 2 0 ESCAPED" "$(mutation_score_log go "$W/anchor-clean.log" yes)"

# ATTRIBUTION is where the unanchored count stops being enough: the splice
# yields a PHANTOM name from the truncated `TestR` fragment. Anything
# reporting WHICH test killed a mutant must use the -json path instead.
ck "the unanchored scan invents a phantom name from the truncated fragment" \
	"1" "$(grep -oE -- 'TestR--- FAIL' "$W/anchor.log" | grep -c . || true)"

# Rust is NOT exposed: libtest holds the stdout lock per result line, so its
# anchor is sound. Measured on a full parallel run of 5217 tests — zero
# markers off column 0. Pinned so nobody "fixes" it by symmetry with Go.
cat > "$W/rust-parallel.log" <<'EOF'
test afxdp::ha::tests::alpha ... ok
test afxdp::ha::tests::beta ... FAILED
test afxdp::ha::tests::gamma ... ok
EOF
ck "the Rust anchor still counts collection under parallelism" \
	"3" "$(mutation_rust_collected "$W/rust-parallel.log")"
ck "the Rust anchor still counts the failure under parallelism" \
	"1" "$(mutation_rust_failed "$W/rust-parallel.log")"

# ---------------------------------------------------------------------------
# #9158 pre-flight: refuse to mutate a target that has uncommitted changes.
#
# TWO DIRECTIONS, because a guard that only ever fires proves nothing and a
# guard that never fires proves less. The middle row is the one that makes the
# pair meaningful: identical predicate, identical caller, and the ONLY
# difference is whether the target was dirty.
#
# Fixture text rather than a repo, so this stays hermetic.
# ---------------------------------------------------------------------------
echo "== pre-flight dirty-target refusal (#9158) =="

ck "a clean target set returns 0" "0" \
	"$(mutation_dirty_targets "" >/dev/null 2>&1; echo $?)"
ck "a clean target set prints nothing" "" \
	"$(mutation_dirty_targets "" 2>/dev/null)"

ck "a MODIFIED target returns 1" "1" \
	"$(mutation_dirty_targets " M userspace-dp/src/nat/allocator.rs" >/dev/null 2>&1; echo $?)"
ck "and names the file it refused on" " M userspace-dp/src/nat/allocator.rs" \
	"$(mutation_dirty_targets " M userspace-dp/src/nat/allocator.rs" 2>/dev/null)"

# STAGED-but-uncommitted is dirty too: `git diff --quiet` (the applied-check
# this guard protects) compares against HEAD, so a staged change defeats it
# exactly as an unstaged one does.
ck "a STAGED target is dirty too" "1" \
	"$(mutation_dirty_targets "M  pkg/api/metrics.go" >/dev/null 2>&1; echo $?)"

# Whitespace-only output is what `git status --porcelain` yields for a clean
# tree through a shell that appends a newline. It must NOT read as dirty --
# that would refuse every clean run and make the guard useless.
ck "a blank line is not dirty" "0" \
	"$(mutation_dirty_targets "
" >/dev/null 2>&1; echo $?)"

ck "two dirty targets are both reported" "2" \
	"$(mutation_dirty_targets " M a.go
 M b.rs" 2>/dev/null | wc -l | tr -d ' ')"

echo
if [ "$fails" -eq 0 ]; then
	echo "mutate-selftest: all checks passed"
else
	echo "mutate-selftest: $fails check(s) FAILED"
	exit 1
fi
