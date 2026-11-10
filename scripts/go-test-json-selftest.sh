#!/usr/bin/env bash
# Self-test for the #8231 machine-readable gate side channel.
#
# The defect this mechanism exists for is a FALSE CLAIM OF COVERAGE: when a
# cell's target test did not fail but ANOTHER test in the package did, the
# count-based verdict is KILLED with rc and count in agreement and nothing
# looking wrong. Only a NAME refutes it, and case 5 below is that case — it is
# the one that fails if the attribution is removed.
#
# Hermetic: no cluster, no network. The go legs use a throwaway module.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$here/mutate-lib.sh"

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL %s\n' "$1"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: want [$3] got [$2]"; fi; }

WORK=$(mkdir -p /var/worktrees/.cache/tmpdir && TMPDIR=/var/worktrees/.cache/tmpdir mktemp -d); trap 'rm -rf "$WORK"' EXIT

# A throwaway module with one PASSING and one FAILING test, so a run has a
# failing name that is NOT the target — the shape case 5 needs.
mkdir -p "$WORK/m"
cat > "$WORK/m/go.mod" <<'EOF'
module mutsel

go 1.21
EOF
cat > "$WORK/m/a_test.go" <<'EOF'
package mutsel

import "testing"

func TestTargetOfTheCell(t *testing.T) {}
func TestSomethingElseAlreadyRed(t *testing.T) { t.Fatal("pre-existing red") }
EOF

# ── 1. empty json arg: byte-identical stdout and exit code to a direct run ──
plain_out=$(cd "$WORK/m" && GOFLAGS="${GOFLAGS:+$GOFLAGS }-json=false" go test ./... 2>&1); plain_rc=$?
wrap_out=$(cd "$WORK/m" && bash "$here/go-test-json.sh" "" go ./... 2>&1); wrap_rc=$?
# Durations vary run to run, so compare the shape rather than the bytes.
norm() { sed -E 's/[0-9]+\.[0-9]+s/DUR/g; s/\(cached\)/DUR/g'; }
check "default path: stdout matches a direct go test" \
	"$(printf '%s' "$wrap_out" | norm)" "$(printf '%s' "$plain_out" | norm)"
check "default path: exit code matches a direct go test" "$wrap_rc" "$plain_rc"

# ── 2. with a side file: stdout still human-readable, events land ──
J="$WORK/events.json"
side_out=$(cd "$WORK/m" && bash "$here/go-test-json.sh" "$J" go ./... 2>&1); side_rc=$?
check "side-file path: exit code still reports the failure" "$side_rc" "$plain_rc"
if printf '%s' "$side_out" | grep -q -- '--- FAIL: TestSomethingElseAlreadyRed'; then
	ok "side-file path: stdout is still the human-readable stream"
else
	bad "side-file path: stdout is not human-readable: $side_out"
fi
if [ -s "$J" ] && head -1 "$J" | jq -e . >/dev/null 2>&1; then
	ok "side-file path: the side file holds JSON events"
else
	bad "side-file path: the side file is empty or not JSON"
fi

# ── 3. the names come back, and ONLY the failing one ──
names=$(mutation_go_failed_names_json "$J" | tr '\n' ',' | sed 's/,$//')
check "attribution: only the failing test is named" "$names" "TestSomethingElseAlreadyRed"

# ── 4. refusal when the stream cannot be produced ──
# An empty PATH for jq only: a caller that asked for attribution must not
# silently receive a stream it cannot attribute over.
# A shim directory holding every tool the script needs EXCEPT jq, so the run
# fails for the reason under test and not because the whole PATH is gone. The
# first version of this case used PATH=/nonexistent and asserted only a non-zero
# exit — which a deletion of the jq check still satisfied, because the command
# then failed for an unrelated reason. It scored a mutation as killed while
# measuring nothing.
shim="$WORK/shim"; mkdir -p "$shim"
for t in go tee cat env bash sed grep; do
	p=$(command -v "$t" 2>/dev/null) && ln -sf "$p" "$shim/$t"
done
nojq=$(cd "$WORK/m" && PATH="$shim" bash "$here/go-test-json.sh" "$WORK/x.json" go ./... 2>&1); nojq_rc=$?
if [ "$nojq_rc" -ne 0 ] && printf '%s' "$nojq" | grep -q 'jq is not installed'; then
	ok "refusal: no jq is a NAMED error, not a silent fallback"
else
	bad "refusal: want the jq refusal message, got rc=$nojq_rc [$nojq]"
fi
if [ -s "$WORK/x.json" ]; then
	bad "refusal: it wrote a side file anyway — a caller would attribute over it"
else
	ok "refusal: no side file was left for a caller to attribute over"
fi

# ── 5. THE CASE. A cell whose target did NOT fail, in a package where another
# test is red. Count-based says KILLED; name-based must say ESCAPED. ──
printf '%s\n' "$side_out" > "$WORK/countlog"
count_failed=$(mutation_go_failed "$WORK/countlog")
count_verdict=$(mutation_verdict yes yes 2 "$count_failed" no no)
check "count-based verdict on the confounded run" "$count_verdict" "KILLED"

# shellcheck disable=SC2046  # deliberate splitting: names are separate args
named_verdict=$(mutation_verdict_for_target "$count_verdict" TestTargetOfTheCell \
	$(mutation_go_failed_names_json "$J"))
case "$named_verdict" in
ESCAPED*) ok "name-based verdict REFUTES the count-based KILLED" ;;
*) bad "name-based verdict did not refute a false KILLED: got [$named_verdict]" ;;
esac

# ── 6. control: when the target DID fail, the name-based verdict agrees ──
# Without this, an attribution that returned ESCAPED unconditionally would
# satisfy case 5 and destroy every real kill.
agree=$(mutation_verdict_for_target KILLED TestSomethingElseAlreadyRed TestSomethingElseAlreadyRed)
check "control: a real kill still scores KILLED" "$agree" "KILLED"

# ── 7. the wrapper APPENDS, and the caller is responsible for truncating ──
# Both facts matter. test-go has two legs that must land in one file, so append
# is required; and a caller that does not truncate between invocations
# attributes over the union of two runs, where a stale name from the previous
# run reads exactly like a current failure. The Makefile truncates once per
# invocation and scripts/mutate.sh truncates once per cell; this pins the
# behaviour they depend on.
T="$WORK/append.json"
( cd "$WORK/m" && bash "$here/go-test-json.sh" "$T" go ./... >/dev/null 2>&1 )
one=$(wc -l <"$T")
( cd "$WORK/m" && bash "$here/go-test-json.sh" "$T" go ./... >/dev/null 2>&1 )
two=$(wc -l <"$T")
if [ "$two" -gt "$one" ]; then
	ok "append: a second run adds to the file rather than replacing it"
else
	bad "append: two runs produced $two lines against $one — the second leg of a multi-leg target would be lost"
fi
: > "$T"
( cd "$WORK/m" && bash "$here/go-test-json.sh" "$T" go ./... >/dev/null 2>&1 )
check "truncation: an explicitly emptied file holds exactly one run" "$(wc -l <"$T")" "$one"

# #18778: a package that hits go test's -timeout aborts mid-run. The wrapper
# must VOID the leg (exit 3, banner on stderr) on BOTH paths, rather than let
# it read as an ordinary failure, and still pass every output line through.
mkdir -p "$WORK/to"
cat > "$WORK/to/go.mod" <<'EOT'
module example.com/to

go 1.21
EOT
cat > "$WORK/to/to_test.go" <<'EOT'
package to

import (
	"testing"
	"time"
)

func TestSlow(t *testing.T) { time.Sleep(30 * time.Second) }
EOT
to_err="$WORK/to.err"
( cd "$WORK/to" && bash "$here/go-test-json.sh" "" go -timeout 2s ./... >"$WORK/to.out" 2>"$to_err" ); to_rc=$?
check "timeout, default path: the leg is VOID (exit 3)" "$to_rc" "3"
if grep -q "VOID: go test hit its -timeout in example.com/to\." "$to_err" && grep -q "panic: test timed out after" "$WORK/to.out"; then
	ok "timeout, default path: VOID banner names the package and the timeout panic passed through"
else
	bad "timeout, default path: missing package-named VOID banner or the passed-through timeout panic"
fi
TJ="$WORK/to.json"; : > "$TJ"
( cd "$WORK/to" && bash "$here/go-test-json.sh" "$TJ" go -timeout 2s ./... >/dev/null 2>"$to_err" ); tj_rc=$?
check "timeout, side-file path: the leg is VOID (exit 3)" "$tj_rc" "3"
# The race legs use go-test-watch.sh (full command line, so the recipe keeps
# its literal `test -race` text); it must VOID the same way.
( cd "$WORK/to" && bash "$here/go-test-watch.sh" go test -timeout 2s ./... >/dev/null 2>"$to_err" ); tw_rc=$?
check "timeout, go-test-watch.sh: the leg is VOID (exit 3)" "$tw_rc" "3"
# FALSE POSITIVES: a failing test whose own output says "timed out" -- an
# unindented "panic: test timed out" line it prints itself, and the same text
# indented through t.Log -- is an ordinary failure, never VOID. A real
# timeout also needs go's alarm frame after the running-test list; the test
# prints cmd/go's kill line (not followed by the package FAIL line) and the
# alarm frame AFTER a non-panic line, so neither full timeout shape pairs.
mkdir -p "$WORK/fp"
cat > "$WORK/fp/go.mod" <<'EOT'
module example.com/fp

go 1.21
EOT
cat > "$WORK/fp/fp_test.go" <<'EOT'
package fp

import (
	"fmt"
	"testing"
)

func TestSaysTimedOut(t *testing.T) {
	fmt.Println("panic: test timed out after 5s")
	fmt.Println("the dial timed out")
	fmt.Println("*** Test killed with quit: ran too long (1m1s).")
	fmt.Println("testing.(*M).startAlarm.func1()")
	t.Log("panic: test timed out after 5s\n\trunning tests:")
	t.Fatal("request timed out")
}
EOT
( cd "$WORK/fp" && bash "$here/go-test-json.sh" "" go -timeout 60s ./... >/dev/null 2>&1 ); fp_rc=$?
if [ "$fp_rc" -ne 3 ] && [ "$fp_rc" -ne 0 ]; then
	ok "false positive: a failing test that prints \"timed out\" is an ordinary failure (rc=$fp_rc), not VOID"
else
	bad "false positive: a failing test that prints \"timed out\" gave rc=$fp_rc (want non-zero, not 3)"
fi
FJ="$WORK/fp.json"; : > "$FJ"
( cd "$WORK/fp" && bash "$here/go-test-json.sh" "$FJ" go -timeout 60s ./... >/dev/null 2>&1 ); fpj_rc=$?
if [ "$fpj_rc" -ne 3 ] && [ "$fpj_rc" -ne 0 ]; then
	ok "false positive, side-file path: ordinary failure (rc=$fpj_rc), not VOID"
else
	bad "false positive, side-file path: rc=$fpj_rc (want non-zero, not 3)"
fi
# #18779 F3 (Kimi): the fp fixture above prints the panic line and the
# "running tests:" text NON-adjacently (its own lines intervene), so
# neither second signal pairs. This fixture prints them ADJACENTLY, the
# exact pair go emits on a real shape-A timeout, and then fails
# normally. Adjacency must not be enough: a real shape A is followed by
# the goroutine dump and ends at the package FAIL line, while this run
# ends at the test's `--- FAIL` line with no dump. It must stay an
# ordinary failure on both paths, never VOID.
mkdir -p "$WORK/fp2"
cat > "$WORK/fp2/go.mod" <<'EOT'
module example.com/fp2

go 1.21
EOT
cat > "$WORK/fp2/fp2_test.go" <<'EOT'
package fp2

import (
	"fmt"
	"testing"
)

func TestPrintsAdjacentTimeout(t *testing.T) {
	fmt.Println("panic: test timed out after 5s")
	fmt.Println("\trunning tests:")
	fmt.Println("\t\tTestPrintsAdjacentTimeout (5s)")
	t.Fatal("request timed out")
}
EOT
( cd "$WORK/fp2" && bash "$here/go-test-json.sh" "" go -timeout 60s ./... >/dev/null 2>&1 ); fp2_rc=$?
if [ "$fp2_rc" -ne 3 ] && [ "$fp2_rc" -ne 0 ]; then
	ok "false positive: a test printing the panic line and running tests: adjacently is an ordinary failure (rc=$fp2_rc), not VOID"
else
	bad "false positive: adjacent panic+running-tests print gave rc=$fp2_rc (want non-zero, not 3)"
fi
FJ2="$WORK/fp2.json"; : > "$FJ2"
( cd "$WORK/fp2" && bash "$here/go-test-json.sh" "$FJ2" go -timeout 60s ./... >/dev/null 2>&1 ); fp2j_rc=$?
if [ "$fp2j_rc" -ne 3 ] && [ "$fp2j_rc" -ne 0 ]; then
	ok "false positive, side-file path: adjacent panic+running-tests print is an ordinary failure (rc=$fp2j_rc), not VOID"
else
	bad "false positive, side-file path: adjacent panic+running-tests print gave rc=$fp2j_rc (want non-zero, not 3)"
fi
# #18779 F2 (Sol+Kimi): an inherited GOFLAGS=-json must not change what
# these wrappers run. The default path asks for TEXT (a -json stream fed
# to the text watcher is never a real timeout shape, so a timed-out leg
# reads as an ordinary failure); the side-file path asks for -json (a
# text stream fed to jq is not events). Measured pre-fix: 21/29 under
# GOFLAGS=-json. The timeout fixture under an inherited -json pins it.
( cd "$WORK/to" && GOFLAGS=-json bash "$here/go-test-json.sh" "" go -timeout 2s ./... >/dev/null 2>"$to_err" ); gf_rc=$?
check "inherited GOFLAGS=-json, default path: a timeout is still VOID (exit 3)" "$gf_rc" "3"
TJ2="$WORK/to2.json"; : > "$TJ2"
( cd "$WORK/to" && GOFLAGS=-json bash "$here/go-test-json.sh" "$TJ2" go -timeout 2s ./... >/dev/null 2>"$to_err" ); gfj_rc=$?
check "inherited GOFLAGS=-json, side-file path: a timeout is still VOID (exit 3)" "$gfj_rc" "3"
[ "$gfj_rc" = 3 ] || echo "    stderr: $(tr '\n' ' ' < "$to_err" | cut -c1-900)"
( cd "$WORK/to" && GOFLAGS=-json bash "$here/go-test-watch.sh" go test -timeout 2s ./... >/dev/null 2>"$to_err" ); gft_rc=$?
check "inherited GOFLAGS=-json, go-test-watch.sh: a timeout is still VOID (exit 3)" "$gft_rc" "3"
# #18778 seat AC: three timeouts the first watcher missed.
# (1) -json interleaves packages LINE BY LINE (measured: 582 package switches
# in a two-package run), so on the reconstructed human stream the line after
# a panic is often ANOTHER package's. A fake go replays a canned interleaved
# stream, deterministically: pkg a's panic, then a pkg b line, then a's
# "running tests:". Only a per-package check sees it, and the banner must
# name a alone -- b finished.
mkdir -p "$WORK/fakego"
cat > "$WORK/fakego/go" <<'EOT'
#!/bin/sh
for l in \
 '{"Action":"output","Package":"example.com/a","Output":"=== RUN   TestHang\n"}' \
 '{"Action":"output","Package":"example.com/b","Output":"=== RUN   TestB\n"}' \
 '{"Action":"output","Package":"example.com/a","Output":"panic: test timed out after 2s\n"}' \
 '{"Action":"output","Package":"example.com/b","Output":"    b_test.go:9: chatter\n"}' \
 '{"Action":"output","Package":"example.com/a","Output":"\trunning tests:\n"}' \
 '{"Action":"output","Package":"example.com/a","Output":"\t\tTestHang (2s)\n"}' \
 '{"Action":"output","Package":"example.com/b","Output":"--- PASS: TestB (0.01s)\n"}' \
 '{"Action":"output","Package":"example.com/a","Output":"\n"}' \
 '{"Action":"output","Package":"example.com/a","Output":"goroutine 17 [running]:\n"}' \
 '{"Action":"output","Package":"example.com/a","Output":"testing.(*M).startAlarm.func1()\n"}' \
 '{"Action":"output","Package":"example.com/b","Output":"ok  \texample.com/b\t0.02s\n"}' \
 '{"Action":"output","Package":"example.com/a","Output":"FAIL\texample.com/a\t2.01s\n"}' \
 '{"Action":"fail","Package":"example.com/a","Elapsed":2.01}'; do
	printf '%s\n' "$l"
done
exit 1
EOT
chmod +x "$WORK/fakego/go"
IJ="$WORK/interleave.json"; : > "$IJ"
bash "$here/go-test-json.sh" "$IJ" "$WORK/fakego/go" ./... >"$WORK/il.log" 2>&1; il_rc=$?
check "timeout, interleaved -json stream: the leg is VOID (exit 3)" "$il_rc" "3"
if grep -q "VOID: go test hit its -timeout in example.com/a\." "$WORK/il.log"; then
	ok "timeout, interleaved -json stream: the banner names the timed-out package and not the one that passed"
else
	bad "timeout, interleaved -json stream: banner wrong: $(head -1 "$WORK/il.log")"
fi
# This is the exact combined wrapper output the mutation driver receives
# after `make test-go` normalizes wrapper exit 3 to make's rc=2. The banner
# remains authoritative even though the output stream itself was interleaved.
check "mutation scorer treats the interleaved wrapper-VOID log as VOID" \
	"yes 2 0 VOID(run did not finish: timeout)" \
	"$(mutation_score_log go "$WORK/il.log" yes)"
# The side file is APPENDED to, so an earlier leg's timeout must not void a
# later clean leg: replay a passing stream into the same file.
cat > "$WORK/fakego/go" <<'EOT'
#!/bin/sh
printf '%s\n' '{"Action":"output","Package":"example.com/c","Output":"ok  \texample.com/c\t0.01s\n"}' '{"Action":"pass","Package":"example.com/c"}'
EOT
bash "$here/go-test-json.sh" "$IJ" "$WORK/fakego/go" ./... >/dev/null 2>&1; ap_rc=$?
check "side file: a clean leg appended after a timed-out leg is not voided" "$ap_rc" "0"

# (2) a hung Example: the alarm fires with NO test in the running list, so
# there is no "running tests:" line -- a blank line and the goroutine dump
# follow the panic. The alarm's own frame is the second signal.
mkdir -p "$WORK/ex"
printf 'module example.com/ex\n\ngo 1.21\n' > "$WORK/ex/go.mod"
cat > "$WORK/ex/ex_test.go" <<'EOT'
package ex

import (
	"fmt"
	"time"
)

func Example() {
	time.Sleep(30 * time.Second)
	fmt.Println("x")
	// Output: x
}
EOT
( cd "$WORK/ex" && bash "$here/go-test-json.sh" "" go -timeout 2s ./... >/dev/null 2>"$WORK/ex.err" ); ex_rc=$?
check "timeout, hung Example (no running tests): the leg is VOID (exit 3)" "$ex_rc" "3"
grep -q "example.com/ex: alarm fired with no test running" "$WORK/ex.err" &&
	ok "timeout, hung Example: the banner names the package and the shape" ||
	bad "timeout, hung Example: banner wrong: $(cat "$WORK/ex.err" | head -2)"
EJ="$WORK/ex.json"; : > "$EJ"
( cd "$WORK/ex" && bash "$here/go-test-json.sh" "$EJ" go -timeout 2s ./... >/dev/null 2>&1 ); exj_rc=$?
check "timeout, hung Example, side-file path: the leg is VOID (exit 3)" "$exj_rc" "3"

# (3) a hung TestMain: the alarm is armed inside m.Run, so it never fires;
# cmd/go kills the binary at -timeout + 1m. Its SIGQUIT dump starts
# `SIGQUIT: quit`, `PC=`, then a goroutine header before the kill marker and
# package FAIL. This row costs about 62 s, so both paths run concurrently.
mkdir -p "$WORK/tm"
printf 'module example.com/tm\n\ngo 1.21\n' > "$WORK/tm/go.mod"
cat > "$WORK/tm/tm_test.go" <<'EOT'
package tm

import (
	"testing"
	"time"
)

func TestMain(m *testing.M) { time.Sleep(time.Hour); m.Run() }

func TestX(t *testing.T) {}
EOT
TMJ="$WORK/tm.json"; : > "$TMJ"
( cd "$WORK/tm" && bash "$here/go-test-json.sh" "" go -timeout 1s ./... >/dev/null 2>"$WORK/tm.err"; echo $? > "$WORK/tm.rc" ) &
( cd "$WORK/tm" && bash "$here/go-test-json.sh" "$TMJ" go -timeout 1s ./... >/dev/null 2>&1; echo $? > "$WORK/tmj.rc" ) &
wait
check "timeout, hung TestMain (killed at -timeout + 1m): the leg is VOID (exit 3)" "$(cat "$WORK/tm.rc")" "3"
check "timeout, hung TestMain, side-file path: the leg is VOID (exit 3)" "$(cat "$WORK/tmj.rc")" "3"
grep -q "example.com/tm: binary killed by go test" "$WORK/tm.err" &&
	ok "timeout, hung TestMain: the banner names the package and the shape" ||
	bad "timeout, hung TestMain: banner wrong: $(head -2 "$WORK/tm.err")"

# A test can print cmd/go's shape-C kill marker and exit 1 without timing out.
# Marker+package FAIL alone are therefore insufficient; a real shape C first
# contains the SIGQUIT stack dump. Keep the printed marker an ordinary failure
# on both text and side-file paths.
mkdir -p "$WORK/fp3"
printf 'module example.com/fp3\n\ngo 1.21\n' > "$WORK/fp3/go.mod"
cat > "$WORK/fp3/fp3_test.go" <<'EOT'
package fp3

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	fmt.Println("*** Test killed with quit: ran too long (1m1s).")
	os.Exit(1)
}

func TestX(t *testing.T) {}
EOT
( cd "$WORK/fp3" && bash "$here/go-test-json.sh" "" go -timeout 60s ./... >/dev/null 2>&1 ); fp3_rc=$?
check "false positive: TestMain printing the cmd/go kill marker stays an ordinary failure (exit 1)" "$fp3_rc" "1"
FP3J="$WORK/fp3.json"; : > "$FP3J"
( cd "$WORK/fp3" && bash "$here/go-test-json.sh" "$FP3J" go -timeout 60s ./... >/dev/null 2>&1 ); fp3j_rc=$?
check "false positive, side-file path: TestMain printing the cmd/go kill marker stays an ordinary failure (exit 1)" "$fp3j_rc" "1"
# Control: a fast package under the same flag must NOT be voided.
( cd "$WORK/m" && bash "$here/go-test-json.sh" "" go -timeout 60s ./... >/dev/null 2>&1 ); ctl_rc=$?
if [ "$ctl_rc" -ne 3 ]; then
	ok "timeout control: a package that finishes within -timeout is not voided (rc=$ctl_rc)"
else
	bad "timeout control: a package that finished in time was voided"
fi

# ── #19066 R18: a production-state change FAILS (1), it is not VOID (3) ──
# testguard-run.sh fails a run that changed a production state path. Its
# status must survive go-test-json.sh and go-test-watch.sh as a FAIL: 3 is
# VOID there (a go-test timeout), which would read a host mutation as
# "undetermined". The state path is a temp dir added through
# XPF_RESIDUE_EXTRA_STATE_PATHS (which can only add paths), and the "go" is a
# stand-in that passes and then writes, rewrites in place or deletes a file
# in it. The clean stand-in is the control: same harness, no state change.
SW=$(mktemp -d "${TMPDIR:-/tmp}/gtj-state.XXXXXX")
mkdir -p "$SW/state"; printf 'seed\n' > "$SW/state/xpf.sources"
mk_fakego() { # $1 name, $2 shell action on "$SW/state"
	cat > "$SW/$1" <<EOT
#!/bin/sh
$2
echo "ok  	fake	0.001s"
exit 0
EOT
	chmod +x "$SW/$1"
}
mk_fakego clean ':'
mk_fakego writes "printf 'new\\n' > '$SW/state/xpf.conf'"
mk_fakego deletes "rm -f '$SW/state/xpf.sources'"
mk_fakego rewrites "cp -p '$SW/state/xpf.sources' '$SW/ref'; printf 'SEED\\n' > '$SW/state/xpf.sources'; touch -r '$SW/ref' '$SW/state/xpf.sources'"
# behindlink: the state tree holds a symlink to a directory elsewhere, and the
# change (same size, mtime restored) is inside that directory.
mkdir -p "$SW/real"; ln -s "$SW/real" "$SW/state/linked"
mk_fakego behindlink "cp -p '$SW/real/f' '$SW/ref'; printf 'SEED\\n' > '$SW/real/f'; touch -r '$SW/ref' '$SW/real/f'"
# #19090 R3: the side-file path too. Its stdout IS the go test -json event
# stream, so a harness report printed to stdout corrupted the side file and
# turned the verdict into a stream error (2). The JSON stand-ins pass with a
# valid event stream and make the same state changes; the leg must exit 1,
# leave a side file that parses as JSON, and carry the FAIL on stderr.
mk_fakejson() { # $1 name, $2 shell action on "$SW/state"
	cat > "$SW/$1" <<EOT
#!/bin/sh
$2
printf '%s\\n' '{"Action":"output","Package":"example.com/fake","Output":"ok  \\texample.com/fake\\t0.001s\\n"}' '{"Action":"pass","Package":"example.com/fake","Elapsed":0.001}'
exit 0
EOT
	chmod +x "$SW/$1"
}
mk_fakejson jclean ':'
mk_fakejson jwrites "printf 'new\\n' > '$SW/state/xpf.conf'"
mk_fakejson jdeletes "rm -f '$SW/state/xpf.sources'"
mk_fakejson jrewrites "cp -p '$SW/state/xpf.sources' '$SW/ref'; printf 'SEED\\n' > '$SW/state/xpf.sources'; touch -r '$SW/ref' '$SW/state/xpf.sources'"
mk_fakejson jbehindlink "cp -p '$SW/real/f' '$SW/ref'; printf 'SEED\\n' > '$SW/real/f'; touch -r '$SW/ref' '$SW/real/f'"
reseed() {
	printf 'seed\n' > "$SW/real/f"; touch -d @1700000000 "$SW/real/f"
	printf 'seed\n' > "$SW/state/xpf.sources"; rm -f "$SW/state/xpf.conf"
}
for case in clean writes deletes rewrites behindlink; do
	reseed
	out=$(XPF_RESIDUE_EXTRA_STATE_PATHS="$SW/state" bash "$here/go-test-json.sh" "" "$SW/$case" ./... 2>&1); rc=$?
	reseed
	wout=$(XPF_RESIDUE_EXTRA_STATE_PATHS="$SW/state" bash "$here/go-test-watch.sh" "$SW/$case" test ./... 2>&1); wrc=$?
	reseed
	sj="$SW/$case.json"; : > "$sj"
	jout=$(XPF_RESIDUE_EXTRA_STATE_PATHS="$SW/state" bash "$here/go-test-json.sh" "$sj" "$SW/j$case" ./... 2>"$SW/jerr"); jrc=$?
	jerr=$(cat "$SW/jerr")
	if jq -e -s 'length > 0' "$sj" >/dev/null 2>&1; then jparse=ok; else jparse=bad; fi
	if [ "$case" = clean ]; then
		check "state control: a passing run that changes no state path exits 0 (go-test-json)" "$rc" "0"
		check "state control: a passing run that changes no state path exits 0 (go-test-watch)" "$wrc" "0"
		check "state control: a passing run that changes no state path exits 0 (go-test-json side file)" "$jrc" "0"
		check "state control: the side file parses as JSON (go-test-json side file)" "$jparse" "ok"
		continue
	fi
	check "state $case: go-test-json exits 1 (FAIL, not VOID 3)" "$rc" "1"
	check "state $case: go-test-watch exits 1 (FAIL, not VOID 3)" "$wrc" "1"
	case "$out" in *"changed production state paths"*) ok "state $case: the FAIL names the production state change";;
		*) bad "state $case: no production-state FAIL message in: $out";; esac
	# #19090 R3: the watch wrapper's own output must carry the cause too, or
	# an unrelated exit 1 would satisfy the row above.
	case "$wout" in *"changed production state paths"*) ok "state $case: go-test-watch names the production state change";;
		*) bad "state $case: go-test-watch has no production-state FAIL message in: $wout";; esac
	check "state $case: go-test-json side-file path exits 1 (FAIL, not a stream error 2)" "$jrc" "1"
	check "state $case: the side file still parses as JSON" "$jparse" "ok"
	case "$jerr" in *"changed production state paths"*) ok "state $case: side-file path carries the FAIL on stderr";;
		*) bad "state $case: side-file path has no production-state FAIL on stderr: $jerr";; esac
	case "$jout$(cat "$sj")" in *"HOST RESIDUE DIFFERENCE"*|*"testguard-run:"*) bad "state $case: a harness diagnostic reached stdout or the side file";;
		*) ok "state $case: no harness diagnostic on stdout or in the side file";; esac
done

# ── #19090 R13-a: a timeout that ALSO changed state is a FAIL (1), not VOID ──
# The wrappers give a go-test timeout VOID (3). A leg that timed out after
# changing production state used to read "undetermined", and a rerun comes
# back clean because the files are already gone. The test removes a watched
# file, then hangs past -timeout; every wrapper path must exit 1 and say why.
# The plain timeout module above (no state change) is the control: still 3.
mkdir -p "$WORK/tos"
cat > "$WORK/tos/go.mod" <<'EOT'
module example.com/tos

go 1.21
EOT
cat > "$WORK/tos/tos_test.go" <<'EOT'
package tos

import (
	"os"
	"testing"
	"time"
)

func TestSlowAfterAStateWrite(t *testing.T) {
	_ = os.Remove(os.Getenv("TG19090_STATE_FILE"))
	time.Sleep(30 * time.Second)
}
EOT
for leg in default side watch; do
	reseed
	TSJ="$SW/tos-$leg.json"; : > "$TSJ"
	case $leg in
	default) ( cd "$WORK/tos" && XPF_RESIDUE_EXTRA_STATE_PATHS="$SW/state" TG19090_STATE_FILE="$SW/state/xpf.sources" bash "$here/go-test-json.sh" "" go -timeout 2s ./... >/dev/null 2>"$SW/tos.err" ); trc=$? ;;
	side) ( cd "$WORK/tos" && XPF_RESIDUE_EXTRA_STATE_PATHS="$SW/state" TG19090_STATE_FILE="$SW/state/xpf.sources" bash "$here/go-test-json.sh" "$TSJ" go -timeout 2s ./... >/dev/null 2>"$SW/tos.err" ); trc=$? ;;
	watch) ( cd "$WORK/tos" && XPF_RESIDUE_EXTRA_STATE_PATHS="$SW/state" TG19090_STATE_FILE="$SW/state/xpf.sources" bash "$here/go-test-watch.sh" go test -timeout 2s ./... >/dev/null 2>"$SW/tos.err" ); trc=$? ;;
	esac
	check "timeout + state change, $leg: the leg is a FAIL (exit 1), not VOID (3)" "$trc" "1"
	if grep -q "timed out AND changed production state" "$SW/tos.err" && grep -q "VOID: go test hit its -timeout in example.com/tos\." "$SW/tos.err"; then
		ok "timeout + state change, $leg: stderr names both the timeout and the state change"
	else
		bad "timeout + state change, $leg: stderr lacks the timeout banner or the state FAIL: $(tr '\n' ' ' < "$SW/tos.err" | cut -c1-400)"
	fi
done

# ── #19090 (Codex on 37c57fe8ac): the state verdict FAILS CLOSED ──────────
# testguard-run.sh appends exactly one completed verdict per run, through a
# descriptor the command does not inherit; every reader reads only an
# explicit clean (or not-run) as clean.
. "$here/testguard-state-verdict.sh"
VD=$(mktemp -d "${TMPDIR:-/tmp}/gtj-verdict.XXXXXX")
vrow() { # $1 label, $2 want, $3 content (printf %b) or @absent / @dir
	rm -rf "$VD/v"
	case $3 in
	@absent) ;;
	@dir) mkdir "$VD/v" ;;
	*) printf '%b' "$3" > "$VD/v" ;;
	esac
	check "verdict reader: $1" "$(testguard_state_verdict "$VD/v")" "$2"
}
vrow "no file is incomplete" incomplete @absent
vrow "an empty file is incomplete" incomplete ''
vrow "an unreadable verdict (a directory) is incomplete" incomplete @dir
vrow "clean" clean 'clean\n'
vrow "not-run reads as clean" clean 'not-run\n'
vrow "two clean runs" clean 'clean\nclean\n'
vrow "clean without a final newline" clean 'clean'
vrow "state-changed" state-changed 'state-changed\n'
vrow "state-changed beside clean" state-changed 'clean\nstate-changed\n'
vrow "interrupted is incomplete" incomplete 'interrupted\n'
vrow "interrupted beside clean is incomplete" incomplete 'clean\ninterrupted\n'
vrow "an unknown line is incomplete" incomplete 'CLEAN\n'

# What testguard-run.sh records.
: > "$VD/run"
XPF_TESTGUARD_STATE_VERDICT="$VD/run" bash "$here/testguard-run.sh" true >/dev/null 2>&1; r=$?
check "testguard-run: a clean run exits 0" "$r" 0
check "testguard-run: a clean run records clean" "$(cat "$VD/run")" clean
reseed; : > "$VD/run"
XPF_RESIDUE_EXTRA_STATE_PATHS="$SW/state" XPF_TESTGUARD_STATE_VERDICT="$VD/run" bash "$here/testguard-run.sh" "$SW/deletes" >/dev/null 2>&1; r=$?
check "testguard-run: a state change exits 1" "$r" 1
check "testguard-run: a state change records state-changed" "$(cat "$VD/run")" state-changed
mkdir -p "$VD/badid"; printf '#!/bin/sh\nexit 1\n' > "$VD/badid/id"; chmod +x "$VD/badid/id"
: > "$VD/run"
PATH="$VD/badid:$PATH" XPF_TESTGUARD_STATE_VERDICT="$VD/run" bash "$here/testguard-run.sh" true >/dev/null 2>&1; r=$?
check "testguard-run: a refusal (a failing id) exits 2" "$r" 2
check "testguard-run: a run refused before its command records not-run" "$(cat "$VD/run")" not-run
: > "$VD/run"; rm -f "$VD/started"
XPF_TESTGUARD_STATE_VERDICT="$VD/run" bash "$here/testguard-run.sh" sh -c "touch '$VD/started'; sleep 3" >/dev/null 2>"$VD/int.err" &
tpid=$!
i=0; while [ ! -e "$VD/started" ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done
kill -TERM "$tpid"; wait "$tpid"; r=$?
check "testguard-run: TERM while the command runs exits 143" "$r" 143
check "testguard-run: a run interrupted before its check records interrupted" "$(cat "$VD/run")" interrupted
grep -q "interrupted before the production-state check completed" "$VD/int.err" &&
	ok "testguard-run: an interrupted run says so on stderr" ||
	bad "testguard-run: no interrupted message: $(tr '\n' ' ' < "$VD/int.err" | cut -c1-300)"
# The command neither inherits the verdict descriptor nor diverts the write
# by replacing the pathname (Codex: a /dev/null symlink made the append
# succeed silently into nothing).
: > "$VD/run"; exec {vrfd}<"$VD/run"
XPF_TESTGUARD_STATE_VERDICT="$VD/run" TG_VERDICT_PATH="$VD/run" bash "$here/testguard-run.sh" \
	sh -c 'for f in /proc/self/fd/*; do [ "$(readlink "$f")" = "$TG_VERDICT_PATH" ] && echo LEAK; done; rm -f "$TG_VERDICT_PATH"; ln -s /dev/null "$TG_VERDICT_PATH"' \
	{vrfd}<&- > "$VD/leak.out" 2>&1
check "testguard-run: the command does not inherit the verdict descriptor" "$(grep -c LEAK "$VD/leak.out")" 0
check "testguard-run: a swapped verdict path does not divert the write" "$(testguard_state_verdict "/proc/self/fd/$vrfd")" clean
check "testguard-run: the swapped path itself reads incomplete, never clean" "$(testguard_state_verdict "$VD/run")" incomplete
exec {vrfd}<&-
rm -f "$VD/run"

# The wrappers on the timeout path: an interrupted check and a swapped path.
mkdir -p "$WORK/tos2"
cat > "$WORK/tos2/go.mod" <<'EOT'
module example.com/tos2

go 1.21
EOT
cat > "$WORK/tos2/tos2_test.go" <<'EOT'
package tos2

import (
	"os"
	"testing"
	"time"
)

func TestInterruptedLeg19090(t *testing.T) {
	if f := os.Getenv("TG19090_STARTED"); f != "" {
		_ = os.WriteFile(f, nil, 0o644)
	}
	time.Sleep(30 * time.Second)
}

func TestSwapsTheVerdictPath19090(t *testing.T) {
	_ = os.Remove(os.Getenv("TG19090_STATE_FILE"))
	if p := os.Getenv("TG19090_VERDICT_PATH"); p != "" {
		_ = os.Remove(p)
		_ = os.Symlink("/dev/null", p)
	}
	time.Sleep(30 * time.Second)
}
EOT
for leg in default watch; do
	rm -f "$SW/started"
	case $leg in
	default) ( cd "$WORK/tos2" && TG19090_STARTED="$SW/started" bash "$here/go-test-json.sh" "" go -timeout 6s -run '^TestInterruptedLeg19090$' ./... >/dev/null 2>"$SW/int.err" ) & ;;
	watch) ( cd "$WORK/tos2" && TG19090_STARTED="$SW/started" bash "$here/go-test-watch.sh" go test -timeout 6s -run '^TestInterruptedLeg19090$' ./... >/dev/null 2>"$SW/int.err" ) & ;;
	esac
	lpid=$!
	i=0; while [ ! -e "$SW/started" ] && kill -0 "$lpid" 2>/dev/null && [ $i -lt 1200 ]; do sleep 0.1; i=$((i+1)); done
	tg=$(pgrep -o -f 'testguard-run\.sh .*TestInterruptedLeg19090')
	if [ -z "$tg" ]; then
		bad "interrupted timeout leg, $leg: FIXTURE: no testguard-run process to interrupt"
		wait "$lpid"
		continue
	fi
	kill -TERM "$tg"
	wait "$lpid"; irc=$?
	check "interrupted timeout leg, $leg: a FAIL (1), not VOID (3)" "$irc" 1
	grep -q "production-state check did not complete" "$SW/int.err" &&
		ok "interrupted timeout leg, $leg: stderr says the check did not complete" ||
		bad "interrupted timeout leg, $leg: no incomplete-check FAIL: $(tr '\n' ' ' < "$SW/int.err" | cut -c1-400)"
done
for leg in default side watch; do
	reseed; : > "$SW/verdict"; : > "$SW/swap.json"
	set -- XPF_TESTGUARD_STATE_VERDICT="$SW/verdict" TG19090_VERDICT_PATH="$SW/verdict" \
		XPF_RESIDUE_EXTRA_STATE_PATHS="$SW/state" TG19090_STATE_FILE="$SW/state/xpf.sources"
	case $leg in
	default) ( cd "$WORK/tos2" && env "$@" bash "$here/go-test-json.sh" "" go -timeout 2s -run '^TestSwapsTheVerdictPath19090$' ./... >/dev/null 2>"$SW/swap.err" ); src=$? ;;
	side) ( cd "$WORK/tos2" && env "$@" bash "$here/go-test-json.sh" "$SW/swap.json" go -timeout 2s -run '^TestSwapsTheVerdictPath19090$' ./... >/dev/null 2>"$SW/swap.err" ); src=$? ;;
	watch) ( cd "$WORK/tos2" && env "$@" bash "$here/go-test-watch.sh" go test -timeout 2s -run '^TestSwapsTheVerdictPath19090$' ./... >/dev/null 2>"$SW/swap.err" ); src=$? ;;
	esac
	set --
	check "swapped verdict path, $leg: timeout + state change is still a FAIL (1)" "$src" 1
	grep -q "timed out AND changed production state" "$SW/swap.err" &&
		ok "swapped verdict path, $leg: the state change is still read (through the descriptor opened first)" ||
		bad "swapped verdict path, $leg: the state change was not read: $(tr '\n' ' ' < "$SW/swap.err" | cut -c1-400)"
	rm -f "$SW/verdict"
done
rm -rf "$VD"
rm -rf "$SW"

# ── #19070 item 3: a signal-killed test binary is NAMED, and stays a FAIL ──
# cmd/go reports a test binary killed by a signal as a column-0
# "signal: <name>" line followed by the package FAIL line. The run must keep
# its ordinary FAIL status (1, not VOID 3) and say which package was
# truncated. The control prints "signal: hangup" inside an indented test log,
# which is not cmd/go's report.
SG=$(mktemp -d "${TMPDIR:-/tmp}/gtj-signal.XXXXXX")
cat > "$SG/killed" <<'EOT'
#!/bin/sh
printf '=== RUN   TestA\n--- PASS: TestA (0.00s)\n=== RUN   TestB\nsignal: hangup\nFAIL\tfake/pkg\t0.012s\n'
exit 1
EOT
cat > "$SG/logged" <<'EOT'
#!/bin/sh
printf '=== RUN   TestA\n    a_test.go:9: child said: signal: hangup\n--- FAIL: TestA (0.00s)\nFAIL\nFAIL\tfake/pkg\t0.012s\n'
exit 1
EOT
chmod +x "$SG/killed" "$SG/logged"
out=$(bash "$here/go-test-json.sh" "" "$SG/killed" ./... 2>&1); rc=$?
check "signal death: go-test-json keeps the ordinary FAIL (exit 1, not VOID 3)" "$rc" "1"
case "$out" in *"go-test TRUNCATED: fake/pkg: the test binary was killed by signal hangup"*) ok "signal death: the truncated package and signal are named";;
	*) bad "signal death: no TRUNCATED banner in: $out";; esac
wout=$(bash "$here/go-test-watch.sh" "$SG/killed" test ./... 2>&1); wrc=$?
check "signal death: go-test-watch keeps the ordinary FAIL (exit 1)" "$wrc" "1"
case "$wout" in *"go-test TRUNCATED: fake/pkg"*) ok "signal death: go-test-watch names it too";;
	*) bad "signal death: go-test-watch printed no TRUNCATED banner: $wout";; esac
# R8 N2 / Codex F1: os/exec names that are not one lower-case word, and a
# death during a partial write ("working...signal: killed").
i=0
for sig in "segmentation fault (core dumped)" "aborted (core dumped)" "user defined signal 1" "CPU time limit exceeded" "trace/breakpoint trap"; do
	i=$((i+1))
	printf '#!/bin/sh\nprintf %s\nexit 1\n' "'=== RUN   TestB\\nsignal: $sig\\nFAIL\\tfake/pkg\\t0.012s\\n'" > "$SG/named$i"
	chmod +x "$SG/named$i"
	out=$(bash "$here/go-test-json.sh" "" "$SG/named$i" ./... 2>&1); rc=$?
	check "signal death \"$sig\": ordinary FAIL (exit 1)" "$rc" "1"
	case "$out" in *"go-test TRUNCATED: fake/pkg: the test binary was killed by signal $sig;"*) ok "signal death \"$sig\": named";;
		*) bad "signal death \"$sig\": no TRUNCATED banner in: $out";; esac
done
cat > "$SG/partial" <<'EOT'
#!/bin/sh
printf '=== RUN   TestB\nworking...signal: killed\nFAIL\tfake/pkg\t0.012s\n'
exit 1
EOT
chmod +x "$SG/partial"
out=$(bash "$here/go-test-json.sh" "" "$SG/partial" ./... 2>&1); rc=$?
case "$out" in *"go-test TRUNCATED: fake/pkg: the test binary was killed by signal killed;"*) ok "signal death after a partial write: named";;
	*) bad "signal death after a partial write: no TRUNCATED banner in: $out";; esac
# Codex F2: the binary reached its own summary ("FAIL") and THEN printed a
# bare "signal: killed" (a TestMain reporting a child's death): not a death.
cat > "$SG/summary" <<'EOT'
#!/bin/sh
printf '=== RUN   TestA\n--- FAIL: TestA (0.00s)\nFAIL\nsignal: killed\nFAIL\tfake/pkg\t0.012s\n'
exit 1
EOT
chmod +x "$SG/summary"
out=$(bash "$here/go-test-json.sh" "" "$SG/summary" ./... 2>&1); rc=$?
check "summary control: an ordinary failing exit stays exit 1" "$rc" "1"
case "$out" in *"TRUNCATED"*) bad "summary control: a binary that reached its summary was named as killed: $out";;
	*) ok "summary control: no TRUNCATED banner once the binary printed its summary";; esac
out=$(bash "$here/go-test-json.sh" "" "$SG/logged" ./... 2>&1); rc=$?
check "signal control: an indented log line is not cmd/go's report (exit 1)" "$rc" "1"
case "$out" in *"TRUNCATED"*) bad "signal control: a logged 'signal: hangup' was read as a death: $out";;
	*) ok "signal control: no TRUNCATED banner for a logged line";; esac
# A REAL signal death, through both paths: a test that SIGKILLs its own
# binary. TestZNeverRuns is after it and must not report.
mkdir -p "$SG/m"
printf 'module sigdeath\n\ngo 1.21\n' > "$SG/m/go.mod"
cat > "$SG/m/s_test.go" <<'EOT'
package sigdeath

import (
	"syscall"
	"testing"
)

func TestA(t *testing.T)              {}
func TestKillsItsOwnBinary(t *testing.T) { fmt.Print("working..."); _ = syscall.Kill(syscall.Getpid(), syscall.SIGKILL) }
func TestZNeverRuns(t *testing.T)     {}
EOT
sed -i 's/^import (/import (\n\t"fmt"/' "$SG/m/s_test.go"
out=$(cd "$SG/m" && bash "$here/go-test-json.sh" "" go -count=1 ./... 2>&1); rc=$?
check "real signal death, text path: ordinary FAIL (exit 1)" "$rc" "1"
case "$out" in *"go-test TRUNCATED: sigdeath: the test binary was killed by signal killed"*) ok "real signal death, text path: named";;
	*) bad "real signal death, text path: no TRUNCATED banner in: $out";; esac
SJ="$SG/s.json"; : > "$SJ"
out=$(cd "$SG/m" && bash "$here/go-test-json.sh" "$SJ" go -count=1 ./... 2>&1); rc=$?
check "real signal death, side-file path: ordinary FAIL (exit 1)" "$rc" "1"
case "$out" in *"go-test TRUNCATED: sigdeath:"*) ok "real signal death, side-file path: named";;
	*) bad "real signal death, side-file path: no TRUNCATED banner in: $out";; esac
if grep -q '"Test":"TestZNeverRuns"' "$SJ"; then bad "real signal death: a test after the death reported"; else ok "real signal death: the test after the death never reported (what the banner warns of)"; fi
# Codex F2 as a REAL module: every test finishes (one fails), then TestMain
# prints a bare "signal: killed" and exits with m.Run's code. Not a death.
mkdir -p "$SG/n"
printf 'module sigsummary\n\ngo 1.21\n' > "$SG/n/go.mod"
cat > "$SG/n/n_test.go" <<'EOT'
package sigsummary

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	code := m.Run()
	fmt.Fprintln(os.Stderr, "signal: killed")
	os.Exit(code)
}

func TestOrdinaryFailure(t *testing.T) { t.Error("ordinary failure") }
EOT
for mode in text json; do
	jf=""; [ "$mode" = json ] && { jf="$SG/n.json"; : > "$jf"; }
	out=$(cd "$SG/n" && bash "$here/go-test-json.sh" "$jf" go -count=1 ./... 2>&1); rc=$?
	check "real summary control, $mode path: ordinary FAIL (exit 1)" "$rc" "1"
	case "$out" in *"TRUNCATED"*) bad "real summary control, $mode path: a completed binary was named as killed: $out";;
		*) ok "real summary control, $mode path: no TRUNCATED banner";; esac
done
rm -rf "$SG"

printf '\ngo-test-json-selftest: passed=%d failed=%d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
