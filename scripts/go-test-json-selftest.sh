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
plain_out=$(cd "$WORK/m" && go test ./... 2>&1); plain_rc=$?
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
# indented through t.Log -- is an ordinary failure, never VOID. go's real
# timeout panic is column-0 AND followed by its "running tests:" line. The
# test also prints cmd/go's kill line (not followed by the package FAIL line)
# and the alarm frame AFTER a non-panic line, so neither second signal pairs.
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
 '{"Action":"output","Package":"example.com/b","Output":"ok  \texample.com/b\t0.02s\n"}' \
 '{"Action":"output","Package":"example.com/a","Output":"FAIL\texample.com/a\t2.01s\n"}' \
 '{"Action":"fail","Package":"example.com/a","Elapsed":2.01}'; do
	printf '%s\n' "$l"
done
exit 1
EOT
chmod +x "$WORK/fakego/go"
IJ="$WORK/interleave.json"; : > "$IJ"
bash "$here/go-test-json.sh" "$IJ" "$WORK/fakego/go" ./... >/dev/null 2>"$WORK/il.err"; il_rc=$?
check "timeout, interleaved -json stream: the leg is VOID (exit 3)" "$il_rc" "3"
if grep -q "VOID: go test hit its -timeout in example.com/a\." "$WORK/il.err"; then
	ok "timeout, interleaved -json stream: the banner names the timed-out package and not the one that passed"
else
	bad "timeout, interleaved -json stream: banner wrong: $(head -1 "$WORK/il.err")"
fi
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
# cmd/go kills the binary at -timeout + 1m and prints "*** Test killed with
# quit: ran too long (1m1s)." then the package FAIL line. This row costs
# about 62 s, so the text and side-file paths run concurrently.
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

# Control: a fast package under the same flag must NOT be voided.
( cd "$WORK/m" && bash "$here/go-test-json.sh" "" go -timeout 60s ./... >/dev/null 2>&1 ); ctl_rc=$?
if [ "$ctl_rc" -ne 3 ]; then
	ok "timeout control: a package that finishes within -timeout is not voided (rc=$ctl_rc)"
else
	bad "timeout control: a package that finished in time was voided"
fi

printf '\ngo-test-json-selftest: passed=%d failed=%d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
