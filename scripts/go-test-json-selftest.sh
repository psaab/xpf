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

printf '\ngo-test-json-selftest: passed=%d failed=%d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
