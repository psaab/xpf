#!/bin/bash
# scripts/debug-leg-census-selftest.sh -- fail-closed fixture tests for the
# exact debug-leg census (#10492).
#
# The live validator asks Cargo for 14 target-qualified lists, so its static
# self-test uses a tiny fixture census instead. Every mutation below must turn
# the same validator RED and name the violated contract; a validator that
# merely exits non-zero for every fixture is caught by the positive control.
set -u

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
VALIDATOR="$REPO_ROOT/scripts/debug-leg-census.py"
PASS=0
FAILN=0

ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAILN=$((FAILN + 1)); printf '  FAIL %s\n' "$*" >&2; }

for required in "$VALIDATOR"; do
	[ -f "$required" ] || {
		bad "missing validator: $required"
		exit 1
	}
done

mk_fixture() {
	local d
	d=$(mktemp -d "${TMPDIR:-/tmp}/debug-leg-census-cell.XXXXXXXX")
	cat >"$d/census.json" <<'EOF'
{"targets":[{"name":"fixture-bin","kind":"bin","listed":["frame::keep","nat::ignored"],"ignored":["nat::ignored"]},{"name":"fixture-test","kind":"test","listed":["session::keep","checksum::excluded"],"ignored":[]}]}
EOF
	printf '%b\n' \
		'fixture-bin\tframe::keep' \
		'fixture-test\tsession::keep' >"$d/debug-leg.tests"
	printf '%b\n' \
		'fixture-bin\tnat::ignored\tMEASUREMENT: fixture ignored path' >"$d/debug-leg.ignored"
	printf '%b\n' \
		'fixture-test\tchecksum::excluded\tfixture control-plane exclusion' >"$d/debug-leg.excluded"
	printf '%s' "$d"
}

run_fixture() {
	python3 "$VALIDATOR" --fixture-root "$1"
}

expect_fail() {
	local name=$1
	local needle=$2
	local mutator=$3
	local d rc
	d=$(mk_fixture)
	"$mutator" "$d"
	if run_fixture "$d" >"$d/out" 2>&1; then
		bad "ESCAPE: $name -- validator still passed"
	elif ! grep -Fqi -- "$needle" "$d/out"; then
		bad "$name -- validator failed for the wrong reason (wanted /$needle/)"
		sed -n '1,12p' "$d/out" | sed 's/^/        /' >&2
	else
		ok "$name"
	fi
	rm -rf "$d"
}

# Positive controls must pass before the mutations have meaning.
if python3 "$VALIDATOR" --self-test >/dev/null 2>&1; then
	ok "parser/classifier positive controls"
else
	bad "parser/classifier positive controls"
fi
d=$(mk_fixture)
if run_fixture "$d" >"$d/out" 2>&1; then
	ok "unmutated fixture: validator OK"
else
	bad "unmutated fixture FAILED -- mutation cells would be vacuous"
	sed -n '1,12p' "$d/out" | sed 's/^/        /' >&2
fi
rm -rf "$d"

empty_allowlist() { : >"$1/debug-leg.tests"; }
empty_live() {
	python3 - "$1/census.json" <<'PY'
import json
import sys
path = sys.argv[1]
data = json.load(open(path, encoding="utf-8"))
for target in data["targets"]:
    target["listed"] = []
    target["ignored"] = []
json.dump(data, open(path, "w", encoding="utf-8"), separators=(",", ":"))
PY
}
missing_expected() { sed -i '/^fixture-bin\tframe::keep$/d' "$1/debug-leg.tests"; }
unexpected_family() {
	python3 - "$1/census.json" <<'PY'
import json
import sys
path = sys.argv[1]
data = json.load(open(path, encoding="utf-8"))
data["targets"][1]["listed"].append("nat::unexpected")
json.dump(data, open(path, "w", encoding="utf-8"), separators=(",", ":"))
PY
}
ignored_transition() {
	python3 - "$1/census.json" <<'PY'
import json
import sys
path = sys.argv[1]
data = json.load(open(path, encoding="utf-8"))
data["targets"][0]["ignored"] = []
json.dump(data, open(path, "w", encoding="utf-8"), separators=(",", ":"))
PY
}
duplicate_registry() {
	python3 - "$1/debug-leg.tests" <<'PY'
import sys
path = sys.argv[1]
lines = open(path, encoding="utf-8").read().splitlines()
lines.insert(1, "fixture-bin\tframe::keep")
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY
}
unsorted_registry() {
	printf '%b\n' \
		'fixture-test\tsession::keep' \
		'fixture-bin\tframe::keep' >"$1/debug-leg.tests"
}
duplicate_target_path() {
	python3 - "$1/census.json" "$1/debug-leg.tests" <<'PY'
import json
import sys
census_path, registry_path = sys.argv[1:]
data = json.load(open(census_path, encoding="utf-8"))
data["targets"][1]["listed"].append("frame::keep")
json.dump(data, open(census_path, "w", encoding="utf-8"), separators=(",", ":"))
lines = open(registry_path, encoding="utf-8").read().splitlines()
lines.insert(1, "fixture-test\tframe::keep")
open(registry_path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY
}

expect_fail "empty allowlist" "registry is empty" empty_allowlist
expect_fail "empty live list" "live census is empty" empty_live
expect_fail "missing expected path" "frame::keep" missing_expected
expect_fail "unexpected family path" "nat::unexpected" unexpected_family
expect_fail "ignored-to-runnable transition" "ignored family equation" ignored_transition
expect_fail "duplicate registry entry" "duplicate target/path" duplicate_registry
expect_fail "unsorted registry" "registry is unsorted" unsorted_registry
expect_fail "duplicate target path" "target collision" duplicate_target_path

echo ""
echo "debug-leg census self-test: $PASS passed, $FAILN failed"
[ "$FAILN" -eq 0 ]
