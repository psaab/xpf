#!/bin/sh
# make-guard-probes-selftest.sh — pin the -json=false argv contract of the
# two privileged Makefile legs that scan `^=== RUN` text (#12599).
#
# test-memlock-guards and test-shim-run run `go test -v` and then require
# every guarded test name to appear as a plain-text `=== RUN` line. An
# inherited GOFLAGS=-json flips the stream to JSON records, so every cell
# false-reds as "did not run" — the #12519 defect class. The legs therefore
# pin -json=false explicitly.
#
# These fixtures prove that behaviourally, never by grepping the Makefile
# for the flag text (#12587 F1: a text grep is wrong in both directions —
# a comment satisfies it, a constructed flag defeats it). A fake `go` on
# PATH exits 23 unless -json=false is in its actual argv, then prints
# canned RUN lines for every name the invoked leg censuses. GO is unset so
# an inherited absolute path cannot bypass the fake (#12081/#12519 idiom).
#
# Hermetic: no Go build, no BPF, no root. A fake `id` answers 0 to `-u`
# so the legs' root gate passes without privilege; the fake `go` never
# executes a real test.
set -u

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
MAKEFILE="$ROOT/Makefile"
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS: $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }

[ -f "$MAKEFILE" ] || { echo "FAIL: Makefile not found: $MAKEFILE"; exit 1; }
command -v make >/dev/null 2>&1 || { echo "SKIP: make not installed"; exit 77; }

# Fixture PATHs must select the fake go, not an inherited absolute GO:
# test-memlock-guards invokes $(GO), which `GO ?= go` would otherwise
# resolve from the environment past the fixture.
unset GO

FIX=$(mktemp -d); trap 'rm -rf "$FIX"' EXIT

# Canned output: every name either leg censuses, derived with the same
# pipelines the Makefile recipes use, so a renamed guard moves the
# fixture with the gate instead of silently uncoupling from it.
CANNED="$FIX/canned.txt"
{
	sed -n 's/.*Test: "\(Test[A-Za-z0-9_]*\)".*/\1/p' "$ROOT/pkg/memlockcensus/registry.go"
	grep -hoE '^func Test[A-Za-z0-9_]+' \
		"$ROOT/pkg/dataplane/userspace/fragment_disposition_7494_test.go" \
		"$ROOT/pkg/dataplane/userspace/qinq_disposition_9888_test.go" \
		"$ROOT/pkg/dataplane/userspace/stag_disposition_10655_test.go" \
		"$ROOT/pkg/dataplane/userspace/tagged_only_local_drop_12055_test.go" \
		"$ROOT/pkg/dataplane/userspace/xdp_shim_dispatch_10864_test.go" \
		"$ROOT/pkg/dataplane/userspace/wg_zone_admission_11574_test.go" |
		sed 's/^func //'
} | sort -u | while IFS= read -r n; do
	printf '=== RUN   %s\n--- PASS: %s (0.00s)\n' "$n" "$n"
done > "$CANNED"
printf 'PASS\nok  \tfake\t0.001s\n' >> "$CANNED"
[ -s "$CANNED" ] || { echo "FAIL: derived NO canned test names — fixture would prove nothing"; exit 1; }

# Fake id: only `-u` is answered (0, root); anything else delegates.
cat > "$FIX/id" <<'EOF'
#!/bin/sh
if [ "$1" = "-u" ]; then echo 0; exit 0; fi
exec /usr/bin/id "$@"
EOF

# write_fake_go <path> <check|reject>: check exits 23 unless -json=false
# is in argv, then prints the canned output; reject always exits 23,
# simulating the argv the check fake sees when the pin is removed.
write_fake_go() {
	if [ "$2" = "reject" ]; then
		printf '#!/bin/sh\necho "FAIL: -json=false missing from go argv" >&2\nexit 23\n' > "$1"
	else
		cat > "$1" <<'EOF'
#!/bin/sh
found=0
for arg do
	[ "$arg" = "-json=false" ] && found=1
done
if [ "$found" -ne 1 ]; then
	echo "FAIL: -json=false missing from go argv" >&2
	exit 23
fi
exec cat "$CANNED_GO_OUTPUT"
EOF
	fi
	chmod +x "$1"
}
chmod +x "$FIX/id"

# run_leg <target>: run one Makefile leg against the fixture PATH under
# an inherited GOFLAGS=-json. Prints output; rc is the leg's.
run_leg() {
	(cd "$ROOT" && CANNED_GO_OUTPUT="$CANNED" GOFLAGS=-json MAKEFLAGS= \
		PATH="$FIX:$PATH" make "$1" 2>&1)
}

# ── 1. test-shim-run passes -json=false under GOFLAGS=-json ──
write_fake_go "$FIX/go" check
out=$(run_leg test-shim-run); rc=$?
if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q '^=== RUN'; then
	ok "test-shim-run: -json=false is passed explicitly under GOFLAGS=-json"
else
	bad "test-shim-run argv guard expected pass, got $rc: $out"
fi

# ── 2. test-memlock-guards passes -json=false under GOFLAGS=-json ──
out=$(run_leg test-memlock-guards); rc=$?
if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q 'every registered guard executed'; then
	ok "test-memlock-guards: -json=false is passed explicitly under GOFLAGS=-json"
else
	bad "test-memlock-guards argv guard expected pass, got $rc: $out"
fi

# ── 3. negative control: a go that rejects the argv (the shape the check
# fake produces when the pin is removed) must red the shim leg, never
# pass silently on canned output it never printed.
write_fake_go "$FIX/go" reject
out=$(run_leg test-shim-run); rc=$?
if [ "$rc" -ne 0 ]; then
	ok "test-shim-run: go exit 23 (missing -json=false) fails the leg"
else
	bad "test-shim-run expected failure when go rejects argv, got 0: $out"
fi

# ── 4. negative control, memlock leg: same rejection must red it too.
out=$(run_leg test-memlock-guards); rc=$?
if [ "$rc" -ne 0 ]; then
	ok "test-memlock-guards: go exit 23 (missing -json=false) fails the leg"
else
	bad "test-memlock-guards expected failure when go rejects argv, got 0: $out"
fi

echo
echo "  make-guard probes selftest: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
[ "$PASS" -gt 0 ] || { echo "FAIL: the selftest ran ZERO cells" >&2; exit 1; }
exit 0
