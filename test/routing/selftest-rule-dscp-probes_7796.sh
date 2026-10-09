#!/bin/sh
# selftest-rule-dscp-probes_7796.sh — pin the #7796 leg's output guards.
#
# Run the real leg against fixture PATHs and canned go test output. These cells
# need neither a Go build nor a network namespace; they catch regressions in the
# post-run ip decision, named RUN/SKIP scans, and -json=false output pin.
set -u

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LEG="$HERE/selftest-rule-dscp_7796.sh"
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS: $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }

[ -f "$LEG" ] || { echo "FAIL: leg not found: $LEG"; exit 1; }

abspath() {
	p=$(command -v "$1" 2>/dev/null)
	case "$p" in
	/*) [ -x "$p" ] && { echo "$p"; return 0; } ;;
	esac
	for d in /usr/bin /bin /usr/local/bin; do
		if [ -x "$d/$1" ]; then echo "$d/$1"; return 0; fi
	done
	return 1
}

FIX=$(mktemp -d); trap 'rm -rf "$FIX"' EXIT
for t in sh go unshare ip grep sed true cat; do
	p=$(abspath "$t") || { echo "FAIL: cannot resolve fixture tool $t"; exit 1; }
	ln -s "$p" "$FIX/$t"
done

mkfix() {
	name=$1; shift
	d="$FIX/$name"; mkdir -p "$d"
	for t in sh go unshare ip grep sed true cat; do ln -s "$FIX/$t" "$d/$t"; done
	for rm_t in "$@"; do rm -f "$d/$rm_t"; done
	echo "$d"
}

write_fake_unshare() {
	cat > "$1" <<'EOF'
#!/bin/sh
while [ $# -gt 0 ]; do
	case "$1" in
	-*) shift ;;
	*) break ;;
	esac
done
exec "$@"
EOF
	chmod +x "$1"
}

write_fake_go() {
	printf '#!/bin/sh\ncat "%s"\nexit 0\n' "$2" > "$1"
	chmod +x "$1"
}

write_good_output() {
	cat > "$1" <<'EOF'
=== RUN   TestRuleAddDSCPAcceptedByKernel7796
--- PASS: TestRuleAddDSCPAcceptedByKernel7796 (0.00s)
=== RUN   TestRuleDSCPRoundTripsThroughKernel7796
--- PASS: TestRuleDSCPRoundTripsThroughKernel7796 (0.00s)
=== RUN   TestRuleAddDSCPRejectsLegacyTOS7796
--- PASS: TestRuleAddDSCPRejectsLegacyTOS7796 (0.00s)
=== RUN   TestDSCPZeroIsDistinctFromNoDSCP7796
--- PASS: TestDSCPZeroIsDistinctFromNoDSCP7796 (0.00s)
EOF
}

# 1. Missing ip still runs all four cells; only the two readback SKIPs yield 77.
d=$(mkfix noip ip); rm -f "$d/unshare" "$d/go"
write_fake_unshare "$d/unshare"
cat > "$d/canned.txt" <<'EOF'
=== RUN   TestRuleAddDSCPAcceptedByKernel7796
--- PASS: TestRuleAddDSCPAcceptedByKernel7796 (0.00s)
=== RUN   TestRuleDSCPRoundTripsThroughKernel7796
--- SKIP: TestRuleDSCPRoundTripsThroughKernel7796 (0.00s)
=== RUN   TestRuleAddDSCPRejectsLegacyTOS7796
--- PASS: TestRuleAddDSCPRejectsLegacyTOS7796 (0.00s)
=== RUN   TestDSCPZeroIsDistinctFromNoDSCP7796
--- SKIP: TestDSCPZeroIsDistinctFromNoDSCP7796 (0.00s)
EOF
write_fake_go "$d/go" "$d/canned.txt"
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 77 ] && printf '%s\n' "$out" | grep -q 'SKIP: iproute2 not found'; then
	ok "missing ip returns 77 after the two readback skips"
else
	bad "missing ip expected 77, got $rc: $out"
fi

# 2. A healthy canned run passes.
d=$(mkfix good); rm -f "$d/unshare" "$d/go"
write_fake_unshare "$d/unshare"; write_good_output "$d/canned.txt"; write_fake_go "$d/go" "$d/canned.txt"
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q 'PASS: all four 7796 kernel cells ran and passed'; then
	ok "canned good run passes"
else
	bad "canned good run expected 0, got $rc: $out"
fi

# 3. A named readback SKIP with ip present must FAIL and name that cell.
d=$(mkfix skip); rm -f "$d/unshare" "$d/go"
write_fake_unshare "$d/unshare"
cat > "$d/canned.txt" <<'EOF'
=== RUN   TestRuleAddDSCPAcceptedByKernel7796
--- PASS: TestRuleAddDSCPAcceptedByKernel7796 (0.00s)
=== RUN   TestRuleDSCPRoundTripsThroughKernel7796
--- SKIP: TestRuleDSCPRoundTripsThroughKernel7796 (0.00s)
=== RUN   TestRuleAddDSCPRejectsLegacyTOS7796
--- PASS: TestRuleAddDSCPRejectsLegacyTOS7796 (0.00s)
=== RUN   TestDSCPZeroIsDistinctFromNoDSCP7796
--- PASS: TestDSCPZeroIsDistinctFromNoDSCP7796 (0.00s)
EOF
write_fake_go "$d/go" "$d/canned.txt"
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 1 ] && printf '%s\n' "$out" | grep -q 'FAIL: TestRuleDSCPRoundTripsThroughKernel7796 SKIPPED'; then
	ok "canned readback SKIP fails by cell name"
else
	bad "canned readback SKIP expected named FAIL, got $rc: $out"
fi

# 4. Omitting a guarded cell must FAIL with the did-not-run diagnostic.
d=$(mkfix missing); rm -f "$d/unshare" "$d/go"
write_fake_unshare "$d/unshare"
cat > "$d/canned.txt" <<'EOF'
=== RUN   TestRuleAddDSCPAcceptedByKernel7796
--- PASS: TestRuleAddDSCPAcceptedByKernel7796 (0.00s)
=== RUN   TestRuleDSCPRoundTripsThroughKernel7796
--- PASS: TestRuleDSCPRoundTripsThroughKernel7796 (0.00s)
=== RUN   TestRuleAddDSCPRejectsLegacyTOS7796
--- PASS: TestRuleAddDSCPRejectsLegacyTOS7796 (0.00s)
EOF
write_fake_go "$d/go" "$d/canned.txt"
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 1 ] && printf '%s\n' "$out" | grep -q 'FAIL: TestDSCPZeroIsDistinctFromNoDSCP7796 did not run'; then
	ok "canned missing cell fails as did not run"
else
	bad "canned missing cell expected named FAIL, got $rc: $out"
fi

# 5. Pin -json=false in argv even when inherited GOFLAGS requests JSON.
d=$(mkfix jsonflag); rm -f "$d/unshare" "$d/go"
write_fake_unshare "$d/unshare"; write_good_output "$d/canned.txt"
cat > "$d/go" <<'EOF'
#!/bin/sh
found=0
for arg do
	[ "$arg" = "-json=false" ] && found=1
done
if [ "$found" -ne 1 ]; then
	echo "FAIL: -json=false missing from go argv"
	exit 23
fi
exec cat "$CANNED_GO_OUTPUT"
EOF
chmod +x "$d/go"
out=$(CANNED_GO_OUTPUT="$d/canned.txt" GOFLAGS=-json PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q 'PASS: all four 7796 kernel cells ran and passed'; then
	ok "-json=false is passed explicitly under GOFLAGS=-json"
else
	bad "-json=false argv guard expected pass, got $rc: $out"
fi

echo
echo "  rule-dscp probes selftest: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
[ "$PASS" -gt 0 ] || { echo "FAIL: the selftest ran ZERO cells" >&2; exit 1; }
exit 0
