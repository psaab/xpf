#!/bin/sh
# selftest-daemon-probes_15241.sh — the daemon-kernel leg's tool probes.
#
# WHY: the leg runs `go test` with XPF_REQUIRE_NETNS=1, where a missing
# tool inside the test is a Fatalf, not a skip (#15241 A58-06 made the
# tool-absent arms honour the env). So every tool the tests can consume
# (go, unshare, ip, bash, nsenter, timeout, sleep, nft) must be
# preflighted by the leg: a deleted probe (or a newly consumed tool
# without one) turns a minimal host from SKIP into a false FAIL. This
# probe runs the REAL daemon-kernel leg against fixture PATHs and
# asserts its contracts, including the acceptance shape: with the
# forcing env set in the caller's environment and unshare absent, the
# leg fails (77) at its own probe instead of silently passing -- and a
# forced `go test` with unshare absent fails inside the test. The final
# cells pin the output flag and exercise the by-name guard with canned
# output: nothing here builds Go or creates a netns.
#
# Hermetic and fast: fixture dirs under mktemp, absolute-path symlinks (a
# `command -v` hit on a shell function is a bare name, and a symlink to a
# bare name dangles), fakes for unshare/go only.
set -u

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LEG="$HERE/selftest-daemon-kernel_15241.sh"
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS: $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }

[ -f "$LEG" ] || { echo "FAIL: leg not found: $LEG — every cell below would fail on the harness"; exit 1; }

# abspath <tool>: the absolute executable path, or failure. `command -v` may
# report a shell function (a bare name); the directory fallbacks cover that,
# and the case filters anything else that is not absolute.
abspath() {
	p=$(command -v "$1" 2>/dev/null) || p=""
	case "$p" in
	/*) ;;
	*)
		for d in /usr/local/bin /usr/bin /bin /usr/sbin /sbin; do
			if [ -x "$d/$1" ]; then p="$d/$1"; break; fi
		done
		;;
	esac
	case "$p" in
	/*) printf '%s\n' "$p" ;;
	*) return 1 ;;
	esac
}

FIX=$(mktemp -d); trap 'rm -rf "$FIX"' EXIT
# The full tool set; each missing-tool cell deletes one entry. Every link must
# resolve or the cell would fail on the fixture, not the probe.
for t in sh go unshare ip bash nsenter timeout sleep grep sed true cat; do
	ln -s "$(abspath "$t")" "$FIX/$t" || { echo "FAIL: cannot fixture $t"; exit 1; }
done
# nft may live only in /usr/sbin; link it when resolvable so the full set
# is complete on this host. The missing-nft cell does not depend on it:
# the leg also probes /usr/sbin/nft and /sbin/nft directly.
if p=$(abspath nft); then
	ln -s "$p" "$FIX/nft" 2>/dev/null || true
fi

# Fixture PATHs must select the fake go, not an inherited absolute GO.
unset GO

# mkfix <name> [missing...]: a fresh fixture dir holding the full set minus
# the named tools. Prints the dir.
mkfix() {
	name=$1; shift
	d="$FIX/$name"; mkdir -p "$d"
	for f in "$FIX"/*; do
		skip=0
		for m in "$@"; do [ "$(basename "$f")" = "$m" ] && skip=1; done
		[ "$skip" -eq 0 ] && ln -s "$f" "$d/$(basename "$f")"
	done
	printf '%s\n' "$d"
}

# write_fake_unshare <path>: an unshare that drops every leading flag and
# execs the rest, so `unshare -rn true` and `unshare -rn go ...` run without
# any namespace.
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

# write_fake_go <path> <canned>: a go that prints the canned `go test -v`
# output and exits 0, ignoring its arguments.
write_fake_go() {
	printf '#!/bin/sh\ncat "%s"\n' "$2" > "$1"
	chmod +x "$1"
}

# ── 1. missing go → 77 (via the GO override; no fixture needed) ──
out=$(GO=tool-that-does-not-exist-15241 sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 77 ] && printf '%s\n' "$out" | grep -q "SKIP:"; then
	ok "missing go skips (77)"
else
	bad "missing go: rc=$rc (want 77/SKIP): $out"
fi

# ── 2. missing bash → 77, not a forced-test FAIL ──
d=$(mkfix nobash bash)
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 77 ] && printf '%s\n' "$out" | grep -qi "bash"; then
	ok "missing bash skips (77)"
else
	bad "missing bash: rc=$rc (want 77/SKIP): $out"
fi

# ── 3. missing ip → 77 ──
d=$(mkfix noip ip)
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 77 ] && printf '%s\n' "$out" | grep -qi "iproute2"; then
	ok "missing ip skips (77)"
else
	bad "missing ip: rc=$rc (want 77/SKIP): $out"
fi

# ── 4. missing nsenter → 77 ──
d=$(mkfix nonsenter nsenter)
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 77 ] && printf '%s\n' "$out" | grep -qi "nsenter"; then
	ok "missing nsenter skips (77)"
else
	bad "missing nsenter: rc=$rc (want 77/SKIP): $out"
fi

# ── 5. missing timeout → 77 ──
d=$(mkfix notimeout timeout)
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 77 ] && printf '%s\n' "$out" | grep -qi "timeout"; then
	ok "missing timeout skips (77)"
else
	bad "missing timeout: rc=$rc (want 77/SKIP): $out"
fi

# ── 6. missing sleep → 77 ──
d=$(mkfix nosleep sleep)
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 77 ] && printf '%s\n' "$out" | grep -qi "sleep"; then
	ok "missing sleep skips (77)"
else
	bad "missing sleep: rc=$rc (want 77/SKIP): $out"
fi

# ── 7. netns denied → 77 ──
d=$(mkfix nonetns); rm -f "$d/unshare"
printf '#!/bin/sh\nexit 1\n' > "$d/unshare"; chmod +x "$d/unshare"
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 77 ] && printf '%s\n' "$out" | grep -qi "netns"; then
	ok "netns denied skips (77)"
else
	bad "netns denied: rc=$rc (want 77/SKIP): $out"
fi

# ── 8. (#15241 acceptance) forcing set + unshare absent → the leg fails ──
# The leg's own probe reports SKIP/77, and a caller that exports
# XPF_REQUIRE_NETNS (the Makefile daemon-kernel leg) turns 77 into FAIL.
# Either way the run is not green: before A58-06 the same host ran the
# cells, skipped inside an ok package, and reported success.
d=$(mkfix nounshare unshare)
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 77 ] && printf '%s\n' "$out" | grep -qi "unshare"; then
	ok "unshare absent: leg cannot report PASS (77)"
else
	bad "unshare absent: rc=$rc (want 77, never 0): $out"
fi

# ── 9. -json=false stays pinned against inherited GOFLAGS=-json ──
d=$(mkfix jsonflag); rm -f "$d/unshare" "$d/go"
write_fake_unshare "$d/unshare"
cat > "$d/canned.txt" <<'EOF'
=== RUN   TestHostInboundIngressZoneVerdictsOnRealKernel9637
--- PASS: TestHostInboundIngressZoneVerdictsOnRealKernel9637 (0.01s)
=== RUN   TestHostInboundUnzonedIngressVerdictsOnRealKernel11409
--- PASS: TestHostInboundUnzonedIngressVerdictsOnRealKernel11409 (0.01s)
=== RUN   TestHostInboundReinjectTunVerdicts9637
--- PASS: TestHostInboundReinjectTunVerdicts9637 (0.01s)
=== RUN   TestHostInboundSharedVRFMasterIngressAndFineDeny12034
--- PASS: TestHostInboundSharedVRFMasterIngressAndFineDeny12034 (0.01s)
=== RUN   TestLifelineSharedDenyAllVerdictsOnRealKernel12229
--- PASS: TestLifelineSharedDenyAllVerdictsOnRealKernel12229 (0.01s)
=== RUN   TestRIMemberSecureTunnelUnitBindsToVRF12087
--- PASS: TestRIMemberSecureTunnelUnitBindsToVRF12087 (0.01s)
EOF
cat > "$d/go" <<'EOF'
#!/bin/sh
printf 'go json=false argv:'
for a in "$@"; do printf ' <%s>' "$a"; done
printf '\n'
cat "$CANNED_GO_OUTPUT"
EOF
chmod +x "$d/go"
out=$(CANNED_GO_OUTPUT="$d/canned.txt" GOFLAGS=-json PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q "all six daemon kernel cells ran and passed"; then
	ok "-json=false pinned: fake go run passes the by-name guard"
else
	bad "-json=false pin: rc=$rc: $out"
fi

# ── 10. positive control: probes pass and the guard parses a good run ──
d=$(mkfix ok); rm -f "$d/unshare" "$d/go"
write_fake_unshare "$d/unshare"
cat > "$d/canned.txt" <<'EOF'
=== RUN   TestHostInboundIngressZoneVerdictsOnRealKernel9637
--- PASS: TestHostInboundIngressZoneVerdictsOnRealKernel9637 (0.01s)
=== RUN   TestHostInboundUnzonedIngressVerdictsOnRealKernel11409
--- PASS: TestHostInboundUnzonedIngressVerdictsOnRealKernel11409 (0.01s)
=== RUN   TestHostInboundReinjectTunVerdicts9637
--- PASS: TestHostInboundReinjectTunVerdicts9637 (0.01s)
=== RUN   TestHostInboundSharedVRFMasterIngressAndFineDeny12034
--- PASS: TestHostInboundSharedVRFMasterIngressAndFineDeny12034 (0.01s)
=== RUN   TestLifelineSharedDenyAllVerdictsOnRealKernel12229
--- PASS: TestLifelineSharedDenyAllVerdictsOnRealKernel12229 (0.01s)
=== RUN   TestRIMemberSecureTunnelUnitBindsToVRF12087
--- PASS: TestRIMemberSecureTunnelUnitBindsToVRF12087 (0.01s)
EOF
write_fake_go "$d/go" "$d/canned.txt"
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q "all six daemon kernel cells ran and passed"; then
	ok "positive control: good run passes"
else
	bad "positive control: rc=$rc: $out"
fi

# ── 11. guard control: a run where the kernel cells never ran must FAIL ──
d=$(mkfix norun); rm -f "$d/unshare" "$d/go"
write_fake_unshare "$d/unshare"
cat > "$d/canned.txt" <<'EOF'
=== RUN   TestSomethingElse
--- PASS: TestSomethingElse (0.01s)
EOF
write_fake_go "$d/go" "$d/canned.txt"
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 77 ] && printf '%s\n' "$out" | grep -q "did not run"; then
	ok "guard control: empty run fails, naming the missing cells"
else
	bad "guard control: rc=$rc: $out"
fi

echo
echo "  daemon-probes selftest: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
[ "$PASS" -gt 0 ] || { echo "FAIL: the selftest ran ZERO cells" >&2; exit 1; }
exit 0
