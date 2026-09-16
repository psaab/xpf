#!/bin/sh
# selftest-routing-probes_9812.sh — the 9812 forcing leg's tool probes.
#
# WHY: the leg runs `go test` with XPF_REQUIRE_NETNS=1, where a missing tool
# inside the test is a Fatalf, not a skip. So every tool the test can consume
# (go, unshare, ip, bash) must be preflighted by the leg: a deleted probe (or
# a newly consumed tool without one) turns a minimal host from SKIP into a
# false FAIL. Each cell below runs the REAL leg against a fixture PATH and
# asserts the contract. The last two cells drive the leg's by-name guard with
# canned `go test -v` output: nothing here builds Go or creates a netns.
#
# Hermetic and fast: fixture dirs under mktemp, absolute-path symlinks (a
# `command -v` hit on a shell function is a bare name, and a symlink to a bare
# name dangles), fakes for unshare/go only.
set -u

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LEG="$HERE/selftest-routing-kernel_9812.sh"
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS: $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }

[ -f "$LEG" ] || { echo "FAIL: leg not found: $LEG — every cell below would fail on the harness"; exit 1; }

# abspath <tool>: the absolute executable path, or failure. `command -v` may
# report a shell function (a bare name); the directory fallbacks cover that,
# and the case filters anything else that is not absolute.
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
# The full tool set; each missing-tool cell deletes one entry. Every link must
# resolve or the cell would fail on the fixture, not the probe.
for t in sh go unshare ip bash grep sed true cat; do
	p=$(abspath "$t") || { echo "FAIL: cannot resolve fixture tool $t"; exit 1; }
	ln -s "$p" "$FIX/$t"
done

# mkfix <name> [missing...]: a fresh fixture dir holding the full set minus
# the named tools. Prints the dir.
mkfix() {
	name=$1; shift
	d="$FIX/$name"; mkdir -p "$d"
	for t in sh go unshare ip bash grep sed true cat; do ln -s "$FIX/$t" "$d/$t"; done
	for rm_t in "$@"; do rm -f "$d/$rm_t"; done
	echo "$d"
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
	printf '#!/bin/sh\ncat "%s"\nexit 0\n' "$2" > "$1"
	chmod +x "$1"
}

# ── 1. missing go → 77 (via the GO override; no fixture needed) ──
out=$(GO=tool-that-does-not-exist-9812 sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 77 ] && printf '%s\n' "$out" | grep -q "SKIP:"; then
	ok "missing go SKIPs (77)"
else
	bad "missing go: rc=$rc out=$out"
fi

# ── 2. missing bash → 77, not a forced-test FAIL ──
d=$(mkfix nobash bash)
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 77 ] && printf '%s\n' "$out" | grep -qi "bash"; then
	ok "missing bash SKIPs (77)"
else
	bad "missing bash: rc=$rc out=$out"
fi

# ── 3. missing ip → 77 ──
d=$(mkfix noip ip)
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 77 ] && printf '%s\n' "$out" | grep -qi "iproute2"; then
	ok "missing ip SKIPs (77)"
else
	bad "missing ip: rc=$rc out=$out"
fi

# ── 4. netns denied → 77 ──
d=$(mkfix nonetns); rm -f "$d/unshare"
printf '#!/bin/sh\nexit 1\n' > "$d/unshare"; chmod +x "$d/unshare"
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 77 ] && printf '%s\n' "$out" | grep -qi "netns"; then
	ok "denied netns SKIPs (77)"
else
	bad "denied netns: rc=$rc out=$out"
fi

# ── 5. positive control: probes pass and the guard parses a good run ──
d=$(mkfix ok); rm -f "$d/unshare" "$d/go"
write_fake_unshare "$d/unshare"
cat > "$d/canned.txt" <<'EOF'
=== RUN   TestNextTableIngressScopeOnRealKernel_9420
--- PASS: TestNextTableIngressScopeOnRealKernel_9420 (0.06s)
=== RUN   TestVRFMissTerminatorOnRealKernel9819
--- PASS: TestVRFMissTerminatorOnRealKernel9819 (0.45s)
PASS
ok  	github.com/psaab/xpf/pkg/routing	0.516s
EOF
write_fake_go "$d/go" "$d/canned.txt"
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q "both routing kernel cells ran and passed"; then
	ok "positive control: good canned run passes the guard"
else
	bad "positive control: rc=$rc out=$out"
fi

# ── 6. guard control: a run where the kernel cells never ran must FAIL ──
d=$(mkfix norun); rm -f "$d/unshare" "$d/go"
write_fake_unshare "$d/unshare"
cat > "$d/canned.txt" <<'EOF'
=== RUN   TestSomethingElse
--- PASS: TestSomethingElse (0.00s)
PASS
ok  	github.com/psaab/xpf/pkg/routing	0.010s
EOF
write_fake_go "$d/go" "$d/canned.txt"
out=$(PATH="$d" sh "$LEG" 2>&1); rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 77 ] && printf '%s\n' "$out" | grep -q "did not run"; then
	ok "guard control: rotted predicate FAILs by name"
else
	bad "guard control: rc=$rc out=$out"
fi

echo
echo "  routing-probes selftest: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
[ "$PASS" -gt 0 ] || { echo "FAIL: the selftest ran ZERO cells" >&2; exit 1; }
exit 0
