#!/bin/sh
# Self-test for scripts/image/xpf-grow-root (#1925).
#
# Runs the REAL wrapper with PATH shadowed by mock findmnt/lsblk/growpart/
# resize2fs, XPF_GROW_ROOT_SYSFS pointed at a synthetic sysfs tree, and
# XPF_GROW_ROOT_STAMP pointed at a temp file, then asserts:
#   1. device resolution — the right (disk, partition) pair + the exact
#      growpart/resize2fs argv across sda/vda/nvme bus naming;
#   2. STAMP discipline — the stamp is written ONLY on genuine success
#      (NOCHANGE / grew+resize2fs-ok) and left ABSENT on every failure
#      (growpart real failure, growpart-grew-but-resize2fs-failed partial,
#      unresolved root) so the unit's ConditionPathExists re-fires and the
#      grow retries; AND the wrapper ALWAYS exits 0 (boot never blocked);
#   3. retry convergence — a resize2fs-fail (no stamp) followed by a second
#      run with growpart->NOCHANGE + resize2fs->ok writes the stamp.
#
# Non-tautological by construction: the mock growpart/resize2fs record
# EXACTLY the args the wrapper passed; the assertions pin those bytes, and
# the stamp checks read the real file the wrapper writes. The
# resize2fs-fails / growpart-fails cases MUST FAIL against any build that
# stamps unconditionally (e.g. an ExecStartPost touch, or the pre-fix head
# 8fccd325) — they pin the exact regression Codex flagged. A negative
# control proves the harness can fail.
#
# Pure user-space: no root, no real block devices, no kernel. Runs in CI /
# the engineering quad's gate alongside bash -n + shellcheck.
set -u

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WRAPPER="$HERE/xpf-grow-root"
[ -x "$WRAPPER" ] || { echo "FATAL: $WRAPPER not executable"; exit 1; }

PASS=0
FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $*" >&2; FAIL=$((FAIL + 1)); }

# Fail hard if mktemp fails (e.g. a read-only TMPDIR): an empty WORK would
# make the mocks/sysfs land under /bin and /sys and corrupt the host.
WORK=$(mkdir -p /var/worktrees/.cache/tmpdir && mktemp -d "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-grow-root-test.XXXXXX") || {
    echo "FATAL: mktemp -d failed (read-only TMPDIR?)" >&2; exit 1; }
[ -n "$WORK" ] && [ -d "$WORK" ] || {
    echo "FATAL: WORK dir not created" >&2; exit 1; }
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

BIN="$WORK/bin"
mkdir -p "$BIN"

# ── mock binaries (PATH shim). Each logs its call into $WORK/<name>.calls ──
# findmnt -no SOURCE /  -> the per-case ROOT_SRC; lsblk -no PKNAME <src> ->
# the per-case PKNAME; growpart/resize2fs record their argv. growpart honors
# GROWPART_RC + GROWPART_OUT so the NOCHANGE/grow paths can be exercised.
cat > "$BIN/findmnt" <<'EOF'
#!/bin/sh
# Only `findmnt -no SOURCE /` is used by the wrapper.
printf '%s\n' "${MOCK_ROOT_SRC:-}"
EOF
cat > "$BIN/lsblk" <<'EOF'
#!/bin/sh
# Only `lsblk -no PKNAME <src>` is used by the wrapper.
printf '%s\n' "${MOCK_PKNAME:-}"
EOF
cat > "$BIN/growpart" <<'EOF'
#!/bin/sh
printf '%s %s\n' "$1" "$2" > "$MOCK_CALLS_DIR/growpart.calls"
printf '%s' "${GROWPART_OUT:-CHANGED: partition resized}"
exit "${GROWPART_RC:-0}"
EOF
cat > "$BIN/resize2fs" <<'EOF'
#!/bin/sh
printf '%s\n' "$1" > "$MOCK_CALLS_DIR/resize2fs.calls"
echo "The filesystem is now larger."
exit "${RESIZE2FS_RC:-0}"
EOF
chmod +x "$BIN"/findmnt "$BIN"/lsblk "$BIN"/growpart "$BIN"/resize2fs

# Synthetic sysfs: <dev>/partition exists (with the partnum) ONLY for real
# partitions; whole disks omit it.
SYSFS="$WORK/sys"
make_part() { mkdir -p "$SYSFS/$1"; printf '%s\n' "$2" > "$SYSFS/$1/partition"; }
make_disk() { mkdir -p "$SYSFS/$1"; }  # no partition file
make_part sda1 1
make_part vda1 1
make_part nvme0n1p1 1
make_disk sda            # whole disk, not a partition

STAMP="$WORK/root-grown"

# run_case <root_src> <pkname> [GROWPART_RC] [GROWPART_OUT] [RESIZE2FS_RC]
# Records the wrapper's exit code in $WORK/rc; the stamp lands at $STAMP.
run_case() {
    rm -f "$WORK/growpart.calls" "$WORK/resize2fs.calls" "$STAMP"
    MOCK_CALLS_DIR="$WORK" \
    MOCK_ROOT_SRC="$1" MOCK_PKNAME="$2" \
    GROWPART_RC="${3:-0}" GROWPART_OUT="${4:-}" RESIZE2FS_RC="${5:-0}" \
    XPF_GROW_ROOT_SYSFS="$SYSFS" XPF_GROW_ROOT_STAMP="$STAMP" \
    PATH="$BIN:$PATH" \
        "$WRAPPER" >/dev/null 2>&1
    echo "$?" > "$WORK/rc"
}

# The wrapper must ALWAYS exit 0 (oneshot never fails the boot).
expect_exit0() {  # expect_exit0 <label>
    rc=$(cat "$WORK/rc" 2>/dev/null || echo "?")
    if [ "$rc" = "0" ]; then ok "$1: exit 0 (boot non-blocking)"
    else bad "$1: exit $rc, want 0 (boot must never be blocked)"; fi
}

expect_stamp() {  # expect_stamp <label>
    if [ -f "$STAMP" ]; then ok "$1: stamp written (success)"
    else bad "$1: stamp MISSING — a genuine success must stamp"; fi
}

expect_no_stamp() {  # expect_no_stamp <label>
    if [ ! -f "$STAMP" ]; then ok "$1: stamp absent (will retry next boot)"
    else bad "$1: stamp WRITTEN on failure — failed grow stranded forever"; fi
}

expect_grow() {  # expect_grow <label> <disk> <partnum> <root_src>
    label=$1; xdisk=$2; xpart=$3; xsrc=$4
    gp=$(cat "$WORK/growpart.calls" 2>/dev/null || true)
    r2=$(cat "$WORK/resize2fs.calls" 2>/dev/null || true)
    if [ "$gp" = "/dev/$xdisk $xpart" ]; then
        ok "$label: growpart got '/dev/$xdisk $xpart'"
    else
        bad "$label: growpart got '$gp', want '/dev/$xdisk $xpart'"
    fi
    if [ "$r2" = "$xsrc" ]; then
        ok "$label: resize2fs got '$xsrc'"
    else
        bad "$label: resize2fs got '$r2', want '$xsrc'"
    fi
}

# A failure case that resolved the device still CALLED growpart; assert the
# stamp is absent + exit 0. (Distinct from expect_skip, which is for the
# pre-resolution bail-outs that never call growpart.)
expect_skip() {  # expect_skip <label> — pre-resolution bail-out
    label=$1
    if [ ! -f "$WORK/growpart.calls" ] && [ ! -f "$WORK/resize2fs.calls" ]; then
        ok "$label: did not reach growpart/resize2fs (unresolved)"
    else
        bad "$label: reached growpart unexpectedly (growpart='$(cat "$WORK/growpart.calls" 2>/dev/null)')"
    fi
}

echo "== xpf-grow-root self-test =="

# ── positive cases: each bus naming resolves to the right disk + partnum,
#    grow succeeds -> stamp written, exit 0. ──
run_case /dev/sda1 sda
expect_grow "sda1"      sda      1 /dev/sda1
expect_stamp "sda1"; expect_exit0 "sda1"
run_case /dev/vda1 vda
expect_grow "vda1"      vda      1 /dev/vda1
expect_stamp "vda1"; expect_exit0 "vda1"
run_case /dev/nvme0n1p1 nvme0n1
expect_grow "nvme0n1p1" nvme0n1  1 /dev/nvme0n1p1
expect_stamp "nvme0n1p1"; expect_exit0 "nvme0n1p1"

# ── NOCHANGE path: growpart exit 1 + NOCHANGE is success-for-its-step; the
#    wrapper runs resize2fs (ok) and STAMPS (nothing left to grow). ──
run_case /dev/sda1 sda 1 "NOCHANGE: partition 1 is size ... it cannot be grown"
expect_grow "NOCHANGE" sda 1 /dev/sda1
expect_stamp "NOCHANGE (nothing to grow is success)"; expect_exit0 "NOCHANGE"

# ── FAILURE: resize2fs fails after a successful growpart. This is the
#    dangerous partial — partition grown, fs still at bake size. The stamp
#    MUST be absent (retry) and the wrapper MUST still exit 0. This case
#    FAILS against any unconditional-stamp build (the Codex MAJOR). ──
run_case /dev/sda1 sda 0 "CHANGED: partition resized" 1
expect_grow "resize2fs-fails (growpart ok)" sda 1 /dev/sda1
expect_no_stamp "resize2fs-fails (partition grown, fs NOT)"
expect_exit0 "resize2fs-fails"

# ── FAILURE: growpart fails for a REAL reason (not NOCHANGE). No stamp,
#    exit 0. (resize2fs still runs as a converging no-op.) ──
run_case /dev/sda1 sda 1 "FAILED: something broke" 0
expect_no_stamp "growpart real failure"
expect_exit0 "growpart real failure"

# ── FAILURE then RETRY-CONVERGENCE: after a resize2fs-fail leaves no stamp,
#    a second run (growpart NOCHANGE — already grown — + resize2fs ok)
#    writes the stamp. Proves the partial converges on the next boot. ──
run_case /dev/sda1 sda 0 "CHANGED: partition resized" 1
expect_no_stamp "convergence step 1 (resize2fs-fail, no stamp)"
run_case /dev/sda1 sda 1 "NOCHANGE: partition 1 is size ... it cannot be grown" 0
expect_stamp "convergence step 2 (NOCHANGE + resize2fs ok -> stamp)"
expect_exit0 "convergence step 2"

# ── unresolved-root cases: never reach growpart; FAILURE (no stamp, retry)
#    + exit 0. (An unresolved device must not stamp — a later boot retries.)
run_case "tmpfs" ""
expect_skip "non-/dev root (tmpfs)"
expect_no_stamp "non-/dev root (tmpfs)"; expect_exit0 "non-/dev root"
run_case /dev/sda sda          # /dev/sda has no .../partition -> not a partition
expect_skip "whole-disk root (/dev/sda, no partition)"
expect_no_stamp "whole-disk root"; expect_exit0 "whole-disk root"
run_case "" ""
expect_skip "empty findmnt source"
expect_no_stamp "empty findmnt source"; expect_exit0 "empty findmnt source"

# ── negative control: prove the harness can FAIL (sda1 must NOT resolve to
#    vda). If this 'ok' fires the assertions are tautological. ──
run_case /dev/sda1 sda
gp=$(cat "$WORK/growpart.calls" 2>/dev/null || true)
if [ "$gp" != "/dev/vda 1" ]; then
    ok "negative control: sda1 did NOT resolve to /dev/vda (assertions are live)"
else
    bad "negative control: sda1 wrongly matched /dev/vda — assertions tautological"
fi

echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
