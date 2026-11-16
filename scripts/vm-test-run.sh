#!/usr/bin/env bash
# scripts/vm-test-run.sh -- run a test command for this worktree inside an
# xpf test-runner VM, never on the workstation (#19035, user directive
# 2026-11-08: "running the dataplane on this host is a bad idea ... run them
# in a VM on tcp or udp").
#
# Usage:
#   scripts/vm-test-run.sh [--runner <remote:instance>] [--name <lane>] [--root]
#                          [--no-sync] -- <command ...>
#   scripts/vm-test-run.sh [opts] -- '<shell command string>'
#
#   With several arguments after --, they are a command and its words, quoted
#   one by one. A single argument is run as a shell command string, so
#   'XPF_REQUIRE_NETNS=1 make test-target-services-lib' works as written.
#
#   --runner   test-runner instance (default: $XPF_TEST_RUNNER, else
#              udp:xpf-testrunner). The provisioned runners are
#              tcp:xpf-testrunner{,2} and udp:xpf-testrunner{,2,3}
#              (docs/testing.md has the current list).
#   --name     per-lane directory on the runner (default: the worktree's
#              basename). Source lands in /work/<name>/src; cargo output in
#              /work/<name>/target, so incremental builds persist per lane.
#   --root     run the command as root (privileged VM legs such as
#              `make vm-test-root`); default is the unprivileged `runner` user.
#   --no-sync  skip the source sync (re-run against what is already there).
#   --separate-stderr
#              keep the command's stderr apart from its stdout (see below);
#              for a caller that parses stdout alone.
#
#   If the runner is FROZEN (a gate cell pauses its same-host runner while it
#   measures), the script waits for it to resume, up to XPF_TEST_RUNNER_WAIT_S
#   seconds (default 7200), then exits 75.
#
# Stream order (#19139): `incus exec` carries the command's stdout and stderr
# as two separate streams, and the workstation merges them (`>log 2>&1`) in
# ARRIVAL order, not write order. cargo writes `Running <target>` and `error:
# test failed` to stderr while libtest writes results to stdout, so a merged
# log spliced `error: test failed ...` into the middle of `test X ... FAILED`
# and moved `Running` lines away from their tests. By default the command
# therefore runs with `exec 2>&1`, so both leave the runner as ONE stream in
# the order they were written; the workstation then sees nothing on the
# command's stderr. --separate-stderr keeps the two apart, and then their
# relative order is NOT preserved.
#
# The sync copies tracked plus untracked-but-not-ignored files of the current
# worktree (uncommitted edits included), preserving mtimes so cargo and go
# keep their incremental state. Files deleted locally are deleted on the
# runner too: the source tree is replaced on every sync. No .git is copied;
# GOFLAGS gets -buildvcs=false.
#
# The lane's target dir is kept only when nothing is in doubt (#19134).
# cargo calls a crate fresh when no source is newer than its artefacts, so a
# kept target dir re-tested an OLD binary whenever the synced sources were
# older than the last build (another worktree, an older commit) or the last
# run changed a file on the runner and the sync put the original back. No
# mtime-based repair is attempted: the user chose "clean on any doubt". A
# per-lane ledger (/work/<name>/.xpf-src-ledger.json) records the synced
# tree's identity (a hash over every path, its content and mode) and, per
# path, the hash, mtime and mode the sync wrote. The next sync deletes the
# lane's target dir when ANY of these holds:
#   - the synced tree's identity differs from the ledger's;
#   - a file in the previous tree differs from what the sync wrote (content,
#     mtime or mode), or was deleted, or was created on the runner (outside
#     __pycache__/ directories, which no build reads);
#   - the ledger is missing, unreadable, or in an older format;
#   - scanning either tree hit an error.
# Clocks never enter the decision. The cost is a full rebuild of the lane
# after any change to the tree; an unchanged re-sync keeps the incremental
# build. Residual: a runner-side change that restores both a file's bytes AND
# its exact mtime is indistinguishable from no change.
# The deletion is confined to the lane: before anything touches it, the lane
# is opened from /work without following a symlink, and must be a directory
# on /work's filesystem with no mount point at or under it
# (/proc/self/mountinfo). The target dir is deleted through directory fds,
# never following a symlink and refusing a directory on another filesystem.
# On any doubt about the path, the sync refuses (exit 2) instead.
#
# The command runs via `bash -lc` in /work/<name>/src with
# CARGO_TARGET_DIR=/work/<name>/target, TMPDIR=/work/<name>/tmp and
# GOTMPDIR=/wtgt. The exit status is the command's.
set -euo pipefail

runner="${XPF_TEST_RUNNER:-udp:xpf-testrunner}"
name=""
as_root=0
sync=1
merge_stderr=1
while [[ $# -gt 0 ]]; do
	case "$1" in
	--runner) runner="$2"; shift 2 ;;
	--name) name="$2"; shift 2 ;;
	--root) as_root=1; shift ;;
	--no-sync) sync=0; shift ;;
	--separate-stderr) merge_stderr=0; shift ;;
	--) shift; break ;;
	-h|--help) sed -n '2,43p' "$0"; exit 0 ;;
	*) echo "vm-test-run: unknown argument: $1 (use -- before the command)" >&2; exit 2 ;;
	esac
done
if [[ $# -eq 0 ]]; then
	echo "vm-test-run: no command given (usage: $0 [opts] -- <command ...>)" >&2
	exit 2
fi

top="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "vm-test-run: run from inside a worktree" >&2; exit 2; }
[[ -n "$name" ]] || name="$(basename "$top")"
if [[ ! "$name" =~ ^[A-Za-z0-9._-]+$ || "$name" =~ ^\.+$ ]]; then
	echo "vm-test-run: lane name must match [A-Za-z0-9._-]+ and not be all dots: $name" >&2
	exit 2
fi
base="/work/${name}"

# A gate measurement cell pauses the same-host runner while it measures
# (plan section 8). Wait for it to resume rather than fail with "Instance is
# frozen". A job already running inside the VM just stalls and resumes.
#
# Read the state with `incus info`. `incus list remote:name` treats the name as
# a filter it never matches and prints nothing, so the first version of this
# loop (61e3e483e4) never saw FROZEN and never waited.
runner_status() {
	incus info "$runner" 2>/dev/null | awk 'tolower($1) == "status:" {print toupper($2); exit}'
}
waited=0
while [[ "$(runner_status)" == "FROZEN" ]]; do
	if [[ "$waited" -eq 0 ]]; then
		echo "vm-test-run: ${runner} is FROZEN by a gate cell; waiting for it to resume ..." >&2
	fi
	if [[ "$waited" -ge "${XPF_TEST_RUNNER_WAIT_S:-7200}" ]]; then
		echo "vm-test-run: ${runner} still FROZEN after ${waited}s; giving up" >&2
		exit 75
	fi
	sleep 15
	waited=$((waited + 15))
done
[[ "$waited" -gt 0 ]] && echo "vm-test-run: ${runner} no longer FROZEN after ${waited}s (state: $(runner_status))" >&2

# The runner must be a VM that was provisioned as a test runner.
if ! incus exec "$runner" -- test -f /etc/xpf-testrunner 2>/dev/null; then
	echo "vm-test-run: ${runner} is not a provisioned xpf test runner (/etc/xpf-testrunner missing)" >&2
	exit 2
fi
if [[ "$(incus exec "$runner" -- systemd-detect-virt --vm 2>/dev/null || true)" == "none" ]]; then
	echo "vm-test-run: ${runner} is not a virtual machine; refusing" >&2
	exit 2
fi

# #19134: the lane check, the keep-or-clean decision and the swap of the
# synced tree into place (see "The lane's target dir" above). Runs on the
# runner as `runner`: python3 -I - {check|sync} /work/ <name>. Exit 3 is a
# refusal it explains on stderr.
lane_py=$(
	cat <<'PY'
import hashlib, json, os, re, stat, sys

mode, parent_arg, name = sys.argv[1], sys.argv[2], sys.argv[3]
LEDGER, FORMAT = ".xpf-src-ledger.json", 3
SKIP_DIRS = {"__pycache__"}
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC


class Refuse(Exception):
    pass


def mounts_under(path):
    """Mount points at or below path, from /proc/self/mountinfo."""
    found = []
    with open("/proc/self/mountinfo", encoding="utf-8", errors="surrogateescape") as handle:
        for line in handle:
            fields = line.split()
            if len(fields) < 5:
                raise Refuse(f"unparseable /proc/self/mountinfo line: {line.strip()!r}")
            point = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), fields[4])
            if point == path or point.startswith(path + "/"):
                found.append(point)
    return found


def open_lane(pfd):
    return os.open(name, DIR_FLAGS | os.O_NOFOLLOW, dir_fd=pfd)


def lane():
    """(parent fd, lane fd), or (parent fd, None) when the lane does not exist yet.
    Refuses unless the lane is a plain directory on /work's filesystem with no
    mount point at or under it."""
    parent = os.path.realpath(parent_arg)
    pfd = os.open(parent, DIR_FLAGS)
    path = os.path.join(parent, name)
    try:
        lfd = open_lane(pfd)
    except FileNotFoundError:
        return pfd, None
    except OSError as exc:
        raise Refuse(f"{path} is not a plain directory ({exc.strerror})") from exc
    if os.fstat(lfd).st_dev != os.fstat(pfd).st_dev:
        raise Refuse(f"{path} is on another filesystem than {parent}")
    mounts = mounts_under(path)
    if mounts:
        raise Refuse(f"mount point(s) under the lane: {', '.join(mounts[:3])}")
    return pfd, lfd


def open_dir(dfd, entry_name, st):
    """Open a directory entry already lstat'ed as a directory, without following
    a symlink; a directory the owner cannot read is made readable first."""
    try:
        fd = os.open(entry_name, DIR_FLAGS | os.O_NOFOLLOW, dir_fd=dfd)
    except PermissionError:
        os.chmod(entry_name, 0o700, dir_fd=dfd)
        fd = os.open(entry_name, DIR_FLAGS | os.O_NOFOLLOW, dir_fd=dfd)
    got = os.fstat(fd)
    if (got.st_dev, got.st_ino) != (st.st_dev, st.st_ino):
        os.close(fd)
        raise Refuse(f"{entry_name} changed while it was being opened")
    return fd


def digest_fd(fd):
    h = hashlib.blake2b(digest_size=16)
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            return h.hexdigest()
        h.update(chunk)


def scan(dfd, prefix, out):
    """Every non-directory entry under dfd: {path: [digest, mtime_ns, mode]}."""
    for entry in list(os.scandir(dfd)):
        st = os.lstat(entry.name, dir_fd=dfd)
        rel = prefix + entry.name
        if stat.S_ISDIR(st.st_mode):
            if entry.name in SKIP_DIRS:
                continue
            cfd = open_dir(dfd, entry.name, st)
            try:
                scan(cfd, rel + "/", out)
            finally:
                os.close(cfd)
            continue
        if stat.S_ISLNK(st.st_mode):
            digest = "L:" + os.readlink(entry.name, dir_fd=dfd)
        elif stat.S_ISREG(st.st_mode):
            ffd = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
            try:
                digest = digest_fd(ffd)
            finally:
                os.close(ffd)
        else:
            digest = f"T:{stat.S_IFMT(st.st_mode)}"
        out[rel] = [digest, st.st_mtime_ns, stat.S_IMODE(st.st_mode)]
    return out


def scan_tree(lfd, top):
    fd = os.open(top, DIR_FLAGS | os.O_NOFOLLOW, dir_fd=lfd)
    try:
        return scan(fd, "", {})
    finally:
        os.close(fd)


def identity(files):
    h = hashlib.sha256()
    for rel in sorted(files):
        h.update(f"{rel}\0{files[rel][0]}\0{files[rel][2]:o}\n".encode("utf-8", "surrogateescape"))
    return h.hexdigest()


def purge(dfd, dev):
    """Delete everything inside dfd, fd-relatively, never following a symlink
    and refusing a directory on another filesystem."""
    for entry in list(os.scandir(dfd)):
        st = os.lstat(entry.name, dir_fd=dfd)
        if stat.S_ISDIR(st.st_mode):
            if st.st_dev != dev:
                raise Refuse(f"{entry.name} is on another filesystem")
            cfd = open_dir(dfd, entry.name, st)
            try:
                purge(cfd, dev)
            finally:
                os.close(cfd)
            os.rmdir(entry.name, dir_fd=dfd)
        else:
            os.unlink(entry.name, dir_fd=dfd)


def remove_dir(lfd, entry_name, dev):
    try:
        st = os.lstat(entry_name, dir_fd=lfd)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(st.st_mode):
        raise Refuse(f"{entry_name} in the lane is not a directory")
    fd = open_dir(lfd, entry_name, st)
    try:
        purge(fd, dev)
    finally:
        os.close(fd)
    os.rmdir(entry_name, dir_fd=lfd)


def read_ledger(lfd):
    try:
        fd = os.open(LEDGER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=lfd)
    except FileNotFoundError:
        return None, "no ledger"
    except OSError as exc:
        return None, f"unreadable ledger ({exc.strerror})"
    try:
        with os.fdopen(fd, encoding="utf-8") as handle:
            ledger = json.load(handle)
    except (OSError, ValueError) as exc:
        return None, f"unreadable ledger ({exc})"
    if not (isinstance(ledger, dict) and ledger.get("v") == FORMAT
            and isinstance(ledger.get("tree"), str) and isinstance(ledger.get("files"), dict)):
        return None, "ledger in an older format"
    return ledger, None


def sync():
    pfd, lfd = lane()
    if lfd is None:
        raise Refuse("the lane does not exist after the sync created it")
    dev = os.fstat(lfd).st_dev
    reasons = []
    ledger, why = read_ledger(lfd)
    if why:
        reasons.append(why)
    try:
        new = scan_tree(lfd, "src.new")
    except OSError as exc:
        new = None
        reasons.append(f"could not scan the synced tree ({exc})")
    if ledger is not None and new is not None:
        ledger_tree, ledger_files = ledger["tree"], ledger["files"]
        if ledger_tree != identity(new):
            reasons.append("the synced tree changed")
        try:
            old = scan_tree(lfd, "src")
        except FileNotFoundError:
            old = {}
        except OSError as exc:
            old = None
            reasons.append(f"could not scan the previous tree ({exc})")
        if old is not None:
            changed = sorted(rel for rel, rec in old.items() if ledger_files.get(rel) != rec)
            gone = sorted(rel for rel in ledger_files if rel not in old)
            if changed or gone:
                reasons.append(f"the last run changed {len(changed)} and removed {len(gone)} file(s) on the runner"
                               f" (e.g. {', '.join((changed + gone)[:3])})")
    if reasons:
        try:
            st = os.lstat("target", dir_fd=lfd)
        except FileNotFoundError:
            st = None
        if st is not None:
            if not stat.S_ISDIR(st.st_mode):
                raise Refuse("the lane's target is not a directory")
            tfd = open_dir(lfd, "target", st)
            try:
                purge(tfd, dev)
            finally:
                os.close(tfd)
        print(f"vm-test-run: cleaned the lane's target dir: {'; '.join(reasons)} (#19134)", file=sys.stderr)
    else:
        print("vm-test-run: kept the lane's build: same tree, no runner-side changes (#19134)", file=sys.stderr)
    remove_dir(lfd, "src", dev)
    os.rename("src.new", "src", src_dir_fd=lfd, dst_dir_fd=lfd)
    if new is None:
        try:
            os.unlink(LEDGER, dir_fd=lfd)
        except FileNotFoundError:
            pass
        return
    tmp = LEDGER + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=lfd)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump({"v": FORMAT, "tree": identity(new), "files": new}, handle)
    os.replace(tmp, LEDGER, src_dir_fd=lfd, dst_dir_fd=lfd)


try:
    if mode == "check":
        lane()
    elif mode == "sync":
        sync()
    else:
        raise SystemExit(f"lane_py: unknown mode {mode!r}")
except Refuse as exc:
    print(f"vm-test-run: refusing: {exc} (#19134)", file=sys.stderr)
    sys.exit(3)
PY
)
if [[ "$sync" -eq 1 ]]; then
	if ! printf '%s\n' "$lane_py" | incus exec "$runner" -- su runner -c "python3 -I - check /work/ '${name}'"; then
		echo "vm-test-run: ${base} is not a plain lane directory on ${runner}; refusing (#19134)" >&2
		exit 2
	fi
	incus exec "$runner" -- bash -c "rm -rf '${base}/src.new' && mkdir -p '${base}/src.new' '${base}/target' '${base}/tmp' && chown -R runner:runner '${base}'"
	(cd "$top" && git ls-files -z -co --exclude-standard | tar --null -T - -cf -) |
		incus exec "$runner" -- su runner -c "tar -xf - -C '${base}/src.new'"
	if ! printf '%s\n' "$lane_py" | incus exec "$runner" -- su runner -c "python3 -I - sync /work/ '${name}'"; then
		echo "vm-test-run: could not decide whether to keep the lane's build, or clean it safely, on ${runner}; refusing rather than risk testing a stale build (#19134)" >&2
		exit 2
	fi
	# testguard-run.sh runs Go tests in a private network namespace with no
	# network, so a cold module cache fails there as "setup failed". Fetch the
	# modules first, outside the guard. With a warm cache this is quick and
	# fetches nothing.
	# The download must not change the tree under test: `go mod download`
	# restores a missing /go.mod hash line in go.sum, and a test would then
	# pass on a tree that fails on the workstation. The module files are hashed
	# before and after, and the comparison prints exactly one verdict line on
	# stdout (the download's own output goes to stderr). The run proceeds only
	# on an explicit UNCHANGED line: a CHANGED line, or no verdict at all (the
	# remote shell was killed between the download and the comparison), is
	# refused. Fail closed, never open.
	if incus exec "$runner" -- test -f "${base}/src/go.mod"; then
		mod_rc=0
		mod_out=$(incus exec "$runner" -- su - runner -c "cd '${base}/src' || exit 2; h() { cat go.mod go.sum go.work go.work.sum 2>/dev/null | sha256sum; }; before=\$(h); GOFLAGS=-buildvcs=false go mod download >&2; rc=\$?; echo; if [ \"\$before\" = \"\$(h)\" ]; then echo VMTR_MODULE_FILES_UNCHANGED; else echo VMTR_MODULE_FILES_CHANGED; fi; exit \$rc") || mod_rc=$?
		mod_verdict=$(printf '%s\n' "$mod_out" | grep -xE 'VMTR_MODULE_FILES_(UN)?CHANGED' | tail -n 1 || true)
		if [[ "$mod_verdict" == VMTR_MODULE_FILES_CHANGED ]]; then
			echo "vm-test-run: go mod download changed go.mod/go.sum/go.work; the tree under test is not tidy (run 'go mod tidy' and commit); refusing" >&2
			exit 2
		elif [[ "$mod_verdict" != VMTR_MODULE_FILES_UNCHANGED ]]; then
			echo "vm-test-run: the module-file check did not complete on ${runner} (rc ${mod_rc}); refusing rather than testing a tree that may have changed" >&2
			exit 2
		elif [[ "$mod_rc" -ne 0 ]]; then
			echo "vm-test-run: warning: go mod download failed on ${runner} (rc ${mod_rc}); Go legs under testguard may fail with [setup failed]" >&2
		fi
	fi
fi

# One argument is a shell command string ('VAR=1 make test' works as
# written); several arguments are a command plus words, each quoted.
# Quoting a lone string as one word made 'VAR=1 make ...' an assignment
# with no command: it ran nothing and exited 0 (#19035, seat R10 on #19022).
if [[ $# -eq 1 ]]; then
	cmd="$1"
else
	cmd=""
	for a in "$@"; do cmd+="$(printf '%q ' "$a")"; done
fi
# GOCACHE: the Makefile defaults it to the workstation's shared
# /var/worktrees/.cache/go-build, which does not exist on a runner. Root legs
# get their own cache so they never leave root-owned entries in runner's.
gocache=/home/runner/.cache/go-build
[[ "$as_root" -eq 1 ]] && gocache=/root/.cache/go-build
env_prefix="export CARGO_TARGET_DIR='${base}/target' TMPDIR='${base}/tmp' GOTMPDIR=/wtgt GOCACHE='${gocache}' GOFLAGS='-buildvcs=false' XPF_TEST_RUNNER_LANE='${name}'; mkdir -p /wtgt 2>/dev/null || true; [ -f \"\$HOME/.cargo/env\" ] && . \"\$HOME/.cargo/env\"; cd '${base}/src' || { echo 'vm-test-run: no source tree at ${base}/src (sync it first)' >&2; exit 2; }"
# #19139: one stream, in write order (see "Stream order" above).
stream_prefix=""
[[ "$merge_stderr" -eq 1 ]] && stream_prefix="exec 2>&1; "
rc=0
# A root leg keeps HOME=/home/runner (for the toolchains), so whatever it
# wrote under runner's lane dir, module cache, cargo dir or cache is
# root-owned and breaks later unprivileged runs. Hand it back in a SEPARATE
# exec after the command: a trap in the command's own shell is skipped by
# `exec`, and its status can leak into the result. The command's status is
# already recorded in rc; this step cannot change it. A Ctrl-C or TERM to
# this script runs the same step before exiting 130/143.
root_handback() {
	# Not interruptible: a second Ctrl-C must not leave the repair half-done.
	trap '' INT TERM
	incus exec "$runner" -- find "${base}" /home/runner/go /home/runner/.cargo /home/runner/.cache \
		-xdev ! -user runner -exec chown -h runner:runner {} + >/dev/null 2>&1 || true
	trap - INT TERM
}
if [[ "$as_root" -eq 1 ]]; then
	trap 'root_handback; exit 130' INT
	trap 'root_handback; exit 143' TERM
	incus exec "$runner" -- bash -lc "${stream_prefix}export HOME=/home/runner PATH=/home/runner/.cargo/bin:\$PATH; ${env_prefix}; ${cmd}" || rc=$?
	trap - INT TERM
	root_handback
else
	incus exec "$runner" -- su - runner -c "${stream_prefix}${env_prefix}; ${cmd}" || rc=$?
fi
exit "$rc"
