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
#              tcp:xpf-testrunner{,2,3} and udp:xpf-testrunner{,2,3,4}
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
#   --allow-unproven-root
#              run a --root leg even when the runner has no VM proof for its
#              current boot (see "Disclosure" below); vm-proof=absent is
#              still printed.
#   --allow-xpf-state
#              run a --root leg even when the runner's /var/lib/xpf holds
#              state (see "Runner state" below); the entries are still listed.
#   --with-git sync a SHALLOW git repo with the tree (see "Git" below), for
#              the tests that need one: `--with-git -- make test-git-leg`.
#              The default lane name gets a -git suffix, so the git leg never
#              thrashes the plain lane's build. Refused with --no-sync and in a
#              mutation lane.
#   --cleanup-on-success
#              after a command that exits 0 (its output is already back on
#              the workstation), remove the lane on the runner with
#              scripts/runner-lane-sweep.sh --lane <name> --idle-s 0, which
#              still keeps a lane another process is using. A failing run
#              keeps its lane for inspection. Without it, idle lanes go after
#              6 h (the runner's hourly xpf-lane-sweep.timer).
#   --mutation mark this lane as a mutation lane: XPF_MUTATION_LANE=1 is set
#              in the lane, and --with-git is refused. Also set by
#              XPF_MUTATION_LANE=1 in the caller's environment (scripts/mutate.sh
#              exports it).
#
#   If the runner is FROZEN (a gate cell pauses its same-host runner while it
#   measures), the script waits for it to resume, up to XPF_TEST_RUNNER_WAIT_S
#   seconds (default 7200), then exits 75.
#
# Disclosure (#19142): every run ends with one line on stderr,
#   vm-test-run: paused-for=<s>s (workstation <s>s, runner monotonic <s>s,
#   heartbeat gaps <s>s)
# A gate cell PAUSES the runners of the host it measures (`incus pause`), and
# a run inside a paused runner freezes with it. Nothing in the run's output
# said so, and a timeout from such a run reads as a hang, a flake or a
# regression. Two clocks are read, one for each way the guest clock can behave
# across a pause: a 1 Hz heartbeat on the runner sums gaps of more than 2 s on
# its CLOCK_MONOTONIC (a guest clock that jumps across the pause), and the
# workstation's elapsed time is compared with the runner's monotonic elapsed
# time, minus 2 s of exec overhead (a guest clock that stops). It is a
# conservative stall heuristic, not proof either way:
#   - paused-for=0 means BELOW THE DETECTION THRESHOLD, not pause-free: a
#     stopped-clock pause under about 2 s, or heartbeat gaps that each stay
#     under 2 s, read as 0;
#   - a positive value means a POSSIBLE stall, including exec and start-up
#     overhead (a slow start before the heartbeat runs counts too), not a
#     stall attributed to incus;
#   - one REAL gate pause has been observed (udp:xpf-testrunner3,
#     2026-11-16 07:20:22Z-07:21:56Z, 94 s): the run reported paused-for=93s,
#     all from heartbeat gaps (workstation 1500.1 s, runner monotonic
#     1500.0 s). There the guest's CLOCK_MONOTONIC ran through the pause and
#     the heartbeat branch caught it. The wall branch stays for a guest whose
#     clock stops. No selftest pauses a real VM.
# A positive paused-for adds a line saying that a timeout or timing-sensitive
# result from the run is VOID unless re-run clean; paused-for=unknown means the
# runner's clock record could not be read.
# A --root leg also prints vm-proof=present|absent. The proof is
# /run/xpf-testguard-vm-boot-id holding the current boot ID, root-owned and
# mode 444, written by scripts/mark-test-vm.sh (testguard-run.sh applies the
# same test). Without it testguard-run.sh runs even a root leg inside
# `unshare -Urp`, where every privileged cell SKIPs. So a --root run without
# the proof is refused (exit 2) unless --allow-unproven-root is given.
#
# Runner state (#19162): /var/lib/xpf is the daemon's production state
# directory. A test that reads it (HA epoch lock, fabric-auth grace, transit
# gate ownership, ...) while an earlier root leg has left state there gets a
# verdict that depends on that leg, and nothing named the leg that wrote it.
# testguard-run.sh covers a root run with a throwaway overlay (#19084); a root
# command that bypasses it writes the real path. So, before the command, a
# --root run with a non-empty /var/lib/xpf is refused (exit 2) with the list
# and a move-aside recipe, unless --allow-xpf-state is given (then it runs and
# the list is printed); a runner-user run, which cannot write there but can
# read the world-readable files, prints the list as a warning. After a --root
# command, every entry that was not there before is named on stderr: that
# command wrote production state. The command's status is unchanged.
# A probe that FAILS is not a clean directory: a --root run is refused (or,
# with --allow-xpf-state, runs with the unknown state disclosed), and a failed
# after-probe is disclosed. A --root leg runs its probe, command, after-probe
# and report as ONE script on the runner under
# `flock -w <wait> /run/xpf-root-lane.lock`, so the lock lives exactly as
# long as the remote command: overlapping root lanes wait for each other
# (the waiter names the holder) instead of both observing an empty directory
# and claiming each other's writes. A nested --root run from inside a root
# lane (XPF_VMTR_ROOT_LANE) is refused rather than waiting on itself. The
# runner side leaves through one finalizer that ignores TERM/INT/HUP through
# its report. An INT/TERM to this script during the command ends it and
# exits 130/143, listing what /var/lib/xpf then holds with the attribution
# UNKNOWN (the lock ended with the command, so another lane may have written
# since); INT/TERM during the handback after it are ignored until it ends.
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
# Git (#19080): a handful of Go tests need a git checkout (git ls-files, git
# archive HEAD, the refactoring-audit changed set against origin/master).
# Without .git they SKIP, naming `make test-git-leg`. --with-git adds a .git to
# the synced tree: a shallow repo holding HEAD and its history down to the
# merge-base with the base ref (XPF_AUDIT_BASE_REF, default origin/master),
# with refs/remotes/origin/master AT that merge-base and the index read from
# HEAD. It is built on the workstation from the local object store (nothing is
# fetched from a remote) and lands in the lane like any other synced path, so
# the next plain sync removes it. A mutation lane must contain no git metadata
# (a mutant "restored" through git, or a cell that reads git state, would
# score against the wrong tree), so --with-git is refused there.
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
#   - a path of the previous tree differs from what the sync wrote (a file's
#     content, mtime or mode; a directory's existence or mode), or was deleted,
#     or was created on the runner. The one exemption: an entry the RUNNER
#     created inside a __pycache__ directory (Python's bytecode cache). A
#     SYNCED __pycache__ path is in the tree's identity like any other;
#   - the ledger is missing, unreadable, or in an older format;
#   - scanning either tree hit an error.
# Clocks never enter the decision. The cost is a full rebuild of the lane
# after any change to the tree; an unchanged re-sync keeps the incremental
# build. Residual: a runner-side change that restores both a file's bytes AND
# its exact mtime is indistinguishable from no change.
# Threat model for the deletion: a runner is single-tenant and every writer on
# it is one of our own lanes. What is defended against is ACCIDENTAL aliasing
# that exists when the sync starts: a lane that is a symlink to another lane
# (/work/alias -> /work/other), a bind mount under a lane, a stale lane. A
# concurrent adversary renaming lanes or adding bind mounts while a sync runs
# is out of scope; in particular a same-filesystem bind mount added under the
# target after the check is not seen. Within that model: ONE process, run as
# root, does every destructive step (removing and creating src.new, handing
# files to runner, the extraction, the clean, the swap) while holding the
# lane's directory fd. It opens /work/<name> from /work without following a
# symlink and requires a directory on /work's filesystem with no mount point
# at or under it (/proc/self/mountinfo). Every deletion and chown goes through
# directory fds, never follows a symlink, checks each directory's identity and
# filesystem (the target dir's root included), and repairs an unreadable
# directory through an O_PATH handle on that same object. On any doubt about
# the path the sync refuses (exit 2) instead.
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
allow_unproven_root=0
allow_xpf_state=0
with_git=0
mutation=0
cleanup_on_success=0
[[ -n "${XPF_MUTATION_LANE:-}" ]] && mutation=1
while [[ $# -gt 0 ]]; do
	case "$1" in
	--runner) runner="$2"; shift 2 ;;
	--name) name="$2"; shift 2 ;;
	--root) as_root=1; shift ;;
	--no-sync) sync=0; shift ;;
	--separate-stderr) merge_stderr=0; shift ;;
	--allow-unproven-root) allow_unproven_root=1; shift ;;
	--allow-xpf-state) allow_xpf_state=1; shift ;;
	--with-git) with_git=1; shift ;;
	--mutation) mutation=1; shift ;;
	--cleanup-on-success) cleanup_on_success=1; shift ;;
	--) shift; break ;;
	# The whole leading comment block, however long it grows (a fixed line
	# range went stale twice as the header grew).
	-h|--help) awk 'NR == 1 { next } /^#/ { print; next } { exit }' "$0"; exit 0 ;;
	*) echo "vm-test-run: unknown argument: $1 (use -- before the command)" >&2; exit 2 ;;
	esac
done
if [[ $# -eq 0 ]]; then
	echo "vm-test-run: no command given (usage: $0 [opts] -- <command ...>)" >&2
	exit 2
fi

if [[ "$with_git" -eq 1 && "$mutation" -eq 1 ]]; then
	echo "vm-test-run: refusing --with-git in a mutation lane (--mutation or XPF_MUTATION_LANE=${XPF_MUTATION_LANE:-}): a mutation sandbox must contain no git metadata (#19080)" >&2
	exit 2
fi
if [[ "$with_git" -eq 1 && "$sync" -eq 0 ]]; then
	echo "vm-test-run: refusing --with-git with --no-sync: the shallow repo is part of the sync (#19080)" >&2
	exit 2
fi

top="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "vm-test-run: run from inside a worktree" >&2; exit 2; }
if [[ -z "$name" ]]; then
	name="$(basename "$top")"
	[[ "$with_git" -eq 1 ]] && name="${name}-git"
fi
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
# wait_unfrozen [soft]: wait (up to XPF_TEST_RUNNER_WAIT_S) while the runner
# is FROZEN; exits 75 when it never resumes, or with "soft" returns 1 instead
# (after the command, whose status must survive).
wait_unfrozen() {
	local waited=0
	while [[ "$(runner_status)" == "FROZEN" ]]; do
		if [[ "$waited" -eq 0 ]]; then
			echo "vm-test-run: ${runner} is FROZEN by a gate cell; waiting for it to resume ..." >&2
		fi
		if [[ "$waited" -ge "${XPF_TEST_RUNNER_WAIT_S:-7200}" ]]; then
			echo "vm-test-run: ${runner} still FROZEN after ${waited}s; giving up" >&2
			[[ "${1:-}" == soft ]] && return 1
			exit 75
		fi
		sleep 15
		waited=$((waited + 15))
	done
	if [[ "$waited" -gt 0 ]]; then
		echo "vm-test-run: ${runner} no longer FROZEN after ${waited}s (state: $(runner_status))" >&2
	fi
}
wait_unfrozen

# The runner must be a VM that was provisioned as a test runner.
if ! incus exec "$runner" -- test -f /etc/xpf-testrunner 2>/dev/null; then
	echo "vm-test-run: ${runner} is not a provisioned xpf test runner (/etc/xpf-testrunner missing)" >&2
	exit 2
fi
if [[ "$(incus exec "$runner" -- systemd-detect-virt --vm 2>/dev/null || true)" == "none" ]]; then
	echo "vm-test-run: ${runner} is not a virtual machine; refusing" >&2
	exit 2
fi

# #19134: one process prepares the lane, extracts the synced tree, decides
# whether to keep the build, cleans it if not, and swaps the tree into place
# (see "The lane's target dir" above). It runs on the runner as root, holding
# the lane's directory fd from the first check to the last write:
#   python3 -I -c "$lane_py" sync /work/ <name>   (the tar stream on stdin)
# Exit 3 is a refusal it explains on stderr.
lane_py=$(
	cat <<'PY'
import hashlib, json, os, pwd, re, stat, subprocess, sys

mode, parent_arg, name = sys.argv[1], sys.argv[2], sys.argv[3]
LEDGER, FORMAT = ".xpf-src-ledger.json", 4
CACHE_DIR = "__pycache__"
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


def real_root():
    """Root in the initial user namespace: only then are files handed to runner."""
    if os.geteuid() != 0:
        return False
    try:
        with open("/proc/self/uid_map", encoding="ascii") as handle:
            return handle.read().split() == ["0", "0", "4294967295"]
    except OSError:
        return False


def lane():
    """The lane's fd. Creates the lane if it does not exist; refuses unless it
    is a plain directory on the parent's filesystem with no mount point at or
    under it."""
    parent = os.path.realpath(parent_arg)
    pfd = os.open(parent, DIR_FLAGS)
    path = os.path.join(parent, name)
    try:
        lfd = open_lane(pfd)
    except FileNotFoundError:
        os.mkdir(name, 0o755, dir_fd=pfd)
        lfd = open_lane(pfd)
    except OSError as exc:
        raise Refuse(f"{path} is not a plain directory ({exc.strerror})") from exc
    if os.fstat(lfd).st_dev != os.fstat(pfd).st_dev:
        raise Refuse(f"{path} is on another filesystem than {parent}")
    mounts = mounts_under(path)
    if mounts:
        raise Refuse(f"mount point(s) under the lane: {', '.join(mounts[:3])}")
    os.close(pfd)
    return lfd


def open_dir(dfd, entry_name, st):
    """Open a directory entry already lstat'ed as st, never following a
    symlink. A directory the caller cannot read is made readable through an
    O_PATH handle on that same object, never by name."""
    try:
        fd = os.open(entry_name, DIR_FLAGS | os.O_NOFOLLOW, dir_fd=dfd)
    except PermissionError:
        handle = os.open(entry_name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        try:
            got = os.fstat(handle)
            if not stat.S_ISDIR(got.st_mode) or (got.st_dev, got.st_ino) != (st.st_dev, st.st_ino):
                raise Refuse(f"{entry_name} changed while it was being opened")
            os.chmod(f"/proc/self/fd/{handle}", 0o700)
            fd = os.open(f"/proc/self/fd/{handle}", DIR_FLAGS)
        finally:
            os.close(handle)
    got = os.fstat(fd)
    if (got.st_dev, got.st_ino) != (st.st_dev, st.st_ino):
        os.close(fd)
        raise Refuse(f"{entry_name} changed while it was being opened")
    return fd


def child_dir(dfd, entry_name, dev):
    """(fd, stat) of a directory entry that must be a real directory on dev,
    or (None, None) when it does not exist."""
    try:
        st = os.lstat(entry_name, dir_fd=dfd)
    except FileNotFoundError:
        return None, None
    if not stat.S_ISDIR(st.st_mode):
        raise Refuse(f"{entry_name} in the lane is not a directory")
    if st.st_dev != dev:
        raise Refuse(f"{entry_name} in the lane is on another filesystem")
    return open_dir(dfd, entry_name, st), st


def digest_fd(fd):
    h = hashlib.blake2b(digest_size=16)
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            return h.hexdigest()
        h.update(chunk)


def scan(dfd, prefix, out):
    """Every entry under dfd: {path: [digest, mtime_ns, mode]}. A directory is
    recorded by existence and mode ("D", no mtime: its mtime moves with every
    entry made in it)."""
    for entry in list(os.scandir(dfd)):
        st = os.lstat(entry.name, dir_fd=dfd)
        rel = prefix + entry.name
        if stat.S_ISDIR(st.st_mode):  # a directory: existence and mode
            out[rel] = ["D", None, stat.S_IMODE(st.st_mode)]
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


def scan_tree(lfd, top, dev):
    fd, _ = child_dir(lfd, top, dev)
    if fd is None:
        raise FileNotFoundError(top)
    try:
        return scan(fd, "", {})
    finally:
        os.close(fd)


def identity(files):
    h = hashlib.sha256()
    for rel in sorted(files):
        h.update(f"{rel}\0{files[rel][0]}\0{files[rel][2]:o}\n".encode("utf-8", "surrogateescape"))
    return h.hexdigest()


def runner_cache(rel):
    """A __pycache__ directory, or an entry inside one. Only a RUNNER-CREATED
    one is exempt from the runner-change check: a synced one is in the tree's
    identity like any other path."""
    parts = rel.split("/")
    return CACHE_DIR in parts


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
    fd, _ = child_dir(lfd, entry_name, dev)
    if fd is None:
        return
    try:
        purge(fd, dev)
    finally:
        os.close(fd)
    os.rmdir(entry_name, dir_fd=lfd)


def chown_tree(dfd, dev, uid, gid):
    """Hand every entry under dfd to uid:gid, fd-relatively, never following a
    symlink (root legs leave root-owned files behind)."""
    for entry in list(os.scandir(dfd)):
        st = os.lstat(entry.name, dir_fd=dfd)
        if (st.st_uid, st.st_gid) != (uid, gid):
            os.chown(entry.name, uid, gid, dir_fd=dfd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            if st.st_dev != dev:
                raise Refuse(f"{entry.name} is on another filesystem")
            cfd = open_dir(dfd, entry.name, st)
            try:
                chown_tree(cfd, dev, uid, gid)
            finally:
                os.close(cfd)


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


def extract(lfd, dev, owner):
    """tar -x of stdin inside src.new, as runner when we are root."""
    fd, _ = child_dir(lfd, "src.new", dev)
    def enter():
        os.fchdir(fd)
        if owner:
            os.setgroups([])
            os.setgid(owner[1])
            os.setuid(owner[0])
    try:
        done = subprocess.run(["tar", "-xf", "-"], preexec_fn=enter, pass_fds=(fd,), check=False)
    finally:
        os.close(fd)
    if done.returncode != 0:
        raise SystemExit(f"vm-test-run: tar -x into the lane failed (rc {done.returncode})")


def sync():
    lfd = lane()
    dev = os.fstat(lfd).st_dev
    owner = None
    if real_root():
        user = pwd.getpwnam("runner")
        owner = (user.pw_uid, user.pw_gid)
    # Prepare: a fresh src.new, the lane's target and tmp dirs, all runner's.
    remove_dir(lfd, "src.new", dev)
    os.mkdir("src.new", 0o755, dir_fd=lfd)
    for keep in ("target", "tmp"):
        fd, _ = child_dir(lfd, keep, dev)
        if fd is None:
            os.mkdir(keep, 0o755, dir_fd=lfd)
        else:
            os.close(fd)
    if owner:
        os.chown(lfd, *owner)
        chown_tree(lfd, dev, *owner)
    extract(lfd, dev, owner)
    # Decide.
    reasons = []
    ledger, why = read_ledger(lfd)
    if why:
        reasons.append(why)
    try:
        new = scan_tree(lfd, "src.new", dev)
    except OSError as exc:
        new = None
        reasons.append(f"could not scan the synced tree ({exc})")
    if ledger is not None and new is not None:
        ledger_tree, ledger_files = ledger["tree"], ledger["files"]
        if ledger_tree != identity(new):
            reasons.append("the synced tree changed")
        try:
            old = scan_tree(lfd, "src", dev)
        except FileNotFoundError:
            old = {}
        except OSError as exc:
            old = None
            reasons.append(f"could not scan the previous tree ({exc})")
        if old is not None:
            changed = sorted(rel for rel, rec in old.items()
                             if ledger_files.get(rel) != rec and not (rel not in ledger_files and runner_cache(rel)))
            gone = sorted(rel for rel in ledger_files if rel not in old)
            if changed or gone:
                reasons.append(f"the last run changed {len(changed)} and removed {len(gone)} path(s) on the runner"
                               f" (e.g. {', '.join((changed + gone)[:3])})")
    # Clean, swap, record.
    if reasons:
        tfd, _ = child_dir(lfd, "target", dev)
        if tfd is not None:
            try:
                if os.fstat(tfd).st_dev != dev:
                    raise Refuse("the lane's target is on another filesystem")
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
    if owner:
        os.fchown(fd, *owner)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump({"v": FORMAT, "tree": identity(new), "files": new}, handle)
    os.replace(tmp, LEDGER, src_dir_fd=lfd, dst_dir_fd=lfd)


try:
    if mode == "sync":
        sync()
    else:
        raise SystemExit(f"lane_py: unknown mode {mode!r}")
except Refuse as exc:
    print(f"vm-test-run: refusing: {exc} (#19134)", file=sys.stderr)
    sys.exit(3)
PY
)
# --with-git (#19080, see "Git" above): build the shallow repo the sync adds
# as .git. Prints its directory; the caller removes it after the sync.
build_shallow_git() {
	local head mb n common dir
	head=$(git -C "$top" rev-parse --verify --quiet 'HEAD^{commit}') ||
		{ echo "vm-test-run: --with-git: no commit at HEAD (#19080)" >&2; return 1; }
	mb=$(git -C "$top" merge-base "${XPF_AUDIT_BASE_REF:-origin/master}" "$head") ||
		{ echo "vm-test-run: --with-git: no merge-base between ${XPF_AUDIT_BASE_REF:-origin/master} and HEAD; fetch it or set XPF_AUDIT_BASE_REF (#19080)" >&2; return 1; }
	n=$(git -C "$top" rev-list --count "${mb}..${head}") || return 1
	common=$(git -C "$top" rev-parse --path-format=absolute --git-common-dir) || return 1
	{ [[ -n "${TMPDIR:-}" ]] || mkdir -p /var/worktrees/.cache/tmpdir; } &&
		dir=$(mktemp -d "${TMPDIR:-/var/worktrees/.cache/tmpdir}/vmtr-git.XXXXXX") || return 1
	printf '%s\n' "$dir"
	if git init -q --template= "$dir" &&
		git -C "$dir" fetch -q --no-tags --depth="$((n + 1))" \
			--upload-pack='git -c uploadpack.allowAnySHA1InWant=true upload-pack' \
			"file://${common}" "$head" &&
		git -C "$dir" update-ref refs/heads/xpf-lane "$head" &&
		git -C "$dir" symbolic-ref HEAD refs/heads/xpf-lane &&
		git -C "$dir" update-ref refs/remotes/origin/master "$mb" &&
		git -C "$dir" read-tree HEAD &&
		[[ "$(git -C "$dir" merge-base refs/remotes/origin/master HEAD)" == "$mb" ]]; then
		echo "vm-test-run: --with-git: shallow repo: HEAD ${head:0:12}, origin/master = merge-base ${mb:0:12} (${n} commit(s) apart) (#19080)" >&2
		return 0
	fi
	echo "vm-test-run: --with-git: could not build the shallow repo (#19080)" >&2
	return 1
}
git_root=""
if [[ "$with_git" -eq 1 ]]; then
	if ! git_root=$(build_shallow_git); then
		[[ -n "$git_root" ]] && rm -rf -- "$git_root"
		exit 2
	fi
fi
if [[ "$sync" -eq 1 ]]; then
	sync_rc=0
	(cd "$top" && git ls-files -z -co --exclude-standard |
		tar --null -cf - -T - ${git_root:+-C "$git_root" .git}) |
		incus exec "$runner" -- python3 -I -c "$lane_py" sync /work/ "${name}" || sync_rc=$?
	[[ -n "$git_root" ]] && rm -rf -- "$git_root"
	if [[ "$sync_rc" -ne 0 ]]; then
		echo "vm-test-run: could not prepare, decide on, or safely clean ${base} on ${runner}; refusing rather than risk testing a stale build (#19134)" >&2
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
# #19080: a mutation lane says so to everything it runs.
[[ "$mutation" -eq 1 ]] && env_prefix+="; export XPF_MUTATION_LANE=1"
# #19139: one stream, in write order (see "Stream order" above).
stream_prefix=""
[[ "$merge_stderr" -eq 1 ]] && stream_prefix="exec 2>&1; "
# #19142: the VM proof for a root leg (see "Disclosure" above). The same test
# testguard-run.sh applies; prints present or absent.
vm_proof_sh=$(
	cat <<'SH'
# vm-proof (#19142)
p=/run/xpf-testguard-vm-boot-id
b=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || b=
if [ -n "$b" ] && [ -f "$p" ] && [ ! -L "$p" ] &&
	[ "$(stat -c '%u %a' "$p" 2>/dev/null)" = "0 444" ] &&
	[ "$(cat "$p" 2>/dev/null)" = "$b" ]; then
	echo present
else
	echo absent
fi
SH
)
if [[ "$as_root" -eq 1 ]]; then
	vm_proof=$(incus exec "$runner" -- bash -c "$vm_proof_sh" 2>/dev/null) || vm_proof=
	[[ "$vm_proof" == present || "$vm_proof" == absent ]] || vm_proof=unknown
	echo "vm-test-run: vm-proof=${vm_proof} on ${runner} (#19142)" >&2
	if [[ "$vm_proof" != present && "$allow_unproven_root" -ne 1 ]]; then
		echo "vm-test-run: refusing a --root run without the VM proof: testguard-run.sh would run it inside unshare -Urp, where every privileged cell SKIPs. As root on the runner, run scripts/mark-test-vm.sh (the proof is in /run, so once per boot), or pass --allow-unproven-root to run with vm-proof=${vm_proof} disclosed (#19142)" >&2
		exit 2
	fi
fi

# #19162: the runner's /var/lib/xpf (see "Runner state" above).
#
# The probe answers with ONE status line: XPF_STATE=absent, XPF_STATE=empty,
# XPF_STATE=nonempty (followed by one entry per line), or XPF_STATE=error
# <why>. Anything else, including a failed `incus exec`, is an error. Only an
# OBSERVED absent or empty directory admits a --root run without
# --allow-xpf-state: a probe that failed is not a clean directory.
xpf_state_sh='# xpf-state (#19162)
d=/var/lib/xpf
if [ ! -e "$d" ] && [ ! -L "$d" ]; then echo XPF_STATE=absent; exit 0; fi
if [ ! -d "$d" ]; then echo "XPF_STATE=error $d is not a directory"; exit 0; fi
if ! l=$(ls -A1 "$d" 2>&1); then echo "XPF_STATE=error $l"; exit 0; fi
if [ -z "$l" ]; then echo XPF_STATE=empty; else echo XPF_STATE=nonempty; printf "%s\n" "$l"; fi'
# xpf_state_probe <var>: sets <var>_status (absent|empty|nonempty|error) and
# <var>_entries (one per line; for error, the reason).
before_status='' before_entries='' after_status='' after_entries=''
xpf_state_probe() {
	local out first
	out=$(incus exec "$runner" -- bash -c "$xpf_state_sh" 2>&1) || out="XPF_STATE=error incus exec failed: ${out//$'\n'/ }"
	first=${out%%$'\n'*}
	case "$first" in
	XPF_STATE=absent | XPF_STATE=empty) printf -v "$1_status" '%s' "${first#XPF_STATE=}"; printf -v "$1_entries" '' ;;
	XPF_STATE=nonempty)
		printf -v "$1_status" nonempty
		printf -v "$1_entries" '%s' "${out#*$'\n'}"
		;;
	XPF_STATE=error*) printf -v "$1_status" error; printf -v "$1_entries" '%s' "${first#XPF_STATE=error }" ;;
	*) printf -v "$1_status" error; printf -v "$1_entries" 'unrecognised probe output: %s' "${first:0:120}" ;;
	esac
}

# #19162: a --root leg runs as ONE script on the runner, under
# `flock -w <wait> /run/xpf-root-lane.lock`: the before-probe and admission,
# the command, the after-probe and the report all run inside it, so the lock
# lives exactly as long as the remote command that needs it. Two root lanes
# on one runner therefore cannot both observe a clean directory, or claim
# each other's writes. (An earlier draft held the lock from a separate,
# FIFO-fed remote process. Its lifetime differed from the command's: it
# could outlive a dead orchestrator through an inherited descriptor, or be
# released while the command ran on. Codex on b7f.) A runner-user leg cannot
# write /var/lib/xpf; it only warns about what it may read.
if [[ "$as_root" -eq 1 && -n "${XPF_VMTR_ROOT_LANE:-}" ]]; then
	echo "vm-test-run: refusing a nested --root run: this process runs inside a root lane (XPF_VMTR_ROOT_LANE), which holds ${runner}'s root-lane lock; it would wait on itself (#19162)" >&2
	exit 2
fi
if [[ "$as_root" -eq 0 ]]; then
	xpf_state_probe before
	if [[ "$before_status" == nonempty ]]; then
		echo "vm-test-run: warning: ${runner}:/var/lib/xpf holds state from an earlier root leg ($(tr '\n' ' ' <<<"$before_entries" | sed 's/ $//')); a test that reads it depends on that leg (#19162)" >&2
	elif [[ "$before_status" == error ]]; then
		echo "vm-test-run: warning: ${runner}:/var/lib/xpf could not be inspected (${before_entries}), so it is not known to be clean (#19162)" >&2
	fi
fi
# The root-lane script. It reads its parameters from the environment the
# remote command line exports (VMTR_*, XPF_STATE_DIR); the command itself
# replaces @WRAPPED@.
root_lane_sh=$(
	cat <<'SH'
# vm-test-run root lane (#19162): runs under the runner's root-lane lock.
set -u
# This invocation's own copy; bash keeps it open, so it can go now.
rm -f -- "$0" 2>/dev/null
# How long this lane waited for the lock: the workstation does not count it
# as a pause (the heartbeat starts only after it).
awk -v t0="${VMTR_PRELOCK_UPTIME:-}" '{ if (t0 != "") printf "%.1f\n", $1 - t0 }' /proc/uptime >"$VMTR_LOCKWAIT_FILE" 2>/dev/null || true
export XPF_VMTR_ROOT_LANE=1
printf '%s\n' "$VMTR_OWNER" >"$VMTR_ROOT_OWNER" 2>/dev/null || true
probe() {
	d=$XPF_STATE_DIR
	if [ ! -e "$d" ] && [ ! -L "$d" ]; then echo XPF_STATE=absent; return; fi
	if [ ! -d "$d" ]; then echo "XPF_STATE=error $d is not a directory"; return; fi
	if ! l=$(ls -A1 "$d" 2>&1); then echo "XPF_STATE=error $l"; return; fi
	if [ -z "$l" ]; then echo XPF_STATE=empty; else echo XPF_STATE=nonempty; printf '%s\n' "$l"; fi
}
entries() { printf '%s\n' "$1" | tail -n +2 | grep -v '^$'; }
before=$(probe)
bstatus=${before%%$'\n'*}
seen=
case "$bstatus" in
XPF_STATE=nonempty) seen="holds state an earlier root leg left ($(entries "$before" | tr '\n' ' ' | sed 's/ $//'))" ;;
XPF_STATE=error*) seen="could not be inspected (${bstatus#XPF_STATE=error }), so it is not known to be clean" ;;
esac
if [ -n "$seen" ]; then
	if [ "$VMTR_ALLOW_XPF_STATE" != 1 ]; then
		echo "vm-test-run: refusing a --root run: ${VMTR_RUNNER}:${XPF_STATE_DIR} ${seen}, and tests read that production path. Move it aside when no root lane is running there, e.g. as root on the runner: d=/var/lib/xpf-residue/\$(date -u +%Y%m%dT%H%M%SZ); mkdir -p \$d && find /var/lib/xpf -mindepth 1 -maxdepth 1 -exec mv -t \$d {} + ; or pass --allow-xpf-state to run with it disclosed (#19162)" >&2
		exit 2
	fi
	echo "vm-test-run: warning: ${VMTR_RUNNER}:${XPF_STATE_DIR} ${seen}; a test that reads it depends on that (#19162)" >&2
fi
report() {
	after=$(probe)
	astatus=${after%%$'\n'*}
	case "$astatus" in
	XPF_STATE=error*)
		echo "vm-test-run: could not inspect ${VMTR_RUNNER}:${XPF_STATE_DIR} after the --root command (${astatus#XPF_STATE=error }); whether it wrote production state is unknown (#19162)" >&2
		return 0 ;;
	esac
	case "$bstatus" in
	XPF_STATE=error*)
		if [ -n "$(entries "$after")" ]; then
			echo "vm-test-run: ${VMTR_RUNNER}:${XPF_STATE_DIR} holds $(entries "$after" | tr '\n' ' ' | sed 's/ $//') after the --root command; the before-probe failed, so what it added is unknown (#19162)" >&2
		fi
		return 0 ;;
	esac
	new=$(comm -13 <(entries "$before" | sort) <(entries "$after" | sort) | tr '\n' ' ')
	if [ -n "$new" ]; then
		echo "vm-test-run: this --root command wrote production state to ${VMTR_RUNNER}:${XPF_STATE_DIR}: ${new% } (#19162)" >&2
	fi
}
# finalize <status>: the one way out, on the normal path and on a signal.
# It IGNORES TERM/INT/HUP first and keeps them ignored through the report
# and the exit (fold of Codex on b7g, F9: the normal path used to restore
# the default actions before reporting, so a TERM then killed the report).
# Idempotent: a second entry returns at once.
cmd_pid=
finalized=
finalize() {
	trap '' TERM INT HUP
	[ -n "$finalized" ] && return 0
	finalized=1
	if [ -n "$cmd_pid" ] && kill -0 "$cmd_pid" 2>/dev/null; then
		kill "$cmd_pid" 2>/dev/null
		wait "$cmd_pid" 2>/dev/null
	fi
	report
	exit "$1"
}
trap 'finalize 143' TERM
trap 'finalize 130' INT
trap 'finalize 129' HUP
(
@WRAPPED@
) &
cmd_pid=$!
wait "$cmd_pid"
finalize "$?"
SH
)
# interrupted_report: the workstation's best effort after INT/TERM ended the
# root command. Ending the client ends the remote lane and releases its lock,
# so another root lane may already be running and writing: nothing seen now
# can be attributed to this command (fold of Codex on b7g, F8). It reports
# what /var/lib/xpf holds, and says the attribution is unknown.
interrupted_report() {
	xpf_state_probe after
	case "$after_status" in
	error) echo "vm-test-run: the --root command was interrupted, and ${runner}:/var/lib/xpf could not be inspected (#19162)" >&2 ;;
	nonempty) echo "vm-test-run: the --root command was interrupted; ${runner}:/var/lib/xpf now holds: $(printf '%s\n' "$after_entries" | grep -v '^$' | tr '\n' ' ' | sed 's/ $//') (attribution unknown: its lock ended with it, so another root lane may have written since) (#19162)" >&2 ;;
	esac
	return 0
}

# #19142: the runner-side heartbeat (see "Disclosure" above). It writes
# "<start> <last> <gaps> <samples>" (CLOCK_MONOTONIC ns) to its file once a
# second and on SIGTERM, exits 0 on SIGTERM (so bash prints no job notice into
# the command's output), and stops on its own if its shell goes away. It is
# passed inside single quotes, so it must contain none.
heartbeat_py=$(
	cat <<'PY'
import os, signal, sys, time
SECOND = 1000000000
path, parent = sys.argv[1], os.getppid()
start = last = time.monotonic_ns()
gaps = samples = 0
def save(now):
    tmp = path + ".tmp"
    with open(tmp, "w") as handle:
        handle.write(f"{start} {now} {gaps} {samples}\n")
    os.replace(tmp, path)
def sample():
    global last, gaps, samples
    now = time.monotonic_ns()
    if now - last > 2 * SECOND:
        gaps += now - last - SECOND
    last, samples = now, samples + 1
    save(now)
def stop(*_):
    sample()
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
save(start)
while os.getppid() == parent:
    time.sleep(1)
    sample()
PY
)
if [[ "$heartbeat_py" == *"'"* ]]; then
	echo "vm-test-run: internal error: the heartbeat program contains a single quote" >&2
	exit 2
fi
clock_file="${base}/tmp/.vmtr-clock.$$.${RANDOM}"
# The command starts only once the heartbeat has written its first record (or
# after 3 s), so a short command still leaves one.
clock_start="mkdir -p '${base}/tmp'; python3 -I -c '${heartbeat_py}' '${clock_file}' </dev/null >/dev/null 2>&1 & vmtr_hb=\$!; disown \$vmtr_hb 2>/dev/null; vmtr_n=0; while [ ! -s '${clock_file}' ] && [ \$vmtr_n -lt 60 ]; do sleep 0.05; vmtr_n=\$((vmtr_n + 1)); done; "
# The command runs in a subshell between newlines, so its own `exit` and a
# trailing `# comment` behave as before; its status is the run's.
clock_stop="vmtr_rc=\$?; kill \$vmtr_hb 2>/dev/null; for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do kill -0 \$vmtr_hb 2>/dev/null || break; sleep 0.1; done; exit \$vmtr_rc"
wrapped="${clock_start}(
${cmd}
); ${clock_stop}"
# ws_now: the workstation's own uptime clock, which no NTP step moves.
ws_now() { awk '{print $1}' /proc/uptime; }

rc=0
# A root leg keeps HOME=/home/runner (for the toolchains), so whatever it
# wrote under runner's lane dir, module cache, cargo dir or cache is
# root-owned and breaks later unprivileged runs. Hand it back in a SEPARATE
# exec after the command: a trap in the command's own shell is skipped by
# `exec`, and its status can leak into the result. The command's status is
# already recorded in rc; this step cannot change it. A Ctrl-C or TERM to
# this script runs the same step before exiting 130/143.
root_handback() {
	# Its callers ignore INT/TERM around it: a second Ctrl-C must not leave the
	# repair half-done. It does not touch the traps itself (F9: resetting them
	# here re-armed the default action mid-finalization).
	incus exec "$runner" -- find "${base}" /home/runner/go /home/runner/.cargo /home/runner/.cache \
		-xdev ! -user runner -exec chown -h runner:runner {} + >/dev/null 2>&1 || true
}
# root_interrupted <status>: INT/TERM during a --root command. End the
# command (closing the client ends the remote lane, and its lock), report
# best effort, hand files back, exit with the signal's status.
root_interrupted() {
	trap '' INT TERM
	if [[ -n "${root_cmd_pid:-}" ]]; then
		kill "$root_cmd_pid" 2>/dev/null || true
		wait "$root_cmd_pid" 2>/dev/null || true
	fi
	if wait_unfrozen soft; then interrupted_report || true; fi
	root_handback
	exit "$1"
}
if [[ "$as_root" -eq 1 ]]; then
	trap 'root_interrupted 130' INT
	trap 'root_interrupted 143' TERM
	# Per invocation: two runs of one lane name must not share (and
	# overwrite) the script.
	lane_script="${base}/tmp/.vmtr-root-lane.$$.sh"
	lane_lockwait="${base}/tmp/.vmtr-lockwait.$$"
	# The replacement is QUOTED: bash 5.2's patsub_replacement would otherwise
	# turn every `&` in the command (`2>&1`, `&&`) into the matched pattern.
	printf '%s\n' "${root_lane_sh/@WRAPPED@/"$wrapped"}" |
		incus exec "$runner" -- bash -c "mkdir -p '${base}/tmp' && cat >'${lane_script}'"
	owner="lane=${name} pid=$$ host=$(hostname -s 2>/dev/null || echo unknown) since=$(date -u +%FT%TZ)"
	lock_wait=${XPF_TEST_RUNNER_WAIT_S:-7200}
	lane_env="export XPF_STATE_DIR=/var/lib/xpf VMTR_ROOT_OWNER=/run/xpf-root-lane.owner VMTR_LOCKWAIT_FILE='${lane_lockwait}' VMTR_ALLOW_XPF_STATE=${allow_xpf_state} VMTR_RUNNER='${runner}' VMTR_OWNER='${owner}'"
	lock_wait_note="if ! flock -n /run/xpf-root-lane.lock true 2>/dev/null; then echo \"vm-test-run: waiting for another --root run on ${runner} to finish (holder: \$(cat /run/xpf-root-lane.owner 2>/dev/null || echo unknown)) (#19162)\" >&2; fi"
	ws_t0=$(ws_now)
	# In the background, so a TERM to this script runs root_interrupted now
	# rather than after the command ends (bash defers traps for a foreground
	# child). A non-interactive shell gives it /dev/null as stdin.
	incus exec "$runner" -- bash -lc "${stream_prefix}export HOME=/home/runner PATH=/home/runner/.cargo/bin:\$PATH; ${env_prefix}; ${lane_env}; ${lock_wait_note}; export VMTR_PRELOCK_UPTIME=\$(cut -d' ' -f1 /proc/uptime); exec flock -w ${lock_wait} -E 75 /run/xpf-root-lane.lock bash '${lane_script}'" &
	root_cmd_pid=$!
	wait "$root_cmd_pid" || rc=$?
	root_cmd_pid=
	ws_t1=$(ws_now)
	# Finalization: the remote lane already reported. INT/TERM are IGNORED
	# until the handback completes, so a signal here cannot cut it short
	# (Codex on b7f, F9); the command's status is already in rc.
	trap '' INT TERM
	root_handback
	trap - INT TERM
else
	ws_t0=$(ws_now)
	incus exec "$runner" -- su - runner -c "${stream_prefix}${env_prefix}; ${wrapped}" || rc=$?
	ws_t1=$(ws_now)
fi

# #19142: the pause verdict (see "Disclosure" above).
clock=
lock_waited=0
if wait_unfrozen soft; then
	clock=$(incus exec "$runner" -- bash -c "cat '${clock_file}' 2>/dev/null; rm -f '${clock_file}' '${clock_file}.tmp'" 2>/dev/null) || clock=
	# #19162: a --root lane's wait for the root-lane lock is not a pause.
	if [[ "$as_root" -eq 1 ]]; then
		lock_waited=$(incus exec "$runner" -- bash -c "cat '${lane_lockwait}' 2>/dev/null; rm -f '${lane_lockwait}'" 2>/dev/null) || lock_waited=0
		[[ "$lock_waited" =~ ^[0-9]+(\.[0-9]+)?$ ]] || lock_waited=0
		if awk -v w="$lock_waited" 'BEGIN { exit !(w >= 1) }'; then
			echo "vm-test-run: waited ${lock_waited}s for ${runner}'s root-lane lock; not counted as a pause (#19162)" >&2
		fi
	fi
fi
pause_report=$(awk -v t0="$ws_t0" -v t1="$ws_t1" -v lw="$lock_waited" -v rec="$clock" 'BEGIN {
	w = t1 - t0 - lw
	if (split(rec, f, " ") < 4 || f[2] < f[1]) {
		printf "unknown %.1f", w
		exit
	}
	g = (f[2] - f[1]) / 1e9
	h = f[3] / 1e9
	x = w - g - 2
	if (x < 0) x = 0
	p = (h > x) ? h : x
	printf "%d %.1f %.1f %.1f", int(p), w, g, h
}')
read -r paused w_s g_s h_s <<<"$pause_report"
if [[ "$paused" == unknown ]]; then
	echo "vm-test-run: paused-for=unknown (workstation ${w_s}s; no runner clock record) (#19142)" >&2
else
	echo "vm-test-run: paused-for=${paused}s (workstation ${w_s}s, runner monotonic ${g_s}s, heartbeat gaps ${h_s}s) (#19142)" >&2
	if [[ "$paused" -gt 0 ]]; then
		echo "vm-test-run: this run was paused or stalled for about ${paused}s: a timeout or timing-sensitive result from it is VOID unless re-run clean (#19142)" >&2
	fi
fi
# --cleanup-on-success: the whole-lane sweep for this one lane, as root on the
# runner (it keeps a lane with a process cwd or fd under it).
if [[ "$cleanup_on_success" -eq 1 ]]; then
	if [[ "$rc" -eq 0 ]]; then
		if ! incus exec "$runner" -- bash -s -- --root /work --lane "$name" --idle-s 0 \
			--log /var/log/xpf-lane-sweep.log <"$(dirname "$0")/runner-lane-sweep.sh" >&2; then
			echo "vm-test-run: warning: could not clean up ${base} on ${runner}" >&2
		fi
	else
		echo "vm-test-run: kept ${base} on ${runner} for inspection: the command exited ${rc} (--cleanup-on-success)" >&2
	fi
fi
exit "$rc"
