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
# worktree (uncommitted edits included). Files deleted locally are deleted on
# the runner too: the source tree is replaced on every sync, the target dir is
# not. No .git is copied; GOFLAGS gets -buildvcs=false.
#
# Source mtimes (#19134): cargo decides a crate is fresh by comparing source
# mtimes with its artefacts, and the target dir outlives every sync. A tree
# whose files carry OLDER mtimes than the lane's last build (another worktree,
# an older commit) therefore re-tested the previous binary. So the sync does
# not keep the workstation's mtimes. A per-lane ledger
# (/work/<name>/.xpf-src-ledger.json) records each path's content hash and the
# exact mtime (ns) the sync applied to it. A file whose content the ledger
# knows gets that mtime back, so an unchanged tree keeps its incremental
# build. Every other file gets a fresh stamp: a new or changed file, and one
# the previous run TOUCHED on the runner (its content or mtime no longer
# matches what the sync applied, or the run deleted it). Content alone is not
# enough: a run that edits a file, builds, and writes the original bytes back
# (scripts/mutate-9546.py restores its mutants this way) leaves content the
# ledger knows over a binary built from the edit. A fresh stamp is the sync
# time or, if later, the newest artefact in target/*/deps plus one second, so
# neither a clock behind the build nor a coarse filesystem can leave the
# source older than the artefact. If the clock is behind the previous sync,
# the target dir is deleted outright. A lane with a build but no
# (current-format) ledger restamps everything once.
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

# #19134: restamp the synced tree from the lane's content ledger (see "Source
# mtimes" above), then swap it in for the previous tree. Runs on the runner as
# `runner`: python3 -I - <base>.
restamp_py=$(
	cat <<'PY'
import glob, hashlib, json, os, shutil, sys, time

base = sys.argv[1]
src, new = os.path.join(base, "src"), os.path.join(base, "src.new")
ledger_path = os.path.join(base, ".xpf-src-ledger.json")
target = os.path.join(base, "target")


def files(root):
    for top, _dirs, names in os.walk(root):
        for name in names:
            path = os.path.join(top, name)
            if os.path.isfile(path) and not os.path.islink(path):
                yield os.path.relpath(path, root), path


def digest(path):
    h = hashlib.blake2b(digest_size=16)
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


SECOND = 1_000_000_000


def newest_artifact_ns(target):
    """The newest mtime among the lane's compiled artefacts: one readdir of
    each <target>/<profile>/deps and <target>/<triple>/<profile>/deps, not a
    walk of the whole target dir."""
    newest = None
    for pattern in ("*/deps", "*/*/deps"):
        for deps in glob.glob(os.path.join(glob.escape(target), pattern)):
            try:
                entries = list(os.scandir(deps))
            except OSError:
                continue
            for entry in entries:
                try:
                    mtime = entry.stat(follow_symlinks=False).st_mtime_ns
                except OSError:
                    continue
                if newest is None or mtime > newest:
                    newest = mtime
    return newest


# Ledger format 2: {"v": 2, "files": {path: [content hash, applied mtime ns]},
# "last_sync_ns": the clock at the previous sync}. Anything else (format 1
# kept float first-seen times) counts as no ledger.
last_sync = None
try:
    with open(ledger_path, encoding="utf-8") as handle:
        ledger = json.load(handle)
    known = ledger["files"] if isinstance(ledger, dict) and ledger.get("v") == 2 else None
    if not isinstance(known, dict):
        known = None
    else:
        last_sync = ledger.get("last_sync_ns")
except (OSError, ValueError, KeyError):
    known = None
if known is None:
    # No record of what the target dir was built from: trust nothing in it.
    known = {}
now = time.time_ns()
# Fail-closed backstop: the clock is behind the previous sync, so an artefact
# anywhere in the target dir may be newer than any stamp this sync can apply.
# Throw the builds away rather than reason about which are safe.
if isinstance(last_sync, int) and now < last_sync:
    print(f"vm-test-run: the runner clock is {(last_sync - now) / SECOND:.1f}s behind the previous sync;"
          f" cleaning {target} so no earlier build can be reused (#19134)", file=sys.stderr)
    if os.path.lexists(target):
        shutil.rmtree(target)
    os.makedirs(target)
    known = {}


def touched_on_runner(rel, path):
    entry = known.get(rel)
    if entry is None or entry[0] != digest(path):
        return True  # new or different content
    return os.stat(path).st_mtime_ns != entry[1]  # rewritten, even with the same bytes


# A file the previous run touched on the runner (a mutant, a restored mutant,
# a regenerated file) may be what the target was built from: its synced
# content gets a new stamp even when it matches the ledger. So does a file
# that run deleted.
dirty, seen = set(), set()
if os.path.isdir(src):
    for rel, path in files(src):
        seen.add(rel)
        if touched_on_runner(rel, path):
            dirty.add(rel)
dirty |= set(known) - seen
# A new or touched file must be NEWER than every artefact it could be confused
# with. The clock alone does not guarantee that: it can be behind an artefact's
# mtime (a step backward between the build and this sync), and a coarse
# filesystem can round the source and the artefact into the same tick. So the
# stamp is at least the newest artefact plus a second.
floor = newest_artifact_ns(target)
stamp_new = now if floor is None else max(now, floor + SECOND)
fresh, stamped = {}, 0
for rel, path in files(new):
    h = digest(path)
    entry = known.get(rel)
    if entry is not None and entry[0] == h and rel not in dirty:
        stamp = entry[1]
    else:
        stamp, stamped = stamp_new, stamped + 1
    os.utime(path, ns=(stamp, stamp))
    fresh[rel] = [h, stamp]
tmp = ledger_path + ".tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    json.dump({"v": 2, "files": fresh, "last_sync_ns": now}, handle)
os.replace(tmp, ledger_path)
if os.path.lexists(src):
    shutil.rmtree(src)
os.rename(new, src)
built = os.path.isdir(target) and any(os.scandir(target))
ahead = f", {(stamp_new - now) / SECOND:.1f}s ahead of the clock to clear the newest artefact" if stamp_new > now else ""
print(f"vm-test-run: {stamped} of {len(fresh)} synced files new or changed for this lane"
      f"{' (target dir present)' if built else ''}; stamped with the sync time{ahead}", file=sys.stderr)
PY
)
if [[ "$sync" -eq 1 ]]; then
	incus exec "$runner" -- bash -c "rm -rf '${base}/src.new' && mkdir -p '${base}/src.new' '${base}/target' '${base}/tmp' && chown -R runner:runner '${base}'"
	(cd "$top" && git ls-files -z -co --exclude-standard | tar --null -T - -cf -) |
		incus exec "$runner" -- su runner -c "tar -xf - -C '${base}/src.new'"
	if ! printf '%s\n' "$restamp_py" | incus exec "$runner" -- su runner -c "python3 -I - '${base}'"; then
		echo "vm-test-run: could not restamp the synced tree on ${runner} (#19134); refusing rather than risk testing a stale build" >&2
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
