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
#              tcp:xpf-testrunner and udp:xpf-testrunner.
#   --name     per-lane directory on the runner (default: the worktree's
#              basename). Source lands in /work/<name>/src; cargo output in
#              /work/<name>/target, so incremental builds persist per lane.
#   --root     run the command as root (privileged VM legs such as
#              `make vm-test-root`); default is the unprivileged `runner` user.
#   --no-sync  skip the source sync (re-run against what is already there).
#
#   If the runner is FROZEN (a gate cell pauses its same-host runner while it
#   measures), the script waits for it to resume, up to XPF_TEST_RUNNER_WAIT_S
#   seconds (default 7200), then exits 75.
#
# The sync copies tracked plus untracked-but-not-ignored files of the current
# worktree (uncommitted edits included), preserving mtimes so cargo and go
# keep their incremental state. Files deleted locally are deleted on the
# runner too: the source tree is replaced on every sync, the target dir is
# not. No .git is copied; GOFLAGS gets -buildvcs=false.
#
# The command runs via `bash -lc` in /work/<name>/src with
# CARGO_TARGET_DIR=/work/<name>/target, TMPDIR=/work/<name>/tmp and
# GOTMPDIR=/wtgt. The exit status is the command's.
set -euo pipefail

runner="${XPF_TEST_RUNNER:-udp:xpf-testrunner}"
name=""
as_root=0
sync=1
while [[ $# -gt 0 ]]; do
	case "$1" in
	--runner) runner="$2"; shift 2 ;;
	--name) name="$2"; shift 2 ;;
	--root) as_root=1; shift ;;
	--no-sync) sync=0; shift ;;
	--) shift; break ;;
	-h|--help) sed -n '2,30p' "$0"; exit 0 ;;
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

if [[ "$sync" -eq 1 ]]; then
	incus exec "$runner" -- bash -c "rm -rf '${base}/src' && mkdir -p '${base}/src' '${base}/target' '${base}/tmp' && chown -R runner:runner '${base}'"
	(cd "$top" && git ls-files -z -co --exclude-standard | tar --null -T - -cf -) |
		incus exec "$runner" -- su runner -c "tar -xf - -C '${base}/src'"
	# testguard-run.sh runs Go tests in a private network namespace with no
	# network, so a cold module cache fails there as "setup failed". Fetch the
	# modules first, outside the guard. With a warm cache this is quick and
	# fetches nothing.
	# The download must not change the tree under test: `go mod download`
	# restores a missing /go.mod hash line in go.sum, and a test would then
	# pass on a tree that fails on the workstation. The module files are hashed
	# before and after; a change prints a marker on stdout (the download's own
	# output goes to stderr), and the run is refused. The marker, not an exit
	# code, carries the verdict, so the download's own status cannot be
	# mistaken for it.
	if incus exec "$runner" -- test -f "${base}/src/go.mod"; then
		mod_rc=0
		mod_out=$(incus exec "$runner" -- su - runner -c "cd '${base}/src' || exit 2; h() { cat go.mod go.sum go.work go.work.sum 2>/dev/null | sha256sum; }; before=\$(h); GOFLAGS=-buildvcs=false go mod download >&2; rc=\$?; [ \"\$before\" = \"\$(h)\" ] || echo VMTR_MODULE_FILES_CHANGED; exit \$rc") || mod_rc=$?
		if [[ "$mod_out" == *VMTR_MODULE_FILES_CHANGED* ]]; then
			echo "vm-test-run: go mod download changed go.mod/go.sum/go.work; the tree under test is not tidy (run 'go mod tidy' and commit); refusing" >&2
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
rc=0
if [[ "$as_root" -eq 1 ]]; then
	incus exec "$runner" -- bash -lc "export HOME=/home/runner PATH=/home/runner/.cargo/bin:\$PATH; ${env_prefix}; ${cmd}" || rc=$?
	# A root leg keeps HOME=/home/runner (for the toolchains), so whatever it
	# wrote under runner's lane dir, module cache, cargo dir or cache is
	# root-owned and breaks later unprivileged runs. Hand it back in a
	# SEPARATE exec after the command: a trap in the command's own shell is
	# skipped by `exec`, and its status can leak into the result. The
	# command's status is already recorded in rc; this step cannot change it.
	incus exec "$runner" -- find "${base}" /home/runner/go /home/runner/.cargo /home/runner/.cache \
		-xdev ! -user runner -exec chown -h runner:runner {} + >/dev/null 2>&1 || true
else
	incus exec "$runner" -- su - runner -c "${env_prefix}; ${cmd}" || rc=$?
fi
exit "$rc"
