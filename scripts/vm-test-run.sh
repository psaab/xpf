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
if [[ ! "$name" =~ ^[A-Za-z0-9._-]+$ ]]; then
	echo "vm-test-run: lane name must match [A-Za-z0-9._-]+: $name" >&2
	exit 2
fi
base="/work/${name}"

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
env_prefix="export CARGO_TARGET_DIR='${base}/target' TMPDIR='${base}/tmp' GOTMPDIR=/wtgt GOFLAGS='-buildvcs=false' XPF_TEST_RUNNER_LANE='${name}'; mkdir -p /wtgt 2>/dev/null || true; [ -f \"\$HOME/.cargo/env\" ] && . \"\$HOME/.cargo/env\"; cd '${base}/src'"
if [[ "$as_root" -eq 1 ]]; then
	incus exec "$runner" -- bash -lc "export HOME=/home/runner PATH=/home/runner/.cargo/bin:\$PATH; ${env_prefix}; ${cmd}"
else
	incus exec "$runner" -- su - runner -c "${env_prefix}; ${cmd}"
fi
