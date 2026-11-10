#!/usr/bin/env bash
# Run a command with private net+mount namespaces and an observable PID 1
# baseline for internal/testguard. The parent PID 1 keeps the original
# namespaces; the child enters both namespaces before exec. Host residue is
# measured read-only before and after and reported without cleanup.
set -euo pipefail
if (($# == 0)); then
	echo "usage: testguard-run.sh command [args...]" >&2
	exit 2
fi
root=$(cd "$(dirname "$0")/.." && pwd)
shim_dir="$root/test/support/host-bin-shims"
real_path=
IFS=: read -r -a path_entries <<<"$PATH"
for entry in "${path_entries[@]}"; do
	[[ -n "$entry" && "$entry" != "$shim_dir" ]] || continue
	real_path="${real_path:+$real_path:}$entry"
done
if [[ -n "$real_path" ]]; then
	PATH="$shim_dir:$real_path"
else
	PATH="$shim_dir"
fi
export PATH
# #19066: inside these namespaces a further private namespace is always
# creatable, so a test that could not get one has a broken mechanism, not an
# unlucky environment. Netns cells report that through
# testguard.NetnsUnavailable, which FAILS under XPF_REQUIRE_NETNS instead of
# skipping. Before this, 10 re-exec cells skipped as "netns unavailable" on
# every run while the package guard was refusing their child.
export XPF_REQUIRE_NETNS=1

command=$1
shift
if [[ "$command" == go || "$command" == "$shim_dir/go" ]]; then
	go_bin=$(PATH="$real_path" command -v go) || {
		echo "testguard-run: real Go binary not found" >&2
		exit 127
	}
	set -- "$go_bin" "$@"
else
	set -- "$command" "$@"
fi
scratch=${TMPDIR:-/var/worktrees/.cache/tmpdir}
mkdir -p "$scratch"
work=$(mktemp -d "$scratch/testguard-run.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
"$root/scripts/host-residue-snapshot.sh" "$work/before.txt"
set +e
proof=/run/xpf-testguard-vm-boot-id
current_boot=$(cat /proc/sys/kernel/random/boot_id)
proof_boot=
if [[ -f "$proof" && ! -L "$proof" ]] &&
	[[ $(stat -c '%u %a' "$proof" 2>/dev/null || true) == "0 444" ]]; then
	proof_boot=$(cat "$proof")
fi
# #18559: inside the private net namespace, bring loopback UP before the
# command runs. A fresh namespace starts with `lo` DOWN and every package of
# one `go test ./...` shares it, so before this a cell that serves or dials
# 127.0.0.1 passed or failed by TEST ORDER: it passed only if a fixture that
# raises lo itself (pkg/cluster's ensureLoopbackRoutable18038,
# #18952/#18960; pkg/daemon's sync-pair repairs, #18933/#18935) had already
# run. Loopback is private
# to the namespace, so isolation from the host is unchanged. A failure to
# raise it is reported, not hidden.
inner='ip link set lo up 2>/dev/null || echo "testguard-run: could not bring loopback up in the test namespace" >&2; exec "$@"'
# #19084: on a ROOT run, the production trees are covered by a throwaway
# overlay in a private mount namespace before the command runs. A private
# mount namespace alone isolates nothing on disk: a root test that writes or
# unlinks /etc/... does it on the host's root filesystem. Every enumeration of
# production paths (TestMain redirects, seams) has missed some (#19084: 7 of
# R18's 46 seeded files still deleted or rewritten after the redirects), so
# the trees themselves are covered instead. The lower layer is the host's real
# tree, so tests still READ it; every write, unlink, rename or chmod lands in
# an upper layer on a tmpfs that exists only in this namespace and is
# discarded when the run ends. The test namespaces below are created inside
# this one, so the command and every child it starts see the overlay and read
# back what they just wrote. Host daemons are outside it and keep the real
# trees: nothing a test writes reaches them, which is the point.
#
# The overlay is mounted by real root BEFORE any user namespace exists. Inside
# the user namespace (the root path without the VM proof) mounts inherited
# from the host are locked, and overlayfs cannot clone a lower tree that has
# locked submounts (/run has several: "failed to clone lowerpath"). A tree
# that cannot be covered FAILS the run before the command starts (exit 2): a
# root run without the overlay is exactly the destructive run this prevents.
# Non-root runs are unchanged: they cannot write these trees anyway. The
# residue check below stays as the detector: on a root run it should report
# nothing.
overlay_trees="/etc /var/lib /var/log /run"
cover=()
if [[ $(id -u) == 0 ]]; then
	mkdir -p "$work/overlay"
	cover=(unshare -m --propagation private sh -c '
s=$0; t=$1; shift
mount -t tmpfs -o mode=0700 testguard-overlay "$s" || { echo "testguard-run: FATAL: cannot mount the overlay scratch tmpfs on $s; refusing a root run that could write host state (#19084)" >&2; exit 2; }
for d in $t; do
	n=$(printf %s "$d" | tr / _)
	mkdir -p "$s/$n.upper" "$s/$n.work" || exit 2
	mount -t overlay testguard-overlay -o "lowerdir=$d,upperdir=$s/$n.upper,workdir=$s/$n.work" "$d" || {
		echo "testguard-run: FATAL: cannot cover $d with a throwaway overlay; refusing a root run that could write host state (#19084)" >&2
		exit 2
	}
done
exec "$@"' "$work/overlay" "$overlay_trees")
fi
if [[ $(id -u) == 0 && -n "$current_boot" && "$proof_boot" == "$current_boot" ]]; then
	# The VM proof permits the privileged lane to retain its VM capabilities
	# (for BPF/memlock tests); namespace identity is still independently
	# checked by testguard in the child.
	XPF_SACRIFICIAL_HOST=1 "${cover[@]}" \
		unshare -pf --fork --mount-proc sh -c '(unshare -nm sh -c "$0" testguard-run "$@")' "$inner" "$@"
else
	# A caller-supplied intent sentinel is not proof; do not propagate it on
	# the workstation path.
	env -u XPF_SACRIFICIAL_HOST "${cover[@]}" \
		unshare -Urp --fork --mount-proc sh -c '(unshare -nm sh -c "$0" testguard-run "$@")' "$inner" "$@"
fi
rc=$?
set -e
"$root/scripts/host-residue-snapshot.sh" "$work/after.txt"
if ! cmp -s "$work/before.txt" "$work/after.txt"; then
	echo "HOST RESIDUE DIFFERENCE (report-only; no cleanup performed):"
	diff -u "$work/before.txt" "$work/after.txt" || true
fi
# #19066: a difference in the production state paths FAILS the run, with
# status 1 when the tests themselves passed. NOT 3: go-test-json.sh,
# go-test-watch.sh and the Makefile read 3 as VOID (a go-test timeout), which
# would turn a host mutation into "undetermined", and a rerun would come back
# clean because the files are already gone (#19066 R18). The rest of the
# report stays report-only (systemd session scopes come and go with other
# users of the host); these paths have no other writer on a test host, so a
# difference there is a test that wrote or deleted production state.
state_sections() { awk '/^--- state(-content)? /{on=1} /^--- / && !/^--- state(-content)? /{on=0} on' "$1"; }
if ! cmp -s <(state_sections "$work/before.txt") <(state_sections "$work/after.txt"); then
	echo "testguard-run: FAIL: the run changed production state paths on the host (no cleanup performed):" >&2
	diff -u <(state_sections "$work/before.txt") <(state_sections "$work/after.txt") >&2 || true
	[[ "$rc" -eq 0 ]] && rc=1
fi
exit "$rc"
