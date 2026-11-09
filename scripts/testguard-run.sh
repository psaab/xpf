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
#
# #19049: also allow unprivileged ICMP datagram ("ping") sockets in the
# namespace. A fresh network namespace starts with net.ipv4.ping_group_range
# at the kernel default "1 0" (no group), so icmp.ListenPacket("udp4"/"udp6")
# fails with EACCES for every caller, uid 0 included — the check is by group,
# not capability. Every host the product runs on has the systemd default
# "0 2147483647". The product's ICMP prober (pkg/cluster ip-monitoring) and
# tunnel keepalive (pkg/routing) open exactly these sockets, so under the old
# namespace the real prober could not open a socket at all and its cells read
# "probe not completed": TestIPMonitorPrimaryDualStackDemotes16425 was red on
# every testguard run. The sysctl is per network namespace, so the host's
# value is untouched. The full range is written first; inside an unprivileged
# user namespace only the mapped gid is valid, so the fallback is the
# caller's own gid. A failure is reported, not hidden.
inner='ip link set lo up 2>/dev/null || echo "testguard-run: could not bring loopback up in the test namespace" >&2; { echo "0 2147483647" >/proc/sys/net/ipv4/ping_group_range || echo "$(id -g) $(id -g)" >/proc/sys/net/ipv4/ping_group_range; } 2>/dev/null || echo "testguard-run: could not allow ICMP datagram sockets (ping_group_range) in the test namespace" >&2; exec "$@"'
if [[ $(id -u) == 0 && -n "$current_boot" && "$proof_boot" == "$current_boot" ]]; then
	# The VM proof permits the privileged lane to retain its VM capabilities
	# (for BPF/memlock tests); namespace identity is still independently
	# checked by testguard in the child.
	XPF_SACRIFICIAL_HOST=1 \
		unshare -pf --fork --mount-proc sh -c '(unshare -nm sh -c "$0" testguard-run "$@")' "$inner" "$@"
else
	# A caller-supplied intent sentinel is not proof; do not propagate it on
	# the workstation path.
	env -u XPF_SACRIFICIAL_HOST \
		unshare -Urp --fork --mount-proc sh -c '(unshare -nm sh -c "$0" testguard-run "$@")' "$inner" "$@"
fi
rc=$?
set -e
"$root/scripts/host-residue-snapshot.sh" "$work/after.txt"
if ! cmp -s "$work/before.txt" "$work/after.txt"; then
	echo "HOST RESIDUE DIFFERENCE (report-only; no cleanup performed):"
	diff -u "$work/before.txt" "$work/after.txt" || true
fi
exit "$rc"
