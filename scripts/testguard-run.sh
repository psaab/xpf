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
PATH="$root/test/support/host-bin-shims:$PATH"
export PATH
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
if [[ $(id -u) == 0 && -n "$current_boot" && "$proof_boot" == "$current_boot" ]]; then
	# The VM proof permits the privileged lane to retain its VM capabilities
	# (for BPF/memlock tests); namespace identity is still independently
	# checked by testguard in the child.
	XPF_SACRIFICIAL_HOST=1 XPF_TESTGUARD_ACTIVE=1 \
		unshare -pf --fork --mount-proc sh -c '(unshare -nm "$@")' testguard-run "$@"
else
	# A caller-supplied intent sentinel is not proof; do not propagate it on
	# the workstation path.
	env -u XPF_SACRIFICIAL_HOST XPF_TESTGUARD_ACTIVE=1 \
		unshare -Urp --fork --mount-proc sh -c '(unshare -nm "$@")' testguard-run "$@"
fi
rc=$?
set -e
"$root/scripts/host-residue-snapshot.sh" "$work/after.txt"
if ! cmp -s "$work/before.txt" "$work/after.txt"; then
	echo "HOST RESIDUE DIFFERENCE (report-only; no cleanup performed):"
	diff -u "$work/before.txt" "$work/after.txt" || true
fi
exit "$rc"
