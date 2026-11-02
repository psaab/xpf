#!/usr/bin/env bash
# Establish the boot-ID proof used by testguard-run.sh for privileged VM legs.
# This command is only called by `make vm-test-root`; it refuses the workstation.
set -euo pipefail
if [[ $(id -u) -ne 0 ]]; then
	echo "mark-test-vm: privileged VM test leg requires root inside the VM" >&2
	exit 1
fi
virt=$(systemd-detect-virt --vm 2>/dev/null || true)
if [[ -z "$virt" || "$virt" == none ]]; then
	echo "mark-test-vm: refusing to mark a non-VM host" >&2
	exit 1
fi
boot_id=$(cat /proc/sys/kernel/random/boot_id)
[[ "$boot_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || {
	echo "mark-test-vm: malformed current boot ID" >&2
	exit 1
}
tmp=$(mktemp /run/.xpf-testguard-vm-boot-id.XXXXXX)
trap 'rm -f "$tmp"' EXIT
printf '%s\n' "$boot_id" >"$tmp"
chown root:root "$tmp"
chmod 0444 "$tmp"
mv -f "$tmp" /run/xpf-testguard-vm-boot-id
trap - EXIT
