#!/usr/bin/env bash
# Sourced by Incus harnesses before any apt/systemctl operation on a target.
# Verifies the Incus instance is a VM, installs fail-closed command shims, and
# records a boot-ID proof inside it for those shims.

xpf_assert_vm_target() {
	local ref=${1:?missing Incus instance reference}
	local info type boot_id helper_dir shim_dir tool
	info=$(incus info "$ref" --format json) || {
		echo "vm-target-guard: cannot inspect target $ref" >&2
		return 1
	}
	type=$(printf '%s' "$info" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("type", ""))') || {
		echo "vm-target-guard: cannot decode Incus instance type for $ref" >&2
		return 1
	}
	if [[ "$type" != virtual-machine ]]; then
		echo "vm-target-guard: refusing $ref: target type is '$type', not virtual-machine" >&2
		return 1
	fi
	boot_id=$(incus exec "$ref" -- cat /proc/sys/kernel/random/boot_id) || {
		echo "vm-target-guard: cannot read target boot ID for $ref" >&2
		return 1
	}
	if [[ ! "$boot_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
		echo "vm-target-guard: malformed target boot ID for $ref" >&2
		return 1
	fi
	helper_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
	shim_dir="$helper_dir/test/support/host-bin-shims"
	incus exec "$ref" -- mkdir -p /usr/local/bin || return 1
	for tool in apt apt-get systemctl dpkg refuse-host-tool; do
		incus file push "$shim_dir/$tool" "$ref/usr/local/bin/$tool" --mode 0755 || {
			echo "vm-target-guard: cannot install $tool shim in $ref" >&2
			return 1
		}
	done
	incus exec "$ref" -- sh -ceu '
		current=$(cat /proc/sys/kernel/random/boot_id)
		[ "$current" = "$1" ] || { echo "vm-target-guard: target rebooted during proof" >&2; exit 1; }
		umask 022
		tmp=$(mktemp /run/.xpf-testguard-vm-boot-id.XXXXXX)
		printf "%s\n" "$current" >"$tmp"
		chown root:root "$tmp"
		chmod 0444 "$tmp"
		mv -f "$tmp" /run/xpf-testguard-vm-boot-id
	' sh "$boot_id" || {
		echo "vm-target-guard: cannot install boot-ID proof in $ref" >&2
		return 1
	}
}
