#!/usr/bin/env bash
# Read-only snapshot of host state that tests/harnesses must leave alone.
# Usage: host-residue-snapshot.sh OUTPUT
set -euo pipefail
if (($# != 1)); then
	echo "usage: $0 OUTPUT" >&2
	exit 2
fi
out=$1
mkdir -p "$(dirname "$out")"
: >"$out"
record() {
	local name=$1
	shift
	{
		printf '\n--- %s ---\n' "$name"
		if command -v "$1" >/dev/null 2>&1; then
			"$@" 2>&1 || printf 'UNAVAILABLE_OR_DENIED rc=%s\n' "$?"
		else
			printf 'UNAVAILABLE\n'
		fi
	} >>"$out"
}
record links ip -brief link
record rules ip rule show
record nft-ruleset nft list ruleset
record bpffs-pins find /sys/fs/bpf/xpf -xdev -maxdepth 8 -printf '%y %p\n'
record systemd-units /usr/bin/systemctl list-units --all --no-legend --no-pager
record dpkg-state dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Abbrev}\n'
