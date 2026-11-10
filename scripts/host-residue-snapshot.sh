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
# Production state paths (#19066 R18 F1, Codex F1). An empty api
# TLSSelfSignedDir means /etc/xpf/tls, and the apply tail's empty desired
# state removes xpf-managed SSH, chrony and rsyslog files. A re-executed test
# child at uid 0 is real root on a root leg, and a file it creates or unlinks
# is on the shared root filesystem even from a private mount namespace.
# Each tree is recorded twice: entries with metadata (type, mode, owner, size,
# mtime, and a symlink's target), and a sha256 of every regular file reached
# with symlinks followed, so a same-size overwrite with its mtime restored, or
# a change behind a symlinked directory, still shows (#19066 Codex D3). These
# trees are small. testguard-run.sh fails the run on any difference in these
# sections (the "state " records). XPF_RESIDUE_EXTRA_STATE_PATHS (space
# separated) ADDS paths; it cannot remove any. Its user is the selftest.
for path in /etc/xpf /var/lib/xpf /etc/frr /etc/systemd/network \
	/etc/ssh/ssh_known_hosts /etc/ssh/sshd_config.d /etc/chrony/sources.d \
	/etc/chrony/conf.d /etc/rsyslog.d ${XPF_RESIDUE_EXTRA_STATE_PATHS:-}; do
	record "state $path" find "$path" -xdev -maxdepth 6 -printf '%y %m %U:%G %s %T@ %p -> %l\n'
	record "state-content $path" sh -c 'find -L "$1" -xdev -maxdepth 6 -type f -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum' sh "$path"
done
