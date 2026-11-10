#!/usr/bin/env bash
# shellcheck shell=bash
#
# rss-pin.sh: pin and record the NIC RSS hash key on the cluster's data
# interfaces, so the A and B arms of a gate get the same flow-to-worker
# placement (#19072).
#
# Why it is needed: xpfd programs a CSPRNG Toeplitz key with
# `ethtool -X <if> hkey <key>` on every data interface (#11057,
# pkg/dataplane/compiler.go configureRSSHashKey). The key is drawn once per
# xpfd PROCESS (rssHashKeyForBoot is a sync.Once), so every deploy, every
# daemon restart and every reboot (H1's crash) installs a new one. Every
# config commit re-applies the current process's key, because the write
# runs on each CompileConfig. A fixed key set here therefore holds only
# until the next xpfd start or config commit: pin AFTER the last config
# change (deploy, canonical reset, CoS apply) and before the measured
# cells, and record around every placement-sensitive cell.
#
# Data interfaces are the `ge-*` netdevs (not VLAN children) that expose a
# readable RSS hash key in `ethtool -x`. That is a capability probe, not a
# driver-name gate (#9040). The fabric parent's virtio NIC reports
# "Operation not supported" and is recorded but not pinned.
#
# CLI (instances default to $FW0 $FW1 from cluster-env.sh):
#   rss-pin.sh record <label> [instance...]  read-only; one line per node,
#                                            raw `ethtool -x` appended to
#                                            $XPF_RSS_RECORD when it is set
#   rss-pin.sh verify [instance...]          read-only; rc 0 only if every
#                                            data interface carries the key
#   rss-pin.sh pin [instance...]             sets the key, then verifies by
#                                            reading it back (takes the
#                                            cluster lock)
# Exit codes: 0 ok; 1 a data interface does not carry the key (or a set
# failed); 2 a node has no data interface with a readable key (nothing to
# pin: placement is uncontrolled); 3 a node could not be read.
#
# Library: source it and call rss_record / rss_verify / rss_pin.

# The 40-byte Microsoft Toeplitz default key, the key G1 pinned for #18780.
RSS_PIN_KEY_DEFAULT="6d:5a:56:da:25:5b:0e:c2:41:67:25:3d:43:a3:8f:b0:d0:ca:2b:cb:ae:7b:30:b4:77:cb:2d:a3:80:30:f2:0c:6a:42:b7:3b:be:ac:01:fa"

rss_pin_key() {
	printf '%s' "${XPF_RSS_PIN_KEY:-$RSS_PIN_KEY_DEFAULT}" | tr 'A-F' 'a-f'
}

# The remote side is plain POSIX sh. RSS_SYSFS points it at a fake netdev
# tree in the selftest; on a node it is unset and /sys/class/net is used.
RSS_REMOTE_DUMP='root=${RSS_SYSFS:-/sys/class/net}
for p in "$root"/ge-*; do
	[ -e "$p" ] || continue
	i=${p##*/}
	case $i in *.*) continue ;; esac
	d=$(ethtool -i "$i" 2>/dev/null | sed -n "s/^driver: //p")
	echo "== $i driver=${d:-unknown}"
	ethtool -x "$i" 2>&1
done
exit 0'

RSS_REMOTE_PIN='root=${RSS_SYSFS:-/sys/class/net}; key=$1; rc=0
for p in "$root"/ge-*; do
	[ -e "$p" ] || continue
	i=${p##*/}
	case $i in *.*) continue ;; esac
	ethtool -x "$i" 2>/dev/null | grep -q "^RSS hash key" || continue
	if ethtool -X "$i" hkey "$key" >/dev/null 2>&1; then echo "$i set"; else echo "$i FAILED"; rc=1; fi
done
exit $rc'

rss_exec() { # <instance> <sh script> [args...]
	local inst=$1 script=$2
	shift 2
	timeout -k 2 30 incus exec "$inst" -- sh -c "$script" rss "$@"
}

# rss_parse <dump>: one line per interface,
# `<if> <key|-> <indirection sha8> <ethtool -x sha12> <driver>`.
rss_parse() {
	python3 -I -c '
import hashlib, re, sys
blocks = re.split(r"^== ", sys.stdin.read(), flags=re.M)
for b in blocks[1:]:
    head, _, body = b.partition("\n")
    name = head.split()[0]
    drv = (re.search(r"driver=(\S*)", head) or [None, "unknown"])[1]
    lines = body.splitlines()
    key = "-"
    for n, l in enumerate(lines):
        if l.startswith("RSS hash key"):
            key = (lines[n + 1] if n + 1 < len(lines) else "").strip().lower() or "-"
    indir = "\n".join(l for l in lines if re.match(r"^\s+\d+:", l))
    print(name, key, hashlib.sha256(indir.encode()).hexdigest()[:8],
          hashlib.sha256(body.encode()).hexdigest()[:12], drv)
'
}

# rss_record <label> <instance...>: print `rss[<label>] <inst>: <if>
# key=<PINNED|sha8 of the key|none> indir=<sha8> x=<sha12>; ...` per node.
# Read-only. rc 3 if a node could not be read.
rss_record() {
	local label=$1 inst dump rc=0 pin line name key indir x drv k
	shift
	pin=$(rss_pin_key)
	for inst in "$@"; do
		if ! dump=$(rss_exec "$inst" "$RSS_REMOTE_DUMP"); then
			echo "rss[$label] $inst: UNREADABLE"
			rc=3
			continue
		fi
		if [[ -n "${XPF_RSS_RECORD:-}" ]]; then
			printf '### rss[%s] %s %s\n%s\n' "$label" "$inst" "$(date -u +%FT%TZ)" "$dump" >>"$XPF_RSS_RECORD"
		fi
		line=""
		while read -r name key indir x drv; do
			[[ -n "$name" ]] || continue
			if [[ "$key" == "-" ]]; then
				k=none
			elif [[ "$key" == "$pin" ]]; then
				k=PINNED
			else
				k=$(printf '%s' "$key" | sha256sum | cut -c1-8)
			fi
			line+="$name key=$k indir=$indir x=$x; "
		done < <(printf '%s\n' "$dump" | rss_parse)
		echo "rss[$label] $inst: ${line:-no ge-* interfaces}"
	done
	return "$rc"
}

# rss_verify <instance...>: rc 0 only if every data interface (a ge-*
# with a readable key) on every node carries the pin key; 1 if one does
# not; 2 if a node has no such interface; 3 if a node could not be read.
rss_verify() {
	local inst dump pin name key indir x drv keyed unreadable=0 mismatch=0 nokey=0
	pin=$(rss_pin_key)
	for inst in "$@"; do
		if ! dump=$(rss_exec "$inst" "$RSS_REMOTE_DUMP"); then
			echo "rss verify $inst: UNREADABLE" >&2
			unreadable=1
			continue
		fi
		keyed=0
		while read -r name key indir x drv; do
			[[ -n "$name" && "$key" != "-" ]] || continue
			keyed=$((keyed + 1))
			if [[ "$key" != "$pin" ]]; then
				echo "rss verify $inst: $name carries another key (placement uncontrolled)" >&2
				mismatch=1
			fi
		done < <(printf '%s\n' "$dump" | rss_parse)
		if ((keyed == 0)); then
			echo "rss verify $inst: no data interface with a readable RSS key" >&2
			nokey=1
		fi
	done
	if ((unreadable)); then return 3; fi
	if ((mismatch)); then return 1; fi
	if ((nokey)); then return 2; fi
	return 0
}

# rss_pin <instance...>: set the pin key on every data interface, then
# verify by reading it back. A driver that accepts the write but keeps its
# own key is caught by the read-back.
rss_pin() {
	local inst out rc=0 vrc key
	key=$(rss_pin_key)
	for inst in "$@"; do
		if ! out=$(rss_exec "$inst" "$RSS_REMOTE_PIN" "$key"); then
			rc=1
		fi
		echo "rss pin $inst: $(printf '%s' "$out" | tr '\n' ' ')"
	done
	rss_verify "$@"
	vrc=$?
	((vrc != 0)) && rc=$vrc
	return "$rc"
}

rss_main() {
	local cmd=${1:-} label
	shift || true
	case "$cmd" in
	record)
		label=${1:?usage: rss-pin.sh record <label> [instance...]}
		shift
		;;
	pin | verify) ;;
	*)
		echo "usage: rss-pin.sh {record <label>|pin|verify} [instance...]" >&2
		return 64
		;;
	esac
	local dir
	dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	if [[ "$cmd" == pin ]]; then
		# Setting the key mutates shared cluster state: run as a lock cell
		# (directly inside a live cell, else re-exec through with-cluster.sh).
		# shellcheck source=cluster-lock.sh
		source "$dir/cluster-lock.sh"
		if ! xpf_cluster_lock_held; then
			exec "$dir/with-cluster.sh" "rss-pin pin $*" -- "$dir/rss-pin.sh" pin "$@"
		fi
	fi
	if (($# == 0)); then
		# shellcheck source=cluster-env.sh
		source "$dir/cluster-env.sh"
		set -- "$FW0" "$FW1"
	fi
	case "$cmd" in
	record) rss_record "$label" "$@" ;;
	verify) rss_verify "$@" ;;
	pin) rss_pin "$@" ;;
	esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	set -uo pipefail
	rss_main "$@"
	exit $?
fi
