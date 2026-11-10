#!/usr/bin/env bash
# shellcheck shell=bash
#
# rss-pin.sh: pin and record the NIC RSS hash key on the cluster's data
# interfaces, so the A and B arms of a gate get the same flow-to-worker
# placement (#19072).
#
# Why it is needed: xpfd programs a CSPRNG Toeplitz key with
# `ethtool -X <if> hkey <key>` on every data interface (#11057,
# pkg/dataplane/compiler.go configureRSSHashKey). Builds with the #19072
# product fix keep one key per BOOT (stored in /run/xpf/rss-hash-key): every
# xpfd start in that boot programs the same key, and a reboot (H1's crash)
# draws a new one; nodes and clusters all differ. Builds without the fix
# draw a new key in every xpfd PROCESS. Either way xpfd writes ITS key on
# every start and every config commit (the write runs on each
# CompileConfig), so a fixed key set here holds only until the next xpfd
# start or config commit, with or without the fix. Pin AFTER the last
# config change (deploy, canonical reset, CoS apply) and before the measured
# cells, and verify after them: a before/after check cannot see a pin that
# was lost and restored in between.
#
# Data interfaces are the `ge-*` netdevs (not VLAN children) that expose a
# readable RSS hash key in `ethtool -x`. That is a capability probe, not a
# driver-name gate (#9040). Each interface is one of three states:
#   keyed        `ethtool -x` shows an RSS hash key;
#   unsupported  `ethtool -x` fails with "Operation not supported" (the
#                fabric parent's virtio NIC): recorded, never pinned;
#   failed       any other outcome: unreadable, never an exemption.
# `pin` stores the keyed set on the node (/run/xpf-rss-pin.required; /run,
# so a reboot clears it with the pin). `verify` requires every interface in
# that set to be present, keyed and pinned, and fails on any failed read
# (#19072 review F3): a VF that vanishes or stops answering cannot drop out.
#
# Key material never leaves the node: records show PINNED (the pin key is
# public), none, UNREADABLE or a sha prefix, and the raw `ethtool -x` dump in
# $XPF_RSS_RECORD has its key line replaced the same way (review R2).
#
# CLI (instances default to $FW0 $FW1 from cluster-env.sh):
#   rss-pin.sh record <label> [instance...]  read-only; one line per node,
#                                            redacted `ethtool -x` appended
#                                            to $XPF_RSS_RECORD when set
#   rss-pin.sh verify [instance...]          read-only; rc 0 only if every
#                                            required data interface carries
#                                            the key
#   rss-pin.sh pin [instance...]             sets the key, stores the
#                                            required set, then verifies by
#                                            reading back (takes the cluster
#                                            lock)
# Exit codes: 0 ok; 1 a required data interface is missing or does not carry
# the key (or a set failed); 2 placement is uncontrolled (no keyed data
# interface, or no pin inventory on the node); 3 a node or an interface could
# not be read.
#
# Library: source it and call rss_record / rss_verify / rss_pin, and
# rss_post_cell_verdict for a gate's post-cell check.

# The 40-byte Microsoft Toeplitz default key, the key G1 pinned for #18780.
RSS_PIN_KEY_DEFAULT="6d:5a:56:da:25:5b:0e:c2:41:67:25:3d:43:a3:8f:b0:d0:ca:2b:cb:ae:7b:30:b4:77:cb:2d:a3:80:30:f2:0c:6a:42:b7:3b:be:ac:01:fa"

rss_pin_key() {
	printf '%s' "${XPF_RSS_PIN_KEY:-$RSS_PIN_KEY_DEFAULT}" | tr 'A-F' 'a-f'
}

# The remote side is plain POSIX sh. RSS_SYSFS points it at a fake netdev
# tree in the selftest; on a node it is unset and /sys/class/net is used.
# RSS_REQUIRED likewise points at the node's pin inventory.
RSS_REMOTE_DUMP='root=${RSS_SYSFS:-/sys/class/net}; inv=${RSS_REQUIRED:-/run/xpf-rss-pin.required}
for p in "$root"/ge-*; do
	[ -e "$p" ] || continue
	i=${p##*/}
	case $i in *.*) continue ;; esac
	d=$(ethtool -i "$i" 2>/dev/null | sed -n "s/^driver: //p")
	out=$(ethtool -x "$i" 2>&1)
	echo "== $i driver=${d:-unknown} rc=$?"
	printf "%s\n" "$out"
done
if [ -r "$inv" ]; then echo "@@ required $(tr "\n" " " <"$inv")"; else echo "@@ required-absent"; fi
exit 0'

RSS_REMOTE_PIN='root=${RSS_SYSFS:-/sys/class/net}; inv=${RSS_REQUIRED:-/run/xpf-rss-pin.required}; key=$1; rc=0; req=""
for p in "$root"/ge-*; do
	[ -e "$p" ] || continue
	i=${p##*/}
	case $i in *.*) continue ;; esac
	out=$(ethtool -x "$i" 2>&1)
	xrc=$?
	if printf "%s\n" "$out" | grep -q "^RSS hash key"; then
		req="$req$i "
		if ethtool -X "$i" hkey "$key" >/dev/null 2>&1; then echo "$i set"; else echo "$i FAILED"; rc=1; fi
	elif [ "$xrc" -ne 0 ] && printf "%s\n" "$out" | grep -q "Operation not supported"; then
		:
	else
		echo "$i UNREADABLE"
		rc=1
	fi
done
printf "%s\n" $req >"$inv.tmp" && mv -f "$inv.tmp" "$inv" || { echo "pin inventory not written"; rc=1; }
exit $rc'

rss_exec() { # <instance> <sh script> [args...]
	local inst=$1 script=$2
	shift 2
	timeout -k 2 30 incus exec "$inst" -- sh -c "$script" rss "$@"
}

# rss_parse <dump>: one line per interface,
# `I <if> <key|-> <indirection sha8> <ethtool -x sha12> <driver> <state>`
# (state keyed|unsupported|failed), then `R <if>` per interface in the
# node's pin inventory, or `N -` when the node has no inventory.
rss_parse() {
	python3 -I -c '
import hashlib, re, sys
text = sys.stdin.read()
inv = re.search(r"^@@ (required(?:-absent)?)(.*)$", text, flags=re.M)
blocks = re.split(r"^== ", re.split(r"^@@ ", text, flags=re.M)[0], flags=re.M)
for b in blocks[1:]:
    head, _, body = b.partition("\n")
    name = head.split()[0]
    drv = (re.search(r"driver=(\S*)", head) or [None, "unknown"])[1]
    rc = (re.search(r"rc=(\d+)", head) or [None, "?"])[1]
    lines = body.splitlines()
    key = "-"
    for n, l in enumerate(lines):
        if l.startswith("RSS hash key"):
            key = (lines[n + 1] if n + 1 < len(lines) else "").strip().lower() or "-"
    if key != "-":
        state = "keyed"
    elif rc not in ("0", "?") and "Operation not supported" in body:
        state = "unsupported"
    else:
        state = "failed"
    indir = "\n".join(l for l in lines if re.match(r"^\s+\d+:", l))
    print("I", name, key, hashlib.sha256(indir.encode()).hexdigest()[:8],
          hashlib.sha256(body.encode()).hexdigest()[:12], drv, state)
if inv and inv.group(1) == "required":
    for name in inv.group(2).split():
        print("R", name)
else:
    print("N", "-")
'
}

# rss_redact <pin key>: copy a remote dump with every RSS key line replaced
# by PINNED (the pin is public) or a sha256 prefix, so no artifact carries a
# node's random key (#19072 review R2).
rss_redact() {
	python3 -I -c '
import hashlib, sys
pin = sys.argv[1]
lines = sys.stdin.read().splitlines()
out, take = [], False
for l in lines:
    if take:
        k = l.strip().lower()
        out.append("    <" + ("PINNED" if k == pin else "sha256:" + hashlib.sha256(k.encode()).hexdigest()[:12]) + ">")
        take = False
        continue
    out.append(l)
    take = l.startswith("RSS hash key")
print("\n".join(out))
' "$1"
}

# rss_record <label> <instance...>: print `rss[<label>] <inst>: <if>
# key=<PINNED|sha8 of the key|none> indir=<sha8> x=<sha12>; ...` per node.
# Read-only. rc 3 if a node could not be read.
rss_record() {
	local label=$1 inst dump rc=0 pin line tag name key indir x state k
	shift
	pin=$(rss_pin_key)
	for inst in "$@"; do
		if ! dump=$(rss_exec "$inst" "$RSS_REMOTE_DUMP"); then
			echo "rss[$label] $inst: UNREADABLE"
			rc=3
			continue
		fi
		if [[ -n "${XPF_RSS_RECORD:-}" ]]; then
			printf '### rss[%s] %s %s\n%s\n' "$label" "$inst" "$(date -u +%FT%TZ)" \
				"$(printf '%s\n' "$dump" | rss_redact "$pin")" >>"$XPF_RSS_RECORD"
		fi
		line=""
		while read -r tag name key indir x _ state; do
			[[ "$tag" == I ]] || continue
			if [[ "$state" == failed ]]; then
				k=UNREADABLE
			elif [[ "$key" == "-" ]]; then
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

# rss_verify <instance...>: rc 0 only if, on every node, every interface
# in the pin inventory is present, keyed and carries the pin key, every
# other keyed interface carries it too, and no interface read failed.
# rc 1: a required interface is missing or carries another key; 2: no
# keyed data interface, or no pin inventory; 3: a node or interface could
# not be read.
rss_verify() {
	local inst dump pin tag name key state keyed req have r noinv unreadable=0 mismatch=0 nokey=0
	pin=$(rss_pin_key)
	for inst in "$@"; do
		if ! dump=$(rss_exec "$inst" "$RSS_REMOTE_DUMP"); then
			echo "rss verify $inst: UNREADABLE" >&2
			unreadable=1
			continue
		fi
		keyed=0 req="" have=" " noinv=0
		while read -r tag name key _ _ _ state; do
			case "$tag" in
			R) req+=" $name" ;;
			N) noinv=1 ;;
			I)
				have+="$name:$state "
				case "$state" in
				failed)
					echo "rss verify $inst: $name: ethtool -x failed (interface unreadable, not an exemption)" >&2
					unreadable=1
					;;
				keyed)
					keyed=$((keyed + 1))
					if [[ "$key" != "$pin" ]]; then
						echo "rss verify $inst: $name carries another key (placement uncontrolled)" >&2
						mismatch=1
					fi
					;;
				esac
				;;
			esac
		done < <(printf '%s\n' "$dump" | rss_parse)
		for r in $req; do
			if [[ "$have" != *" $r:"* ]]; then
				echo "rss verify $inst: required interface $r is missing" >&2
				mismatch=1
			elif [[ "$have" != *" $r:keyed "* ]]; then
				echo "rss verify $inst: required interface $r no longer shows a readable RSS key" >&2
				mismatch=1
			fi
		done
		if ((noinv)); then
			echo "rss verify $inst: no pin inventory on the node (rss-pin.sh pin was not run this boot)" >&2
			nokey=1
		fi
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

# rss_post_cell_verdict <rc> <result.json|""> <instance...> (#19072 review
# F2): the gate path's check at the END of a placement-sensitive cell. It
# verifies the pin again. If the pin no longer holds, or cannot be read, a
# passing cell (rc 0) becomes VOID (rc 2) and an ABORT_CAUSE line carries
# the reason into the ledger row (harness-result.sh smoke-cells). A FAIL
# (rc 1) or an existing VOID keeps its rc, so a real failure is never
# relabelled. The outcome is written into result.json under "rss" either
# way. Scope: a before/after check. A pin lost and restored inside the cell
# is invisible to it. Returns the cell's new rc.
rss_post_cell_verdict() {
	local rc=$1 result=$2 vrc out effect=none
	shift 2
	out=$(rss_verify "$@" 2>&1)
	vrc=$?
	[[ -z "$out" ]] || printf '%s\n' "$out"
	if ((vrc != 0)); then
		if ((rc == 0)); then
			rc=2
			effect="PASS->VOID"
			echo "ABORT_CAUSE=rss: the RSS pin did not hold to the end of the cell (rss_verify rc=$vrc); per-stream placement is uncontrolled, so the cell is VOID"
		else
			effect="kept rc=$rc"
			echo "rss: the RSS pin did not hold to the end of the cell (rss_verify rc=$vrc); the cell keeps rc=$rc"
		fi
	else
		echo "rss: the RSS pin held from the start to the end of the cell"
	fi
	if [[ -n "$result" && -f "$result" ]]; then
		python3 -I - "$result" "$vrc" "$effect" <<'PY' || echo "rss: could not annotate $result"
import json, os, sys
path, vrc, effect = sys.argv[1], int(sys.argv[2]), sys.argv[3]
with open(path) as f:
    obj = json.load(f)
obj["rss"] = {"post_cell_verify_rc": vrc, "effect": effect,
              "scope": "pin verified before and after the cell; a pin lost and restored inside it is not seen"}
if effect == "PASS->VOID":
    s = obj.setdefault("summary", {})
    s["exit"] = 2
    s["rss_void"] = "the RSS pin did not hold to the end of the cell"
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(obj, f, sort_keys=True)
os.replace(tmp, path)
PY
	fi
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
