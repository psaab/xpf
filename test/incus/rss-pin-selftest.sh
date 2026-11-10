#!/usr/bin/env bash
# Self-test for test/incus/rss-pin.sh (#19072).
#
# Hermetic: no cluster, no VM, no real NIC. `incus` and `ethtool` are fake
# executables on PATH (rss-pin.sh runs `timeout incus exec ...`, so a shell
# function cannot stand in for them). The fake `incus exec <instance> --`
# runs the remote script locally against that instance's fake netdev tree:
# one directory per netdev, plus a state file per interface for its driver,
# RSS key and behaviour.
#
# The cell that matters most is the STICKY driver: it accepts
# `ethtool -X <if> hkey <key>` with rc 0 and keeps its own key. Only a
# read-back can tell that pin from a working one, and the mutation leg
# removes the read-back to show this cell is what catches it.
#
# Usage: ./test/incus/rss-pin-selftest.sh   (rc 0 = all pass)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="${SCRIPT_DIR}/rss-pin.sh"

PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/state"
export MOCK_ROOT="$T"

cat >"$T/bin/incus" <<'EOF'
#!/usr/bin/env bash
# Fake `incus exec <instance> -- <cmd...>`: run <cmd> locally against the
# instance's fake netdev tree.
[[ "${1:-}" == exec ]] || { echo "fake incus: only exec is supported" >&2; exit 2; }
inst=$2
shift 2
[[ "${1:-}" == -- ]] && shift
d="$MOCK_ROOT/state/$inst"
[[ -d "$d" ]] || { echo "Error: Instance not found" >&2; exit 1; }
RSS_SYSFS="$d/net" FAKE_ETH="$d/eth" PATH="$MOCK_ROOT/bin:$PATH" exec "$@"
EOF

cat >"$T/bin/ethtool" <<'EOF'
#!/usr/bin/env bash
# Fake ethtool: -i, -x and -X <if> hkey <key> over $FAKE_ETH/<if>.*
op=$1 i=$2 s="$FAKE_ETH/$2"
case "$op" in
-i) echo "driver: $(cat "$s.driver" 2>/dev/null || echo virtio_net)" ;;
-x)
	if [[ ! -f "$s.key" ]]; then
		echo "Cannot get RX ring count: Operation not supported"
		exit 1
	fi
	echo "RX flow hash indirection table for $i with 6 RX ring(s):"
	echo "    0:      0     1     2     3     4     5     0     1"
	echo "    8:      2     3     4     5     0     1     2     3"
	echo "RSS hash key:"
	cat "$s.key"
	echo "RSS hash function:"
	echo "    toeplitz: on"
	;;
-X)
	[[ "$3" == hkey ]] || exit 2
	[[ -f "$s.key" ]] || { echo "Cannot set RX flow hash configuration: Operation not supported" >&2; exit 1; }
	[[ -f "$s.refuse" ]] && { echo "Cannot set RX flow hash configuration: Invalid argument" >&2; exit 1; }
	[[ -f "$s.sticky" ]] && exit 0
	printf '%s\n' "$4" >"$s.key"
	;;
*) exit 2 ;;
esac
EOF
chmod +x "$T/bin/incus" "$T/bin/ethtool"
export PATH="$T/bin:$PATH"

RANDKEY_A="58:ff:18:80:e5:c0:ca:25:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
RANDKEY_B="a5:a9:04:30:d7:32:14:7d:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"

# node <instance> <netdev:driver:key|-> ...   (key "-" = no RSS key, like virtio)
node() {
	local inst=$1 spec name drv key
	shift
	rm -rf "$T/state/$inst"
	mkdir -p "$T/state/$inst/net" "$T/state/$inst/eth"
	for spec in "$@"; do
		IFS=: read -r name drv key <<<"${spec%%=*}"
		key=${spec#*=}
		mkdir -p "$T/state/$inst/net/$name"
		echo "$drv" >"$T/state/$inst/eth/$name.driver"
		[[ "$key" == "-" ]] || printf '%s\n' "$key" >"$T/state/$inst/eth/$name.key"
	done
}
key_of() { cat "$T/state/$1/eth/$2.key"; }

# Two lab-shaped nodes: the virtio fabric parent (no key), two mlx5 data VFs
# sharing xpfd's random key, a VLAN child and fxp0.
lab_nodes() {
	node fw0 "ge-0-0-0:virtio_net=-" "ge-0-0-1:mlx5_core=$RANDKEY_A" "ge-0-0-2:mlx5_core=$RANDKEY_A" \
		"ge-0-0-2.50:vlan=-" "fxp0:virtio_net=-"
	node fw1 "ge-7-0-0:virtio_net=-" "ge-7-0-1:mlx5_core=$RANDKEY_B" "ge-7-0-2:mlx5_core=$RANDKEY_B"
}

run_cells() { # <library path>; every cell sources it in a subshell
	local lib=$1 out rc pin
	pin="6d:5a:56:da:25:5b:0e:c2:41:67:25:3d:43:a3:8f:b0:d0:ca:2b:cb:ae:7b:30:b4:77:cb:2d:a3:80:30:f2:0c:6a:42:b7:3b:be:ac:01:fa"

	lab_nodes
	out=$(XPF_RSS_RECORD="$T/rec.txt" bash -c 'source "$1"; rss_record post-deploy fw0 fw1' _ "$lib" 2>&1)
	rc=$?
	if ((rc == 0)) && grep -q '^rss\[post-deploy\] fw0: ge-0-0-0 key=none indir=' <<<"$out" &&
		grep -q 'ge-0-0-1 key=[0-9a-f]\{8\} indir=[0-9a-f]\{8\} x=[0-9a-f]\{12\};' <<<"$out" &&
		! grep -q 'ge-0-0-2.50\|fxp0' <<<"$out" && grep -q '^### rss\[post-deploy\] fw1 ' "$T/rec.txt"; then
		ok "record: one line per node, data VFs keyed, VLAN children and fxp0 skipped, raw dump kept"
	else
		bad "record: unexpected output (rc=$rc): $out"
	fi

	out=$(bash -c 'source "$1"; rss_verify fw0 fw1' _ "$lib" 2>&1)
	rc=$?
	if ((rc == 1)) && grep -q 'carries another key' <<<"$out"; then
		ok "verify: xpfd's random keys are not the pin (rc 1)"
	else
		bad "verify on unpinned nodes: rc=$rc out=$out"
	fi

	out=$(bash -c 'source "$1"; rss_pin fw0 fw1' _ "$lib" 2>&1)
	rc=$?
	if ((rc == 0)) && [[ "$(key_of fw0 ge-0-0-1)" == "$pin" && "$(key_of fw1 ge-7-0-2)" == "$pin" ]] &&
		[[ ! -f "$T/state/fw0/eth/ge-0-0-0.key" ]] &&
		bash -c 'source "$1"; rss_record pinned fw0' _ "$lib" | grep -q 'ge-0-0-1 key=PINNED'; then
		ok "pin: every data VF carries the fixed key, the keyless fabric parent untouched, record says PINNED"
	else
		bad "pin: rc=$rc out=$out"
	fi

	printf '%s\n' "$RANDKEY_B" >"$T/state/fw0/eth/ge-0-0-1.key" # a deploy: xpfd's new key
	out=$(bash -c 'source "$1"; rss_verify fw0 fw1' _ "$lib" 2>&1)
	rc=$?
	if ((rc == 1)) && grep -q 'fw0: ge-0-0-1 carries another key' <<<"$out"; then
		ok "verify: a key replaced after the pin (xpfd restart or config commit) is caught"
	else
		bad "verify after drift: rc=$rc out=$out"
	fi

	lab_nodes
	touch "$T/state/fw0/eth/ge-0-0-2.refuse"
	out=$(bash -c 'source "$1"; rss_pin fw0' _ "$lib" 2>&1)
	rc=$?
	if ((rc == 1)) && grep -q 'ge-0-0-2 FAILED' <<<"$out"; then
		ok "pin: a refused key write fails the pin (rc 1)"
	else
		bad "pin with a refused write: rc=$rc out=$out"
	fi

	lab_nodes
	touch "$T/state/fw0/eth/ge-0-0-1.sticky"
	out=$(bash -c 'source "$1"; rss_pin fw0' _ "$lib" 2>&1)
	rc=$?
	if ((rc == 1)) && grep -q 'ge-0-0-1 carries another key' <<<"$out"; then
		ok "pin: a driver that accepts the write but keeps its own key is caught by the read-back"
	else
		bad "pin with a sticky driver: rc=$rc out=$out"
	fi

	node fw9 "ge-0-0-0:virtio_net=-"
	out=$(bash -c 'source "$1"; rss_pin fw9' _ "$lib" 2>&1)
	rc=$?
	if ((rc == 2)) && grep -q 'no data interface with a readable RSS key' <<<"$out"; then
		ok "pin/verify: a node with no keyed data interface is rc 2 (placement uncontrolled), never success"
	else
		bad "keyless node: rc=$rc out=$out"
	fi

	# The last ge-* netdev has no RSS key (its `ethtool -x` fails): the node
	# is still readable, and a pinned data VF before it still verifies.
	node fw8 "ge-0-0-1:mlx5_core=$pin" "ge-0-0-9:virtio_net=-"
	out=$(bash -c 'source "$1"; rss_verify fw8' _ "$lib" 2>&1)
	rc=$?
	if ((rc == 0)); then
		ok "verify: a keyless interface listed last does not make the node unreadable"
	else
		bad "keyless last interface: rc=$rc out=$out"
	fi

	out=$(bash -c 'source "$1"; rss_record x ghost; echo "rc=$?"; rss_verify ghost; echo "rc=$?"' _ "$lib" 2>&1)
	if grep -q 'rss\[x\] ghost: UNREADABLE' <<<"$out" && [[ $(grep -c '^rc=3$' <<<"$out") == 2 ]]; then
		ok "record/verify: an unreadable node is rc 3"
	else
		bad "unreadable node: $out"
	fi

	lab_nodes
	out=$(XPF_RSS_PIN_KEY="00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77" \
		bash -c 'source "$1"; rss_pin fw1' _ "$lib" 2>&1)
	rc=$?
	if ((rc == 0)) && [[ "$(key_of fw1 ge-7-0-1)" == 00:11:22:33:44:55:66:77:88:99:aa:bb:* ]]; then
		ok "pin: XPF_RSS_PIN_KEY overrides the key (case-normalized)"
	else
		bad "key override: rc=$rc out=$out"
	fi
}

# The deploy hook in cluster-setup.sh, extracted and run with stubs.
deploy_hook_cells() {
	local fn out rc
	fn=$(awk '/^deploy_rss_after\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$SCRIPT_DIR/cluster-setup.sh")
	if [[ -z "$fn" ]]; then
		bad "control: could not extract deploy_rss_after from cluster-setup.sh"
		return
	fi
	lab_nodes
	out=$(XPF_RSS_PIN=1 bash -c '
		source "$1"; eval "$2"
		r() { printf "%s\n" "$1"; }; vm_name() { printf "fw%s\n" "$1"; }
		info() { echo "INFO: $*"; }; warn() { echo "WARN: $*"; }; die() { echo "DIE: $*"; exit 1; }
		deploy_rss_after all' _ "$LIB" "$fn" 2>&1)
	rc=$?
	if ((rc == 0)) && grep -q '^rss\[post-deploy\] fw0:' <<<"$out" && grep -q '^rss\[pinned\] fw1: .*ge-7-0-1 key=PINNED' <<<"$out"; then
		ok "deploy hook: records after the deploy, then pins and records PINNED under XPF_RSS_PIN=1"
	else
		bad "deploy hook (pin): rc=$rc out=$out"
	fi
	lab_nodes
	touch "$T/state/fw1/eth/ge-7-0-2.sticky"
	out=$(XPF_RSS_PIN=1 bash -c '
		source "$1"; eval "$2"
		r() { printf "%s\n" "$1"; }; vm_name() { printf "fw%s\n" "$1"; }
		info() { :; }; warn() { :; }; die() { echo "DIE: $*"; exit 1; }
		deploy_rss_after all' _ "$LIB" "$fn" 2>&1)
	rc=$?
	if ((rc != 0)) && grep -q '^DIE: XPF_RSS_PIN=1: the fixed RSS key did not hold' <<<"$out"; then
		ok "deploy hook: a pin that does not hold fails the deploy, so the gate cannot measure (VOID)"
	else
		bad "deploy hook (sticky): rc=$rc out=$out"
	fi
	lab_nodes
	out=$(bash -c '
		unset XPF_RSS_PIN; source "$1"; eval "$2"
		r() { printf "%s\n" "$1"; }; vm_name() { printf "fw%s\n" "$1"; }
		info() { echo "INFO: $*"; }; warn() { :; }; die() { echo "DIE: $*"; exit 1; }
		deploy_rss_after 0' _ "$LIB" "$fn" 2>&1)
	rc=$?
	if ((rc == 0)) && grep -q '^rss\[post-deploy\] fw0:' <<<"$out" && grep -q 'INFO: RSS key not pinned' <<<"$out" &&
		[[ "$(key_of fw0 ge-0-0-1)" == "$RANDKEY_A" ]]; then
		ok "deploy hook: without XPF_RSS_PIN it records and leaves xpfd's key alone"
	else
		bad "deploy hook (no pin): rc=$rc out=$out"
	fi
}

run_cells "$LIB"
deploy_hook_cells

# Mutation leg: each mutant must turn at least one cell red.
mutant() { # <name> <python replace old> <new>
	local name=$1 m="$T/mut-$RANDOM.sh" before=$FAIL passed=$PASS
	python3 -I - "$LIB" "$m" "$2" "$3" <<'PY'
import sys
src, dst, old, new = sys.argv[1:5]
t = open(src).read()
assert t.count(old) == 1, ("anchor", old, t.count(old))
open(dst, "w").write(t.replace(old, new))
PY
	if (($? != 0)); then
		bad "mutant $name: anchor missing (VOID)"
		return
	fi
	echo "--- mutant: $name"
	run_cells "$m" >"$T/mut.out" 2>&1
	FAIL=$before PASS=$passed
	if grep -q '^FAIL:' "$T/mut.out"; then
		ok "mutant $name KILLED by: $(grep '^FAIL:' "$T/mut.out" | head -1 | cut -c7-90)"
	else
		bad "mutant $name SURVIVED"
	fi
}
mutant "pin without read-back" $'\trss_verify "$@"\n\tvrc=$?' $'\ttrue\n\tvrc=$?'
mutant "keyless node passes verify" $'\tif ((nokey)); then return 2; fi' $'\tif ((nokey)); then return 0; fi'
mutant "VLAN children recorded as data interfaces" $'\tcase $i in *.*) continue ;; esac\n\td=$(ethtool -i' $'\td=$(ethtool -i'
mutant "dump status taken from the last ethtool" $'done\nexit 0\'\n\nRSS_REMOTE_PIN' $'done\'\n\nRSS_REMOTE_PIN'
mutant "key read from the header line" $'key = (lines[n + 1] if n + 1 < len(lines) else "")' $'key = (lines[n] if n < len(lines) else "")'

echo
echo "rss-pin selftest: $PASS passed, $FAIL failed"
((FAIL == 0))
