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
RSS_SYSFS="$d/net" RSS_REQUIRED="$d/rss-required" FAKE_ETH="$d/eth" PATH="$MOCK_ROOT/bin:$PATH" exec "$@"
EOF

cat >"$T/bin/ethtool" <<'EOF'
#!/usr/bin/env bash
# Fake ethtool: -i, -x and -X <if> hkey <key> over $FAKE_ETH/<if>.*
op=$1 i=$2 s="$FAKE_ETH/$2"
case "$op" in
-i) echo "driver: $(cat "$s.driver" 2>/dev/null || echo virtio_net)" ;;
-x)
	if [[ -f "$s.broken" ]]; then
		echo "Cannot get RX flow hash indirection table: Input/output error"
		exit 1
	fi
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
	# A fresh record file per run: the mutation leg reruns these cells, and a
	# key one mutant leaked into an appended file must not fail (and so
	# falsely "kill") every later mutant.
	rm -f "$T/rec.txt"
	out=$(XPF_RSS_RECORD="$T/rec.txt" bash -c 'source "$1"; rss_record post-deploy fw0 fw1' _ "$lib" 2>&1)
	rc=$?
	if ((rc == 0)) && grep -q '^rss\[post-deploy\] fw0: ge-0-0-0 key=none indir=' <<<"$out" &&
		grep -q 'ge-0-0-1 key=[0-9a-f]\{8\} indir=[0-9a-f]\{8\} x=[0-9a-f]\{12\};' <<<"$out" &&
		! grep -q 'ge-0-0-2.50\|fxp0' <<<"$out" && grep -q '^### rss\[post-deploy\] fw1 ' "$T/rec.txt" &&
		grep -q '^    <sha256:[0-9a-f]\{12\}>$' "$T/rec.txt" && grep -q 'toeplitz: on' "$T/rec.txt" &&
		! grep -qiF -e "${RANDKEY_A:0:20}" -e "${RANDKEY_B:0:20}" "$T/rec.txt"; then
		ok "record: one line per node, data VFs keyed, VLAN children and fxp0 skipped, dump kept with its key redacted"
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

	# The last ge-* netdev has no RSS key (its `ethtool -x` fails with
	# "Operation not supported"): the node is still readable, and a pinned
	# data VF before it still verifies.
	node fw8 "ge-0-0-1:mlx5_core=$pin" "ge-0-0-9:virtio_net=-"
	out=$(bash -c 'source "$1"; rss_pin fw8 >/dev/null; rss_verify fw8' _ "$lib" 2>&1)
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

	# Review F3: a required VF must not drop out of the verified set.
	lab_nodes
	out=$(bash -c 'source "$1"; rss_pin fw0' _ "$lib" 2>&1)
	rc=$?
	if ((rc == 0)) && [[ "$(tr '\n' ' ' <"$T/state/fw0/rss-required")" == "ge-0-0-1 ge-0-0-2 " ]]; then
		ok "pin: stores the keyed data VFs as the node's required set (the keyless fabric parent is not in it)"
	else
		bad "pin inventory: rc=$rc out=$out inventory=$(cat "$T/state/fw0/rss-required" 2>&1)"
	fi
	touch "$T/state/fw0/eth/ge-0-0-2.broken"
	out=$(bash -c 'source "$1"; rss_verify fw0' _ "$lib" 2>&1)
	rc=$?
	if ((rc == 3)) && grep -q 'ge-0-0-2: ethtool -x failed' <<<"$out"; then
		ok "verify: a pinned VF whose ethtool -x starts failing is unreadable (rc 3), not skipped"
	else
		bad "verify with a failing required VF: rc=$rc out=$out"
	fi
	rm -f "$T/state/fw0/eth/ge-0-0-2.broken"
	rm -rf "$T/state/fw0/net/ge-0-0-2"
	out=$(bash -c 'source "$1"; rss_verify fw0' _ "$lib" 2>&1)
	rc=$?
	if ((rc == 1)) && grep -q 'required interface ge-0-0-2 is missing' <<<"$out"; then
		ok "verify: a pinned VF that vanishes fails verification (rc 1) although the other VF is pinned"
	else
		bad "verify with a vanished required VF: rc=$rc out=$out"
	fi
	lab_nodes
	touch "$T/state/fw0/eth/ge-0-0-2.broken"
	out=$(bash -c 'source "$1"; rss_pin fw0' _ "$lib" 2>&1)
	rc=$?
	if ((rc != 0)) && grep -q 'ge-0-0-2 UNREADABLE' <<<"$out"; then
		ok "pin: a VF whose ethtool -x fails (not 'not supported') fails the pin"
	else
		bad "pin with a failing VF: rc=$rc out=$out"
	fi
	lab_nodes
	out=$(bash -c 'source "$1"; rss_pin fw0 >/dev/null; rm -f "$2"; rss_verify fw0' _ "$lib" "$T/state/fw0/rss-required" 2>&1)
	rc=$?
	if ((rc == 2)) && grep -q 'no pin inventory' <<<"$out"; then
		ok "verify: the inventory removed while the keys stay pinned is rc 2, never success"
	else
		bad "verify without an inventory: rc=$rc out=$out"
	fi
	# The true post-reboot state (Codex review of ae1e5dc3b2): /run lost the
	# inventory AND xpfd programmed its own new key. Mismatch outranks the
	# missing inventory, so this is rc 1, with both reported.
	lab_nodes
	out=$(bash -c 'source "$1"; rss_pin fw0 >/dev/null; rm -f "$2"; printf "%s\n" "$3" >"$4"; printf "%s\n" "$3" >"$5"; rss_verify fw0' \
		_ "$lib" "$T/state/fw0/rss-required" "$RANDKEY_B" "$T/state/fw0/eth/ge-0-0-1.key" "$T/state/fw0/eth/ge-0-0-2.key" 2>&1)
	rc=$?
	if ((rc == 1)) && grep -q 'no pin inventory' <<<"$out" && grep -q 'ge-0-0-1 carries another key' <<<"$out"; then
		ok "verify: after a reboot (inventory gone, xpfd's new key) it is rc 1 (mismatch outranks the missing inventory), both reported"
	else
		bad "verify after a reboot: rc=$rc out=$out"
	fi
	# Re-pin after the interface set changes: the inventory is rebuilt.
	lab_nodes
	bash -c 'source "$1"; rss_pin fw0' _ "$lib" >/dev/null 2>&1
	rm -rf "$T/state/fw0/net/ge-0-0-2"
	mkdir -p "$T/state/fw0/net/ge-0-0-3"
	echo mlx5_core >"$T/state/fw0/eth/ge-0-0-3.driver"
	printf '%s\n' "$RANDKEY_A" >"$T/state/fw0/eth/ge-0-0-3.key"
	out=$(bash -c 'source "$1"; rss_verify fw0; echo "before=$?"; rss_pin fw0 >/dev/null; rss_verify fw0; echo "after=$?"' _ "$lib" 2>&1)
	if grep -q '^before=1$' <<<"$out" && grep -q 'required interface ge-0-0-2 is missing' <<<"$out" &&
		grep -q 'ge-0-0-3 carries another key' <<<"$out" && grep -q '^after=0$' <<<"$out" &&
		[[ "$(tr '\n' ' ' <"$T/state/fw0/rss-required")" == "ge-0-0-1 ge-0-0-3 " ]]; then
		ok "re-pin: after a VF is replaced, verify fails until a re-pin rebuilds the required set"
	else
		bad "re-pin after an interface change: $out inventory=$(cat "$T/state/fw0/rss-required" 2>&1)"
	fi

	# Review F2: the post-cell verdict.
	local res
	res="$T/result.json"
	lab_nodes
	bash -c 'source "$1"; rss_pin fw0 fw1' _ "$lib" >/dev/null 2>&1
	printf '{"summary": {"exit": 0}}\n' >"$res"
	out=$(bash -c 'source "$1"; rss_post_cell_verdict 0 "$2" fw0 fw1; echo "rc=$?"' _ "$lib" "$res" 2>&1)
	if grep -q '^rc=0$' <<<"$out" && grep -q 'pin held from the start to the end' <<<"$out" &&
		python3 -I -c 'import json,sys; o=json.load(open(sys.argv[1])); sys.exit(0 if o["rss"]["post_cell_verify_rc"]==0 and o["summary"]["exit"]==0 else 1)' "$res"; then
		ok "post-cell: an unchanged pin keeps a PASS (rc 0) and is recorded in result.json"
	else
		bad "post-cell control: $out $(cat "$res")"
	fi
	printf '%s\n' "$RANDKEY_B" >"$T/state/fw1/eth/ge-7-0-2.key" # xpfd restored its key mid-cell
	printf '{"summary": {"exit": 0}}\n' >"$res"
	out=$(bash -c 'source "$1"; rss_post_cell_verdict 0 "$2" fw0 fw1; echo "rc=$?"' _ "$lib" "$res" 2>&1)
	if grep -q '^rc=2$' <<<"$out" && grep -q '^ABORT_CAUSE=rss: the RSS pin did not hold' <<<"$out" &&
		python3 -I -c 'import json,sys; o=json.load(open(sys.argv[1])); sys.exit(0 if o["summary"]["exit"]==2 and o["rss"]["effect"]=="PASS->VOID" else 1)' "$res"; then
		ok "post-cell: a key replaced during a passing cell turns it VOID (rc 2, ABORT_CAUSE, result.json exit 2)"
	else
		bad "post-cell drift on PASS: $out $(cat "$res")"
	fi
	printf '{"summary": {"exit": 1}}\n' >"$res"
	out=$(bash -c 'source "$1"; rss_post_cell_verdict 1 "$2" fw0 fw1; echo "rc=$?"' _ "$lib" "$res" 2>&1)
	if grep -q '^rc=1$' <<<"$out" && ! grep -q '^ABORT_CAUSE=' <<<"$out" &&
		python3 -I -c 'import json,sys; o=json.load(open(sys.argv[1])); sys.exit(0 if o["summary"]["exit"]==1 else 1)' "$res"; then
		ok "post-cell: a FAIL stays FAIL (rc 1) when the pin also drifted"
	else
		bad "post-cell drift on FAIL: $out $(cat "$res")"
	fi
	lab_nodes
	bash -c 'source "$1"; rss_pin fw0 fw1' _ "$lib" >/dev/null 2>&1
	out=$(bash -c 'source "$1"; rss_post_cell_verdict 0 "" fw0 ghost; echo "rc=$?"' _ "$lib" 2>&1)
	if grep -q '^rc=2$' <<<"$out" && grep -q '^ABORT_CAUSE=rss: .*rc=3' <<<"$out"; then
		ok "post-cell: a node that cannot be read after the cell turns a PASS into VOID"
	else
		bad "post-cell unreadable: $out"
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
# Review F1: cluster-deploy-and-gate must carry XPF_RSS_PIN to the GATE, not
# only to the deploy. Run the real recipe from a copy of the Makefile, with
# the real deploy-lib.sh, stub with-cluster.sh / cluster-setup.sh, and a stub
# gate target (MAKEFILES) that writes what it observes. The copy is its own
# throwaway git repository, because deploy_gate_wave compares the checkout's
# identity before and after the deploy.
wiring_run() { # <makefile> <label> [make args...] -> prints the probe file
	local mk=$1 label=$2 w="$T/wiring-$2"
	shift 2
	rm -rf "$w"
	mkdir -p "$w/test/incus" "$w/scripts/image"
	cp "$mk" "$w/Makefile"
	# The Makefile validates its build metadata at parse time (#12698).
	cp "$SCRIPT_DIR/../../scripts/image/validate-build-metadata.py" "$w/scripts/image/"
	cp "$SCRIPT_DIR/deploy-lib.sh" "$w/test/incus/deploy-lib.sh"
	printf '%s\n' '#!/usr/bin/env bash' 'while (($#)) && [[ $1 != -- ]]; do shift; done; shift; exec "$@"' >"$w/test/incus/with-cluster.sh"
	printf '%s\n' '#!/usr/bin/env bash' 'echo "deploy XPF_RSS_PIN=${XPF_RSS_PIN-unset}" >>"$RSS_WIRING_PROBE"' >"$w/test/incus/cluster-setup.sh"
	chmod +x "$w/test/incus/with-cluster.sh" "$w/test/incus/cluster-setup.sh"
	printf 'rss-wiring-gate:\n\t@echo "gate XPF_RSS_PIN=$${XPF_RSS_PIN-unset}" >>"$$RSS_WIRING_PROBE"\n' >"$T/wiring-stub.mk"
	(cd "$w" && git init -q && git add -A && git -c user.name=t -c user.email=t@t commit -qm wiring) || {
		echo "WIRING-SETUP-FAILED"
		return
	}
	: >"$T/wiring-$label.probe"
	(cd "$w" && env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL "${WIRING_ENV[@]}" MAKEFILES="$T/wiring-stub.mk" \
		RSS_WIRING_PROBE="$T/wiring-$label.probe" make -s -o prepare-deb cluster-deploy-and-gate \
		CLUSTER_GATE=rss-wiring-gate "$@" >"$T/wiring-$label.out" 2>&1) || echo "MAKE-RC=$?"
	cat "$T/wiring-$label.probe"
}
wiring_cells() { # <makefile> -> 0 if every expectation held
	local mk=$1 got all=0
	WIRING_ENV=(-u XPF_RSS_PIN)
	got=$(wiring_run "$mk" unset)
	if [[ "$got" == $'deploy XPF_RSS_PIN=1\ngate XPF_RSS_PIN=1' ]]; then
		ok "wiring: with XPF_RSS_PIN unset, the deploy AND the gate both see 1"
	else
		bad "wiring (unset): got [${got//$'\n'/|}] $(tail -3 "$T/wiring-unset.out" 2>/dev/null | tr '\n' ' ')"
		all=1
	fi
	got=$(wiring_run "$mk" cmdline XPF_RSS_PIN=0)
	if [[ "$got" == $'deploy XPF_RSS_PIN=0\ngate XPF_RSS_PIN=0' ]]; then
		ok "wiring: XPF_RSS_PIN=0 on the command line stays 0 for the deploy and the gate"
	else
		bad "wiring (cmdline 0): got [${got//$'\n'/|}]"
		all=1
	fi
	WIRING_ENV=(XPF_RSS_PIN=0)
	got=$(wiring_run "$mk" env0)
	if [[ "$got" == $'deploy XPF_RSS_PIN=0\ngate XPF_RSS_PIN=0' ]]; then
		ok "wiring: XPF_RSS_PIN=0 in the environment stays 0 for the deploy and the gate"
	else
		bad "wiring (env 0): got [${got//$'\n'/|}]"
		all=1
	fi
	return "$all"
}
wiring_cells "$SCRIPT_DIR/../../Makefile"
# Its mutant: the pre-fix recipe, which gave the policy to the deploy's env only.
python3 -I - "$SCRIPT_DIR/../../Makefile" "$T/Makefile.mut" <<'PY'
import sys
src, dst = sys.argv[1:3]
t = open(src).read()
old = 'env XPF_RSS_PIN="$(XPF_RSS_PIN)" bash -c \'source ./test/incus/deploy-lib.sh; deploy_gate_wave "$$PWD" "$$1" "$(MAKE)" env BPFRX_CLUSTER_ENV="$(CLUSTER_ENV)" '
new = 'bash -c \'source ./test/incus/deploy-lib.sh; deploy_gate_wave "$$PWD" "$$1" "$(MAKE)" env BPFRX_CLUSTER_ENV="$(CLUSTER_ENV)" XPF_RSS_PIN="$(XPF_RSS_PIN)" '
assert t.count(old) == 1, ("anchor", t.count(old))
open(dst, "w").write(t.replace(old, new))
PY
if (($? != 0)); then
	bad "mutant pin policy given to the deploy only: anchor missing (VOID)"
else
	before=$FAIL passed=$PASS
	echo "--- mutant: pin policy given to the deploy only"
	wiring_cells "$T/Makefile.mut" >"$T/wiring-mut.out" 2>&1
	FAIL=$before PASS=$passed
	if grep -qF 'FAIL: wiring (unset): got [deploy XPF_RSS_PIN=1|gate XPF_RSS_PIN=unset]' "$T/wiring-mut.out"; then
		ok "mutant pin policy given to the deploy only KILLED by: the gate saw XPF_RSS_PIN unset"
	else
		bad "mutant pin policy given to the deploy only SURVIVED: $(grep -m2 'wiring' "$T/wiring-mut.out")"
	fi
fi


# Review (Codex, ae1e5dc3b2): the post-cell verdict must be WIRED into the
# real soak, and reach the ledger. Run the REAL rg-move-soak.sh from a copy
# beside stub cluster-cell.sh / cluster-env.sh and a stub rg_move_soak.py
# that writes result.json, prints the summary pair, and (optionally) puts
# xpfd's key back on one VF mid-run. The real rss-pin.sh and the real
# smoke-cells adapter (harness-result.sh) judge the outcome.
soak_stub_tree() { # <soak script>
	local d="$T/soakstub"
	rm -rf "$d"
	mkdir -p "$d"
	cp "$1" "$d/rg-move-soak.sh"
	cp "$LIB" "$d/rss-pin.sh"
	printf '%s\n' 'xpf_enter_destructive_cluster_cell() { :; }' >"$d/cluster-cell.sh"
	printf '%s\n' 'FW0=fw0 FW1=fw1 CLUSTER_LAN_HOST=lan IPERF_TARGET4=192.0.2.1 IPERF_TARGET6=' >"$d/cluster-env.sh"
	cat >"$d/rg_move_soak.py" <<'PY'
import json, os, sys
args = sys.argv[1:]
out = args[args.index("--outdir") + 1]
rc = 0 if os.environ["STUB_SOAK_MODE"] == "pass" else 1
drift = os.environ.get("STUB_SOAK_DRIFT", "")
if drift:  # xpfd restored its own key on one VF during the cell
    with open(drift, "w") as f:
        f.write(os.environ["STUB_SOAK_DRIFT_KEY"] + "\n")
with open(os.path.join(out, "result.json"), "w") as f:
    json.dump({"summary": {"exit": rc}}, f)
print("rg-move-soak: %d passed, %d failed, 0 cost (0 void)" % ((3, 0) if rc == 0 else (2, 1)))
sys.exit(rc)
PY
}
soak_run() { # <label> <pass|fail> <drift: yes|no> -> "rc verdict reason"
	local label=$1 mode=$2 drift="" out="$T/soakout-$1" rc adapt
	[[ "$3" == yes ]] && drift="$T/state/fw1/eth/ge-7-0-2.key"
	lab_nodes
	bash -c 'source "$1"; rss_pin fw0 fw1' _ "$LIB" >/dev/null 2>&1
	rm -rf "$out"
	(cd "$T/soakstub" && env XPF_RSS_PIN=1 SOAK_OUT="$out" STUB_SOAK_MODE="$mode" STUB_SOAK_DRIFT="$drift" \
		STUB_SOAK_DRIFT_KEY="$RANDKEY_B" bash ./rg-move-soak.sh >"$T/soak-$label.log" 2>&1)
	rc=$?
	adapt=$(bash -c 'source "$1"; harness_adapt_smoke_cells "$2" "$3"' _ "$SCRIPT_DIR/harness-result.sh" "$rc" "$T/soak-$label.log" 2>/dev/null | tail -1)
	printf '%s\t%s\n' "$rc" "$adapt"
}
soak_exit() { # <label> -> result.json summary.exit and rss.effect
	python3 -I -c 'import json,sys; o=json.load(open(sys.argv[1])); print(o["summary"]["exit"], o.get("rss", {}).get("effect", "absent"))' \
		"$T/soakout-$1/result.json" 2>&1
}
soak_cells() { # <soak script> -> 0 if every expectation held
	local all=0 got rc verdict reason
	soak_stub_tree "$1"
	got=$(soak_run drift-pass pass yes)
	IFS=$'\t' read -r rc verdict reason _ <<<"$got"
	if [[ "$rc" == 2 && "$verdict" == VOID && "$reason" == *"ABORT_CAUSE=rss: the RSS pin did not hold"* &&
		"$(soak_exit drift-pass)" == "2 PASS->VOID" ]]; then
		ok "soak: a pin lost during a passing soak exits 2, result.json exit 2 (PASS->VOID), ledger row VOID with the rss reason"
	else
		bad "soak (drift, pass): rc=$rc verdict=$verdict reason=${reason:0:160} json=$(soak_exit drift-pass)"
		all=1
	fi
	got=$(soak_run drift-fail fail yes)
	IFS=$'\t' read -r rc verdict reason _ <<<"$got"
	if [[ "$rc" == 1 && "$verdict" == FAIL && "$(soak_exit drift-fail)" == "1 kept rc=1" ]]; then
		ok "soak: a FAILing soak whose pin also drifted stays FAIL (exit 1, ledger FAIL, result.json exit 1)"
	else
		bad "soak (drift, fail): rc=$rc verdict=$verdict reason=${reason:0:160} json=$(soak_exit drift-fail)"
		all=1
	fi
	got=$(soak_run hold-pass pass no)
	IFS=$'\t' read -r rc verdict reason _ <<<"$got"
	if [[ "$rc" == 0 && "$verdict" == PASS && "$(soak_exit hold-pass)" == "0 none" ]]; then
		ok "soak: a held pin keeps a passing soak PASS (exit 0, ledger PASS, rss recorded in result.json)"
	else
		bad "soak (held, pass): rc=$rc verdict=$verdict reason=${reason:0:160} json=$(soak_exit hold-pass)"
		all=1
	fi
	return "$all"
}
soak_cells "$SCRIPT_DIR/rg-move-soak.sh"
soak_mutant() { # <name> <old> <new>
	local name=$1 before=$FAIL passed=$PASS
	python3 -I - "$SCRIPT_DIR/rg-move-soak.sh" "$T/rg-move-soak.mut" "$2" "$3" <<'PY'
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
	soak_cells "$T/rg-move-soak.mut" >"$T/soak-mut.out" 2>&1
	FAIL=$before PASS=$passed
	if grep -q '^FAIL: soak (drift, pass)' "$T/soak-mut.out"; then
		ok "mutant $name KILLED by: $(grep -m1 '^FAIL: soak (drift, pass)' "$T/soak-mut.out" | cut -c7-110)"
	else
		bad "mutant $name SURVIVED: $(grep -m2 '^FAIL:\|^PASS: soak' "$T/soak-mut.out" | tr '\n' ' ')"
	fi
}
soak_mutant "soak never calls the post-cell verdict" $'\trss_post_cell_verdict "$rc" "$OUT/result.json" "$FW0" "$FW1"\n\trc=$?' $'\t:'
soak_mutant "soak drops the post-cell verdict's status" $'\trss_post_cell_verdict "$rc" "$OUT/result.json" "$FW0" "$FW1"\n\trc=$?' $'\trss_post_cell_verdict "$rc" "$OUT/result.json" "$FW0" "$FW1"'

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
mutant "failed read treated as unsupported" $'    else:\n        state = "failed"' $'    else:\n        state = "unsupported"'
mutant "required set ignored" $'\t\tfor r in $req; do' $'\t\tfor r in ; do'
mutant "pin skips an unreadable interface" $'\t\techo "$i UNREADABLE"\n\t\trc=1' $'\t\t:'
mutant "raw key written to the record" $'"$(printf \'%s\\n\' "$dump" | rss_redact "$pin")"' $'"$dump"'
mutant "post-cell drift keeps a PASS" $'\t\t\trc=2\n\t\t\teffect="PASS->VOID"' $'\t\t\teffect="PASS->VOID"'
mutant "post-cell relabels a FAIL" $'\t\tif ((rc == 0)); then\n\t\t\trc=2' $'\t\tif ((rc <= 1)); then\n\t\t\trc=2'
mutant "key read from the header line" $'key = (lines[n + 1] if n + 1 < len(lines) else "")' $'key = (lines[n] if n < len(lines) else "")'

echo
echo "rss-pin selftest: $PASS passed, $FAIL failed"
((FAIL == 0))
