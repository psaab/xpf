#!/usr/bin/env bash
# Script-level regression cell for test-private-rg.sh (#12211).
# Runs the real full-cycle script with fake Incus/make/sleep and no cluster.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
SCRIPT="${2:-$SRC/test/incus/test-private-rg.sh}"
# shellcheck source=test/incus/private-rg-lib.sh
source "$SRC/test/incus/private-rg-lib.sh"
W=$(mktemp -d "${TMPDIR:-/var/worktrees/.cache/tmpdir}/private-rg-fullcycle.XXXXXX")
trap 'rm -rf "$W"' EXIT
fails=0
ok() { echo "PASS: $*"; }
bad() { echo "FAIL: $*"; fails=$((fails + 1)); }

mkdir -p "$W/bin"
cat >"$W/bin/incus" <<'EOF'
#!/usr/bin/env bash
S="$FAKE_STATE"
[[ "$1" == exec ]] || exit 0
shift
node="$1"
shift
[[ "$1" == -- ]] && shift
cmd="$1"
shift
mode=$(cat "$S/mode" 2>/dev/null || echo private)
case "$cmd" in
systemctl)
	if [[ "$1" == is-active ]]; then
		echo "$node after-deploy-$(cat "$S/deploys" 2>/dev/null || echo 0)" >>"$S/ready.log"
	elif [[ "$1" == show ]]; then
		[[ -f "$S/empty-invocation" ]] || echo "inv-$(cat "$S/deploys" 2>/dev/null || echo 0)"
	fi
	exit 0
	;;
journalctl)
	printf '%s\n' "$*" >>"$S/journal.calls"
	[[ " $* " == *" _SYSTEMD_INVOCATION_ID=inv-"* && " $* " != *" -n "* ]] || exit 95
	echo "xpfd: started"
	[[ "$mode" == legacy ]] && printf 'vrrp: instance starting\nvrrp: state change to MASTER\n'
	exit 0
	;;
cli)
	printf '%s %s\n' "$node" "$(cat "$S/deploys" 2>/dev/null || echo 0)" >>"$S/cli.log"
	[[ -f "$S/cli-fail" ]] && exit 88
	if [[ -f "$S/$node.conf" ]]; then
		cat "$S/$node.conf"
	elif [[ -n "${FAKE_BAD_ATTEST:-}" && "$(cat "$S/deploys")" == 3 ]]; then
		: >"$S/bad-attest"
		echo "set chassis cluster cluster-id 22"
		echo "set chassis cluster no-private-rg-election"
	else
		echo "set chassis cluster cluster-id 22"
		[[ "$mode" == legacy ]] && echo "set chassis cluster no-private-rg-election"
	fi
	exit 0
	;;
timeout)
	printf '%s\n' "$*" | grep -oE -- '-i [^ ]+' >>"$S/capture.log"
	case " $* " in
	*" -i ge-0-0-2 "*|*" -i ge-0-0-1 "*) echo "0 packets captured" >&2; exit 124 ;;
	esac
	echo "tcpdump: unexpected capture target: $*" >&2
	exit 1
	;;
ip)
	printf 'inet %s/24\ninet %s/24\ninet6 %s/64\n' "$WAN_VIP4" "$LAN_VIP4" "$LAN_VIP6"
	;;
esac
exit 0
EOF
cat >"$W/bin/make" <<'EOF'
#!/usr/bin/env bash
S="$FAKE_STATE"
n=$(( $(cat "$S/deploys" 2>/dev/null || echo 0) + 1 ))
echo "$n" >"$S/deploys"
echo "$n FAST=${XPF_DEPLOY_FAST:-}" >>"$S/make.log"
if grep -q no-private-rg-election "$CLUSTER_CONF"; then echo legacy; else echo private; fi >"$S/mode"
if [[ "${FAKE_FAIL_RESTORE_ON:-}" == "$n" ]]; then : >"$S/fail-restore"; fi
for i in 1 2 3 4 5 6 7 8; do echo "deploy line $i"; done
if [[ "${FAKE_INT_ON:-}" == "$n" ]]; then kill -s INT 0; /usr/bin/sleep 1; fi
[[ "${FAKE_TERM_ON:-}" == "$n" ]] && kill -TERM "$(cat "$S/pid")"
[[ "${FAKE_FAIL_ON:-}" == "$n" ]] && exit 2
exit 0
EOF
cat >"$W/bin/cp" <<'EOF'
#!/usr/bin/env bash
destination="${!#}"
if [[ -f "$FAKE_STATE/fail-restore" && "$destination" == "$CLUSTER_CONF" ]]; then
	echo "injected restore-copy failure" >&2
	exit 1
fi
exec /bin/cp "$@"
EOF
printf '#!/bin/sh\nexit 0\n' >"$W/bin/sleep"
chmod +x "$W/bin/"*

run_case() { # run_case <label> <wanted-rc> [VAR=val...]
	local label="$1" wanted="$2"
	shift 2
	local T="$W/$label" S="$W/$label.state"
	mkdir -p "$T/test/incus" "$T/docs" "$S/tmp"
	cp "$SCRIPT" "$T/test/incus/test-private-rg.sh"
	cp "$SRC/test/incus/cluster-env.sh" "$SRC/test/incus/loss-userspace-cluster.env" "$T/test/incus/"
	cp "$SRC/test/incus/private-rg-lib.sh" "$T/test/incus/"
	cp "$SRC/docs/ha-cluster-userspace.conf" "$T/docs/"
	echo 'xpf_enter_destructive_cluster_cell() { :; }' >"$T/test/incus/cluster-cell.sh"
	git -C "$T" init -q && git -C "$T" add -A &&
		git -C "$T" -c user.name=selftest -c user.email=selftest@example.invalid commit -qm base
	if [[ "$label" == dirty-start ]]; then
		printf '\n# pre-existing mode-neutral user edit\n' >>"$T/docs/ha-cluster-userspace.conf"
	fi
	cp "$T/docs/ha-cluster-userspace.conf" "$S/orig"
	if [[ "$label" == sigpipe-* ]]; then
		(
			cd "$T" || exit 99
			env -u BPFRX_CLUSTER_ENV -u CLUSTER_CONF -u PROJECT_ROOT -u FW0 -u FW1 \
				PATH="$W/bin:$PATH" FAKE_STATE="$S" HOME="$W" INCUS_CONF="$W/none" TMPDIR="$S/tmp" "$@" \
				setsid -w bash -c 'trap ":" INT
					bash test/incus/test-private-rg.sh full 2>&1 | tee "$FAKE_STATE/tee.log" >/dev/null
					pipeline_status=("${PIPESTATUS[@]}")
					printf "%s %s\n" "${pipeline_status[0]}" "${pipeline_status[1]}" >"$FAKE_STATE/pipeline-status"
					exit "${pipeline_status[0]}"'
		) >"$S/out" 2>&1
	else
		(
			cd "$T" || exit 99
			env -u BPFRX_CLUSTER_ENV -u CLUSTER_CONF -u PROJECT_ROOT -u FW0 -u FW1 \
				PATH="$W/bin:$PATH" FAKE_STATE="$S" HOME="$W" INCUS_CONF="$W/none" TMPDIR="$S/tmp" "$@" \
				bash -c 'echo $$ >"$FAKE_STATE/pid"; exec bash test/incus/test-private-rg.sh full'
		) >"$S/out" 2>&1
	fi
	local rc=$?
	if [[ "$rc" == "$wanted" ]]; then
		ok "$label: exit $rc"
	else
		bad "$label: exit $rc, wanted $wanted"
		cat "$S/out"
	fi
	if [[ "$label" == restore-failure* ]]; then
		local snapshot
		snapshot=$(find "$S/tmp" -path '*/test-private-rg-conf.*/conf' -type f -print)
		[[ "$(cat "$S/deploys")" == 2 ]] && ok "$label: skipped cleanup redeploy" || bad "$label: cleanup deploy count $(cat "$S/deploys")"
		[[ -n "$snapshot" ]] && cmp -s "$S/orig" "$snapshot" &&
			ok "$label: original snapshot retained" || bad "$label: original snapshot missing or changed"
		[[ -n "$snapshot" ]] && grep -Fq "not redeploying an unrestored $T/docs/ha-cluster-userspace.conf; original bytes kept at $snapshot" "$S/out" &&
			ok "$label: retained snapshot path reported" || bad "$label: retained snapshot path not reported"
		if [[ "$label" == restore-failure-after-pass ]]; then
			[[ "$(cat "$S/mode")" == legacy ]] &&
				ok "$label: failed restore leaves deployed mode unchanged" || bad "$label: failed restore mode $(cat "$S/mode")"
		fi
		return
	fi
	if [[ "$label" == dirty-start ]]; then
		cmp -s "$T/docs/ha-cluster-userspace.conf" "$S/orig" &&
		   ! git -C "$T" diff --quiet -- docs/ha-cluster-userspace.conf &&
			ok "$label: pre-existing tracked edit preserved without false failure" || bad "$label: pre-existing tracked edit was not preserved"
	else
		cmp -s "$T/docs/ha-cluster-userspace.conf" "$S/orig" && git -C "$T" diff --quiet -- docs/ha-cluster-userspace.conf &&
			ok "$label: CONF byte-identical + git-clean" || bad "$label: CONF not restored"
	fi
	if [[ "$(cat "$S/mode" 2>/dev/null)" == private ]]; then
		ok "$label: cluster left in private mode"
	else
		bad "$label: cluster left in $(cat "$S/mode" 2>/dev/null) mode"
	fi
	[[ "$(grep -c 'FAST=1$' "$S/make.log" 2>/dev/null)" == "$(wc -l <"$S/make.log")" ]] &&
		ok "$label: every deploy is raw" || bad "$label: non-raw deploy"
	if [[ "$label" == sigpipe-bad-attest ]]; then
		[[ "$(grep -c " $(wc -l <"$S/make.log")$" "$S/cli.log" 2>/dev/null)" == 1 ]] &&
			ok "$label: failed attestation stops at the first node" || bad "$label: failed attestation did not stop at the first node"
	else
		[[ "$(grep -c " $(wc -l <"$S/make.log")$" "$S/cli.log" 2>/dev/null)" == 2 ]] &&
			ok "$label: both nodes attested after the final deploy" || bad "$label: missing two-node attestation after final deploy"
	fi
	if [[ "$label" == sigpipe-* ]]; then
		[[ "$(cat "$S/deploys")" == 3 ]] &&
			ok "$label: cleanup reached the third deploy" || bad "$label: deploy count $(cat "$S/deploys")"
		if [[ "$label" == sigpipe-bad-attest ]]; then
			[[ -f "$S/bad-attest" ]] &&
				ok "$label: injected failed post-restore attestation" || bad "$label: post-restore attestation was not exercised"
			if find "$S/tmp" -maxdepth 1 -type d -name 'test-private-rg-conf.*' -print -quit | grep -q .; then
				bad "$label: leaked private snapshot after failed attestation"
			else
				ok "$label: no private snapshot leaked after failed attestation"
			fi
		else
			[[ -f "$S/pipeline-status" && "$(cut -d' ' -f1 "$S/pipeline-status")" == 130 ]] &&
				ok "$label: piped script preserved Ctrl-C exit 130" || bad "$label: missing Ctrl-C script status"
		fi
		[[ "$(grep -c ' after-deploy-3$' "$S/ready.log" 2>/dev/null)" == 2 ]] &&
			ok "$label: readiness probed both nodes after final deploy" || bad "$label: readiness probes after final deploy $(grep -c ' after-deploy-3$' "$S/ready.log" 2>/dev/null)"
	fi
	if [[ "$label" == success ]]; then
		[[ "$(sort -u "$S/capture.log" 2>/dev/null | tr '\n' ' ')" == "-i ge-0-0-1 -i ge-0-0-2 " ]] &&
			ok "$label: captured exactly the LAN+WAN RETH members" || bad "$label: capture targets $(sort -u "$S/capture.log" 2>/dev/null | tr '\n' ' ')"
	fi
}

run_case success 0
run_case abort-deploy2 2 FAKE_FAIL_ON=2
run_case term-deploy2 143 FAKE_TERM_ON=2
run_case restore-failure 2 FAKE_FAIL_ON=2 FAKE_FAIL_RESTORE_ON=2
run_case restore-failure-after-pass 1 FAKE_FAIL_RESTORE_ON=2
run_case redeploy-failure 1 FAKE_FAIL_ON=3
run_case dirty-start 0
run_case sigpipe-probes 130 FAKE_INT_ON=2
run_case sigpipe-bad-attest 130 FAKE_INT_ON=2 FAKE_BAD_ATTEST=1
# Guard tests run the production library against the same fake Incus boundary.
GUARD="$W/guards"
mkdir -p "$GUARD"
: >"$GUARD/deploys"
echo 0 >"$GUARD/deploys"
: >"$GUARD/mode"
: >"$GUARD/journal.calls"
export PATH="$W/bin:$PATH" FAKE_STATE="$GUARD"
touch "$GUARD/empty-invocation"
if ! privrg_xpfd_journal fw0 >"$GUARD/journal.out" 2>&1 && [[ ! -s "$GUARD/journal.calls" ]]; then
	ok "empty invocation ID fails closed before journal query"
else
	bad "empty invocation ID fails closed before journal query"
fi
rm -f "$GUARD/empty-invocation"

: >"$GUARD/fw0.conf"
if privrg_assert_running_mode fw0 private 2>"$GUARD/empty-config.err"; then
	bad "empty running config cannot attest private mode"
elif grep -q 'FATAL: privrg: running chassis cluster config is empty' "$GUARD/empty-config.err"; then
	ok "empty running config cannot attest private mode"
else
	bad "empty running config cannot attest private mode"
fi
printf 'unreadable response\n' >"$GUARD/fw0.conf"
if privrg_assert_running_mode fw0 private 2>"$GUARD/unreadable.err"; then
	bad "config without readable chassis-cluster set lines fails closed"
elif grep -q 'no readable chassis cluster set lines' "$GUARD/unreadable.err"; then
	ok "config without readable chassis-cluster set lines fails closed"
else
	bad "config without readable chassis-cluster set lines fails closed"
fi
touch "$GUARD/cli-fail"
if privrg_assert_running_mode fw0 private 2>"$GUARD/cli-fail.err"; then
	bad "unreadable Incus config response fails closed"
elif grep -q 'cannot read running chassis cluster config' "$GUARD/cli-fail.err"; then
	ok "unreadable Incus config response fails closed"
else
	bad "unreadable Incus config response fails closed"
fi
rm -f "$GUARD/cli-fail"
printf 'set chassis cluster node 0\n' >"$GUARD/fw0.conf"
printf 'set chassis cluster no-private-rg-election\n' >"$GUARD/fw1.conf"
if privrg_assert_both_running_modes fw0 fw1 private 2>"$GUARD/split.err"; then
	bad "node1 running mode is included in two-node attestation"
elif grep -q 'fw1 running config still disables' "$GUARD/split.err"; then
	ok "node1 running mode is included in two-node attestation"
else
	bad "node1 running mode is included in two-node attestation"
fi
if privrg_snapshot_conf "$GUARD/missing.conf" "$GUARD/missing.snapshot" 2>"$GUARD/missing.err"; then
	bad "snapshot rejects missing source with an actionable failure"
elif grep -q 'FATAL: privrg: refusing to snapshot missing conf' "$GUARD/missing.err" && [[ ! -e "$GUARD/missing.snapshot" ]]; then
	ok "snapshot rejects missing source with an actionable failure"
else
	bad "snapshot rejects missing source with an actionable failure"
fi

echo "private-rg full-cycle selftest: $fails failure(s)"
[[ "$fails" -eq 0 ]]
