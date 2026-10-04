#!/usr/bin/env bash
# Hermetic end-to-end test of the #11378/#11379 FBF steering gate.
#
# Runs the real harness under its real private lock-cell entry point against a
# deterministic fake Incus surface. The healthy case exercises IPv4+IPv6
# steering and IPv4 fallback; negative controls cover no transition, a
# blackholed fallback, a stale ISP-B userspace egress, and the original healthy
# leg's wrong-next-hop/drop failures. No cluster, build, or network is used.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/test-fbf-steering.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
mkdir -p "$TMP_DIR/bin"

cat >"$TMP_DIR/bin/incus" <<'FAKE_INCUS'
#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == list ]]; then
	exit 0
fi
if [[ ${1:-} == file ]]; then
	exit 0
fi
[[ ${1:-} == exec ]] || { echo "unexpected Incus command: $*" >&2; exit 2; }
target=$2
shift 2
[[ ${1:-} == -- ]] && shift
command=${1:-}
shift || true

baseline_config() {
	cat <<'EOF'
set interfaces reth0 unit 50 family inet address 172.16.50.8/24
set interfaces reth0 unit 80 family inet address 172.16.80.8/24
set security nat source rule-set lan-to-wan rule snat then source-nat interface
EOF
}

ip_rules4() {
	printf '0: from all lookup local\n1000: from all lookup main\n'
}
ip_rules6() {
	printf '0: from all lookup local\n1000: from all lookup main\n'
}
base_routes4() {
	printf 'default via 172.16.50.1 dev wan50 proto static\n'
	printf '172.16.50.0/24 dev wan50 proto kernel scope link\n'
	printf '172.16.80.0/24 dev wan80 proto kernel scope link\n'
}
base_routes6() {
	printf 'default via 2001:559:8585:50::1 dev wan50 proto static\n'
	printf '2001:559:8585:50::/64 dev wan50 proto kernel scope link\n'
	printf '2001:559:8585:80::/64 dev wan80 proto kernel scope link\n'
}

case "$command" in
	/usr/local/sbin/cli)
		if [[ ${1:-} == -c ]]; then
			query="${2:-}"
			case "$query" in
				'show configuration | display set')
					baseline_config
					if [[ -f "${FBF_FAKE_STATE_DIR}/committed" ]]; then
						printf 'set routing-instances ISP-B instance-type forwarding\n'
						printf 'set firewall family inet filter fbf-steer term to-isp-b then routing-instance ISP-B\n'
						printf 'set services ip-monitoring policy fbf-fallback match rpm-probe FBF-ISP-B\n'
					fi
					;;
				'show system commit history')
					if [[ -f "${FBF_FAKE_STATE_DIR}/commit-marker" ]]; then
						printf '  0  2026-04-01 00:00:00  commit  %s\n' \
							"$(<"${FBF_FAKE_STATE_DIR}/commit-marker")"
						if [[ ${FBF_FAKE_SCENARIO} == foreign-latest ]]; then
							printf '  1  2026-04-01 00:01:00  commit  external-change\n'
						fi
					else
						printf 'No commit history available\n'
					fi
					;;
				'show services ip-monitoring status')
					if [[ ! -f "${FBF_FAKE_STATE_DIR}/committed" ]]; then
						printf 'No ip-monitoring policies configured\n'
					elif [[ ${FBF_FAKE_SCENARIO} == disabled-transition &&
						-f "${FBF_FAKE_STATE_DIR}/poisoned" ]]; then
						printf 'Policy - fbf-fallback (Status: PASS)\n'
						printf 'Route-Action\nISP-B.inet.0 0.0.0.0/0 172.16.80.1 APPLIED\n'
					elif [[ -f "${FBF_FAKE_STATE_DIR}/poisoned" ]]; then
						printf 'Policy - fbf-fallback (Status: FAIL)\n'
						printf 'Route-Action\nISP-B.inet.0 0.0.0.0/0 172.16.50.1 APPLIED\n'
					else
						printf 'Policy - fbf-fallback (Status: PASS)\n'
						printf 'Route-Action\nISP-B.inet.0 0.0.0.0/0 172.16.80.1 APPLIED\n'
					fi
					;;
				*)
					echo "unexpected CLI query: $query" >&2
					exit 2
					;;
			esac
		else
			input=$(cat)
			if [[ $input == *'rollback 1'* ]]; then
				rm -f "${FBF_FAKE_STATE_DIR}/committed" "${FBF_FAKE_STATE_DIR}/commit-marker"
				printf 'configuration rolled back\ncommit complete\n'
			elif [[ $input == *'commit check'* ]]; then
				printf 'load merge complete\nconfiguration check succeeds\n'
			else
				marker="$(sed -n 's/^commit comment //p' <<<"$input")"
				[[ -n "$marker" ]] || { echo "commit marker missing" >&2; exit 2; }
				printf '%s\n' "$marker" >"${FBF_FAKE_STATE_DIR}/commit-marker"
				touch "${FBF_FAKE_STATE_DIR}/committed"
				printf 'load merge complete\ncommit complete\n'
			fi
		fi
		;;
	sh)
		text="${2:-}"
		if [[ $text == *'command -v ip'* || $text == *'command -v ping'* ||
			$text == *'command -v tcpdump'* ]]; then
			:
		elif [[ $text == *'timeout '*tcpdump* ]]; then
			touch "${FBF_FAKE_STATE_DIR}/capture-active"
			printf '9001\n' >"${FBF_FAKE_STATE_DIR}/capture.pid"
		elif [[ $text == *'kill -INT'* ]]; then
			rm -f "${FBF_FAKE_STATE_DIR}/capture-active"
		elif [[ $text == *'ip -6 rule show'* ]]; then
			printf '200\n'
		elif [[ $text == *'ip -4 rule show'* || $text == *'ip rule show'* ]]; then
			printf '100\n'
		elif [[ $text == *'curl -fsS 127.0.0.1:8080/metrics'* ]]; then
			family=inet
			[[ $text == *'family="inet6"'* ]] && family=inet6
			counter_file="${FBF_FAKE_STATE_DIR}/metric-${family}"
			n=0
			[[ -f $counter_file ]] && read -r n <"$counter_file"
			n=$((n + 1))
			printf '%s\n' "$n" >"$counter_file"
			if (( n % 2 == 1 )); then printf '0\n'; else printf '6\n'; fi
		else
			echo "unexpected remote shell command: $text" >&2
			exit 2
		fi
		;;
	ip)
		args="$*"
		if [[ "$target" == *xpf-mouse-target && $args == *'neigh show to 2001:559:8585:80::1'* ]]; then
			printf '2001:559:8585:80::1 dev eth0 lladdr 02:00:00:00:80:01 REACHABLE\n'
		elif [[ "$target" == *xpf-mouse-target && $args == *'neigh show to 172.16.80.1'* ]]; then
			printf '172.16.80.1 dev eth0 lladdr 02:00:00:00:80:01 REACHABLE\n'
		elif [[ $args == *'-4 -j -details neigh show'* ]]; then
			if [[ -f "${FBF_FAKE_STATE_DIR}/neighbor.json" ]]; then
				cat "${FBF_FAKE_STATE_DIR}/neighbor.json"
			else
				printf '[]\n'
			fi
		elif [[ $args == *'-4 neigh replace'* && $args == *'nud permanent'* ]]; then
			dead=""
			read -r -a parts <<<"$args"
			for ((i = 0; i < ${#parts[@]} - 1; i++)); do
				[[ ${parts[$i]} == lladdr ]] && dead="${parts[$((i + 1))]}"
			done
			printf '[{"dst":"172.16.80.1","dev":"wan80","lladdr":"%s","state":"PERMANENT","flags":[]}]\n' \
				"$dead" >"${FBF_FAKE_STATE_DIR}/neighbor.json"
			touch "${FBF_FAKE_STATE_DIR}/poisoned"
		elif [[ $args == *'-4 neigh replace'* ]]; then
			printf '[{"dst":"172.16.80.1","dev":"wan80","lladdr":"02:00:00:00:80:99","state":"STALE","flags":["router"]}]\n' \
				>"${FBF_FAKE_STATE_DIR}/neighbor.json"
			rm -f "${FBF_FAKE_STATE_DIR}/poisoned"
		elif [[ $args == *'-4 neigh del'* ]]; then
			rm -f "${FBF_FAKE_STATE_DIR}/neighbor.json" "${FBF_FAKE_STATE_DIR}/poisoned"
		elif [[ $args == *'route get 172.16.80.1'* ]]; then
			printf '172.16.80.1 dev wan80 src 172.16.80.8 uid 0\n'
		elif [[ $args == *'-4 route show table all'* ]]; then
			base_routes4
		elif [[ $args == *'-6 route show table all'* ]]; then
			base_routes6
		elif [[ $args == *'-6 route show table 200'* ]]; then
			printf 'default via 2001:559:8585:80::1 dev wan80 proto static\n'
		elif [[ $args == *'-4 route show table 100'* ]]; then
			if [[ -f "${FBF_FAKE_STATE_DIR}/poisoned" &&
				${FBF_FAKE_SCENARIO} != disabled-transition ]]; then
				printf 'default via 172.16.50.1 dev wan50 proto static\n'
			else
				printf 'default via 172.16.80.1 dev wan80 proto static\n'
			fi
		elif [[ $args == *'-6 route show default'* ]]; then
			printf 'default via 2001:559:8585:50::1 dev wan50 proto static\n'
		elif [[ $args == *'-4 route show default'* ]]; then
			printf 'default via 172.16.50.1 dev wan50 proto static\n'
		elif [[ $args == *'rule show'* ]]; then
			if [[ $args == *'-6'* ]]; then ip_rules6; else ip_rules4; fi
		elif [[ $args == *'nexthop show'* ]]; then
			:
		else
			echo "unexpected ip command on $target: $args" >&2
			exit 2
		fi
		;;
	ping)
		args=("$@")
		identifier=""
		family=4
		class=control
		phase=baseline
		for ((i = 0; i < ${#args[@]}; i++)); do
			[[ ${args[$i]} == -6 ]] && family=6
			[[ ${args[$i]} == -Q && ${args[$((i + 1))]:-} == 0x68 ]] && class=marked
			if [[ ${args[$i]} == -e && -n ${args[$((i + 1))]:-} ]]; then
				identifier="${args[$((i + 1))]}"
			fi
		done
		if [[ -n "$identifier" ]]; then
			[[ -f "${FBF_FAKE_STATE_DIR}/poisoned" ]] && phase=fallback
			printf '%s\t%s\t%s\t%s\n' "$phase" "$family" "$class" "$identifier" \
				>>"${FBF_FAKE_STATE_DIR}/probes.tsv"
		fi
		drop=0
		if [[ ${FBF_FAKE_SCENARIO} == steer-and-drop && $phase == baseline && $class == marked ]]; then
			drop=1
		elif [[ ${FBF_FAKE_SCENARIO} == fallback-drop && $phase == fallback && $class == marked ]]; then
			drop=1
		fi
		if (( drop )); then
			printf '5 packets transmitted, 0 received, 100%% packet loss\n'
		else
			printf '5 packets transmitted, 5 received, 0%% packet loss\n'
		fi
		;;
	rm)
		if [[ "$target" == *xpf-mouse-target ]]; then
			rm -f "${FBF_FAKE_STATE_DIR}/capture-active" "${FBF_FAKE_STATE_DIR}/capture.pid"
		fi
		;;
	tcpdump)
		exit 0
		;;
	cat)
		if [[ "$target" != *xpf-mouse-target ]]; then
			echo "unexpected remote cat target: $target $*" >&2
			exit 2
		fi
		[[ -f "${FBF_FAKE_STATE_DIR}/probes.tsv" ]] || exit 0
		while IFS=$'\t' read -r phase family class identifier; do
			[[ -n "$identifier" ]] || continue
			if [[ $phase == baseline ]]; then
				if [[ $class == marked ]]; then
					mac4=02:00:00:00:80:01
					mac6=02:00:00:00:80:01
					[[ ${FBF_FAKE_SCENARIO} == wrong-egress ]] && {
						mac4=02:00:00:00:80:02
						mac6=02:00:00:00:80:02
					}
					src4=172.16.80.8
					src6=2001:559:8585:80::8
					tos4=0x68
					tos6=0x68
				else
					mac4=02:00:00:00:80:08
					mac6=02:00:00:00:80:08
					src4=172.16.50.8
					src6=2001:559:8585:50::8
					tos4=0x0
					tos6=0x0
				fi
			elif [[ $class == marked ]]; then
				[[ ${FBF_FAKE_SCENARIO} == fallback-drop ]] && continue
				mac4=02:00:00:00:80:01
				src4=172.16.50.8
				[[ ${FBF_FAKE_SCENARIO} == fallback-wrong-egress ]] && src4=172.16.80.8
				tos4=0x68
			else
				mac4=02:00:00:00:80:08
				src4=172.16.50.8
				tos4=0x0
			fi
			for seq in 1 2 3 4 5; do
				if [[ $family == 4 ]]; then
					printf '12:00:00.00000%s %s > 02:00:00:00:80:ee, ethertype IPv4 (0x0800), length 98: IP (tos %s, ttl 64, id %s, offset 0, flags [DF], proto ICMP (1), length 84) %s > 172.16.80.201: ICMP echo request, id %s, seq %s, length 64\n' \
						"$seq" "$mac4" "$tos4" "$seq" "$src4" "$identifier" "$seq"
				else
					printf '12:00:00.00000%s %s > 02:00:00:00:80:ee, ethertype IPv6 (0x86dd), length 98: IP6 (class %s, flowlabel 0, hlim 64, next-header ICMPv6 (58), payload length: 64) %s > 2001:559:8585:80::201: ICMP6, echo request, id %s, seq %s, length 64\n' \
						"$seq" "$mac6" "$tos6" "$src6" "$identifier" "$seq"
				fi
			done
		done <"${FBF_FAKE_STATE_DIR}/probes.tsv"
		;;
	*)
		echo "unexpected remote command: $command $*" >&2
		exit 2
		;;
esac
FAKE_INCUS
chmod +x "$TMP_DIR/bin/incus"
cat >"$TMP_DIR/bin/sleep" <<'FAKE_SLEEP'
#!/usr/bin/env sh
exit 0
FAKE_SLEEP
chmod +x "$TMP_DIR/bin/sleep"

pass=0
fail=0
run_case() {
	local scenario="$1" expected="$2" state output rc=0 summary
	state="${TMP_DIR}/${scenario}"
	output="${TMP_DIR}/${scenario}.out"
	mkdir -p "$state"
	if [[ "$scenario" != healthy-absent ]]; then
		printf '[{"dst":"172.16.80.1","dev":"wan80","lladdr":"02:00:00:00:80:99","state":"STALE","flags":["router"]}]\n' \
			>"${state}/neighbor.json"
	else
		touch "${state}/neighbor-absent"
	fi
	if FBF_FAKE_SCENARIO="$scenario" FBF_FAKE_STATE_DIR="$state" \
		XPF_CLUSTER_LOCK="${state}/cluster.lock" XPF_CLUSTER_OWNER="${state}/cluster.owner" \
		XPF_CLUSTER_EPOCH="${state}/cluster.epoch" XPF_CLUSTER_EPOCH_STATE_DIR="$state" \
		XPF_CLUSTER_BUILD_PROBE=0 FBF_FAILOVER_DEADLINE=1 \
		PATH="${TMP_DIR}/bin:${PATH}" bash "$HARNESS" >"$output" 2>&1; then
		rc=0
	else
		rc=$?
	fi
	summary="$(grep -E '[0-9]+ passed, [0-9]+ failed' "$output" || true)"
	case "$expected" in
		pass)
			if (( rc == 0 )) && grep -Fq 'PASS: FBF healthy steering plus IPv4 ip-monitoring fallback verified' "$output" \
				&& grep -Eq '[0-9]+ passed, 0 failed' <<<"$summary"; then
				pass=$((pass + 1)); printf 'ok   %-26s -> IPv4 fallback and IPv4/IPv6 healthy steering PASS\n' "$scenario"
			else
				fail=$((fail + 1)); printf 'FAIL %-26s -> expected completed PASS (exit %s)\n' "$scenario" "$rc"; cat "$output"
			fi
			;;
		baseline-drop)
			if (( rc != 0 )) && grep -Fq 'received only 0/5 replies' "$output" \
				&& grep -Eq '[0-9]+ passed, [1-9][0-9]* failed' <<<"$summary"; then
				pass=$((pass + 1)); printf 'ok   %-26s -> healthy-leg drop rejected\n' "$scenario"
			else
				fail=$((fail + 1)); printf 'FAIL %-26s -> baseline drop must fail measured forwarding (exit %s)\n' "$scenario"; cat "$output"
			fi
			;;
		wrong-egress)
			if (( rc != 0 )) && grep -Fq 'IPv4 target replies: ISP-B echo check received 5/5 replies' "$output" \
				&& grep -Fq 'marked IPv4 requests did not arrive from ISP-B gateway MAC' "$output"; then
				pass=$((pass + 1)); printf 'ok   %-26s -> replies with wrong healthy-leg next hop rejected\n' "$scenario"
			else
				fail=$((fail + 1)); printf 'FAIL %-26s -> wrong healthy-leg next hop must fail (exit %s)\n' "$scenario"; cat "$output"
			fi
			;;
		no-transition)
			if (( rc != 0 )) && grep -Fq 'stayed PASS despite the deliberate ISP-B neighbor blackhole' "$output" \
				&& grep -Eq '[0-9]+ passed, [1-9][0-9]* failed' <<<"$summary"; then
				pass=$((pass + 1)); printf 'ok   %-26s -> disabled ip-monitoring transition rejected\n' "$scenario"
			else
				fail=$((fail + 1)); printf 'FAIL %-26s -> missing fallback transition must fail (exit %s)\n' "$scenario"; cat "$output"
			fi
			;;
		fallback-drop)
			if (( rc != 0 )) && grep -Fq 'IPv4 marked fallback probe failed: ISP-B echo check received only 0/5 replies' "$output" \
				&& grep -Eq '[0-9]+ passed, [1-9][0-9]* failed' <<<"$summary"; then
				pass=$((pass + 1)); printf 'ok   %-26s -> fallback blackhole rejected\n' "$scenario"
			else
				fail=$((fail + 1)); printf 'FAIL %-26s -> dropped fallback traffic must fail (exit %s)\n' "$scenario"; cat "$output"
			fi
			;;
		wrong-source)
			if (( rc != 0 )) && grep -Fq 'IPv4 fallback marked replies: ISP-B echo check received 5/5 replies' "$output" \
				&& grep -Fq 'did not use expected ISP-A interface-SNAT source 172.16.50.8' "$output" \
				&& grep -Eq '[0-9]+ passed, [1-9][0-9]* failed' <<<"$summary"; then
				pass=$((pass + 1)); printf 'ok   %-26s -> stale ISP-B source rejected after route transition\n' "$scenario"
			else
				fail=$((fail + 1)); printf 'FAIL %-26s -> wrong fallback egress source must fail (exit %s)\n' "$scenario"; cat "$output"
			fi
			;;
		ownership-refused)
			if (( rc != 0 )) && grep -Fq 'latest commit is not owned by marker' "$output" \
				&& grep -Fq 'refusing rollback' "$output" \
				&& ! grep -Fq 'Restoring pre-test config' "$output" \
				&& grep -Eq '[0-9]+ passed, [1-9][0-9]* failed' <<<"$summary"; then
				pass=$((pass + 1)); printf 'ok   %-26s -> unowned latest commit is not rolled back\n' "$scenario"
			else
				fail=$((fail + 1)); printf 'FAIL %-26s -> unowned latest commit must block rollback (exit %s)\n' "$scenario"; cat "$output"
			fi
			;;
	esac

	if ! grep -Fq 'lock acquired' "$output" || ! grep -Fq 'purpose: test-fbf-steering' "$output"; then
		fail=$((fail + 1)); printf 'FAIL %-26s -> script did not acquire the shared-cell lock\n' "$scenario"
	fi
	if [[ "$expected" == ownership-refused ]]; then
		[[ -e "${state}/committed" ]] || {
			fail=$((fail + 1)); printf 'FAIL %-26s -> script rolled back a config after ownership changed\n' "$scenario"
		}
	else
		[[ ! -e "${state}/committed" ]] || {
			fail=$((fail + 1)); printf 'FAIL %-26s -> fixture config was not restored\n' "$scenario"
		}
	fi
	[[ ! -e "${state}/poisoned" ]] || {
		fail=$((fail + 1)); printf 'FAIL %-26s -> poisoned neighbor was not restored\n' "$scenario"
	}
	if [[ "$scenario" == healthy-absent ]]; then
		[[ ! -e "${state}/neighbor.json" ]] || {
			fail=$((fail + 1)); printf 'FAIL %-26s -> absent neighbor predecessor was not restored\n' "$scenario"
		}
	elif ! grep -Fq '"lladdr":"02:00:00:00:80:99","state":"STALE","flags":["router"]' "${state}/neighbor.json"; then
		fail=$((fail + 1)); printf 'FAIL %-26s -> exact prior neighbor MAC/NUD/flags were not restored\n' "$scenario"
	fi
}

run_case healthy pass
run_case healthy-absent pass
run_case steer-and-drop baseline-drop
run_case wrong-egress wrong-egress
run_case disabled-transition no-transition
run_case fallback-drop fallback-drop
run_case fallback-wrong-egress wrong-source
run_case foreign-latest ownership-refused
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
