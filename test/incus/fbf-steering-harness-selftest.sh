#!/usr/bin/env bash
# Hermetic end-to-end test of the #11306 FBF steering verdict.
#
# Runs the real harness against a deterministic fake Incus surface with valid
# tables and term-hit deltas. Drop has no replies; wrong-egress has replies but
# the peer capture's marked source MAC is not the resolved ISP-B gateway.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/test-fbf-steering.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
mkdir -p "$TMP_DIR/bin"

cat > "$TMP_DIR/bin/incus" <<'FAKE_INCUS'
#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == file ]]; then
    exit 0
fi
[[ ${1:-} == exec ]] || { echo "unexpected Incus command: $*" >&2; exit 2; }
target=$2
shift 2
[[ ${1:-} == -- ]] && shift
command=${1:-}
shift || true

case "$command" in
    /usr/local/sbin/cli)
        if [[ ${1:-} == -c ]]; then
            printf 'policy fbf-fallback is active\n'
        else
            input=$(cat)
            if [[ $input == *'rollback 1'* ]]; then
                printf 'configuration rolled back\ncommit complete\n'
            else
                printf 'load merge complete\nconfiguration check succeeds\ncommit complete\n'
            fi
        fi
        ;;
    sh)
        text=${2:-}
        if [[ $text == *'command -v tcpdump'* || $text == *'timeout 60 tcpdump'* || $text == *'kill -INT'* ]]; then
            :
        elif [[ $text == *'ip -6 rule show'* ]]; then
            printf '29000: from all lookup 200\n'
        elif [[ $text == *'ip -4 rule show'* || $text == *'ip rule show'* ]]; then
            printf '29000: from all lookup 100\n'
        elif [[ $text == *'curl -s 127.0.0.1:8080/metrics'* ]]; then
            family=inet
            [[ $text == *'family="inet6"'* ]] && family=inet6
            counter_file="${FBF_FAKE_STATE_DIR}/metric-${family}"
            n=0
            [[ -f $counter_file ]] && read -r n < "$counter_file"
            n=$((n + 1))
            printf '%s\n' "$n" > "$counter_file"
            if (( n == 1 )); then printf '0\n'; else printf '6\n'; fi
        else
            echo "unexpected remote shell command: $text" >&2
            exit 2
        fi
        ;;
    ip)
        args="$*"
        if [[ $args == *'route show table'* ]]; then
            if [[ $args == *'-6 route show table'* ]]; then
                printf 'default via 2001:559:8585:80::1 dev ge-0-0-2.80 proto static\n'
            else
                printf 'default via 172.16.80.1 dev ge-0-0-2.80 proto static\n'
            fi
        elif [[ $args == *'-6 route show default'* ]]; then
            printf 'default via 2001:559:8585:50::1 dev ge-0-0-2.50 proto static\n'
        elif [[ $args == *'route show default'* ]]; then
            printf 'default via 172.16.50.1 dev ge-0-0-2.50 proto static\n'
        elif [[ $args == *'neigh show to 2001:559:8585:80::1'* ]]; then
            printf '2001:559:8585:80::1 dev eth0 lladdr 02:00:00:00:80:01 REACHABLE\n'
        elif [[ $args == *'neigh show to 172.16.80.1'* ]]; then
            printf '172.16.80.1 dev eth0 lladdr 02:00:00:00:80:01 REACHABLE\n'
        elif [[ $args == *'nexthop show'* ]]; then
            :
        else
            echo "unexpected ip command: $args" >&2
            exit 2
        fi
        ;;
    ping)
        args=" $* "
        if [[ $args == *' -Q 0x68 '* ]]; then
            if [[ ${FBF_FAKE_SCENARIO} == healthy || ${FBF_FAKE_SCENARIO} == wrong-egress ]]; then
                printf '5 packets transmitted, 5 received, 0%% packet loss\n'
            else
                printf '5 packets transmitted, 0 received, 100%% packet loss\n'
            fi
        else
            printf '5 packets transmitted, 0 received, 100%% packet loss\n'
        fi
        ;;
    rm)
        exit 0
        ;;
    tcpdump)
        exit 0
        ;;
    cat)
        if [[ ${FBF_FAKE_SCENARIO} == healthy ]]; then
            marked_mac4=02:00:00:00:80:01
            marked_mac6=02:00:00:00:80:01
        elif [[ ${FBF_FAKE_SCENARIO} == wrong-egress ]]; then
            marked_mac4=02:00:00:00:80:02
            marked_mac6=02:00:00:00:80:02
        else
            exit 0
        fi
        for seq in 1 2 3 4 5; do
            printf '12:00:00.00000%s %s > 02:00:00:00:80:ee, ethertype IPv4 (0x0800), length 98: IP (tos 0x68, ttl 64, id %s, offset 0, flags [DF], proto ICMP (1), length 84) 10.0.61.102 > 172.16.80.201: ICMP echo request, id 1, seq %s, length 64\n' "$seq" "$marked_mac4" "$seq" "$seq"
            printf '12:00:01.00000%s 02:00:00:00:80:08 > 02:00:00:00:80:ee, ethertype IPv4 (0x0800), length 98: IP (tos 0x0, ttl 64, id %s, offset 0, flags [DF], proto ICMP (1), length 84) 10.0.61.102 > 172.16.80.201: ICMP echo request, id 2, seq %s, length 64\n' "$seq" "$seq" "$seq"
            printf '12:00:02.00000%s %s > 02:00:00:00:80:ee, ethertype IPv6 (0x86dd), length 98: IP6 (class 0x68, flowlabel 0, hlim 64, next-header ICMPv6 (58), payload length: 64) 2001:559:8585:61::102 > 2001:559:8585:80::201: ICMP6, echo request, id 1, seq %s, length 64\n' "$seq" "$marked_mac6" "$seq"
            printf '12:00:03.00000%s 02:00:00:00:80:08 > 02:00:00:00:80:ee, ethertype IPv6 (0x86dd), length 98: IP6 (class 0x0, flowlabel 0, hlim 64, next-header ICMPv6 (58), payload length: 64) 2001:559:8585:61::102 > 2001:559:8585:80::201: ICMP6, echo request, id 2, seq %s, length 64\n' "$seq" "$seq"
        done
        ;;
    *)
        echo "unexpected remote command: $command $*" >&2
        exit 2
        ;;
esac
FAKE_INCUS
chmod +x "$TMP_DIR/bin/incus"
cat > "$TMP_DIR/bin/sleep" <<'FAKE_SLEEP'
#!/usr/bin/env sh
exit 0
FAKE_SLEEP
chmod +x "$TMP_DIR/bin/sleep"

pass=0
fail=0
run_case() {
    local scenario="$1" expected="$2" state output rc=0
    state="${TMP_DIR}/${scenario}"
    output="${TMP_DIR}/${scenario}.out"
    mkdir -p "$state"
    if FBF_FAKE_SCENARIO="$scenario" FBF_FAKE_STATE_DIR="$state" \
        PATH="${TMP_DIR}/bin:${PATH}" bash "$HARNESS" >"$output" 2>&1; then
        rc=0
    else
        rc=$?
    fi

    if [[ $scenario == wrong-egress ]]; then
        if (( rc != 0 )) &&
            grep -Fq 'IPv4 target replies: ISP-B echo check received 5/5 replies' "$output" &&
            grep -Fq 'marked IPv4 requests did not arrive from ISP-B gateway MAC' "$output"; then
            pass=$((pass + 1)); printf 'ok   %-26s -> replies but wrong next-hop rejected\n' "$scenario"
        else
            fail=$((fail + 1)); printf 'FAIL %-26s -> expected replies with wrong gateway MAC to fail (exit %s)\n' "$scenario" "$rc"
            cat "$output"
        fi
    elif [[ $expected == pass ]]; then
        if (( rc == 0 )) && grep -Fq 'PASS: FBF two-upstream steering smoke complete' "$output" \
            && grep -Fq 'IPv6' "$output"; then
            pass=$((pass + 1)); printf 'ok   %-26s -> forwarded\n' "$scenario"
        else
            fail=$((fail + 1)); printf 'FAIL %-26s -> expected IPv4+IPv6 forward PASS (exit %s)\n' "$scenario" "$rc"
            cat "$output"
        fi
    elif (( rc != 0 )) && grep -Fq 'received only 0/5 replies' "$output" \
        && ! grep -Fq 'PASS: FBF two-upstream steering smoke complete' "$output"; then
        pass=$((pass + 1)); printf 'ok   %-26s -> dropped traffic rejected\n' "$scenario"
    else
        fail=$((fail + 1)); printf 'FAIL %-26s -> term hits must not pass without ISP-B echo replies (exit %s)\n' "$scenario" "$rc"
        cat "$output"
    fi
}

run_case healthy pass
run_case steer-and-drop fail
run_case wrong-egress fail
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
