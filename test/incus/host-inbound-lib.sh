#!/usr/bin/env bash
# shellcheck shell=bash
#
# Verdict helpers for the #6936 on-wire host-inbound smoke
# (test/incus/test-host-inbound.sh).
#
# WHY THIS EXISTS
#
# #6936 asks for on-wire host-inbound coverage — VLAN, and admission across an
# HA failover — because the compile-side tests (pkg/config/host_inbound_*) can
# only show what the compiler PRODUCED, never what the box ADMITTED. The
# failure mode being covered is SILENT: an admission that quietly stops working
# after a failover looks, from a prober, exactly like a service that is
# correctly denied. Both are "nothing came back".
#
# That is the same trap #7798 had to close in the FBF smoke, and the #6936
# comment asks for it to be avoided on the FIRST pass here rather than after
# someone notices. So the vocabulary below deliberately has no state called
# "DENIED". A probe cannot observe a deny. It can only observe SILENCE, and
# silence is promoted to "denied" ONLY by a positive control that proves, in
# the same run and from the same prober, that a packet CAN reach the firewall's
# host stack at that address family.
#
#   OPEN / REFUSED -> ADMITTED   the SYN reached the host stack (a listener
#                                accepted, or the stack answered RST). Either
#                                way host-inbound let it through.
#   TIMEOUT        -> SILENT     nothing came back. A host-inbound DROP *or* a
#                                blind probe. NOT a verdict on its own.
#   ERROR          -> UNREACHED  ICMP unreachable / no route / EHOSTUNREACH:
#                                the packet never reached a host-inbound
#                                decision at all, so it can neither confirm an
#                                admit nor certify a deny.
#   (no line)      -> BLIND      the prober produced no reading for this cell.
#
# The REFUSED state is what makes the negative cells meaningful. xpfd binds its
# own listeners on 127.0.0.1 only, so an ADMITTED probe to a non-listening port
# comes back as an RST from the kernel stack -- a POSITIVE, packet-carrying
# signal that host-inbound admitted it. Without that distinction the only
# observable difference between "admitted, nothing listening" and "dropped by
# host-inbound" would be a timeout, and every deny cell would be unfalsifiable.
#
# Depends on nothing but bash, so host-inbound-selftest.sh
# (`make test-host-inbound-lib`) is hermetic — no cluster, no incus, no network.

# hi_classify_probe <probe-output> <target> <port>
#
#   Reduce the prober's raw output to one word of the admission vocabulary.
#   TOTAL: always prints exactly one of ADMITTED / SILENT / UNREACHED / BLIND.
#
#   The prober (host_inbound_probe.py) emits one line per cell:
#       PROBE <target> <port> <OPEN|REFUSED|TIMEOUT|ERROR> <elapsed>
#   Missing line, unparseable line, or an unknown result word all read as
#   BLIND — never as SILENT, because "the prober said nothing about this cell"
#   must not be able to masquerade as "the firewall said nothing to this cell".
hi_classify_probe() {
	local out="$1" target="$2" port="$3" line result
	line="$(awk -v t="$target" -v p="$port" \
		'$1 == "PROBE" && $2 == t && $3 == p { print $4; exit }' <<<"$out")"
	result="${line//[[:space:]]/}"
	case "$result" in
	OPEN | REFUSED) printf 'ADMITTED\n' ;;
	TIMEOUT) printf 'SILENT\n' ;;
	ERROR) printf 'UNREACHED\n' ;;
	*) printf 'BLIND\n' ;;
	esac
}

# hi_classify_ping <ping-output>
#
#   Same vocabulary for an ICMP cell. TOTAL.
#
#   `ping` reports "N received"; anything that is not a positive receive count
#   is SILENT, and output that carries no statistics line at all is BLIND (the
#   prober did not run, or incus itself failed) rather than SILENT. An ICMP
#   error — "Destination Host Unreachable" / "Network is unreachable" — is
#   UNREACHED: the packet did not reach a host-inbound decision.
hi_classify_ping() {
	local out="$1" recv
	if [[ -z "${out//[[:space:]]/}" ]]; then
		printf 'BLIND\n'
		return 0
	fi
	if ! grep -q 'packets transmitted' <<<"$out"; then
		printf 'BLIND\n'
		return 0
	fi
	recv="$(sed -n 's/.*transmitted, \([0-9][0-9]*\) received.*/\1/p' <<<"$out" | head -1)"
	if [[ -n "$recv" && "$recv" -gt 0 ]]; then
		printf 'ADMITTED\n'
		return 0
	fi
	if grep -qE 'Unreachable|unreachable' <<<"$out"; then
		printf 'UNREACHED\n'
		return 0
	fi
	printf 'SILENT\n'
}

# hi_cell_verdict <expect ADMIT|DENY> <observation> <control-observation>
#
#   Print exactly one line: "PASS <why>" or "FAIL <why>". TOTAL BY
#   CONSTRUCTION — every input combination prints, so this cell can never be
#   the silent hole that a bare `[[ -z "$out" ]] && pass` would be.
#
#   <control-observation> is the run's POSITIVE CONTROL for this address
#   family, classified through the same vocabulary: a probe of a service the
#   zone DOES admit, at an address in the SAME zone, from the SAME prober, in
#   the SAME run. It exists solely so a DENY cell can tell "the firewall
#   dropped it" from "my prober is blind". This is the middle row of
#   host-inbound-selftest.sh, and it is the reason this file exists.
hi_cell_verdict() {
	local expect="$1" obs="$2" control="$3"
	case "$expect" in
	ADMIT)
		case "$obs" in
		ADMITTED) printf 'PASS %s\n' "admitted (the host stack answered)" ;;
		SILENT) printf 'FAIL %s\n' "expected ADMIT but nothing came back — an admitted host-inbound service is being dropped" ;;
		UNREACHED) printf 'FAIL %s\n' "expected ADMIT but the probe never reached the firewall (ICMP unreachable / no route) — this cell measured routing, not host-inbound" ;;
		*) printf 'FAIL %s\n' "expected ADMIT but the prober returned no reading for this cell (observation=${obs:-<empty>})" ;;
		esac
		;;
	DENY)
		case "$obs" in
		ADMITTED) printf 'FAIL %s\n' "expected DENY but the host stack answered — host-inbound admitted a service the zone does not list" ;;
		SILENT)
			if [[ "$control" == "ADMITTED" ]]; then
				printf 'PASS %s\n' "silent, and the run's positive control was admitted — so the silence is a host-inbound drop, not a blind prober"
			else
				printf 'FAIL %s\n' "silent, but the run's positive control was ${control:-<empty>} rather than ADMITTED — the prober is not proven able to reach the firewall at all, so this silence CANNOT be scored as a deny (it is indistinguishable from a blind probe)"
			fi
			;;
		UNREACHED) printf 'FAIL %s\n' "expected DENY but the probe never reached the firewall (ICMP unreachable / no route) — an unreachable is not a host-inbound deny, and scoring it as one would certify the deny on a packet that never got a verdict" ;;
		*) printf 'FAIL %s\n' "expected DENY but the prober returned no reading for this cell (observation=${obs:-<empty>}) — an absence cannot be certified by an instrument that produced nothing" ;;
		esac
		;;
	*)
		printf 'FAIL %s\n' "unknown expectation ${expect:-<empty>} — the cell table is malformed"
		;;
	esac
}

# hi_config_readable <display-set-output>
#
#   Exit 0 iff the `show configuration security zones | display set` output is
#   usable as evidence. An empty or zone-less read must never be allowed to
#   answer an ABSENT question: "the wan zone does not admit ssh" and "I could
#   not read the config" are the same string to grep, and only one of them is
#   a reason to run the matrix.
hi_config_readable() {
	local lines="$1"
	[[ -n "${lines//[[:space:]]/}" ]] || return 1
	grep -q '^set security zones security-zone ' <<<"$lines"
}

# hi_zone_scope_admits <display-set-lines> <scope-prefix> <service>
#
#   Echo yes (admitted), no (explicitly denied or the replacement scope
#   omits the service), all (admitted by all/any-service), or absent (scope
#   has no host-inbound override). <scope-prefix> ends immediately before
#   `host-inbound-traffic`.
hi_zone_scope_admits() {
	local lines="$1" prefix="$2" svc="$3" base
	base="${prefix} host-inbound-traffic system-services"
	# Service-specific exclusions subtract even from `all`.
	if grep -qxF "${base} ${svc} except" <<<"$lines"; then
		printf 'no\n'; return 0
	fi
	if grep -qxF "${base} ${svc}" <<<"$lines"; then
		printf 'yes\n'; return 0
	fi
	# `all except` removes the named-service blanket. `any-service` is a
	# distinct full admit (#12054); its except form is rejected by config.
	if grep -qxF "${base} all except" <<<"$lines" \
		&& ! grep -qxF "${base} any-service" <<<"$lines"; then
		printf 'no\n'; return 0
	fi
	if grep -qxF "${base} all" <<<"$lines" \
		|| grep -qxF "${base} any-service" <<<"$lines"; then
		printf 'all\n'; return 0
	fi
	# Any host-inbound declaration makes this scope a replacement scope
	# (#6515), even if it only declares protocols or excludes all services.
	if grep -qF "${base} " <<<"$lines" \
		|| grep -qF "${prefix} host-inbound-traffic protocols " <<<"$lines"; then
		printf 'no\n'; return 0
	fi
	printf 'absent\n'
}

# hi_zone_service_verdict <display-set-lines> <zone> <service> <want PRESENT|ABSENT> [<iface>]
#
#   Print exactly one line: "PASS <why>" or "FAIL <why>". TOTAL. With <iface>,
#   an interface-level host-inbound override replaces the zone posture.
hi_zone_service_verdict() {
	local lines="$1" zone="$2" svc="$3" want="$4" iface="${5:-}" found scope ifound
	if ! hi_config_readable "$lines"; then
		printf 'FAIL %s\n' "zone posture check (${zone}/${svc}): 'show configuration security zones | display set' returned nothing usable — the precondition is unread, so neither PRESENT nor ABSENT can be concluded"
		return 0
	fi
	scope="zone ${zone}"
	found="$(hi_zone_scope_admits "$lines" "set security zones security-zone ${zone}" "$svc")"
	if [[ -n "$iface" ]]; then
		ifound="$(hi_zone_scope_admits "$lines" "set security zones security-zone ${zone} interfaces ${iface}" "$svc")"
		if [[ "$ifound" != absent ]]; then
			found="$ifound"
			scope="interface ${iface} in zone ${zone}"
		fi
	fi
	case "$want:$found" in
	PRESENT:yes) printf 'PASS %s admits %s\n' "$scope" "$svc" ;;
	PRESENT:all) printf 'PASS %s admits %s (via system-services all/any-service)\n' "$scope" "$svc" ;;
	PRESENT:no) printf 'FAIL %s no longer admits %s; the matrix ADMIT cells are stale — update the expectation table, do not weaken the cell\n' "$scope" "$svc" ;;
	ABSENT:no) printf 'PASS %s does not admit %s\n' "$scope" "$svc" ;;
	ABSENT:yes) printf 'FAIL %s now admits %s; the matrix DENY cells are stale — update the expectation table, do not weaken the cell\n' "$scope" "$svc" ;;
	ABSENT:all) printf 'FAIL %s carries system-services all/any-service, which subsumes %s; the matrix DENY cells are stale\n' "$scope" "$svc" ;;
	*) printf 'FAIL %s\n' "zone posture check (${zone}/${svc}): unknown expectation ${want:-<empty>} or unreadable scope verdict ${found:-<empty>}" ;;
	esac
}

# hi_iface_address <display-set-lines> <iface> <unit> <inet|inet6>
#
#   Echo the bare address (no prefix length) configured on <iface> unit <unit>
#   for <family>, or nothing when there is none. Used so the smoke derives its
#   probe targets from the box's OWN config instead of hard-coding lab
#   addresses that rot when the cluster is re-addressed.
#
#   Prints nothing rather than a partial value on an unreadable config; the
#   caller treats an empty result as a precondition failure.
hi_iface_address() {
	local lines="$1" iface="$2" unit="$3" family="$4" addr
	hi_config_readable_iface "$lines" || return 0
	addr="$(awk -v i="$iface" -v u="$unit" -v f="$family" '
		$1 == "set" && $2 == "interfaces" && $3 == i && $4 == "unit" && $5 == u \
			&& $6 == "family" && $7 == f && $8 == "address" { print $9; exit }' <<<"$lines")"
	printf '%s\n' "${addr%%/*}"
}

# hi_config_readable_iface <display-set-lines>
#
#   The interface-stanza twin of hi_config_readable: an empty or
#   interface-less read must not answer "this interface has no address".
hi_config_readable_iface() {
	local lines="$1"
	[[ -n "${lines//[[:space:]]/}" ]] || return 1
	grep -q '^set interfaces ' <<<"$lines"
}

# hi_matrix_stable_verdict <label-a> <observations-a> <label-b> <observations-b>
#
#   Print exactly one line: "PASS <why>" or "FAIL <why>". TOTAL.
#
#   The HA-failover leg's actual assertion. It is NOT "the matrix passed after
#   the failover" — that alone is satisfied by a run where every cell went
#   silent, since a matrix of all-DENY expectations would then read clean. It
#   is "the matrix is bit-identical to the pre-failover one", so an admission
#   that silently stopped working across the failover shows up as a DIFF even
#   where the cell's own expectation would have tolerated it.
#
#   Each observations argument is the newline-separated list of
#   "<cell-name> <observation>" lines from one matrix run.
hi_matrix_stable_verdict() {
	local la="$1" a="$2" lb="$3" b="$4" diff
	if [[ -z "${a//[[:space:]]/}" || -z "${b//[[:space:]]/}" ]]; then
		printf 'FAIL %s\n' "matrix stability (${la} vs ${lb}): one of the two runs produced no observations at all, so they cannot be compared — an empty run must never read as 'unchanged'"
		return 0
	fi
	if [[ "$(sort <<<"$a")" == "$(sort <<<"$b")" ]]; then
		printf 'PASS %s\n' "host-inbound matrix identical ${la} and ${lb} ($(grep -c . <<<"$a") cells)"
		return 0
	fi
	diff="$(comm -3 <(sort <<<"$a") <(sort <<<"$b") | tr '\t' ' ' | tr '\n' ';')"
	printf 'FAIL %s\n' "host-inbound matrix CHANGED between ${la} and ${lb} — differing cells: ${diff}"
}

# hi_wildcard_socket_pids <port>
#
#   Read `ss -tlnp` output on stdin; print the sorted-unique PIDs of sockets
#   bound to a WILDCARD address with an EXACT port match, one per line.
#   Empty output means no externally-reachable listener on this port.
#
#   Extracted from test-host-inbound.sh's fail-closed listener gate (#9637):
#   a bare `ss :port` check can be satisfied by a loopback-only listener
#   (unreachable to external probers) or by `:220` when asking for `:22`,
#   while the prober reaches a different socket. So only rows whose LOCAL
#   address is wildcard (0.0.0.0/[::], never 127.0.0.1/[::1]) with an exact
#   port match count, and every emitted PID must be an owned marker PID
#   (the caller checks ownership — this helper deliberately does NOT
#   filter, so a foreign PID is emitted and rejected, never silently
#   dropped).
hi_wildcard_socket_pids() {
	local port="$1"
	awk -v p="$port" '
		$4 ~ /^(0\.0\.0\.0|\[::\]):[0-9]+$/ {
			addrport = $4; sub(/.*:/, "", addrport)
			if (addrport == p) {
				line = $0
				while (match(line, /pid=[0-9]+/)) {
					print substr(line, RSTART + 4, RLENGTH - 4)
					line = substr(line, RSTART + RLENGTH)
				}
			}
		}' | sort -u
}

# hi_socket_ownership_verdict <port> <owned-pids>
#
#   Read `ss -tlnp` output on stdin; print exactly one line: "PASS <why>"
#   or "FAIL <why>". TOTAL.
#
#   The per-port listener-presence gate the host-inbound smoke runs before
#   ANY cell is scored (#9637 listeners, made port-specific by #12912).
#   <owned-pids> is THIS port's marker process list — `pgrep -f` on the
#   port-specific marker, never a marker shared with the other port: with
#   one shared marker a live TCP/22 listener vouched for a dead TCP/23 one.
#
#   FAIL, never a silent pass, when:
#     * hi_wildcard_socket_pids finds no pid for the exact port — nothing
#       externally reachable is listening there. An empty pid list must not
#       walk through an empty ownership loop (#12912: that is exactly how a
#       missing TCP/23 listener let every telnet DENY cell pass vacuously
#       while the live TCP/22 listener kept the shared marker non-empty);
#     * any socket pid is absent from <owned-pids> — the port is held by a
#       foreign or stale process, and cells would be scored against
#       someone else's socket.
hi_socket_ownership_verdict() {
	local port="$1" owned="$2"
	local ssout sockpids spid
	ssout="$(cat)"
	sockpids="$(hi_wildcard_socket_pids "$port" <<<"$ssout")"
	if [[ -z "$sockpids" ]]; then
		echo "FAIL port $port has no wildcard-bound listener (this port's marker pids: $(tr '\n' ' ' <<<"$owned")) — nothing would answer the prober, so cells would pass vacuously"
		return
	fi
	for spid in $sockpids; do
		grep -qxF "$spid" <<<"$owned" || {
			echo "FAIL port $port held by pid $spid, not this port's marker process (owned: $(tr '\n' ' ' <<<"$owned")) — refusing to score cells against a foreign socket"
			return
		}
	done
	echo "PASS port $port wildcard listener held by this port's marker pid(s): $(tr '\n' ' ' <<<"$sockpids")"
}
