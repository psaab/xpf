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

# hi_zone_service_verdict <display-set-lines> <zone> <service> <want PRESENT|ABSENT>
#
#   Print exactly one line: "PASS <why>" or "FAIL <why>". TOTAL.
#
#   The smoke's expectation table is only correct for a particular zone
#   posture. Rather than hard-coding that posture and silently asserting the
#   wrong matrix if the shared cluster's config changes, the smoke checks the
#   posture it depends on FIRST and refuses to run otherwise.
#
#   Exact whole-line match, so `system-services ssh` is not satisfied by a
#   hypothetical `system-services ssh-something`, and an ABSENT question is
#   never answered from an unreadable config.
hi_zone_service_verdict() {
	local lines="$1" zone="$2" svc="$3" want="$4" needle found=no
	if ! hi_config_readable "$lines"; then
		printf 'FAIL %s\n' "zone posture check (${zone}/${svc}): 'show configuration security zones | display set' returned nothing usable — the precondition is unread, so neither PRESENT nor ABSENT can be concluded"
		return 0
	fi
	needle="set security zones security-zone ${zone} host-inbound-traffic system-services ${svc}"
	if grep -qxF "$needle" <<<"$lines"; then
		found=yes
	fi
	# `system-services all` subsumes every named service, so an ABSENT
	# expectation must fail on it too — otherwise a zone opened wide would
	# still satisfy "ssh is not listed".
	if grep -qxF "set security zones security-zone ${zone} host-inbound-traffic system-services all" <<<"$lines"; then
		found=all
	fi
	case "$want:$found" in
	PRESENT:yes) printf 'PASS %s\n' "zone ${zone} admits ${svc}" ;;
	PRESENT:all) printf 'PASS %s\n' "zone ${zone} admits ${svc} (via system-services all)" ;;
	PRESENT:no) printf 'FAIL %s\n' "zone ${zone} no longer admits ${svc}; the matrix's ADMIT cells for this zone are stale — update the expectation table, do not weaken the cell" ;;
	ABSENT:no) printf 'PASS %s\n' "zone ${zone} does not admit ${svc}" ;;
	ABSENT:yes) printf 'FAIL %s\n' "zone ${zone} now admits ${svc}; the matrix's DENY cells for this zone are stale — update the expectation table, do not weaken the cell" ;;
	ABSENT:all) printf 'FAIL %s\n' "zone ${zone} carries 'system-services all', which subsumes ${svc}; the matrix's DENY cells for this zone are stale" ;;
	*) printf 'FAIL %s\n' "zone posture check (${zone}/${svc}): unknown expectation ${want:-<empty>}" ;;
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
