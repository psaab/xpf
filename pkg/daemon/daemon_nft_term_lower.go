package daemon

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// Junos filter TERM -> nft lowering, split out of daemon_nft.go (#7714).
//
// The seam is the UNRESOLVABLE-INPUT DISPOSITION CONTRACT stated below, not a
// line count. Four dispositions were interleaved across a 423-line function and
// inferable only by reading all of it, which is how #6806 shipped one of them
// wrong. Naming each lowering step after the disposition it implements is the
// change; the file boundary just follows it.

// UNRESOLVABLE-INPUT DISPOSITIONS in the lo0 text oracle (#7714).
//
// `nftRulesFromTerm` lowers one Junos filter term to nft. When an input cannot
// be rendered faithfully it has FOUR distinct dispositions, chosen per match
// kind for stated reasons. They were only inferable by reading the whole
// function, which is how #6806 shipped one of them wrong — its own comment
// records that the code "previously said the token was dropped with a warning"
// when it does not, and that dropping a narrowing token is never the safe
// direction. Stating them as a SET is the point of the split:
//
//	A. EMIT NO RULE — an address direction that is constrained but resolves to
//	   no prefix of this family with a positive scope. The term cannot match
//	   anything, so a rule would be dead. `nftTermAddrPredicates` returns
//	   emitNoRule.
//	B. EMIT THE TOKEN VERBATIM — an unresolvable protocol / ICMP type / ICMP
//	   code. Invalid nft is the POINT: `nft -f -` loads atomically, so the whole
//	   ruleset is REJECTED and the prior generation stays installed (#6806,
//	   matching #6405 ports/DSCP and #6512 addresses).
//	   `nftTermProtocolPredicates`, `nftTermICMPPredicates`.
//	C. FAIL THE TERM CLOSED WITH A SCOPED DROP — an unrepresentable tcp-flags
//	   expression (#5512). Rendering the term without its flag narrowing would
//	   widen it, so the term becomes a drop scoped to TCP. Still inline, in the
//	   disposition section below.
//	D. MAKE THE TERM MATCH NOTHING — an unrepresentable flexible-match-range
//	   (#6804), mirroring userspace, which poisons it to
//	   `FlexMatchStart::Unsupported`. Deliberately NOT C: a flex-match
//	   constraint is not necessarily protocol-scoped. Still inline below.
//
// C and D are NOT interchangeable with each other or with A, and none of them
// is "drop the predicate and carry on" — that is the fail-open #6405/#6512
// removed from this very function.

// nftTermAddrPredicates lowers source/destination address + prefix-list matches
// (#3433). DISPOSITION A: when a constrained direction resolves to an empty
// positive set for this family the term matches NOTHING, and the caller must
// emit no rule at all rather than a rule with the constraint dropped.
func nftTermAddrPredicates(term *config.FirewallFilterTerm, family string, prefixLists map[string]*config.PrefixList) (parts []string, emitNoRule bool) {
	// Source / destination address + prefix-list lowering (#3433). Route both
	// directions through the SHARED userspace resolver
	// (dpuserspace.ResolveFilterPrefixListAddrs) so the kernel lo0 mirror uses the
	// SAME empty-set / except / positive-wins / `any`-no-constraint semantics as
	// the userspace matcher (pkg/dataplane/userspace/filters.go +
	// userspace-dp/src/filter/engine/matching.rs nets_match_v4/v6) — the raw
	// string concatenation this replaced diverged on every one of those shapes
	// (over-matched in the kernel mirror, or emitted invalid nft that failed the
	// atomic load). nftAddrPredicate then family-filters the resolved set for THIS
	// chain's family and renders the matching nft predicate. When a direction is
	// constrained but resolves to no prefix of this family with a positive scope,
	// the term matches NOTHING (Junos empty-positive set) — skip the whole rule so
	// the kernel mirror neither over-matches (fail-open) nor emits unloadable nft.
	srcAddrs, srcExcept, srcConstrained := dpuserspace.ResolveFilterPrefixListAddrs(
		term.SourceAddresses, term.SourcePrefixLists, prefixLists, "", term.Name, "source", term.Action)
	srcPred, srcMatchesNothing := nftAddrPredicate("saddr", family, srcAddrs, srcExcept, srcConstrained)
	if srcMatchesNothing {
		return nil, true
	}
	if srcPred != "" {
		parts = append(parts, srcPred)
	}

	dstAddrs, dstExcept, dstConstrained := dpuserspace.ResolveFilterPrefixListAddrs(
		term.DestAddresses, term.DestPrefixLists, prefixLists, "", term.Name, "destination", term.Action)
	dstPred, dstMatchesNothing := nftAddrPredicate("daddr", family, dstAddrs, dstExcept, dstConstrained)
	if dstMatchesNothing {
		return nil, true
	}
	if dstPred != "" {
		parts = append(parts, dstPred)
	}
	return parts, false
}

// nftTermProtocolPredicates lowers `from protocol` (#2545 multi-value, #3436
// numeric SSOT). DISPOSITION B: an unresolvable token is kept VERBATIM so the
// atomic nft load is REJECTED and the prior generation is retained (#6806).
func nftTermProtocolPredicates(term *config.FirewallFilterTerm) (parts []string) {
	// Protocol matching (#2545: multi-value — emit an nft set on >1).
	//
	// #3436: resolve every `from protocol` token through the shared
	// appid.ProtocolNumber SSOT and emit NUMERIC protocol numbers. The commit
	// gate (filterProtocolResolvable) and the userspace matcher (ip_proto.rs)
	// accept Junos predefined-protocol aliases — junos-gre, junos-tcp-any,
	// junos-icmp-all, ipip/junos-ip-in-ip, ... — that nft does NOT understand.
	// Emitting them raw (`meta l4proto junos-gre`) is an nft parse error that
	// rejects the WHOLE atomic lo0 table (legitimate commit broken) or, on the
	// lenient/peer-sync path, mirrors a DIFFERENT protocol than userspace. The
	// numeric form is unconditionally nft-safe and resolves to the SAME protocol
	// number the Rust matcher uses. A token outside the SSOT cannot reach a
	// committed config (the gate rejects it); a leniently-loaded one is kept
	// VERBATIM so the nft load fails CLOSED (#6806).
	//
	// It previously said the token was "dropped with a warning ... mirroring the
	// tcp-flags lowering below". Both halves of that were wrong. The tcp-flags
	// lowering does NOT drop its predicate — #5512 made it fail the TERM closed
	// with a scoped drop — and dropping a protocol predicate is the fail-open
	// that #6405/#6512 removed from the port, DSCP and address paths in this very
	// function. A dropped narrowing token is never the safe direction.
	if len(term.Protocols) > 0 {
		protos := make([]string, 0, len(term.Protocols))
		for _, p := range term.Protocols {
			if n, ok := appid.ProtocolNumber(p); ok {
				protos = append(protos, strconv.Itoa(int(n)))
			} else {
				// #6806: keep the raw token VERBATIM so `nft -f -` REJECTS the
				// whole ruleset and the prior generation is retained — the same
				// fail-closed posture this oracle already has for an
				// unresolvable port / DSCP token (#6405) and a malformed address
				// (#6512), and what keeps it in agreement with lo0Protocols in
				// pkg/nftables/netlink_lo0.go, the production builder, which
				// errors on the same token.
				//
				// It used to be DROPPED with a warning. That was fail-OPEN in
				// both directions: an all-unresolvable list emitted NO l4proto
				// predicate (the term matched every protocol in its scope), and
				// a partially-unresolvable one built the rule from a NARROWED
				// subset, so a discard/reject term stopped denying the protocol
				// it could not resolve.
				slog.Warn("lo0 kernel nftables mirror: unresolvable protocol kept "+
					"VERBATIM so the nft load fails closed rather than widening the term",
					"term", term.Name, "protocol", p)
				protos = append(protos, p)
			}
		}
		if len(protos) == 1 {
			parts = append(parts, "meta l4proto "+protos[0])
		} else if len(protos) > 1 {
			parts = append(parts, "meta l4proto { "+strings.Join(protos, ", ")+" }")
		}
	}
	return parts
}

// nftTermICMPPredicates lowers ICMP/ICMPv6 type and code (#2545 multi-value,
// #3483 independent predicates). DISPOSITION B: a token the compiler could not
// resolve to a byte is rendered alongside the resolved ones by
// nftIntSetWithRaw, so the load fails CLOSED instead of silently widening the
// term (#6806).
func nftTermICMPPredicates(term *config.FirewallFilterTerm, family string) (parts []string) {
	// ICMP type/code matching (#2545: multi-value).
	//
	// #3483: emit the `icmp code` predicate WHENEVER a code is configured,
	// independent of whether a type is also set. The userspace projections
	// enforce the code criterion on its own — pkg/dataplane/userspace/filters.go
	// emits ICMPCodes gated only on len(term.ICMPCodes) > 0, and the Rust matcher
	// (userspace-dp/src/filter/engine/matching.rs) tests icmp_code_match_enabled
	// in a block separate from icmp_type_match_enabled. The pre-fix nft mirror
	// nested the code predicate under `if len(term.ICMPTypes) > 0`, so a
	// code-only term (`from protocol icmp icmp-code 4 then discard`, no
	// icmp-type) dropped the code match entirely on the kernel lo0 path. That
	// made the kernel mirror match BROADER than userspace: a `discard` term
	// dropped ALL ICMP (fail-closed over-broad), an `accept` term admitted ALL
	// ICMP (fail-open). Render type and code as independent predicates so a
	// code-only term matches the same packets in nft as in userspace.
	//
	// #6806: a token the compiler could NOT resolve to a byte lives on
	// term.UnknownICMPTypes / UnknownICMPCodes, not in the int slices above, so
	// rendering only the resolved bytes dropped it. An all-unresolvable list left
	// both int slices empty and emitted no ICMP predicate at all, so the term
	// matched EVERY ICMP type in its scope — an `accept` term admitting all ICMP
	// (fail-open), a `discard` term dropping all ICMP (over-broad). Render the
	// raw tokens alongside the resolved bytes so `nft -f -` REJECTS the whole
	// ruleset and the prior generation is retained, matching the port / DSCP /
	// address posture and the netlink builder's ICMPTypeUnrepresentable /
	// ICMPCodeUnrepresentable fail-closed.
	if len(term.ICMPTypes) > 0 || len(term.ICMPCodes) > 0 ||
		len(term.UnknownICMPTypes) > 0 || len(term.UnknownICMPCodes) > 0 {
		icmpFamily := "icmp"
		if family == "ip6" {
			icmpFamily = "icmpv6"
		}
		if len(term.ICMPTypes) > 0 || len(term.UnknownICMPTypes) > 0 {
			parts = append(parts, icmpFamily+" type "+
				nftIntSetWithRaw(term.ICMPTypes, term.UnknownICMPTypes))
		}
		if len(term.ICMPCodes) > 0 || len(term.UnknownICMPCodes) > 0 {
			parts = append(parts, icmpFamily+" code "+
				nftIntSetWithRaw(term.ICMPCodes, term.UnknownICMPCodes))
		}
	}
	return parts
}

func nftRulesFromTerm(term *config.FirewallFilterTerm, family string, prefixLists map[string]*config.PrefixList) []string {
	var parts []string

	addrParts, emitNoRule := nftTermAddrPredicates(term, family, prefixLists)
	if emitNoRule {
		return nil
	}
	parts = append(parts, addrParts...)

	protoParts := nftTermProtocolPredicates(term)
	parts = append(parts, protoParts...)

	// #9953: a port comparison with no protocol predicate reads two bytes out of
	// whatever header follows the IP header. On the lo0 input chain that includes
	// SCTP, GRE and ICMP reaching a firewall-local address by the ordinary
	// host-bound path, so `destination-port 22` is evaluated against packets that
	// have no ports at all — fail-OPEN for an accept term, an unasked-for drop for
	// a discard term.
	//
	// The condition is asked of the SAME predicate the netlink builder uses
	// (pkg/nftables), so the two render paths agree by construction rather than by
	// the parity test noticing afterwards. Note it keys on protoParts being EMPTY,
	// not on len(term.Protocols): an unresolvable protocol token is kept verbatim
	// by the lowering above precisely so `nft -f -` rejects the ruleset, and such a
	// term HAS a protocol predicate — supplying a fallback there would replace a
	// deliberate fail-closed with a silently widened rule.
	if xnft.Lo0NeedsPortProtocolFallback(
		len(protoParts) > 0,
		len(term.ICMPTypes) > 0 || len(term.ICMPCodes) > 0,
		xnft.Lo0TermComparesPort(term.SourcePorts, term.DestinationPorts,
			term.SourcePortsExcept, term.DestPortsExcept),
	) {
		if expr := xnft.Lo0PortFallbackL4ProtoExpr(); expr != "" {
			parts = append(parts, expr)
		}
	}

	// Source port matching
	if len(term.SourcePorts) == 1 {
		parts = append(parts, "th sport "+term.SourcePorts[0])
	} else if len(term.SourcePorts) > 1 {
		parts = append(parts, "th sport { "+strings.Join(term.SourcePorts, ", ")+" }")
	}

	// Destination port matching
	if len(term.DestinationPorts) == 1 {
		parts = append(parts, "th dport "+term.DestinationPorts[0])
	} else if len(term.DestinationPorts) > 1 {
		parts = append(parts, "th dport { "+strings.Join(term.DestinationPorts, ", ")+" }")
	}

	// Negated (except) port matching (#3231). `source-port-except` /
	// `destination-port-except` (parsed since #2622/#3205) were dropped here,
	// so a `discard` term blocked the ports it should have exempted and an
	// accept-all-except-SSH term silently permitted SSH — a control-plane
	// bypass on the lo0 input filter. Emit the nft negated form mirroring the
	// positive port emission above (`th sport != ...` / `th dport != ...`).
	if len(term.SourcePortsExcept) == 1 {
		parts = append(parts, "th sport != "+term.SourcePortsExcept[0])
	} else if len(term.SourcePortsExcept) > 1 {
		parts = append(parts, "th sport != { "+strings.Join(term.SourcePortsExcept, ", ")+" }")
	}
	if len(term.DestPortsExcept) == 1 {
		parts = append(parts, "th dport != "+term.DestPortsExcept[0])
	} else if len(term.DestPortsExcept) > 1 {
		parts = append(parts, "th dport != { "+strings.Join(term.DestPortsExcept, ", ")+" }")
	}

	// DSCP / traffic-class matching (#2545: multi-value).
	if len(term.DSCPs) > 0 {
		dscpKey := "ip dscp "
		if family == "ip6" {
			dscpKey = "ip6 dscp "
		}
		dscps := make([]string, 0, len(term.DSCPs))
		for _, d := range term.DSCPs {
			dscps = append(dscps, nftDSCPValue(d))
		}
		if len(dscps) == 1 {
			parts = append(parts, dscpKey+dscps[0])
		} else {
			parts = append(parts, dscpKey+"{ "+strings.Join(dscps, ", ")+" }")
		}
	}

	parts = append(parts, nftTermICMPPredicates(term, family)...)

	// TCP flags matching (#3231). The Junos `tcp-flags` value is an
	// AND-conjunction with optional negation (`syn & !ack` = SYN required,
	// ACK forbidden). The pre-fix code joined the RAW tokens with commas
	// (`tcp flags syn,&,!ack`), which is invalid nft — and because nft loads
	// the lo0 ruleset atomically, that single syntax error rejected the WHOLE
	// ruleset and left the host control-plane filter fail-OPEN. Even a plain
	// list (`tcp flags syn,ack`) is wrong: nft reads a comma list as a
	// disjunctive set, not the Junos conjunction, and forbidden flags are not
	// representable that way at all. Reuse the commit-validated parser to get
	// the required/forbidden masks and emit the canonical
	// `tcp flags & (mentioned-mask) == required` form.
	//
	// #5512: an UNREPRESENTABLE expression (a `|` disjunction, a De-Morgan
	// negated group, an unknown flag, a dangling `!`, a `&` with no operand)
	// cannot reach here from a normal commit — compileFirewall plus the #5455
	// strict gate reject it. It CAN reach here from the LENIENT load path (peer
	// session-sync, a #1960 fail-closed load-downgrade, a mixed-version
	// snapshot), which admits the term with only a warning. The pre-#5512 code
	// then DROPPED the tcp-flags predicate with a warning and emitted the term's
	// configured verdict — WIDENING it: an `accept` term meant to admit only a
	// specific flag combination (`syn & !ack`) now admitted EVERY TCP segment it
	// scoped. On the PRIMARY host-inbound path (the XDP shim shunts host traffic
	// to the kernel before userspace-dp, so this nft chain is the enforcement
	// point — see the Disposition comment below) that is a control-plane
	// fail-OPEN.
	//
	// The userspace lo0 evaluator fails the SAME input CLOSED: the snapshot
	// builder sets TCPFlagsUnparseable (pkg/dataplane/userspace/filters.go) and
	// the Rust filter compiler raises SnapshotIntegrityError::
	// UnrepresentableFilterTCPFlags (userspace-dp/src/filter/compiler.rs),
	// refusing the term rather than admitting it permissively. Mirror that
	// direction here — but per-TERM: we must NOT reject the whole ruleset, since
	// nft loads the lo0 table atomically and a rejected table leaves NO host
	// filter = fail-OPEN (the exact trap the comma-join syntax error hit before
	// this file was hardened). Record the unrepresentable expression and fail
	// THIS term closed below (drop its scoped traffic) instead of appending a
	// flag predicate.
	// #6804: an unrepresentable flexible-match-range makes the term match
	// NOTHING, mirroring userspace (which poisons it to
	// FlexMatchStart::Unsupported so flex_matches() returns false and later
	// terms still run). Returning "" makes buildLo0FilterPayload skip the rule,
	// which is the kernel equivalent.
	//
	// Deliberately NOT the #5512 tcp-flags drop: a tcp-flags constraint only
	// ever matches TCP, so that drop can be scoped with `meta l4proto 6`. A
	// flexible-match-range has no such natural narrowing, so a term whose ONLY
	// predicate was the flex-match would render a bare `drop` and deny ALL
	// host-inbound traffic — turning a fail-open into a lockout.
	if lo0FlexMatchUnrepresentable(term) {
		slog.Warn("lo0 kernel nftables mirror: unrepresentable flexible-match-range; "+
			"the term matches NOTHING (mirroring the userspace fail-closed) so its "+
			"narrowing is never silently dropped", "term", term.Name)
		return nil
	}

	tcpFlagsFailClosed := false
	if len(term.TCPFlags) > 0 {
		if required, forbidden, ok, err := config.ParseTCPFlagsExpression(term.TCPFlags); err != nil {
			slog.Warn("lo0 kernel nftables mirror: unrepresentable tcp-flags expression, failing term CLOSED (drop) to match userspace (snapshot/version drift)",
				"term", term.Name, "tcp_flags", term.TCPFlags, "error", err)
			tcpFlagsFailClosed = true
		} else if ok {
			parts = append(parts, nftTCPFlagsMatch(required, forbidden))
		}
	}

	// IP fragment matching (#3231). `ip frag-off` is an IPv4-only header field;
	// emitting it in the inet6 chain is an nft syntax error that (atomic load)
	// rejected the whole ruleset and failed the lo0 filter open. Family-condition
	// the match: the IPv4 fragment-offset test for ip, and the IPv6 fragment
	// extension-header existence test for ip6.
	if term.IsFragment {
		if family == "ip6" {
			parts = append(parts, "exthdr frag exists")
		} else {
			parts = append(parts, "ip frag-off & 0x1fff != 0")
		}
	}

	// #6804: flexible-match-range. Before this the oracle had no case for it at
	// all, so the predicate was silently DROPPED and the term rendered WIDER
	// than configured — an accept-term admitted every packet it scoped instead
	// of only those whose header bytes matched. This chain is the PRIMARY
	// enforcement for host traffic (the XDP shim shunts host-bound packets to
	// the kernel before userspace-dp), so that is a control-plane fail-OPEN.
	//
	// nft's raw payload syntax takes BIT offset and BIT length from the base:
	// `@nh,<off>,<len>`. match-start layer-3 — the only start point the compiler
	// emits — is the network header base.
	// The `!lo0FlexMatchUnrepresentable` conjunct is a BELT and is currently
	// UNREACHABLE: the early return above already left the function for every
	// unrepresentable term, so by here the predicate is always false. It is kept
	// because it is the guard that would matter if the early return were ever
	// moved or narrowed — but a mutation that deletes it CANNOT red, and #7722
	// was filed on exactly that green. Recorded here so the next mutation sweep
	// reads it as dominated rather than as an unguarded fail-open. The
	// disposition itself is bound by
	// TestNftRuleFromTermFlexMatchUnrepresentableMatchesNothing7722.
	if fm := term.FlexMatch; fm != nil && !lo0FlexMatchUnrepresentable(term) {
		parts = append(parts, nftFlexMatchExpr(*fm))
	}

	// Disposition. Mirror the userspace lo0 evaluator
	// (pkg/dataplane/userspace/filters.go:89) so the kernel lo0 chain enforces the
	// SAME term semantics. The XDP shim shunts ordinary host-bound traffic to the
	// Linux kernel before it reaches userspace-dp, so this chain is the PRIMARY
	// enforcement for host traffic — a wrong terminating verdict here is a real
	// control-plane mis-enforcement, not a cosmetic shadow.
	//
	// #3427: a term with NO terminating action is a FALL-THROUGH in Junos — apply
	// the term's modifiers and continue to the NEXT term. This covers both the
	// explicit `then next term` (term.NextTerm) and a modifier-only term
	// (Action=="" carrying only count/log/forwarding-class/policer/dscp). The
	// pre-fix code mapped Action=="" to a terminating nft `accept`, which SHADOWED
	// every later discard/reject term in the kernel mirror — a fail-OPEN that
	// diverged from userspace (e.g. `from protocol tcp then next term` followed by
	// `from destination-port 22 then discard` accepted SSH at term 1, leaving the
	// drop unreachable). Emit NOTHING for a fall-through term: the kernel chain
	// does not mirror counters/log, so the term contributes no enforcement and the
	// subsequent terms must run. Returning "" makes buildLo0FilterPayload skip the
	// rule.
	//
	// A routing-instance (PBR) term is explicitly NOT a fall-through: userspace
	// sets continue_term=false when routing_instance is non-empty
	// (pkg/dataplane/userspace compiler.rs) and the evaluator TERMINATES the
	// matched term, returning its action — the empty-action placeholder Accept
	// (compiler.rs) — so the packet is ACCEPTED. The kernel lo0 input chain
	// cannot perform route-selection, but the filter VERDICT is accept, so it
	// must emit a TERMINATING accept (not skip): skipping would let a later
	// deny term match and OVER-DROP legitimate host traffic on the
	// kernel-primary lo0 chain. Userspace remains authoritative for the actual
	// route-selection. Falls through to the verdict emission below (empty action
	// -> default accept).

	// #3445: build the NON-TERMINATING modifier statements the kernel lo0 mirror
	// can honor natively. nft executes a rule's statements left-to-right and the
	// verdict terminates, so these prepend the verdict: a term renders as
	// `<matches> log prefix "..." counter name "<n>" <verdict>`.
	//   - then log / then syslog (both set term.Log) -> nft `log` (to journald),
	//     with a stable prefix carrying the term name for operator correlation.
	//   - then count <name> -> a NAMED nft counter so the kernel per-term match
	//     count is observable (`nft list table inet xpf_lo0`). The object is
	//     declared in the table body by buildLo0FilterPayload (nft requires the
	//     declaration before the chain references it); the reference is quoted.
	// policer / dscp-rewrite / forwarding-class / loss-priority are deliberately
	// NOT emitted (they cannot be faithfully expressed on a host-inbound chain);
	// they are surfaced as commit-time warnings instead (see the doc comment).
	var mods []string
	if term.Log {
		mods = append(mods, `log prefix "`+nftLo0LogPrefix(term.Name)+`"`)
	}
	if term.Count != "" {
		mods = append(mods, `counter name "`+xnft.Lo0CounterName(term.Count)+`"`)
	}
	match := strings.Join(parts, " ")
	modStr := strings.Join(mods, " ")

	// #5512: fail-closed override for an unrepresentable tcp-flags expression.
	// We could not render the flag narrowing, so emitting the term's normal
	// verdict would WIDEN it (an accept-term would admit every TCP segment it
	// scoped). Deny the term's scoped traffic instead — a per-term terminating
	// `drop` that mirrors the userspace fail-closed direction (see the tcp-flags
	// comment above) without failing the whole ruleset. This overrides the
	// term's configured action for ALL dispositions: an accept-term's traffic is
	// denied; a discard-term already drops; a reject-term's deny becomes a silent
	// drop; a fall-through / routing-instance (PBR) term terminates as a drop
	// rather than continuing (or accepting) permissively.
	//
	// Scope the drop to TCP with `meta l4proto 6`. A tcp-flags constraint only
	// ever matches TCP in the userspace matcher (per_packet_l4_matches returns
	// false for a non-TCP protocol, userspace-dp/src/filter/engine/matching.rs),
	// so "everything the term would have matched" is a subset of TCP; the guard
	// makes the drop a precise mirror instead of an over-broad one, and — when
	// the term carried no other predicate (tcp-flags was its only match) —
	// prevents a bare `drop` from denying ALL host-inbound traffic. The guard is
	// redundant-but-valid nft when the term already constrains l4proto to TCP,
	// and family-agnostic (`meta l4proto` works in both the ip and ip6 pass, like
	// the reject lowering below). The honored log/count modifiers ride the rule
	// so the fail-closed drops stay observable.
	if tcpFlagsFailClosed {
		return []string{joinNftFields(match, "meta l4proto 6", modStr, "drop")}
	}

	// Fall-through (#3427): a term with NO terminating action (explicit `then
	// next term` or a modifier-only term) APPLIES its modifiers and continues to
	// the next term. Emit the honored modifiers as a NON-TERMINATING rule (no
	// verdict) so the per-term log/count fires while later discard/reject terms
	// stay reachable — nft falls through any rule that carries no verdict. With
	// no honored modifier the term contributes nothing: return no rule (the
	// pre-#3445 behavior), which keeps the subsequent terms reachable.
	if (term.NextTerm || term.Action == "") && term.RoutingInstance == "" {
		if modStr == "" {
			return nil
		}
		return []string{joinNftFields(match, modStr)}
	}

	// reject (#3445 H10): faithfully mirror the userspace reject-reply synthesis
	// (userspace-dp poll_descriptor/reject_reply.rs) — a TCP RST for TCP and an
	// ICMP/ICMPv6 "administratively prohibited" Destination Unreachable for every
	// other protocol. nft cannot select the reply protocol within ONE rule, so
	// emit two: a TCP-only `reject with tcp reset`, then a family-agnostic
	// `reject with icmpx type admin-prohibited` (icmpx selects ICMP vs ICMPv6
	// from the actual packet, so the SAME pair is correct in both the ip and ip6
	// rendering passes and needs no L3 qualifier). The pre-fix bare `reject` sent
	// ICMP port-unreachable for ALL protocols (including TCP) — a different wire
	// response than userspace. The honored modifiers ride BOTH rules; the rules
	// are mutually exclusive by l4proto, so each matched packet is logged/counted
	// exactly once.
	if term.Action == "reject" {
		return []string{
			joinNftFields(match, "meta l4proto 6", modStr, "reject with tcp reset"),
			joinNftFields(match, modStr, "reject with icmpx type admin-prohibited"),
		}
	}

	// Terminating verdict. Mirror the Rust filter compiler's action mapping
	// (userspace-dp/src/filter/compiler.rs) EXACTLY so the kernel-PRIMARY lo0
	// input chain can never diverge from the userspace evaluator on a matched
	// terminating term:
	//   - discard             -> drop   (silent)
	//   - accept              -> accept
	//   - ""  (routing-instance PBR terminate-as-accept, #3427) -> accept
	//   - any OTHER non-empty -> drop   (FAIL CLOSED, #3724 M08)
	//
	// An unknown / unhandled NON-EMPTY action can only reach here from a tolerant
	// load, a peer session-sync, or a mixed-version snapshot: the strict commit
	// gate (validateFilterActionsStrict, plus the UnknownActions capture in
	// compileFilterThen which leaves term.Action == "") rejects an unknown `then`
	// token before it is ever persisted through the CLI path. The Rust compiler
	// fails such a term CLOSED to FilterAction::Discard; the kernel mirror MUST
	// match that. The pre-#3724 code defaulted the unknown case to nft `accept`,
	// which fails OPEN on the primary host-bound enforcement path — the kernel
	// would ADMIT host-bound traffic the operator's lo0 filter meant to drop
	// while userspace-dp drops it (a mixed-version control-plane fail-open). Fail
	// closed to `drop` and log the drift so the divergence is observable.
	var action string
	switch term.Action {
	case "discard":
		action = "drop"
	case "accept", "":
		// "" reaches here only for the routing-instance (PBR) term — a plain
		// empty-action fall-through returned above. Its filter verdict is accept
		// (userspace terminates-as-accept; route selection stays userspace-only).
		action = "accept"
	default:
		slog.Warn("lo0 kernel nftables mirror: unknown terminating action, failing closed to drop (snapshot/version drift)",
			"term", term.Name, "action", term.Action)
		action = "drop"
	}
	return []string{joinNftFields(match, modStr, action)}
}
