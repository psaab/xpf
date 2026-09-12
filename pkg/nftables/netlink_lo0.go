package nftables

// netlink_lo0.go builds the `inet xpf_lo0` loopback input-filter chain via
// netlink, mirroring buildLo0FilterPayload / nftRulesFromTerm in
// pkg/daemon/daemon_nft.go (the parity ORACLE). Source/destination scopes arrive
// pre-resolved (prefix-lists already expanded by the daemon converter); this
// builder re-applies the family-filter / empty-set / match-nothing semantics
// (mirroring nftFamilyAddrs / nftAddrPredicate) and the term disposition
// (fall-through, reject pair, tcp-flags fail-closed, verdict mapping) that
// nftRulesFromTerm encodes, so a term lowers to the SAME 0/1/2 kernel rules.

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/nftables/expr"
	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// buildLo0FilterNetlink queues the lo0 filter table (counters + chain + rules)
// into the plan, mirroring buildLo0FilterPayload. The caller has created the
// table + `input` chain (priority nftLo0FilterPriority, policy accept).
func buildLo0FilterNetlink(p *nlPlan, spec Lo0FilterSpec) {
	seen := map[string]bool{}
	declareCounters := func(terms []Lo0FilterTerm) {
		for _, t := range terms {
			if t.Count == "" {
				continue
			}
			cn := Lo0CounterName(t.Count)
			if !seen[cn] {
				seen[cn] = true
				p.counterObj(cn)
			}
		}
	}
	declareCounters(spec.V4Terms)
	declareCounters(spec.V6Terms)

	for _, t := range spec.V4Terms {
		buildLo0TermNetlink(p, t, famV4)
	}
	for _, t := range spec.V6Terms {
		buildLo0TermNetlink(p, t, famV6)
	}
}

// buildLo0TermNetlink lowers one filter term to 0, 1, or 2 kernel rules,
// mirroring nftRulesFromTerm.
func buildLo0TermNetlink(p *nlPlan, t Lo0FilterTerm, f nlFamily) {
	// Resolve the address predicates first: a positive scope that resolves to no
	// prefix of this family is a Junos match-nothing term (skip entirely).
	// #6512: a malformed token in either direction fails the plan CLOSED. Never
	// install a rule built from a narrowed (or, on an except list, widened)
	// subset of what the operator authored.
	srcAddrs, srcSkip, srcErr := lo0AddrScope(f, t.SrcAddrs, t.SrcExcept, t.SrcConstrained)
	if srcErr != nil {
		p.fail(fmt.Errorf("lo0 filter term %q source-address (except=%t): %w", t.Name, t.SrcExcept, srcErr))
		return
	}
	if srcSkip {
		return
	}
	dstAddrs, dstSkip, dstErr := lo0AddrScope(f, t.DstAddrs, t.DstExcept, t.DstConstrained)
	if dstErr != nil {
		p.fail(fmt.Errorf("lo0 filter term %q destination-address (except=%t): %w", t.Name, t.DstExcept, dstErr))
		return
	}
	if dstSkip {
		return
	}

	// #6806: an `icmp-type` / `icmp-code` token the compiler could not resolve to
	// a byte is recorded on config.FirewallFilterTerm.UnknownICMPTypes /
	// UnknownICMPCodes and carried here as these markers. Unlike an unresolvable
	// protocol or address the raw token does NOT reach this builder — ICMPTypes /
	// ICMPCodes carry only the RESOLVED bytes — so the marker is the only way the
	// mirror can see it, exactly like the #6463 AddressUnrepresentable channel.
	//
	// Without it, an all-unresolvable list left the resolved slice empty, the
	// `len(t.ICMPTypes) > 0` guard in applyMatches emitted no predicate, and the
	// term matched EVERY ICMP type in its scope. The userspace mirror sets the
	// identically-named ICMPTypeUnrepresentable / ICMPCodeUnrepresentable
	// (pkg/dataplane/userspace/filters.go) and the Rust filter compiler fails the
	// whole snapshot closed, so failing the plan here is what keeps the two
	// dataplanes from enforcing different policy on the same config (#3406).
	if t.ICMPTypeUnrepresentable || t.ICMPCodeUnrepresentable {
		p.fail(fmt.Errorf("lo0 filter term %q: unrepresentable icmp-type/icmp-code "+
			"(type_unrepresentable=%t code_unrepresentable=%t)",
			t.Name, t.ICMPTypeUnrepresentable, t.ICMPCodeUnrepresentable))
		return
	}

	// applyMatches appends every match predicate (in oracle order) to a rule
	// assembler; it does NOT append the tcp-flags predicate when fail-closed.
	tcpFailClosed := false
	if len(t.TCPFlags) > 0 {
		if _, _, _, err := config.ParseTCPFlagsExpression(t.TCPFlags); err != nil {
			slog.Warn("lo0 netlink mirror: unrepresentable tcp-flags expression, failing term CLOSED (drop) to match userspace",
				"term", t.Name, "tcp_flags", strings.Join(t.TCPFlags, " "), "error", err)
			tcpFailClosed = true
		}
	}
	// #6804: fail-closed for an unrepresentable flexible-match-range.
	//
	// The direction is NOT the tcp-flags drop, and mirroring userspace is what
	// decides that. Userspace poisons such a term to FlexMatchStart::Unsupported
	// so flex_matches() returns false and the term matches NOTHING — later terms
	// still run (pkg/dataplane/userspace/filters.go). The kernel equivalent of
	// "matches nothing" is to emit NO RULE for the term.
	//
	// A drop would be wrong here in a way it is not for tcp-flags: a tcp-flags
	// constraint only ever matches TCP, so #5512 can scope its drop with
	// `meta l4proto 6`. A flexible-match-range has no such natural narrowing, so
	// a term whose ONLY predicate was the flex-match would render a bare `drop`
	// and deny ALL host-inbound traffic — turning a fail-open into a lockout.
	if t.FlexMatchUnrepresentable || (t.FlexMatch != nil && !flexMatchRepresentable(*t.FlexMatch)) {
		slog.Warn("lo0 netlink mirror: unrepresentable flexible-match-range; the "+
			"term matches NOTHING (mirroring the userspace fail-closed) so its "+
			"narrowing is never silently dropped", "term", t.Name)
		return
	}
	// addPorts resolves one port-token list and appends its transport-port match.
	// An unrepresentable token FAILS the plan CLOSED (a.p.fail), exactly as the
	// nft oracle does: the oracle emits the raw token and `nft -f -` REJECTS it,
	// retaining the prior ruleset — so the netlink build must abort the install
	// rather than DROP the predicate and widen a port-constrained rule to
	// match-all (the #6405 fail-open).
	addPorts := func(a *ruleAsm, tokens []string, dir string, except bool) {
		ports, err := parsePortTokens(tokens)
		if err != nil {
			a.p.fail(fmt.Errorf("lo0 filter term %q %s (except=%t): %w", t.Name, dir, except, err))
			return
		}
		if len(ports) > 0 {
			a.thPort(dir, ports, except)
		}
	}
	applyMatches := func(a *ruleAsm) {
		if len(srcAddrs) > 0 {
			a.saddr(f, srcAddrs, t.SrcExcept)
		}
		if len(dstAddrs) > 0 {
			a.daddr(f, dstAddrs, t.DstExcept)
		}
		if len(t.Protocols) > 0 {
			// #6806: an unresolvable protocol token fails the plan CLOSED, the
			// same posture as ports (#6405), DSCP (#6405) and addresses (#6512)
			// immediately around it. Dropping the predicate widened the term.
			protos, err := lo0Protocols(t.Protocols)
			if err != nil {
				a.p.fail(fmt.Errorf("lo0 filter term %q protocol: %w", t.Name, err))
			} else if len(protos) > 0 {
				a.l4protoSet(protos)
			}
		} else if Lo0NeedsPortProtocolFallback(
			len(t.Protocols) > 0,
			len(t.ICMPTypes) > 0 || len(t.ICMPCodes) > 0,
			Lo0TermComparesPort(t.SourcePorts, t.DestinationPorts, t.SourcePortsExcept, t.DestPortsExcept),
		) {
			// #9953: this term compares a transport PORT but names no protocol, so
			// without a guard the two bytes it reads come out of whatever header
			// follows the IP header — including SCTP, GRE and ICMP, which reach
			// this chain by the ordinary host-bound path. See
			// lo0_port_fallback_9953.go for why that set is not hypothetical.
			//
			// Emitted BEFORE addPorts below so the protocol comparison short-circuits
			// ahead of the payload load, which is both correct and the order the nft
			// text oracle produces.
			a.l4protoSet(Lo0PortFallbackProtocols())
		}
		addPorts(a, t.SourcePorts, "sport", false)
		addPorts(a, t.DestinationPorts, "dport", false)
		addPorts(a, t.SourcePortsExcept, "sport", true)
		addPorts(a, t.DestPortsExcept, "dport", true)
		if len(t.DSCPs) > 0 {
			// DSCP mirrors the port path: nftDSCPValue emits the raw token on an
			// unresolvable name (nft then rejects -> fail closed), so dropping the
			// predicate here would widen the match. Fail the plan closed instead.
			dscps, err := lo0DSCPs(t.DSCPs)
			if err != nil {
				a.p.fail(fmt.Errorf("lo0 filter term %q dscp: %w", t.Name, err))
			} else if len(dscps) > 0 {
				a.dscp(f, dscps)
			}
		}
		if len(t.ICMPTypes) > 0 {
			a.icmpType(f, intsToU8(t.ICMPTypes))
		}
		if len(t.ICMPCodes) > 0 {
			a.icmpCode(f, intsToU8(t.ICMPCodes))
		}
		if !tcpFailClosed && len(t.TCPFlags) > 0 {
			if required, forbidden, ok, _ := config.ParseTCPFlagsExpression(t.TCPFlags); ok {
				a.tcpFlags(required, forbidden)
			}
		}
		if t.IsFragment {
			if f.v6 {
				a.exthdrFragV6()
			} else {
				a.fragV4()
			}
		}
		// #6804: emit the flexible-match-range narrowing. Skipped when failing
		// closed, exactly like tcp-flags — the drop below covers the term.
		if !tcpFailClosed && t.FlexMatch != nil {
			a.flexMatch(*t.FlexMatch)
		}
	}
	applyMods := func(a *ruleAsm) {
		if t.Log {
			a.logPrefix(nftLo0LogPrefix(t.Name))
		}
		if t.Count != "" {
			a.counterRef(Lo0CounterName(t.Count))
		}
	}

	// #5512: fail-closed override for an unrepresentable tcp-flags expression —
	// a TCP-scoped drop instead of the term's widened verdict.
	if tcpFailClosed {
		a := p.rule()
		applyMatches(a)
		a.needL4proto(protoTCP) // literal `meta l4proto 6` guard
		applyMods(a)
		a.emit(verdictDrop()...)
		return
	}

	// Fall-through (#3427): a term with no terminating action applies its honored
	// modifiers and continues. Emit a non-terminating rule (no verdict) only when
	// there is a modifier to honor; otherwise emit no rule.
	if (t.NextTerm || t.Action == "") && t.RoutingInstance == "" {
		if !t.Log && t.Count == "" {
			return
		}
		a := p.rule()
		applyMatches(a)
		applyMods(a)
		a.emit()
		return
	}

	// reject (#3445 H10): a TCP RST plus a family-agnostic ICMP/ICMPv6
	// admin-prohibited reply — two mutually-exclusive rules.
	//
	// #9072: emit only the rules the term's PROTOCOL can actually reach.
	//
	// `applyMatches` latches `l4Val` from the term's own protocol, so
	// `needL4proto(protoTCP)` on a non-TCP term saw `l4Val != 6` and appended a
	// SECOND, contradictory `meta l4proto` compare — `l4proto==11 &&
	// l4proto==06`. Dead by construction, and operator-visible in
	// `nft list ruleset`, where a self-contradictory rule invites misdiagnosis.
	//
	// ENFORCEMENT WAS NEVER AFFECTED and this does not claim otherwise: the
	// icmpx rule always carried the correct family-agnostic reject for the
	// specified protocols in every case, including the mixed `[tcp udp]` one.
	// The change is which rules are EMITTED, never which packets are rejected —
	// asserted by the cells rather than argued here.
	if t.Action == "reject" {
		tcpReachable, tcpOnly := lo0RejectTCPReach(t)

		// The TCP-RST rule is reachable only if TCP is among the term's
		// protocols (or the term names none, matching every protocol).
		if tcpReachable {
			a1 := p.rule()
			applyMatches(a1)
			a1.needL4proto(protoTCP)
			applyMods(a1)
			a1.emit(rejectTCPReset()...)
		}

		// The icmpx rule is DEAD for a TCP-ONLY term: the rule above already
		// matches every packet this one could, and rejects it. Symmetric with
		// the arm above rather than an afterthought — the table in #9072 shows
		// the dead rule moving between r00 and r01 depending on the protocol,
		// so fixing one end only would leave the other.
		if !tcpOnly {
			a2 := p.rule()
			applyMatches(a2)
			applyMods(a2)
			a2.emit(rejectICMPXAdminProhibited()...)
		}
		return
	}

	// Terminating verdict (mirrors the Rust compiler's action mapping).
	var verdict []expr.Any
	switch t.Action {
	case "discard":
		verdict = verdictDrop()
	case "accept", "":
		verdict = verdictAccept()
	default:
		slog.Warn("lo0 netlink mirror: unknown terminating action, failing closed to drop",
			"term", t.Name, "action", t.Action)
		verdict = verdictDrop()
	}
	a := p.rule()
	applyMatches(a)
	applyMods(a)
	a.emit(verdict...)
}

// lo0AddrScope mirrors nftFamilyAddrs + nftAddrPredicate's family-filter and
// match-nothing decision. It returns the family-filtered address list to feed
// the address match, skip==true when the term matches nothing (a positive scope
// constrained to no prefix of this family) — the caller drops the rule — and a
// non-nil error when any token was MALFORMED, which fails the plan closed.
func lo0AddrScope(f nlFamily, addrs []string, except, constrained bool) (out []string, skip bool, err error) {
	if !constrained {
		return nil, false, nil
	}
	fam, err := filterFamilyAddrs(f, addrs)
	if err != nil {
		return nil, false, err
	}
	if len(fam) == 0 {
		if except {
			// Empty except set -> match ALL -> no predicate.
			return nil, false, nil
		}
		// Empty positive set -> match NOTHING -> skip the rule.
		return nil, true, nil
	}
	return fam, false, nil
}

// filterFamilyAddrs keeps only this family's literals, dropping empty/"any" and
// WRONG-FAMILY tokens and canonicalizing each. A MALFORMED token — one that is
// neither a valid address nor a valid prefix — returns an error so the caller
// FAILS THE PLAN CLOSED (#6512).
//
// Dropping a malformed token per-token and installing the surviving subset is
// the fail-open this closes. It is wrong in BOTH directions and the direction
// depends on data the lowering cannot see:
//
//   - a POSITIVE list narrows — a `discard`/`reject` term then enforces a
//     smaller address set than the operator wrote, and a host in the dropped
//     range is accepted by fall-through;
//   - an EXCEPT list WIDENS, and if every token is malformed the list empties
//     and lo0AddrScope's empty-except arm drops the predicate entirely, so the
//     direction becomes UNCONSTRAINED and the rule matches every address. That
//     is the "empty means match everything" shape, so skipping a bad entry can
//     never be the fix here.
//
// Failing closed instead is the same posture parsePortTokens / lo0DSCPs take in
// this file for an unrepresentable port / DSCP token (#6405), and it is what
// the exec-`nft` oracle does for those: emit the raw token, `nft -f -` rejects
// the whole ruleset, the prior ruleset is retained. nftFamilyAddrs in
// pkg/daemon/daemon_nft.go now keeps a malformed address token verbatim for the
// same reason, so the two builders still agree.
//
// Fail-closed here does NOT mean fail-to-boot (#1960). The install error makes
// applyLo0Filter warn and, with no real filter loaded, install the cold-boot
// fail-closed fence — which admits the mandatory L3 / return traffic and never
// touches a lifeline interface — and the boot apply logs and discards the
// error. A config that used to load still loads; it just does not get a kernel
// filter that differs from what the operator wrote.
//
// Malformedness is detected HERE rather than read off the #6463
// AddressUnrepresentable marker because that marker is derived from
// term.UnknownAddresses, which records only malformed LITERAL `from
// source-address` / `destination-address` tokens. A malformed entry inside a
// referenced `policy-options prefix-list` reaches this builder through
// ResolveFilterPrefixListAddrs with the marker unset — and, unlike a bad
// literal, it is not rejected by the strict commit gate either (see
// validateFirewallPrefixListReferencesStrict, which validates the reference,
// not the entries). Detecting the token itself covers both provenances.
func filterFamilyAddrs(f nlFamily, addrs []string) ([]string, error) {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a == "" || a == "any" {
			continue
		}
		if pfx, err := netip.ParsePrefix(a); err == nil {
			if pfx.Addr().Is6() == f.v6 {
				out = append(out, pfx.String())
			}
			continue
		}
		if ip, err := netip.ParseAddr(a); err == nil {
			if ip.Is6() == f.v6 {
				out = append(out, ip.String())
			}
			continue
		}
		return nil, fmt.Errorf("malformed address %q (neither an IP nor a CIDR prefix)", a)
	}
	return out, nil
}

// lo0RejectTCPReach reports, for a reject term, whether the TCP-RST rule is
// REACHABLE and whether the term is TCP-ONLY (#9072).
//
// A term naming no protocol matches every protocol, so TCP is reachable and the
// term is not TCP-only — that is the pre-#9072 shape and both rules are emitted,
// unchanged.
//
// An UNRESOLVABLE protocol token is deliberately treated as "reachable, not
// TCP-only", i.e. emit both rules exactly as before. `applyMatches` fails the
// plan CLOSED on that token (#6806), so the rules are never installed; deciding
// emission on a set this function could not resolve would be reasoning from a
// value the caller is about to reject anyway, and the failure must come from
// there rather than from a silently narrower ruleset here.
func lo0RejectTCPReach(t Lo0FilterTerm) (tcpReachable, tcpOnly bool) {
	if len(t.Protocols) == 0 {
		return true, false
	}
	protos, err := lo0Protocols(t.Protocols)
	// The `len(protos) == 0` arm is DEFENSIVE and unreachable today:
	// lo0Protocols returns one entry per token or a non-nil error, and
	// len(t.Protocols) > 0 is already established above. It is kept so a future
	// lo0Protocols that can legitimately resolve to nothing degrades to the
	// pre-#9072 both-rules shape rather than silently narrowing the ruleset —
	// and it is labelled rather than left to look load-bearing, because a
	// mutant that flips it SURVIVES and that survival is correct.
	if err != nil || len(protos) == 0 {
		return true, false
	}
	hasTCP := false
	other := false
	for _, pr := range protos {
		if pr == protoTCP {
			hasTCP = true
		} else {
			other = true
		}
	}
	return hasTCP, hasTCP && !other
}

// lo0Protocols mirrors the #3436 numeric protocol lowering: resolve each Junos
// protocol token through appid.ProtocolNumber.
//
// #6801-sibling / #6806: an unresolvable token returns a non-nil error so the
// caller FAILS THE PLAN CLOSED, exactly like lo0DSCPs and parsePortTokens.
// It used to be DROPPED with a warning, which is the fail-open this closes:
//
//   - ALL tokens unresolvable -> the resolved slice is empty -> the caller's
//     `len(protos) > 0` guard emits NO l4proto predicate at all, so a term
//     written to admit one protocol admits EVERY protocol in its scope.
//   - SOME tokens unresolvable -> the rule is built from a NARROWED subset of
//     what the operator authored, which is wrong in the other direction for a
//     discard/reject term (traffic on the dropped protocol is no longer denied
//     and falls through).
//
// A token outside the SSOT cannot reach a committed config — the strict gate
// (validateFilterMatchValuesStrict) rejects it — but it reaches here from the
// tolerant load / peer-sync / mixed-version paths (#1960), which is exactly
// where the two dataplanes must not diverge: the userspace mirror hands the
// RAW token to the Rust filter compiler, which rejects the whole snapshot and
// keeps its last-good policy (pkg/dataplane/userspace/filters.go). Silently
// widening the kernel term while userspace refuses the same filter is the
// mode-dependent fail-open this issue is about.
func lo0Protocols(tokens []string) ([]uint8, error) {
	out := make([]uint8, 0, len(tokens))
	for _, tok := range tokens {
		n, ok := appid.ProtocolNumber(tok)
		if !ok {
			return nil, fmt.Errorf("unresolvable protocol %q", tok)
		}
		out = append(out, n)
	}
	return out, nil
}

// lo0DSCPs mirrors nftDSCPValue: resolve each DSCP token to a numeric codepoint
// via the shared dataplane.DSCPValues SSOT, or a bare numeric 0..63. An
// unresolvable token returns a non-nil error so the caller FAILS CLOSED — the
// oracle's nftDSCPValue emits the raw token, which `nft -f -` then rejects
// (prior ruleset retained), so silently dropping the predicate here would widen
// the match (a fail-open, the same class as the #6405 port bug).
func lo0DSCPs(tokens []string) ([]uint8, error) {
	out := make([]uint8, 0, len(tokens))
	for _, tok := range tokens {
		key := strings.ToLower(strings.TrimSpace(tok))
		if v, ok := dataplane.DSCPValues[key]; ok {
			out = append(out, v)
			continue
		}
		if v, err := strconv.Atoi(key); err == nil && v >= 0 && v <= 63 {
			out = append(out, uint8(v))
			continue
		}
		return nil, fmt.Errorf("unrepresentable dscp token %q (fail closed to match the nft oracle, which rejects it)", tok)
	}
	return out, nil
}

// parsePortTokens resolves lo0 filter port tokens ("22", "ssh", "1024-2048")
// into numeric [lo,hi] ranges via config.ResolveFilterPortRange — the SAME SSOT
// the compile path and the kernel filter-based-forwarding mirror use, and the
// same numeric resolution nft applies to the raw token the oracle emits (a
// /etc/services-style name like `ssh` -> 22).
//
// A token that cannot be represented numerically (an unknown service name, a
// malformed range) returns a non-nil error so the caller FAILS CLOSED: the
// oracle emits the raw token and `nft -f -` REJECTS it, so the prior ruleset is
// retained. The netlink build MUST likewise abort the install rather than DROP
// the whole port predicate and widen a port-constrained rule to match ALL ports
// (the #6405 host-inbound fail-open). An empty token list yields no predicate.
func parsePortTokens(tokens []string) ([]nlPort, error) {
	if len(tokens) == 0 {
		return nil, nil
	}
	out := make([]nlPort, 0, len(tokens))
	for _, tok := range tokens {
		lo, hi, ok := config.ResolveFilterPortRange(strings.TrimSpace(tok))
		if !ok {
			return nil, fmt.Errorf("unrepresentable port token %q (fail closed to match the nft oracle, which rejects it)", tok)
		}
		out = append(out, nlPort{lo: lo, hi: hi})
	}
	return out, nil
}

// nftLo0LogPrefix mirrors nftLo0LogPrefix in the oracle: `xpf-lo0 <term>: `,
// quote/backslash stripped, bounded to 64 bytes.
func nftLo0LogPrefix(term string) string {
	const maxLen = 64
	safe := strings.NewReplacer(`"`, "", `\`, "").Replace(term)
	p := "xpf-lo0 " + safe + ": "
	if len(p) > maxLen {
		p = p[:maxLen]
	}
	return p
}

// intsToU8 narrows resolved ICMP type/code values to the bytes nftables
// matches on.
//
// #8597 K54, REFUTED — recorded here so the next reader does not add the guard
// that is not needed. The finding was that `uint8(v)` truncates silently, so a
// configured icmp-type of 999 would match type 231 instead of being rejected.
// It does not, and the reason is WHERE the bound lives.
//
// The only callers are the two icmpType/icmpCode sites above, whose values come
// from FilterTerm.ICMPTypes / .ICMPCodes. Those slices are populated solely by
// resolveICMPTypeToken / resolveICMPCodeToken (pkg/config/filter_match_resolve.go),
// which accept a numeric token only when `n >= 0 && n <= 255` and otherwise
// return ok=false, sending the token to UnknownICMPTypes / UnknownICMPCodes
// instead (#3205/#6806). An out-of-range value can therefore never enter the
// int slices this function reads.
//
// The load-bearing detail is that this bound is in the COMPILER, not in
// setSchema. A schema `validator` gates only the strict commit path:
// Store.Load and Store.SyncApply compile through compileTreeLenient, which
// downgrades a typed-leaf violation to a warning (#1319), so a schema range is
// not an invariant a downstream consumer may rely on. This one runs on every
// ingress path, strict and tolerant alike. Measured: a tree carrying
// `from icmp-type 999` compiled leniently yields ICMPTypes=[] and
// UnknownICMPTypes=[999].
//
// Contrast #8597 K51 (pkg/dhcp/dhcpv6.go, pdHintPrefixLength), which was the
// same shape but REAL precisely because its only bound was a schema validator.
// If a future change resolves ICMP tokens without that 0..255 check — or adds a
// third caller reading ints from somewhere else — this conversion becomes
// unsound and the guard belongs at that new source, not here.
func intsToU8(vals []int) []uint8 {
	out := make([]uint8, 0, len(vals))
	for _, v := range vals {
		out = append(out, uint8(v))
	}
	return out
}
