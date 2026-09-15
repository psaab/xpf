package userspace

import (
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// flexMatchStartUnrepresentable is the sentinel match-start emitted for a term
// whose flexible-match-range is UNREPRESENTABLE on the wire. It is deliberately
// NOT "layer-3" / "layer-4", so the Rust filter compiler lowers it to
// FlexMatchStart::Unsupported and flex_matches() returns false — the term
// matches NOTHING (fail-closed) rather than enforcing something the operator
// did not write.
//
// TWO CAUSES REACH IT:
//   - #5823: more than one range named for a single term.
//   - #9020: parameters the compiler could not represent (UnknownFlexMatch) —
//     a bad byte-offset, an unparseable match-value, a match-start outside
//     {layer-3, layer-4}.
//
// The value was "unrepresentable-multi-range" while #5823 was the only cause.
// It is renamed because it reaches `show firewall ... effective`, and telling
// an operator with ONE range that their term has multiple is the
// misdirecting-diagnostic shape this tree has been repeatedly bitten by. The
// exact string carries no wire contract: the Rust side matches "layer-3" and
// "layer-4" and treats everything else as Unsupported.
const flexMatchStartUnrepresentable = "unrepresentable"

// BuildFirewallFilterSnapshots returns the effective (compiled) firewall-filter
// snapshots the userspace dataplane actually receives for cfg — the same value
// buildSnapshot threads into ConfigSnapshot.Filters. It is exported so the
// `show firewall [filter <name>] effective` CLI surface (#4422) can render
// exactly what the matcher enforces: post prefix-list resolution, address/port
// `except` folding (positive-wins on a mixed term), DSCP code-point resolution,
// TCP-flags mask lowering, fall-through (NextTerm) computation, flex-match
// lowering, and fail-closed (unrepresentable) marker assignment. It is
// read-only and derives entirely from cfg — it touches no dataplane state.
func BuildFirewallFilterSnapshots(cfg *config.Config) []FirewallFilterSnapshot {
	return buildFirewallFilterSnapshots(cfg)
}

func buildFirewallFilterSnapshots(cfg *config.Config) []FirewallFilterSnapshot {
	if cfg == nil {
		return nil
	}
	var out []FirewallFilterSnapshot
	// inet filters
	inetNames := make([]string, 0, len(cfg.Firewall.FiltersInet))
	for name := range cfg.Firewall.FiltersInet {
		inetNames = append(inetNames, name)
	}
	sort.Strings(inetNames)
	for _, name := range inetNames {
		filter := cfg.Firewall.FiltersInet[name]
		if filter == nil {
			continue
		}
		snap := FirewallFilterSnapshot{
			Name:   name,
			Family: "inet",
			Terms:  buildFilterTermSnapshots(name, filter, cfg),
		}
		out = append(out, snap)
	}
	// inet6 filters
	inet6Names := make([]string, 0, len(cfg.Firewall.FiltersInet6))
	for name := range cfg.Firewall.FiltersInet6 {
		inet6Names = append(inet6Names, name)
	}
	sort.Strings(inet6Names)
	for _, name := range inet6Names {
		filter := cfg.Firewall.FiltersInet6[name]
		if filter == nil {
			continue
		}
		snap := FirewallFilterSnapshot{
			Name:   name,
			Family: "inet6",
			Terms:  buildFilterTermSnapshots(name, filter, cfg),
		}
		out = append(out, snap)
	}
	return out
}

func buildFilterTermSnapshots(filterName string, filter *config.FirewallFilter, cfg *config.Config) []FirewallTermSnapshot {
	// #2214: return a non-nil empty slice (never nil) so the enclosing
	// FirewallFilterSnapshot.Terms marshals as `[]`, never JSON `null`. The
	// Terms field has no `,omitempty` (the compiler can store a filter with
	// zero terms — see compileFirewall) and the Rust `Vec<FirewallTermSnapshot>`
	// rejects an explicit null, which aborts the whole snapshot decode and
	// kills ALL transit (#1961 no-transit signature).
	if filter == nil || len(filter.Terms) == 0 {
		return []FirewallTermSnapshot{}
	}
	terms := make([]FirewallTermSnapshot, 0, len(filter.Terms))
	for _, term := range filter.Terms {
		if term == nil {
			continue
		}
		snap := FirewallTermSnapshot{
			Name:              term.Name,
			Action:            term.Action,
			Count:             term.Count,
			Log:               term.Log,
			RejectMessageType: term.RejectMessageType,
			Syslog:            term.Syslog,
			PolicerName:       term.Policer,
			RoutingInstance:   term.RoutingInstance,
			ForwardingClass:   term.ForwardingClass,
			// #2544: fall-through. A term whose `then` carries NO terminating
			// action must apply its modifiers and FALL THROUGH to the next term
			// (Junos). This covers BOTH the explicit `then next term`
			// (term.NextTerm set by compileFilterThen) AND a modifier-only term
			// (Action=="" with only count/log/forwarding-class/policer/dscp).
			// Junos treats a modifier-only term as an implicit fall-through, so
			// the signal is uniformly "no terminating action" == fall-through.
			// A routing-instance (PBR) term is terminating-wise its own decision
			// and is NOT a fall-through even with an empty Action — leave it.
			NextTerm: (term.NextTerm || term.Action == "") && term.RoutingInstance == "",
		}
		// Source / destination addresses: literal CIDRs PLUS the prefixes
		// resolved from any `from source-prefix-list` / `destination-prefix-list`
		// reference (#2506). The legacy eBPF compiler expanded these
		// (pkg/dataplane/compiler_filter.go); the userspace snapshot builder
		// dropped them entirely, so a term scoped by a prefix-list reached the
		// dataplane with NO address constraint (fail-open for accept/PBR,
		// fail-closed for discard/reject — either way wrong).
		srcAddrs, srcExcept, srcConstrained := resolvePrefixListAddrs(
			term.SourceAddresses, term.SourcePrefixLists, cfg, filterName, term.Name, "source", term.Action)
		dstAddrs, dstExcept, dstConstrained := resolvePrefixListAddrs(
			term.DestAddresses, term.DestPrefixLists, cfg, filterName, term.Name, "destination", term.Action)
		snap.SourceAddresses = srcAddrs
		snap.DestAddresses = dstAddrs
		snap.SourceExcept = srcExcept
		snap.DestExcept = dstExcept
		snap.SourceConstrained = srcConstrained
		snap.DestConstrained = dstConstrained
		// Protocols (#2545: a term may carry several `from protocol` values;
		// emit ALL of them into the wire vector — the Rust matcher does set
		// membership).
		for _, p := range term.Protocols {
			if p != "" {
				snap.Protocols = append(snap.Protocols, p)
			}
		}
		// Source ports
		snap.SourcePorts = append(snap.SourcePorts, term.SourcePorts...)
		// Destination ports
		snap.DestPorts = append(snap.DestPorts, term.DestinationPorts...)
		// Negated port sets (#2622): match all ports EXCEPT these. Emitted as
		// separate wire fields; the Rust matcher inverts membership.
		snap.SourcePortsExcept = append(snap.SourcePortsExcept, term.SourcePortsExcept...)
		snap.DestPortsExcept = append(snap.DestPortsExcept, term.DestPortsExcept...)
		// #6459: a `from {source,destination}-port[-except]` token the compiler
		// could not resolve to a number is recorded on term.UnknownPorts by
		// compileFilterFrom (resolveFilterPortTokens) and kept VERBATIM in the
		// port lists above. The strict commit gate
		// (validateFilterMatchValuesStrict, #3205) rejects it; on the lenient /
		// peer-sync path it reaches here. The pre-#6459 Rust filter compiler
		// dropped the unresolvable token PER-TOKEN
		// (`filter_map(parse_port_spec)`): a PARTIALLY-unresolvable list built
		// a matcher over only the surviving subset — a discard/reject term then
		// silently enforced a NARROWER port set than the operator wrote, and
		// the traffic meant for the dropped ports fell through to the implicit
		// accept (fail-OPEN). (An ALL-unresolvable list already failed closed
		// at match-time via `constrained && PortMatcher::Any`, #2400/#3205.)
		// Mark the term so the Rust filter compiler fails the snapshot CLOSED
		// rather than enforcing the narrowed subset — mirroring the
		// ICMP/DSCP/tcp-flags/flex #3406 family.
		if len(term.UnknownPorts) > 0 {
			snap.PortsUnrepresentable = true
		}
		// #6463: a literal `from source-address` / `destination-address` token
		// that is not a parseable IP/CIDR is recorded on term.UnknownAddresses
		// by compileFilterFrom (recordFilterAddrTokens). The strict commit gate
		// (validateFilterAddressLiteralsStrict, #3433) rejects it; on the
		// lenient / peer-sync path it reaches here. The pre-#6463 Rust
		// parse_address dropped such a token PER-TOKEN (its `Err(_)` arm pushed
		// nothing): a PARTIALLY-malformed list matched only the surviving
		// prefixes — a discard/reject term then silently enforced a NARROWER
		// address set than the operator wrote, and a host in the dropped range
		// was accepted by fall-through (fail-OPEN). (An ALL-malformed direction
		// already failed closed at match-time via `constrained && empty`,
		// #2400.) Mark the term so the Rust filter compiler fails the snapshot
		// CLOSED rather than enforcing the narrowed subset.
		if len(term.UnknownAddresses) > 0 {
			snap.AddressUnrepresentable = true
		}
		// #9875: a WHOLE `from` leaf the dataplane does not enforce
		// (term.UnknownFrom, recorded by compileFilterFrom's default arm,
		// #3307) or a value-bearing leaf written with NO operand
		// (term.ValuelessFrom, #8480). The strict commit gates
		// (validateFilterFromMatchStrict,
		// validateFirewallFilterValuelessFromStrict) reject both; on the
		// lenient / peer-sync path they reach here. The pre-#9875 builder
		// emitted only the surviving match set — byte-identical to a term
		// authored without the leaf — so an accept term over-permitted
		// and a discard/reject term over-dropped with no signal past the
		// boot warning. Mark the term so the Rust filter compiler fails
		// the snapshot CLOSED rather than enforcing the widened match —
		// mirroring the ICMP/DSCP/ports/address #3406 family.
		if len(term.UnknownFrom) > 0 || len(term.ValuelessFrom) > 0 {
			snap.FromUnrepresentable = true
		}
		// #3406: a single direction carrying BOTH a positive port list and a
		// `*-port-except` list has no single-inversion representation, so the Rust
		// filter compiler resolves it POSITIVE-WINS (the except list is ignored —
		// `source_port_except`/`dest_port_except` only fire when the positive list is
		// empty, see parse_term in userspace-dp/src/filter/compiler.rs). That is the
		// fail-safe resolution (it narrows to the positive scope, never widens), but
		// the pre-#3406 path dropped the except side SILENTLY. This shape is
		// hard-rejected at commit (validateFilterPortExceptStrict, #2622/#3297/#3302);
		// it reaches here only on the lenient / peer-sync path. Surface the dropped
		// except set with a warning so it is operator-visible — symmetric with the
		// mixed address-except warning in resolvePrefixListAddrs (#3359). Warn (not
		// fail-closed) because positive-wins narrows rather than widens, so unlike the
		// ICMP/DSCP/flex cases there is no silent fail-open to backstop.
		if portsHaveReal(term.SourcePorts) && portsHaveReal(term.SourcePortsExcept) {
			slog.Warn("firewall filter term mixes a positive source-port list with a "+
				"source-port-except list; the except list is ignored (positive-wins). "+
				"Split into separate terms (commit rejects this shape, #2622).",
				"filter", filterName, "term", term.Name)
		}
		if portsHaveReal(term.DestinationPorts) && portsHaveReal(term.DestPortsExcept) {
			slog.Warn("firewall filter term mixes a positive destination-port list with a "+
				"destination-port-except list; the except list is ignored (positive-wins). "+
				"Split into separate terms (commit rejects this shape, #2622).",
				"filter", filterName, "term", term.Name)
		}
		// DSCP (#2545: multi-value — emit every resolved code point).
		// #3406: a `from dscp` / `from traffic-class` MATCH token that resolves to
		// neither a known code-point name nor an integer 0..63 is UNREPRESENTABLE.
		// The strict commit gate (validateFilterDSCPStrict, #3309) rejects it; on
		// the lenient / peer-sync path it reaches here. The pre-#3406 builder
		// silently dropped the bad token — when EVERY token was unresolvable the
		// emitted vector was empty, which the Rust matcher reads as "no DSCP
		// constraint" → the DSCP dimension is dropped and the term WIDENS
		// (fail-OPEN). Mark the term so the Rust filter compiler fails the snapshot
		// CLOSED instead of dropping the constraint.
		for _, d := range term.DSCPs {
			if d == "" {
				continue
			}
			// #7422: the SAME resolver `show firewall` renders from, so the
			// builder's emit condition and the renderer's installed-or-not
			// verdict cannot drift (dataplane.ResolveFilterDSCP).
			if val, ok := dataplane.ResolveFilterDSCP(d); ok {
				snap.DSCPValues = append(snap.DSCPValues, val)
			} else {
				snap.DSCPMatchUnrepresentable = true
			}
		}
		// DSCP rewrite. #3406: an unrepresentable `then dscp` / `then traffic-class`
		// REWRITE token is CoS-only — it changes no match/action semantics, only a
		// marking side effect — so it does NOT fail the snapshot closed (that would
		// brick forwarding over a cosmetic marking). The strict commit gate
		// (validateFilterDSCPStrict) rejects it for fresh configs; on the lenient /
		// peer-sync path it reaches here. Surface the silent drop with a warning
		// (the pre-#3406 builder emitted NO rewrite and NO signal) so the lost CoS
		// marking is operator-visible.
		if term.DSCPRewrite != "" {
			if val, ok := dataplane.ResolveFilterDSCP(term.DSCPRewrite); ok {
				rewrite := val
				snap.DSCPRewrite = &rewrite
			} else {
				slog.Warn("dropping unresolvable filter term dscp/traffic-class rewrite "+
					"(CoS marking lost — the term still matches and acts)",
					"filter", filterName, "term", term.Name, "dscp_rewrite", term.DSCPRewrite)
			}
		}
		// Per-packet L4 match conditions (#2362). Previously parsed but
		// dropped on the wire — wire them through so the dataplane matches
		// exactly what the operator authored.
		// #3076: parse the full Junos tcp-flags expression (`syn & !ack`,
		// `(syn & !ack)`, plain lists) into a required-bits mask AND a
		// forbidden-bits mask. A TCP segment matches when
		// (flags & required) == required && (flags & forbidden) == 0.
		// Unrepresentable expressions (disjunction, negated groups, unknown
		// flags) are rejected at commit by compileFirewall, so a parse error
		// here is unreachable for a committed config; if one slips through
		// (e.g. a hand-built snapshot) #3367 marks the term unparseable on the
		// wire so the Rust filter compiler fails the snapshot CLOSED
		// (SnapshotIntegrityError::UnrepresentableFilterTCPFlags). Leaving the
		// masks nil silently widened the term to match every TCP segment (the
		// pre-#3076/#3367 fail-open), since the Rust matcher treats absent masks
		// as "no tcp-flags constraint".
		if required, forbidden, ok, err := config.ParseTCPFlagsExpression(term.TCPFlags); err != nil {
			slog.Warn("rejecting filter term with unparseable tcp-flags expression",
				"filter", filterName, "term", term.Name, "tcp_flags", term.TCPFlags, "error", err)
			snap.TCPFlagsUnparseable = true
		} else if ok {
			if required != 0 {
				r := required
				snap.TCPFlags = &r
			}
			if forbidden != 0 {
				f := forbidden
				snap.TCPFlagsForbidden = &f
			}
		}
		snap.IsFragment = term.IsFragment
		// icmp-type / icmp-code are multi-value (#2545): emit every in-range
		// byte into the wire vector. Junos icmp-type/icmp-code are 0..255; an
		// empty vector means the criterion is unconstrained. The Rust matcher
		// does set membership (match-ANY within the field).
		for _, t := range term.ICMPTypes {
			if t >= 0 && t <= 255 {
				snap.ICMPTypes = append(snap.ICMPTypes, uint8(t))
			}
		}
		for _, c := range term.ICMPCodes {
			if c >= 0 && c <= 255 {
				snap.ICMPCodes = append(snap.ICMPCodes, uint8(c))
			}
		}
		// #3406: a `from icmp-type` / `from icmp-code` token the compiler could not
		// resolve to a byte in 0..255 (a symbolic name with no mapping, or a
		// numeric value out of range) is recorded on term.UnknownICMPTypes /
		// term.UnknownICMPCodes by compileFilterFrom. The strict commit gate
		// (validateFilterMatchValuesStrict) rejects it; on the lenient / peer-sync
		// path it reaches here. The loops above emit only the RESOLVED bytes — when
		// every token was unresolvable the emitted vector is empty, which the Rust
		// matcher reads as "no ICMP constraint" → the dimension is dropped and the
		// term WIDENS (fail-OPEN). Mark the term so the Rust filter compiler fails
		// the snapshot CLOSED rather than silently widening it.
		if len(term.UnknownICMPTypes) > 0 {
			snap.ICMPTypeUnrepresentable = true
		}
		if len(term.UnknownICMPCodes) > 0 {
			snap.ICMPCodeUnrepresentable = true
		}
		// Flexible-match-range (#3077). Previously parsed + compiled for the
		// retired legacy dataplane (pkg/dataplane/compiler_filter.go) but
		// silently dropped here, so the byte-offset constraint never reached the
		// sole runtime dataplane and the term matched too broadly (fail-open).
		// Mirror the legacy lowering: FlexLength is the match width in BYTES
		// (BitLength/8, defaulted to 4 == 32-bit when unset, capped at 4 since
		// the wire value is a u32), and the compared value is pre-masked. The
		// byte offset is L3-relative (match-start layer-3, the only start point
		// the compiler emits). A zero effective length is dropped (no
		// constraint) rather than emitted as a degenerate always-fail match.
		if len(term.FlexMatchRangeNames) > 1 || len(term.UnknownFlexMatch) > 0 {
			// #5823: the term names more than one flexible-match-range range;
			// the wire matcher supports exactly one. The strict commit gate
			// (validateFilterFlexMatchStrict) already rejects this, so a term
			// reaches here ONLY on the tolerant load / peer-sync path (#1960).
			// Silently enforcing just the first range is fail-OPEN — the packets
			// the other ranges covered escape the intended match (an accept term
			// over-permits, a discard/reject over-drops). Fail CLOSED: emit an
			// UNREPRESENTABLE flex-match so the term matches NOTHING. A
			// non-{layer-3,layer-4} match-start lowers to
			// FlexMatchStart::Unsupported in the Rust matcher, whose
			// flex_matches() returns false for the term (never the wrong-base
			// match) — the existing per-term fail-closed channel, so no
			// multi-range support is added to the wire/matcher. Length stays
			// 1..=4 so flex_enabled is true (a length outside that range would
			// instead reject the WHOLE snapshot); Value/Mask are unread once the
			// start is Unsupported.
			// #9020: the SAME fail-closed channel now also covers a term whose
			// flexible-match-range parameters could not be represented.
			//
			// The compiler records those in UnknownFlexMatch and then assigns
			// term.FlexMatch anyway, so the tolerant load / peer-sync path
			// shipped a DEFAULTED live match: `byte-offset 999` became offset 0,
			// an unparseable `match-value` became 0, and a non-{layer-3,layer-4}
			// `match-start` was evaluated at the L3 base. A discard term then
			// enforced "the first bytes at offset 0 equal zero" instead of the
			// pattern the operator wrote -- dropping traffic it should not and
			// admitting the traffic it was written to drop.
			//
			// The nftables sibling has always checked BOTH conditions
			// (daemon_nft.go:2248, daemon_nft_netlink.go:231); only this path
			// checked one. Same defect class as the multi-range case above and
			// the same remedy, so it reuses the channel rather than adding one.
			slog.Warn("firewall filter term has an unrepresentable flexible-match-range; "+
				"poisoning the term to match nothing (fail-closed) until the config is corrected",
				"filter_term", term.Name,
				"ranges", strings.Join(term.FlexMatchRangeNames, ","),
				"unrepresentable", strings.Join(term.UnknownFlexMatch, ","),
				"issue", "#5823/#9020")
			snap.FlexMatch = &FlexMatchSnapshot{
				Offset:     0,
				Length:     1,
				Value:      0,
				Mask:       0,
				MatchStart: flexMatchStartUnrepresentable,
			}
		} else if fm := term.FlexMatch; fm != nil {
			// #3203: round UP to whole bytes so a non-multiple-of-8 bit length
			// (e.g. 12 bits -> 2 bytes) reads enough bytes to cover the field.
			// Integer truncation (BitLength/8) gave 1 byte for 12 bits, dropping
			// the partial trailing byte so the match always failed closed. The
			// Go compiler's default mask zeroes the extra bits within the ceil
			// byte, so the matcher's (read & mask) == value comparison stays
			// correct for a sub-byte field.
			length := (int(fm.BitLength) + 7) / 8
			if length == 0 {
				length = 4 // default 32-bit, matching compiler_filter.go
			}
			// #3406: do NOT cap an oversized width to 4. The commit gate bounds
			// bit-length to 1..32 (validateFilterFlexMatchStrict), so ceil(bits/8) is
			// always 1..4 for a committed config; a length > 4 can only arrive via a
			// corrupt / hand-built / version-drifted snapshot (BitLength is a u8, so
			// the max possible is ceil(255/8) = 32 — no uint8 overflow below).
			// Capping it to 4 and still emitting the term compared only the truncated
			// 4-byte window, BROADENING the match (fail-open). Carry the real width so
			// the Rust filter compiler raises
			// SnapshotIntegrityError::UnrepresentableFilterFlexMatch and rejects the
			// whole snapshot instead.
			// #3232: carry the match-start base. layer-3 (default) maps to ""
			// so the wire stays byte-identical for every pre-#3232 term
			// (omitempty); only an explicit layer-4 emits a value. The compiler
			// has already rejected payload/unknown at commit, so MatchStart is
			// only ever "layer-3" or "layer-4" here.
			matchStart := ""
			if fm.MatchStart == "layer-4" {
				matchStart = "layer-4"
			}
			snap.FlexMatch = &FlexMatchSnapshot{
				Offset:     fm.ByteOffset,
				Length:     uint8(length),
				Value:      fm.Value & fm.Mask,
				Mask:       fm.Mask,
				MatchStart: matchStart,
			}
		}
		terms = append(terms, snap)
	}
	return terms
}

// resolvePrefixListAddrs merges a firewall-filter term's literal source/dest
// address CIDRs with the prefixes resolved from its source/destination
// prefix-list references (#2506). It returns the combined CIDR list, a
// per-direction `except` (inversion) flag, and a `constrained` flag.
//
// `constrained` is TRUE whenever the term SPECIFIED any scope for this
// direction — at least one literal address OR at least one prefix-list
// reference — INDEPENDENT of whether resolution yielded any prefixes. This is
// the load-bearing signal for the empty-resolution case (Copilot, this PR): a
// `source-prefix-list X` whose X is defined-but-empty (passes the strict gate)
// OR unresolved on the lenient/peer-sync path resolves to ZERO prefixes. If the
// matcher derived "constrained" from the list length alone, an empty list would
// collapse to match-ANY and silently drop the operator's scope (fail-open for
// `accept`/PBR, wrong scope for `discard`). Carrying `constrained` explicitly
// lets the matcher distinguish "no scope specified -> match any" from "scope
// specified but resolved empty -> match per Junos empty-set semantics".
//
// Semantics (Junos), realized in the Rust matcher (nets_match_v4/v6):
//   - A plain `source-prefix-list NAME` reference contributes NAME's prefixes
//     to the term's positive match set, OR'd with any literal source-address
//     entries — a packet matches the direction if its address falls in ANY of
//     them. NAME empty -> "match sources in {}" = match NOTHING (fail-closed).
//   - `source-prefix-list NAME except` means "match every source EXCEPT those
//     in NAME". Represented as the expanded prefixes plus `except=true`; the
//     matcher evaluates `(addr ∈ prefixes) XOR except`. NAME empty -> "match
//     sources NOT in {}" = match ALL.
//
// Scope (this PR): the two clean, common cases are wired through —
//  1. positive prefix-lists (with or without literal addresses), and
//  2. an `except` prefix-list as the SOLE address source for the direction.
//
// The MIXED case — literal/positive addresses AND an `except` prefix-list in
// the SAME direction of ONE term — has no single boolean-inversion
// representation (one direction would need both a positive set and a negated
// set). This shape is hard-rejected at commit by
// config.validateFilterAddressExceptStrict (#3359); it reaches here only on the
// tolerant load / peer-sync path (an already-persisted or peer-synced config —
// #1960 no-brick). The resolution is POSITIVE-WINS: the except prefixes are
// IGNORED (never folded into the positive set) and a warning is emitted. The
// earlier behavior folded the except prefixes INTO the positive set, which was
// fail-OPEN: a `discard`/`reject` term then no longer dropped the traffic the
// operator carved out via `except`, and an `accept` term ADMITTED the prefixes
// the operator wrote to exclude. Positive-wins keeps an `accept` term's admit
// set no wider than the operator's positive scope and keeps a `discard`/`reject`
// term dropping at least the positive set — fail-safe in both directions.
// Sibling of the #3297 port-except positive-wins fallback. The faithful
// structured representation (a positive set AND a negated set per direction) is
// a documented follow-up.
//
// An undefined prefix-list reference is NOT silently dropped here — it is a
// strict commit-time error (validateFirewallPrefixListReferencesStrict, #1960
// strict/lenient pattern). On the tolerant load / peer-sync path that gate
// downgrades to a warning and an unresolved reference contributes no prefixes;
// because the reference still makes the direction `constrained`, the matcher
// fails closed (positive) / match-all (except) per the empty-set semantics
// above rather than collapsing to match-any.
//
// `action` is the term's terminating action ("accept"/"discard"/"reject"/"").
// It only affects the #5225 action-aware fail-closed lowering of an UNRESOLVED
// positive prefix-list ref combined with an `except` ref (see
// ResolveFilterPrefixListAddrs); every other shape is action-independent.
func resolvePrefixListAddrs(
	literal []string,
	refs []config.PrefixListRef,
	cfg *config.Config,
	filterName, termName, direction, action string,
) (addrs []string, except bool, constrained bool) {
	var prefixLists map[string]*config.PrefixList
	if cfg != nil {
		prefixLists = cfg.PolicyOptions.PrefixLists
	}
	return ResolveFilterPrefixListAddrs(literal, refs, prefixLists, filterName, termName, direction, action)
}

// filterAddrIsReal mirrors the Rust matcher's addr_is_real (userspace-dp
// filter/compiler.rs): the empty string and the literal "any" are NO-CONSTRAINT
// placeholders that parse_address drops, so they must NOT make a direction
// address-constrained. Otherwise a `from source-address any` would fail closed
// (constrained + empty-positive = match NOTHING) instead of the Junos match-ALL,
// a control-plane lockout risk on the lo0 host filter (#3433 H01).
func filterAddrIsReal(a string) bool { return a != "" && a != "any" }

// addrsAllMatchAny reports whether EVERY entry of a positive address list is the
// match-any universe — an empty list, or only `0.0.0.0/0` / `::/0` CIDRs. It
// backs the #4338 "any except X" compose in ResolveFilterPrefixListAddrs: a
// positive set that is nothing but the universe, alongside an `except`
// prefix-list, reduces to the sole-`except` representation ("any addr not in X").
// A single SPECIFIC positive entry makes it false, so the mixed
// specific-positive + except term falls through to the fail-safe positive-wins
// path instead. An unparseable entry makes it false too (treated as specific) so
// a malformed literal never widens the term to match-all.
func addrsAllMatchAny(addrs []string) bool {
	for _, a := range addrs {
		if a == "" || a == "any" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(a)
		if err != nil {
			return false
		}
		if ones, _ := ipnet.Mask.Size(); ones != 0 {
			return false
		}
	}
	return true
}

// portsHaveReal reports whether a port-match list carries at least one real
// (non-empty) entry, mirroring the Rust matcher's port_is_real
// (userspace-dp/src/filter/compiler.rs). It backs the #3406 mixed positive +
// `*-port-except` warning: the Rust compiler resolves a mixed direction
// positive-wins (the except side is dropped), so the Go builder surfaces the
// drop only when BOTH sides actually carry a real port.
func portsHaveReal(ports []string) bool {
	for _, p := range ports {
		if p != "" {
			return true
		}
	}
	return false
}

// firewallFilterActionDenies reports whether a firewall-filter term's terminating
// action DROPS the packet — Junos `discard` (silent drop) or `reject` (drop with
// an ICMP/TCP-RST notification). It gates the #5225 action-aware fail-closed
// lowering of an UNRESOLVED positive prefix-list ref combined with an `except`
// ref (ResolveFilterPrefixListAddrs): a deny term fails closed by matching ALL
// (drop broadly, so a later permit cannot leak the traffic the deny was written
// to stop); every other action — `accept`, a routing-instance (PBR) redirect, or
// a modifier-only fall-through (Action == "") — fails closed by matching NOTHING,
// because an unresolvable positive scope must never be admitted, redirected, or
// counted as a match. The action strings match FirewallFilterTerm.Action /
// FirewallTermSnapshot.Action ("accept"/"discard"/"reject"/"").
func firewallFilterActionDenies(action string) bool {
	return action == "discard" || action == "reject"
}

// ResolveFilterPrefixListAddrs is the SHARED single source of truth for lowering
// a firewall-filter term's source/destination address + prefix-list scope into
// the (addrs, except, constrained) triple the matcher consumes. It is exported so
// the daemon lo0 kernel-nft mirror (pkg/daemon/daemon_nft.go) lowers addresses
// with EXACTLY these semantics — empty-positive, empty-except, positive-wins on a
// mixed term, and `any`-as-no-constraint — instead of a divergent raw string
// concatenation (#3433). resolvePrefixListAddrs delegates here; see the doc on
// resolvePrefixListAddrs for the full empty-set / except / mixed semantics.
// `action` is the term's terminating action ("accept"/"discard"/"reject"/"").
// It participates in exactly ONE decision: the #5225 action-aware fail-closed
// lowering of an UNRESOLVED positive prefix-list ref combined with an `except`
// ref (see the compose gate below). Every other shape is action-independent, so
// callers that do not care (or lack an action) may pass "".
func ResolveFilterPrefixListAddrs(
	literal []string,
	refs []config.PrefixListRef,
	prefixLists map[string]*config.PrefixList,
	filterName, termName, direction, action string,
) (addrs []string, except bool, constrained bool) {
	// Drop the no-constraint placeholders ("any" / empty) from the literal list
	// BEFORE deciding `constrained` so a bare `from source-address any` is
	// unconstrained (match-ALL), matching the Rust matcher (addr_is_real /
	// parse_address) and Junos. A real literal alongside `any` keeps its scope —
	// `[ any 10/8 ]` matches 10/8 (the `any` is ignored), unchanged from the Rust
	// behavior where parse_address drops only the `any` token.
	realLiteral := make([]string, 0, len(literal))
	for _, a := range literal {
		if filterAddrIsReal(a) {
			realLiteral = append(realLiteral, a)
		}
	}

	// The direction is constrained iff the operator wrote ANY real scope for it —
	// a real literal address or a prefix-list reference — regardless of
	// resolution. A prefix-list reference ALWAYS constrains (even when it resolves
	// empty / is unresolved on the lenient path), so the matcher fails closed.
	constrained = len(realLiteral) > 0 || len(refs) > 0

	if len(refs) == 0 {
		// No prefix-lists: copy the real literal addresses verbatim (never share
		// the term's backing slice).
		if len(realLiteral) == 0 {
			return nil, false, false
		}
		out := make([]string, len(realLiteral))
		copy(out, realLiteral)
		return out, false, true
	}

	var positive []string
	positive = append(positive, realLiteral...)
	var exceptPrefixes []string
	hasExcept := false
	hasPositiveRef := false
	// hasUnresolvedPositiveRef records that a PLAIN (non-except) prefix-list ref
	// failed to resolve (pl == nil) on the tolerant path. It is distinct from
	// hasPositiveRef (a RESOLVED positive ref): an unresolved positive ref
	// contributes no prefixes to `positive`, so the direction can LOOK match-any
	// (empty positive) while the operator actually scoped it to a specific,
	// now-unresolvable set. The #5225 compose gate uses this to refuse the
	// "any except X" widening for that direction. (#5225)
	hasUnresolvedPositiveRef := false

	for _, ref := range refs {
		pl := prefixLists[ref.Name]
		if pl == nil {
			// Undefined reference. The strict gate rejects this at commit; on
			// the tolerant path it is a warning and we contribute no prefixes
			// for it — but the direction stays `constrained` (set above), so the
			// matcher fails closed rather than matching any.
			//
			// #5097: still record the reference's POLARITY before skipping it.
			// An unresolved `except` ref contributes no prefixes but MUST set
			// hasExcept so a SOLE unresolved except lowers to the empty-set
			// complement (nil, true, true) = "match every address NOT in {}" =
			// match ALL, exactly like the resolved-but-empty except case below.
			// The pre-#5097 `continue` skipped this before the ref.Except check,
			// so hasExcept stayed false and a sole unresolved except collapsed to
			// (nil, false, true) = match NOTHING — which turned a `discard`/
			// `reject` term into a no-op on the tolerant/peer-sync path (the deny
			// matched no packet and traffic fell through to a later permit), a
			// fail-OPEN for the deny it was written to enforce. Recording
			// hasExcept keeps the empty except set matching broadly (fail
			// CLOSED). A positive ref contributes no prefixes: an unresolved
			// positive scope with NO accompanying except correctly lowers to
			// (nil, false, true) = match NOTHING, already fail-closed for positive
			// membership.
			//
			// #5225: record an unresolved POSITIVE ref so the compose gate below
			// can tell a genuine match-any positive (`0.0.0.0/0`, empty literal)
			// apart from a positive set that is empty ONLY because a positive ref
			// did not resolve. Without this the ref's absence from `positive` let
			// addrsAllMatchAny return true and the `hasExcept` set (recorded above
			// or by a sibling except ref) fired the "any except X" compose, which
			// lowered the direction to match-ALL. For an `accept` term that is
			// admit-ALL = fail-OPEN — the term admitted every packet instead of the
			// intended (unresolvable, so empty) set.
			slog.Warn("firewall filter prefix-list reference unresolved",
				"filter", filterName, "term", termName, "direction", direction,
				"prefix-list", ref.Name)
			if ref.Except {
				hasExcept = true
			} else {
				hasUnresolvedPositiveRef = true
			}
			continue
		}
		if ref.Except {
			hasExcept = true
			exceptPrefixes = append(exceptPrefixes, pl.Prefixes...)
		} else {
			hasPositiveRef = true
			positive = append(positive, pl.Prefixes...)
		}
	}

	// Clean except case: an `except` prefix-list is the sole address source for
	// this direction (no literal addresses, no positive prefix-lists). Note this
	// holds even when the except list resolved EMPTY — the direction is
	// constrained and except is set, so the matcher's empty guard returns
	// `except` (= match ALL), the Junos "not in {}" semantic.
	//
	// #4338: a match-any positive literal (`0.0.0.0/0` / `::/0`) alongside an
	// `except` prefix-list (and NO positive prefix-list) is the canonical Junos
	// "match any EXCEPT the listed prefixes" lockdown idiom. The match-any is the
	// universe, so `any AND NOT X` reduces to the sole-`except` case: DROP the
	// redundant match-any from the positive set and emit the term as `except`
	// over X. Without this the term below folds positive-wins (match-any wins →
	// the term matches ALL, never excluding X) — a fail-OPEN that defeats the
	// lockdown. config.validateFilterAddressExceptStrict accepts this exact shape
	// (#4338); a SPECIFIC positive literal + except is still rejected at commit
	// and only reaches here on the lenient path, where positive-wins keeps it
	// fail-safe.
	if hasExcept && !hasPositiveRef && addrsAllMatchAny(positive) {
		// #5225: an UNRESOLVED positive prefix-list ref makes `positive` empty
		// WITHOUT the operator having written the match-any universe — the empty
		// set here is "a specific scope that did not resolve", NOT "any". The
		// #4338 "any except X" compose (invert the empty positive to match-ALL)
		// must NOT apply to it. Fail closed BY ACTION so the term never widens
		// past the operator's (now unresolvable) intent:
		//   - accept (and every non-deny terminating / fall-through / PBR action):
		//     match NOTHING. Admitting, redirecting, or counting an unresolvable
		//     positive set is fail-OPEN. Pre-#5225 this composed to match-ALL =
		//     ADMIT every packet — the reported defect.
		//   - discard/reject: match ALL (the sole-`except` complement, unchanged
		//     from the #4338/#5097 path) so the deny still drops broadly; a deny
		//     that matched nothing would fall through to a later permit term =
		//     fail-OPEN for the deny it was written to enforce (the #5097 concern).
		// Only the unresolved-positive-ref case is action-gated; a genuine
		// match-any positive (no unresolved positive ref) keeps the #4338/#5097
		// match-ALL compose verbatim for all actions.
		if hasUnresolvedPositiveRef && !firewallFilterActionDenies(action) {
			return nil, false, true
		}
		return exceptPrefixes, true, true
	}

	if hasExcept {
		// Mixed positive + except in one direction — out of scope for the
		// boolean-inversion model (one direction would need both a positive set
		// and a negated set). This shape is hard-rejected at commit by
		// validateFilterAddressExceptStrict (#3359); it only reaches here on the
		// tolerant load / peer-sync path (an already-persisted or peer-synced
		// config — #1960 no-brick). POSITIVE-WINS: ignore the except prefixes
		// entirely (do NOT fold them in) and warn so the operator splits the
		// term. The earlier fold (`positive = append(positive, exceptPrefixes)`)
		// was fail-OPEN: it widened the match by treating the excepted prefixes
		// as a positive match, so a `discard`/`reject` term no longer dropped
		// the traffic the operator carved out via `except`, and an `accept` term
		// ADMITTED the prefixes the operator wrote to exclude. Dropping the
		// except side instead keeps an `accept` term's admit set no wider than
		// the operator's positive scope and keeps a `discard`/`reject` term
		// dropping at least the positive set — fail-safe in both directions.
		// Sibling of the #3297 port-except positive-wins fallback.
		slog.Warn("firewall filter term mixes literal/positive addresses with an "+
			"except prefix-list in one direction; the except modifier is ignored "+
			"(positive-wins — the except prefixes are NOT matched). Split into "+
			"separate terms (commit rejects this shape, #3359).",
			"filter", filterName, "term", termName, "direction", direction)
	}

	// `positive` may be empty here (e.g. a positive prefix-list that resolved to
	// no prefixes, or an unresolved positive ref). The direction is still
	// constrained, so the matcher fails closed (matches nothing) rather than
	// matching any.
	return positive, false, true
}

func buildPolicerSnapshots(cfg *config.Config) []PolicerSnapshot {
	if cfg == nil || len(cfg.Firewall.Policers) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Firewall.Policers))
	for name := range cfg.Firewall.Policers {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]PolicerSnapshot, 0, len(names))
	for _, name := range names {
		pol := cfg.Firewall.Policers[name]
		if pol == nil {
			continue
		}
		snap := PolicerSnapshot{
			Name: name,
			// #8429: pol.BandwidthLimit is BYTES per second —
			// parseBandwidthLimit is literally `parseScaledDecimalUnit(s) / 8`.
			// The wire field is bits per second and the helper divides by 8
			// again (`filter/compiler.rs`, committed_rate_bytes_per_sec), so
			// shipping the byte value straight across enforced ONE EIGHTH of
			// the configured rate: `bandwidth-limit 8m` metered at 1 Mbit/s.
			//
			// With `then discard` that drops conforming customer traffic and
			// the policer counters attribute it to the customer, so the surface
			// an operator checks confirms the wrong story.
			//
			// Converted HERE rather than by removing the helper's divisor,
			// because this is the only leg that crosses units. The three-color
			// leg below parses through the SAME function and is correct — it
			// emits into `committed_rate_bytes_per_sec`, a byte-NAMED field the
			// helper does not re-divide — and the eBPF leg
			// (`dataplane/compiler_filter.go`, RateBytesSec) is byte-named too.
			// Changing parseBandwidthLimit would break both.
			//
			// Cannot overflow: the value is `scaled/8` for a `scaled` that
			// already fit a uint64, so multiplying back is bounded by it.
			BandwidthBps: pol.BandwidthLimit * 8,
			BurstBytes:   pol.BurstSizeLimit,
		}
		if pol.ThenAction == "discard" {
			snap.DiscardExcess = true
		}
		out = append(out, snap)
	}
	return out
}

func buildThreeColorPolicerSnapshots(cfg *config.Config) []ThreeColorPolicerSnapshot {
	if cfg == nil || len(cfg.Firewall.ThreeColorPolicers) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Firewall.ThreeColorPolicers))
	for name := range cfg.Firewall.ThreeColorPolicers {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]ThreeColorPolicerSnapshot, 0, len(names))
	for _, name := range names {
		pol := cfg.Firewall.ThreeColorPolicers[name]
		if pol == nil {
			continue
		}
		mode := "single-rate"
		peakOrExcessRate := uint64(0)
		if pol.TwoRate {
			mode = "two-rate"
			peakOrExcessRate = pol.PIR
		}
		out = append(out, ThreeColorPolicerSnapshot{
			Name:                   name,
			Mode:                   mode,
			ColorBlind:             pol.ColorBlind,
			CommittedRateBytes:     pol.CIR,
			CommittedBurstBytes:    pol.CBS,
			PeakOrExcessRateBytes:  peakOrExcessRate,
			PeakOrExcessBurstBytes: pol.PBS,
			ThenAction:             pol.ThenAction,
		})
	}
	return out
}
