package config

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// defaultPoolAlarmHysteresis is the gap, in utilization percentage points,
// placed below the raise-threshold when an operator configures a raise-only
// pool-utilization-alarm (no explicit clear-threshold). A 10-point gap gives
// the alarm state machine hysteresis so it does not flap around the raise
// boundary, and keeps the defaulted clear inside the valid 1..raise-1 band for
// every realistic raise (>= 2). Junos allows a raise-only alarm; xpf mirrors
// that by synthesizing this clear rather than requiring the operator to name
// one (#4077).
const defaultPoolAlarmHysteresis = 10

// defaultPoolAlarmClearThreshold returns the clear-threshold to use when the
// operator supplied only a raise-threshold. It is raise minus a fixed
// hysteresis margin, floored at 1 so it stays a valid percentage. For raise >=
// 2 the result is strictly less than raise (0 < clear < raise), so it passes
// the commit gate and enables the runtime alarm; e.g. raise 90 -> clear 80,
// raise 50 -> clear 40, raise 5 -> clear 1.
func defaultPoolAlarmClearThreshold(raise int) int {
	clear := raise - defaultPoolAlarmHysteresis
	if clear < 1 {
		clear = 1
	}
	return clear
}

// validatePoolUtilizationAlarm is the #2079 strict-vs-lenient gate for the
// `security nat source pool-utilization-alarm raise-threshold/clear-threshold`
// thresholds. Junos requires only raise-threshold; clear-threshold is optional
// and, when omitted, is defaulted at parse time to a hysteresis margin below
// raise (defaultPoolAlarmClearThreshold, #4077) so a raise-only alarm both
// commits and runs. This gate therefore only ever sees a zero/invalid
// clear-threshold when the operator EXPLICITLY provided one. A bare
// `pool-utilization-alarm;` compiles to raise=0/clear=0 (an always-firing
// alarm) and inverted/equal thresholds make hysteresis meaningless. Strict
// (commit / commit-check): hard-reject. Lenient (load / peer-sync, #1979
// doctrine): return the message as a warning so a config committed before this
// gate existed still boots (#1960 fail-closed-on-compile-failure would
// otherwise brick the daemon on restart). The runtime monitor treats raise<=0
// as disabled, so a leniently loaded bad config is inert, not always-firing.
func validatePoolUtilizationAlarm(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	a := cfg.Security.NAT.PoolUtilizationAlarm
	if a == nil {
		return nil, nil
	}
	var msg string
	switch {
	case a.RaiseThreshold <= 0 || a.RaiseThreshold > 100:
		msg = fmt.Sprintf("pool-utilization-alarm: raise-threshold must be in 1..100, got %d", a.RaiseThreshold)
	case a.ClearThreshold <= 0 || a.ClearThreshold >= a.RaiseThreshold:
		msg = fmt.Sprintf("pool-utilization-alarm: clear-threshold must be in 1..raise-threshold-1 (0 < clear < raise), got clear=%d raise=%d", a.ClearThreshold, a.RaiseThreshold)
	default:
		return nil, nil
	}
	if lenient {
		return []string{msg + " (ignored: alarm disabled until corrected)"}, nil
	}
	return nil, fmt.Errorf("%s", msg)
}

// natAddrFamily classifies an IP-part string the way the Rust parsers do,
// so the Go commit gate and the dataplane agree on every input.
//
//   - kind "v4": parses as IPv4 AND is textually a dotted-quad (no colon) —
//     i.e. exactly what Rust `Ipv4Addr::from_str` / `IpAddr::V4` accept.
//   - kind "v6": parses as IPv6 (textually colon-bearing) — what Rust
//     `IpAddr::V6` represents.
//   - kind "": does not parse as an IP at all (e.g. an address-book name);
//     NOT this validator's concern.
//
// The colon test is load-bearing: Go's net.ParseIP("::ffff:1.2.3.4").To4()
// is NON-nil (Go folds the IPv4-mapped form), but Rust `Ipv4Addr::from_str`
// REJECTS it and `IpAddr::from_str` classifies it as V6. Keying the family
// on text (no colon == v4) reproduces the Rust classification exactly, so a
// mapped form is treated as IPv6 here too — never accepted as a v4 host that
// the dataplane would then silently drop.
func natAddrFamily(ipPart string) string {
	if net.ParseIP(ipPart) == nil {
		return ""
	}
	if strings.IndexByte(ipPart, ':') >= 0 {
		return "v6"
	}
	return "v4"
}

// natCIDRIPPart returns the address portion of a CIDR string (everything before
// the first '/'), or the whole string if it carries no mask. It exists so the
// textual natAddrFamily classification can be applied to the ORIGINAL config
// text rather than a parsed net.IP — net.ParseCIDR/ParseIP folds an
// IPv4-mapped IPv6 literal (::ffff:1.2.3.4) into a 4-byte form whose .To4() is
// non-nil, which diverges from Rust's Ipv6Addr::from_str (it keeps the literal
// as V6). Keying the family on the un-parsed text preserves Go<->Rust parity.
func natCIDRIPPart(cidr string) string {
	if slash := strings.IndexByte(cidr, '/'); slash >= 0 {
		return cidr[:slash]
	}
	return cidr
}

// isHostMaskAddress reports whether addr is a host route the static-NAT
// dataplane can install: a bare IP (no mask) or the canonical host mask
// (/32 for IPv4, /128 for IPv6). It mirrors EXACTLY the Rust host-mask gate
// added in PR #2167 for static NAT (parse_nat_addr in
// userspace-dp/src/nat/static_nat.rs): static NAT is a strictly 1:1 host
// mapping, so a non-host mask carries no representable meaning. The family
// (hence the required mask) is keyed on natAddrFamily so an IPv4-mapped
// IPv6 literal is classified the SAME as Rust (V6, host_len 128). The
// second return value reports whether addr parsed as an IP at all; a non-IP
// token (e.g. an address-book name) is NOT this validator's concern and is
// left to the existing address handling.
//
// NOTE: NAT64 source-pool addresses use isNAT64PoolHostAddress, NOT this
// predicate — the Rust parse_pool_v4 (nat64.rs) is IPv4-ONLY (the pool
// translates to IPv4 source addresses), so an IPv6 pool entry that this
// predicate would accept (its /128 host form) is silently dropped there.
func isHostMaskAddress(addr string) (host bool, parsed bool) {
	slash := strings.IndexByte(addr, '/')
	ipPart := addr
	if slash >= 0 {
		ipPart = addr[:slash]
	}
	fam := natAddrFamily(ipPart)
	if fam == "" {
		return false, false
	}
	if slash < 0 {
		// Bare address — a host in both families.
		return true, true
	}
	maskPart := addr[slash+1:]
	wantMask := "128"
	if fam == "v4" {
		wantMask = "32"
	}
	return maskPart == wantMask, true
}

// natStaticPrefixInfo classifies a static-NAT address the way the Rust
// parse_nat_prefix (static_nat.rs, #3031) does: it returns the family, the
// prefix length, whether the value is a host route, and whether it parsed as
// an IP at all. A bare address is a host route (len == max). A `/N` mask is
// parsed numerically; bits < 0 flags a malformed/out-of-range mask (a
// non-numeric or `/33`/`/129` suffix) so the caller leaves the existing
// host-route rejection to fire. A non-IP token (address-book name) returns
// parsedIP == false and is not this validator's concern.
func natStaticPrefixInfo(addr string) (fam string, bits int, isHost, parsedIP bool) {
	slash := strings.IndexByte(addr, '/')
	ipPart := addr
	if slash >= 0 {
		ipPart = addr[:slash]
	}
	fam = natAddrFamily(ipPart)
	if fam == "" {
		return "", -1, false, false
	}
	max := 128
	if fam == "v4" {
		max = 32
	}
	if slash < 0 {
		return fam, max, true, true
	}
	n, err := strconv.Atoi(addr[slash+1:])
	if err != nil || n < 0 || n > max {
		return fam, -1, false, true
	}
	return fam, n, n == max, true
}

// isStaticBlockPair reports whether (match, then) is a valid block-to-block
// (subnet) static-NAT 1:1 mapping (#3031): both sides parse as IPs, both are
// non-host prefixes of the SAME family with EQUAL prefix length. The Rust
// dataplane installs exactly this case (offset-preserving remap); a
// host-vs-block, mismatched-length, mixed-family, or malformed-mask pair is
// NOT a block pair and falls through to the existing host-route rejection.
func isStaticBlockPair(match, then string) bool {
	mf, mb, mh, mp := natStaticPrefixInfo(match)
	tf, tb, th, tp := natStaticPrefixInfo(then)
	if !mp || !tp {
		return false // a non-IP token — leave to existing handling
	}
	if mh || th || mb < 0 || tb < 0 {
		return false // a host side or a malformed mask — not a block pair
	}
	return mf == tf && mb == tb
}

// isNAT64PoolHostAddress reports whether addr is an IPv4 host route the
// NAT64 source pool can install. It mirrors EXACTLY the Rust parse_pool_v4
// gate (userspace-dp/src/nat64.rs): the NAT64 pool holds IPv4 source
// addresses, so it accepts ONLY a bare IPv4 address or an IPv4 /32 — an
// IPv6 address (bare or any mask, INCLUDING the IPv4-mapped ::ffff:x.x.x.x
// form that Ipv4Addr::from_str rejects) and a non-host IPv4 mask are all
// silently dropped by parse_pool_v4, so the commit gate must reject them
// too or the gate and the dataplane disagree. Family is keyed on
// natAddrFamily (textual, colon == v6) to match Ipv4Addr::from_str. The
// second return value reports whether addr parsed as an IP at all (so a
// non-IP address-book token is left to existing handling); a parseable
// non-IPv4 address returns (host=false, parsed=true) — it parsed, but is
// not an installable pool address.
func isNAT64PoolHostAddress(addr string) (host bool, parsed bool) {
	slash := strings.IndexByte(addr, '/')
	ipPart := addr
	if slash >= 0 {
		ipPart = addr[:slash]
	}
	fam := natAddrFamily(ipPart)
	if fam == "" {
		return false, false
	}
	if fam != "v4" {
		// Parsed, but not an IPv4 pool address — reject (parse_pool_v4 drops).
		return false, true
	}
	if slash < 0 {
		return true, true
	}
	// Only an IPv4 /32 is an installable pool host address.
	return addr[slash+1:] == "32", true
}

// nptv6PrefixHasHostBits reports whether the CIDR text `cidr` carries any
// bit set beyond its prefix length — i.e. the raw address is not equal to
// its own network (masked) address. `parsed` is the *net.IPNet returned by
// net.ParseCIDR(cidr) (its .IP is already masked); the comparison parses the
// raw IP part of the original text and re-masks it under the same mask. The
// second return value is false when the raw IP cannot be parsed (the caller
// has already proven cidr parses via ParseCIDR, so this is defensive only).
// #2380: net.ParseCIDR silently masks, so this surfaces the discarded bits.
func nptv6PrefixHasHostBits(cidr string, parsed *net.IPNet) (host bool, ok bool) {
	if parsed == nil {
		return false, false
	}
	raw := net.ParseIP(natCIDRIPPart(cidr))
	if raw == nil {
		return false, false
	}
	// Mask the raw address with the prefix's mask and compare to the raw
	// address. If they differ, host/subnet bits were set beyond the prefix.
	masked := raw.Mask(parsed.Mask)
	if masked == nil {
		// Mask width does not match the address family — should not happen
		// for an IPv6 prefix that already parsed, but treat as no host bits.
		return false, true
	}
	return !masked.Equal(raw), true
}

// validateNATHostMaskStrict is the #2173 strict-vs-lenient gate that
// rejects a static-NAT match/prefix or a NAT64 source-pool address whose
// mask is not a host route (/32 for v4, /128 for v6; a bare address is a
// host too). #2132 made the Rust dataplane TOLERATE the canonical host
// mask, and PR #2167 then hardened the Rust parser to REJECT a non-host
// mask — so today a misconfigured /24 static-NAT match or pool address is
// SILENTLY DROPPED at the dataplane (the rule is parsed-out, never
// installed) with no operator feedback. This commit-time check surfaces
// the misconfiguration at `commit`/`commit check` instead.
//
// Scope mirrors what the Rust host-mask gate covers:
//   - static-NAT rules' `match destination-address` (-> ExternalIP) and
//     `then static-nat prefix` (-> InternalIP). NPTv6 (`nptv6-prefix`) and
//     NAT64 (`static-nat inet`) rules are EXEMPT: NPTv6 is a genuine prefix
//     translation (RFC 6296), and an `inet` rule's match is the NAT64
//     well-known prefix (e.g. 64:ff9b::/96) with translation driven by the
//     separate NAT64 snapshot, not the static_nat table.
//   - NAT64 source-pool addresses (the IPv4 pool referenced by a
//     `nat64 rule-set ... source-pool` — parse_pool_v4 host-mask gate).
//
// Strict (commit / commit-check): hard-reject. Lenient (load / peer-sync,
// #1960 / #1979 doctrine): return the message as a warning so a config
// committed before this gate existed still boots (fail-closed-on-compile-
// failure would otherwise brick the daemon on restart); the dataplane
// independently drops the bad entry, so a leniently-loaded config is
// already inert for that rule, not mis-installed.
func validateNATHostMaskStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	// emitSuffix returns a violation as an error (strict) or appends it to the
	// lenient warning list with a dataplane-effect suffix. The suffix differs
	// by case: a static-NAT IP failure drops the WHOLE rule (parse_nat_addr
	// returns None for the rule's match/then), whereas a NAT64 source-pool
	// entry is dropped individually by filter_map(parse_pool_v4) — the rest of
	// the pool/rule stays installed. Keep the load-path text precise so the
	// operator does not over-read the impact.
	emitSuffix := func(msg, suffix string) error {
		if lenient {
			warnings = append(warnings, msg+suffix)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	emit := func(msg string) error {
		return emitSuffix(msg, " (ignored: rule dropped by dataplane until corrected)")
	}

	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.IsNPTv6 {
				continue
			}
			// `then static-nat inet` is a NAT64 translation, not host-1:1
			// static NAT: its `match destination-address` is the NAT64
			// well-known prefix (e.g. 64:ff9b::/96, a legitimate non-host
			// prefix) and the actual translation is driven by the separate
			// NAT64 snapshot (buildNAT64Snapshots), not the static_nat table
			// (the inet rule's static_nat snapshot entry is expected to be a
			// no-op the Rust parse drops). Exempt the whole rule.
			if rule.Then == "inet" {
				continue
			}
			// #3206: a `match destination-address` / `then static-nat
			// prefix` that is not a parseable literal IP or CIDR (an
			// address-book name, or a typo'd prefix) is NOT caught by the
			// host-mask check below — that check fires only when the value
			// parses (`parsed && !host`). An unparseable value falls all the
			// way through to the Rust dataplane, where `parse_nat_prefix`
			// returns None and `from_snapshots` does `continue`, SILENTLY
			// dropping the entire static-NAT mapping with no commit error or
			// runtime feedback (the operator authored a rule that simply does
			// not exist at runtime). Static NAT takes literal IP/CIDR
			// endpoints, not address-book references, so reject an
			// unparseable value at commit. `natStaticPrefixInfo` mirrors the
			// Rust `parse_nat_prefix` classification; its `parsedIP == false`
			// is precisely the silently-dropped case. Run this BEFORE the
			// blockPair / host-mask checks so an unparseable value reports its
			// own (clearer) error rather than being skipped as "not a block
			// pair".
			if rule.Match != "" {
				if _, _, _, parsedIP := natStaticPrefixInfo(rule.Match); !parsedIP {
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q match destination-address %q is not a valid IP address or CIDR prefix (static NAT requires a literal address or prefix, not an address-book name or a typo'd value)",
						rs.Name, rule.Name, rule.Match)); err != nil {
						return nil, err
					}
				}
			}
			if rule.Then != "" {
				if _, _, _, parsedIP := natStaticPrefixInfo(rule.Then); !parsedIP {
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q then static-nat prefix %q is not a valid IP address or CIDR prefix (static NAT requires a literal address or prefix, not an address-book name or a typo'd value)",
						rs.Name, rule.Name, rule.Then)); err != nil {
						return nil, err
					}
				}
			}
			// #3031: a valid block-to-block (subnet) static-NAT rule —
			// equal-length non-host prefixes of the same family — is now
			// installed by the dataplane (offset-preserving 1:1 remap), so do
			// NOT reject it as a non-host mask. Only the genuinely-invalid
			// non-host cases (host-vs-block, mismatched length, mixed family,
			// malformed mask) fall through to the host-route rejection below.
			blockPair := isStaticBlockPair(rule.Match, rule.Then)
			// #3202: a block-to-block (subnet) static-NAT rule that ALSO
			// carries a `match destination-port` or a `then static-nat
			// mapped-port` is not representable in the dataplane. The Rust
			// `StaticNatBlock` (static_nat.rs `from_snapshots`) stores only the
			// address prefixes and performs an offset-preserving, ALL-PORT 1:1
			// remap — it has no `match_dst_port`/`mapped_port` fields. So the
			// port match/mapping is SILENTLY discarded and "NAT only port 80 of
			// this /24, remap to 8080" degrades to "NAT every port of the /24"
			// (over-broad NAT / policy bypass). This also matches Junos: a
			// `static-nat prefix` is an address-only 1:1 subnet map; per-port
			// translation is a host-scope construct (`static-nat ... mapped-port`
			// on a /32). Reject the combination at strict commit-check so the
			// operator authors a host static-NAT rule for the port forward, or
			// drops the port tokens for a whole-subnet 1:1. (#3031 added the
			// address-only block map; it did not add this rejection.)
			if blockPair && (rule.MatchDestinationPort != 0 || rule.MappedPort != 0) {
				if err := emitSuffix(fmt.Sprintf(
					"security nat static rule-set %q rule %q maps a subnet (block-to-block prefix) but also specifies a port (match destination-port / then static-nat mapped-port); subnet static NAT is address-only 1:1 and the dataplane cannot translate per-port for a block, so the port mapping is silently dropped (use a /32 host match+prefix for a port forward, or drop the port tokens for a whole-subnet 1:1)",
					rs.Name, rule.Name),
					" (ignored: port mapping dropped by dataplane until corrected)"); err != nil {
					return nil, err
				}
			}
			if rule.Match != "" && !blockPair {
				if host, parsed := isHostMaskAddress(rule.Match); parsed && !host {
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q match destination-address %q must be a host route (/32 for IPv4, /128 for IPv6); a non-host mask is silently dropped by the dataplane",
						rs.Name, rule.Name, rule.Match)); err != nil {
						return nil, err
					}
				}
			}
			if rule.Then != "" && !blockPair {
				if host, parsed := isHostMaskAddress(rule.Then); parsed && !host {
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q then static-nat prefix %q must be a host route (/32 for IPv4, /128 for IPv6); a non-host mask is silently dropped by the dataplane",
						rs.Name, rule.Name, rule.Then)); err != nil {
						return nil, err
					}
				}
			}
			// #2491: port-mapped static NAT. The `mapped-port` token rides
			// inside the children:nil static-nat leaf, so the schema's
			// value-slot validator never sees it; range-check it here. An
			// out-of-range port would truncate to a wrong u16 in the snapshot,
			// so reject it. A `mapped-port` requires a matching `match
			// destination-port`: without an external port to match, the port
			// rewrite has no inbound trigger and the reverse SNAT cannot
			// recover the original port.
			if rule.MatchDestinationPort != 0 && (rule.MatchDestinationPort < 1 || rule.MatchDestinationPort > 65535) {
				if err := emitSuffix(fmt.Sprintf(
					"security nat static rule-set %q rule %q match destination-port %d is out of range (1-65535)",
					rs.Name, rule.Name, rule.MatchDestinationPort),
					" (ignored: port match dropped by dataplane until corrected)"); err != nil {
					return nil, err
				}
			}
			// #2769: a `match destination-port` WITHOUT a `then static-nat
			// mapped-port` is a port-scoped 1:1 (no port translation). The
			// dataplane scopes the reverse SNAT to that one port — but the
			// half-config is almost always an operator mistake (the intent is
			// usually a full port-forward with mapped-port). Reject it at
			// strict commit-check, mirroring the existing mapped-port-without-
			// match-port rejection below, so the operator must either drop the
			// port match (whole-address 1:1) or add a mapped-port (port
			// forward). The dataplane backstop (static_nat.rs) keeps the
			// reverse SNAT scoped to the matched port if the rule slips through
			// the lenient load / peer-sync path.
			if rule.MatchDestinationPort != 0 && rule.MappedPort == 0 {
				if err := emitSuffix(fmt.Sprintf(
					"security nat static rule-set %q rule %q match destination-port %d requires a matching `then static-nat mapped-port` (a port match without a port translation either broadens or scopes the reverse source-NAT in a non-obvious way; drop the port match for a whole-address 1:1, or add a mapped-port for a port forward)",
					rs.Name, rule.Name, rule.MatchDestinationPort),
					" (ignored: port match dropped by dataplane until corrected)"); err != nil {
					return nil, err
				}
			}
			if rule.MappedPort != 0 {
				if rule.MappedPort < 1 || rule.MappedPort > 65535 {
					if err := emitSuffix(fmt.Sprintf(
						"security nat static rule-set %q rule %q then static-nat mapped-port %d is out of range (1-65535)",
						rs.Name, rule.Name, rule.MappedPort),
						" (ignored: port translation dropped by dataplane until corrected)"); err != nil {
						return nil, err
					}
				}
				if rule.MatchDestinationPort == 0 {
					if err := emitSuffix(fmt.Sprintf(
						"security nat static rule-set %q rule %q then static-nat mapped-port %d requires a matching `match destination-port`",
						rs.Name, rule.Name, rule.MappedPort),
						" (ignored: port translation dropped by dataplane until corrected)"); err != nil {
						return nil, err
					}
				}
			}
		}
	}

	// NAT64 source-pool addresses are discrete IPv4 host source IPs: the Rust
	// parse_pool_v4 (nat64.rs) accepts ONLY a bare IPv4 or an IPv4 /32 and
	// silently drops everything else (an IPv6 address, a non-host IPv4 mask).
	// Range-expanded pool entries are always /32 by construction
	// (expandAddressRange), so only an operator-authored single
	// `pool address <X>` can trip this.
	for _, rs := range cfg.Security.NAT.NAT64 {
		if rs == nil || rs.SourcePool == "" {
			continue
		}
		pool, ok := cfg.Security.NAT.SourcePools[rs.SourcePool]
		if !ok || pool == nil {
			continue
		}
		addrs := pool.Addresses
		if pool.Address != "" {
			addrs = append([]string{pool.Address}, addrs...)
		}
		for _, a := range addrs {
			if a == "" {
				continue
			}
			if host, parsed := isNAT64PoolHostAddress(a); parsed && !host {
				if err := emitSuffix(fmt.Sprintf(
					"security nat source pool %q address %q is referenced by nat64 rule-set %q source-pool and must be an IPv4 host route (a bare IPv4 address or /32); a non-host or IPv6 address is silently dropped by the dataplane",
					pool.Name, a, rs.Name),
					" (ignored: only this pool address is dropped by the dataplane until corrected)"); err != nil {
					return nil, err
				}
			}
		}
	}

	return warnings, nil
}

// validateNPTv6Strict is the #2240/#2241 strict-vs-lenient gate for NPTv6
// (RFC 6296) static-NAT rules (`then static-nat nptv6-prefix`).
//
// #2240 (fail-closed validation): the dataplane compiler
// (`pkg/dataplane/compiler_nat.go` compileNPTv6) historically logged a warning
// and `continue`d past any per-rule validation failure (unparseable prefix,
// mismatched /48-vs-/64 lengths, an unsupported length, a non-IPv6 prefix),
// then unconditionally called `DeleteStaleNPTv6(written)` over only the VALID
// subset — so editing one previously-good rule into an invalid one TORE DOWN
// its working translation entry with no replacement installed, silently
// disabling a working translation. The Rust helper mirrored the silent skip.
// In a retired-eBPF world (#1373) the userspace helper is the enforcement
// plane, so this is a fail-OPEN regression: a typo silently changes
// reachability and source/destination identity while the commit still reports
// success. This commit-time gate surfaces the misconfiguration loudly.
//
// #2241 (overlap rejection): NPTv6 supports both /48 and /64 rules. The runtime
// resolves a match by FIRST hit in insertion order with no longest-prefix
// match, so a broad /48 configured before a nested /64 shadows the /64 and
// reordering the same rules changes the translation identity. Reject any
// overlapping pair (in either direction) so resolution is deterministic.
//
// Strict (commit / commit-check): hard-reject. Lenient (load / peer-sync, #1960
// / #1979 doctrine): return the messages as warnings so a config committed
// before this gate existed (or peer-synced) still boots. The "previous state is
// kept" impact note in the lenient warning is scoped to the userspace
// apply/preflight, not asserted as a general validator guarantee: the Rust
// helper's own #2240/#2241 backstop (`Nptv6State::try_from_snapshots`) rejects
// the whole snapshot at apply, so the apply preflight keeps the previous live
// forwarding state and a leniently-loaded bad config never installs a
// torn-down or nondeterministic NPTv6 runtime. The validator itself only
// classifies the rule as invalid; it is the helper preflight that preserves
// the prior forwarding state.
func validateNPTv6Strict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	emit := func(msg string) error {
		if lenient {
			warnings = append(warnings,
				msg+" (this NPTv6 rule is invalid; on a userspace-dataplane apply/preflight"+
					" the helper rejects the whole NPTv6 snapshot and the previous state is kept,"+
					" so the rule will not take effect until corrected)")
			return nil
		}
		return fmt.Errorf("%s", msg)
	}

	// Track already-validated prefixes per direction to reject overlaps (#2241).
	// Outbound matches on the internal prefix; inbound matches on the external
	// (match) prefix. Each direction is checked independently.
	type seenPrefix struct {
		net         *net.IPNet
		ones        int
		ruleSetName string
		ruleName    string
	}
	var internalSeen, externalSeen []seenPrefix

	// overlaps reports whether two IPv6 prefixes overlap — i.e. one contains
	// the other's network address (the shorter prefix is a prefix of the
	// longer). This covers identical /48-/48, identical /64-/64, and a /48
	// nesting a /64 (the case that makes first-match resolution order-
	// dependent).
	overlaps := func(a, b *net.IPNet) bool {
		return a.Contains(b.IP) || b.Contains(a.IP)
	}

	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || !rule.IsNPTv6 {
				continue
			}

			// External prefix = `match destination-address`. The family is
			// classified from the original CIDR text (natCIDRIPPart +
			// natAddrFamily below), not the parsed net.IP, so the parsed IP
			// values are intentionally discarded.
			_, extNet, errExt := net.ParseCIDR(rule.Match)
			// Internal prefix = `then static-nat nptv6-prefix`.
			_, intNet, errInt := net.ParseCIDR(rule.Then)

			if errExt != nil {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q match destination-address %q is not a valid IPv6 prefix for nptv6-prefix translation",
					rs.Name, rule.Name, rule.Match)); err != nil {
					return nil, err
				}
				continue
			}
			if errInt != nil {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q then static-nat nptv6-prefix %q is not a valid IPv6 prefix",
					rs.Name, rule.Name, rule.Then)); err != nil {
					return nil, err
				}
				continue
			}

			extOnes, _ := extNet.Mask.Size()
			intOnes, _ := intNet.Mask.Size()

			if extOnes != intOnes {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q nptv6 prefix lengths must match (match %q is /%d, nptv6-prefix %q is /%d)",
					rs.Name, rule.Name, rule.Match, extOnes, rule.Then, intOnes)); err != nil {
					return nil, err
				}
				continue
			}
			if extOnes != 48 && extOnes != 64 {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q nptv6 prefix length /%d is unsupported (only /48 and /64 are allowed)",
					rs.Name, rule.Name, extOnes)); err != nil {
					return nil, err
				}
				continue
			}
			// Family classification MUST be textual (natAddrFamily), not
			// net.IP.To4(): Go folds an IPv4-mapped IPv6 literal
			// (::ffff:1.2.3.4) so its parsed .To4() is non-nil, but Rust's
			// Ipv6Addr::from_str (parse_prefix in userspace-dp/src/nptv6.rs)
			// accepts the same text as a valid IPv6 address and APPLIES the
			// rule. A To4()-based check here would warn-skip on the lenient
			// load path while the dataplane installs the rule — a Go<->Rust
			// divergence (#2247 item 2). Classifying on the original text
			// (colon == v6) matches the helper exactly, so an IPv4-mapped form
			// is treated as IPv6 here too. We split the IP part off the CIDR
			// (the same idiom as isHostMaskAddress); ParseCIDR already proved
			// these parse, so a missing slash cannot happen, but the helper is
			// robust either way.
			if natAddrFamily(natCIDRIPPart(rule.Match)) != "v6" ||
				natAddrFamily(natCIDRIPPart(rule.Then)) != "v6" {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q nptv6 prefixes must be IPv6 (match %q, nptv6-prefix %q)",
					rs.Name, rule.Name, rule.Match, rule.Then)); err != nil {
					return nil, err
				}
				continue
			}

			// #2380: host-bits-zero strictness. net.ParseCIDR masks the
			// address to the prefix length silently, so a prefix with bits
			// set beyond the prefix length (e.g. 2001:db8:1:2::/48) parses
			// as a DIFFERENT prefix (2001:db8:1::/48) than the operator
			// wrote, and the Rust parse_prefix (nptv6.rs) discards the extra
			// words identically. Both planes agree on the masked result, so
			// there is no traffic-correctness bug — but the operator gets a
			// rule that does not match what they typed, with no feedback.
			// Junos rejects host bits set on a prefix; mirror that here. This
			// is the same class as isHostMaskAddress for static-NAT host
			// masks. The masked network address is extNet.IP / intNet.IP; the
			// raw address is the IP part of the original CIDR text. A mismatch
			// means host/subnet bits were set.
			if host, ok := nptv6PrefixHasHostBits(rule.Match, extNet); ok && host {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q match destination-address %q has host bits set beyond the /%d prefix (Junos rejects this; write the masked prefix explicitly)",
					rs.Name, rule.Name, rule.Match, extOnes)); err != nil {
					return nil, err
				}
				continue
			}
			if host, ok := nptv6PrefixHasHostBits(rule.Then, intNet); ok && host {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q then static-nat nptv6-prefix %q has host bits set beyond the /%d prefix (Junos rejects this; write the masked prefix explicitly)",
					rs.Name, rule.Name, rule.Then, intOnes)); err != nil {
					return nil, err
				}
				continue
			}

			// #2241: overlap rejection. Check the internal (outbound) and
			// external (inbound) prefixes independently against prior rules.
			//
			// #4339: a rule is NEVER compared against itself. A single NPTv6
			// rule in a rule-set with MULTIPLE from-scopes (`from zone A; from
			// zone B`, or several interfaces) is scope-expanded by
			// compileNATStatic into one StaticNATRuleSet entry PER scope, all
			// sharing the rule-set name AND the rule name (they are one logical
			// rule; only the from-scope differs). The seen lists span every
			// rule-set, so the second scope-expansion's prefixes matched the
			// first's exactly and the rule was reported as overlapping ITSELF —
			// blocking ANY NPTv6 mapping whose rule-set had more than one
			// from-scope. Skip the same (rule-set, rule) identity so only
			// DISTINCT rules are compared for a genuine, order-dependent overlap.
			sameRule := func(prev seenPrefix) bool {
				return prev.ruleSetName == rs.Name && prev.ruleName == rule.Name
			}
			overlapFound := false
			for _, prev := range internalSeen {
				if sameRule(prev) {
					continue
				}
				if overlaps(prev.net, intNet) {
					overlapFound = true
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q nptv6-prefix %q overlaps rule-set %q rule %q (outbound/internal prefixes overlap; first-match resolution would be order-dependent)",
						rs.Name, rule.Name, rule.Then, prev.ruleSetName, prev.ruleName)); err != nil {
						return nil, err
					}
					break
				}
			}
			for _, prev := range externalSeen {
				if sameRule(prev) {
					continue
				}
				if overlaps(prev.net, extNet) {
					overlapFound = true
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q match destination-address %q overlaps rule-set %q rule %q (inbound/external prefixes overlap; first-match resolution would be order-dependent)",
						rs.Name, rule.Name, rule.Match, prev.ruleSetName, prev.ruleName)); err != nil {
						return nil, err
					}
					break
				}
			}
			if overlapFound {
				// Do not register an overlapping rule as a baseline for
				// subsequent comparisons; the snapshot is already rejected.
				continue
			}

			internalSeen = append(internalSeen, seenPrefix{net: intNet, ones: intOnes, ruleSetName: rs.Name, ruleName: rule.Name})
			externalSeen = append(externalSeen, seenPrefix{net: extNet, ones: extOnes, ruleSetName: rs.Name, ruleName: rule.Name})
		}
	}

	return warnings, nil
}

// validateNAT64PrefixStrict is the #3886 strict-vs-lenient gate for a NAT64
// rule-set's `prefix` (`security nat nat64 rule-set <r> prefix <p>`).
//
// The prefix is read verbatim into NAT64RuleSnapshot.Prefix
// (compiler_nat.go:compileNAT64 -> buildNAT64Snapshots) and parsed at
// dataplane apply by Nat64State::try_from_snapshots (userspace-dp/src/nat64.rs).
// That /96-integrity check REQUIRES the prefix to be `<ipv6-address>/96`: it
// splits on '/', the token after the first '/' MUST parse as a decimal /96
// (only /96 is supported by the translator), and the address token before the
// '/' MUST parse as an IPv6 address. Anything else (a non-/96 length, a missing
// or garbage mask, a non-IPv6 / malformed address) makes try_from_snapshots
// return a SnapshotIntegrityError, which propagates via `?` out of
// build_reconcile_forwarding and ABORTS the whole forwarding rebuild WITHOUT
// publishing a snapshot. The dataplane is then frozen at the last-good state:
// every later commit (new sessions, policy, NAT) silently stops reaching the
// dataplane with no operator feedback. Without this gate a single bad NAT64
// prefix COMMITS GREEN and wedges the entire control->dataplane pipeline.
//
// This mirrors the Rust /96-integrity check EXACTLY so anything that would
// abort the rebuild at runtime is rejected at commit — no commit-accept ->
// runtime-abort gap. An empty/absent prefix is deliberately OUT OF SCOPE: the
// Go builder (buildNAT64Snapshots) skips an empty-prefix rule, so it is never
// emitted on the wire and never reaches the Rust check, so it cannot freeze the
// rebuild.
//
// Strict (commit / commit-check): hard-reject a non-/96 or malformed prefix.
// Lenient (load / peer-sync, #1960 / #1979 doctrine): return the message as a
// warning so a config committed before this gate existed (or peer-synced) still
// BOOTS — fail-closed-on-compile-failure would otherwise brick the daemon on
// restart. The Rust helper's own try_from_snapshots backstop keeps the previous
// live forwarding state on the leniently-loaded config, so the bad rule never
// installs. Same doctrine as validateNPTv6Strict.
func validateNAT64PrefixStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	emit := func(msg string) error {
		if lenient {
			warnings = append(warnings,
				msg+" (this NAT64 rule is invalid; on a userspace-dataplane apply/preflight"+
					" the helper's Nat64State::try_from_snapshots rejects the whole forwarding"+
					" snapshot and the previous live state is kept, so this rule — and every"+
					" later config change — will not reach the dataplane until it is corrected)")
			return nil
		}
		return fmt.Errorf("%s", msg)
	}

	for _, rs := range cfg.Security.NAT.NAT64 {
		if rs == nil || rs.Prefix == "" {
			continue
		}
		// Mirror Nat64State::try_from_snapshots (userspace-dp/src/nat64.rs)
		// EXACTLY. Split on '/' (Rust `split('/')`); a trailing junk field
		// after the mask is ignored by both sides, so we index [0] and [1] and
		// disregard the rest rather than SplitN'ing the mask.
		parts := strings.Split(rs.Prefix, "/")
		// The token after the first '/' must parse as a decimal /96. A missing
		// mask (no '/'), an empty mask, a non-numeric mask, or any length other
		// than 96 is rejected — only /96 is supported by the translator.
		mask96 := false
		if len(parts) >= 2 {
			if m, err := strconv.ParseUint(parts[1], 10, 8); err == nil && m == 96 {
				mask96 = true
			}
		}
		if !mask96 {
			if err := emit(fmt.Sprintf(
				"security nat nat64 rule-set %q prefix %q must be an IPv6 prefix of length /96 (RFC 6052: the well-known 64:ff9b::/96 or a /96 network-specific prefix); any other length or a missing/garbage mask is rejected by the dataplane, which aborts the entire forwarding rebuild",
				rs.Name, rs.Prefix)); err != nil {
				return nil, err
			}
			continue
		}
		// The address token before the first '/' must parse as an IPv6 address.
		// natAddrFamily keys the family on the un-parsed text (colon == v6) so
		// an IPv4-mapped literal (::ffff:1.2.3.4) is classified V6, matching
		// Rust's Ipv6Addr::from_str exactly (a dotted-quad or a non-IP token is
		// NOT V6 and is rejected).
		if natAddrFamily(parts[0]) != "v6" {
			if err := emit(fmt.Sprintf(
				"security nat nat64 rule-set %q prefix %q has an address part %q that is not a valid IPv6 address; the dataplane rejects it and aborts the entire forwarding rebuild",
				rs.Name, rs.Prefix, parts[0])); err != nil {
				return nil, err
			}
			continue
		}
	}

	return warnings, nil
}

func compileNAT(node *Node, sec *SecurityConfig) error {
	// Initialize SourcePools map
	if sec.NAT.SourcePools == nil {
		sec.NAT.SourcePools = make(map[string]*NATPool)
	}

	// #3915: iterate EVERY source/destination/static/nat64/natv6v4/proxy-arp
	// sub-block under this nat{} node, not just the FIRST. The Junos parser
	// APPENDS a repeated hierarchical block as a sibling (parseStatements,
	// parser.go) instead of merging it, so `load override`/`load merge` can
	// produce a second `source {}` (or destination/static/nat64/proxy-arp)
	// block carrying additional rule-sets. The prior FindChild-first read
	// compiled only the first block and SILENTLY DROPPED the second block's
	// rule-sets -> the SNAT/DNAT/static rule-set vanished and traffic that
	// should have been translated egressed untranslated (a NAT bypass /
	// connectivity break). Each sub-block compiler APPENDS its rule-sets
	// (sec.NAT.Source / Destination.RuleSets / Static / NAT64 / ProxyARP) and
	// map-assigns its pools, so invoking it once per duplicate block MERGES the
	// blocks exactly as Junos merges duplicate hierarchical stanzas. With a
	// single block the callback fires exactly once, bit-identical to the prior
	// FindChild read. Mirrors the #3842 policy dup-block accumulate fix and the
	// #3444/#3562 forEachChild dup-block-bypass class.
	if err := forEachChild(node.Children, "source", func(srcNode *Node) error {
		if err := compileNATSource(srcNode, sec); err != nil {
			return fmt.Errorf("source: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	if err := forEachChild(node.Children, "destination", func(dstNode *Node) error {
		if err := compileNATDestination(dstNode, sec); err != nil {
			return fmt.Errorf("destination: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	if err := forEachChild(node.Children, "static", func(staticNode *Node) error {
		if err := compileNATStatic(staticNode, sec); err != nil {
			return fmt.Errorf("static: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	if err := forEachChild(node.Children, "nat64", func(nat64Node *Node) error {
		if err := compileNAT64(nat64Node, sec); err != nil {
			return fmt.Errorf("nat64: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	// natv6v4 { no-v6-frag-header; } — accumulate across duplicate blocks:
	// initialize the struct once and OR the flag so a second natv6v4 block
	// cannot silently reset an already-observed no-v6-frag-header.
	if err := forEachChild(node.Children, "natv6v4", func(v6v4Node *Node) error {
		if sec.NAT.NATv6v4 == nil {
			sec.NAT.NATv6v4 = &NATv6v4Config{}
		}
		if v6v4Node.FindChild("no-v6-frag-header") != nil {
			sec.NAT.NATv6v4.NoV6FragHeader = true
		}
		return nil
	}); err != nil {
		return err
	}

	// proxy-arp { interface <name> { address <addr>; } }
	if err := forEachChild(node.Children, "proxy-arp", func(proxyNode *Node) error {
		for _, inst := range namedInstances(proxyNode.FindChildren("interface")) {
			entry := &ProxyARPEntry{Interface: inst.name}
			for _, prop := range inst.node.Children {
				if prop.Name() != "address" {
					continue
				}
				// Hierarchical range: Keys=["address","addr1","to","addr2"]
				if len(prop.Keys) >= 4 && prop.Keys[2] == "to" {
					expanded, err := expandAddressRange(prop.Keys[1], prop.Keys[3])
					if err != nil {
						return fmt.Errorf("proxy-arp interface %s: %w", inst.name, err)
					}
					entry.Addresses = append(entry.Addresses, expanded...)
					continue
				}

				// Set syntax range: Keys=["address","addr1"], child Keys=["to","addr2"]
				toChild := prop.FindChild("to")
				if toChild != nil {
					low := nodeVal(prop)
					high := nodeVal(toChild)
					if low != "" && high != "" {
						expanded, err := expandAddressRange(low, high)
						if err != nil {
							return fmt.Errorf("proxy-arp interface %s: %w", inst.name, err)
						}
						entry.Addresses = append(entry.Addresses, expanded...)
						continue
					}
				}

				// Single address
				if v := nodeVal(prop); v != "" {
					addr := v
					if !strings.Contains(addr, "/") {
						addr += "/32"
					}
					entry.Addresses = append(entry.Addresses, addr)
				}
			}
			sec.NAT.ProxyARP = append(sec.NAT.ProxyARP, entry)
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func compileNAT64(node *Node, sec *SecurityConfig) error {
	for _, inst := range namedInstances(node.FindChildren("rule-set")) {
		rs := &NAT64RuleSet{Name: inst.name}

		for _, child := range inst.node.Children {
			switch child.Name() {
			case "prefix":
				rs.Prefix = nodeVal(child)
			case "source-pool":
				rs.SourcePool = nodeVal(child)
			}
		}

		sec.NAT.NAT64 = append(sec.NAT.NAT64, rs)
	}
	return nil
}

// parseZoneList extracts zone names from a from/to node.
// Handles every AST shape the parser can produce for `from zone ...`:
//   - `from` carries the list inline: Keys=["from","zone","A","B","C"] → ["A","B","C"]
//   - Unified bracket list (#2419): one "zone" child with the whole list
//     collapsed onto its Keys — Keys=["zone","A","B","C"] → ["A","B","C"].
//     This is the shape flat-set `set ... from zone [ A B C ]` now produces;
//     before #2419 it split into a "zone" child plus orphan leaf children, and
//     reading only nodeVal here silently dropped every zone but the first
//     (FAIL-OPEN static NAT — the dropped zone's whole rule-set vanished).
//   - Hierarchical / legacy block: multiple "zone" children, each
//     Keys=["zone","A"] (from `from { zone A; zone B; }` or repeated
//     `set ... from zone A` / `from zone B` set commands).
//
// For each "zone" child we accumulate Keys[1:] AND any orphan leaf children,
// mirroring firewallMatchValues (compiler_firewall.go) — the #2419 contract for
// reading a multi-value leaf across both AST shapes.
func parseZoneList(node *Node) []string {
	// `from` carries the zone list inline on its own Keys.
	if len(node.Keys) >= 3 && node.Keys[1] == "zone" {
		return node.Keys[2:]
	}
	var zones []string
	for _, child := range node.Children {
		if child.Name() != "zone" {
			continue
		}
		// Unified bracket list / single value: every token after "zone".
		for _, k := range child.Keys[1:] {
			if k != "" {
				zones = append(zones, k)
			}
		}
		// Legacy bracket-expanded orphan leaf children (defensive — older
		// trees that still split the list into child leaves).
		for _, grandchild := range child.Children {
			if grandchild.IsLeaf && len(grandchild.Keys) >= 1 && grandchild.Keys[0] != "" {
				zones = append(zones, grandchild.Keys[0])
			}
		}
	}
	return zones
}

// natMatchScope is one (kind, value) scope token from a NAT rule-set
// `from`/`to` clause. kind is one of "zone" | "interface" |
// "routing-instance" (#3096).
type natMatchScope struct {
	kind  string
	value string
}

// natScopeKinds is the set of from/to scope keywords a NAT rule-set clause can
// carry. Order matters only for deterministic emission, not precedence.
var natScopeKinds = []string{"zone", "interface", "routing-instance"}

// parseNATMatchScopes generalizes parseZoneList (#3096): it extracts every
// from/to scope token — `zone`, `interface`, AND `routing-instance` — from a
// from/to clause node in both AST shapes the parser produces, instead of
// dropping the non-zone kinds:
//
//   - Inline: the `from`/`to` node carries the scope on its own Keys, e.g.
//     Keys=["from","interface","ge-0/0/1.0"] or the bracket-collapsed
//     Keys=["from","zone","A","B"] (#2419).
//   - Child-leaf / hierarchical: one child per scope kind, each
//     Keys=["interface","ge-0/0/1.0"] (with bracket lists collapsed onto the
//     child's Keys, plus defensive orphan grandchildren — mirroring
//     parseZoneList / firewallMatchValues).
//
// Junos restricts a single from/to clause to ONE kind. This function
// accumulates every kind present so the mixed-kind case is VISIBLE rather than
// silently dropped, but a mixed-kind clause is REJECTED at commit /
// commit-check by validateNATRuleSetMixedScopeAST (#4881) — it never reaches
// the Cartesian expansion, which would OR-expand it into multiple rule-sets and
// widen the match (there is no AND-at-match-time enforcement; the prior comment
// claiming that was wrong). On the tolerant load / peer-sync path the reject is
// downgraded to a warning, so a persisted mixed-kind clause still boots and is
// OR-expanded as before — accumulating every kind here keeps that legacy
// behaviour intact for the leniently-loaded case.
func parseNATMatchScopes(node *Node) []natMatchScope {
	var out []natMatchScope
	// Inline shape: `from`/`to` carries the scope on its own Keys.
	if len(node.Keys) >= 3 {
		for _, kind := range natScopeKinds {
			if node.Keys[1] == kind {
				for _, v := range node.Keys[2:] {
					if v != "" {
						out = append(out, natMatchScope{kind: kind, value: v})
					}
				}
			}
		}
	}
	// Child-leaf shape: one child per scope token.
	for _, child := range node.Children {
		kind := child.Name()
		isScope := false
		for _, k := range natScopeKinds {
			if k == kind {
				isScope = true
				break
			}
		}
		if !isScope {
			continue
		}
		// Unified bracket list / single value: every token after the kind.
		for _, v := range child.Keys[1:] {
			if v != "" {
				out = append(out, natMatchScope{kind: kind, value: v})
			}
		}
		// Defensive: older trees split the bracket list into orphan leaf
		// grandchildren.
		for _, grandchild := range child.Children {
			if grandchild.IsLeaf && len(grandchild.Keys) >= 1 && grandchild.Keys[0] != "" {
				out = append(out, natMatchScope{kind: kind, value: grandchild.Keys[0]})
			}
		}
	}
	return out
}

// collectNATScopes reads the `from` (and, when wantTo, `to`) clauses of a
// rule-set node into from/to scope lists. An empty side defaults to a single
// match-any zone scope ({kind:"zone", value:""}) — the legacy global
// behaviour. #3096.
func collectNATScopes(rsNode *Node, wantTo bool) (fromScopes, toScopes []natMatchScope) {
	for _, child := range rsNode.Children {
		switch child.Name() {
		case "from":
			fromScopes = append(fromScopes, parseNATMatchScopes(child)...)
		case "to":
			if wantTo {
				toScopes = append(toScopes, parseNATMatchScopes(child)...)
			}
		}
	}
	if len(fromScopes) == 0 {
		fromScopes = []natMatchScope{{kind: "zone", value: ""}}
	}
	if wantTo && len(toScopes) == 0 {
		toScopes = []natMatchScope{{kind: "zone", value: ""}}
	}
	return fromScopes, toScopes
}

// applyNATFromScope stamps a from-scope onto a NATRuleSet's typed fields.
func applyNATFromScope(rs *NATRuleSet, s natMatchScope) {
	switch s.kind {
	case "interface":
		rs.FromInterface = s.value
	case "routing-instance":
		rs.FromRoutingInstance = s.value
	default: // "zone"
		rs.FromZone = s.value
	}
}

// applyNATToScope stamps a to-scope onto a NATRuleSet's typed fields.
func applyNATToScope(rs *NATRuleSet, s natMatchScope) {
	switch s.kind {
	case "interface":
		rs.ToInterface = s.value
	case "routing-instance":
		rs.ToRoutingInstance = s.value
	default: // "zone"
		rs.ToZone = s.value
	}
}

// applyStaticNATFromScope stamps a from-scope onto a StaticNATRuleSet.
func applyStaticNATFromScope(rs *StaticNATRuleSet, s natMatchScope) {
	switch s.kind {
	case "interface":
		rs.FromInterface = s.value
	case "routing-instance":
		rs.FromRoutingInstance = s.value
	default: // "zone"
		rs.FromZone = s.value
	}
}

// appendPoolAddresses parses a source-NAT pool `address` token stream and
// appends every IP onto pool.Addresses, expanding any `<low> to <high>`
// sub-range in place. The token stream is the multi-value form of the
// #2419 dual-AST-shape class: a bracket list `[ a b c ]`, a range
// `a to b`, or a mix `a b to c d` all collapse onto one Keys slice, and a
// hierarchical block passes each child node's Keys. Reading the FULL token
// stream (not just the first token) is the #4521 fix — the previous code
// read only Keys[1], truncating a bracket list to its first IP.
func appendPoolAddresses(pool *NATPool, tokens []string) error {
	for i := 0; i < len(tokens); {
		tok := tokens[i]
		if tok == "" {
			i++
			continue
		}
		// Range: "<low> to <high>" — three consecutive tokens with a
		// following high address present.
		if i+2 < len(tokens) && tokens[i+1] == "to" {
			expanded, err := expandAddressRange(tok, tokens[i+2])
			if err != nil {
				return fmt.Errorf("pool %q address range: %w", pool.Name, err)
			}
			pool.Addresses = append(pool.Addresses, expanded...)
			i += 3
			continue
		}
		pool.Addresses = append(pool.Addresses, tok)
		i++
	}
	return nil
}

// expandAddressRange expands "low/mask to high/mask" into individual IP strings.
// Both low and high must be /32 CIDRs. Max 256 IPs.
func expandAddressRange(low, high string) ([]string, error) {
	lowCIDR := low
	if !strings.Contains(lowCIDR, "/") {
		lowCIDR += "/32"
	}
	highCIDR := high
	if !strings.Contains(highCIDR, "/") {
		highCIDR += "/32"
	}
	lowIP, _, err := net.ParseCIDR(lowCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid low address %q: %w", low, err)
	}
	highIP, _, err := net.ParseCIDR(highCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid high address %q: %w", high, err)
	}
	lowIP = lowIP.To4()
	highIP = highIP.To4()
	if lowIP == nil || highIP == nil {
		return nil, fmt.Errorf("address range only supports IPv4")
	}
	lowN := binary.BigEndian.Uint32(lowIP)
	highN := binary.BigEndian.Uint32(highIP)
	if lowN > highN {
		return nil, fmt.Errorf("low address %s > high address %s", low, high)
	}
	count := highN - lowN + 1
	if count > 256 {
		return nil, fmt.Errorf("address range too large: %d IPs (max 256)", count)
	}
	var result []string
	buf := make(net.IP, 4)
	for i := uint32(0); i < count; i++ {
		binary.BigEndian.PutUint32(buf, lowN+i)
		result = append(result, buf.String()+"/32")
	}
	return result, nil
}

// parseSourcePoolPortRange interprets the tokens that follow a source-pool
// `port range` keyword into an inclusive [low, high] range (#3906). It accepts
// two shapes so both the Junos wire grammar and the legacy explicit-keyword
// grammar compile:
//
//   - Junos: `<low> to <high>` (e.g. Keys after "range" = ["5000","to","6000"])
//     and a bare `<low>` (single port, low == high).
//   - Legacy: `low <lo> high <hi>` (Keys after "range" = ["low","5000","high",
//     "6000"]) — the shape the pre-#3906 compiler required. Before #3906 only
//     this shape was accepted, so the Junos `port range <low> to <high>` was
//     silently dropped and the pool defaulted to 1024-65535 PAT.
//
// A reversed (low > high) or out-of-range value parses successfully here (it is
// carried into PortLow/PortHigh); the strict commit gate
// (validateSourceNATPoolStrict) hard-rejects it so the operator sees the error
// rather than the rule dropping at runtime. ok is false only when no numeric low
// could be read (garbage tokens), leaving PortLow/PortHigh at their default.
func parseSourcePoolPortRange(toks []string) (low, high int, ok bool) {
	// Legacy explicit-keyword shape: low <lo> high <hi>.
	if len(toks) >= 4 && toks[0] == "low" && toks[2] == "high" {
		lo, err1 := strconv.Atoi(toks[1])
		hi, err2 := strconv.Atoi(toks[3])
		if err1 != nil || err2 != nil {
			return 0, 0, false
		}
		return lo, hi, true
	}
	// Junos shape: <low> [to <high>].
	if len(toks) == 0 {
		return 0, 0, false
	}
	lo, err := strconv.Atoi(toks[0])
	if err != nil {
		return 0, 0, false
	}
	hi := lo
	if len(toks) >= 3 && toks[1] == "to" {
		v, err2 := strconv.Atoi(toks[2])
		if err2 != nil {
			return 0, 0, false
		}
		hi = v
	}
	return lo, hi, true
}

// applyDeterministicKeys reads deterministic CGNAT sub-tokens from a flat-set
// key slice that begins immediately AFTER the "deterministic" keyword, e.g.
// ["block-size","2016"] or ["host","address","100.64.0.0/22"] or ["host","X"].
// Only fields that are present are written, so the caller can invoke it
// repeatedly across sibling `port deterministic ...` leaves and the values
// ACCUMULATE rather than overwrite last-wins (#3864; #2419 dual-AST-shape).
func applyDeterministicKeys(det *DeterministicNATConfig, keys []string) {
	for i := 0; i < len(keys); i++ {
		switch keys[i] {
		case "block-size":
			if i+1 < len(keys) {
				if n, err := strconv.Atoi(keys[i+1]); err == nil {
					det.BlockSize = n
				}
			}
		case "host":
			// "host address X" (canonical) or the tolerant "host X".
			if i+1 < len(keys) && keys[i+1] == "address" {
				if i+2 < len(keys) {
					det.HostAddress = keys[i+2]
				}
			} else if i+1 < len(keys) {
				det.HostAddress = keys[i+1]
			}
		}
	}
}

// applyDeterministicChildren reads deterministic CGNAT sub-fields from the
// CHILDREN of a `deterministic` container node (the hierarchical /
// schema-grouped shape, `deterministic { block-size N; host address X }`).
// Like applyDeterministicKeys it only writes present fields so mixed/repeated
// shapes accumulate into a single config (#3864).
func applyDeterministicChildren(det *DeterministicNATConfig, detNode *Node) {
	// The deterministic node may itself carry trailing flat-set tokens
	// (e.g. Keys=["deterministic","block-size","2016"]).
	if len(detNode.Keys) > 1 {
		applyDeterministicKeys(det, detNode.Keys[1:])
	}
	for _, c := range detNode.Children {
		switch c.Name() {
		case "block-size":
			if v := nodeVal(c); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					det.BlockSize = n
				}
			}
		case "host":
			applyDeterministicHost(det, c)
		}
	}
}

// applyDeterministicHost reads the subscriber CIDR from a `host` node in any
// of its shapes: the flat leaf Keys=["host","address","X"], the hierarchical
// `host { address X }`, or the tolerant bare `host X`. It never records the
// literal keyword "address" as the value (#3864).
func applyDeterministicHost(det *DeterministicNATConfig, hostNode *Node) {
	if len(hostNode.Keys) >= 3 && hostNode.Keys[1] == "address" {
		det.HostAddress = hostNode.Keys[2]
		return
	}
	if addr := hostNode.FindChild("address"); addr != nil {
		if v := nodeVal(addr); v != "" {
			det.HostAddress = v
			return
		}
	}
	if len(hostNode.Keys) == 2 {
		det.HostAddress = hostNode.Keys[1]
	}
}

func compileNATSource(node *Node, sec *SecurityConfig) error {
	// Global flags
	if node.FindChild("address-persistent") != nil {
		sec.NAT.AddressPersistent = true
	}

	// #4291: `nat source interface port-overloading off` disables source-port
	// reuse across destinations (a src-port-uniqueness hardening posture).
	// Accepted + recorded for the advisory (ValidateConfig); NOT enforced —
	// source-port overloading is always on in the SNAT allocator, so `off`
	// hardens nothing. Handle both the flat-set collapse
	// (["interface","port-overloading","off"]) and the hierarchical
	// `interface { port-overloading off; }` shape.
	if ifNode := node.FindChild("interface"); ifNode != nil {
		poOff := false
		for i := 0; i+1 < len(ifNode.Keys); i++ {
			if ifNode.Keys[i] == "port-overloading" && ifNode.Keys[i+1] == "off" {
				poOff = true
			}
		}
		if po := ifNode.FindChild("port-overloading"); po != nil && nodeVal(po) == "off" {
			poOff = true
		}
		if poOff {
			sec.NAT.SourceInterfacePortOverloadingOff = true
		}
	}

	// Parse source NAT pools
	for _, inst := range namedInstances(node.FindChildren("pool")) {
		pool := &NATPool{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "address":
				// A source pool `address` value carries EVERY IP the
				// SNAT allocator may draw from. It arrives in four
				// shapes (#2419 dual-AST-shape class — mirror
				// firewallMatchValues):
				//
				//   discrete set lines : one `address <ip>;` prop per IP
				//   bracket list       : `address [ a b c ]` — UNMODELED
				//                        in schema (schema_security.go
				//                        pool children), so SetPath's
				//                        unmodeled-leaf path collapses
				//                        every trailing token onto ONE
				//                        node: Keys=["address","a","b","c"]
				//   range              : `address <low> to <high>`
				//                        Keys=["address",low,"to",high]
				//   hierarchical block : `address { a; b to c; }` — one
				//                        child node per entry
				//                        (Keys=["a"] / ["b","to","c"])
				//
				// Before #4521 the inline branch read only prop.Keys[1]
				// and the range branch required Keys[2]=="to", so a
				// bracket list silently kept ONLY the first IP → the
				// pool shrank to one address → premature source-port
				// exhaustion. Read the whole Keys[1:] token stream
				// (plus the block children), expanding any `<low> to
				// <high>` sub-range in place. Keys[1:] and Children are
				// mutually exclusive per the #2419 pattern: the inline
				// form has no children and the block form has no inline
				// Keys value, so reading both cannot double-append.
				if err := appendPoolAddresses(pool, prop.Keys[1:]); err != nil {
					return err
				}
				for _, addrChild := range prop.Children {
					// A block child's own Keys are the address token
					// stream (Keys[0] is the IP, not the property name).
					if err := appendPoolAddresses(pool, addrChild.Keys); err != nil {
						return err
					}
				}
			case "port":
				// Port block configuration for a source pool. Supported
				// AST shapes (#3864, #2419 dual-AST-shape):
				//
				//   flat leaf  : Keys=["port","range","low",N,"high",M]
				//                Keys=["port",N]
				//                Keys=["port","deterministic","block-size",N]
				//                Keys=["port","deterministic","host","address",X]
				//   hierarchical / schema-grouped: one `port` container
				//                (schema_security.go groups the flat-set
				//                tokens) with `range`/`deterministic`
				//                children — `port { range low N high M;
				//                deterministic { block-size N; host address
				//                X } }`.
				//
				// Deterministic block-size and host address arrive on
				// SEPARATE flat-set `set` lines; before #3864 each sibling
				// `port deterministic ...` leaf reset pool.Deterministic to
				// a fresh struct (last-wins) and the host address was never
				// read off Keys, so the documented CGNAT quick-start was
				// spuriously rejected ("block-size must be > 0" / "host
				// address required"). Deterministic fields are now
				// ACCUMULATED into a single config across every shape and
				// sibling, writing only fields that are present.
				ensureDet := func() *DeterministicNATConfig {
					if pool.Deterministic == nil {
						pool.Deterministic = &DeterministicNATConfig{}
					}
					return pool.Deterministic
				}

				// Port range / single value — flat leaf shapes
				// (Keys=["port","range",...]/["port",N]/["port",
				// "no-translation"]). #3906: `range` accepts both the Junos
				// wire shape `<low> to <high>` and the legacy `low <lo> high
				// <hi>` shape; `no-translation` preserves the source port.
				if len(prop.Keys) >= 3 && prop.Keys[1] == "range" {
					if lo, hi, ok := parseSourcePoolPortRange(prop.Keys[2:]); ok {
						pool.PortLow = lo
						pool.PortHigh = hi
					}
				} else if len(prop.Keys) == 2 && prop.Keys[1] != "range" &&
					prop.Keys[1] != "deterministic" &&
					prop.Keys[1] != "no-translation" {
					// "port N" single value.
					if n, err := strconv.Atoi(prop.Keys[1]); err == nil {
						pool.PortLow = n
						pool.PortHigh = n
					}
				}
				// no-translation may ride along on the flat-leaf keys
				// (Keys=["port","no-translation"]).
				for _, k := range prop.Keys[1:] {
					if k == "no-translation" {
						pool.PortNoTranslation = true
					}
				}

				// Deterministic — flat leaf: Keys=["port","deterministic",...].
				if len(prop.Keys) >= 2 && prop.Keys[1] == "deterministic" {
					applyDeterministicKeys(ensureDet(), prop.Keys[2:])
				}

				// Children — hierarchical / schema-grouped `port { ... }`.
				for _, pc := range prop.Children {
					switch pc.Name() {
					case "range":
						// range <low> to <high> | range low <lo> high <hi>
						// (#3906). pc.Keys[1:] is the token slice after the
						// `range` keyword.
						if lo, hi, ok := parseSourcePoolPortRange(pc.Keys[1:]); ok {
							pool.PortLow = lo
							pool.PortHigh = hi
						}
					case "no-translation":
						pool.PortNoTranslation = true
					case "deterministic":
						applyDeterministicChildren(ensureDet(), pc)
					default:
						// Bare numeric child: `port N` grouped under a
						// modeled container becomes port { N }.
						if pc.IsLeaf && len(pc.Keys) == 1 {
							if n, err := strconv.Atoi(pc.Keys[0]); err == nil {
								pool.PortLow = n
								pool.PortHigh = n
							}
						}
					}
				}
			case "persistent-nat":
				// #2823: default is target-host-port (the pre-#2823
				// false-flag (dst_ip, dst_port) keying) so a config that
				// configures persistent-nat with no explicit permit keeps
				// the #2819 behavior byte-identical.
				pnat := &PersistentNATConfig{
					InactivityTimeout: 300,
					Permit:            PersistentNATPermitTargetHostPort,
				}
				parsePermit := func(v string) {
					switch v {
					case "any-remote-host":
						pnat.Permit = PersistentNATPermitAnyRemoteHost
					case "target-host":
						pnat.Permit = PersistentNATPermitTargetHost
					case "target-host-port":
						pnat.Permit = PersistentNATPermitTargetHostPort
					}
				}
				// Flat-set shape: persistent-nat collapses trailing tokens
				// onto Keys (e.g. ["persistent-nat","permit","target-host"]
				// or ["persistent-nat","inactivity-timeout","600"]).
				for i := 1; i+1 < len(prop.Keys); i++ {
					switch prop.Keys[i] {
					case "permit":
						parsePermit(prop.Keys[i+1])
					case "inactivity-timeout":
						if n, err := strconv.Atoi(prop.Keys[i+1]); err == nil {
							pnat.InactivityTimeout = n
						}
					}
				}
				// Hierarchical / schema-grouped shape: permit and
				// inactivity-timeout arrive as child leaves.
				for _, pnProp := range prop.Children {
					switch pnProp.Name() {
					case "permit":
						if v := nodeVal(pnProp); v != "" {
							parsePermit(v)
						}
					case "inactivity-timeout":
						if v := nodeVal(pnProp); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								pnat.InactivityTimeout = n
							}
						}
					}
				}
				pool.PersistentNAT = pnat
			case "port-overloading-factor":
				// #4291: source-pool port-overloading-factor <n>. Accepted +
				// recorded for the advisory (ValidateConfig); not enforced —
				// the SNAT allocator has no factor-scaled port budget. Flat-set
				// collapses ["port-overloading-factor","<n>"] onto Keys; the
				// hierarchical shape carries the value as nodeVal.
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						pool.PortOverloadingFactor = n
					}
				}
			case "routing-instance":
				// #4292: source-pool translation-target routing-instance.
				// Accepted + recorded for the advisory; not enforced (the
				// dataplane does not route the post-translation packet against
				// a non-ingress table).
				if v := nodeVal(prop); v != "" {
					pool.RoutingInstance = v
				}
			}
		}
		if pool.PortLow == 0 {
			pool.PortLow = 1024
		}
		if pool.PortHigh == 0 {
			pool.PortHigh = 65535
		}
		sec.NAT.SourcePools[pool.Name] = pool
	}

	// Parse pool-utilization-alarm
	if alarmNode := node.FindChild("pool-utilization-alarm"); alarmNode != nil {
		alarm := &PoolUtilizationAlarmConfig{}
		// clearSet records whether the operator explicitly provided a
		// clear-threshold token. Junos makes clear-threshold OPTIONAL: a
		// raise-only alarm is legal (#4077). When it is omitted we default it
		// to a hysteresis margin below raise (defaultPoolAlarmClearThreshold),
		// so the raise-only config compiles AND the runtime monitor enables the
		// alarm (it treats clear<=0 as disabled). An EXPLICIT clear-threshold —
		// even an invalid one like 0 or >= raise — is preserved verbatim so the
		// commit gate still rejects it.
		clearSet := false
		for _, ap := range alarmNode.Children {
			switch ap.Name() {
			case "raise-threshold":
				if v := nodeVal(ap); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						alarm.RaiseThreshold = n
					}
				}
			case "clear-threshold":
				clearSet = true
				if v := nodeVal(ap); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						alarm.ClearThreshold = n
					}
				}
			}
		}
		// Also handle flat keys: pool-utilization-alarm raise-threshold 80 clear-threshold 70
		for i := 1; i < len(alarmNode.Keys); i++ {
			if alarmNode.Keys[i] == "raise-threshold" && i+1 < len(alarmNode.Keys) {
				if n, err := strconv.Atoi(alarmNode.Keys[i+1]); err == nil {
					alarm.RaiseThreshold = n
				}
			}
			if alarmNode.Keys[i] == "clear-threshold" && i+1 < len(alarmNode.Keys) {
				clearSet = true
				if n, err := strconv.Atoi(alarmNode.Keys[i+1]); err == nil {
					alarm.ClearThreshold = n
				}
			}
		}
		// Raise-only config: default the clear-threshold to a hysteresis margin
		// below raise so the alarm is usable without an explicit clear.
		if alarm.RaiseThreshold > 0 && !clearSet {
			alarm.ClearThreshold = defaultPoolAlarmClearThreshold(alarm.RaiseThreshold)
		}
		sec.NAT.PoolUtilizationAlarm = alarm
	}

	// Validate deterministic NAT pools
	for _, pool := range sec.NAT.SourcePools {
		if pool.Deterministic == nil {
			continue
		}
		det := pool.Deterministic
		if det.BlockSize <= 0 {
			return fmt.Errorf("pool %q: deterministic block-size must be > 0", pool.Name)
		}
		if det.HostAddress == "" {
			return fmt.Errorf("pool %q: deterministic host address required", pool.Name)
		}
		_, hostNet, err := net.ParseCIDR(det.HostAddress)
		if err != nil {
			return fmt.Errorf("pool %q: invalid host address %q: %w", pool.Name, det.HostAddress, err)
		}
		ones, bits := hostNet.Mask.Size()
		portLow := pool.PortLow
		if portLow == 0 {
			portLow = 1024
		}
		portHigh := pool.PortHigh
		if portHigh == 0 {
			portHigh = 65535
		}
		portRange := portHigh - portLow + 1
		if det.BlockSize > portRange {
			return fmt.Errorf("pool %q: block-size %d exceeds port range %d", pool.Name, det.BlockSize, portRange)
		}
		blocksPerIP := portRange / det.BlockSize
		totalBlocks := len(pool.Addresses) * blocksPerIP

		if bits == 128 {
			// IPv6 host address — validate word-aligned prefix
			if ones != 32 && ones != 64 {
				return fmt.Errorf("pool %q: IPv6 host prefix must be /32 or /64, got /%d", pool.Name, ones)
			}
			// For IPv6, subscriber count is capped by pool capacity
			if totalBlocks == 0 {
				return fmt.Errorf("pool %q: insufficient capacity (0 blocks) for IPv6 deterministic NAT", pool.Name)
			}
		} else {
			// IPv4 host address
			hostCount := 1 << uint(bits-ones)
			if totalBlocks < hostCount {
				return fmt.Errorf("pool %q: insufficient capacity (%d blocks) for %d subscribers", pool.Name, totalBlocks, hostCount)
			}
		}
		if pool.PersistentNAT != nil {
			return fmt.Errorf("pool %q: deterministic and persistent-nat are mutually exclusive", pool.Name)
		}
		if sec.NAT.AddressPersistent {
			return fmt.Errorf("pool %q: deterministic and address-persistent are mutually exclusive", pool.Name)
		}
	}

	// #2079: pool-utilization-alarm threshold validation is NOT performed
	// here — it is a strict-vs-lenient gate (validatePoolUtilizationAlarm,
	// compiler.go typed-config phase) so the strict commit path hard-rejects
	// while the tolerant load/peer-sync path WARNS. Doing it here would hard-
	// fail CompileConfigLenient and brick a daemon restart on a legacy config
	// that was committed before #2079 added validation (#1979 doctrine).

	// Parse source NAT rule-sets
	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
		// #3096: capture from/to scope across zone | interface |
		// routing-instance (bracket lists produce multiple scopes).
		fromScopes, toScopes := collectNATScopes(rsInst.node, true)

		// Parse rules (shared across all scope-pair expansions)
		var rules []*NATRule
		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
			rule := &NATRule{Name: ruleInst.name}

			// #3850: iterate EVERY `match {}` block, not just the first — a
			// duplicate block (a `load merge`/`load override` that splits its
			// conditions, or a hierarchical config authored twice) must
			// AND-combine every condition, never be dropped by a FindChild-first
			// read (a fail-open widening of the NAT match). Flat-set is
			// unaffected: SetPath merges duplicate containers into one node
			// (ast_edit.go), so this only changes the hierarchical/parser shape.
			for _, matchNode := range ruleInst.node.FindChildren("match") {
				for _, m := range matchNode.Children {
					switch m.Name() {
					case "source-address":
						// Support bracket lists: source-address [ addr1 addr2 ... ]
						if len(m.Keys) >= 2 {
							rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, child.Name())
							}
						}
						if len(rule.Match.SourceAddresses) > 0 {
							rule.Match.SourceAddress = rule.Match.SourceAddresses[0]
						}
					case "source-address-name":
						// #2416: address-book reference; resolved to prefixes at
						// snapshot-build time (appendNATSourceAddressName).
						// #3431: accumulate EVERY value of a bracket list /
						// repeated leaf (mirror firewallMatchValues) — a
						// `match source-address-name [ a b ]` used to keep only
						// the first and silently drop the rest.
						rule.Match.SourceAddressNames = append(rule.Match.SourceAddressNames, firewallMatchValues(m)...)
						if len(rule.Match.SourceAddressNames) > 0 {
							rule.Match.SourceAddressName = rule.Match.SourceAddressNames[0]
						}
					case "destination-address":
						// Support bracket lists: destination-address [ addr1 addr2 ... ]
						if len(m.Keys) >= 2 {
							rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, child.Name())
							}
						}
						if len(rule.Match.DestinationAddresses) > 0 {
							rule.Match.DestinationAddress = rule.Match.DestinationAddresses[0]
						} else {
							rule.Match.DestinationAddress = nodeVal(m)
						}
					case "destination-address-name":
						// #3229: address-book reference; resolved to prefixes at
						// snapshot-build time (appendNATDestinationAddressName).
						// #3431: accumulate every value (bracket list / repeated).
						rule.Match.DestinationAddressNames = append(rule.Match.DestinationAddressNames, firewallMatchValues(m)...)
						if len(rule.Match.DestinationAddressNames) > 0 {
							rule.Match.DestinationAddressName = rule.Match.DestinationAddressNames[0]
						}
					case "destination-port":
						// #3429 (H03): route source-NAT destination-port through
						// the shared DNAT port-list parser. The old scalar path
						// read only nodeVal/single child, so a flat-set
						// `destination-port 20000 to 20003` (collapsed onto
						// Keys=[destination-port 20000 to 20003], no children)
						// silently kept only the first port. parseDNATPortList
						// handles bracket lists and `low to high` ranges in both
						// the hierarchical and flat-set AST shapes.
						dports, dinvalid, drev := parseDNATPortList(m)
						rule.Match.DestinationPorts = append(rule.Match.DestinationPorts, dports...)
						rule.Match.InvalidDestinationPorts = append(rule.Match.InvalidDestinationPorts, dinvalid...)
						rule.Match.ReversedDestinationPortRanges = append(rule.Match.ReversedDestinationPortRanges, drev...)
						if rule.Match.DestinationPort == 0 && len(rule.Match.DestinationPorts) > 0 {
							rule.Match.DestinationPort = rule.Match.DestinationPorts[0]
						}
					case "application":
						// #3431: accumulate every application (bracket list /
						// repeated) — `match application [ a b ]` used to keep
						// only the first and silently drop the rest.
						rule.Match.Applications = append(rule.Match.Applications, firewallMatchValues(m)...)
						if len(rule.Match.Applications) > 0 {
							rule.Match.Application = rule.Match.Applications[0]
						}
					}
				}
			}

			// #3850: iterate EVERY `then {}` block, not just the first. A NAT
			// rule carries a single translation action, so a duplicate then
			// block resolves last-wins (Junos merges duplicate stanzas) — the
			// second block's action is applied, never silently dropped. RESET
			// the translation spec at the top of each block so only the LAST
			// block's fields survive: a source-nat then-block is a COMPLETE,
			// mutually-exclusive spec (interface | pool | off), so without the
			// reset a first `interface` block would leave Interface=true stale
			// under a second `pool` block (both fields set → the dataplane's
			// field precedence, not true last-wins). NATThen carries only these
			// translation-mode fields, so a whole-struct reset is safe (#3850
			// review).
			for _, thenNode := range ruleInst.node.FindChildren("then") {
				rule.Then = NATThen{}
				for _, t := range thenNode.Children {
					if t.Name() == "source-nat" {
						if len(t.Keys) >= 2 {
							switch t.Keys[1] {
							case "interface":
								rule.Then.Type = NATSource
								rule.Then.Interface = true
							case "off":
								rule.Then.Type = NATSource
								rule.Then.Off = true
							case "pool":
								rule.Then.Type = NATSource
								if len(t.Keys) >= 3 {
									rule.Then.PoolName = t.Keys[2]
								}
							}
						} else if t.FindChild("interface") != nil {
							rule.Then.Type = NATSource
							rule.Then.Interface = true
						} else if t.FindChild("off") != nil {
							rule.Then.Type = NATSource
							rule.Then.Off = true
						} else if poolNode := t.FindChild("pool"); poolNode != nil {
							rule.Then.Type = NATSource
							rule.Then.PoolName = nodeVal(poolNode)
						}
					}
				}
			}

			rules = append(rules, rule)
		}

		// Expand Cartesian product of from-scopes × to-scopes (#3096).
		for _, fs := range fromScopes {
			for _, ts := range toScopes {
				rs := &NATRuleSet{
					Name:  rsInst.name,
					Rules: rules,
				}
				applyNATFromScope(rs, fs)
				applyNATToScope(rs, ts)
				sec.NAT.Source = append(sec.NAT.Source, rs)
			}
		}
	}
	return nil
}

// parseDNATPoolAddress walks a destination-NAT pool `address` statement and
// captures the translated address and (optionally nested) `port <N>` token.
// Junos expresses the DNAT pool port as `address port <N>` (a child of the
// address leaf), not a top-level `port`. The token stream after "address" may
// be the bare IP, a `port <N>` pair, both interleaved, or — in the hierarchical
// shape — split across Children (`address { <ip>; port <N>; }`). A `port` token
// records PortRaw (and the parsed int) so validateDNATPoolStrict and the
// snapshot builder can fail closed on an invalid value; everything else is the
// translated address. PortRaw lets the gate tell a configured port (which must
// be 1..65535) from no port leaf at all (Port==0 = preserve destination port).
func parseDNATPoolAddress(pool *NATPool, prop *Node) {
	toks := append([]string(nil), prop.Keys[1:]...)
	for _, c := range prop.Children {
		toks = append(toks, c.Keys...)
	}
	for i := 0; i < len(toks); i++ {
		if toks[i] == "port" {
			if i+1 < len(toks) {
				pool.PortRaw = toks[i+1]
				if n, err := strconv.Atoi(toks[i+1]); err == nil {
					pool.Port = n
				}
				i++
			}
			continue
		}
		pool.Address = toks[i]
	}
}

func compileNATDestination(node *Node, sec *SecurityConfig) error {
	if sec.NAT.Destination == nil {
		sec.NAT.Destination = &DestinationNATConfig{
			Pools: make(map[string]*NATPool),
		}
	}

	// Parse pools
	for _, inst := range namedInstances(node.FindChildren("pool")) {
		pool := &NATPool{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "address":
				// DNAT pool address grammar (Junos):
				//   address <ip|cidr>      translated address
				//   address port <N>       translated port (nested under address)
				//   address <ip> port <N>  both on one statement
				// A hierarchical `address { <ip>; port <N>; }` carries the IP and
				// the `port <N>` pair in Children. The pre-#3450 parser did a bare
				// `pool.Address = nodeVal(prop)`, which set Address to the literal
				// "port" for an `address port 80` statement and dropped the port
				// entirely. Walk every token so the address and the nested port are
				// each captured.
				parseDNATPoolAddress(pool, prop)
			case "port":
				// Top-level `port <N>` form (flat-set / older configs).
				if v := nodeVal(prop); v != "" {
					// #3450: preserve the raw token so the strict gate and the
					// snapshot builder can reject a configured-but-invalid port
					// (0/out-of-range/non-numeric) rather than wrap on a uint16
					// cast or collapse to the preserve-destination-port default.
					pool.PortRaw = v
					if n, err := strconv.Atoi(v); err == nil {
						pool.Port = n
					}
				}
			case "routing-instance":
				// #4292: destination-pool translation-target routing-instance.
				// Accepted + recorded for the advisory (ValidateConfig); not
				// enforced (the dataplane does not route the post-translation
				// packet against a non-ingress table).
				if v := nodeVal(prop); v != "" {
					pool.RoutingInstance = v
				}
			}
		}

		sec.NAT.Destination.Pools[pool.Name] = pool
	}

	// Parse rule-sets
	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
		// #3096: capture the `from` scope across zone | interface |
		// routing-instance (bracket lists produce multiple scopes).
		// #3444: a destination-NAT rule-set has only a `from` clause — DNAT
		// translates the destination on inbound, so there is no egress
		// context. A `to` scope is rejected at strict commit
		// (validateDNATRuleSetToScopeAST); it is NOT collected here so it
		// can never be stamped onto a NATRuleSet (the snapshot builder and
		// the Rust DNAT runtime model only the `from` clause).
		fromScopes, _ := collectNATScopes(rsInst.node, false)

		var rules []*NATRule
		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
			rule := &NATRule{Name: ruleInst.name}

			// #3850: iterate EVERY `match {}` block, not just the first — a
			// duplicate block (a `load merge`/`load override` that splits its
			// conditions, or a hierarchical config authored twice) must
			// AND-combine every condition, never be dropped by a FindChild-first
			// read (a fail-open widening of the NAT match). Flat-set is
			// unaffected: SetPath merges duplicate containers into one node
			// (ast_edit.go), so this only changes the hierarchical/parser shape.
			for _, matchNode := range ruleInst.node.FindChildren("match") {
				for _, m := range matchNode.Children {
					switch m.Name() {
					case "destination-address":
						// Support bracket lists: destination-address [ addr1 addr2 ... ]
						if len(m.Keys) >= 2 {
							rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, child.Name())
							}
						}
						if len(rule.Match.DestinationAddresses) > 0 {
							rule.Match.DestinationAddress = rule.Match.DestinationAddresses[0]
						} else {
							rule.Match.DestinationAddress = nodeVal(m)
						}
					case "destination-address-name":
						// #3229: address-book reference; resolved to prefixes at
						// snapshot-build time (appendNATDestinationAddressName).
						// #3431: accumulate every value (bracket list / repeated).
						rule.Match.DestinationAddressNames = append(rule.Match.DestinationAddressNames, firewallMatchValues(m)...)
						if len(rule.Match.DestinationAddressNames) > 0 {
							rule.Match.DestinationAddressName = rule.Match.DestinationAddressNames[0]
						}
					case "destination-port":
						dports, dinvalid, drev := parseDNATPortList(m)
						rule.Match.DestinationPorts = append(rule.Match.DestinationPorts, dports...)
						rule.Match.InvalidDestinationPorts = append(rule.Match.InvalidDestinationPorts, dinvalid...)
						rule.Match.ReversedDestinationPortRanges = append(rule.Match.ReversedDestinationPortRanges, drev...)
						if rule.Match.DestinationPort == 0 && len(rule.Match.DestinationPorts) > 0 {
							rule.Match.DestinationPort = rule.Match.DestinationPorts[0]
						}
					case "source-address":
						// Support bracket lists: source-address [ addr1 addr2 ... ]
						if len(m.Keys) >= 2 {
							rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, child.Name())
							}
						}
						if len(rule.Match.SourceAddresses) > 0 {
							rule.Match.SourceAddress = rule.Match.SourceAddresses[0]
						}
					case "source-address-name":
						// #3431: accumulate every value (bracket list / repeated).
						rule.Match.SourceAddressNames = append(rule.Match.SourceAddressNames, firewallMatchValues(m)...)
						if len(rule.Match.SourceAddressNames) > 0 {
							rule.Match.SourceAddressName = rule.Match.SourceAddressNames[0]
						}
					case "protocol":
						// #3431: accumulate every protocol (bracket list /
						// repeated) — `match protocol [ tcp udp ]` used to keep
						// only the first.
						rule.Match.Protocols = append(rule.Match.Protocols, firewallMatchValues(m)...)
						if len(rule.Match.Protocols) > 0 {
							rule.Match.Protocol = rule.Match.Protocols[0]
						}
					case "application":
						// #3431: accumulate every application (bracket list / repeated).
						rule.Match.Applications = append(rule.Match.Applications, firewallMatchValues(m)...)
						if len(rule.Match.Applications) > 0 {
							rule.Match.Application = rule.Match.Applications[0]
						}
					}
				}
			}

			// #3850: iterate EVERY `then {}` block, not just the first. A NAT
			// rule carries a single translation action, so a duplicate then
			// block resolves last-wins (Junos merges duplicate stanzas) — the
			// second block's action is applied, never silently dropped. RESET
			// the translation spec at the top of each block (see the source-NAT
			// note) so a second `pool` block cannot inherit a first `off`
			// block's stale field; a destination-nat then-block is a complete
			// mutually-exclusive spec (pool | off) and NATThen carries only
			// translation-mode fields (#3850 review).
			for _, thenNode := range ruleInst.node.FindChildren("then") {
				rule.Then = NATThen{}
				for _, t := range thenNode.Children {
					if t.Name() == "destination-nat" {
						// #3844: `then destination-nat off` is a no-translate
						// EXEMPTION — traffic matching this rule must NOT be
						// DNAT'd. Mirror the source-nat `off` handling above so
						// the exemption carries Then.Type=NATDestination +
						// Then.Off=true instead of compiling to an empty Then
						// that the snapshot builder skips (the #3844 fail-open,
						// where the "exempted" traffic fell through to a later
						// DNAT rule). Both AST shapes are handled: the flat-set
						// leaf (Keys=["destination-nat","off"]) and the
						// hierarchical child (`destination-nat { off; }`).
						if len(t.Keys) >= 2 && t.Keys[1] == "off" {
							rule.Then.Type = NATDestination
							rule.Then.Off = true
						} else if len(t.Keys) >= 3 && t.Keys[1] == "pool" {
							rule.Then.Type = NATDestination
							rule.Then.PoolName = t.Keys[2]
						} else if poolNode := t.FindChild("pool"); poolNode != nil {
							rule.Then.Type = NATDestination
							rule.Then.PoolName = nodeVal(poolNode)
						} else if t.FindChild("off") != nil {
							rule.Then.Type = NATDestination
							rule.Then.Off = true
						}
					}
				}
			}

			rules = append(rules, rule)
		}

		// Expand per from-scope (#3096). DNAT carries no `to` scope (#3444).
		for _, fs := range fromScopes {
			rs := &NATRuleSet{
				Name:  rsInst.name,
				Rules: rules,
			}
			applyNATFromScope(rs, fs)
			sec.NAT.Destination.RuleSets = append(sec.NAT.Destination.RuleSets, rs)
		}
	}
	return nil
}

// parseDNATPortList extracts destination ports from a destination-port node.
// Handles single port, multiple ports as children, and port ranges ("20000 to 30000").
// AST shapes handled:
//   - Hierarchical multi-port: destination-port { 80; 443; 20000 to 30000; }
//   - Single port leaf: destination-port 8080;
//   - Set syntax range: destination-port 20000 { to 30000; } (args=1 consumes low, "to N" is child)
//
// The second return value (#3446) is the list of raw tokens that did NOT parse
// as an integer — e.g. `http`, `httpp`. The parser previously dropped these
// silently, which let an all-nonnumeric `match destination-port` collapse to an
// empty port list and then widen to the wildcard port at snapshot-build time
// (H14). They are surfaced to the caller (stored on
// NATMatch.InvalidDestinationPorts) so the strict commit gate can reject them
// and the snapshot builders can fail CLOSED. The `to` range keyword is never
// reported as an invalid token. Out-of-range numerics (0, -1, 70000) DO parse
// as integers, so they flow through `ports` and are range-checked downstream
// (validateNATMatchDestinationPortStrict + the 1..65535 builder filter).
//
// The third return value (#4422) is the list of raw `<low> to <high>` tokens
// where high < low — a reversed range. The parser previously fell through such
// a range and split it into its two discrete endpoints (`4000 to 3000` → match
// ports {4000, 3000}), silently miscompiling the operator's intended contiguous
// range. They are surfaced to the caller (stored on
// NATMatch.ReversedDestinationPortRanges) so validateNATMatchDestinationPortStrict
// can reject them at commit; the two endpoints still flow through `ports` so the
// lenient load / peer-sync path installs exactly what it did before (no
// regression), warning instead of rejecting.
// appendDNATPortRange expands an inclusive `low to high` destination-port range
// into individual ports, BOUNDED to the valid 1..65535 port space (#3449). The
// per-port `for p := low; p <= high` loops below used operator-supplied
// endpoints with no upper bound, so a huge/garbage range (e.g.
// `destination-port 1 to 4000000000`) allocated billions of ints at COMPILE
// time — a control-plane OOM that triggered BEFORE the strict commit gate could
// reject the out-of-range endpoint. When either endpoint is outside 1..65535
// the range is NOT expanded; both endpoints are appended verbatim so
// validateNATMatchDestinationPortStrict (#3446) still sees and rejects the
// out-of-range value (fail-closed at commit). A valid in-range range expands to
// at most 65535 ints, which the snapshot builder coalesces back into one
// compact wire range (no per-port table entry blow-up).
func appendDNATPortRange(ports []int, low, high int) []int {
	if low < 1 || low > 65535 || high < 1 || high > 65535 {
		return append(ports, low, high)
	}
	for p := low; p <= high; p++ {
		ports = append(ports, p)
	}
	return ports
}

func parseDNATPortList(m *Node) (ports []int, invalid []string, reversed []string) {
	// addReversed records a `<low> to <high>` range whose high < low. The two
	// endpoints are still appended to ports (preserving the pre-#4422 split
	// behaviour so the lenient load / peer-sync path does not change what it
	// installs) — the reversed token drives the strict commit reject only.
	addReversed := func(low, high int) {
		reversed = append(reversed, fmt.Sprintf("%d to %d", low, high))
		ports = append(ports, low, high)
	}
	addInvalid := func(tok string) {
		// `to` is the range keyword; `[`/`]` are bracket-list delimiters that
		// survive into the flat-set SetPath AST as literal tokens. None of these
		// is an operator-entered port value, so they are never reported as an
		// invalid port (only genuine garbage like `http` is).
		switch tok {
		case "to", "[", "]":
			return
		}
		invalid = append(invalid, tok)
	}
	// Unified single-leaf shape (#2419): both the hierarchical parser and
	// the flat-set SetPath now collapse a bracket list or a `low to high`
	// range onto the node's own keys, with NO children:
	//   destination-port [ 80 443 ]        → Keys=[destination-port 80 443]
	//   destination-port 20000 to 20003     → Keys=[destination-port 20000 to 20003]
	// Parse the trailing key tokens directly. A `to` token between two
	// numbers is a range; everything else is an individual port.
	if len(m.Children) == 0 && len(m.Keys) >= 2 {
		vals := m.Keys[1:]
		for i := 0; i < len(vals); i++ {
			low, err := parseCanonicalPort(vals[i])
			if err != nil {
				addInvalid(vals[i])
				continue
			}
			if i+2 < len(vals) && vals[i+1] == "to" {
				if high, err2 := parseCanonicalPort(vals[i+2]); err2 == nil {
					if high >= low {
						ports = appendDNATPortRange(ports, low, high)
					} else {
						addReversed(low, high)
					}
					i += 2
					continue
				}
			}
			ports = append(ports, low)
		}
		return ports, invalid, reversed
	}
	if len(m.Children) > 0 {
		// Check for set-syntax port range: Keys=["destination-port","20000"] + child "to 30000"
		if len(m.Keys) >= 2 {
			if low, err := parseCanonicalPort(m.Keys[1]); err == nil {
				// Look for "to" child indicating a range
				toChild := m.FindChild("to")
				if toChild != nil {
					if high, err2 := parseCanonicalPort(nodeVal(toChild)); err2 == nil {
						if high >= low {
							ports = appendDNATPortRange(ports, low, high)
						} else {
							addReversed(low, high)
						}
						return ports, invalid, reversed
					}
				}
				// No range — just a port with non-range children (shouldn't happen, but be safe)
				ports = append(ports, low)
			} else {
				addInvalid(m.Keys[1])
			}
		}
		// Multiple ports/ranges as children: destination-port { 80; 443; 20000 to 30000; }
		for i := 0; i < len(m.Children); i++ {
			child := m.Children[i]
			low, err := parseCanonicalPort(child.Name())
			if err != nil {
				addInvalid(child.Name())
				continue
			}
			// Hierarchical range: "20000 to 30000" → leaf Keys=["20000", "to", "30000"]
			if len(child.Keys) >= 3 && child.Keys[1] == "to" {
				if high, err2 := parseCanonicalPort(child.Keys[2]); err2 == nil {
					if high >= low {
						ports = appendDNATPortRange(ports, low, high)
					} else {
						addReversed(low, high)
					}
					continue
				}
			}
			// Sibling-node range: child[i]="20000", child[i+1]="to", child[i+2]="30000"
			if i+2 < len(m.Children) && m.Children[i+1].Name() == "to" {
				if high, err2 := parseCanonicalPort(m.Children[i+2].Name()); err2 == nil {
					if high >= low {
						ports = appendDNATPortRange(ports, low, high)
					} else {
						addReversed(low, high)
					}
					i += 2
					continue
				}
			}
			ports = append(ports, low)
		}
	} else if v := nodeVal(m); v != "" {
		// Single port: destination-port 8080;
		if n, err := parseCanonicalPort(v); err == nil {
			ports = append(ports, n)
		} else {
			addInvalid(v)
		}
	}
	return ports, invalid, reversed
}

// staticNATMappedPortFromKeys extracts the `mapped-port <port>` modifier
// from a flat-set static-NAT leaf's collapsed Keys (#2491). The lexer
// collapses `then static-nat prefix <ip> mapped-port <port>` onto one node
// whose Keys are `["static-nat","prefix","<ip>","mapped-port","<port>"]`
// because `static-nat` is a children:nil schema leaf. Returns 0 (no port
// translation) when the keyword is absent or its value is non-numeric;
// the schema does not yet range-check this in-leaf token, so the caller's
// dataplane parse fails closed on an out-of-range value.
func staticNATMappedPortFromKeys(keys []string) int {
	for i := 0; i+1 < len(keys); i++ {
		if keys[i] == "mapped-port" {
			if p, err := strconv.Atoi(keys[i+1]); err == nil {
				return p
			}
			return 0
		}
	}
	return 0
}

// staticNATRoutingInstanceFromKeys scans a collapsed static-nat `then` leaf's
// Keys for the trailing `routing-instance <ri>` translation target (#4292) and
// returns the instance name (or "" when absent). The free-form static-nat leaf
// absorbs the whole `then static-nat <target> routing-instance <ri>` line onto
// one node's Keys in the flat-set shape.
//
// It scans from the END and returns the LAST occurrence, because the Junos
// grammar places the target routing-instance at the TAIL of the line. Scanning
// forward (first match) would return the wrong token if an earlier
// "routing-instance" appeared in the key list — e.g. `then static-nat
// prefix-name routing-instance routing-instance MYVRF`, where the address-book
// entry is pathologically NAMED "routing-instance": first-match would return
// that entry name instead of the trailing "MYVRF". Last-match is strictly more
// correct for the trailing-routing-instance grammar.
func staticNATRoutingInstanceFromKeys(keys []string) string {
	for i := len(keys) - 2; i >= 0; i-- {
		if keys[i] == "routing-instance" {
			return keys[i+1]
		}
	}
	return ""
}

// resolveStaticNATThenPrefixName resolves a `then static-nat prefix-name <name>`
// reference (#4290) to the single literal prefix that names the 1:1 translation
// target. Junos `prefix-name` references a single global address-book entry: an
// `address <name> <prefix>` resolves to its prefix; an `address-set` that
// expands to exactly one address resolves to that address's prefix; anything
// else (undefined, an address with no prefix, an empty / multi-member set,
// dangling) is not a valid scalar 1:1 target and returns ok=false so the caller
// leaves Then=="" and the strict guard rejects it.
func resolveStaticNATThenPrefixName(ab *AddressBook, name string) (string, bool) {
	if ab == nil || name == "" {
		return "", false
	}
	if a, ok := ab.Addresses[name]; ok && a != nil && a.Value != "" {
		return a.Value, true
	}
	if _, ok := ab.AddressSets[name]; ok {
		members, err := ExpandAddressSet(name, ab)
		if err != nil || len(members) != 1 {
			return "", false
		}
		if a, ok := ab.Addresses[members[0]]; ok && a != nil && a.Value != "" {
			return a.Value, true
		}
	}
	return "", false
}

// resolveStaticNATThenPrefixNames resolves every `then static-nat prefix-name`
// reference recorded during compileNATStatic into the rule's literal Then
// target (#4290). It runs AFTER the zone-local address books are folded into the
// global book (compiler.go), so the fully-resolved global book is available
// (compileNAT can run before compileAddressBook within a single `security {}`
// root, so resolution cannot happen inline in the then switch). An unresolvable
// reference leaves Then=="" — validateStaticNATThenTargetStrict then rejects it
// at strict commit (warns on the lenient load / peer-sync path, #1960).
func resolveStaticNATThenPrefixNames(sec *SecurityConfig) {
	ab := sec.AddressBook
	for _, rs := range sec.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.ThenPrefixName == "" || rule.Then != "" {
				continue
			}
			if prefix, ok := resolveStaticNATThenPrefixName(ab, rule.ThenPrefixName); ok {
				rule.Then = prefix
			}
		}
	}
}

// validateStaticNATThenTargetStrict rejects a static-NAT rule that would install
// with an EMPTY translation target (#4290). Two causes both leave Then=="":
//
//   - an unresolvable `then static-nat prefix-name <name>` (undefined /
//     multi-member / prefix-less address-book entry — resolveStaticNATThen-
//     PrefixNames could not fill Then); and
//   - a bare / misspelled `then static-nat` target keyword (a typo the free-form
//     static-nat leaf accepted — the then switch matched no case).
//
// Both previously committed cleanly and installed a static NAT with no
// translation (silent broken 1:1). NPTv6 rules are skipped (their Then holds the
// nptv6 prefix and buildStaticNATSnapshots handles them on a separate path).
// Strict on commit / commit-check (hard reject); the call site downgrades to a
// warning on the tolerant load / peer-sync path (#1960) where the dataplane then
// fails closed (the empty prefix does not parse as an IP → no translation).
// Rule-sets are walked in slice order for a deterministic first error.
func validateStaticNATThenTargetStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.IsNPTv6 || rule.Then != "" {
				continue
			}
			if rule.ThenPrefixName != "" {
				return fmt.Errorf(
					"static NAT rule-set %q rule %q references `then static-nat "+
						"prefix-name %q`, which does not resolve to a single "+
						"address-book prefix (define `security address-book "+
						"global address %s <prefix>`, or fix the name — the "+
						"translation target would otherwise be silently empty "+
						"and the 1:1 NAT would install with no target) (#4290)",
					rs.Name, rule.Name, rule.ThenPrefixName, rule.ThenPrefixName)
			}
			return fmt.Errorf(
				"static NAT rule-set %q rule %q has an empty `then static-nat` "+
					"translation target (an unhandled or misspelled target "+
					"keyword — expected prefix | prefix-name | nptv6-prefix | "+
					"inet) — the rule would otherwise install with no "+
					"translation and silently forward the packet untranslated "+
					"(#4290)",
				rs.Name, rule.Name)
		}
	}
	return nil
}

func compileNATStatic(node *Node, sec *SecurityConfig) error {
	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
		// #3096: capture from scope across zone | interface |
		// routing-instance (static NAT has no `to` clause).
		fromScopes, _ := collectNATScopes(rsInst.node, false)

		// Parse rules (shared across all scope expansions)
		var rules []*StaticNATRule
		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
			rule := &StaticNATRule{Name: ruleInst.name}

			// #3850: iterate EVERY `match {}` block, not just the first — a
			// duplicate block (a `load merge`/`load override` that splits its
			// conditions, or a hierarchical config authored twice) must
			// AND-combine every condition, never be dropped by a FindChild-first
			// read (a fail-open widening of the NAT match). Flat-set is
			// unaffected: SetPath merges duplicate containers into one node
			// (ast_edit.go), so this only changes the hierarchical/parser shape.
			for _, matchNode := range ruleInst.node.FindChildren("match") {
				for _, m := range matchNode.Children {
					switch m.Name() {
					case "destination-address":
						rule.Match = nodeVal(m)
					case "source-address":
						// #3435 (M02): support bracket / repeated lists
						// (`source-address [ a b c ]`) — the schema declares
						// this leaf `multi: true`, so the values collapse onto
						// m.Keys[1:] (flat-set) or m.Children (hierarchical).
						// Reading only nodeVal dropped every prefix after the
						// first. Mirror the source/destination-NAT loops above.
						if len(m.Keys) >= 2 {
							rule.SourceAddresses = append(rule.SourceAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.SourceAddresses = append(rule.SourceAddresses, child.Name())
							}
						}
						if len(rule.SourceAddresses) > 0 {
							// Back-compat: first element stays in the singular
							// field (NAT64 "::/0" tests, peer-sync).
							rule.SourceAddress = rule.SourceAddresses[0]
						}
					case "destination-port":
						// #2491: external (pre-translation) destination
						// port the inbound packet must carry. Schema
						// already range-checks 1..65535; tolerate a
						// non-numeric value defensively (leave 0 = any).
						if p, err := strconv.Atoi(nodeVal(m)); err == nil {
							rule.MatchDestinationPort = p
						}
					}
				}
			}

			// #3850: iterate EVERY `then {}` block, not just the first. A NAT
			// rule carries a single translation action, so a duplicate then
			// block resolves last-wins (Junos merges duplicate stanzas) — the
			// second block's action is applied, never silently dropped. RESET
			// the static-nat target fields at the top of each block so only the
			// LAST block's spec survives (no stale prefix/nptv6/mapped-port from
			// an earlier block). The reset covers ONLY the then-set fields
			// (Then/IsNPTv6/MappedPort) — the match fields (Match/SourceAddress
			// (es)/MatchDestinationPort) are set by the match loop above and MUST
			// persist. A single static-nat then-block is a complete spec, so
			// `prefix X mapped-port P` within one block stays coupled: the reset
			// runs BETWEEN blocks, then the whole block is read (#3850 review).
			for _, thenNode := range ruleInst.node.FindChildren("then") {
				rule.Then = ""
				rule.IsNPTv6 = false
				rule.MappedPort = 0
				// #4290 / #4292: reset the named-target reference and the
				// translation-target routing-instance alongside the other
				// then-set fields so only the LAST then-block's spec survives.
				rule.ThenPrefixName = ""
				rule.ThenRoutingInstance = ""
				for _, t := range thenNode.Children {
					if t.Name() == "static-nat" {
						if len(t.Keys) >= 3 && t.Keys[1] == "nptv6-prefix" {
							// set ... then static-nat nptv6-prefix PREFIX
							rule.Then = t.Keys[2]
							rule.IsNPTv6 = true
						} else if np := t.FindChild("nptv6-prefix"); np != nil {
							// static-nat { nptv6-prefix { PREFIX; } }
							rule.Then = nodeVal(np)
							rule.IsNPTv6 = true
						} else if len(t.Keys) >= 3 && t.Keys[1] == "prefix-name" {
							// #4290: set ... then static-nat prefix-name NAME.
							// The named form of `prefix <ip>`: NAME references a
							// global address-book entry whose literal prefix is
							// the 1:1 translation target. Recorded raw here and
							// resolved into rule.Then post-address-book-fold by
							// resolveStaticNATThenPrefixNames (the book may not
							// be compiled yet at this point). Before #4290 this
							// keyword fell through, leaving Then=="" (empty
							// translation target, silent broken static NAT).
							rule.ThenPrefixName = t.Keys[2]
						} else if pn := t.FindChild("prefix-name"); pn != nil {
							// static-nat { prefix-name NAME; }
							rule.ThenPrefixName = nodeVal(pn)
						} else if len(t.Keys) >= 3 && t.Keys[1] == "prefix" {
							rule.Then = t.Keys[2]
							// #2491: optional trailing `mapped-port <port>`.
							// Flat-set collapses the whole `prefix <ip>
							// mapped-port <port>` onto this one leaf's Keys
							// (`static-nat` is a children:nil schema leaf), so
							// scan for the keyword + value pair.
							rule.MappedPort = staticNATMappedPortFromKeys(t.Keys)
						} else if pn := t.FindChild("prefix"); pn != nil {
							rule.Then = nodeVal(pn)
							// #2491: `then static-nat prefix <ip> mapped-port
							// <port>` collapses onto the `prefix` child's Keys
							// (`["prefix","<ip>","mapped-port","<port>"]`)
							// because `static-nat` is a children:nil schema
							// leaf, so the modifier rides on the prefix leaf,
							// not a sibling `mapped-port` node. Scan pn.Keys.
							rule.MappedPort = staticNATMappedPortFromKeys(pn.Keys)
							// Hierarchical shape `static-nat { prefix X;
							// mapped-port P; }` carries it as a sibling child.
							if rule.MappedPort == 0 {
								if mp := t.FindChild("mapped-port"); mp != nil {
									if p, err := strconv.Atoi(nodeVal(mp)); err == nil {
										rule.MappedPort = p
									}
								}
							}
						} else if t.FindChild("inet") != nil || (len(t.Keys) >= 2 && t.Keys[1] == "inet") {
							// static-nat { inet; } — NAT64 translation
							rule.Then = "inet"
						}
						// #4292: a translation-target `routing-instance <ri>`
						// may trail ANY of the targets above (Junos allows it on
						// inet and prefix). It rides on the free-form static-nat
						// leaf in one of three AST shapes: collapsed onto t.Keys
						// (["static-nat","prefix","<ip>","routing-instance",
						// "<ri>"]); on the TARGET child leaf's Keys (the common
						// flat-set shape — static-nat has a `prefix`/`inet` child
						// whose Keys carry the trailing routing-instance pair); or
						// as a distinct sibling `routing-instance` child. Captured
						// for the accepted-but-unenforced advisory; the dataplane
						// does not route the post-translation packet against a
						// non-ingress table.
						if ri := staticNATRoutingInstanceFromKeys(t.Keys); ri != "" {
							rule.ThenRoutingInstance = ri
						} else if riNode := t.FindChild("routing-instance"); riNode != nil {
							rule.ThenRoutingInstance = nodeVal(riNode)
						} else {
							for _, c := range t.Children {
								if ri := staticNATRoutingInstanceFromKeys(c.Keys); ri != "" {
									rule.ThenRoutingInstance = ri
									break
								}
							}
						}
					}
				}
			}

			rules = append(rules, rule)
		}

		// Expand for each from-scope (#3096).
		for _, fs := range fromScopes {
			rs := &StaticNATRuleSet{
				Name:  rsInst.name,
				Rules: rules,
			}
			applyStaticNATFromScope(rs, fs)
			sec.NAT.Static = append(sec.NAT.Static, rs)
		}
	}
	return nil
}
