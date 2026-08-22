package config

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

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

// NATAddrFamily exposes natAddrFamily to the shared control-plane NAT query
// package (pkg/nat), so the forensic deterministic-NAT forward/reverse lookup
// classifies pool and prefix addresses with the SAME colon-strict Go/Rust
// parity rule the commit gate uses — never Go's net.IP.To4(), which folds an
// IPv4-mapped literal and diverges from the Rust dataplane parsers. See
// natAddrFamily.
func NATAddrFamily(ipPart string) string { return natAddrFamily(ipPart) }

// NATCIDRIPPart exposes natCIDRIPPart so the same shared package can strip a
// CIDR mask before the textual family classification. See natCIDRIPPart.
func NATCIDRIPPart(cidr string) string { return natCIDRIPPart(cidr) }

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
	// #5194 A3-b2-F9: compute the inclusive count in uint64. In uint32 the
	// full-domain range 0.0.0.0-255.255.255.255 has highN-lowN == 0xFFFFFFFF and
	// +1 WRAPS to 0, so the `> 256` guard passed, the generation loop ran zero
	// times, and the oversized range committed as an EMPTY pool with nil error
	// instead of the promised size error.
	count := uint64(highN) - uint64(lowN) + 1
	if count > 256 {
		return nil, fmt.Errorf("address range too large: %d IPs (max 256)", count)
	}
	var result []string
	buf := make(net.IP, 4)
	// count is bounded by 256 here, so the uint32 loop bound cannot wrap.
	for i := uint32(0); i < uint32(count); i++ {
		binary.BigEndian.PutUint32(buf, lowN+i)
		result = append(result, buf.String()+"/32")
	}
	return result, nil
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
				// A deterministic CGNAT block-size must be positive; the
				// strict commit gate rejects <= 0, but the lenient/tolerant
				// load path (#1960) would otherwise retain a negative Atoi
				// result. Guard the parse so a non-positive value is ignored
				// rather than stored (#5250 A3-b1 b1-F1).
				if n, err := strconv.Atoi(keys[i+1]); err == nil && n > 0 {
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
				// See applyDeterministicKeys: reject a non-positive block-size
				// on the lenient path rather than storing it (#5250 A3-b1 b1-F1).
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
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

// natMatchPrefixParses mirrors the Rust NAT match-prefix parser EXACTLY, so
// "accepted at commit" and "installed at runtime" cannot diverge for a NAT
// rule's literal `match source-address` / `match destination-address` values.
//
// Those values reach the wire VERBATIM — the Go snapshot builders copy the
// list without filtering (pkg/dataplane/userspace/nat_source.go,
// nat_destination.go, nat_static.go) — and all three Rust consumers parse each
// entry the same way:
//
//   - source NAT:      parse_match_prefix (userspace-dp/src/nat/source.rs)
//   - destination NAT: DnatTable::from_snapshots (nat/destination.rs)
//   - static NAT:      SourceConstraint::from_list (nat/static_nat.rs)
//
// Each tries `IpNet::from_str` first (a CIDR, host bits permitted) and falls
// back to `IpAddr::from_str` (a bare host IP, promoted to /32 or /128). An
// entry that satisfies neither is DROPPED from the match set.
//
// The Go mirror is net.ParseCIDR then net.ParseIP, chosen over the netip
// equivalents because netip.ParsePrefix is STRICTER than Rust on the mask
// text: it rejects a zero-padded prefix length (`1.2.3.4/024`) that Rust's
// `u8::from_str` accepts as 24, so a netip-based gate would reject a value the
// dataplane installs — the one direction a widened validator must never take
// (#1960 no-brick). net.ParseIP is likewise the right bare-host mirror because
// it rejects a zone-suffixed literal (`fe80::1%eth0`) exactly as Rust's
// `IpAddr::from_str` does, where netip.ParseAddr would accept it.
//
// An empty value returns false: an empty entry is not a prefix, it still
// leaves the match list NON-empty, and the Rust `*_constrained` flag is keyed
// on list length — so an empty entry narrows the rule (or, alone, makes it
// match nothing) exactly like any other unparseable one.
func natMatchPrefixParses(raw string) bool {
	if _, _, err := net.ParseCIDR(raw); err == nil {
		return true
	}
	return net.ParseIP(raw) != nil
}
