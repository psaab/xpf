package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
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

// natRuleSetChildren returns the effective children of a NAT rule-set node,
// expanding a scope tail packed onto its header
// (`rule-set RS from zone trust { rule ... }`, #14421). The braced spelling
// returns node.Children unchanged. packedBodyChildren cannot be used here:
// the packed `from zone trust` tail runs through the multi-valued `zone`
// leaf, whose terminal declares no body, so packedBodyChildren returns the
// real children unexpanded (#6818 guard) and the scope stays invisible.
// Instead the tail is consumed with the grammar's own arity — `from`/`to`
// (no args) then a scope kind (args:1, multi) then one value per scope —
// terminated at `rule` or end-of-tail, and each scope value is synthesised
// as the clause child parseNATMatchScopes already reads
// (Keys=[from, <kind>, <value>]). Bracket lists reach here already collapsed
// onto Keys (TokensBracketed is not retained by the hierarchical parser), so
// a multi-value packed clause reads as multiple scopes of one kind — the
// same OR the braced bracket list produces; mixed kinds in the tail are
// still caught by the mixed-scope gate because every synthesised clause is
// returned. A `rule` tail is left in the real children (the compilers read
// rules from rsNode directly, never through this helper). An unmodelled tail
// returns the real children unchanged — never guess.
func natRuleSetChildren(rsNode *Node, natKind string) []*Node {
	if rsNode == nil || len(rsNode.Keys) < 2 {
		return nodeChildren(rsNode)
	}
	_ = natKind
	tail := instanceValueTail(rsNode, rsNode.Keys[1])
	if len(tail) == 0 || (tail[0] != "from" && tail[0] != "to") {
		return rsNode.Children
	}
	out := append([]*Node(nil), rsNode.Children...)
	for len(tail) > 0 {
		clause := tail[0]
		if clause != "from" && clause != "to" {
			return rsNode.Children
		}
		if len(tail) == 2 {
			base := len(rsNode.Keys) - len(tail)
			if base+1 < len(rsNode.Keys) && base+1 < len(rsNode.KeysBracketed) && rsNode.KeysBracketed[base+1] {
				out = append(out, &Node{Keys: []string{clause, tail[1], ""}, InheritedFrom: rsNode.InheritedFrom})
				tail = nil
				continue
			}
			return rsNode.Children
		}
		if len(tail) < 3 {
			return rsNode.Children
		}
		kind := tail[1]
		known := false
		for _, k := range natScopeKinds {
			if k == kind {
				known = true
				break
			}
		}
		if !known {
			return rsNode.Children
		}
		values := tail[2:]
		n := 0
		for n < len(values) && values[n] != "from" && values[n] != "to" && values[n] != "rule" {
			n++
		}
		if n == 0 {
			return rsNode.Children
		}
		for _, v := range values[:n] {
			out = append(out, &Node{Keys: []string{clause, kind, v}, InheritedFrom: rsNode.InheritedFrom})
		}
		tail = values[n:]
	}
	if len(out) == len(rsNode.Children) {
		return rsNode.Children
	}
	return out
}

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
// rule-set node into from/to scope lists. It injects the match-any default
// ({kind:"zone", value:""}) only for an absent clause; a present clause that
// contains no non-empty scope stays empty so it cannot widen to match-any.
// #3096.
//
// natKind (source|destination|static) is accepted for call-site symmetry
// with the gates; the packed-header expansion is kind-independent.
func collectNATScopes(rsNode *Node, wantTo bool, natKind ...string) (fromScopes, toScopes []natMatchScope) {
	kind := ""
	if len(natKind) > 0 {
		kind = natKind[0]
	}
	fromPresent, toPresent := false, false
	for _, child := range natRuleSetChildren(rsNode, kind) {
		switch child.Name() {
		case "from":
			fromPresent = true
			fromScopes = append(fromScopes, parseNATMatchScopes(child)...)
		case "to":
			if wantTo {
				toPresent = true
				toScopes = append(toScopes, parseNATMatchScopes(child)...)
			}
		}
	}
	if !fromPresent {
		fromScopes = []natMatchScope{{kind: "zone", value: ""}}
	}
	if wantTo && !toPresent {
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
		if s.value == "" {
			rs.fromUnscopedStamped = true
		}
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
		if s.value == "" {
			rs.toUnscopedStamped = true
		}
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
			switch {
			case errors.Is(err, errNATAddressRangeTooLarge):
				// #8814: RECORD rather than fail (see OversizedAddressRanges).
				pool.OversizedAddressRanges = append(pool.OversizedAddressRanges,
					fmt.Sprintf("%s to %s: %v", tok, tokens[i+2], err))
			case err != nil:
				// #15674: RECORD rather than fail. A hard error here also
				// reaches the LENIENT path (no compileOpts in this chain),
				// so a persisted malformed/reversed/non-host-mask range
				// bricked boot. Record it; strict rejects, lenient warns,
				// and the pool loads without that range.
				pool.InvalidAddressRanges = append(pool.InvalidAddressRanges,
					fmt.Sprintf("%s to %s: %v", tok, tokens[i+2], err))
			default:
				pool.Addresses = append(pool.Addresses, expanded...)
			}
			i += 3
			continue
		}
		pool.Addresses = append(pool.Addresses, tok)
		i++
	}
	return nil
}

// errNATAddressRangeTooLarge marks the expandAddressRange failure that is a
// SIZE limit rather than a malformed input (#8814). The cap stays here: the
// widest spelling would otherwise allocate billions of strings on the
// lenient boot path. Only the ERROR became a recordable fact.
var errNATAddressRangeTooLarge = errors.New("address range too large")

// parseRangeEndpoint parses one range endpoint: a bare IP or a host prefix
// (/32 for IPv4, /128 for IPv6). Any other explicit prefix length is
// rejected (#15674): previously net.ParseCIDR discarded the mask and the
// endpoint was silently rewritten to a /32 host. IPv6 support itself
// landed via #15677 on master; this keeps the host-mask validation.
func parseRangeEndpoint(s string) (netip.Addr, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("invalid address %q: %w", s, err)
		}
		addr := p.Addr()
		want := 128
		if addr.Is4() {
			want = 32
		}
		if p.Bits() != want {
			return netip.Addr{}, fmt.Errorf(
				"address %q has non-host prefix length /%d; range endpoints must be bare IPs or /%d",
				s, p.Bits(), want)
		}
		return addr, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid address %q: %w", s, err)
	}
	return addr, nil
}

// expandAddressRange expands "low to high" into individual host strings
// (/32 for IPv4, /128 for IPv6). Endpoints must be bare IPs or host
// prefixes of the same family. Max 256 IPs; a larger range returns
// errNATAddressRangeTooLarge.
func expandAddressRange(low, high string) ([]string, error) {
	lowAddr, err := parseRangeEndpoint(low)
	if err != nil {
		return nil, err
	}
	highAddr, err := parseRangeEndpoint(high)
	if err != nil {
		return nil, err
	}
	if lowAddr.Is4() != highAddr.Is4() {
		return nil, fmt.Errorf("address range endpoints %q and %q are different address families", low, high)
	}
	if highAddr.Compare(lowAddr) < 0 {
		return nil, fmt.Errorf("low address %s > high address %s", low, high)
	}
	// Count: IPv4 via uint32 subtraction in uint64 (#5194 wrap guard);
	// IPv6 via successive Next() steps bounded by the cap (no 128-bit
	// subtraction). The exact count is reported for IPv4 so the recorded
	// oversized spec carries the size (#8814 test contract).
	var count uint64
	if lowAddr.Is4() {
		l4, h4 := lowAddr.As4(), highAddr.As4()
		lo := uint64(l4[0])<<24 | uint64(l4[1])<<16 | uint64(l4[2])<<8 | uint64(l4[3])
		hi := uint64(h4[0])<<24 | uint64(h4[1])<<16 | uint64(h4[2])<<8 | uint64(h4[3])
		count = hi - lo + 1
		if count > 256 {
			return nil, fmt.Errorf("%w: %d IPs (max 256)", errNATAddressRangeTooLarge, count)
		}
	} else {
		count = 1
		for cur := lowAddr; cur != highAddr; {
			cur = cur.Next()
			count++
			if count > 256 {
				return nil, fmt.Errorf("%w: more than 256 IPs (max 256)", errNATAddressRangeTooLarge)
			}
		}
	}
	suffix := "/128"
	if lowAddr.Is4() {
		suffix = "/32"
	}
	result := make([]string, 0, count)
	for cur := lowAddr; ; cur = cur.Next() {
		result = append(result, cur.String()+suffix)
		if cur == highAddr {
			break
		}
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
//
// #7481: the "mirrors the Rust parser EXACTLY" claim this comment used to make
// was FALSE, and it was asserted by prose rather than by a test. One Go
// predicate was said to mirror two structurally different Rust
// implementations — source/mod.rs's IpNet/IpAddr path and static_nat.rs's
// hand-rolled splitn + u8::from_str. They disagreed on `/+24` and on `/024`,
// and so did the Go gate.
//
// The agreement is now asserted by a shared-corpus differential
// (testdata/nat_match_prefix_corpus.txt, read by BOTH languages' tests) rather
// than by this comment. A comment cannot fail.
func natMatchPrefixParses(raw string) bool {
	// #7481: NORMALIZE the prefix-length spelling before parsing, so every end
	// of the stack answers the same way.
	//
	// Three parsers, three different tolerances, measured over one corpus:
	//
	//	literal            Go ParseCIDR   ipnet::IpNet   u8::from_str
	//	10.0.0.0/024       accept         REJECT         accept
	//	2001:db8::/064     accept         ACCEPT         accept
	//	2001:db8::/0064    accept         reject         accept
	//	10.0.0.0/+24       reject         reject         ACCEPT
	//
	// `ipnet` disagrees with ITSELF across address families on zero padding —
	// v6 takes a three-digit `064`, v4 refuses `024`. Nobody would choose that;
	// it is an artifact of two parse paths inside a dependency.
	//
	// NORMALIZE RATHER THAN REJECT, and that is a deliberate reversal. Rejecting
	// the odd spellings is the reject-only direction and would normally win —
	// but #7145's test says plainly why it does not here: a box committed with
	// `match source-address 1.2.3.4/024` is forwarding today (static NAT
	// installs it), and a widened validator that refuses a working value bricks
	// that operator's next commit (#1960). Both spellings are UNAMBIGUOUS —
	// `/+24`, `/024` and `/0024` can only mean 24 — so normalizing loses no
	// information and there is no wrong interpretation to pick.
	//
	// The danger was never the spelling. It was the DISAGREEMENT: `/024`
	// committed clean here and was then dropped by parse_match_prefix, leaving a
	// NAT rule that matched nothing. Agreement removes that whether the shared
	// answer is accept or reject; accept is the one that bricks nobody.
	raw = normalizeNATPrefixLen(raw)
	if _, _, err := net.ParseCIDR(raw); err == nil {
		return true
	}
	return net.ParseIP(raw) != nil
}

// normalizeNATPrefixLen rewrites a tolerated prefix-length spelling to its
// canonical decimal form (#7481): a leading `+` is dropped and leading zeros
// are stripped, so `/+24`, `/024` and `/0024` all become `/24`.
//
// Its Rust twin is nat::normalize_nat_prefix_len, and
// testdata/nat_match_prefix_corpus.txt is the shared corpus that binds the two.
// A leading `-` is left alone: a negative prefix length is not a tolerated
// spelling of anything, and every parser refuses it.
func normalizeNATPrefixLen(raw string) string {
	i := strings.IndexByte(raw, '/')
	if i < 0 {
		return raw // bare host address; no prefix length to normalize
	}
	addr, mask := raw[:i+1], raw[i+1:]
	mask = strings.TrimPrefix(mask, "+")
	// Strip leading zeros but keep the last digit, so "/0" survives as "0"
	// rather than becoming empty.
	for len(mask) > 1 && mask[0] == '0' {
		mask = mask[1:]
	}
	return addr + mask
}

// NATMatchPrefixParses exposes natMatchPrefixParses so the userspace snapshot
// builders can bind their own per-entry skip predicate to this one in a TEST
// rather than by comment.
//
// #7215 is what that binding is for. validateDestinationNATAddressesStrict
// carried a comment promising its acceptance "MUST match the builder's exactly"
// and then drifted from dnatDestinationParts for six years' worth of mask
// spellings — it stripped the mask text before parsing, so `10.0.0.0/33`
// committed clean and the builder silently discarded it. A comment cannot fail;
// a differential over both predicates can. See natMatchPrefixParses and
// pkg/dataplane/userspace/nat_destination.go.
func NATMatchPrefixParses(raw string) bool { return natMatchPrefixParses(raw) }

// NormalizeNATPrefixLen exposes normalizeNATPrefixLen so every consumer of the
// NAT match-prefix grammar applies the SAME normalization (#7481) — the commit
// gate, the Go snapshot builders, and (via nat::normalize_nat_prefix_len) both
// Rust parsers.
//
// It is exported for the same reason NATMatchPrefixParses is: the alternative
// is each consumer re-deriving the tolerance and the set of accepted spellings
// drifting, which is exactly what #7481 found across three implementations.
func NormalizeNATPrefixLen(raw string) string { return normalizeNATPrefixLen(raw) }

// appendNATUnknownMatchLeaf records a `match` child keyword the NAT match
// switches do not read (#9877). First-seen order with dedupe: the switches
// iterate EVERY `match` block (#3850), so a repeated unknown leaf would
// otherwise record (and warn) twice. The lists are tiny; a linear scan is
// cheaper than a set.
func appendNATUnknownMatchLeaf(leaves []string, keyword string) []string {
	for _, l := range leaves {
		if l == keyword {
			return leaves
		}
	}
	return append(leaves, keyword)
}

// natMatchLeafKnown reports whether head is a modeled `match` leaf for a NAT
// direction ("source", "destination" or "static") — navigating the SAME
// schema map the compact normalizer consults before unfolding a packed tail
// (compact_normalize_8662.go:142), so the two can never disagree on which
// heads unfold. A packed head outside this map never unfolds and would
// otherwise escape every match switch; a modeled head with a packed tail is
// a deliberately declined fold (#8880), not an unknown leaf.
//
// Direct children-map access, no wildcard fallback: every keyword on this
// path is a literal schema child, and a wildcard descent could only
// misattribute. A failed lookup reports false (record): the suite's compact
// fixtures would catch a broken path immediately.
func natMatchLeafKnown(direction, head string) bool {
	node := setSchema
	for _, kw := range []string{"security", "nat", direction, "rule-set", "rule", "match"} {
		if node == nil {
			return false
		}
		node = node.children[kw]
	}
	if node == nil {
		return false
	}
	_, ok := node.children[head]
	return ok
}
