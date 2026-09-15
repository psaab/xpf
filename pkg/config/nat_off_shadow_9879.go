package config

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Shared "is this DNAT `off` exemption partially shadowed?" predicate (#9879).
//
// A `then destination-nat off` exemption short-circuits only the match tiers
// probed AFTER it: the dataplane resolves DNAT by most-specific match, NOT by
// rule order (userspace-dp/src/nat/destination.rs, MOST-SPECIFIC-WINS). So a
// BROAD `off` configured BEFORE a NARROWER later translate rule loses for the
// overlapping subspace — the "exempted" traffic is translated anyway, with a
// clean commit and no warning (fail-open).
//
// The fix is visibility, not a dataplane reordering (the tiered hash buys O(1)
// lookup — the HPC constraint): the commit gate rejects the losing shape on the
// strict path and warns on the lenient path, and the show surface annotates the
// shadowed `off` rule. BOTH consumers call DNATOffShadowReason, so the gate and
// the annotation cannot disagree about which rules are shadowed (the #6534
// single-predicate shape). The annotation is a PARTIALLY SHADOWED warning, not
// a NOT INSTALLED exclusion: the `off` entry IS installed and still exempts the
// non-overlapping remainder — claiming NOT INSTALLED would promise fall-through
// that does not happen.
//
// SCOPE (deliberately narrow; anything uncertain skips rather than fires, so
// the gate cannot false-reject):
//
//   - Same rule-set only, off-before-translate in configured rule order. Pairs
//     across rule-sets also compete in the merged table when their from-scopes
//     overlap, but modeling zone/interface/RI overlap plus the within-tier
//     zone-specific-first rule is a follow-up.
//   - Literal addresses only. Either side using an address-book name (source or
//     destination) skips: name resolution needs the feed overlay the gate does
//     not carry.
//   - No `match application` on either side. Application terms expand to
//     protocol/port/source-port/ICMP constraints in the builder; resolving that
//     expansion here would reimplement the builder.
//   - Valid ports only. InvalidDestinationPorts / ReversedDestinationPortRanges
//     (rejected elsewhere on strict; split-endpoint installs on lenient) skip.
//   - Both rules installed. An `off` or translate rule the builder drops
//     (DestinationNATRuleExcludedReason — unknown #9877 leaves, undefined or
//     invalid pool, empty match) installs nothing and cannot shadow or be
//     shadowed; such pairs skip. In particular a translate rule that is NOT
//     INSTALLED never yields a "TRANSLATED" claim.
//
// TRUE PROBE ORDER (review-hardened; an earlier revision compared tiers
// pairwise and was wrong in both directions). The Rust lookup probes buckets
// in this order — exact-host (proto,port), (proto,0), (PROTO_ANY,0), then the
// same three for prefixes — so the rank tuple is lexicographic:
//
//	destClass (host > prefix) > port (exact > wildcard/range) >
//	proto (pinned > ANY) > prefixLen (longer > shorter)
//
// Consequences the pairwise model got wrong and the witness search gets
// right: an exact-port bucket beats a wildcard-port bucket even when the
// wildcard side has the longer prefix (a /24 exact-port `off` HOLDS against a
// /26 wildcard-port translate); and EVERY host tier precedes EVERY prefix
// tier (an any-protocol HOST translate beats a pinned-protocol PREFIX `off`).
// Equal ranks tie to config order (the `off` is first, so it holds).
//
// SOUNDNESS (GPT-2): the predicate fires only on an explicit WITNESS FLOW —
// a concrete (destination, protocol, port, source) verified against EVERY
// emitted entry of BOTH rules, with the translate side's best matching entry
// strictly outranking the exemption's best. A rule with several destinations
// (e.g. an exemption carrying both a prefix and its contained host) is
// evaluated by its best entry for the witness, never by its weakest cell, so
// a same-tier host entry that holds is never overruled by a weaker prefix
// cell. Picking heuristics affect completeness only (a missed witness is a
// miss, never a false fire); verification is exact.
//
// The tier model mirrors the snapshot builder (pkg/dataplane/userspace/
// nat_destination.go) and the Rust table exactly:
//
//   - A port-constrained rule with no pinned protocol installs TCP+UDP rows
//     (#6462); an unconstrained any-protocol rule installs the single PROTO_ANY
//     row. A multi-port run installs ONE wildcard-port row with a range
//     constraint (#3449), i.e. the SAME tier as a plain wildcard.
//   - Protocol tokens compare case-insensitively after trim; two NUMERIC tokens
//     compare by value. A name-vs-number spelling of one protocol ("tcp" vs
//     "6") is treated as disjoint (a miss, never a false fire): unifying them
//     needs the pkg/appid SSOT, which imports this package.
//   - An unresolvable pinned protocol is dropped from the rule's set, mirroring
//     the Rust `None => continue` backstop (destination.rs `from_snapshots`);
//     a rule left with no installable protocol installs nothing and skips. The
//     strict #2396(a) gate rejects such a rule before this one runs, so the
//     drop only matters on the lenient path.

// DNATOffShadowReason reports why a destination-NAT `off` rule is PARTIALLY
// SHADOWED — the later narrower translate rule that re-enters its exempted
// match space — or "" when the rule is not a shadowed exemption.
//
// Callers: validateDNATOffShadowStrict (the commit gate) and
// natshow.RenderDestRuleDetail (the show annotation). A nil rule, a non-`off`
// rule, a rule that installs nothing, a not-installed translate candidate,
// and any pair outside the documented scope all report "".
func DNATOffShadowReason(dnat *DestinationNATConfig, rs *NATRuleSet, rule *NATRule) string {
	if dnat == nil || rs == nil || rule == nil {
		return ""
	}
	if rule.Then.Type != NATDestination || !rule.Then.Off {
		return ""
	}
	if rule.LenientMatchDropped {
		return ""
	}
	if DestinationNATRuleExcludedReason(dnat, rule) != "" {
		return ""
	}
	offIdx := -1
	for i, r := range rs.Rules {
		if r == rule {
			offIdx = i
			break
		}
	}
	if offIdx < 0 {
		return ""
	}
	off, ok := dnatOffShadowShape(rule)
	if !ok {
		return ""
	}
	for _, tr := range rs.Rules[offIdx+1:] {
		if tr == nil || tr.Then.Off || tr.Then.PoolName == "" {
			continue
		}
		if tr.LenientMatchDropped {
			continue
		}
		if DestinationNATRuleExcludedReason(dnat, tr) != "" {
			continue
		}
		trShape, ok := dnatOffShadowShape(tr)
		if !ok {
			continue
		}
		if detail, hit := dnatOffShadowWitness(off, trShape); hit {
			return fmt.Sprintf("later translate rule %q in this rule-set re-enters "+
				"the exempted space (%s): matching traffic is TRANSLATED, not "+
				"exempted (#9879)", tr.Name, detail)
		}
	}
	return ""
}

// dnatOffNet is one parsed literal destination or source: a host or a prefix.
type dnatOffNet struct {
	raw    string // original literal, for messages
	ip     net.IP
	prefix *net.IPNet // nil for a host
	host   bool
	v6     bool // colon-strict family (natAddrFamily), the Go/Rust parity rule
}

// dnatOffPorts is a rule's destination-port match as EMITTED cells: discrete
// exact ports, multi-port runs (wildcard-keyed with a range constraint, #3449),
// and/or a genuine no-port wildcard cell.
type dnatOffPorts struct {
	exacts []int
	ranges [][2]int
	wild   bool
}

// dnatOffShape is the gate's model of one DNAT rule's match, in emitted terms.
type dnatOffShape struct {
	dests []dnatOffNet
	srcs  []dnatOffNet // empty = unconstrained (match any source)
	// protos holds canonical pinned protocols ("s:tcp" or "n:6"); anyProto is
	// the PROTO_ANY wildcard (only when no protocol is pinned).
	protos   []string
	anyProto bool
	ports    dnatOffPorts
}

// dnatOffShadowShape parses a rule's match into emitted terms, reporting false
// for any shape outside the gate's scope or that installs nothing (both skip
// rather than fire).
func dnatOffShadowShape(rule *NATRule) (dnatOffShape, bool) {
	var s dnatOffShape
	// Out of scope: application matches and address-book names (see file doc).
	if len(rule.Match.ApplicationList()) > 0 {
		return s, false
	}
	if len(rule.Match.SourceAddressNameList()) > 0 || len(rule.Match.DestinationAddressNameList()) > 0 {
		return s, false
	}
	if len(rule.Match.InvalidDestinationPorts) > 0 || len(rule.Match.ReversedDestinationPortRanges) > 0 {
		return s, false
	}
	ports, ok := dnatOffCoalescePorts(rule.Match)
	if !ok {
		return s, false
	}
	s.ports = ports
	dests := append([]string(nil), rule.Match.DestinationAddresses...)
	if len(dests) == 0 && rule.Match.DestinationAddress != "" {
		dests = append(dests, rule.Match.DestinationAddress)
	}
	if len(dests) == 0 {
		return s, false
	}
	for _, d := range dests {
		n, ok := dnatOffParseNet(d)
		if !ok {
			return s, false
		}
		s.dests = append(s.dests, n)
	}
	srcs := append([]string(nil), rule.Match.SourceAddresses...)
	if len(srcs) == 0 && rule.Match.SourceAddress != "" {
		srcs = append(srcs, rule.Match.SourceAddress)
	}
	for _, src := range srcs {
		n, ok := dnatOffParseNet(src)
		if !ok {
			return s, false
		}
		s.srcs = append(s.srcs, n)
	}
	protos, anyProto, ok := dnatOffProtos(rule.Match.ProtocolList(), portsConstrained(ports))
	if !ok {
		return s, false
	}
	s.protos = protos
	s.anyProto = anyProto
	return s, true
}

// dnatOffParseNet classifies one literal as a host or a prefix, mirroring the
// builder's dnatDestinationParts host-vs-prefix split (bare IP or /32//128 is
// a host; any other CIDR is a prefix). ok is false for anything unparseable.
func dnatOffParseNet(raw string) (dnatOffNet, bool) {
	var n dnatOffNet
	n.raw = raw
	n.v6 = natAddrFamily(natCIDRIPPart(raw)) == "v6"
	norm := NormalizeNATPrefixLen(raw)
	if strings.IndexByte(norm, '/') == -1 {
		ip := net.ParseIP(norm)
		if ip == nil {
			return n, false
		}
		n.ip = ip
		n.host = true
		return n, true
	}
	ip, ipNet, err := net.ParseCIDR(norm)
	if err != nil {
		return n, false
	}
	ones, bits := ipNet.Mask.Size()
	if ones == bits {
		n.ip = ip
		n.host = true
		return n, true
	}
	n.ip = ipNet.IP
	n.prefix = ipNet
	return n, true
}

// dnatOffCoalescePorts mirrors userspace.coalescePortRanges (sort, dedup,
// run-merge over the valid 1..65535 values) and then splits runs into exact
// cells (single port) and wildcard-keyed range cells (#3449). ok is false when
// the rule configured ports but none are representable (the builder emits no
// snapshot for the term — the rule installs nothing).
func dnatOffCoalescePorts(m NATMatch) (dnatOffPorts, bool) {
	var p dnatOffPorts
	ports := append([]int(nil), m.DestinationPorts...)
	if len(ports) == 0 && m.DestinationPort != 0 {
		ports = append(ports, m.DestinationPort)
	}
	if len(ports) == 0 {
		p.wild = true
		return p, true
	}
	seen := make(map[int]struct{}, len(ports))
	uniq := make([]int, 0, len(ports))
	for _, v := range ports {
		if v < 1 || v > 65535 {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		uniq = append(uniq, v)
	}
	if len(uniq) == 0 {
		return p, false
	}
	sort.Ints(uniq)
	lo, hi := uniq[0], uniq[0]
	flush := func() {
		if lo == hi {
			p.exacts = append(p.exacts, lo)
		} else {
			p.ranges = append(p.ranges, [2]int{lo, hi})
		}
	}
	for _, v := range uniq[1:] {
		if v == hi+1 {
			hi = v
			continue
		}
		flush()
		lo, hi = v, v
	}
	flush()
	return p, true
}

// portsConstrained reports whether the coalesced ports constrain the port axis
// at all (any exact or range cell). A genuine wildcard does not — it is what
// keeps an any-protocol rule on the PROTO_ANY row instead of expanding to
// TCP+UDP (#6462).
func portsConstrained(p dnatOffPorts) bool {
	return len(p.exacts) > 0 || len(p.ranges) > 0
}

// dnatOffProtos resolves a rule's pinned protocols to canonical tokens,
// dropping unresolvable ones exactly where the Rust table drops their entries
// (`None => continue`). ok is false when the rule pinned protocols but none
// resolve (it installs nothing). An unpinned rule expands to TCP+UDP when
// port-constrained (#6462) and stays PROTO_ANY otherwise.
func dnatOffProtos(tokens []string, constrained bool) ([]string, bool, bool) {
	if len(tokens) == 0 {
		if constrained {
			return []string{"s:tcp", "s:udp"}, false, true
		}
		return nil, true, true
	}
	seen := make(map[string]struct{}, len(tokens))
	var out []string
	for _, t := range tokens {
		norm := strings.ToLower(strings.TrimSpace(t))
		if !dnatProtocolResolvable(norm) {
			continue
		}
		canon := "s:" + norm
		if n, err := strconv.Atoi(norm); err == nil {
			canon = "n:" + strconv.Itoa(n)
		}
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		out = append(out, canon)
	}
	if len(out) == 0 {
		return nil, false, false
	}
	sort.Strings(out)
	return out, false, true
}

// dnatOffPortCell is one emitted port cell: an exact port, a multi-port run
// (wildcard-keyed), or the genuine wildcard.
type dnatOffPortCell struct {
	exact int // >0 for an exact-port cell
	lo    int // range low (valid when exact==0 && !wild)
	hi    int // range high (valid when exact==0 && !wild)
	wild  bool
}

// dnatOffEntry is one emitted (destination x protocol x port) cell — one row
// the builder would install and the Rust table would probe.
type dnatOffEntry struct {
	dest  dnatOffNet
	proto string // "*" for PROTO_ANY, else a canonical pinned token
	port  dnatOffPortCell
}

// dnatOffEntries expands a shape to its emitted entries (Cartesian product,
// exactly as the builder emits per destination x protocol x port range).
func dnatOffEntries(s dnatOffShape) []dnatOffEntry {
	protos := s.protos
	if s.anyProto {
		protos = []string{"*"}
	}
	var cells []dnatOffPortCell
	for _, p := range s.ports.exacts {
		cells = append(cells, dnatOffPortCell{exact: p})
	}
	for _, r := range s.ports.ranges {
		cells = append(cells, dnatOffPortCell{lo: r[0], hi: r[1]})
	}
	if s.ports.wild {
		cells = append(cells, dnatOffPortCell{wild: true})
	}
	var out []dnatOffEntry
	for _, d := range s.dests {
		for _, p := range protos {
			for _, c := range cells {
				out = append(out, dnatOffEntry{dest: d, proto: p, port: c})
			}
		}
	}
	return out
}

// dnatOffPrefixLen returns the mask length for rank comparison (hosts count as
// full length). Compared only after destClass/port/proto tie, i.e. only
// between same-class entries.
func dnatOffPrefixLen(n dnatOffNet) int {
	if n.host {
		if n.v6 {
			return 128
		}
		return 32
	}
	ones, _ := n.prefix.Mask.Size()
	return ones
}

// dnatOffRankCompare compares two entries' probe ranks lexicographically:
// destClass (host > prefix) > port (exact > wild/range) > proto (pinned >
// ANY) > prefixLen (longer > shorter). Returns 1 if a outranks b, -1 if b
// outranks a, 0 on a tie (config order decides — the `off` is first, so a tie
// is never a shadow).
func dnatOffRankCompare(a, b dnatOffEntry) int {
	ac, bc := 0, 0
	if a.dest.host {
		ac = 1
	}
	if b.dest.host {
		bc = 1
	}
	if ac != bc {
		if ac > bc {
			return 1
		}
		return -1
	}
	at, bt := 0, 0
	if a.port.exact > 0 {
		at = 1
	}
	if b.port.exact > 0 {
		bt = 1
	}
	if at != bt {
		if at > bt {
			return 1
		}
		return -1
	}
	ap, bp := 0, 0
	if a.proto != "*" {
		ap = 1
	}
	if b.proto != "*" {
		bp = 1
	}
	if ap != bp {
		if ap > bp {
			return 1
		}
		return -1
	}
	al, bl := dnatOffPrefixLen(a.dest), dnatOffPrefixLen(b.dest)
	if al != bl {
		if al > bl {
			return 1
		}
		return -1
	}
	return 0
}

// dnatOffFlow is a concrete witness candidate: one destination, protocol,
// port, and source to test against every entry of both rules.
type dnatOffFlow struct {
	dst   net.IP
	v6    bool
	proto string // canonical token (never "*": ANY matches any token)
	port  int
	src   net.IP
	srcV6 bool
}

// dnatOffEntryMatches reports whether an entry matches a witness flow, given
// the rule's source set (empty = unconstrained). Family gates every axis: a
// v4 entry never matches a v6 flow.
func dnatOffEntryMatches(e dnatOffEntry, srcs []dnatOffNet, f dnatOffFlow) bool {
	if e.dest.v6 != f.v6 {
		return false
	}
	if e.dest.host {
		if !e.dest.ip.Equal(f.dst) {
			return false
		}
	} else if !e.dest.prefix.Contains(f.dst) {
		return false
	}
	if e.proto != "*" && e.proto != f.proto {
		return false
	}
	switch {
	case e.port.exact > 0:
		if f.port != e.port.exact {
			return false
		}
	case !e.port.wild:
		if f.port < e.port.lo || f.port > e.port.hi {
			return false
		}
	}
	if len(srcs) > 0 {
		hit := false
		for _, s := range srcs {
			if s.v6 != f.srcV6 {
				continue
			}
			if s.host {
				if s.ip.Equal(f.src) {
					hit = true
					break
				}
			} else if s.prefix.Contains(f.src) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// dnatOffBest returns the highest-ranked entry matching a flow, or ok=false
// when nothing matches (the flow is outside the rule's space).
func dnatOffBest(entries []dnatOffEntry, srcs []dnatOffNet, f dnatOffFlow) (dnatOffEntry, bool) {
	var best dnatOffEntry
	found := false
	for _, e := range entries {
		if !dnatOffEntryMatches(e, srcs, f) {
			continue
		}
		if !found || dnatOffRankCompare(e, best) > 0 {
			best, found = e, true
		}
	}
	return best, found
}

// dnatOffShadowWitness reports whether translate shape tr re-enters off shape
// off's match space at a STRICTLY more specific tier, proved by an explicit
// witness flow verified against EVERY entry of both rules. The detail names
// the witness (destination, protocol, port). Deterministic: translate entries
// in shape order (config dest order, sorted protos, sorted ports).
func dnatOffShadowWitness(off, tr dnatOffShape) (string, bool) {
	offEntries := dnatOffEntries(off)
	trEntries := dnatOffEntries(tr)
	for _, te := range trEntries {
		for _, cand := range dnatOffWitnessCandidates(te, off, tr) {
			offBest, offHit := dnatOffBest(offEntries, off.srcs, cand)
			if !offHit {
				continue
			}
			trBest, trHit := dnatOffBest(trEntries, tr.srcs, cand)
			if !trHit {
				continue
			}
			if dnatOffRankCompare(trBest, offBest) > 0 {
				return fmt.Sprintf("destination %s (%s, port %d)",
					cand.dst.String(), dnatOffProtoDesc(cand.proto), cand.port), true
			}
		}
	}
	return "", false
}

// dnatOffWitnessCandidates builds witness flows for one translate entry: the
// entry's own match space intersected with the exemption's space, one
// candidate per overlapping exemption-destination shape (host, or each
// overlapping prefix with a best-chance IP). Empty means the entry cannot
// witness (disjoint, or every shared address is held by a stronger exemption
// entry the verifier would confirm).
func dnatOffWitnessCandidates(te dnatOffEntry, off, tr dnatOffShape) []dnatOffFlow {
	proto, ok := dnatOffWitnessProto(te.proto, off)
	if !ok {
		return nil
	}
	port, ok := dnatOffWitnessPort(te.port, off.ports)
	if !ok {
		return nil
	}
	var dsts []net.IP
	if te.dest.host {
		if !dnatOffIPInDests(te.dest.ip, te.dest.v6, off.dests) {
			return nil
		}
		dsts = []net.IP{te.dest.ip}
	} else {
		dsts = dnatOffPrefixCandidates(te.dest, off.dests)
		if len(dsts) == 0 {
			return nil
		}
	}
	var out []dnatOffFlow
	for _, dst := range dsts {
		src, ok := dnatOffWitnessSource(off.srcs, tr.srcs, te.dest.v6)
		if !ok {
			continue
		}
		out = append(out, dnatOffFlow{
			dst: dst, v6: te.dest.v6, proto: proto, port: port, src: src, srcV6: te.dest.v6,
		})
	}
	return out
}

// dnatOffWitnessProto picks the witness protocol token for a translate entry:
// the translate pin when the exemption shares it (or is ANY), else the
// exemption's first pin when the translate is ANY. ok=false means disjoint
// protocols (no shared flow).
func dnatOffWitnessProto(trProto string, off dnatOffShape) (string, bool) {
	if trProto == "*" {
		if off.anyProto {
			return "s:tcp", true
		}
		if len(off.protos) == 0 {
			return "", false
		}
		return off.protos[0], true
	}
	if off.anyProto {
		return trProto, true
	}
	for _, p := range off.protos {
		if p == trProto {
			return trProto, true
		}
	}
	return "", false
}

// dnatOffWitnessPort picks the witness port for a translate port cell: a port
// in the translate cell that the exemption also matches, preferring the
// exemption's lowest tier (range/wildcard over exact) so the candidate gives
// the translate its best chance. ok=false means disjoint ports. The verifier,
// not this preference, decides the outcome.
func dnatOffWitnessPort(trCell dnatOffPortCell, off dnatOffPorts) (int, bool) {
	switch {
	case trCell.exact > 0:
		p := trCell.exact
		if off.wild || dnatOffPortsHaveExact(off.exacts, p) || dnatOffPortsRangeCovers(off.ranges, p) {
			return p, true
		}
		return 0, false
	case trCell.wild:
		if off.wild {
			return 80, true
		}
		if len(off.ranges) > 0 {
			return off.ranges[0][0], true
		}
		if len(off.exacts) > 0 {
			return off.exacts[0], true
		}
		return 0, false
	default:
		lo, hi := trCell.lo, trCell.hi
		if off.wild {
			return lo, true
		}
		for _, r := range off.ranges {
			if o := max(lo, r[0]); o <= min(hi, r[1]) {
				return o, true
			}
		}
		for _, p := range off.exacts {
			if lo <= p && p <= hi {
				return p, true
			}
		}
		return 0, false
	}
}

// dnatOffWitnessSource picks a source IP in both rules' source sets with the
// witness family (a packet's source and destination share one family).
// Either side unconstrained matches any address of that family.
func dnatOffWitnessSource(offSrcs, trSrcs []dnatOffNet, v6 bool) (net.IP, bool) {
	offs := dnatOffNetsOfFamily(offSrcs, v6)
	trs := dnatOffNetsOfFamily(trSrcs, v6)
	if len(offSrcs) > 0 && len(offs) == 0 {
		return nil, false
	}
	if len(trSrcs) > 0 && len(trs) == 0 {
		return nil, false
	}
	if len(offs) == 0 && len(trs) == 0 {
		if v6 {
			return net.ParseIP("2001:db8::1"), true
		}
		return net.ParseIP("198.51.100.1"), true
	}
	if len(offs) == 0 {
		return dnatOffNetRepresentative(trs[0]), true
	}
	if len(trs) == 0 {
		return dnatOffNetRepresentative(offs[0]), true
	}
	for _, o := range offs {
		for _, t := range trs {
			if ip, ok := dnatOffNetIntersectionIP(o, t); ok {
				return ip, true
			}
		}
	}
	return nil, false
}

// dnatOffIPInDests reports whether an IP is covered by any destination in a
// list (same family only).
func dnatOffIPInDests(ip net.IP, v6 bool, dests []dnatOffNet) bool {
	for _, d := range dests {
		if d.v6 != v6 {
			continue
		}
		if d.host {
			if d.ip.Equal(ip) {
				return true
			}
		} else if d.prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// dnatOffPrefixCandidates picks best-chance destination IPs for a translate
// PREFIX entry: one IP per overlapping exemption prefix, each inside the
// intersection, avoiding exemption hosts (a host always beats a prefix) and,
// where possible, longer exemption prefixes (keeping the exemption's best
// short). Empty means every shared address is held (hosts only) or disjoint.
func dnatOffPrefixCandidates(trDest dnatOffNet, offDests []dnatOffNet) []net.IP {
	var hosts []net.IP
	var prefixes []dnatOffNet
	for _, o := range offDests {
		if o.v6 != trDest.v6 {
			continue
		}
		if o.host {
			if trDest.prefix.Contains(o.ip) {
				hosts = append(hosts, o.ip)
			}
		} else if dnatOffPrefixesOverlap(trDest.prefix, o.prefix) {
			prefixes = append(prefixes, o)
		}
	}
	if len(prefixes) == 0 {
		return nil
	}
	sort.Slice(prefixes, func(i, j int) bool {
		return dnatOffPrefixLen(prefixes[i]) < dnatOffPrefixLen(prefixes[j])
	})
	var out []net.IP
	for i, op := range prefixes {
		inter := trDest.prefix
		if dnatOffPrefixLen(op) > dnatOffPrefixLen(trDest) {
			inter = op.prefix
		}
		var longer []*net.IPNet
		for _, q := range prefixes {
			if dnatOffPrefixLen(q) > dnatOffPrefixLen(op) {
				longer = append(longer, q.prefix)
			}
		}
		_ = i
		if ip, ok := dnatOffPickIP(inter, hosts, longer); ok {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		for _, op := range prefixes {
			inter := trDest.prefix
			if dnatOffPrefixLen(op) > dnatOffPrefixLen(trDest) {
				inter = op.prefix
			}
			if ip, ok := dnatOffPickIP(inter, hosts, nil); ok {
				out = append(out, ip)
			}
		}
	}
	return out
}

// dnatOffPickIP returns an IP inside a prefix avoiding a host list and a
// longer-prefix list, trying network-adjacent and broadcast-adjacent
// candidates. ok=false means every tried address is avoided (or outside);
// the caller treats that as no candidate (a miss, never a fire).
func dnatOffPickIP(within *net.IPNet, avoidHosts []net.IP, avoidPrefixes []*net.IPNet) (net.IP, bool) {
	base := within.IP
	bcast := dnatOffBroadcast(within)
	cands := []net.IP{base, dnatOffIPPlus(base, 1), dnatOffIPPlus(base, 2), bcast, dnatOffIPPlus(bcast, -1), dnatOffIPPlus(bcast, -2)}
	for _, c := range cands {
		if c == nil || !within.Contains(c) {
			continue
		}
		bad := false
		for _, h := range avoidHosts {
			if h.Equal(c) {
				bad = true
				break
			}
		}
		if bad {
			continue
		}
		for _, p := range avoidPrefixes {
			if p.Contains(c) {
				bad = true
				break
			}
		}
		if !bad {
			return c, true
		}
	}
	return nil, false
}

// dnatOffBroadcast returns the last address of a prefix.
func dnatOffBroadcast(n *net.IPNet) net.IP {
	ip := n.IP
	mask := n.Mask
	if v4 := ip.To4(); v4 != nil {
		m4 := net.IP(mask).To4()
		if m4 == nil {
			ones, _ := mask.Size()
			m4 = net.IP(net.CIDRMask(ones, 32)).To4()
		}
		out := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			out[i] = v4[i] | ^m4[i]
		}
		return out
	}
	v16 := ip.To16()
	m16 := net.IP(mask).To16()
	out := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		out[i] = v16[i] | ^m16[i]
	}
	return out
}

// dnatOffIPPlus adds a small signed delta to an IP, returning nil on
// overflow/underflow or unparseable input.
func dnatOffIPPlus(ip net.IP, delta int) net.IP {
	if v4 := ip.To4(); v4 != nil {
		v := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
		nv := int64(v) + int64(delta)
		if nv < 0 || nv > 0xffffffff {
			return nil
		}
		return net.IPv4(byte(nv>>24), byte(nv>>16), byte(nv>>8), byte(nv))
	}
	v16 := ip.To16()
	if v16 == nil {
		return nil
	}
	out := make(net.IP, 16)
	copy(out, v16)
	if delta >= 0 {
		carry := delta
		for i := 15; i >= 0 && carry > 0; i-- {
			sum := int(out[i]) + carry
			out[i] = byte(sum & 0xff)
			carry = sum >> 8
		}
		if carry > 0 {
			return nil
		}
	} else {
		borrow := -delta
		for i := 15; i >= 0 && borrow > 0; i-- {
			diff := int(out[i]) - borrow
			if diff < 0 {
				out[i] = byte(diff + 256)
				borrow = 1
			} else {
				out[i] = byte(diff)
				borrow = 0
			}
		}
		if borrow > 0 {
			return nil
		}
	}
	return out
}

// dnatOffPrefixesOverlap reports whether two prefixes intersect (for aligned
// CIDRs, one always contains the other's base when they share anything).
func dnatOffPrefixesOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// dnatOffNetsOfFamily filters parsed nets to one family.
func dnatOffNetsOfFamily(nets []dnatOffNet, v6 bool) []dnatOffNet {
	var out []dnatOffNet
	for _, n := range nets {
		if n.v6 == v6 {
			out = append(out, n)
		}
	}
	return out
}

// dnatOffNetRepresentative returns a concrete IP for a net (the host itself,
// or the prefix network address).
func dnatOffNetRepresentative(n dnatOffNet) net.IP {
	if n.host {
		return n.ip
	}
	return n.prefix.IP
}

// dnatOffNetIntersectionIP returns an IP in the intersection of two same-family
// nets, or ok=false when they are disjoint or cross-family.
func dnatOffNetIntersectionIP(a, b dnatOffNet) (net.IP, bool) {
	if a.v6 != b.v6 {
		return nil, false
	}
	switch {
	case a.host && b.host:
		if a.ip.Equal(b.ip) {
			return a.ip, true
		}
		return nil, false
	case !a.host && b.host:
		if a.prefix.Contains(b.ip) {
			return b.ip, true
		}
		return nil, false
	case a.host && !b.host:
		if b.prefix.Contains(a.ip) {
			return a.ip, true
		}
		return nil, false
	default:
		if !dnatOffPrefixesOverlap(a.prefix, b.prefix) {
			return nil, false
		}
		if dnatOffPrefixLen(a) >= dnatOffPrefixLen(b) {
			return a.prefix.IP, true
		}
		return b.prefix.IP, true
	}
}

func dnatOffPortsHaveExact(exacts []int, p int) bool {
	i := sort.SearchInts(exacts, p)
	return i < len(exacts) && exacts[i] == p
}

func dnatOffPortsRangeCovers(ranges [][2]int, p int) bool {
	for _, r := range ranges {
		if r[0] <= p && p <= r[1] {
			return true
		}
	}
	return false
}

// dnatOffProtoDesc renders a canonical proto token for messages.
func dnatOffProtoDesc(canonical string) string {
	if canonical == "*" {
		return "any protocol"
	}
	if n, ok := strings.CutPrefix(canonical, "n:"); ok {
		return "protocol " + n
	}
	return strings.ToUpper(strings.TrimPrefix(canonical, "s:"))
}
