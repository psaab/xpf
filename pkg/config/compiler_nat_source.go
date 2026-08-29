package config

import (
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
	//
	// proxyARPAddressValues is defined below compileNAT (see #6659).
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

				// Single address, or a bracket / block LIST of addresses
				// (#6659). `address [ 192.0.2.1 192.0.2.2 ]` collapses onto
				// Keys[1:] and `address { 192.0.2.1; 192.0.2.2; }` onto
				// Children; nodeVal read only the first, so every address
				// after the first silently got NO proxy-ARP entry — the
				// firewall answered ARP for one address of the authored set and
				// stayed silent for the rest, so inbound traffic to them was
				// never drawn to this box.
				//
				// The DROP itself is a pure value-drop, not a validation
				// fail-open. But restoring the tail changes what a malformed
				// address does: it used to be discarded at compile, and it now
				// MATERIALISES into Addresses, where the installer
				// (pkg/dataplane/proxyarp.go) fails netip.ParsePrefix, logs a
				// bounded warning and skips it — a silently-inert entry. Before
				// #6659 proxy-ARP addresses carried NO commit-time validator at
				// all, so a malformed address in the FIRST slot committed clean
				// too. Widening a read requires widening its validator in the
				// same change, so validateProxyARPAddressesStrict now checks
				// EVERY value with the installer's own parse (strict rejects,
				// tolerant warns — see compiler_uniformgates_firewall_nat2.go).
				//
				// Read via proxyARPAddressValues rather than firewallMatchValues
				// so a MALFORMED range that fell through the two branches above
				// does not widen at all: it keeps master's single-value read,
				// which is what the dataplane installed before #6659 (#6673).
				//
				// #6714: that fallback is still a DROP — the operator authored
				// a list and the compiler installed one address of it with no
				// diagnostic anywhere. Record the offending statement so the
				// commit gate can say so; the installed set is untouched, so
				// this cannot move a single ARP response either way.
				if proxyARPMalformedRange(prop) {
					entry.MalformedRangeSpecs = append(entry.MalformedRangeSpecs,
						strings.Join(proxyARPStatementTokens(prop), " "))
				}
				for _, v := range proxyARPAddressValues(prop) {
					addr := v
					if !strings.Contains(addr, "/") {
						// #6559: /128 for a bare IPv6 literal. The old
						// unconditional "/32" compiled `2001:db8::1` to a
						// 32-bit prefix on a 128-bit address — the install was
						// correct by accident (Addr() recovers the full
						// address) but the compiled form was indistinguishable
						// from an authored /32 v6 BLOCK, which the expansion
						// below has to tell apart.
						addr += proxyARPHostSuffix(addr)
					}
					// #6559: a multi-host prefix expands to its ARP-addressable
					// hosts here, in the compiler, because `Addresses` is the
					// "/32 CIDRs" contract the installer and the commit gate
					// both read. An over-cap block is returned unchanged so
					// validateProxyARPAddressesStrict can reject it.
					entry.Addresses = append(entry.Addresses, expandProxyARPPrefix(addr)...)
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

// proxyARPAddressValues extracts every address a proxy-arp `address` node
// carries, across BOTH parser AST shapes (#6659 — the proxy-ARP instance of the
// #2419 dual-shape class):
//
//   - single      `address 192.0.2.1;`            → Keys=["address","192.0.2.1"]
//   - bracket     `address [ 192.0.2.1 .2 ];`     → Keys=["address",".1",".2"]
//     (the lexer strips `[`/`]`, so the list collapses onto ONE node's Keys)
//   - block       `address { 192.0.2.1; .2; }`    → one child leaf per address
//
// It differs from firewallMatchValues in exactly one way: A MALFORMED RANGE
// DOES NOT WIDEN. The caller handles `address <low> to <high>` in two earlier
// branches, but those `continue` only on a WELL-FORMED range; a malformed one —
// a `to` child with an empty endpoint, a bracket that leads with the keyword
// (`address [ to 192.0.2.1 ]`), a `to` anywhere past the range slot
// (`address [ .1 .2 to .9 ]`), or a range riding on a BLOCK child's own Keys
// (`address { .1; .2 to .9; }`) — falls through to here. For those, this helper
// returns master's single-value read (nodeVal) and nothing else.
// proxyARPMalformedRange decides that, and it decides it over the statement's
// whole token stream rather than a list of positions — see its comment for why
// the position list is what kept failing.
//
// #6673: the reason is INSTALLATION parity, not compile-verdict parity, and the
// earlier "skip the `to` token" spelling got the second without the first.
// Measured against origin/master with the installer's own gate
// (netip.ParsePrefix, pkg/dataplane/proxyarp.go), for `address [ to 192.0.2.1 ]`
// master compiled ["to/32"] and installed NOTHING, while the token-skip
// spelling compiled ["192.0.2.1/32"] and installed an NTF_PROXY neighbour plus
// the interface proxy responder. The appliance answered ARP for the orphan high
// endpoint of a malformed range — an address master never claimed. Same for
// `address { to; 192.0.2.5; }` (master {}, skip-spelling {192.0.2.5/32}) and,
// worse, for `address [ .1 .2 to .9 ]`, where the skip spelling installed .2 and
// .9 on top of master's .1.
//
// Falling back to nodeVal makes that exact: for a malformed range this helper
// yields master's compiled value, minus the bare keyword — and "to/32" is the
// one value master compiled that could never install. Dropping the keyword
// instead of emitting it also keeps the accept/reject verdict identical: #6659
// added validateProxyARPAddressesStrict, which parses every value with
// netip.ParsePrefix, so materialising "to/32" would HARD-REJECT at strict
// commit a config master accepted — an invented rejection, the other failure
// mode this must avoid.
//
// SCOPE OF THE PARITY CLAIM, stated narrowly because an earlier revision of
// this comment asserted a universal the code did not have. What is measured, by
// compiling a corpus of proxy-arp `address` spellings on this tree and on
// origin/master and filtering both through the installer's own
// netip.ParsePrefix gate: for every spelling in that corpus whose token stream
// contains a `to`, installed(head) == installed(master), in both directions —
// nothing promoted, and nothing that master answered ARP for gone inert. That
// is a claim about a corpus plus a detector that provably sees every `to`, NOT
// a proof over all inputs.
//
// The RESIDUAL, which is deliberate: the veto is per STATEMENT, so a malformed
// range suppresses the #6659 widening for the whole statement it appears in —
// `address { .1; .2 to .9; 198.51.100.1; }` yields .1 alone, dropping the
// well-formed 198.51.100.1 authored beside the broken range. That is exactly
// what master installs, and exactly what the already-shipped bracket form does
// (`address [ .1 .2 to .9 ]` → .1), so it keeps the two spellings consistent
// and preserves parity; per-CHILD vetoing would instead install an address
// master never claimed, which is the regression this whole arm exists to
// prevent. Separate `address` statements are separate nodes, so a malformed one
// never suppresses a well-formed SIBLING STATEMENT — only its own operands.
//
// Not fixed here, and pre-existing on both trees: a block-form range does not
// EXPAND (`address { .1 to .9; }` compiles .1 alone on master and on this
// tree). Making it expand is a behaviour change to the compiler's range
// handling, not a parity fix, so it is out of this arm's scope.
//
// The #6659 widening is untouched where it belongs: a WELL-FORMED list
// (`address [ .1 .2 ]`, `address { .1; .2; }`) still contributes every value,
// which is the fail-open this arm was widened to fix. Pinned by
// TestProxyARPAddresses6673MalformedRangeInstallsExactlyWhatMasterInstalled.
func proxyARPAddressValues(prop *Node) []string {
	// A malformed range keeps master's single-value read. nodeVal is master's
	// exact reader (Keys[1], else the first child's name), so the only value
	// dropped here is the grammar keyword itself.
	if proxyARPMalformedRange(prop) {
		if v := nodeVal(prop); v != "" && v != proxyARPRangeKeyword {
			return []string{v}
		}
		return nil
	}
	var vals []string
	for _, k := range prop.Keys[1:] {
		if k != "" {
			vals = append(vals, k)
		}
	}
	for _, vn := range prop.Children {
		if len(vn.Keys) >= 1 && vn.Keys[0] != "" {
			vals = append(vals, vn.Keys[0])
		}
	}
	return vals
}

// proxyARPRangeKeyword is the `address <low> to <high>` range separator.
const proxyARPRangeKeyword = "to"

// proxyARPMalformedRange reports whether a proxy-arp `address` STATEMENT that
// REACHED the caller's single/list branch still carries a range keyword
// anywhere in its token stream. Both well-formed range shapes are consumed and
// `continue`d before that point, so a surviving `to` means the statement is a
// broken range rather than a list of addresses (#6673).
//
// This deliberately does NOT enumerate the positions a `to` can occupy. Two
// earlier spellings did, and each shipped a live regression at the first
// position the enumeration had not anticipated:
//
//   - the first checked only prop.Keys[1:], and missed `address { to; .5; }`;
//   - the second added Children[i].Keys[0], and missed the BLOCK form
//     `address { .1; .2 to .9; }`, where the range rides on a child's OWN Keys
//     (Children[1].Keys = [".2","to",".9"]) so Keys[0] is the address and the
//     `to` at Keys[1] is invisible.
//
// Measured, the parser puts a `to` in at least four distinct places for this
// one statement — prop.Keys[n], Children[i].Keys[0], Children[i].Keys[n>0]
// (`address { .1 .2 to .9; ... }`), and Children[i].Children[j].Keys[0]
// (`address { .1 { to .9; } ... }`, which nests arbitrarily deep). Enumerating
// them is a losing game, so this walks the whole subtree the parser built for
// this ONE statement and asks whether the range keyword is among its tokens.
// That is position-independent by construction: every token the parser keeps
// lands in some node's Keys within this subtree, so no shape — present or
// future, hierarchical, bracketed or flat-set — can hide a `to` from it.
//
// It cannot false-positive on a well-formed list either: "to" is not a
// parseable address, so an `address` statement whose tokens include it is
// malformed no matter which slot it sits in.
func proxyARPMalformedRange(prop *Node) bool {
	// prop.Keys[0] is the statement keyword itself — the caller reaches here
	// only for a node whose Name() is "address" — so the root scan starts at 1.
	// Every DEEPER node's Keys[0] is a value slot (that is where
	// `address { to; ... }` puts the keyword), so those scan from 0.
	for _, k := range prop.Keys[1:] {
		if k == proxyARPRangeKeyword {
			return true
		}
	}
	for _, vn := range prop.Children {
		if nodeSubtreeHasKey(vn, proxyARPRangeKeyword) {
			return true
		}
	}
	return false
}

// proxyARPStatementTokens flattens the whole token stream of ONE proxy-arp
// `address` statement, in authored order, so a diagnostic can quote what the
// operator actually wrote rather than what survived the read.
//
// It walks the same subtree proxyARPMalformedRange scans, for the same reason:
// the parser spreads one statement's tokens across the node's own Keys, its
// children's Keys and (for `address { .1 { to .9; } }`) their grandchildren's,
// and which slot a token lands in is a property of the authoring shape, not of
// the statement. The leading `address` keyword is dropped — Keys[0] of the
// statement node is the leaf name, and every DEEPER node's Keys[0] is a value.
func proxyARPStatementTokens(prop *Node) []string {
	if prop == nil {
		return nil
	}
	out := append([]string{}, prop.Keys[1:]...)
	var walk func(*Node)
	walk = func(n *Node) {
		for _, c := range n.Children {
			out = append(out, c.Keys...)
			walk(c)
		}
	}
	walk(prop)
	return out
}

// nodeSubtreeHasKey reports whether want appears as any key of n or of any
// node beneath it. Used to detect a grammar keyword anywhere in the token
// stream of a single statement, independent of which AST shape the parser
// chose for it (#6673).
func nodeSubtreeHasKey(n *Node, want string) bool {
	if n == nil {
		return false
	}
	for _, k := range n.Keys {
		if k == want {
			return true
		}
	}
	for _, c := range n.Children {
		if nodeSubtreeHasKey(c, want) {
			return true
		}
	}
	return false
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
// Every endpoint is validated as a CANONICAL port in 1..65535 via
// ParseCanonicalUint (which rejects a leading sign, surrounding whitespace, a
// non-numeric token, and int overflow — the same primitive the DNAT and appid
// port parsers use) and the range must be non-decreasing (low <= high). ok is
// FALSE on ANY violation — a non-numeric / non-canonical token, an endpoint
// outside 1..65535 (0 included), or a reversed range — so the malformed value
// is NEVER stamped into PortLow/PortHigh (#5457). The caller records the raw
// offending spec in PortRangeInvalidSpec so the strict commit gate
// (validateSourceNATPoolStrict) hard-rejects it (operator-visible) AND the
// snapshot builder marks the pool unusable on the tolerant load / peer-sync
// path, rather than silently defaulting a bad range to 1024-65535 PAT.
//
// Before #5457 the endpoints were read with strconv.Atoi and returned ok=true
// even for a negative low ("port range low -1 high 99999" -> (-1, 99999, true))
// or a reversed range ("low 5000 high 100" -> (5000, 100, true)). Only the
// downstream strict gate caught the non-zero cases (the stamped bad value), and
// a 0-valued endpoint slipped through the parser as the "unconfigured" sentinel
// and silently widened to the default PAT range.
//
// #6688: BOTH shapes have a FIXED arity, and a token the grammar does not
// consume now rejects instead of being ignored. `port range` is not a value
// list — it is a compound value TAIL — but the lexer strips brackets before the
// compiler sees anything, so `port range [ 1000 2000 ]` and a mistyped
// `port range 1000 2000` (the `to` dropped) arrive as the SAME token slice
// ["1000","2000"]. The pre-#6688 reader took toks[0] as both endpoints and
// discarded the rest, so an operator who sized a pool at 1001 ports got ONE,
// with no diagnostic anywhere: the pool exhausts under the first real
// translation load and the symptom points nowhere near the config that caused
// it. The same silent discard let an out-of-range or non-numeric second slot
// ("1000 99999", "1000 notaport") commit clean, because the strict pool gate
// only ever saw the stamped first endpoint.
//
// Accepting ["1000","2000"] as [1000,2000] was rejected as the fix: it would
// INVENT a two-token `range <low> <high>` grammar that Junos does not have, and
// — because the brackets are already gone — it would silently redefine the
// mistyped bare form too. Failing closed keeps the authored spec in
// PortRangeInvalidSpec, where validateSourceNATPoolStrict hard-rejects it at
// commit and SourceNATPoolPortRange marks the pool unusable on the tolerant
// load / peer-sync path.
func parseSourcePoolPortRange(toks []string) (low, high int, ok bool) {
	// parsePort validates a single token as a canonical port in 1..65535.
	parsePort := func(s string) (int, bool) {
		n, err := ParseCanonicalUint(s)
		if err != nil || n < 1 || n > 65535 {
			return 0, false
		}
		return n, true
	}
	// Legacy explicit-keyword shape: low <lo> high <hi>. EXACTLY four tokens —
	// a fifth token is not part of this grammar (#6688).
	if len(toks) == 4 && toks[0] == "low" && toks[2] == "high" {
		lo, ok1 := parsePort(toks[1])
		hi, ok2 := parsePort(toks[3])
		if !ok1 || !ok2 || lo > hi {
			return 0, 0, false
		}
		return lo, hi, true
	}
	// Junos shape: `<low>` (single port) or `<low> to <high>`. Both are FIXED
	// arities; see the #6688 note above for why a leftover token rejects.
	switch {
	case len(toks) == 1:
		lo, ok1 := parsePort(toks[0])
		if !ok1 {
			return 0, 0, false
		}
		return lo, lo, true
	case len(toks) == 3 && toks[1] == "to":
		lo, ok1 := parsePort(toks[0])
		hi, ok2 := parsePort(toks[2])
		if !ok1 || !ok2 || lo > hi {
			return 0, 0, false
		}
		return lo, hi, true
	}
	return 0, 0, false
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

				// setPortRange stamps a validated [lo,hi] source-port range onto
				// the pool. A malformed range (parseSourcePoolPortRange ok=false:
				// a non-canonical token, an endpoint outside 1..65535 including 0,
				// or a reversed low>high) is NEVER stamped — it records the raw
				// spec in PortRangeInvalidSpec so the strict commit gate
				// hard-rejects (operator-visible) and the snapshot builder marks
				// the pool unusable on the tolerant load / peer-sync path, rather
				// than silently defaulting the bad range to 1024-65535 PAT (#5457).
				setPortRange := func(toks []string) {
					if lo, hi, ok := parseSourcePoolPortRange(toks); ok {
						pool.PortLow = lo
						pool.PortHigh = hi
					} else {
						pool.PortRangeInvalidSpec = strings.Join(toks, " ")
					}
				}

				// Port range / single value — flat leaf shapes
				// (Keys=["port","range",...]/["port",N]/["port",
				// "no-translation"]). #3906: `range` accepts both the Junos
				// wire shape `<low> to <high>` and the legacy `low <lo> high
				// <hi>` shape; `no-translation` preserves the source port.
				if len(prop.Keys) >= 3 && prop.Keys[1] == "range" {
					setPortRange(prop.Keys[2:])
				} else if len(prop.Keys) == 2 && prop.Keys[1] != "range" &&
					prop.Keys[1] != "deterministic" &&
					prop.Keys[1] != "no-translation" {
					// "port N" single value — validated as a 1..65535 port via the
					// shared parser (a single token is the [N,N] range shape).
					setPortRange(prop.Keys[1:])
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
						setPortRange(pc.Keys[1:])
					case "no-translation":
						pool.PortNoTranslation = true
					case "deterministic":
						applyDeterministicChildren(ensureDet(), pc)
					default:
						// Bare numeric child: `port N` grouped under a
						// modeled container becomes port { N }. Validated as a
						// 1..65535 port via the shared parser.
						if pc.IsLeaf && len(pc.Keys) == 1 {
							setPortRange(pc.Keys)
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
						// #6693: read BOTH slots through the natMatchAddressValues
						// SSOT. The either/or form below read Keys[1:] OR the
						// children, never both, so the MIXED shape
						// `source-address <v1> { <v2>; }` — a value in the
						// identifier slot beside a block — silently dropped the
						// child tail. It is the #4121 defect (fixed for
						// `security policies ... match`) at five NAT sites; the
						// four sibling arms in this same switch already use this
						// reader.
						rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, natMatchAddressValues(m)...)
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
						// #6693: read BOTH slots through the natMatchAddressValues
						// SSOT. The either/or form below read Keys[1:] OR the
						// children, never both, so the MIXED shape
						// `destination-address <v1> { <v2>; }` — a value in the
						// identifier slot beside a block — silently dropped the
						// child tail. It is the #4121 defect (fixed for
						// `security policies ... match`) at five NAT sites; the
						// four sibling arms in this same switch already use this
						// reader.
						rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, natMatchAddressValues(m)...)
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
				// #7014: the FULLY-COMPACT authoring `then source-nat off;`
				// packs every token onto the `then` node itself, so there is no
				// `source-nat` CHILD for the loop below to find and the action
				// set came back EMPTY. The zero-action arm then rejected a
				// stanza that visibly carries an action, with a message saying
				// it "carries no translation action" — a legal Junos spelling
				// refused with a diagnostic that contradicts the config in front
				// of the operator.
				//
				// It failed CLOSED, so no traffic was ever mishandled; the cost
				// was a correct config that would not commit.
				//
				// Read DELIBERATELY the same way as the packed CHILD spelling
				// (`then { source-nat pool P off; }`) one level down: the first
				// action token wins and the result counts as ONE action. That is
				// not the ideal semantics -- a packed contradiction should be
				// rejected -- but it is #7033's whole subject, and #7033's gate
				// message names the packed class as the open case. Narrowing it
				// in this ONE spelling would make that message half-false and
				// leave two packed spellings behaving differently. Uniformity
				// here means #7033 closes the class in one move.
				applyPackedNATThenTokens7014(&rule.Then, thenNode.Keys, "source-nat", NATSource)
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
						} else {
							// #5628: read EVERY hierarchical terminal child, not
							// the first one only (the former `else if` chain
							// silently picked interface > off > pool by child
							// order). A well-formed `source-nat { pool P; }` still
							// sets exactly one field, so this is bit-identical for
							// a valid single-child block. A CONTRADICTORY
							// single-node block such as `source-nat { interface;
							// pool P; }` now sets BOTH fields, so the resolved
							// NATThen faithfully carries two terminal actions and
							// validateNATTerminalActionCardinalityStrict rejects it
							// (strict commit) / warns (tolerant load) instead of
							// silently reinterpreting it.
							if t.FindChild("interface") != nil {
								rule.Then.Type = NATSource
								rule.Then.Interface = true
							}
							if t.FindChild("off") != nil {
								rule.Then.Type = NATSource
								rule.Then.Off = true
							}
							if poolNode := t.FindChild("pool"); poolNode != nil {
								rule.Then.Type = NATSource
								rule.Then.PoolName = nodeVal(poolNode)
							}
						}
					}
				}
			}

			// #7013: record what ONE `then` container authored, so a block that
			// named the same pool twice is still visible after NATThen's scalar
			// collapsed it. Kept PER CONTAINER, not summed: duplicate `then`
			// containers are #3850's accepted last-wins, and summing across them
			// false-rejects a config the suite already pins as legal. The worst
			// single container is the one worth reporting.
			for _, thenNode := range ruleInst.node.FindChildren("then") {
				if c := natThenAuthoredOccurrences(thenNode, "source-nat"); c.worseThan(rule.thenAuthored) {
					rule.thenAuthored = c
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

// applyPackedNATThenTokens7014 reads a terminal action packed onto the `then`
// node's OWN Keys, as the fully-compact `then source-nat off;` spelling
// produces (#7014).
//
// keys is thenNode.Keys, i.e. ["then", "<kind>", <action tokens...>]. It is a
// no-op for every other shape: the hierarchical `then { ... }` and the flat-set
// form both put <kind> in a CHILD, so keys is just ["then"] and this returns
// before touching anything.
//
// First action token wins, matching the packed-child read one level down. See
// the call site for why that uniformity is deliberate rather than an oversight.
func applyPackedNATThenTokens7014(then *NATThen, keys []string, kind string, typ NATType) {
	if len(keys) < 3 || keys[1] != kind {
		return
	}
	switch keys[2] {
	case "interface":
		if typ != NATSource {
			return
		}
		then.Type = typ
		then.Interface = true
	case "off":
		then.Type = typ
		then.Off = true
	case "pool":
		if len(keys) < 4 {
			return
		}
		then.Type = typ
		then.PoolName = keys[3]
	}
}
