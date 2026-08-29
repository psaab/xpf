package config

import (
	"fmt"
	"strconv"
)

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
						dports, dinvalid, drev := parseDNATPortList(m)
						rule.Match.DestinationPorts = append(rule.Match.DestinationPorts, dports...)
						rule.Match.InvalidDestinationPorts = append(rule.Match.InvalidDestinationPorts, dinvalid...)
						rule.Match.ReversedDestinationPortRanges = append(rule.Match.ReversedDestinationPortRanges, drev...)
						if rule.Match.DestinationPort == 0 && len(rule.Match.DestinationPorts) > 0 {
							rule.Match.DestinationPort = rule.Match.DestinationPorts[0]
						}
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
				// #7014: the fully-compact `then destination-nat off;` packs
				// every token onto the `then` node itself, leaving no
				// `destination-nat` CHILD for the loop below and an EMPTY action
				// set that the zero-action arm rejects. See the source-NAT call
				// site for why this reads the same way as the packed child.
				applyPackedNATThenTokens7014(&rule.Then, thenNode.Keys, "destination-nat", NATDestination)
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
						} else {
							// #5628: read EVERY hierarchical terminal child, not
							// the first one only (see the source-NAT note). A valid
							// single-child block (`destination-nat { pool P; }` or
							// `{ off; }`) is bit-identical; a contradictory
							// `destination-nat { pool P; off; }` now sets BOTH
							// fields so validateNATTerminalActionCardinalityStrict
							// can reject it instead of the compiler silently
							// picking pool by child order.
							if poolNode := t.FindChild("pool"); poolNode != nil {
								rule.Then.Type = NATDestination
								rule.Then.PoolName = nodeVal(poolNode)
							}
							if t.FindChild("off") != nil {
								rule.Then.Type = NATDestination
								rule.Then.Off = true
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
				if c := natThenAuthoredOccurrences(thenNode, "destination-nat"); c.worseThan(rule.thenAuthored) {
					rule.thenAuthored = c
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
