package config

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// validatePoolUtilizationAlarm is the #2079 strict-vs-lenient gate for the
// `security nat source pool-utilization-alarm raise-threshold/clear-threshold`
// thresholds. Junos requires raise > clear; a bare `pool-utilization-alarm;`
// compiles to raise=0/clear=0 (an always-firing alarm) and inverted/equal
// thresholds make hysteresis meaningless. Strict (commit / commit-check):
// hard-reject. Lenient (load / peer-sync, #1979 doctrine): return the message
// as a warning so a config committed before this gate existed still boots
// (#1960 fail-closed-on-compile-failure would otherwise brick the daemon on
// restart). The runtime monitor treats raise<=0 as disabled, so a leniently
// loaded bad config is inert, not always-firing.
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
	emit := func(msg string) error {
		if lenient {
			warnings = append(warnings, msg+" (ignored: rule dropped by dataplane until corrected)")
			return nil
		}
		return fmt.Errorf("%s", msg)
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
			if rule.Match != "" {
				if host, parsed := isHostMaskAddress(rule.Match); parsed && !host {
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q match destination-address %q must be a host route (/32 for IPv4, /128 for IPv6); a non-host mask is silently dropped by the dataplane",
						rs.Name, rule.Name, rule.Match)); err != nil {
						return nil, err
					}
				}
			}
			if rule.Then != "" {
				if host, parsed := isHostMaskAddress(rule.Then); parsed && !host {
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q then static-nat prefix %q must be a host route (/32 for IPv4, /128 for IPv6); a non-host mask is silently dropped by the dataplane",
						rs.Name, rule.Name, rule.Then)); err != nil {
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
				if err := emit(fmt.Sprintf(
					"security nat source pool %q address %q is referenced by nat64 rule-set %q source-pool and must be an IPv4 host route (a bare IPv4 address or /32); a non-host or IPv6 address is silently dropped by the dataplane",
					pool.Name, a, rs.Name)); err != nil {
					return nil, err
				}
			}
		}
	}

	return warnings, nil
}

func compileNAT(node *Node, sec *SecurityConfig) error {
	// Initialize SourcePools map
	if sec.NAT.SourcePools == nil {
		sec.NAT.SourcePools = make(map[string]*NATPool)
	}

	srcNode := node.FindChild("source")
	if srcNode != nil {
		if err := compileNATSource(srcNode, sec); err != nil {
			return fmt.Errorf("source: %w", err)
		}
	}

	dstNode := node.FindChild("destination")
	if dstNode != nil {
		if err := compileNATDestination(dstNode, sec); err != nil {
			return fmt.Errorf("destination: %w", err)
		}
	}

	staticNode := node.FindChild("static")
	if staticNode != nil {
		if err := compileNATStatic(staticNode, sec); err != nil {
			return fmt.Errorf("static: %w", err)
		}
	}

	nat64Node := node.FindChild("nat64")
	if nat64Node != nil {
		if err := compileNAT64(nat64Node, sec); err != nil {
			return fmt.Errorf("nat64: %w", err)
		}
	}

	// natv6v4 { no-v6-frag-header; }
	v6v4Node := node.FindChild("natv6v4")
	if v6v4Node != nil {
		sec.NAT.NATv6v4 = &NATv6v4Config{}
		if v6v4Node.FindChild("no-v6-frag-header") != nil {
			sec.NAT.NATv6v4.NoV6FragHeader = true
		}
	}

	// proxy-arp { interface <name> { address <addr>; } }
	proxyNode := node.FindChild("proxy-arp")
	if proxyNode != nil {
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
// Handles multiple AST shapes:
//   - Hierarchical bracket list: Keys=["from","zone","A","B","C"] → ["A","B","C"]
//   - SetPath single: child zone node with value → ["A"]
//   - SetPath multiple: multiple zone children → ["A","B"]
//   - SetPath bracket-expanded: zone child with orphan leaf children → ["A","B"]
func parseZoneList(node *Node) []string {
	// Hierarchical: all zone names inline in Keys
	if len(node.Keys) >= 3 && node.Keys[1] == "zone" {
		return node.Keys[2:]
	}
	// SetPath: iterate all "zone" children (multiple set commands create siblings)
	var zones []string
	for _, child := range node.Children {
		if child.Name() == "zone" {
			if v := nodeVal(child); v != "" {
				zones = append(zones, v)
			}
			// Also collect orphan leaf children (bracket-expanded extra zone names)
			for _, grandchild := range child.Children {
				if grandchild.IsLeaf && len(grandchild.Keys) >= 1 {
					zones = append(zones, grandchild.Keys[0])
				}
			}
		}
	}
	return zones
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

func compileNATSource(node *Node, sec *SecurityConfig) error {
	// Global flags
	if node.FindChild("address-persistent") != nil {
		sec.NAT.AddressPersistent = true
	}

	// Parse source NAT pools
	for _, inst := range namedInstances(node.FindChildren("pool")) {
		pool := &NATPool{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "address":
				// Check for address range: "addr1 to addr2"
				if len(prop.Keys) >= 4 && prop.Keys[2] == "to" {
					expanded, err := expandAddressRange(prop.Keys[1], prop.Keys[3])
					if err != nil {
						return fmt.Errorf("pool %q address range: %w", pool.Name, err)
					}
					pool.Addresses = append(pool.Addresses, expanded...)
				} else if len(prop.Keys) >= 2 && prop.Keys[1] != "" {
					// Inline value form ("address <prefix>;" / flat set).
					// Deliberately NOT nodeVal: its Children[0] fallback
					// would double-append the block form, whose children
					// are walked below (#1808).
					pool.Addresses = append(pool.Addresses, prop.Keys[1])
				}
				// Also handle children for hierarchical syntax
				for _, addrChild := range prop.Children {
					if len(addrChild.Keys) >= 3 && addrChild.Keys[1] == "to" {
						expanded, err := expandAddressRange(addrChild.Keys[0], addrChild.Keys[2])
						if err != nil {
							return fmt.Errorf("pool %q address range: %w", pool.Name, err)
						}
						pool.Addresses = append(pool.Addresses, expanded...)
					} else if addrChild.IsLeaf && len(addrChild.Keys) >= 1 {
						pool.Addresses = append(pool.Addresses, addrChild.Keys[0])
					}
				}
			case "port":
				// "port range low N high M" or "port N"
				if len(prop.Keys) >= 6 && prop.Keys[1] == "range" &&
					prop.Keys[2] == "low" && prop.Keys[4] == "high" {
					if v, err := strconv.Atoi(prop.Keys[3]); err == nil {
						pool.PortLow = v
					}
					if v, err := strconv.Atoi(prop.Keys[5]); err == nil {
						pool.PortHigh = v
					}
				} else if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						pool.PortLow = n
						pool.PortHigh = n
					}
				}
				// Check for deterministic port config (hierarchical)
				for _, portChild := range prop.Children {
					if portChild.Name() == "deterministic" {
						detCfg := &DeterministicNATConfig{}
						for _, detProp := range portChild.Children {
							switch detProp.Name() {
							case "block-size":
								if v := nodeVal(detProp); v != "" {
									if n, err := strconv.Atoi(v); err == nil {
										detCfg.BlockSize = n
									}
								}
							case "host":
								// "host address 100.64.0.0/22"
								if len(detProp.Keys) >= 3 && detProp.Keys[1] == "address" {
									detCfg.HostAddress = detProp.Keys[2]
								} else if v := nodeVal(detProp); v != "" {
									detCfg.HostAddress = v
								}
								for _, hc := range detProp.Children {
									if hc.Name() == "address" {
										if v := nodeVal(hc); v != "" {
											detCfg.HostAddress = v
										}
									}
								}
							}
						}
						pool.Deterministic = detCfg
					}
				}
				// Flat set: "port deterministic block-size 2016"
				if len(prop.Keys) >= 2 && prop.Keys[1] == "deterministic" {
					detCfg := &DeterministicNATConfig{}
					for i := 2; i < len(prop.Keys); i++ {
						if prop.Keys[i] == "block-size" && i+1 < len(prop.Keys) {
							if n, err := strconv.Atoi(prop.Keys[i+1]); err == nil {
								detCfg.BlockSize = n
							}
						}
					}
					// host address from children
					for _, portChild := range prop.Children {
						if portChild.Name() == "host" {
							if len(portChild.Keys) >= 3 && portChild.Keys[1] == "address" {
								detCfg.HostAddress = portChild.Keys[2]
							}
							for _, hc := range portChild.Children {
								if hc.Name() == "address" {
									if v := nodeVal(hc); v != "" {
										detCfg.HostAddress = v
									}
								}
							}
						}
					}
					pool.Deterministic = detCfg
				}
			case "persistent-nat":
				pnat := &PersistentNATConfig{InactivityTimeout: 300}
				for _, pnProp := range prop.Children {
					switch pnProp.Name() {
					case "permit":
						if v := nodeVal(pnProp); v == "any-remote-host" {
							pnat.PermitAnyRemoteHost = true
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
		for _, ap := range alarmNode.Children {
			switch ap.Name() {
			case "raise-threshold":
				if v := nodeVal(ap); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						alarm.RaiseThreshold = n
					}
				}
			case "clear-threshold":
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
				if n, err := strconv.Atoi(alarmNode.Keys[i+1]); err == nil {
					alarm.ClearThreshold = n
				}
			}
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
		// Parse from/to zones (bracket lists produce multiple keys)
		var fromZones, toZones []string
		for _, child := range rsInst.node.Children {
			if child.Name() == "from" {
				fromZones = append(fromZones, parseZoneList(child)...)
			}
			if child.Name() == "to" {
				toZones = append(toZones, parseZoneList(child)...)
			}
		}
		if len(fromZones) == 0 {
			fromZones = []string{""}
		}
		if len(toZones) == 0 {
			toZones = []string{""}
		}

		// Parse rules (shared across all zone-pair expansions)
		var rules []*NATRule
		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
			rule := &NATRule{Name: ruleInst.name}

			matchNode := ruleInst.node.FindChild("match")
			if matchNode != nil {
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
					case "destination-port":
						if len(m.Children) > 0 {
							for _, child := range m.Children {
								if n, err := strconv.Atoi(child.Name()); err == nil {
									rule.Match.DestinationPorts = append(rule.Match.DestinationPorts, n)
									if rule.Match.DestinationPort == 0 {
										rule.Match.DestinationPort = n
									}
								}
							}
						} else if v := nodeVal(m); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								rule.Match.DestinationPort = n
								rule.Match.DestinationPorts = append(rule.Match.DestinationPorts, n)
							}
						}
					case "application":
						rule.Match.Application = nodeVal(m)
					}
				}
			}

			thenNode := ruleInst.node.FindChild("then")
			if thenNode != nil {
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

		// Expand Cartesian product of from-zones × to-zones
		for _, fz := range fromZones {
			for _, tz := range toZones {
				rs := &NATRuleSet{
					Name:     rsInst.name,
					FromZone: fz,
					ToZone:   tz,
					Rules:    rules,
				}
				sec.NAT.Source = append(sec.NAT.Source, rs)
			}
		}
	}
	return nil
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
				pool.Address = nodeVal(prop)
			case "port":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						pool.Port = n
					}
				}
			}
		}

		sec.NAT.Destination.Pools[pool.Name] = pool
	}

	// Parse rule-sets
	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
		// Parse from/to zones (bracket lists produce multiple keys)
		var fromZones, toZones []string
		for _, child := range rsInst.node.Children {
			if child.Name() == "from" {
				fromZones = append(fromZones, parseZoneList(child)...)
			}
			if child.Name() == "to" {
				toZones = append(toZones, parseZoneList(child)...)
			}
		}
		if len(fromZones) == 0 {
			fromZones = []string{""}
		}
		if len(toZones) == 0 {
			toZones = []string{""}
		}

		var rules []*NATRule
		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
			rule := &NATRule{Name: ruleInst.name}

			matchNode := ruleInst.node.FindChild("match")
			if matchNode != nil {
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
					case "destination-port":
						rule.Match.DestinationPorts = append(rule.Match.DestinationPorts, parseDNATPortList(m)...)
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
						rule.Match.SourceAddressName = nodeVal(m)
					case "protocol":
						rule.Match.Protocol = nodeVal(m)
					case "application":
						rule.Match.Application = nodeVal(m)
					}
				}
			}

			thenNode := ruleInst.node.FindChild("then")
			if thenNode != nil {
				for _, t := range thenNode.Children {
					if t.Name() == "destination-nat" {
						if len(t.Keys) >= 3 && t.Keys[1] == "pool" {
							rule.Then.Type = NATDestination
							rule.Then.PoolName = t.Keys[2]
						} else if poolNode := t.FindChild("pool"); poolNode != nil {
							rule.Then.Type = NATDestination
							rule.Then.PoolName = nodeVal(poolNode)
						}
					}
				}
			}

			rules = append(rules, rule)
		}

		// Expand Cartesian product of from-zones × to-zones
		for _, fz := range fromZones {
			for _, tz := range toZones {
				rs := &NATRuleSet{
					Name:     rsInst.name,
					FromZone: fz,
					ToZone:   tz,
					Rules:    rules,
				}
				sec.NAT.Destination.RuleSets = append(sec.NAT.Destination.RuleSets, rs)
			}
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
func parseDNATPortList(m *Node) []int {
	var ports []int
	if len(m.Children) > 0 {
		// Check for set-syntax port range: Keys=["destination-port","20000"] + child "to 30000"
		if len(m.Keys) >= 2 {
			if low, err := strconv.Atoi(m.Keys[1]); err == nil {
				// Look for "to" child indicating a range
				toChild := m.FindChild("to")
				if toChild != nil {
					if high, err2 := strconv.Atoi(nodeVal(toChild)); err2 == nil && high >= low {
						for p := low; p <= high; p++ {
							ports = append(ports, p)
						}
						return ports
					}
				}
				// No range — just a port with non-range children (shouldn't happen, but be safe)
				ports = append(ports, low)
			}
		}
		// Multiple ports/ranges as children: destination-port { 80; 443; 20000 to 30000; }
		for i := 0; i < len(m.Children); i++ {
			child := m.Children[i]
			low, err := strconv.Atoi(child.Name())
			if err != nil {
				continue
			}
			// Hierarchical range: "20000 to 30000" → leaf Keys=["20000", "to", "30000"]
			if len(child.Keys) >= 3 && child.Keys[1] == "to" {
				if high, err2 := strconv.Atoi(child.Keys[2]); err2 == nil && high >= low {
					for p := low; p <= high; p++ {
						ports = append(ports, p)
					}
					continue
				}
			}
			// Sibling-node range: child[i]="20000", child[i+1]="to", child[i+2]="30000"
			if i+2 < len(m.Children) && m.Children[i+1].Name() == "to" {
				if high, err2 := strconv.Atoi(m.Children[i+2].Name()); err2 == nil && high >= low {
					for p := low; p <= high; p++ {
						ports = append(ports, p)
					}
					i += 2
					continue
				}
			}
			ports = append(ports, low)
		}
	} else if v := nodeVal(m); v != "" {
		// Single port: destination-port 8080;
		if n, err := strconv.Atoi(v); err == nil {
			ports = append(ports, n)
		}
	}
	return ports
}

func compileNATStatic(node *Node, sec *SecurityConfig) error {
	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
		// Parse from zones (bracket lists produce multiple keys)
		var fromZones []string
		for _, child := range rsInst.node.Children {
			if child.Name() == "from" {
				fromZones = append(fromZones, parseZoneList(child)...)
			}
		}
		if len(fromZones) == 0 {
			fromZones = []string{""}
		}

		// Parse rules (shared across all zone expansions)
		var rules []*StaticNATRule
		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
			rule := &StaticNATRule{Name: ruleInst.name}

			matchNode := ruleInst.node.FindChild("match")
			if matchNode != nil {
				for _, m := range matchNode.Children {
					switch m.Name() {
					case "destination-address":
						rule.Match = nodeVal(m)
					case "source-address":
						rule.SourceAddress = nodeVal(m)
					}
				}
			}

			thenNode := ruleInst.node.FindChild("then")
			if thenNode != nil {
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
						} else if len(t.Keys) >= 3 && t.Keys[1] == "prefix" {
							rule.Then = t.Keys[2]
						} else if pn := t.FindChild("prefix"); pn != nil {
							rule.Then = nodeVal(pn)
						} else if t.FindChild("inet") != nil || (len(t.Keys) >= 2 && t.Keys[1] == "inet") {
							// static-nat { inet; } — NAT64 translation
							rule.Then = "inet"
						}
					}
				}
			}

			rules = append(rules, rule)
		}

		// Expand for each from-zone
		for _, fz := range fromZones {
			rs := &StaticNATRuleSet{
				Name:     rsInst.name,
				FromZone: fz,
				Rules:    rules,
			}
			sec.NAT.Static = append(sec.NAT.Static, rs)
		}
	}
	return nil
}
