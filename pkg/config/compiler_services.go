package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var supportedRPMProbeTypes = map[string]struct{}{
	DefaultRPMProbeType: {},
	"tcp-ping":          {},
	"http-get":          {},
}

func parseRPMPositiveInt(probeName, testName, field, raw string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("services rpm probe %q test %q %s: invalid integer %q", probeName, testName, field, raw)
	}
	if n <= 0 {
		return 0, fmt.Errorf("services rpm probe %q test %q %s: must be > 0", probeName, testName, field)
	}
	return n, nil
}

func parseRPMRootPositiveInt(field, raw string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("services rpm %s: invalid integer %q", field, raw)
	}
	if n <= 0 {
		return 0, fmt.Errorf("services rpm %s: must be > 0", field)
	}
	return n, nil
}

func validateRPMTest(probeName string, test *RPMTest) error {
	if test.Target == "" {
		return fmt.Errorf("services rpm probe %q test %q: target is required", probeName, test.Name)
	}
	if _, ok := supportedRPMProbeTypes[test.EffectiveProbeType()]; !ok {
		return fmt.Errorf(
			"services rpm probe %q test %q: unsupported probe-type %q (want icmp-ping, tcp-ping, or http-get)",
			probeName, test.Name, test.ProbeType,
		)
	}
	if test.DestPort > 65535 {
		return fmt.Errorf("services rpm probe %q test %q destination-port: must be 1-65535", probeName, test.Name)
	}
	if test.NextHop != "" {
		nh := net.ParseIP(test.NextHop)
		if nh == nil {
			return fmt.Errorf("services rpm probe %q test %q next-hop: invalid IP address %q",
				probeName, test.Name, test.NextHop)
		}
		// The pinned host route is installed with an explicit `dev` +
		// `onlink`, so the egress interface must be named (#1827 §4.2.4).
		if test.DestinationInterface == "" {
			return fmt.Errorf("services rpm probe %q test %q: next-hop requires destination-interface "+
				"(the probe pin route needs an explicit egress device)", probeName, test.Name)
		}
		// The pin installs <target>/32 (or /128) via <next-hop>, so the
		// target must be an IP literal of the same address family.
		target := net.ParseIP(test.Target)
		if target == nil {
			return fmt.Errorf("services rpm probe %q test %q: next-hop pinning requires an IP-literal target (got %q)",
				probeName, test.Name, test.Target)
		}
		if (target.To4() == nil) != (nh.To4() == nil) {
			return fmt.Errorf("services rpm probe %q test %q: next-hop %q address family does not match target %q",
				probeName, test.Name, test.NextHop, test.Target)
		}
	}
	return nil
}

// validateRPMSourceAddressStrict rejects a malformed RPM test
// `source-address` (#2492). A non-empty but unparseable value silently
// turns the tcp-ping/http-get probe dialer into a wildcard/kernel-chosen
// source bind (net.ParseIP -> nil -> net.TCPAddr{IP:nil}), so the probe
// measures the DEFAULT uplink instead of the source-specific path the
// operator pinned. Because RPM feeds event-options / ip-monitoring
// failover, that publishes PASS for the wrong uplink (or FAILs a healthy
// source-specific path). The ICMP path already surfaces a bad source via
// its real listen error; tcp-ping/http-get had no such backstop.
//
// When the target is an IP literal, the source must share its address
// family: a v6 source can never bind a v4 destination connection (and
// vice-versa). For a hostname target the family is unknown until DNS
// resolves, so the family check is skipped — only the parse check
// applies. An EMPTY source-address is legitimate (default source bind)
// and is never rejected.
func validateRPMSourceAddressStrict(cfg *Config) error {
	if cfg == nil || cfg.Services.RPM == nil {
		return nil
	}
	for _, probe := range cfg.Services.RPM.Probes {
		if probe == nil {
			continue
		}
		for _, test := range probe.Tests {
			if test == nil || test.SourceAddress == "" {
				continue
			}
			src := net.ParseIP(test.SourceAddress)
			if src == nil {
				return fmt.Errorf("services rpm probe %q test %q source-address: invalid IP address %q",
					probe.Name, test.Name, test.SourceAddress)
			}
			// Family compatibility only applies to an IP-literal target;
			// a hostname target's family is unknown at commit time.
			if target := net.ParseIP(test.Target); target != nil {
				if (src.To4() == nil) != (target.To4() == nil) {
					return fmt.Errorf(
						"services rpm probe %q test %q: source-address %q address family does not match target %q",
						probe.Name, test.Name, test.SourceAddress, test.Target)
				}
			}
		}
	}
	return nil
}

// #2614: the #2493 validateRPMScopedHostnameStrict gate (which rejected a
// hostname target on a scoped RPM test) was REMOVED. The runtime resolver
// now binds the DNS socket to the probe's VRF/path scope
// (rpm.resolveProbeTarget / probeDialer.Resolver use the same
// SO_BINDTODEVICE / SO_MARK as the probe socket), so a scoped hostname
// resolves in-context and is a legitimate configuration. See
// docs/multi-wan.md.

// validateRPMLinkLocalZoneStrict rejects an IPv6 link-local RPM target
// that carries no scope (#2494). A link-local destination (fe80::/10) is
// meaningless without a zone: the kernel cannot pick the egress link, so
// the ICMP echo goes to the wrong link or fails outright. The scope can
// come from an explicit `%zone` on the target literal (fe80::1%ge-0/0/3)
// or be derived from the test's destination-interface (the same egress
// device the probe data socket binds via SO_BINDTODEVICE). A bare
// link-local with NEITHER is unprobeable and is refused so the operator
// sees the gap at commit instead of a silently-dead probe feeding
// ip-monitoring failover.
//
// Only IP-literal targets are checked: net.ParseIP rejects a zoned
// literal so the zone is split off by hand first (no DNS at commit). A
// hostname resolving to a link-local cannot be caught here (resolution is
// runtime); a hostname that resolves to a bare link-local would fail at
// runtime with ErrProbeSetup (the same missing-zone error in probeICMP).
// routing-instance / next-hop scopes do
// NOT supply a link scope (a VRF master device / fwmark route is not an
// egress link for fe80::), so only destination-interface satisfies the
// requirement. Strict on commit / commit-check (hard reject so the gap is
// operator-visible); lenient on load / peer-sync (warn — #1960 no-brick;
// the runtime probeICMP guard returns ErrProbeSetup for the same bare
// link-local, so a leniently-loaded test HOLDS state instead of actuating
// routes off a dead measurement). Mirrors validateRPMSourceAddressStrict.
func validateRPMLinkLocalZoneStrict(cfg *Config) error {
	if cfg == nil || cfg.Services.RPM == nil {
		return nil
	}
	for _, probe := range cfg.Services.RPM.Probes {
		if probe == nil {
			continue
		}
		for _, test := range probe.Tests {
			if test == nil || test.Target == "" {
				continue
			}
			host := test.Target
			zone := ""
			if i := strings.IndexByte(host, '%'); i >= 0 {
				zone = host[i+1:]
				host = host[:i]
			}
			ip := net.ParseIP(host)
			if ip == nil || ip.To4() != nil || !ip.IsLinkLocalUnicast() {
				continue // not an IPv6 link-local literal
			}
			if zone == "" && test.DestinationInterface == "" {
				return fmt.Errorf(
					"services rpm probe %q test %q: target %q is an IPv6 link-local address "+
						"with no scope — add an explicit %%zone (fe80::1%%ge-0/0/3) or a "+
						"destination-interface so the probe can pick the egress link",
					probe.Name, test.Name, test.Target)
			}
		}
	}
	return nil
}

// validateRPMHTTPGetSchemeStrict rejects an http-get RPM test whose
// target carries an unsupported URL scheme (#2495) OR canonicalizes to a
// hostless URL (C179-042). The runtime probe canonicalizes a schemeless
// target (bare hostname / IP / host:port) by prepending "http://", and
// accepts an explicit "http://" or "https://" target as-is; any other
// scheme (ftp://, gopher://, …) is meaningless for an http-get probe and
// makes http.NewRequestWithContext error before a packet is sent — the
// probe never runs and publishes a permanent FAIL into event-options /
// ip-monitoring failover. A scheme is only present when the target
// contains the "://" separator; a bare "host:port" (no "://") is NOT a
// scheme and is left for the runtime to prefix with http://. Either form
// is then host-checked: a target with no host ("http://", "https://", a
// schemeless ":8080") produces a URL the client cannot dial, so the
// probe would be dead in exactly the same way — reject it too. Only the
// literal target is inspected (no DNS at commit).
//
// Strict on commit / commit-check (hard reject so the operator sees the
// bad scheme immediately); lenient on load / peer-sync (warn — #1960
// no-brick; the runtime canonicalizeHTTPTarget guard returns the same
// error for the bad scheme, so a leniently-loaded test HOLDS state
// instead of actuating routes off a probe that can never run). Mirrors
// validateRPMLinkLocalZoneStrict.
func validateRPMHTTPGetSchemeStrict(cfg *Config) error {
	if cfg == nil || cfg.Services.RPM == nil {
		return nil
	}
	for _, probe := range cfg.Services.RPM.Probes {
		if probe == nil {
			continue
		}
		for _, test := range probe.Tests {
			if test == nil || test.Target == "" {
				continue
			}
			if test.EffectiveProbeType() != "http-get" {
				continue
			}
			// C179-042: a hostless target ("http://", "https://", a
			// schemeless ":8080") canonicalizes to a URL http.NewRequest /
			// the client cannot dial — the probe never sends a packet and its
			// permanent no-run is counted as path loss into event-options /
			// ip-monitoring failover. Reject the empty host at commit so the
			// operator sees it instead of a silently dead probe. hostErr is
			// the shared message for both target forms below.
			hostErr := func() error {
				return fmt.Errorf(
					"services rpm probe %q test %q: http-get target %q has no host "+
						"(an http-get probe needs a hostname or IP address to connect to)",
					probe.Name, test.Name, test.Target)
			}
			// A scheme is present only with the "://" separator; a bare
			// host:port is schemeless (the runtime prepends http://).
			if !strings.Contains(test.Target, "://") {
				// Schemeless: host-check the canonicalized "http://"+target.
				// Stay lenient on a url.Parse failure (unchanged pre-C179-042
				// behavior) so this ADDS only the empty-host rejection — a
				// malformed schemeless target still falls through to the
				// runtime, which handles it exactly as before.
				if u, err := url.Parse("http://" + test.Target); err == nil && u.Hostname() == "" {
					return hostErr()
				}
				continue
			}
			u, err := url.Parse(test.Target)
			if err != nil {
				return fmt.Errorf("services rpm probe %q test %q: invalid http-get target URL %q: %w",
					probe.Name, test.Name, test.Target, err)
			}
			switch u.Scheme {
			case "http", "https":
				// supported
			default:
				return fmt.Errorf(
					"services rpm probe %q test %q: http-get target %q uses unsupported scheme %q "+
						"(only http and https are valid for an http-get probe)",
					probe.Name, test.Name, test.Target, u.Scheme)
			}
			if u.Hostname() == "" {
				return hostErr()
			}
		}
	}
	return nil
}

// validateRPMRoutingInstanceStrict rejects an RPM test whose
// `routing-instance` does not name a CONFIGURED routing instance (#2496).
// The runtime binds the probe DATA socket to the instance's VRF device
// via SO_BINDTODEVICE — vrfDeviceName(ri) synthesizes "vrf-<name>"
// (pkg/rpm/rpm.go). A typo'd / nonexistent instance has no such kernel
// device, so the bind fails with ENODEV: the probe never sends a packet
// and the test silently HOLDS its state forever (never PASS, never FAIL),
// so any event-options / ip-monitoring policy keyed off it gets no
// failover signal. It fails safe (no false PASS), but the candidate
// config should have been rejected at commit so the operator sees the
// typo rather than a permanently dead probe.
//
// An EMPTY routing-instance means the default (master) context and is NOT
// scoped to a VRF device — it is always accepted. Only a non-empty name
// that does not match a configured instance is the error. The configured-
// instance enumeration mirrors validateIPMonitoringStrict's preferred-route
// routing-instance check exactly (same cfg.RoutingInstances source, same
// empty-is-default handling, same "does not exist" error shape).
//
// Strict on commit / commit-check (hard reject so the typo is
// operator-visible); lenient on load / peer-sync (warn — #1960 no-brick;
// the runtime bind returns ENODEV for the same nonexistent instance, so a
// leniently-loaded test HOLDS state instead of actuating routes off a dead
// measurement). Mirrors validateRPMHTTPGetSchemeStrict.
func validateRPMRoutingInstanceStrict(cfg *Config) error {
	if cfg == nil || cfg.Services.RPM == nil {
		return nil
	}
	instances := make(map[string]*RoutingInstanceConfig)
	for _, ri := range cfg.RoutingInstances {
		if ri != nil {
			instances[ri.Name] = ri
		}
	}
	for _, probe := range cfg.Services.RPM.Probes {
		if probe == nil {
			continue
		}
		for _, test := range probe.Tests {
			if test == nil || test.RoutingInstance == "" {
				continue
			}
			if _, ok := instances[test.RoutingInstance]; !ok {
				return fmt.Errorf(
					"services rpm probe %q test %q: routing-instance %q does not exist "+
						"(the probe would bind a nonexistent vrf-%s device and never run)",
					probe.Name, test.Name, test.RoutingInstance, test.RoutingInstance)
			}
		}
	}
	return nil
}

// validateRPMProbePinsStrict enforces the probe-pin band invariants
// (#1827 PR-1a): at most ProbeTableCount next-hop-pinned tests (one
// reserved kernel table each), and no routing-instance table ID may
// collide with the reserved probe table range 7000-7049.
func validateRPMProbePinsStrict(cfg *Config) error {
	pinned := 0
	if cfg.Services.RPM != nil {
		for _, probe := range cfg.Services.RPM.Probes {
			if probe == nil {
				continue
			}
			for _, test := range probe.Tests {
				if test != nil && test.NextHop != "" {
					pinned++
				}
			}
		}
	}
	if pinned > ProbeTableCount {
		return fmt.Errorf("services rpm: %d tests configure next-hop pinning, exceeding the reserved probe table band (%d tables %d-%d)",
			pinned, ProbeTableCount, ProbeTableBase, ProbeTableBase+ProbeTableCount-1)
	}
	if pinned > 0 {
		for _, ri := range cfg.RoutingInstances {
			if ri == nil {
				continue
			}
			if ri.TableID >= ProbeTableBase && ri.TableID < ProbeTableBase+ProbeTableCount {
				return fmt.Errorf("routing-instance %q table ID %d collides with the reserved RPM probe table range %d-%d",
					ri.Name, ri.TableID, ProbeTableBase, ProbeTableBase+ProbeTableCount-1)
			}
		}
	}
	return nil
}

func compileDHCPLocalServer(node *Node, dhcp *DHCPServerConfig, isV6 bool) error {
	lsc := &DHCPLocalServerConfig{
		Groups: make(map[string]*DHCPServerGroup),
	}
	if isV6 {
		dhcp.DHCPv6LocalServer = lsc
	} else {
		dhcp.DHCPLocalServer = lsc
	}

	// #1387 + #2691 P1b (#2663 independent v4/v6 policy): the dynamic-dns block
	// is a server-level policy for THIS family. It can appear under
	// dhcp-local-server (v4) and/or dhcpv6-local-server (v6); each family's
	// block now compiles into its OWN typed field — DynamicDNS (v4) /
	// DynamicDNSv6 (v6) — so the two families keep INDEPENDENT
	// domain/server/TSIG/TTL/conflict-policy/source-binding. This replaces the
	// pre-P1b field-MERGE (mergeDHCPDynamicDNS), under which a v6 `domain`
	// silently filled an empty v4 field and a single shared struct could not
	// represent two different servers. mergeDHCPDynamicDNS is retained ONLY for
	// the degenerate same-family-block-seen-twice case (compileDHCPLocalServer
	// runs once per family, so it is effectively a defensive no-op now).
	if ddnsNode := node.FindChild("dynamic-dns"); ddnsNode != nil {
		if ddns := compileDHCPDynamicDNS(ddnsNode); ddns != nil {
			if isV6 {
				dhcp.DynamicDNSv6 = mergeDHCPDynamicDNS(dhcp.DynamicDNSv6, ddns)
			} else {
				dhcp.DynamicDNS = mergeDHCPDynamicDNS(dhcp.DynamicDNS, ddns)
			}
		}
	}

	// #1387 (stale-lease-cleanup slice / Path S): the
	// expired-leases-processing block is GLOBAL to the family (Kea renders
	// it per Dhcp4/Dhcp6, never per-subnet), so it attaches to this
	// family's DHCPLocalServerConfig (lsc), NOT to a pool. v4 and v6 are
	// tuned independently. A truly empty/garbage block compiles to nil so
	// it neither forces reclamation on nor renders anything.
	if elpNode := node.FindChild("expired-leases-processing"); elpNode != nil {
		lsc.ExpiredLeases = compileDHCPExpiredLeases(elpNode)
	}

	for _, groupInst := range namedInstances(node.FindChildren("group")) {
		group := &DHCPServerGroup{Name: groupInst.name}

		for _, prop := range groupInst.node.Children {
			switch prop.Name() {
			case "interface":
				if v := nodeVal(prop); v != "" {
					group.Interfaces = append(group.Interfaces, v)
				}
			case "pool":
				poolName := nodeVal(prop)
				if poolName != "" {
					pool := &DHCPPool{Name: poolName}
					poolChildren := prop.Children
					if len(prop.Keys) < 2 && len(prop.Children) > 0 {
						poolChildren = prop.Children[0].Children
					}
					for _, pp := range poolChildren {
						switch pp.Name() {
						case "address-range":
							if len(pp.Keys) >= 5 && pp.Keys[1] == "low" && pp.Keys[3] == "high" {
								pool.RangeLow = pp.Keys[2]
								pool.RangeHigh = pp.Keys[4]
							}
						case "subnet":
							pool.Subnet = nodeVal(pp)
						case "router":
							pool.Router = nodeVal(pp)
						case "dns-server":
							if v := nodeVal(pp); v != "" {
								pool.DNSServers = append(pool.DNSServers, v)
							}
						case "lease-time":
							if v := nodeVal(pp); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									pool.LeaseTime = n
								}
							}
						case "domain-name":
							pool.Domain = nodeVal(pp)
						case "static-binding":
							// #2243: fixed/reserved host bindings. Dual-AST:
							// hierarchical `static-binding <mac> { fixed-address
							// <ip>; host-name <n>; }` packs the MAC into Keys[1]
							// (namedInstances picks it up directly); a flat-set
							// `static-binding <mac> fixed-address <ip>` lands the
							// MAC in Keys[1] too. A bare `static-binding { <mac> {
							// ... } }` block nests the MAC one level down, which
							// namedInstances also handles. Each instance's leaves
							// (fixed-address / host-name) are the instance node's
							// children in both shapes.
							for _, sbInst := range namedInstances([]*Node{pp}) {
								sb := &DHCPStaticBinding{MACAddress: sbInst.name}
								for _, leaf := range sbInst.node.Children {
									switch leaf.Name() {
									case "fixed-address":
										sb.FixedAddress = nodeVal(leaf)
									case "host-name":
										sb.HostName = nodeVal(leaf)
									}
								}
								pool.StaticBindings = append(pool.StaticBindings, sb)
							}
						}
					}
					group.Pools = append(group.Pools, pool)
				}
			}
		}

		lsc.Groups[group.Name] = group
	}
	return nil
}

// mergeDHCPDynamicDNS merges a freshly-compiled dynamic-dns block (src)
// into the existing one (dst), field-by-field, so a partial block under the
// second family does not clobber settings the first family established
// (#1387). dst may be nil (first family seen). A field set in EITHER block
// wins: for strings/ttl, a non-zero src value fills an empty dst field (dst
// keeps its own non-zero value — first-family-wins on a genuine conflict,
// matching compileDHCPDynamicDNS's first-value-wins intra-block rule). The
// presence-only Enabled flag LATCHES: once any family enables DDNS it stays
// enabled (a partial second block can never flip it false). src is non-nil
// (compileDHCPDynamicDNS returned a real block).
func mergeDHCPDynamicDNS(dst, src *DHCPDynamicDNSConfig) *DHCPDynamicDNSConfig {
	if dst == nil {
		return src
	}
	dst.Enabled = dst.Enabled || src.Enabled
	if dst.Domain == "" {
		dst.Domain = src.Domain
	}
	if dst.HostnameSource == "" {
		dst.HostnameSource = src.HostnameSource
	}
	if dst.ConflictPolicy == "" {
		dst.ConflictPolicy = src.ConflictPolicy
	}
	if dst.Backend == "" {
		dst.Backend = src.Backend
	}
	if dst.UpdateServer == "" {
		dst.UpdateServer = src.UpdateServer
	}
	if dst.TSIGKeyName == "" {
		dst.TSIGKeyName = src.TSIGKeyName
	}
	if dst.TSIGAlgorithm == "" {
		dst.TSIGAlgorithm = src.TSIGAlgorithm
	}
	if dst.TSIGSecret == "" {
		dst.TSIGSecret = src.TSIGSecret
	}
	if dst.SourceAddress == "" {
		dst.SourceAddress = src.SourceAddress
	}
	if dst.DestinationInterface == "" {
		dst.DestinationInterface = src.DestinationInterface
	}
	if dst.RoutingInstance == "" {
		dst.RoutingInstance = src.RoutingInstance
	}
	if dst.TTLSeconds == 0 {
		dst.TTLSeconds = src.TTLSeconds
	}
	return dst
}

// dhcpDDNSStringProps are the dynamic-dns leaves that carry a string
// value (everything except the valueless `enable` flag and the integer
// `ttl`). Used by compileDHCPDynamicDNS's internal subtree walker to
// recognize a "<leaf> <value>" pair at any depth regardless of the AST
// shape.
var dhcpDDNSStringProps = map[string]bool{
	"domain":          true,
	"hostname-source": true,
	"conflict-policy": true,
	"backend":         true,
	"update-server":   true,
	"tsig-key":        true,
	"tsig-algorithm":  true,
	"tsig-secret":     true,
	// #2691 P1b / #2665 source-binding leaves (per-family transport scoping).
	"source-address":        true,
	"destination-interface": true,
	"routing-instance":      true,
}

// compileDHCPDynamicDNS converts a parsed `dynamic-dns` subtree into a
// typed *DHCPDynamicDNSConfig (#1387). It handles BOTH the hierarchical
// shape (`dynamic-dns { enable; ttl 300; domain corp.example.com; }`,
// each leaf a separate child node) and the flat-set shape
// (`set ... dynamic-dns ttl 300`, where SetPath may pack trailing
// property tokens into a single leaf node's Keys). Returns nil for a
// truly empty block so an empty/garbage stanza does not force DDNS on;
// the runtime keys "configured" on a non-nil block AND Enabled.
func compileDHCPDynamicDNS(node *Node) *DHCPDynamicDNSConfig {
	d := &DHCPDynamicDNSConfig{}
	props := map[string]string{}
	enabled := false

	// Walk the subtree. A leaf can appear as a child node (Keys[0]==leaf,
	// value at Keys[1]) or be packed into a parent node's Keys at any
	// depth (e.g. flat-set `dynamic-dns ttl 300 domain x` collapses into
	// one node with Keys=[..., ttl, 300, domain, x]). First value wins so
	// a later malformed re-set cannot clobber a good one.
	var walk func(n *Node, isRoot bool)
	walk = func(n *Node, isRoot bool) {
		start := 0
		if isRoot {
			start = 1 // skip the "dynamic-dns" identifier itself
		}
		for i := start; i < len(n.Keys); i++ {
			k := n.Keys[i]
			switch {
			case k == "enable":
				enabled = true
			case k == "ttl" && i+1 < len(n.Keys):
				if _, ok := props["ttl"]; !ok {
					props["ttl"] = n.Keys[i+1]
				}
				i++
			case dhcpDDNSStringProps[k] && i+1 < len(n.Keys):
				if _, ok := props[k]; !ok {
					props[k] = n.Keys[i+1]
				}
				i++
			}
		}
		for _, c := range n.Children {
			walk(c, false)
		}
	}
	walk(node, true)

	d.Enabled = enabled
	d.Domain = props["domain"]
	d.HostnameSource = props["hostname-source"]
	d.ConflictPolicy = props["conflict-policy"]
	d.Backend = props["backend"]
	d.UpdateServer = props["update-server"]
	d.TSIGKeyName = props["tsig-key"]
	d.TSIGAlgorithm = props["tsig-algorithm"]
	d.TSIGSecret = Secret(props["tsig-secret"])
	d.SourceAddress = props["source-address"]
	d.DestinationInterface = props["destination-interface"]
	d.RoutingInstance = props["routing-instance"]
	if v := props["ttl"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			d.TTLSeconds = n
		}
	}

	// Empty block -> treat as absent (no DDNS). A block with only
	// `enable` is meaningful (defaults apply), so check the union.
	if !d.Enabled && d.Domain == "" && d.HostnameSource == "" &&
		d.ConflictPolicy == "" && d.Backend == "" && d.UpdateServer == "" &&
		d.TSIGKeyName == "" && d.TSIGAlgorithm == "" && d.TSIGSecret == "" &&
		d.SourceAddress == "" && d.DestinationInterface == "" &&
		d.RoutingInstance == "" && d.TTLSeconds == 0 {
		return nil
	}
	return d
}

// dhcpExpiredLeasesIntProps are the integer-valued expired-leases-processing
// leaves (everything except the valueless `enable` flag). Used by
// compileDHCPExpiredLeases's subtree walker to recognize a "<leaf> <value>"
// pair at any depth regardless of the AST shape.
var dhcpExpiredLeasesIntProps = map[string]bool{
	"reclaim-timer":   true,
	"flush-timer":     true,
	"hold-time":       true,
	"max-leases":      true,
	"max-time":        true,
	"unwarned-cycles": true,
}

// compileDHCPExpiredLeases converts a parsed `expired-leases-processing`
// subtree into a typed *DHCPExpiredLeasesConfig (#1387 stale-lease-cleanup
// slice). Like compileDHCPDynamicDNS it handles BOTH the hierarchical
// shape (`expired-leases-processing { enable; reclaim-timer 10; }`, each
// leaf a separate child node) and the flat-set shape
// (`set ... expired-leases-processing reclaim-timer 10`, where SetPath may
// pack trailing property tokens into a single leaf node's Keys). First
// value wins so a later malformed re-set cannot clobber a good one.
//
// Returns nil for a truly empty/garbage block so an empty stanza neither
// forces reclamation on nor renders anything (closing the
// empty-tree-compiles-non-nil trap). The set/unset distinction for the
// cap knobs (max-leases / max-time) is preserved into the model: 0 is a
// MEANINGFUL Kea value (unlimited) that must render distinctly from unset
// (invariant H2), so a *Set bool latches when the operator supplies the
// key.
func compileDHCPExpiredLeases(node *Node) *DHCPExpiredLeasesConfig {
	c := &DHCPExpiredLeasesConfig{}
	props := map[string]string{}
	enabled := false

	var walk func(n *Node, isRoot bool)
	walk = func(n *Node, isRoot bool) {
		start := 0
		if isRoot {
			start = 1 // skip the "expired-leases-processing" identifier itself
		}
		for i := start; i < len(n.Keys); i++ {
			k := n.Keys[i]
			switch {
			case k == "enable":
				enabled = true
			case dhcpExpiredLeasesIntProps[k] && i+1 < len(n.Keys):
				if _, ok := props[k]; !ok {
					props[k] = n.Keys[i+1]
				}
				i++
			}
		}
		for _, ch := range n.Children {
			walk(ch, false)
		}
	}
	walk(node, true)

	c.Enabled = enabled
	// parseInt sets the field from a decimal prop value when present and
	// well-formed, returning whether the key was present at all (so the
	// caller can distinguish a configured 0 from an unset key for the cap
	// knobs). A garbage value is treated as unset for that field.
	parseInt := func(key string, dst *int) bool {
		v, present := props[key]
		if !present {
			return false
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return false
		}
		*dst = n
		return true
	}
	parseInt("reclaim-timer", &c.ReclaimTimerWait)
	parseInt("flush-timer", &c.FlushReclaimedTimerWait)
	parseInt("hold-time", &c.HoldReclaimedTime)
	c.MaxReclaimLeasesSet = parseInt("max-leases", &c.MaxReclaimLeases)
	c.MaxReclaimTimeSet = parseInt("max-time", &c.MaxReclaimTime)
	parseInt("unwarned-cycles", &c.UnwarnedReclaimCycles)

	// Empty block -> treat as absent (no reclamation block rendered). A
	// block with only `enable` is meaningful (Kea reads {} as "defaults"),
	// so check the union of enable + any configured field.
	if !c.Enabled && c.ReclaimTimerWait == 0 && c.FlushReclaimedTimerWait == 0 &&
		c.HoldReclaimedTime == 0 && !c.MaxReclaimLeasesSet && !c.MaxReclaimTimeSet &&
		c.UnwarnedReclaimCycles == 0 {
		return nil
	}
	return c
}

func compileDynamicAddress(node *Node, sec *SecurityConfig) error {
	if sec.DynamicAddress.FeedServers == nil {
		sec.DynamicAddress.FeedServers = make(map[string]*FeedServer)
	}
	if sec.DynamicAddress.AddressBindings == nil {
		sec.DynamicAddress.AddressBindings = make(map[string]*AddressBinding)
	}

	for _, inst := range namedInstances(node.FindChildren("feed-server")) {
		fs := &FeedServer{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "url":
				fs.URL = nodeVal(prop)
			case "hostname":
				fs.Hostname = nodeVal(prop)
			case "update-interval":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						fs.UpdateInterval = n
					}
				}
			case "hold-interval":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						fs.HoldInterval = n
					}
				}
			case "feed-name":
				fnName := nodeVal(prop)
				if len(prop.Children) > 0 {
					fe := FeedEntry{Name: fnName}
					for _, c := range prop.Children {
						if c.Name() == "path" {
							fe.Path = nodeVal(c)
						}
					}
					fs.FeedEntries = append(fs.FeedEntries, fe)
				} else {
					fs.FeedName = fnName
				}
			}
		}

		sec.DynamicAddress.FeedServers[fs.Name] = fs
	}

	for _, inst := range namedInstances(node.FindChildren("address-name")) {
		ab := &AddressBinding{Name: inst.name}
		if profile := inst.node.FindChild("profile"); profile != nil {
			for _, c := range profile.Children {
				if c.Name() == "feed-name" {
					if fn := nodeVal(c); fn != "" {
						ab.FeedNames = append(ab.FeedNames, fn)
					}
				}
			}
		}
		sec.DynamicAddress.AddressBindings[ab.Name] = ab
	}

	return nil
}

func compileServices(node *Node, svc *ServicesConfig) error {
	if fmNode := node.FindChild("flow-monitoring"); fmNode != nil {
		if err := compileFlowMonitoring(fmNode, svc); err != nil {
			return err
		}
	}
	if rpmNode := node.FindChild("rpm"); rpmNode != nil {
		if err := compileRPM(rpmNode, svc); err != nil {
			return err
		}
	}
	if ipmNode := node.FindChild("ip-monitoring"); ipmNode != nil {
		if err := compileIPMonitoring(ipmNode, svc); err != nil {
			return err
		}
	}
	if node.FindChild("application-identification") != nil {
		svc.ApplicationIdentification = true
	}
	return nil
}

// compileIPMonitoring parses `services ip-monitoring` (#1827 PR-1b).
// Both AST shapes are handled: hierarchical blocks and flat-set replay.
// Two set lines for the same (routing-instance, route) merge into one
// PreferredRoute (next-hop + preferred-metric arrive on separate lines).
func compileIPMonitoring(node *Node, svc *ServicesConfig) error {
	cfg := &IPMonitoringConfig{Policies: make(map[string]*IPMonitoringPolicy)}

	for _, polInst := range namedInstances(node.FindChildren("policy")) {
		pol := &IPMonitoringPolicy{Name: polInst.name}
		routes := make(map[string]*PreferredRoute)
		var order []string

		for _, prop := range polInst.node.Children {
			switch prop.Name() {
			case "match":
				// `match { rpm-probe X; }` or inline `match rpm-probe X;`
				if len(prop.Keys) >= 3 && prop.Keys[1] == "rpm-probe" {
					pol.MatchRPMProbe = prop.Keys[2]
				}
				if c := prop.FindChild("rpm-probe"); c != nil {
					if v := nodeVal(c); v != "" {
						pol.MatchRPMProbe = v
					}
				}
			case "then":
				for _, prNode := range prop.FindChildren("preferred-route") {
					if err := compilePreferredRoutes(prNode, "", pol.Name, routes, &order); err != nil {
						return err
					}
					for _, riInst := range namedInstances(prNode.FindChildren("routing-instance")) {
						if err := compilePreferredRoutes(riInst.node, riInst.name, pol.Name, routes, &order); err != nil {
							return err
						}
					}
				}
			case "hold-down":
				if v := nodeVal(prop); v != "" {
					n, err := strconv.Atoi(v)
					if err != nil || n < 0 {
						return fmt.Errorf("services ip-monitoring policy %q hold-down: invalid value %q", pol.Name, v)
					}
					pol.HoldDownSecs = n
				}
			}
		}

		for _, key := range order {
			pol.PreferredRoutes = append(pol.PreferredRoutes, routes[key])
		}
		cfg.Policies[pol.Name] = pol
	}

	svc.IPMonitoring = cfg
	return nil
}

// compilePreferredRoutes collects `route <cidr> { next-hop X;
// preferred-metric N; }` children of a preferred-route (or its
// routing-instance sub-block), merging repeated lines for the same
// destination.
func compilePreferredRoutes(node *Node, ri, polName string, routes map[string]*PreferredRoute, order *[]string) error {
	for _, rInst := range namedInstances(node.FindChildren("route")) {
		key := ri + "|" + rInst.name
		r := routes[key]
		if r == nil {
			r = &PreferredRoute{RoutingInstance: ri, Destination: rInst.name}
			routes[key] = r
			*order = append(*order, key)
		}
		setMetric := func(v string) error {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return fmt.Errorf("services ip-monitoring policy %q route %s preferred-metric: invalid value %q",
					polName, r.Destination, v)
			}
			r.PreferredMetric = n
			return nil
		}
		// Inline keys: `route 0.0.0.0/0 next-hop 1.2.3.4;`
		keys := rInst.node.Keys
		for i := 2; i+1 < len(keys); i += 2 {
			switch keys[i] {
			case "next-hop":
				r.NextHop = keys[i+1]
			case "preferred-metric":
				if err := setMetric(keys[i+1]); err != nil {
					return err
				}
			}
		}
		// Child-node shape (hierarchical blocks + flat-set replay).
		for _, p := range rInst.node.Children {
			switch p.Name() {
			case "next-hop":
				if v := nodeVal(p); v != "" {
					r.NextHop = v
				}
			case "preferred-metric":
				if v := nodeVal(p); v != "" {
					if err := setMetric(v); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// validateIPMonitoringStrict enforces the #1827 commit checks:
// the matched probe exists, every policy has at least one
// preferred-route, destinations/next-hops are family-consistent, and
// referenced routing instances exist. PR-1b additionally rejected
// `instance-type forwarding` targets; PR-2 lifted that rejection —
// forwarding instances now render into their dedicated kernel table
// (FRR `table <id>`), matching the dataplane's `<ri>.inet.0`, so the
// FRR-vs-dataplane divergence that motivated the fence is fixed.
//
// #1844: a next-hop value that is not an IP literal may instead name a
// DHCP-enabled interface unit (`next-hop ge-0/0/3.0`) — the injected
// route then tracks that unit's DHCP-learned gateway. This function
// also DERIVES the typed-model split for that form (it runs on every
// compile path, strict and lenient alike, so the derivation is present
// after boot Load as well as commit): on success
// PreferredRoute.NextHopInterface is set to the shared DHCPLeaseIfName
// lease key and NextHop is cleared (mutually exclusive). Idempotent:
// an already-derived route is left untouched.
func validateIPMonitoringStrict(cfg *Config) error {
	ipm := cfg.Services.IPMonitoring
	if ipm == nil {
		return nil
	}
	instances := make(map[string]*RoutingInstanceConfig)
	for _, ri := range cfg.RoutingInstances {
		if ri != nil {
			instances[ri.Name] = ri
		}
	}
	for name, pol := range ipm.Policies {
		if pol == nil {
			continue
		}
		if pol.MatchRPMProbe == "" {
			return fmt.Errorf("services ip-monitoring policy %q: match rpm-probe is required", name)
		}
		if cfg.Services.RPM == nil || cfg.Services.RPM.Probes[pol.MatchRPMProbe] == nil {
			return fmt.Errorf("services ip-monitoring policy %q: match rpm-probe %q does not reference a configured services rpm probe",
				name, pol.MatchRPMProbe)
		}
		if len(pol.PreferredRoutes) == 0 {
			return fmt.Errorf("services ip-monitoring policy %q: at least one then preferred-route route is required", name)
		}
		for _, pr := range pol.PreferredRoutes {
			_, dst, err := net.ParseCIDR(pr.Destination)
			if err != nil {
				return fmt.Errorf("services ip-monitoring policy %q route %q: invalid destination prefix",
					name, pr.Destination)
			}
			switch {
			case pr.NextHopInterface != "":
				// Already derived (idempotent re-validation).
			case net.ParseIP(pr.NextHop) != nil:
				nh := net.ParseIP(pr.NextHop)
				if (dst.IP.To4() == nil) != (nh.To4() == nil) {
					return fmt.Errorf("services ip-monitoring policy %q route %s: next-hop %q address family does not match destination",
						name, pr.Destination, pr.NextHop)
				}
			default:
				leaseIface, err := resolveIPMonitoringInterfaceNextHop(cfg, name, pr, dst)
				if err != nil {
					return err
				}
				pr.NextHopInterface = leaseIface
				pr.NextHop = ""
			}
			if pr.RoutingInstance != "" {
				if _, ok := instances[pr.RoutingInstance]; !ok {
					return fmt.Errorf("services ip-monitoring policy %q route %s: routing-instance %q does not exist",
						name, pr.Destination, pr.RoutingInstance)
				}
			}
		}
	}
	return nil
}

// resolveIPMonitoringInterfaceNextHop classifies a non-IP-literal
// preferred-route next-hop value as a DHCP interface unit reference
// (#1844 plan §4.1) and returns the Linux lease key the runtime
// resolver will look up. The accepted form is `<ifd>.<unit-number>`
// where <ifd> is EXACTLY an interface name as configured under
// `interfaces` (Junos form, e.g. ge-0/0/3 — the dashed Linux form is
// not accepted) and <unit-number> is a configured unit of it with
// `family inet dhcp`. Restrictions (each with a distinct error):
//
//   - a bare ifd without `.unit` is rejected;
//   - management interfaces (fxp*/em*/fab* — the name classes the
//     daemon binds to the mgmt VRF) are rejected: collectDHCPRoutes
//     deliberately excludes mgmt leases from FRR, and an overlay route
//     through the mgmt gateway would leak management routing into the
//     default table;
//   - inet6 destinations are rejected (v4-only: DHCPv6 gateways are
//     RA-discovered link-locals and the snapshot RouteSnapshot has no
//     device field — v6 support is a wire-protocol follow-up);
//   - a unit without `family inet dhcp` is rejected (the route tracks
//     a DHCP-learned gateway by definition);
//   - tunnel and loopback interfaces are rejected explicitly (Codex
//     PR #1851 review): the interface compiler sets unit.DHCP from
//     the AST without an interface-class guard, so `family inet dhcp`
//     on a gr-/ip-/st0/lo0/fti unit DOES compile — a DHCP client on a
//     tunnel/loopback can never acquire a lease, so accepting it here
//     would only manufacture a permanently-unresolvable route.
func resolveIPMonitoringInterfaceNextHop(cfg *Config, polName string, pr *PreferredRoute, dst *net.IPNet) (string, error) {
	val := pr.NextHop
	if cfg.Interfaces.Interfaces[val] != nil {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: interface-typed next-hop requires <ifd>.<unit> (got bare interface %q)",
			polName, pr.Destination, val)
	}
	idx := strings.LastIndex(val, ".")
	if idx <= 0 || idx == len(val)-1 {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: next-hop %q is not a valid IP address or DHCP interface unit",
			polName, pr.Destination, val)
	}
	ifdName, unitStr := val[:idx], val[idx+1:]
	unitNum, err := strconv.Atoi(unitStr)
	ifc := cfg.Interfaces.Interfaces[ifdName]
	if err != nil || unitNum < 0 || ifc == nil {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: next-hop %q is not a valid IP address or DHCP interface unit (interface units use the configured Junos name, e.g. ge-0/0/3.0)",
			polName, pr.Destination, val)
	}
	if strings.HasPrefix(ifdName, "fxp") || strings.HasPrefix(ifdName, "em") ||
		strings.HasPrefix(ifdName, "fab") {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: next-hop %q names a management interface; management leases cannot back an ip-monitoring preferred route",
			polName, pr.Destination, val)
	}
	if dst.IP.To4() == nil {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: interface-typed next-hop %q is inet-only (DHCPv6 gateways are RA-derived link-locals; inet6 support is a follow-up)",
			polName, pr.Destination, val)
	}
	unit := ifc.Units[unitNum]
	if unit == nil {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: next-hop %q: interface %s has no unit %d",
			polName, pr.Destination, val, ifdName, unitNum)
	}
	if ifc.Tunnel != nil || unit.Tunnel != nil ||
		strings.HasPrefix(ifdName, "lo") || strings.HasPrefix(ifdName, "st") ||
		strings.HasPrefix(ifdName, "gr-") || strings.HasPrefix(ifdName, "ip-") ||
		strings.HasPrefix(ifdName, "fti") {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: next-hop %q names a tunnel or loopback interface; a DHCP-tracked next-hop requires a broadcast interface unit",
			polName, pr.Destination, val)
	}
	if !unit.DHCP {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: interface-typed next-hop requires family inet dhcp on %s unit %d",
			polName, pr.Destination, ifdName, unitNum)
	}
	return DHCPLeaseIfName(ifdName, unit), nil
}

func compileRPM(node *Node, svc *ServicesConfig) error {
	rpmCfg := &RPMConfig{Probes: make(map[string]*RPMProbe)}
	defaultProbeLimit := 0

	if probeLimitNode := node.FindChild("probe-limit"); probeLimitNode != nil {
		if v := nodeVal(probeLimitNode); v != "" {
			n, err := parseRPMRootPositiveInt("probe-limit", v)
			if err != nil {
				return err
			}
			defaultProbeLimit = n
		}
	}

	for _, probeInst := range namedInstances(node.FindChildren("probe")) {
		// #4820: find-or-create by name rather than always allocating a
		// fresh RPMProbe. A hand-authored `load override` config can carry
		// two literal `probe <name> { ... }` top-level sibling blocks under
		// `services rpm` — the hierarchical parser keeps them as separate
		// same-key siblings (it does not merge, same root cause as #4818's
		// security-zone finding), so namedInstances yields TWO entries for
		// the same probe name. The pre-fix unconditional `probe := &RPMProbe{...}`
		// + `rpmCfg.Probes[probe.Name] = probe` let the second instance
		// silently REPLACE the first, discarding ALL of its tests. Reusing
		// the existing probe (and its Tests map) lets both instances'
		// `test` blocks accumulate into one probe, keyed by test name —
		// matching Junos's merge of repeated same-name blocks.
		probe := rpmCfg.Probes[probeInst.name]
		if probe == nil {
			probe = &RPMProbe{
				Name:  probeInst.name,
				Tests: make(map[string]*RPMTest),
			}
			rpmCfg.Probes[probeInst.name] = probe
		}

		for _, testInst := range namedInstances(probeInst.node.FindChildren("test")) {
			test := &RPMTest{Name: testInst.name}

			for _, prop := range testInst.node.Children {
				switch prop.Name() {
				case "probe-type":
					test.ProbeType = nodeVal(prop)
				case "target":
					// Handle "target 1.1.1.1;", the canonical Junos form
					// "target address 1.1.1.1;" (#1827), and
					// "target url http://1.1.1.1;" — in both inline-keys
					// and child-node AST shapes.
					if len(prop.Keys) >= 3 && (prop.Keys[1] == "url" || prop.Keys[1] == "address") {
						test.Target = prop.Keys[2]
					} else if urlChild := prop.FindChild("url"); urlChild != nil {
						test.Target = nodeVal(urlChild)
					} else if addrChild := prop.FindChild("address"); addrChild != nil {
						test.Target = nodeVal(addrChild)
					} else {
						test.Target = nodeVal(prop)
					}
				case "source-address":
					test.SourceAddress = nodeVal(prop)
				case "routing-instance":
					test.RoutingInstance = nodeVal(prop)
				case "destination-interface":
					test.DestinationInterface = nodeVal(prop)
				case "next-hop":
					test.NextHop = nodeVal(prop)
				case "probe-interval":
					if v := nodeVal(prop); v != "" {
						n, err := parseRPMPositiveInt(probe.Name, test.Name, "probe-interval", v)
						if err != nil {
							return err
						}
						test.ProbeInterval = n
					}
				case "probe-count":
					if v := nodeVal(prop); v != "" {
						n, err := parseRPMPositiveInt(probe.Name, test.Name, "probe-count", v)
						if err != nil {
							return err
						}
						test.ProbeCount = n
					}
				case "test-interval":
					if v := nodeVal(prop); v != "" {
						n, err := parseRPMPositiveInt(probe.Name, test.Name, "test-interval", v)
						if err != nil {
							return err
						}
						test.TestInterval = n
					}
				case "thresholds":
					for _, th := range prop.Children {
						if th.Name() == "successive-loss" {
							if v := nodeVal(th); v != "" {
								n, err := parseRPMPositiveInt(probe.Name, test.Name, "thresholds successive-loss", v)
								if err != nil {
									return err
								}
								test.ThresholdSuccessive = n
							}
						}
					}
				case "probe-limit":
					if v := nodeVal(prop); v != "" {
						n, err := parseRPMPositiveInt(probe.Name, test.Name, "probe-limit", v)
						if err != nil {
							return err
						}
						test.ProbeLimit = n
					}
				case "destination-port":
					if v := nodeVal(prop); v != "" {
						n, err := parseRPMPositiveInt(probe.Name, test.Name, "destination-port", v)
						if err != nil {
							return err
						}
						test.DestPort = n
					}
				}
			}

			if test.ProbeLimit == 0 && defaultProbeLimit > 0 {
				test.ProbeLimit = defaultProbeLimit
			}

			if err := validateRPMTest(probe.Name, test); err != nil {
				return err
			}

			probe.Tests[test.Name] = test
		}
	}

	svc.RPM = rpmCfg
	return nil
}

func compileFlowMonitoring(node *Node, svc *ServicesConfig) error {
	fm := &FlowMonitoringConfig{}

	if v9Node := node.FindChild("version9"); v9Node != nil {
		v9cfg := &NetFlowV9Config{
			Templates: make(map[string]*NetFlowV9Template),
		}
		for _, tmplInst := range namedInstances(v9Node.FindChildren("template")) {
			tmpl := &NetFlowV9Template{Name: tmplInst.name}
			for _, prop := range tmplInst.node.Children {
				switch prop.Name() {
				case "flow-active-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowActiveTimeout = n
						}
					}
				case "flow-inactive-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowInactiveTimeout = n
						}
					}
				case "template-refresh-rate":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.TemplateRefreshRate = n
						}
					}
					if secNode := prop.FindChild("seconds"); secNode != nil {
						if v := nodeVal(secNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								tmpl.TemplateRefreshRate = n
							}
						}
					}
				case "ipv4-template", "ipv6-template":
					tmpl.ExportExtensions = append(tmpl.ExportExtensions, parseExportExtensions(prop)...)
				}
			}
			v9cfg.Templates[tmpl.Name] = tmpl
		}
		fm.Version9 = v9cfg
	}

	if ipfixNode := node.FindChild("version-ipfix"); ipfixNode != nil {
		ipfixCfg := &NetFlowIPFIXConfig{
			Templates: make(map[string]*NetFlowIPFIXTemplate),
		}
		for _, tmplInst := range namedInstances(ipfixNode.FindChildren("template")) {
			tmpl := &NetFlowIPFIXTemplate{Name: tmplInst.name}
			for _, prop := range tmplInst.node.Children {
				switch prop.Name() {
				case "flow-active-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowActiveTimeout = n
						}
					}
				case "flow-inactive-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowInactiveTimeout = n
						}
					}
				case "template-refresh-rate":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.TemplateRefreshRate = n
						}
					}
					if secNode := prop.FindChild("seconds"); secNode != nil {
						if v := nodeVal(secNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								tmpl.TemplateRefreshRate = n
							}
						}
					}
				case "ipv4-template", "ipv6-template":
					tmpl.ExportExtensions = append(tmpl.ExportExtensions, parseExportExtensions(prop)...)
				}
			}
			ipfixCfg.Templates[tmpl.Name] = tmpl
		}
		fm.VersionIPFIX = ipfixCfg
	}

	svc.FlowMonitoring = fm
	return nil
}

func compileForwardingOptions(node *Node, fo *ForwardingOptionsConfig) error {
	sampNode := node.FindChild("sampling")
	if sampNode != nil {
		if err := compileSampling(sampNode, fo); err != nil {
			return err
		}
	}

	relayNode := node.FindChild("dhcp-relay")
	if relayNode != nil {
		if err := compileDHCPRelay(relayNode, fo); err != nil {
			return err
		}
	}

	// Parse family { inet6 { mode <flow-based|packet-based> } }
	if famNode := node.FindChild("family"); famNode != nil {
		if inet6Node := famNode.FindChild("inet6"); inet6Node != nil {
			if modeNode := inet6Node.FindChild("mode"); modeNode != nil {
				fo.FamilyInet6Mode = nodeVal(modeNode)
			}
		}
	}

	if pmNode := node.FindChild("port-mirroring"); pmNode != nil {
		if err := compilePortMirroring(pmNode, fo); err != nil {
			return err
		}
	}

	// #2008 H13 Stage 1: presence flag (mirrors security power-mode-disable).
	if node.FindChild("allow-dataplane-sleep") != nil {
		fo.AllowDataplaneSleep = true
	}

	return nil
}

func compilePortMirroring(node *Node, fo *ForwardingOptionsConfig) error {
	pm := &PortMirroringConfig{
		Instances: make(map[string]*PortMirrorInstance),
	}

	// #3972: an invalid port-mirroring entry is a HARD commit reject naming
	// the offending instance, NOT a green commit that later fail-closes the
	// WHOLE mirror table with only a warn in the snapshot builder. This
	// realizes the #1376 design ("Duplicate ingress ifindex config must be
	// rejected at commit time", docs/pr/1373-retire-ebpf-dataplane/
	// plan-1376-port-mirroring.md) which the original implementation deferred
	// to buildMirrorConfigSnapshots — where one bad entry dropped every valid
	// mirror session silently. Reject up front so an operator with 3 good
	// sessions + 1 typo'd 4th sees the specific error and fixes it instead of
	// losing all mirroring.
	//
	// The mirror table contract is one output per ingress interface, so an
	// ingress source may be used only ONCE across all instances. Ingress
	// names are normalized with LinuxIfName so the vSRX ("ge-0/0/0.0") and
	// Linux ("ge-0-0-0.0") spellings of one interface are recognized as the
	// same source (matching the snapshot builder's ifindex dedup).
	ingressOwner := make(map[string]string)

	for _, inst := range namedInstances(node.FindChildren("instance")) {
		mi := &PortMirrorInstance{Name: inst.name}

		if inputNode := inst.node.FindChild("input"); inputNode != nil {
			if rateNode := inputNode.FindChild("rate"); rateNode != nil {
				if v := nodeVal(rateNode); v != "" {
					n, err := strconv.Atoi(v)
					if err != nil {
						return fmt.Errorf("port-mirroring instance %q: invalid input rate %q: must be a non-negative integer (0 mirrors every packet)", inst.name, v)
					}
					if n < 0 {
						// uint32(InputRate) in the snapshot builder would wrap a
						// negative rate into a huge 1-in-N sampling divisor.
						return fmt.Errorf("port-mirroring instance %q: input rate must not be negative, got %d", inst.name, n)
					}
					mi.InputRate = n
				}
			}
			if ingressNode := inputNode.FindChild("ingress"); ingressNode != nil {
				for _, child := range ingressNode.Children {
					if child.Name() == "interface" {
						if v := nodeVal(child); v != "" {
							key := LinuxIfName(v)
							if owner, dup := ingressOwner[key]; dup {
								if owner == inst.name {
									return fmt.Errorf("port-mirroring instance %q: duplicate ingress interface %q", inst.name, v)
								}
								return fmt.Errorf("port-mirroring: ingress interface %q is mirrored by both instance %q and %q (one output per ingress interface)", v, owner, inst.name)
							}
							ingressOwner[key] = inst.name
							mi.Input = append(mi.Input, v)
						}
					}
				}
			}
		}

		if outputNode := inst.node.FindChild("output"); outputNode != nil {
			if ifNode := outputNode.FindChild("interface"); ifNode != nil {
				mi.Output = nodeVal(ifNode)
			}
		}

		pm.Instances[mi.Name] = mi
	}

	fo.PortMirroring = pm
	return nil
}

func compileSampling(node *Node, fo *ForwardingOptionsConfig) error {
	sc := &SamplingConfig{
		Instances: make(map[string]*SamplingInstance),
	}

	for _, sampInst := range namedInstances(node.FindChildren("instance")) {
		inst := &SamplingInstance{Name: sampInst.name}

		inputNode := sampInst.node.FindChild("input")
		if inputNode != nil {
			for _, prop := range inputNode.Children {
				if prop.Name() == "rate" {
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							inst.InputRate = n
						}
					}
				}
			}
		}

		for _, familyNode := range sampInst.node.FindChildren("family") {
			var afNodes []*Node
			if len(familyNode.Keys) >= 2 {
				afNodes = append(afNodes, familyNode)
			} else {
				afNodes = append(afNodes, familyNode.Children...)
			}
			for _, afNode := range afNodes {
				afName := afNode.Keys[0]
				if len(afNode.Keys) >= 2 {
					afName = afNode.Keys[1]
				}

				sf := compileSamplingFamily(afNode)
				switch afName {
				case "inet":
					inst.FamilyInet = sf
				case "inet6":
					inst.FamilyInet6 = sf
				}
			}
		}

		sc.Instances[inst.Name] = inst
	}

	fo.Sampling = sc
	return nil
}

func compileSamplingFamily(node *Node) *SamplingFamily {
	sf := &SamplingFamily{}

	outputNode := node.FindChild("output")
	if outputNode == nil {
		return sf
	}

	// Junos accepts `source-address` at TWO hierarchies under `output`:
	// directly under `output` (the per-output default that every
	// flow-server inherits) and nested inside an individual flow-server
	// (the per-collector override). The output-level default is tracked
	// here and stored as the family-wide SamplingFamily.SourceAddress
	// (#2605); each flow-server-nested value is tracked PER COLLECTOR on
	// FlowServer.SourceAddress (#3745) so multiple collectors of the same
	// family each keep their own source. The effective per-collector bind
	// (nested override else family default) is resolved in the flowexport
	// manager, not collapsed to one family-wide value here. Before #3745
	// the nested value overwrote a single family-wide string
	// (last-writer-wins across servers), so two collectors with distinct
	// nested sources both bound the last one in AST order.
	var outputLevelSrc string

	for _, child := range outputNode.Children {
		switch child.Name() {
		case "source-address":
			// Output-level default: the source-address sibling of
			// flow-server under `output { ... }`. Standard Junos
			// hierarchy — previously dropped silently (#2605).
			outputLevelSrc = nodeVal(child)
		case "flow-server":
			fsAddr := nodeVal(child)
			if fsAddr != "" {
				fs := &FlowServer{Address: fsAddr}
				fsChildren := child.Children
				if len(child.Keys) < 2 && len(child.Children) > 0 {
					fsChildren = child.Children[0].Children
				}
				for _, prop := range fsChildren {
					switch prop.Name() {
					case "port":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								fs.Port = n
							}
						}
					case "version9-template":
						fs.Version9Template = nodeVal(prop)
						fs.Version = FlowServerVersion9
					case "version9":
						// Hierarchical: version9 { template { <name>; } }
						fs.Version = FlowServerVersion9
						if tmplNode := prop.FindChild("template"); tmplNode != nil {
							// Template name is either nodeVal or first child's name
							if v := nodeVal(tmplNode); v != "" {
								fs.Version9Template = v
							} else if len(tmplNode.Children) > 0 {
								fs.Version9Template = tmplNode.Children[0].Name()
							}
						}
					case "version-ipfix-template":
						fs.VersionIPFIXTemplate = nodeVal(prop)
						fs.Version = FlowServerVersionIPFIX
					case "version-ipfix":
						// Hierarchical: version-ipfix { template { <name>; } }
						// Junos binds each flow-server to exactly one export
						// version; the per-server version-ipfix selector routes
						// THIS collector to the IPFIX exporter only (#2136).
						fs.Version = FlowServerVersionIPFIX
						if tmplNode := prop.FindChild("template"); tmplNode != nil {
							if v := nodeVal(tmplNode); v != "" {
								fs.VersionIPFIXTemplate = v
							} else if len(tmplNode.Children) > 0 {
								fs.VersionIPFIXTemplate = tmplNode.Children[0].Name()
							}
						}
					case "source-address":
						// Per-collector override (flow-server-nested).
						// Stored PER COLLECTOR (#3745) so multiple
						// flow-servers of the same family each keep their
						// own source; the manager resolves the effective
						// bind (this override else the family default).
						fs.SourceAddress = nodeVal(prop)
					}
				}
				sf.FlowServers = append(sf.FlowServers, fs)
			}
		case "inline-jflow":
			sf.InlineJflow = true
			if saNode := child.FindChild("source-address"); saNode != nil {
				sf.InlineJflowSourceAddress = nodeVal(saNode)
			}
			// Also handle inline keys: "inline-jflow source-address X"
			for i := 1; i < len(child.Keys)-1; i++ {
				if child.Keys[i] == "source-address" {
					sf.InlineJflowSourceAddress = child.Keys[i+1]
				}
			}
		}
	}

	// The output-level source-address is the family-wide default bind
	// (the per-output default every flow-server inherits). Per-collector
	// nested overrides live on FlowServer.SourceAddress; the flowexport
	// manager computes the effective bind per collector (nested override
	// else this default). #2605 (output-level) + #3745 (per-collector).
	if outputLevelSrc != "" {
		sf.SourceAddress = outputLevelSrc
	}

	// The output-level source-address is also the default bind for
	// inline-jflow exports when the inline-jflow block did not set its
	// own (manager.go falls back to InlineJflowSourceAddress when
	// SourceAddress is empty, but inline-jflow uses a distinct field).
	if sf.InlineJflow && sf.InlineJflowSourceAddress == "" && outputLevelSrc != "" {
		sf.InlineJflowSourceAddress = outputLevelSrc
	}

	return sf
}

func compileDHCPRelay(node *Node, fo *ForwardingOptionsConfig) error {
	relay := &DHCPRelayConfig{
		ServerGroups: make(map[string]*DHCPRelayServerGroup),
		Groups:       make(map[string]*DHCPRelayGroup),
	}

	for _, sgInst := range namedInstances(node.FindChildren("server-group")) {
		sg := relay.ServerGroups[sgInst.name]
		if sg == nil {
			sg = &DHCPRelayServerGroup{Name: sgInst.name}
			relay.ServerGroups[sg.Name] = sg
		}
		// Inline keys (#1797 dual-AST): "server-group sg1 10.1.1.1;" packs
		// the server addresses into Keys[2:].
		for i := 2; i < len(sgInst.node.Keys); i++ {
			sg.Servers = append(sg.Servers, sgInst.node.Keys[i])
		}
		// Block form: every child is a server address; a child line may
		// itself carry several addresses in its Keys (#1813).
		for _, child := range sgInst.node.Children {
			sg.Servers = append(sg.Servers, child.Keys...)
		}
	}

	for _, gInst := range namedInstances(node.FindChildren("group")) {
		g := relay.Groups[gInst.name]
		if g == nil {
			g = &DHCPRelayGroup{Name: gInst.name}
			relay.Groups[g.Name] = g
		}
		// Inline keys (#1797 dual-AST): "group lan interface ge-0/0/0.0;"
		// packs the properties into Keys[2:].
		keys := gInst.node.Keys
		for i := 2; i < len(keys); i++ {
			switch keys[i] {
			case "interface":
				// Multi-value (#1813): consume every following token up
				// to the next recognized property keyword —
				// `group lan interface [ a b ];` packs all interfaces
				// inline. `overrides` MUST be a boundary keyword
				// (#2076) so a flat-set
				// `group g interface ge-0/0/0.0 overrides always-broadcast`
				// does not swallow `overrides`/`always-broadcast` into
				// the interface list.
				for i+1 < len(keys) && keys[i+1] != "interface" &&
					keys[i+1] != "active-server-group" &&
					keys[i+1] != "overrides" {
					i++
					g.Interfaces = append(g.Interfaces, keys[i])
				}
			case "active-server-group":
				if i+1 < len(keys) {
					i++
					g.ActiveServerGroup = keys[i]
				}
			case "overrides":
				// Inline flat-set spelling (#2076):
				// `group g overrides always-broadcast`. Consume the
				// override sub-keywords until the next group property.
				// #4309: forward-only / relay-agent-option are flags;
				// maximum-hop-count consumes a following value token.
				for i+1 < len(keys) && keys[i+1] != "interface" &&
					keys[i+1] != "active-server-group" &&
					keys[i+1] != "overrides" {
					i++
					switch keys[i] {
					case "always-broadcast":
						g.AlwaysBroadcast = true
					case "forward-only":
						g.ForwardOnly = true
					case "relay-agent-option":
						g.RelayAgentOption = true
					case "trust-option-82":
						g.TrustOption82 = true
					case "maximum-hop-count":
						if i+1 < len(keys) {
							i++
							if n, err := strconv.Atoi(keys[i]); err == nil {
								g.MaximumHopCount = n
							}
						}
					case "maximum-packet-rate":
						if i+1 < len(keys) {
							i++
							if n, err := strconv.Atoi(keys[i]); err == nil {
								g.MaximumPacketRate = n
							}
						}
					}
				}
			}
		}
		for _, prop := range gInst.node.Children {
			switch prop.Name() {
			case "interface":
				// Multi-value spellings (#1813): bracketed
				// `interface [ a b ];` packs all interfaces into
				// Keys[1:] (flat-set replay may carry trailing values
				// as children); braced block `interface { a; b; }`
				// holds one child per interface. nodeVal kept only the
				// first of each.
				for _, k := range prop.Keys[1:] {
					g.Interfaces = append(g.Interfaces, k)
				}
				for _, child := range prop.Children {
					if v := child.Name(); v != "" {
						g.Interfaces = append(g.Interfaces, v)
					}
				}
			case "active-server-group":
				g.ActiveServerGroup = nodeVal(prop)
			case "overrides":
				// Block form (#2076): `overrides { always-broadcast; }`.
				// #4309 adds forward-only / relay-agent-option (flags) and
				// maximum-hop-count (value). Each may appear as a child node
				// OR ride in Keys[1:] when the override block collapses to
				// inline values.
				for _, oc := range prop.Children {
					switch oc.Name() {
					case "always-broadcast":
						g.AlwaysBroadcast = true
					case "forward-only":
						g.ForwardOnly = true
					case "relay-agent-option":
						g.RelayAgentOption = true
					case "trust-option-82":
						g.TrustOption82 = true
					case "maximum-hop-count":
						if v := nodeVal(oc); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								g.MaximumHopCount = n
							}
						}
					case "maximum-packet-rate":
						if v := nodeVal(oc); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								g.MaximumPacketRate = n
							}
						}
					}
				}
				for i := 1; i < len(prop.Keys); i++ {
					switch prop.Keys[i] {
					case "always-broadcast":
						g.AlwaysBroadcast = true
					case "forward-only":
						g.ForwardOnly = true
					case "relay-agent-option":
						g.RelayAgentOption = true
					case "trust-option-82":
						g.TrustOption82 = true
					case "maximum-hop-count":
						if i+1 < len(prop.Keys) {
							i++
							if n, err := strconv.Atoi(prop.Keys[i]); err == nil {
								g.MaximumHopCount = n
							}
						}
					case "maximum-packet-rate":
						if i+1 < len(prop.Keys) {
							i++
							if n, err := strconv.Atoi(prop.Keys[i]); err == nil {
								g.MaximumPacketRate = n
							}
						}
					}
				}
			}
		}
	}

	fo.DHCPRelay = relay
	return nil
}

// eventAttributesMatchExprs extracts every `attributes-match` expression an
// event-policy match node carries, across BOTH parser AST shapes (#6659 — the
// event-options instance of the #2419 dual-shape class).
//
// NOTE for anyone auditing this class: the one-sidedness runs in BOTH
// directions. This arm read Children and never Keys[1:], so its PACKED-LEAF
// spelling compiled to nothing while the block spelling worked. Other arms have
// the MIRROR bug — the CoS code-points collector reads Keys[1:] plus the inline
// tail and never Children, so its hierarchical BLOCK spelling is the broken one.
// Searching for "looks like a nodeVal call" finds only the first direction.
// Check every leaf by compiling BOTH spellings and comparing.
//
// The UNIT here is a whole EXPRESSION (`<event>.<attribute> matches <value>`),
// not a token, so firewallMatchValues is the WRONG reader: it would split one
// constraint into three bogus ones. The two shapes:
//
//   - block / flat-set  `attributes-match { e.owner matches Comcast; }`
//     (and `set ... attributes-match e.owner matches Comcast`)
//     → one CHILD per expression, its Keys carrying the tokens. Joining each
//     child's Keys yields the expression. This shape already worked.
//   - packed leaf       `attributes-match e.owner matches Comcast;`
//     → NO children; the whole expression rides on the node's own Keys after
//     the keyword. Reading only Children compiled ZERO constraints.
//   - bracket list      `attributes-match [ "e.a matches X" "e.b matches Y" ];`
//     → NO children either; the lexer strips the brackets and each QUOTED
//     member is ONE token, so the members collapse onto Keys[1:] side by side.
//     Joining that tail would fuse two constraints into one impossible regex.
//
// Hence the two rules below, which are about the two ways a tail can be
// spelled, not about two different leaves:
//
//   - CHILDREN WIN. When the node has children they are the whole expression
//     list and the node's OWN tail is ignored — verbatim master behaviour,
//     because master read Children and nothing else. `attributes-match bogus {
//     "e.owner matches X"; }` parses as Keys=["attributes-match","bogus"] with
//     one child; master ignored `bogus` and committed, so promoting it into a
//     constraint here would REJECT (as a malformed match expression) a
//     configuration that committed before #6659. Widening a read must not
//     invent a rejection out of a token the previous reader discarded.
//   - Every token GROUP — the node's own tail, and each child's Keys — is
//     split by eventMultiWordLeafValues, because a bracketed list can land in
//     EITHER place depending on which parser ran. A bracketed list mixing a
//     well-formed member with a bare garbage token therefore yields the
//     garbage token as its own (malformed) expression and strict commit
//     rejects it — that is the #6659 fail-closed conversion, not a new
//     invented rejection, because master compiled NOTHING from any packed
//     tail and so let the whole list fail open.
//
// Dropping the constraints is a FAIL-OPEN: an event policy with no
// attributes-match fires on every occurrence of the event rather than the
// narrower set the operator wrote. It also bypassed
// ValidateEventAttributesMatchStrict — a packed-leaf expression naming an unknown
// field committed clean because the compiler never produced it.
// #6673: an authored-but-EMPTY expression is kept, not skipped. Before #6659
// the block spelling appended strings.Join(amChild.Keys, " ") unconditionally,
// so `attributes-match { ""; e1.owner matches X; }` produced an "" entry and
// ValidateEventAttributesMatchStrict HARD-REJECTED it at strict commit as a malformed
// match expression. Filtering it out silently accepted that config instead —
// converting a fail-CLOSED commit gate into a fail-OPEN one, which is the exact
// defect class this arm was widened to fix. The packed spelling now behaves the
// same way (the parity this helper exists for), so `attributes-match "";` is
// rejected too; the tolerant load / peer-sync path downgrades both to a warning
// and still boots. A bare `attributes-match;` carrying no value slot at all
// remains "no constraint authored" and is untouched.
//
// Stored VERBATIM — deliberately no strings.TrimSpace. The lexer preserves
// whitespace INSIDE a quoted token, so master's BLOCK spelling compiled the
// padded form and so does this. #6673: trimming would NOT rewrite the persisted
// config — configstore writes the AST candidate tree (store_commit.go
// writeActive -> db.go writeTreeMarked) and this reader returns new strings. It
// changes the COMPILED policy and its consumers: policySemanticRevision (which
// re-arms the engine), `show event-options`, and the quoted diagnostic.
func eventAttributesMatchExprs(child *Node) []string {
	// Block / flat-set: one expression per child, and the node's own tail is
	// the identifier slot master discarded. Do not promote it (#6673 fold).
	if len(child.Children) > 0 {
		exprs := make([]string, 0, len(child.Children))
		for _, amChild := range child.Children {
			exprs = append(exprs, eventMultiWordLeafValues(amChild, 0)...)
		}
		return exprs
	}
	if len(child.Keys) < 2 {
		// No value slot at all (`attributes-match;`): no constraint authored.
		return nil
	}
	// Packed leaf or bracket list. A one-token tail is the same either way, so
	// an authored-but-EMPTY expression still reaches the strict gate.
	return eventMultiWordLeafValues(child, 1)
}

// eventMultiWordLeafValues splits ONE token group — a node's own Keys tail
// (from > 0) or a single child's whole Keys (from == 0) — into the values it
// carries (#6673 fold).
//
// Both event-options leaves in this file (`attributes-match` and `then
// change-configuration commands`) hold values that are themselves MULTI-WORD
// strings, so "how many values are in this group" cannot be answered by
// counting tokens: `[ "set a b" "delete c" ]` is two values in two tokens,
// while `set system host-name foo` is ONE value in four. What separates them is
// which tokens the operator QUOTED, and that is a property of the source
// TOKEN KIND, not of the token's text — so this reader takes the *Node and
// consults its recorded provenance (Node.KeysQuoted, populated by parseKeys for
// the hierarchical spelling and by SetPathQuoted for the flat-set one) rather
// than re-deriving it from the strings.
//
// It is applied to the CHILDREN as well as the tail, and that is the whole
// point of hoisting it out of the tail branch. Which of the two places a
// bracketed list lands in depends on WHICH PARSER RAN, not on what the operator
// wrote. The hierarchical parser collapses `commands [ "a" "b" ];` onto the
// node's own Keys; ParseSetCommand + SetPath puts the identical list on ONE
// CHILD's Keys, because neither leaf declares `multi: true` in setSchema (the
// flag that would make SetPath absorb a bracket onto the node's own tail).
// Splitting only the tail therefore fixed the hierarchical spelling and left
// the flat-set spelling fusing every member into one string — see
// TestEventChangeConfigCommands6659/flat-set_bracket_list.
//
// The decision is taken on the FIRST token of the group, because the two
// ambiguous mixtures pull in OPPOSITE directions and only the first token
// separates them:
//
//   - `commands set system host-name "foo bar"` — a quoted VALUE inside an
//     otherwise bare statement, tokens [set system host-name "foo bar"]. That
//     is ONE command; an "any token is quoted" rule would shatter it into four.
//     The first token is bare, so: join.
//   - `commands [ "set a b" bogus ]` — a quoted member beside a bare one. That
//     is a LIST whose second member is garbage; joining would fuse the garbage
//     onto a valid command and hand eventengine.classifyPlan a plausible-
//     looking set path to apply. The first token is quoted, so: split, and the
//     bare member reaches classifyPlan alone, fails its set/delete prefix check
//     and rejects the WHOLE batch. Fail-closed, which is the direction a
//     genuinely ambiguous authoring must take.
//
// A single-token group is identical under both rules, so the choice only ever
// decides a group of two or more.
//
// WHY PROVENANCE AND NOT TEXT. The rule this replaced asked whether the first
// token CONTAINED A SPACE or was EMPTY, on the reasoning that the lexer never
// leaves a space inside a bare word. That is sound as far as it goes, but it is
// an implication in one direction only: every space-bearing token was quoted,
// while a quoted token need not bear a space. A quoted ONE-WORD first member —
// `commands [ "set" "system host-name pwned" ]` — has neither a space nor
// emptiness, so it read as bare and the list JOINED into
// `set system host-name pwned`: a syntactically perfect command that passes
// classifyPlan's `set ` prefix check, parses, and is APPLIED. The authoring the
// operator wrote (a bare `set` member) is exactly the one the fail-closed path
// above exists to reject. No refinement of the text test can fix this, because
// the two authorings produce byte-identical tokens; only the token kind
// distinguishes them.
//
// WHEN PROVENANCE IS ABSENT the old text rule is used unchanged, which is a
// deliberate non-regression rather than a second guess. A node carries no
// KeysQuoted when it was synthesized by the compiler, or when it was
// deserialized from a config DB written before this change. Treating "no
// provenance" as "all bare" would be a false claim in the fail-OPEN direction;
// treating it as "all quoted" would SPLIT `commands set system host-name
// "foo bar"` and silently break a working remediation across an upgrade. The
// text rule is what those trees were already evaluated under, so it is the only
// answer that changes nothing for them. Note this is not a widening: for a
// group that genuinely has no quoted token the two rules AGREE by construction,
// since a bare word can be neither empty nor space-bearing — which is also why
// setKeysQuoted may collapse an all-false mask to nil without losing anything.
//
// Residual, unchanged and deliberately not chased: a bracket list whose members
// are ALL single bare-looking words (`[ seta setb ]`) is indistinguishable from
// one unquoted value and joins. Provenance does not help here — both authorings
// have zero quoted tokens and the AST does not record the brackets themselves.
// Every well-formed value of both leaves contains a space (a command carries its
// `set `/`delete ` prefix, an expression carries " matches "), so a group that
// reaches this case is malformed either way, and joining sends it to the same
// gate (classifyPlan's prefix check / ValidateEventAttributesMatchStrict) that
// the split would.
//
// Residual, KNOWN AND NARROWER THAN THE ABOVE: a tree that reaches this reader
// with no provenance is still decided by the text rule, so the fused-member
// read survives for (a) an event policy authored BEFORE this change and still
// sitting in the persisted config DB — until the operator re-authors the
// `commands` line, at which point SetPathQuoted stamps provenance — and (b) any
// future caller that builds these nodes by hand. The serialize/re-parse paths
// (HA config sync, `show | display set` replay, load merge, archive) are NOT in
// this set: keyNeedsAuthoredQuote re-emits the authored quotes that decide the
// grouping, so a round-tripped tree re-parses with the same provenance it had.
func eventMultiWordLeafValues(n *Node, from int) []string {
	if n == nil || from < 0 || from >= len(n.Keys) {
		return nil
	}
	tokens := n.Keys[from:]
	if n.KeysHaveQuoteProvenance() {
		if n.KeyQuoted(from) {
			return append([]string(nil), tokens...)
		}
		return []string{strings.Join(tokens, " ")}
	}
	// No provenance recorded for this node — fall back to the text rule these
	// trees were already evaluated under. See "WHEN PROVENANCE IS ABSENT".
	if tokens[0] == "" || strings.Contains(tokens[0], " ") {
		return append([]string(nil), tokens...)
	}
	return []string{strings.Join(tokens, " ")}
}

// eventChangeConfigCommands extracts every `then change-configuration commands`
// entry, across BOTH parser AST shapes (#6659).
//
// It stays a separate reader from eventAttributesMatchExprs above because the
// two arms differ in what they do with an authored EMPTY value and in which
// gate catches a malformed one — but the TOKEN BOUNDARY is now one shared rule
// (eventMultiWordLeafValues), applied identically to the tail and to each
// child. Verified against the actual parsed ASTs:
//
//   - CHILD form   `commands { "set system host-name foo"; "delete ..."; }`
//     → one child per command. A QUOTED command lexes to a single Key; an
//     UNQUOTED one (`set system host-name foo;`) lexes to Keys=["set","system",
//     "host-name","foo"], so the child's Keys must be JOINED. The pre-#6659
//     reader took child.Name() (Keys[0]) and truncated an unquoted command to
//     its first word — `set` — which is not a command at all.
//   - PACKED form  `commands "set system host-name foo";` → Keys=["commands",
//     "<cmd>"], and `commands [ "cmd1" "cmd2" ]` → Keys=["commands","cmd1",
//     "cmd2"]. Reading only Children compiled zero remediation commands.
//   - FLAT-SET bracket. `set … commands [ "cmd1" "cmd2" ]` is the SAME list as
//     the packed form, but SetPath puts it on ONE CHILD's Keys instead of the
//     node's own. #6673 fold: that is why the boundary rule cannot live in the
//     tail branch — splitting the tail and joining the children fixed one
//     operator's spelling and left the other's fusing into a single string.
//
// #6673 fold: CHILDREN WIN, exactly as in eventAttributesMatchExprs and for
// exactly the same reason. `commands bogus { "set system host-name foo"; }`
// parses as Keys=["commands","bogus"] with one child. Master read Children and
// nothing else, so it ignored `bogus` and the remediation RAN. Emitting both
// hands eventengine.classifyPlan a token that matches neither the `set ` nor
// the `delete ` prefix, and classifyPlan rejects the WHOLE batch (`return nil,
// false`) — HandleEvent then discards it. Both trees accept the configuration;
// only the widened read makes the remediation inert. A tail is read ONLY when
// the node has no children, which is the shape where master compiled nothing at
// all (the #6659 fail-open this helper exists to close).
// #6673: an authored-but-EMPTY command is kept, not skipped — but for a
// DIFFERENT reason than eventAttributesMatchExprs above, and the obvious guess
// is wrong. Before #6659 the block spelling appended cmdChild.Name()
// unconditionally, so `commands { ""; "set system host-name foo"; }` compiled
// to ["", "set …"]. Keeping the entry is OUTPUT PARITY with that, NOT a
// fail-closed gate: unlike attributes-match, nothing downstream rejects an empty
// command. eventengine.classifyPlan opens with `cmd = strings.TrimSpace(cmd);
// if cmd == "" { continue }` — present since the engine's first commit — so it
// is SKIPPED and the batch yields the same typed plan either way (driven
// directly: ["", "set …"] gives ok=true, one op). It is still not unobservable,
// which is why this reader must not decide it away: policySemanticRevision
// hashes EVERY ThenCommands entry (authoring or removing the empty re-arms the
// policy, exactly as on master) and `show event-options` prints the list
// verbatim (pkg/cli/cli_show_routing.go, pkg/grpcapi/server_show_events.go).
// Filtering would diverge the compiled policy from master's on both surfaces
// while changing nothing about what the batch executes; whether an empty command
// is meaningless is the consumer's call, and the consumer already makes it.
// Commands are likewise stored VERBATIM — no TrimSpace, same reasoning,
// classifyPlan trims them itself. A `commands;` with no value slot still
// contributes nothing.
func eventChangeConfigCommands(cmdsNode *Node) []string {
	// Block: each child carries one command — or, on the flat-set path, a
	// whole bracketed LIST of them. eventMultiWordLeafValues decides which,
	// so an unquoted command survives whole instead of truncating to its first
	// word AND a bracket list stops fusing into one string. The node's own tail
	// is the identifier slot master discarded — do not promote it.
	if len(cmdsNode.Children) > 0 {
		cmds := make([]string, 0, len(cmdsNode.Children))
		for _, cmdChild := range cmdsNode.Children {
			cmds = append(cmds, eventMultiWordLeafValues(cmdChild, 0)...)
		}
		return cmds
	}
	// Packed: the tail is a bracketed list of quoted commands, or the bare
	// words of exactly one unquoted command. Same discriminator.
	if len(cmdsNode.Keys) < 2 {
		return nil
	}
	return eventMultiWordLeafValues(cmdsNode, 1)
}

func compileEventOptions(node *Node, policies *[]*EventPolicy) error {
	// #4423 L1: two same-named policy stanzas must MERGE into one policy, not
	// coexist as duplicates. Flat-set / display-set config already merges (the
	// AST collapses same-keyed siblings), but a hierarchical config with two
	// `policy foo { ... }` blocks yields two separate nodes here. Left
	// unmerged they produce two EventPolicy structs with the same Name; the
	// engine keys its runtime/cooldown/semRev maps by Name, so the second
	// clobbers the first's revision and the first policy's remediation is then
	// silently dropped as "policy redefined" at commit. Accumulate by name so
	// both AST shapes behave identically and match Junos merge semantics.
	byName := make(map[string]*EventPolicy)
	for _, pInst := range namedInstances(node.FindChildren("policy")) {
		ep := byName[pInst.name]
		if ep == nil {
			ep = &EventPolicy{
				Name: pInst.name,
			}
			byName[pInst.name] = ep
			*policies = append(*policies, ep)
		}

		for _, child := range pInst.node.Children {
			switch child.Name() {
			case "events":
				// `events` is the trigger set of the policy, so a lost value is
				// the fail-SILENT direction: the automation the operator
				// configured never runs for part of what they asked for.
				//
				// The old read covered both sides of the AST — Keys[1:] for the
				// hierarchical bracket and packed spellings, one value per child
				// for the block and flat-set-repeated ones — exactly as
				// CLAUDE.md prescribes, and STILL dropped (#7126). `events` is
				// not marked `multi: true` in setSchema, so SetPath files
				// `set … events [ ev_one ev_two ]` as ONE child whose Keys hold
				// BOTH names; evtChild.Name() is Keys[0] and returned only
				// ev_one. Reading Children is not reading every KEY of each
				// child. plainListValues reads both sides AND every key.
				ep.Events = append(ep.Events, plainListValues(child)...)
			case "within":
				w := &EventWithin{}
				if v := nodeVal(child); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						w.Seconds = n
					}
				}
				if trigNode := child.FindChild("trigger"); trigNode != nil {
					// trigger on N or trigger until N
					for i := 1; i < len(trigNode.Keys)-1; i++ {
						switch trigNode.Keys[i] {
						case "on":
							if n, err := strconv.Atoi(trigNode.Keys[i+1]); err == nil {
								w.TriggerOn = n
							}
						case "until":
							if n, err := strconv.Atoi(trigNode.Keys[i+1]); err == nil {
								w.TriggerUntil = n
							}
						}
					}
					// Also check children
					if onNode := trigNode.FindChild("on"); onNode != nil {
						if v := nodeVal(onNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								w.TriggerOn = n
							}
						}
					}
					if untilNode := trigNode.FindChild("until"); untilNode != nil {
						if v := nodeVal(untilNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								w.TriggerUntil = n
							}
						}
					}
				}
				ep.WithinClauses = append(ep.WithinClauses, w)
			case "attributes-match":
				ep.AttributesMatch = append(ep.AttributesMatch, eventAttributesMatchExprs(child)...)
			case "then":
				// #6714: FindChildren, not FindChild, on BOTH levels. The
				// hierarchical parser keeps repeated same-keyed statements as
				// SIBLINGS (parseStatements), so
				// `change-configuration { commands "a"; commands "b"; }`
				// arrives as two `commands` nodes and two
				// `change-configuration { ... }` blocks arrive as two nodes.
				// The first-only read compiled command "a" and silently
				// discarded every later one — a remediation action the operator
				// authored that never runs, with nothing on any surface saying
				// so (`show event-options` renders the config back intact).
				//
				// This is spelling-dependent, which is why it survived the
				// #2419 differential gate: the FLAT-SET spelling
				// (`set … commands "a"` / `set … commands "b"`) already kept
				// both, because SetPath merges the repeated leaf into ONE node
				// instead of appending a sibling. Only the brace-authored file
				// dropped — and the gate does not compare the repeated
				// spellings here at all, because setSchema marks `commands`
				// scalar (see docs/config-schema.md).
				for _, ccNode := range child.FindChildren("change-configuration") {
					for _, cmdsNode := range ccNode.FindChildren("commands") {
						ep.ThenCommands = append(ep.ThenCommands, eventChangeConfigCommands(cmdsNode)...)
					}
				}
			}
		}
	}
	return nil
}

// compileBridgeDomains parses the bridge-domains AST section into typed
// BridgeDomainConfig structs.
//
// #6687: `vlan-id-list` is the leaf's ONLY validator (setSchema declares none
// for it), and it is read for EVERY authored value rather than slot 0 alone.
// Strict (commit / commit-check) hard-rejects a non-numeric or out-of-range id
// in any slot; lenient (tolerant load / peer-sync) warns and skips that one
// value so a config already persisted under the narrower gate still boots.
// See the value-reading comment below for why both halves had to change
// together.
func compileBridgeDomains(node *Node, bds *[]*BridgeDomainConfig, lenient bool, warnings *[]string) error {
	for _, child := range node.Children {
		if child.IsLeaf {
			continue
		}
		bdName := child.Name()
		bd := &BridgeDomainConfig{
			Name: bdName,
		}

		// Collect VLAN IDs — `vlan-id-list` is a `multi: true` value leaf, so
		// one node can carry several ids and a bridge domain can carry several
		// nodes. The range/parse checks here are the leaf's ONLY validator (it
		// declares none in setSchema), so reading slot 0 alone was both a value
		// DROP and a GATE ESCAPE (#6687 / #6659): `[ 10 99999 ]`,
		// `{ 10; 99999; }` and `set ... vlan-id-list [ 10 99999 ]` all committed
		// CLEAN and compiled VlanIDs=[10], while the identical bad value in slot
		// 0 was correctly REJECTED "out of range (1-4094)". Measured across all
		// five spellings; the bracketed list is the idiomatic Junos one, so the
		// unvalidated path was the COMMON path.
		//
		// multiLeafAuthoredValues is the documented reader for a `multi: true`
		// leaf: it accumulates the node's own Keys[1:] (hierarchical bracket,
		// and — because the multi flag makes SetPath absorb the tail — the
		// flat-set bracket too) AND one value per child (hierarchical block,
		// flat-set repeated). It keeps empty tokens, which a value list must
		// skip: `vlan-id-list;` carries no id at all and is not a parse error.
		//
		// Widening the READ without widening the TOLERANCE would turn a config
		// that committed clean under the old gate into a boot failure after
		// upgrade, so the severity is now split the same way every other
		// AST-level gate in this compiler splits it (see compiler_opts.go):
		// strict rejects, lenient warns and skips the offending value.
		for _, vlanNode := range child.FindChildren("vlan-id-list") {
			for _, valStr := range multiLeafAuthoredValues(vlanNode) {
				if valStr == "" {
					continue
				}
				v, err := strconv.Atoi(valStr)
				if err != nil {
					if lenient {
						*warnings = append(*warnings, fmt.Sprintf(
							"bridge-domain %s: invalid vlan-id-list value %q: %v (ignored: value dropped)",
							bdName, valStr, err))
						continue
					}
					return fmt.Errorf("bridge-domain %s: invalid vlan-id-list value %q: %w", bdName, valStr, err)
				}
				if v < 1 || v > 4094 {
					if lenient {
						*warnings = append(*warnings, fmt.Sprintf(
							"bridge-domain %s: vlan-id %d out of range (1-4094) (ignored: value dropped)",
							bdName, v))
						continue
					}
					return fmt.Errorf("bridge-domain %s: vlan-id %d out of range (1-4094)", bdName, v)
				}
				bd.VlanIDs = append(bd.VlanIDs, v)
			}
		}

		// Routing interface (e.g. "irb.0")
		if riNode := child.FindChild("routing-interface"); riNode != nil {
			bd.RoutingInterface = nodeVal(riNode)
		}

		// Domain type
		if dtNode := child.FindChild("domain-type"); dtNode != nil {
			bd.DomainType = nodeVal(dtNode)
		}

		*bds = append(*bds, bd)
	}
	return nil
}
