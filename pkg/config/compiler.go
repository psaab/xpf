package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// CompileConfig converts a parsed ConfigTree AST into a typed Config struct.
// It clones the tree before expansion so the original tree is not mutated.
func CompileConfig(tree *ConfigTree) (*Config, error) {
	// Clone the tree before expanding groups — the caller's tree must retain
	// groups and apply-groups nodes for display (show configuration groups).
	tree = tree.Clone()
	usedNodeFallback := false

	// Expand groups before compilation — resolve all apply-groups references.
	if err := tree.ExpandGroups(); err != nil {
		if strings.Contains(err.Error(), `undefined group "${node}"`) {
			vars := map[string]string{"node": "node0"}
			if err2 := tree.ExpandGroupsWithVars(vars); err2 != nil {
				return nil, fmt.Errorf("apply-groups: %w", err2)
			}
			usedNodeFallback = true
		} else {
			return nil, fmt.Errorf("apply-groups: %w", err)
		}
	}

	cfg, err := compileExpanded(tree)
	if err != nil {
		return nil, err
	}
	if usedNodeFallback {
		cfg.Warnings = append(cfg.Warnings, `apply-groups "${node}" resolved using default node0 context during generic compile`)
	}
	return cfg, nil
}

// CompileConfigForNode is like CompileConfig but resolves ${node} variables
// in apply-groups names before lookup. nodeID selects which per-node group
// to apply (e.g. nodeID=0 maps "node" -> "node0", so apply-groups "${node}"
// resolves to group "node0"). This supports a single shared config for both
// nodes in a chassis cluster.
func CompileConfigForNode(tree *ConfigTree, nodeID int) (*Config, error) {
	tree = tree.Clone()

	vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
	if err := tree.ExpandGroupsWithVars(vars); err != nil {
		return nil, fmt.Errorf("apply-groups: %w", err)
	}

	return compileExpanded(tree)
}

// compileExpanded compiles an already-expanded (groups resolved) ConfigTree
// into a typed Config. Shared by CompileConfig and CompileConfigForNode.
func compileExpanded(tree *ConfigTree) (*Config, error) {
	cfg := &Config{
		Security: SecurityConfig{
			Zones:  make(map[string]*ZoneConfig),
			Screen: make(map[string]*ScreenProfile),
		},
		Interfaces: InterfacesConfig{
			Interfaces: make(map[string]*InterfaceConfig),
		},
		Applications: ApplicationsConfig{
			Applications:    make(map[string]*Application),
			ApplicationSets: make(map[string]*ApplicationSet),
		},
		ClassOfService: &ClassOfServiceConfig{
			ForwardingClasses: make(map[string]*CoSForwardingClass),
			DSCPClassifiers:   make(map[string]*CoSDSCPClassifier),
			DSCPRewriteRules:  make(map[string]*CoSDSCPRewriteRule),
			Schedulers:        make(map[string]*CoSScheduler),
			SchedulerMaps:     make(map[string]*CoSSchedulerMap),
			Interfaces:        make(map[string]*CoSInterface),
		},
	}

	for _, node := range tree.Children {
		switch node.Name() {
		case "security":
			if err := compileSecurity(node, &cfg.Security); err != nil {
				return nil, fmt.Errorf("security: %w", err)
			}
		case "interfaces":
			if err := compileInterfaces(node, &cfg.Interfaces); err != nil {
				return nil, fmt.Errorf("interfaces: %w", err)
			}
		case "applications":
			if err := compileApplications(node, &cfg.Applications); err != nil {
				return nil, fmt.Errorf("applications: %w", err)
			}
		case "routing-options":
			if err := compileRoutingOptions(node, &cfg.RoutingOptions); err != nil {
				return nil, fmt.Errorf("routing-options: %w", err)
			}
		case "protocols":
			if err := compileProtocols(node, &cfg.Protocols); err != nil {
				return nil, fmt.Errorf("protocols: %w", err)
			}
		case "routing-instances":
			if err := compileRoutingInstances(node, cfg); err != nil {
				return nil, fmt.Errorf("routing-instances: %w", err)
			}
		case "firewall":
			if err := compileFirewall(node, &cfg.Firewall); err != nil {
				return nil, fmt.Errorf("firewall: %w", err)
			}
		case "class-of-service":
			if err := compileClassOfService(node, cfg.ClassOfService); err != nil {
				return nil, fmt.Errorf("class-of-service: %w", err)
			}
		case "services":
			if err := compileServices(node, &cfg.Services); err != nil {
				return nil, fmt.Errorf("services: %w", err)
			}
		case "forwarding-options":
			if err := compileForwardingOptions(node, &cfg.ForwardingOptions); err != nil {
				return nil, fmt.Errorf("forwarding-options: %w", err)
			}
		case "system":
			if err := compileSystem(node, &cfg.System); err != nil {
				return nil, fmt.Errorf("system: %w", err)
			}
		case "schedulers":
			if err := compileSchedulers(node, cfg); err != nil {
				return nil, fmt.Errorf("schedulers: %w", err)
			}
		case "policy-options":
			if err := compilePolicyOptions(node, &cfg.PolicyOptions); err != nil {
				return nil, fmt.Errorf("policy-options: %w", err)
			}
		case "chassis":
			if err := compileChassis(node, &cfg.Chassis); err != nil {
				return nil, fmt.Errorf("chassis: %w", err)
			}
		case "event-options":
			if err := compileEventOptions(node, &cfg.EventOptions); err != nil {
				return nil, fmt.Errorf("event-options: %w", err)
			}
		case "snmp":
			// Top-level snmp stanza (same format as system { snmp { ... } })
			if err := compileSNMP(node, &cfg.System); err != nil {
				return nil, fmt.Errorf("snmp: %w", err)
			}
		case "bridge-domains":
			if err := compileBridgeDomains(node, &cfg.BridgeDomains); err != nil {
				return nil, fmt.Errorf("bridge-domains: %w", err)
			}
		}
	}

	// Extract lo0 filter input from parsed interfaces into SystemConfig.
	if lo0 := cfg.Interfaces.Interfaces["lo0"]; lo0 != nil {
		if u0 := lo0.Units[0]; u0 != nil {
			cfg.System.Lo0FilterInputV4 = u0.FilterInputV4
			cfg.System.Lo0FilterInputV6 = u0.FilterInputV6
		}
	}

	// Post-compilation fixup: resolve vSRX-style fabric member-interfaces.
	// For fab0/fab1 with fabric-options member-interfaces, resolve which member
	// belongs to the local node using FPC slot → node-id mapping (slot 0 → node0,
	// slot 7 → node1). Also auto-populate FabricInterface/Fabric1Interface when
	// not explicitly set in chassis cluster config.
	if cc := cfg.Chassis.Cluster; cc != nil {
		for ifName, ifc := range cfg.Interfaces.Interfaces {
			if !strings.HasPrefix(ifName, "fab") || len(ifc.FabricMembers) == 0 {
				continue
			}
			for _, member := range ifc.FabricMembers {
				slot := InterfaceSlot(member)
				if slot >= 0 && SlotToNodeID(slot) == cc.NodeID {
					ifc.LocalFabricMember = member
					break
				}
			}
		}
		// Auto-detect fabric interfaces from fab0/fab1 member-interfaces
		// when not explicitly configured via fabric-interface/fabric1-interface.
		// Only set if the local node has a member (LocalFabricMember resolved above).
		// Dual-fabric: if both fab0 and fab1 have local members, set both
		// FabricInterface and Fabric1Interface (#130).
		// Single-fabric: only one fab is local → FabricInterface only.
		if cc.FabricInterface == "" {
			if f0, ok := cfg.Interfaces.Interfaces["fab0"]; ok && f0.LocalFabricMember != "" {
				cc.FabricInterface = "fab0"
			} else if f1, ok := cfg.Interfaces.Interfaces["fab1"]; ok && f1.LocalFabricMember != "" {
				cc.FabricInterface = "fab1"
			}
		}
		// Auto-detect secondary fabric: fab1 when primary is fab0 and fab1
		// also has a local member (dual-fabric topology).
		if cc.Fabric1Interface == "" && cc.FabricInterface == "fab0" {
			if f1, ok := cfg.Interfaces.Interfaces["fab1"]; ok && f1.LocalFabricMember != "" {
				cc.Fabric1Interface = "fab1"
			}
		}
		// Auto-derive Fabric1PeerAddress from the fab1 interface's /30 or /31
		// address when not explicitly configured.
		if cc.Fabric1Interface != "" && cc.Fabric1PeerAddress == "" {
			if f1 := cfg.Interfaces.Interfaces[cc.Fabric1Interface]; f1 != nil {
				if u0 := f1.Units[0]; u0 != nil {
					for _, addr := range u0.Addresses {
						if peer := peerFromPointToPoint(addr); peer != "" {
							cc.Fabric1PeerAddress = peer
							break
						}
					}
				}
			}
		}
	}

	if warnings := ValidateConfig(cfg); len(warnings) > 0 {
		for _, w := range warnings {
			cfg.Warnings = append(cfg.Warnings, w)
		}
	}

	return cfg, nil
}

// ValidateConfig performs cross-reference validation on a compiled config.
// Returns a list of warnings (non-fatal) for references that don't resolve.
func ValidateConfig(cfg *Config) []string {
	var warnings []string

	// Collect valid zone names
	zones := make(map[string]bool)
	for name := range cfg.Security.Zones {
		zones[name] = true
	}

	// Collect valid address-book entries
	addrs := make(map[string]bool)
	if ab := cfg.Security.AddressBook; ab != nil {
		for name := range ab.Addresses {
			addrs[name] = true
		}
		for name := range ab.AddressSets {
			addrs[name] = true
		}
	}

	// Collect valid applications
	apps := make(map[string]bool)
	for name := range cfg.Applications.Applications {
		apps[name] = true
	}
	for name := range cfg.Applications.ApplicationSets {
		apps[name] = true
	}
	// Built-in Junos application names
	builtins := []string{"any", "junos-http", "junos-https", "junos-ssh", "junos-telnet",
		"junos-dns-udp", "junos-dns-tcp", "junos-ping", "junos-icmp-all",
		"junos-bgp", "junos-ospf", "junos-ntp", "junos-dhcp-relay",
		"junos-ftp", "junos-smtp", "junos-icmp6-all", "junos-ike",
		"junos-ipsec-nat-t", "junos-dhcp-client", "junos-dhcp-server",
		"junos-snmp", "junos-syslog", "junos-traceroute", "junos-radius"}
	for _, b := range builtins {
		apps[b] = true
	}

	// Validate application port specs and protocols
	for name, app := range cfg.Applications.Applications {
		if err := validatePortSpec(app.DestinationPort); err != nil {
			warnings = append(warnings, fmt.Sprintf("application %s: destination-port: %v", name, err))
		}
		if err := validatePortSpec(app.SourcePort); err != nil {
			warnings = append(warnings, fmt.Sprintf("application %s: source-port: %v", name, err))
		}
		if app.Protocol != "" {
			if err := validateProtocol(app.Protocol); err != nil {
				warnings = append(warnings, fmt.Sprintf("application %s: %v", name, err))
			}
		}
	}

	// Validate policies
	for _, zpp := range cfg.Security.Policies {
		if zpp.FromZone != "any" && !zones[zpp.FromZone] {
			warnings = append(warnings, fmt.Sprintf(
				"policy from-zone %q: zone not defined", zpp.FromZone))
		}
		if zpp.ToZone != "any" && !zones[zpp.ToZone] {
			warnings = append(warnings, fmt.Sprintf(
				"policy to-zone %q: zone not defined", zpp.ToZone))
		}
		for _, p := range zpp.Policies {
			for _, addr := range p.Match.SourceAddresses {
				if addr != "any" && !addrs[addr] {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: source-address %q not in address-book", p.Name, addr))
				}
			}
			for _, addr := range p.Match.DestinationAddresses {
				if addr != "any" && !addrs[addr] {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: destination-address %q not in address-book", p.Name, addr))
				}
			}
			for _, app := range p.Match.Applications {
				if !apps[app] {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: application %q not defined", p.Name, app))
				}
			}
		}
	}

	// Validate NAT zone references
	for _, rs := range cfg.Security.NAT.Source {
		if rs.FromZone != "" && !zones[rs.FromZone] {
			warnings = append(warnings, fmt.Sprintf(
				"source-nat ruleset %q: from-zone %q not defined", rs.Name, rs.FromZone))
		}
		if rs.ToZone != "" && !zones[rs.ToZone] {
			warnings = append(warnings, fmt.Sprintf(
				"source-nat ruleset %q: to-zone %q not defined", rs.Name, rs.ToZone))
		}
	}

	// Validate screen references in zones
	for name, zone := range cfg.Security.Zones {
		if zone.ScreenProfile != "" {
			if _, ok := cfg.Security.Screen[zone.ScreenProfile]; !ok {
				warnings = append(warnings, fmt.Sprintf(
					"zone %q: screen profile %q not defined", name, zone.ScreenProfile))
			}
		}
	}

	// Validate address-book entries have valid CIDR or IP formats
	if ab := cfg.Security.AddressBook; ab != nil {
		for name, entry := range ab.Addresses {
			if entry.Value != "" {
				if _, _, err := net.ParseCIDR(entry.Value); err != nil {
					if net.ParseIP(entry.Value) == nil {
						warnings = append(warnings, fmt.Sprintf(
							"address-book %q: invalid address %q", name, entry.Value))
					}
				}
			}
		}
		// Validate address-set members reference valid entries
		for setName, as := range ab.AddressSets {
			for _, m := range as.Addresses {
				if !addrs[m] {
					warnings = append(warnings, fmt.Sprintf(
						"address-set %q: member %q not in address-book", setName, m))
				}
			}
			for _, m := range as.AddressSets {
				if !addrs[m] {
					warnings = append(warnings, fmt.Sprintf(
						"address-set %q: nested set %q not in address-book", setName, m))
				}
			}
		}
	}

	// Validate static route destinations are valid CIDR
	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		if sr.Destination != "" {
			if _, _, err := net.ParseCIDR(sr.Destination); err != nil {
				warnings = append(warnings, fmt.Sprintf(
					"static route: invalid destination %q", sr.Destination))
			}
		}
	}

	// Validate DNAT pool references
	if dnat := cfg.Security.NAT.Destination; dnat != nil {
		for _, rs := range dnat.RuleSets {
			for _, rule := range rs.Rules {
				if rule.Then.PoolName != "" {
					if _, ok := dnat.Pools[rule.Then.PoolName]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"destination-nat %q rule %q: pool %q not defined",
							rs.Name, rule.Name, rule.Then.PoolName))
					}
				}
			}
		}
	}

	// Validate SNAT pool references
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			if rule.Then.PoolName != "" {
				if _, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"source-nat %q rule %q: pool %q not defined",
						rs.Name, rule.Name, rule.Then.PoolName))
				}
			}
		}
	}

	// Validate zone interface references
	configuredIfaces := make(map[string]bool)
	for name := range cfg.Interfaces.Interfaces {
		configuredIfaces[name] = true
	}
	for zoneName, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			// Strip unit suffix (e.g. "trust0.0" -> "trust0")
			base := ifName
			if idx := strings.Index(ifName, "."); idx > 0 {
				base = ifName[:idx]
			}
			if !configuredIfaces[base] {
				warnings = append(warnings, fmt.Sprintf(
					"zone %q: interface %q not in interfaces config", zoneName, ifName))
			}
		}
	}

	// Validate scheduler references in policies
	for _, zpp := range cfg.Security.Policies {
		for _, p := range zpp.Policies {
			if p.SchedulerName != "" {
				if _, ok := cfg.Schedulers[p.SchedulerName]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: scheduler %q not defined", p.Name, p.SchedulerName))
				}
			}
		}
	}

	// Validate routing-instance interface references
	for _, ri := range cfg.RoutingInstances {
		for _, ifName := range ri.Interfaces {
			base := ifName
			if idx := strings.Index(ifName, "."); idx > 0 {
				base = ifName[:idx]
			}
			if !configuredIfaces[base] {
				warnings = append(warnings, fmt.Sprintf(
					"routing-instance %q: interface %q not in interfaces config",
					ri.Name, ifName))
			}
		}
	}

	// Validate firewall filter references on interfaces
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		for unitNum, unit := range ifc.Units {
			if unit.FilterInputV4 != "" {
				if _, ok := cfg.Firewall.FiltersInet[unit.FilterInputV4]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter input %q not defined",
						ifName, unitNum, unit.FilterInputV4))
				}
			}
			if unit.FilterInputV6 != "" {
				if _, ok := cfg.Firewall.FiltersInet6[unit.FilterInputV6]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter input-v6 %q not defined",
						ifName, unitNum, unit.FilterInputV6))
				}
			}
			if unit.FilterOutputV4 != "" {
				if _, ok := cfg.Firewall.FiltersInet[unit.FilterOutputV4]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter output %q not defined",
						ifName, unitNum, unit.FilterOutputV4))
				}
			}
			if unit.FilterOutputV6 != "" {
				if _, ok := cfg.Firewall.FiltersInet6[unit.FilterOutputV6]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter output-v6 %q not defined",
						ifName, unitNum, unit.FilterOutputV6))
				}
			}
		}
	}

	// Validate chassis cluster fabric config
	if cc := cfg.Chassis.Cluster; cc != nil {
		// fabric1-interface without fabric1-peer-address (or vice versa) is incomplete
		if (cc.Fabric1Interface != "") != (cc.Fabric1PeerAddress != "") {
			warnings = append(warnings, "chassis cluster: fabric1-interface and fabric1-peer-address must both be set for dual-fabric")
		}
		// Check fabric interfaces are defined in interface config
		for _, pair := range [][2]string{
			{cc.FabricInterface, "fabric-interface"},
			{cc.Fabric1Interface, "fabric1-interface"},
		} {
			ifName, label := pair[0], pair[1]
			if ifName != "" {
				if _, ok := cfg.Interfaces.Interfaces[ifName]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"chassis cluster %s %q: interface not defined", label, ifName))
				}
			}
		}
		// Check control interface is defined
		if cc.ControlInterface != "" {
			if _, ok := cfg.Interfaces.Interfaces[cc.ControlInterface]; !ok {
				warnings = append(warnings, fmt.Sprintf(
					"chassis cluster control-interface %q: interface not defined", cc.ControlInterface))
			}
		}
		// Check fabric member interfaces don't overlap between fab0 and fab1
		if cc.FabricInterface != "" && cc.Fabric1Interface != "" {
			fab0Members := make(map[string]bool)
			if f0 := cfg.Interfaces.Interfaces[cc.FabricInterface]; f0 != nil {
				for _, m := range f0.FabricMembers {
					fab0Members[m] = true
				}
			}
			if f1 := cfg.Interfaces.Interfaces[cc.Fabric1Interface]; f1 != nil {
				for _, m := range f1.FabricMembers {
					if fab0Members[m] {
						warnings = append(warnings, fmt.Sprintf(
							"chassis cluster: fabric member %q shared between %s and %s",
							m, cc.FabricInterface, cc.Fabric1Interface))
					}
				}
			}
		}
	}

	// Validate strict-vip-ownership requires VRRP (incompatible with no-reth-vrrp / private-rg-election)
	if cc := cfg.Chassis.Cluster; cc != nil && (cc.NoRethVRRP || cc.PrivateRGElection) {
		for _, rg := range cc.RedundancyGroups {
			if rg.StrictVIPOwnership {
				warnings = append(warnings, fmt.Sprintf(
					"redundancy-group %d: strict-vip-ownership incompatible with no-reth-vrrp (no VRRP instances to gate on)", rg.ID))
			}
		}
	}

	// Warn if no-reth-vrrp set explicitly — redundant since private-rg-election is now default
	if cc := cfg.Chassis.Cluster; cc != nil && cc.PrivateRGElection && cc.NoRethVRRP {
		warnings = append(warnings, "chassis cluster: no-reth-vrrp is redundant (private-rg-election is the default)")
	}

	if cfg.System.PersistGroupsInheritance {
		warnings = append(warnings, "system commit persist-groups-inheritance configured but group inheritance persistence is not implemented")
	}

	// #654: warn on `system processes X disable` for a process that
	// bpfrx does not actually manage. Silently accepting the knob (as
	// used to happen with e.g. `utmd disable` on vSRX) means the
	// operator gets no signal that the setting is a no-op.
	for _, proc := range cfg.System.DisabledProcesses {
		if !isKnownProcessName(proc) {
			warnings = append(warnings, fmt.Sprintf(
				"system processes %q disable: bpfrx does not manage %q; setting has no runtime effect", proc, proc))
		}
	}

	// #651: warn when archive-sites include inline `password`
	// credentials. Runtime archival shells out to `scp` with
	// `-o BatchMode=yes`, so the password is silently ignored and
	// archival can fail unless matching SSH keys are already set up.
	if cfg.System.Archival != nil {
		for _, url := range cfg.System.Archival.ArchiveSitesWithPassword {
			warnings = append(warnings, fmt.Sprintf(
				"system archival archive-sites %q: inline password is accepted but ignored — archival uses scp BatchMode and relies on SSH keys, not passwords", url))
		}
	}

	if cfg.System.Services != nil && cfg.System.Services.DNSProxyConfigured {
		warnings = append(warnings, "system services dns dns-proxy configured but DNS proxy/forwarder runtime is not implemented")
	}

	if fm := cfg.Services.FlowMonitoring; fm != nil {
		checkExtWarning := func(kind, name string, exts []string) {
			for _, ext := range exts {
				if ext == "app-id" {
					warnings = append(warnings, fmt.Sprintf(
						"flow-monitoring %s template %s: export-extension app-id configured but application data is not available in flow records", kind, name))
				}
			}
		}
		if fm.Version9 != nil {
			for _, tmpl := range fm.Version9.Templates {
				checkExtWarning("version9", tmpl.Name, tmpl.ExportExtensions)
			}
		}
		if fm.VersionIPFIX != nil {
			for _, tmpl := range fm.VersionIPFIX.Templates {
				checkExtWarning("version-ipfix", tmpl.Name, tmpl.ExportExtensions)
			}
		}
	}

	if cos := cfg.ClassOfService; cos != nil {
		warnedClassifierLossPriority := false
		warnedRewriteLossPriority := false
		for _, class := range cos.ForwardingClasses {
			if class == nil {
				continue
			}
			if class.Queue < 0 || class.Queue > 255 {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service forwarding-class %q uses out-of-range queue %d (expected 0..255)",
					class.Name, class.Queue))
			}
		}
		// #915: surplus-sharing is meaningful only on transmit-rate
		// exact schedulers; warn-and-strip when set without exact so
		// the runtime never sees the no-op flag (see #1183 lesson).
		for _, sched := range cos.Schedulers {
			if sched == nil {
				continue
			}
			if sched.SurplusSharing && !sched.TransmitRateExact {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service scheduler %q surplus-sharing is meaningful only with transmit-rate exact; ignored",
					sched.Name))
				sched.SurplusSharing = false
			}
		}
		for _, schedMap := range cos.SchedulerMaps {
			if schedMap == nil {
				continue
			}
			for className, entry := range schedMap.Entries {
				if _, ok := cos.ForwardingClasses[className]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service scheduler-map %q references undefined forwarding-class %q",
						schedMap.Name, className))
				}
				if entry == nil || entry.Scheduler == "" {
					continue
				}
				if _, ok := cos.Schedulers[entry.Scheduler]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service scheduler-map %q references undefined scheduler %q",
						schedMap.Name, entry.Scheduler))
				}
			}
		}
		for _, classifier := range cos.DSCPClassifiers {
			if classifier == nil {
				continue
			}
			for _, entry := range classifier.Entries {
				if entry == nil || entry.ForwardingClass == "" {
					continue
				}
				if _, ok := cos.ForwardingClasses[entry.ForwardingClass]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service dscp classifier %q references undefined forwarding-class %q",
						classifier.Name, entry.ForwardingClass))
				}
				if entry.LossPriority != "" && !warnedClassifierLossPriority {
					warnings = append(warnings, "class-of-service dscp/802.1p classifier loss-priority is accepted for compatibility but not yet enforced by the userspace dataplane")
					warnedClassifierLossPriority = true
				}
			}
		}
		for _, classifier := range cos.IEEE8021Classifiers {
			if classifier == nil {
				continue
			}
			for _, entry := range classifier.Entries {
				if entry == nil || entry.ForwardingClass == "" {
					continue
				}
				if _, ok := cos.ForwardingClasses[entry.ForwardingClass]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service ieee-802.1 classifier %q references undefined forwarding-class %q",
						classifier.Name, entry.ForwardingClass))
				}
				if entry.LossPriority != "" && !warnedClassifierLossPriority {
					warnings = append(warnings, "class-of-service dscp/802.1p classifier loss-priority is accepted for compatibility but not yet enforced by the userspace dataplane")
					warnedClassifierLossPriority = true
				}
			}
		}
		for _, rewriteRule := range cos.DSCPRewriteRules {
			if rewriteRule == nil {
				continue
			}
			for _, entry := range rewriteRule.Entries {
				if entry == nil || entry.ForwardingClass == "" {
					continue
				}
				if _, ok := cos.ForwardingClasses[entry.ForwardingClass]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service dscp rewrite-rule %q references undefined forwarding-class %q",
						rewriteRule.Name, entry.ForwardingClass))
				}
				if entry.LossPriority != "" && !warnedRewriteLossPriority {
					warnings = append(warnings, "class-of-service dscp rewrite-rule loss-priority is accepted for compatibility but not yet enforced by the userspace dataplane")
					warnedRewriteLossPriority = true
				}
			}
		}
		for _, iface := range cos.Interfaces {
			if iface == nil {
				continue
			}
			for _, unit := range iface.Units {
				if unit == nil {
					continue
				}
				if unit.SchedulerMap != "" {
					if _, ok := cos.SchedulerMaps[unit.SchedulerMap]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined scheduler-map %q",
							iface.Name, unit.Unit, unit.SchedulerMap))
					}
				}
				if unit.DSCPClassifier != "" {
					if _, ok := cos.DSCPClassifiers[unit.DSCPClassifier]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined dscp classifier %q",
							iface.Name, unit.Unit, unit.DSCPClassifier))
					}
				}
				if unit.IEEE8021Classifier != "" {
					if _, ok := cos.IEEE8021Classifiers[unit.IEEE8021Classifier]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined ieee-802.1 classifier %q",
							iface.Name, unit.Unit, unit.IEEE8021Classifier))
					}
				}
				if unit.DSCPRewriteRule != "" {
					if _, ok := cos.DSCPRewriteRules[unit.DSCPRewriteRule]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined dscp rewrite-rule %q",
							iface.Name, unit.Unit, unit.DSCPRewriteRule))
					}
				}
			}
		}
		if (len(cos.Interfaces) > 0 || len(cos.DSCPClassifiers) > 0 || len(cos.IEEE8021Classifiers) > 0 || len(cos.DSCPRewriteRules) > 0) && cfg.System.DataplaneType != "userspace" {
			warnings = append(warnings, "class-of-service shaping, classifier attachment, and dscp rewrite-rule attachment are only implemented in the userspace dataplane; configuration is accepted but will not take effect on this dataplane")
		}
	}

	return warnings
}

// knownManagedProcessNames is the set of Junos process names that bpfrx
// actually honours when `system processes X disable` is configured.
// The runtime sites hard-code their process name (not a table lookup):
//   - pkg/daemon/daemon.go ~:715 — `isProcessDisabled(cfg, "snmpd")`
//   - pkg/daemon/daemon_system.go ~:383 — `isProcessDisabled(cfg, "ntp")`
// This table mirrors those hard-codes for the purpose of the #654
// validation warning. Any addition here MUST be paired with a matching
// runtime gating site, or the warning will go quiet while the knob
// remains a no-op.
var knownManagedProcessNames = map[string]struct{}{
	"snmpd": {},
	"ntp":   {},
}

func isKnownProcessName(name string) bool {
	_, ok := knownManagedProcessNames[name]
	return ok
}

func compileApplications(node *Node, apps *ApplicationsConfig) error {
	for _, inst := range namedInstances(node.FindChildren("application")) {
		appName := inst.name
		app := &Application{Name: appName}

		var terms []*Application
		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "protocol":
				app.Protocol = nodeVal(prop)
			case "destination-port":
				app.DestinationPort = nodeVal(prop)
			case "source-port":
				app.SourcePort = nodeVal(prop)
			case "inactivity-timeout", "timeout":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						app.InactivityTimeout = n
					}
				}
			case "alg":
				app.ALG = nodeVal(prop)
			case "description":
				app.Description = nodeVal(prop)
			case "term":
				// Inline term: "term <name> [alg <a>] protocol <p> [source-port <sp>]
				//               [destination-port <dp>] [inactivity-timeout <t>];"
				if len(prop.Keys) < 2 {
					continue
				}
				// Hierarchical: all values in prop.Keys (inline statement)
				// Flat set: values split across prop.Keys and prop.Children
				allKeys := prop.Keys[1:]
				for _, c := range prop.Children {
					allKeys = append(allKeys, c.Keys...)
				}
				termApps := parseApplicationTerms(appName, allKeys)
				terms = append(terms, termApps...)
			}
		}

		if len(terms) > 0 {
			implicitSet := &ApplicationSet{Name: appName}
			for _, t := range terms {
				t.Description = app.Description
				apps.Applications[t.Name] = t
				implicitSet.Applications = append(implicitSet.Applications, t.Name)
			}
			apps.ApplicationSets[appName] = implicitSet
		} else {
			apps.Applications[appName] = app
		}
	}

	for _, inst := range namedInstances(node.FindChildren("application-set")) {
		as := &ApplicationSet{Name: inst.name}

		for _, member := range inst.node.Children {
			if member.Name() == "application" {
				v := nodeVal(member)
				if v != "" {
					as.Applications = append(as.Applications, v)
				}
			}
		}

		apps.ApplicationSets[as.Name] = as
	}

	return nil
}

// parseApplicationTerms parses an inline term like:
// "term-name [alg ssh] protocol tcp [source-port 22] [destination-port 22] [inactivity-timeout 86400]"
// When multiple protocol values are present, returns one Application per
// unique protocol (each sharing the same ports/timeout/alg).
func parseApplicationTerms(parentName string, keys []string) []*Application {
	if len(keys) == 0 {
		return nil
	}
	termName := keys[0]

	var protocols []string
	var dstPort, srcPort, alg string
	var timeout int

	for i := 1; i < len(keys); i++ {
		switch keys[i] {
		case "protocol":
			if i+1 < len(keys) {
				i++
				protocols = append(protocols, normalizeProtocol(keys[i]))
			}
		case "destination-port":
			if i+1 < len(keys) {
				i++
				dstPort = keys[i]
			}
		case "source-port":
			if i+1 < len(keys) {
				i++
				srcPort = keys[i]
			}
		case "inactivity-timeout", "timeout":
			if i+1 < len(keys) {
				i++
				if v, err := strconv.Atoi(keys[i]); err == nil {
					timeout = v
				}
			}
		case "alg":
			if i+1 < len(keys) {
				i++
				alg = keys[i]
			}
		}
	}

	// Deduplicate protocols (e.g. "junos-icmp-all" and "icmp" both normalize to "icmp")
	if len(protocols) == 0 {
		protocols = []string{""}
	}
	seen := make(map[string]bool)
	var unique []string
	for _, p := range protocols {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}

	var result []*Application
	for _, proto := range unique {
		name := parentName + "-" + termName
		if len(unique) > 1 {
			suffix := proto
			if suffix == "" {
				suffix = "any"
			}
			name = parentName + "-" + termName + "-" + suffix
		}
		result = append(result, &Application{
			Name:              name,
			Protocol:          proto,
			DestinationPort:   dstPort,
			SourcePort:        srcPort,
			InactivityTimeout: timeout,
			ALG:               alg,
		})
	}
	return result
}

// normalizeProtocol maps Junos protocol aliases to canonical names
// so that "junos-icmp-all" and "icmp" deduplicate correctly.
func normalizeProtocol(name string) string {
	switch strings.ToLower(name) {
	case "junos-icmp-all", "junos-ping":
		return "icmp"
	case "junos-icmp6-all", "junos-pingv6", "icmp6":
		return "icmpv6"
	case "junos-gre":
		return "gre"
	case "junos-ospf":
		return "89"
	case "junos-tcp-any":
		return "tcp"
	case "junos-udp-any":
		return "udp"
	case "junos-ip-in-ip", "junos-ipip":
		return "4"
	default:
		return name
	}
}

// validatePortSpec checks that a port specification is valid.
// Valid formats: "80", "8080-8090", named ports like "http".
func validatePortSpec(spec string) error {
	if spec == "" {
		return nil
	}
	namedPorts := map[string]bool{
		"http": true, "https": true, "ssh": true, "telnet": true,
		"ftp": true, "ftp-data": true, "smtp": true, "dns": true,
		"pop3": true, "imap": true, "snmp": true, "ntp": true,
		"bgp": true, "ldap": true, "syslog": true,
	}
	if namedPorts[strings.ToLower(spec)] {
		return nil
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("invalid port range %q: non-numeric", spec)
		}
		if lo < 1 || lo > 65535 {
			return fmt.Errorf("invalid port %d: must be 1-65535", lo)
		}
		if hi < 1 || hi > 65535 {
			return fmt.Errorf("invalid port %d: must be 1-65535", hi)
		}
		if lo > hi {
			return fmt.Errorf("invalid port range %q: start > end", spec)
		}
		return nil
	}
	port, err := strconv.Atoi(spec)
	if err != nil {
		return fmt.Errorf("invalid port %q: not a number or known service", spec)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d: must be 1-65535", port)
	}
	return nil
}

// validateProtocol checks that a protocol specification is valid.
func validateProtocol(proto string) error {
	validProtos := map[string]bool{
		"tcp": true, "udp": true, "icmp": true, "icmp6": true, "icmpv6": true,
		"ospf": true, "gre": true, "ipip": true, "ah": true, "esp": true,
		"igmp": true, "pim": true, "sctp": true, "vrrp": true, "egp": true,
	}
	if validProtos[strings.ToLower(proto)] {
		return nil
	}
	// Accept junos-* protocol aliases
	if strings.HasPrefix(strings.ToLower(proto), "junos-") {
		return nil
	}
	n, err := strconv.Atoi(proto)
	if err != nil {
		return fmt.Errorf("invalid protocol %q", proto)
	}
	if n < 0 || n > 255 {
		return fmt.Errorf("invalid protocol number %d: must be 0-255", n)
	}
	return nil
}

func nodeVal(n *Node) string {
	if len(n.Keys) >= 2 {
		return n.Keys[1]
	}
	if len(n.Children) > 0 {
		return n.Children[0].Name()
	}
	return ""
}
