package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestRoutingConfigParsing(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set routing-options static route 0.0.0.0/0 next-hop 192.168.1.1", "set routing-options static route 10.10.0.0/16 next-hop 10.0.0.2", "set routing-options static route 192.168.99.0/24 discard", "set routing-options static route 172.16.0.0/12 next-hop 10.0.0.3", "set routing-options static route 172.16.0.0/12 preference 100", "set protocols ospf router-id 10.0.0.1", "set protocols ospf area 0.0.0.0 interface eth1", "set protocols ospf area 0.0.0.0 interface gre0", "set protocols ospf area 0.0.0.0 interface eth2 passive", "set protocols bgp local-as 65001", "set protocols bgp router-id 10.0.0.1", "set protocols bgp group ebgp peer-as 65002", "set protocols bgp group ebgp neighbor 10.1.0.1", "set interfaces gre0 tunnel source 10.0.0.1", "set interfaces gre0 tunnel destination 10.1.0.1", "set interfaces gre0 unit 0 family inet address 172.16.0.1/30", "set security ipsec proposal aes256 protocol esp", "set security ipsec proposal aes256 encryption-algorithm aes-256-cbc", "set security ipsec proposal aes256 authentication-algorithm hmac-sha-256", "set security ipsec proposal aes256 dh-group 14", "set security ipsec proposal aes256 lifetime-seconds 3600", "set security ipsec vpn site-a gateway 10.1.0.1", "set security ipsec vpn site-a local-address 10.0.0.1", "set security ipsec vpn site-a ipsec-policy aes256", "set security ipsec vpn site-a local-identity 10.0.0.0/24", "set security ipsec vpn site-a remote-identity 10.1.0.0/24", `set security ipsec vpn site-a pre-shared-key "secret123"`}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	output := tree.Format()
	t.Logf("Formatted tree:\n%s", output)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig failed: %v", err)
	}
	if len(cfg.RoutingOptions.StaticRoutes) != 4 {
		t.Fatalf("expected 4 static routes, got %d", len(cfg.RoutingOptions.StaticRoutes))
	}
	r0 := cfg.RoutingOptions.StaticRoutes[0]
	if r0.Destination != "0.0.0.0/0" || len(r0.NextHops) != 1 || r0.NextHops[0].Address != "192.168.1.1" {
		t.Errorf("route 0: dest=%s nhs=%v", r0.Destination, r0.NextHops)
	}
	if r0.Preference != 5 {
		t.Errorf("route 0: expected default preference 5, got %d", r0.Preference)
	}
	r2 := cfg.RoutingOptions.StaticRoutes[2]
	if r2.Destination != "192.168.99.0/24" || !r2.Discard {
		t.Errorf("route 2: dest=%s discard=%v", r2.Destination, r2.Discard)
	}
	r3 := cfg.RoutingOptions.StaticRoutes[3]
	if r3.Destination != "172.16.0.0/12" || len(r3.NextHops) != 1 || r3.NextHops[0].Address != "10.0.0.3" {
		t.Errorf("route 3: dest=%s nhs=%v", r3.Destination, r3.NextHops)
	}
	if r3.Preference != 100 {
		t.Errorf("route 3: expected preference 100, got %d", r3.Preference)
	}
	if cfg.Protocols.OSPF == nil {
		t.Fatal("OSPF config is nil")
	}
	if cfg.Protocols.OSPF.RouterID != "10.0.0.1" {
		t.Errorf("OSPF router-id: %s", cfg.Protocols.OSPF.RouterID)
	}
	if len(cfg.Protocols.OSPF.Areas) != 1 {
		t.Fatalf("expected 1 OSPF area, got %d", len(cfg.Protocols.OSPF.Areas))
	}
	area := cfg.Protocols.OSPF.Areas[0]
	if area.ID != "0.0.0.0" {
		t.Errorf("OSPF area ID: %s", area.ID)
	}
	if len(area.Interfaces) != 3 {
		t.Fatalf("expected 3 OSPF interfaces, got %d", len(area.Interfaces))
	}
	if area.Interfaces[0].Name != "eth1" || area.Interfaces[0].Passive {
		t.Errorf("OSPF iface 0: name=%s passive=%v", area.Interfaces[0].Name, area.Interfaces[0].Passive)
	}
	if area.Interfaces[2].Name != "eth2" || !area.Interfaces[2].Passive {
		t.Errorf("OSPF iface 2: name=%s passive=%v", area.Interfaces[2].Name, area.Interfaces[2].Passive)
	}
	if cfg.Protocols.BGP == nil {
		t.Fatal("BGP config is nil")
	}
	if cfg.Protocols.BGP.LocalAS != 65001 {
		t.Errorf("BGP local-as: %d", cfg.Protocols.BGP.LocalAS)
	}
	if cfg.Protocols.BGP.RouterID != "10.0.0.1" {
		t.Errorf("BGP router-id: %s", cfg.Protocols.BGP.RouterID)
	}
	if len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("expected 1 BGP neighbor, got %d", len(cfg.Protocols.BGP.Neighbors))
	}
	nbr := cfg.Protocols.BGP.Neighbors[0]
	if nbr.Address != "10.1.0.1" || nbr.PeerAS != 65002 {
		t.Errorf("BGP neighbor: addr=%s peer-as=%d", nbr.Address, nbr.PeerAS)
	}
	ifc := cfg.Interfaces.Interfaces["gre0"]
	if ifc == nil {
		t.Fatal("missing interface gre0")
	}
	if ifc.Tunnel == nil {
		t.Fatal("gre0 missing tunnel config")
	}
	if ifc.Tunnel.Source != "10.0.0.1" || ifc.Tunnel.Destination != "10.1.0.1" {
		t.Errorf("tunnel: src=%s dst=%s", ifc.Tunnel.Source, ifc.Tunnel.Destination)
	}
	if len(ifc.Tunnel.Addresses) != 1 || ifc.Tunnel.Addresses[0] != "172.16.0.1/30" {
		t.Errorf("tunnel addresses: %v", ifc.Tunnel.Addresses)
	}
	prop := cfg.Security.IPsec.Proposals["aes256"]
	if prop == nil {
		t.Fatal("missing IPsec proposal aes256")
	}
	if prop.Protocol != "esp" {
		t.Errorf("proposal protocol: %s", prop.Protocol)
	}
	if prop.EncryptionAlg != "aes-256-cbc" {
		t.Errorf("proposal encryption: %s", prop.EncryptionAlg)
	}
	if prop.AuthAlg != "hmac-sha-256" {
		t.Errorf("proposal auth: %s", prop.AuthAlg)
	}
	if prop.DHGroup != 14 {
		t.Errorf("proposal dh-group: %d", prop.DHGroup)
	}
	if prop.LifetimeSeconds != 3600 {
		t.Errorf("proposal lifetime: %d", prop.LifetimeSeconds)
	}
	vpn := cfg.Security.IPsec.VPNs["site-a"]
	if vpn == nil {
		t.Fatal("missing IPsec VPN site-a")
	}
	if vpn.Gateway != "10.1.0.1" {
		t.Errorf("vpn gateway: %s", vpn.Gateway)
	}
	if vpn.LocalAddr != "10.0.0.1" {
		t.Errorf("vpn local-address: %s", vpn.LocalAddr)
	}
	if vpn.IPsecPolicy != "aes256" {
		t.Errorf("vpn ipsec-policy: %s", vpn.IPsecPolicy)
	}
	if vpn.LocalID != "10.0.0.0/24" {
		t.Errorf("vpn local-identity: %s", vpn.LocalID)
	}
	if vpn.RemoteID != "10.1.0.0/24" {
		t.Errorf("vpn remote-identity: %s", vpn.RemoteID)
	}
	if vpn.PSK != "secret123" {
		t.Errorf("vpn psk: %s", vpn.PSK)
	}
	parser2 := NewParser(output)
	tree2, errs := parser2.Parse()
	if len(errs) > 0 {
		t.Fatalf("re-parse errors: %v", errs)
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("re-compile failed: %v", err)
	}
	if len(cfg2.RoutingOptions.StaticRoutes) != len(cfg.RoutingOptions.StaticRoutes) {
		t.Error("round-trip static route count mismatch")
	}
	if cfg2.Protocols.OSPF == nil || cfg2.Protocols.OSPF.RouterID != cfg.Protocols.OSPF.RouterID {
		t.Error("round-trip OSPF mismatch")
	}
	if cfg2.Protocols.BGP == nil || cfg2.Protocols.BGP.LocalAS != cfg.Protocols.BGP.LocalAS {
		t.Error("round-trip BGP mismatch")
	}
}

func TestECMPStaticRoutes(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set routing-options static route 10.0.0.0/8 next-hop 10.0.1.1", "set routing-options static route 10.0.0.0/8 next-hop 10.0.2.1", "set routing-options static route 192.168.0.0/16 next-hop 10.0.1.1"}
	for _, cmd := range setCommands {
		fields := strings.Fields(cmd)
		if err := tree.SetPath(fields[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.RoutingOptions.StaticRoutes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(cfg.RoutingOptions.StaticRoutes))
	}
	r0 := cfg.RoutingOptions.StaticRoutes[0]
	if r0.Destination != "10.0.0.0/8" {
		t.Errorf("route 0 dest: %s", r0.Destination)
	}
	if len(r0.NextHops) != 2 {
		t.Fatalf("route 0: expected 2 next-hops, got %d", len(r0.NextHops))
	}
	if r0.NextHops[0].Address != "10.0.1.1" || r0.NextHops[1].Address != "10.0.2.1" {
		t.Errorf("route 0 next-hops: %v", r0.NextHops)
	}
	r1 := cfg.RoutingOptions.StaticRoutes[1]
	if r1.Destination != "192.168.0.0/16" || len(r1.NextHops) != 1 {
		t.Errorf("route 1: dest=%s nhs=%v", r1.Destination, r1.NextHops)
	}
	hierInput := `routing-options {
    static {
        route 10.0.0.0/8 {
            next-hop 10.0.1.1;
            next-hop 10.0.2.1;
            next-hop 10.0.3.1;
        }
    }
}`
	parser := NewParser(hierInput)
	hierTree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	hierCfg, err := CompileConfig(hierTree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(hierCfg.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(hierCfg.RoutingOptions.StaticRoutes))
	}
	hr := hierCfg.RoutingOptions.StaticRoutes[0]
	if len(hr.NextHops) != 3 {
		t.Fatalf("expected 3 next-hops, got %d", len(hr.NextHops))
	}
	if hr.NextHops[0].Address != "10.0.1.1" || hr.NextHops[1].Address != "10.0.2.1" || hr.NextHops[2].Address != "10.0.3.1" {
		t.Errorf("hierarchical next-hops: %v", hr.NextHops)
	}
}

func TestNextTableStaticRoutes(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		// The next-table target routing-instance must be defined or the
		// #5693 definedness gate rejects the commit.
		"set routing-instances Comcast-GigabitPro instance-type virtual-router",
		// #9810: one unclaimed unit (N=1) so the per-ingress window gate admits the leak.
		"set interfaces ge-0/0/0 unit 0",
		"set routing-options static route 0.0.0.0/0 next-table Comcast-GigabitPro.inet.0",
		"set routing-options static route 10.1.10.0/24 next-hop 50.247.115.22",
	}
	for _, cmd := range setCommands {
		fields := strings.Fields(cmd)
		if err := tree.SetPath(fields[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.RoutingOptions.StaticRoutes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(cfg.RoutingOptions.StaticRoutes))
	}
	r0 := cfg.RoutingOptions.StaticRoutes[0]
	if r0.Destination != "0.0.0.0/0" {
		t.Errorf("route 0 dest: %s", r0.Destination)
	}
	if r0.NextTable != "Comcast-GigabitPro" {
		t.Errorf("route 0 next-table: got %q, want %q", r0.NextTable, "Comcast-GigabitPro")
	}
	if len(r0.NextHops) != 0 {
		t.Errorf("route 0 should have no next-hops, got %v", r0.NextHops)
	}
	r1 := cfg.RoutingOptions.StaticRoutes[1]
	if r1.NextTable != "" {
		t.Errorf("route 1 should have no next-table, got %q", r1.NextTable)
	}
	if len(r1.NextHops) != 1 || r1.NextHops[0].Address != "50.247.115.22" {
		t.Errorf("route 1 next-hops: %v", r1.NextHops)
	}
	// The next-table target routing-instance must be defined or the #5693
	// definedness gate rejects the commit.
	hierInput := `routing-instances {
    Comcast-GigabitPro {
        instance-type virtual-router;
    }
}
interfaces {
    ge-0/0/0 {
        unit 0;
    }
}
routing-options {
    static {
        route 0.0.0.0/0 {
            next-table Comcast-GigabitPro.inet.0;
        }
    }
    rib inet6.0 {
        static {
            route ::/0 next-table Comcast-GigabitPro.inet6.0;
        }
    }
}`
	parser := NewParser(hierInput)
	hierTree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	hierCfg, err := CompileConfig(hierTree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(hierCfg.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("expected 1 inet route, got %d", len(hierCfg.RoutingOptions.StaticRoutes))
	}
	if hierCfg.RoutingOptions.StaticRoutes[0].NextTable != "Comcast-GigabitPro" {
		t.Errorf("inet next-table: got %q", hierCfg.RoutingOptions.StaticRoutes[0].NextTable)
	}
	if len(hierCfg.RoutingOptions.Inet6StaticRoutes) != 1 {
		t.Fatalf("expected 1 inet6 route, got %d", len(hierCfg.RoutingOptions.Inet6StaticRoutes))
	}
	if hierCfg.RoutingOptions.Inet6StaticRoutes[0].NextTable != "Comcast-GigabitPro" {
		t.Errorf("inet6 next-table: got %q", hierCfg.RoutingOptions.Inet6StaticRoutes[0].NextTable)
	}
}

func TestNestedAddressSets(t *testing.T) {
	input := `security {
    address-book {
        global {
            address srv1 10.0.1.10/32;
            address srv2 10.0.1.20/32;
            address srv3 10.0.2.10/32;
            address-set servers {
                address srv1;
                address srv2;
            }
            address-set all-servers {
                address srv3;
                address-set servers;
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	ab := cfg.Security.AddressBook
	if ab == nil {
		t.Fatal("missing address book")
	}
	if len(ab.Addresses) != 3 {
		t.Fatalf("expected 3 addresses, got %d", len(ab.Addresses))
	}
	servers := ab.AddressSets["servers"]
	if servers == nil {
		t.Fatal("missing address-set servers")
	}
	if len(servers.Addresses) != 2 {
		t.Errorf("servers: expected 2 address members, got %d", len(servers.Addresses))
	}
	if len(servers.AddressSets) != 0 {
		t.Errorf("servers: expected 0 address-set members, got %d", len(servers.AddressSets))
	}
	allServers := ab.AddressSets["all-servers"]
	if allServers == nil {
		t.Fatal("missing address-set all-servers")
	}
	if len(allServers.Addresses) != 1 {
		t.Errorf("all-servers: expected 1 address member, got %d", len(allServers.Addresses))
	}
	if len(allServers.AddressSets) != 1 {
		t.Errorf("all-servers: expected 1 address-set member, got %d", len(allServers.AddressSets))
	}
	if len(allServers.AddressSets) > 0 && allServers.AddressSets[0] != "servers" {
		t.Errorf("all-servers nested set: expected 'servers', got %q", allServers.AddressSets[0])
	}
	expanded, err := ExpandAddressSet("all-servers", ab)
	if err != nil {
		t.Fatalf("expand error: %v", err)
	}
	if len(expanded) != 3 {
		t.Errorf("expected 3 expanded addresses, got %d: %v", len(expanded), expanded)
	}
	expandedMap := make(map[string]bool)
	for _, a := range expanded {
		expandedMap[a] = true
	}
	for _, expected := range []string{"srv1", "srv2", "srv3"} {
		if !expandedMap[expected] {
			t.Errorf("expanded set missing %q", expected)
		}
	}
	tree2 := &ConfigTree{}
	setCommands := []string{"set security address-book global address srv1 10.0.1.10/32", "set security address-book global address srv2 10.0.1.20/32", "set security address-book global address srv3 10.0.2.10/32", "set security address-book global address-set servers address srv1", "set security address-book global address-set servers address srv2", "set security address-book global address-set all-servers address srv3", "set security address-book global address-set all-servers address-set servers"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree2.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("compile set syntax: %v", err)
	}
	allServers2 := cfg2.Security.AddressBook.AddressSets["all-servers"]
	if allServers2 == nil {
		t.Fatal("missing all-servers from set syntax")
	}
	if len(allServers2.Addresses) != 1 || len(allServers2.AddressSets) != 1 {
		t.Errorf("all-servers from set syntax: addresses=%d sets=%d", len(allServers2.Addresses), len(allServers2.AddressSets))
	}
	expanded2, err := ExpandAddressSet("all-servers", cfg2.Security.AddressBook)
	if err != nil {
		t.Fatalf("expand set syntax error: %v", err)
	}
	if len(expanded2) != 3 {
		t.Errorf("expected 3 expanded from set syntax, got %d: %v", len(expanded2), expanded2)
	}
}

func TestNestedAddressSetCycleDetection(t *testing.T) {
	ab := &AddressBook{Addresses: map[string]*Address{"a1": {Name: "a1", Value: "10.0.0.1/32"}}, AddressSets: map[string]*AddressSet{"set-a": {Name: "set-a", Addresses: []string{"a1"}, AddressSets: []string{"set-b"}}, "set-b": {Name: "set-b", AddressSets: []string{"set-a"}}}}
	_, err := ExpandAddressSet("set-a", ab)
	if err == nil {
		t.Fatal("expected cycle detection error")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("expected cycle error, got: %v", err)
	}
}

func TestRoutingInstances(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set routing-instances Comcast-GigabitPro instance-type virtual-router", "set routing-instances Comcast-GigabitPro interface enp7s0.100", "set routing-instances Comcast-GigabitPro interface enp7s0.200", "set routing-instances Comcast-GigabitPro routing-options static route 0.0.0.0/0 next-hop 74.93.96.1", "set routing-instances Comcast-GigabitPro routing-options static route 0.0.0.0/0 preference 10", "set routing-instances ATT instance-type virtual-router", "set routing-instances ATT interface enp8s0", "set routing-instances ATT routing-options static route 0.0.0.0/0 next-hop 192.168.1.254", "set routing-instances ATT protocols bgp local-as 65001", "set routing-instances ATT protocols bgp group upstream peer-as 7018", "set routing-instances ATT protocols bgp group upstream neighbor 192.168.1.254"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	output := tree.Format()
	t.Logf("Formatted tree:\n%s", output)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig failed: %v", err)
	}
	if len(cfg.RoutingInstances) != 2 {
		t.Fatalf("expected 2 routing instances, got %d", len(cfg.RoutingInstances))
	}
	var comcast, att *RoutingInstanceConfig
	// Find the two instances (order not guaranteed).
	for _, ri := range cfg.RoutingInstances {
		switch ri.Name {
		case "Comcast-GigabitPro":
			comcast = ri
		case "ATT":
			att = ri
		}
	}
	if comcast == nil {
		t.Fatal("missing routing instance Comcast-GigabitPro")
	}
	if comcast.InstanceType != "virtual-router" {
		t.Errorf("Comcast instance-type: %s", comcast.InstanceType)
	}
	if len(comcast.Interfaces) != 2 {
		t.Errorf("Comcast interfaces: expected 2, got %d", len(comcast.Interfaces))
	}
	if len(comcast.StaticRoutes) != 1 {
		t.Fatalf("Comcast static routes: expected 1, got %d", len(comcast.StaticRoutes))
	}
	if len(comcast.StaticRoutes[0].NextHops) != 1 || comcast.StaticRoutes[0].NextHops[0].Address != "74.93.96.1" {
		t.Errorf("Comcast route next-hops: %v", comcast.StaticRoutes[0].NextHops)
	}
	if comcast.StaticRoutes[0].Preference != 10 {
		t.Errorf("Comcast route preference: %d", comcast.StaticRoutes[0].Preference)
	}
	if comcast.TableID < 100 {
		t.Errorf("Comcast table ID should be >= 100, got %d", comcast.TableID)
	}
	if att == nil {
		t.Fatal("missing routing instance ATT")
	}
	if len(att.Interfaces) != 1 || att.Interfaces[0] != "enp8s0" {
		t.Errorf("ATT interfaces: %v", att.Interfaces)
	}
	if len(att.StaticRoutes) != 1 {
		t.Fatalf("ATT static routes: expected 1, got %d", len(att.StaticRoutes))
	}
	if att.BGP == nil {
		t.Fatal("ATT BGP config is nil")
	}
	if att.BGP.LocalAS != 65001 {
		t.Errorf("ATT BGP local-as: %d", att.BGP.LocalAS)
	}
	if len(att.BGP.Neighbors) != 1 {
		t.Fatalf("ATT BGP neighbors: expected 1, got %d", len(att.BGP.Neighbors))
	}
	if att.BGP.Neighbors[0].Address != "192.168.1.254" || att.BGP.Neighbors[0].PeerAS != 7018 {
		t.Errorf("ATT BGP neighbor: addr=%s as=%d", att.BGP.Neighbors[0].Address, att.BGP.Neighbors[0].PeerAS)
	}
	hierInput := `routing-instances {
    Comcast-GigabitPro {
        instance-type virtual-router;
        interface enp7s0.100;
        routing-options {
            static {
                route 0.0.0.0/0 {
                    next-hop 74.93.96.1;
                }
            }
        }
    }
}`
	parser := NewParser(hierInput)
	hierTree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("hierarchical parse errors: %v", errs)
	}
	hierCfg, err := CompileConfig(hierTree)
	if err != nil {
		t.Fatalf("hierarchical compile error: %v", err)
	}
	if len(hierCfg.RoutingInstances) != 1 {
		t.Fatalf("hierarchical: expected 1 instance, got %d", len(hierCfg.RoutingInstances))
	}
	if hierCfg.RoutingInstances[0].Name != "Comcast-GigabitPro" {
		t.Errorf("hierarchical instance name: %s", hierCfg.RoutingInstances[0].Name)
	}
}

func TestForwardingInstanceType(t *testing.T) {
	input := `routing-instances {
    vpn-fwd {
        instance-type forwarding;
        routing-options {
            static {
                route 10.99.0.0/16 next-hop 10.0.40.1;
            }
        }
    }
    normal-vr {
        instance-type virtual-router;
        interface trust0;
        routing-options {
            static {
                route 192.168.0.0/16 next-hop 10.0.1.1;
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if len(cfg.RoutingInstances) != 2 {
		t.Fatalf("expected 2 routing instances, got %d", len(cfg.RoutingInstances))
	}
	var fwd, vr *RoutingInstanceConfig
	for _, ri := range cfg.RoutingInstances {
		switch ri.Name {
		case "vpn-fwd":
			fwd = ri
		case "normal-vr":
			vr = ri
		}
	}
	if fwd == nil {
		t.Fatal("missing vpn-fwd instance")
	}
	if fwd.InstanceType != "forwarding" {
		t.Errorf("vpn-fwd instance-type: got %q, want forwarding", fwd.InstanceType)
	}
	if len(fwd.StaticRoutes) != 1 {
		t.Fatalf("vpn-fwd static routes: expected 1, got %d", len(fwd.StaticRoutes))
	}
	if len(fwd.Interfaces) != 0 {
		t.Errorf("vpn-fwd interfaces: expected 0, got %d", len(fwd.Interfaces))
	}
	if vr == nil {
		t.Fatal("missing normal-vr instance")
	}
	if vr.InstanceType != "virtual-router" {
		t.Errorf("normal-vr instance-type: got %q, want virtual-router", vr.InstanceType)
	}
	if len(vr.Interfaces) != 1 {
		t.Errorf("normal-vr interfaces: expected 1, got %d", len(vr.Interfaces))
	}
	tree2 := &ConfigTree{}
	for _, cmd := range []string{"set routing-instances vpn-fwd instance-type forwarding", "set routing-instances vpn-fwd routing-options static route 10.99.0.0/16 next-hop 10.0.40.1", "set routing-instances normal-vr instance-type virtual-router", "set routing-instances normal-vr interface trust0"} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree2.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("set-command compile error: %v", err)
	}
	var fwd2 *RoutingInstanceConfig
	for _, ri := range cfg2.RoutingInstances {
		if ri.Name == "vpn-fwd" {
			fwd2 = ri
		}
	}
	if fwd2 == nil {
		t.Fatal("set syntax: missing vpn-fwd instance")
	}
	if fwd2.InstanceType != "forwarding" {
		t.Errorf("set syntax: vpn-fwd instance-type: got %q, want forwarding", fwd2.InstanceType)
	}
}

func TestRouterAdvertisement(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set protocols router-advertisement interface vlan100 managed-configuration", "set protocols router-advertisement interface vlan100 other-stateful-configuration", "set protocols router-advertisement interface vlan100 default-lifetime 1800", "set protocols router-advertisement interface vlan100 max-advertisement-interval 600", "set protocols router-advertisement interface vlan100 link-mtu 1500", "set protocols router-advertisement interface vlan100 reachable-time 30000", "set protocols router-advertisement interface vlan100 retransmit-timer 1000", "set protocols router-advertisement interface vlan100 prefix 2001:db8:1::/64 on-link", "set protocols router-advertisement interface vlan100 prefix 2001:db8:1::/64 autonomous", "set protocols router-advertisement interface vlan100 dns-server-address 2001:db8::53", "set protocols router-advertisement interface vlan100 dns-server-address 2001:db8::54", "set protocols router-advertisement interface vlan100 nat64prefix 64:ff9b::/96", "set protocols router-advertisement interface vlan200 prefix 2001:db8:2::/64"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig failed: %v", err)
	}
	if len(cfg.Protocols.RouterAdvertisement) != 2 {
		t.Fatalf("expected 2 RA interfaces, got %d", len(cfg.Protocols.RouterAdvertisement))
	}
	var ra100 *RAInterfaceConfig
	// Find vlan100 config.
	for _, ra := range cfg.Protocols.RouterAdvertisement {
		if ra.Interface == "vlan100" {
			ra100 = ra
		}
	}
	if ra100 == nil {
		t.Fatal("missing RA config for vlan100")
	}
	if !ra100.ManagedConfig {
		t.Error("vlan100: managed-configuration should be true")
	}
	if !ra100.OtherStateful {
		t.Error("vlan100: other-stateful should be true")
	}
	if ra100.DefaultLifetime != 1800 {
		t.Errorf("vlan100: default-lifetime = %d", ra100.DefaultLifetime)
	}
	if ra100.LinkMTU != 1500 {
		t.Errorf("vlan100: link-mtu = %d", ra100.LinkMTU)
	}
	// #4307 (I-2): reachable-time / retransmit-timer must survive compile.
	// Before the leaves existed both were silently dropped and stayed 0.
	if ra100.ReachableTime != 30000 {
		t.Errorf("vlan100: reachable-time = %d, want 30000", ra100.ReachableTime)
	}
	if ra100.RetransTimer != 1000 {
		t.Errorf("vlan100: retransmit-timer = %d, want 1000", ra100.RetransTimer)
	}
	if len(ra100.Prefixes) != 1 || ra100.Prefixes[0].Prefix != "2001:db8:1::/64" {
		t.Errorf("vlan100: prefixes = %+v", ra100.Prefixes)
	}
	if !ra100.Prefixes[0].OnLink || !ra100.Prefixes[0].Autonomous {
		t.Error("vlan100: prefix flags should default to on-link+autonomous")
	}
	if len(ra100.DNSServers) != 2 {
		t.Errorf("vlan100: dns-servers = %v", ra100.DNSServers)
	}
	if ra100.NAT64Prefix != "64:ff9b::/96" {
		t.Errorf("vlan100: nat64prefix = %s", ra100.NAT64Prefix)
	}
}

func TestRoutingInstanceWithZone(t *testing.T) {
	input := `
interfaces {
    enp7s0 {
        unit 0 {
            family inet {
                address 10.0.2.10/24;
            }
        }
    }
}
routing-instances {
    isp-a {
        instance-type virtual-router;
        interface enp7s0;
        routing-options {
            static {
                route 0.0.0.0/0 {
                    next-hop 10.0.2.1;
                }
            }
        }
    }
}
security {
    zones {
        security-zone untrust {
            interfaces {
                enp7s0;
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("expected 1 routing instance, got %d", len(cfg.RoutingInstances))
	}
	ri := cfg.RoutingInstances[0]
	if ri.Name != "isp-a" {
		t.Errorf("instance name: got %q, want %q", ri.Name, "isp-a")
	}
	if len(ri.Interfaces) != 1 || ri.Interfaces[0] != "enp7s0" {
		t.Errorf("instance interfaces: got %v, want [enp7s0]", ri.Interfaces)
	}
	// #3855: table id is the stable name-hash, not positional 100.
	if want := StableRoutingInstanceTableID(ri.Name); ri.TableID != want {
		t.Errorf("table ID: got %d, want stable %d", ri.TableID, want)
	}
	if len(ri.StaticRoutes) != 1 {
		t.Fatalf("expected 1 static route, got %d", len(ri.StaticRoutes))
	}
	if len(ri.StaticRoutes[0].NextHops) != 1 || ri.StaticRoutes[0].NextHops[0].Address != "10.0.2.1" {
		t.Errorf("next-hops: got %v, want [{10.0.2.1 }]", ri.StaticRoutes[0].NextHops)
	}
	zone, ok := cfg.Security.Zones["untrust"]
	if !ok {
		t.Fatal("missing untrust zone")
	}
	if len(zone.Interfaces) != 1 || zone.Interfaces[0] != "enp7s0" {
		t.Errorf("zone interfaces: got %v, want [enp7s0]", zone.Interfaces)
	}
}

func TestOSPFExportAndCost(t *testing.T) {
	input := `
protocols {
    ospf {
        router-id 10.0.0.1;
        export connected;
        export static;
        area 0.0.0.0 {
            interface trust0 {
                cost 100;
                passive;
            }
            interface dmz0;
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospf := cfg.Protocols.OSPF
	if ospf == nil {
		t.Fatal("OSPF config is nil")
	}
	if ospf.RouterID != "10.0.0.1" {
		t.Errorf("router-id: got %q, want %q", ospf.RouterID, "10.0.0.1")
	}
	if len(ospf.Export) != 2 {
		t.Fatalf("export count: got %d, want 2", len(ospf.Export))
	}
	if ospf.Export[0] != "connected" || ospf.Export[1] != "static" {
		t.Errorf("exports: got %v, want [connected static]", ospf.Export)
	}
	if len(ospf.Areas) != 1 {
		t.Fatalf("area count: got %d, want 1", len(ospf.Areas))
	}
	area := ospf.Areas[0]
	if len(area.Interfaces) != 2 {
		t.Fatalf("interface count: got %d, want 2", len(area.Interfaces))
	}
	if area.Interfaces[0].Cost != 100 {
		t.Errorf("trust0 cost: got %d, want 100", area.Interfaces[0].Cost)
	}
	if !area.Interfaces[0].Passive {
		t.Error("trust0 should be passive")
	}
}

func TestOSPFExportSetSyntax(t *testing.T) {
	cmds := []string{"set protocols ospf router-id 10.0.0.1", "set protocols ospf export connected", "set protocols ospf area 0.0.0.0 interface trust0 cost 100"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospf := cfg.Protocols.OSPF
	if ospf == nil {
		t.Fatal("OSPF config is nil")
	}
	if ospf.RouterID != "10.0.0.1" {
		t.Errorf("router-id: got %q, want %q", ospf.RouterID, "10.0.0.1")
	}
	if len(ospf.Export) != 1 || ospf.Export[0] != "connected" {
		t.Errorf("exports: got %v, want [connected]", ospf.Export)
	}
}

func TestBGPExportAndNeighborDetails(t *testing.T) {
	input := `protocols {
    bgp {
        local-as 65001;
        router-id 1.1.1.1;
        export connected;
        export static;
        group external {
            peer-as 65002;
            description upstream-peers;
            multihop 3;
            neighbor 10.0.2.1 {
                description specific-peer;
            }
            neighbor 10.0.3.1;
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if bgp.LocalAS != 65001 {
		t.Errorf("local-as: got %d, want 65001", bgp.LocalAS)
	}
	if len(bgp.Export) != 2 {
		t.Fatalf("exports: got %v, want [connected static]", bgp.Export)
	}
	if bgp.Export[0] != "connected" || bgp.Export[1] != "static" {
		t.Errorf("exports: got %v, want [connected static]", bgp.Export)
	}
	if len(bgp.Neighbors) != 2 {
		t.Fatalf("neighbors: got %d, want 2", len(bgp.Neighbors))
	}
	n0 := bgp.Neighbors[0]
	if n0.Address != "10.0.2.1" {
		t.Errorf("neighbor[0] address: got %q", n0.Address)
	}
	if n0.Description != "specific-peer" {
		t.Errorf("neighbor[0] description: got %q, want %q", n0.Description, "specific-peer")
	}
	if n0.MultihopTTL != 3 {
		t.Errorf("neighbor[0] multihop: got %d, want 3", n0.MultihopTTL)
	}
	n1 := bgp.Neighbors[1]
	if n1.Address != "10.0.3.1" {
		t.Errorf("neighbor[1] address: got %q", n1.Address)
	}
	if n1.Description != "upstream-peers" {
		t.Errorf("neighbor[1] description: got %q, want %q", n1.Description, "upstream-peers")
	}
	if n1.MultihopTTL != 3 {
		t.Errorf("neighbor[1] multihop: got %d, want 3", n1.MultihopTTL)
	}
}

func TestBGPExportSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp export connected", "set protocols bgp export static", "set protocols bgp group external peer-as 65002", "set protocols bgp group external neighbor 10.0.2.1"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if len(bgp.Export) != 2 {
		t.Fatalf("exports: got %v, want [connected static]", bgp.Export)
	}
	if len(bgp.Neighbors) != 1 || bgp.Neighbors[0].Address != "10.0.2.1" {
		t.Errorf("neighbors: got %v", bgp.Neighbors)
	}
}

func TestISISExport(t *testing.T) {
	input := `protocols {
    isis {
        net 49.0001.1921.6800.1001.00;
        level level-1-2;
        export connected;
        export static;
        interface trust0;
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	isis := cfg.Protocols.ISIS
	if isis == nil {
		t.Fatal("ISIS config is nil")
	}
	if len(isis.Export) != 2 {
		t.Fatalf("exports: got %v, want [connected static]", isis.Export)
	}
	if isis.Export[0] != "connected" || isis.Export[1] != "static" {
		t.Errorf("exports: got %v", isis.Export)
	}
}

func TestBGPGroupExportFamily(t *testing.T) {
	tree := &ConfigTree{}
	// my-export-policy must be a defined policy-statement: a BGP
	// group/neighbor export renders `route-map <name> out`, which the
	// #2144 commit gate requires to resolve (a dangling route-map name
	// fails open to permit-all in FRR).
	for _, cmd := range []string{"set protocols bgp local-as 64701", "set protocols bgp group ebgp-peer family inet unicast", "set protocols bgp group ebgp-peer family inet6 unicast", "set protocols bgp group ebgp-peer export my-export-policy", "set protocols bgp group ebgp-peer peer-as 65002", "set protocols bgp group ebgp-peer neighbor 10.1.0.1", "set protocols bgp group ebgp-peer neighbor 10.2.0.1", "set policy-options policy-statement my-export-policy term t1 then accept"} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if bgp.LocalAS != 64701 {
		t.Errorf("LocalAS = %d, want 64701", bgp.LocalAS)
	}
	if len(bgp.Neighbors) != 2 {
		t.Fatalf("got %d neighbors, want 2", len(bgp.Neighbors))
	}
	n := bgp.Neighbors[0]
	if n.Address != "10.1.0.1" {
		t.Errorf("neighbor 0 address = %q, want 10.1.0.1", n.Address)
	}
	if !n.FamilyInet {
		t.Error("neighbor should have FamilyInet=true")
	}
	// #2454: a bare IPv4 neighbor in a dual-stack group inherits ONLY the
	// inet family. Inheriting FamilyInet6 made the renderer emit
	// `neighbor 10.1.0.1 activate` under `address-family ipv6 unicast`,
	// which is invalid without RFC 5549 extended-nexthop. This assertion is
	// a fail-on-revert anchor for the address-version gate.
	if n.FamilyInet6 {
		t.Error("IPv4 neighbor must NOT inherit group FamilyInet6 (#2454)")
	}
	if len(n.Export) != 1 || n.Export[0] != "my-export-policy" {
		t.Errorf("neighbor export = %v, want [my-export-policy]", n.Export)
	}
}

func TestRoutingOptionsExtended(t *testing.T) {
	// load-balancing-policy must be a defined policy-statement: the #2144
	// commit gate rejects a forwarding-table export naming a missing policy
	// (resolveECMP silently returns 0 max-paths, disabling ECMP).
	input := `policy-options {
    policy-statement load-balancing-policy {
        term t1 {
            then {
                load-balance per-packet;
                accept;
            }
        }
    }
}
routing-options {
    autonomous-system 64701;
    rib inet6.0 {
        static {
            route ::/0 next-hop 2001:db8::1;
        }
    }
    static {
        route 0.0.0.0/0 next-hop 10.0.0.1;
        route 10.1.0.0/16 next-hop 10.0.1.1;
    }
    forwarding-table {
        export load-balancing-policy;
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ro := cfg.RoutingOptions
	if ro.AutonomousSystem != 64701 {
		t.Errorf("AS = %d, want 64701", ro.AutonomousSystem)
	}
	if ro.ForwardingTableExport != "load-balancing-policy" {
		t.Errorf("forwarding-table export = %q, want load-balancing-policy", ro.ForwardingTableExport)
	}
	if len(ro.StaticRoutes) != 2 {
		t.Fatalf("got %d static routes, want 2", len(ro.StaticRoutes))
	}
	if len(ro.Inet6StaticRoutes) != 1 {
		t.Fatalf("got %d inet6 static routes, want 1", len(ro.Inet6StaticRoutes))
	}
	v6 := ro.Inet6StaticRoutes[0]
	if v6.Destination != "::/0" {
		t.Errorf("inet6 route dest = %q, want ::/0", v6.Destination)
	}
	if len(v6.NextHops) != 1 || v6.NextHops[0].Address != "2001:db8::1" {
		t.Errorf("inet6 route next-hop = %v, want 2001:db8::1", v6.NextHops)
	}
}

func TestRoutingInstanceInterfaceRoutesRibGroup(t *testing.T) {
	input := `routing-instances {
    ATT {
        instance-type virtual-router;
        routing-options {
            interface-routes {
                rib-group {
                    inet Other-ISPS;
                    inet6 Other-ISP6;
                }
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("RoutingInstances = %d, want 1", len(cfg.RoutingInstances))
	}
	ri := cfg.RoutingInstances[0]
	if ri.InterfaceRoutesRibGroup != "Other-ISPS" {
		t.Errorf("InterfaceRoutesRibGroup = %q, want Other-ISPS", ri.InterfaceRoutesRibGroup)
	}
	if ri.InterfaceRoutesRibGroupV6 != "Other-ISP6" {
		t.Errorf("InterfaceRoutesRibGroupV6 = %q, want Other-ISP6", ri.InterfaceRoutesRibGroupV6)
	}
}

func TestOSPFAuthSetSyntax(t *testing.T) {
	cmds := []string{"set protocols ospf area 0.0.0.0 interface trust0 authentication md5 1 key secret123", "set protocols ospf area 0.0.0.0 interface dmz0 authentication simple-password plainpw"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospf := cfg.Protocols.OSPF
	if ospf == nil {
		t.Fatal("OSPF config is nil")
	}
	if len(ospf.Areas) != 1 {
		t.Fatalf("area count: got %d, want 1", len(ospf.Areas))
	}
	ifaces := ospf.Areas[0].Interfaces
	if len(ifaces) != 2 {
		t.Fatalf("interface count: got %d, want 2", len(ifaces))
	}
	if ifaces[0].AuthType != "md5" {
		t.Errorf("trust0 AuthType: got %q, want md5", ifaces[0].AuthType)
	}
	if ifaces[0].AuthKeyID != 1 {
		t.Errorf("trust0 AuthKeyID: got %d, want 1", ifaces[0].AuthKeyID)
	}
	if ifaces[0].AuthKey != "secret123" {
		t.Errorf("trust0 AuthKey: got %q, want secret123", ifaces[0].AuthKey)
	}
	if ifaces[1].AuthType != "simple" {
		t.Errorf("dmz0 AuthType: got %q, want simple", ifaces[1].AuthType)
	}
	if ifaces[1].AuthKey != "plainpw" {
		t.Errorf("dmz0 AuthKey: got %q, want plainpw", ifaces[1].AuthKey)
	}
}

func TestBGPAuthSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp group external peer-as 65002", "set protocols bgp group external authentication-key bgpSecret", "set protocols bgp group external neighbor 10.0.2.1"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("neighbors: got %d, want 1", len(bgp.Neighbors))
	}
	if bgp.Neighbors[0].AuthPassword != "bgpSecret" {
		t.Errorf("AuthPassword: got %q, want bgpSecret", bgp.Neighbors[0].AuthPassword)
	}
}

func TestBGPNeighborAuthOverride(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp group external peer-as 65002", "set protocols bgp group external authentication-key groupKey", "set protocols bgp group external neighbor 10.0.2.1 authentication-key neighborKey", "set protocols bgp group external neighbor 10.0.3.1"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if len(bgp.Neighbors) != 2 {
		t.Fatalf("neighbors: got %d, want 2", len(bgp.Neighbors))
	}
	if bgp.Neighbors[0].AuthPassword != "neighborKey" {
		t.Errorf("neighbor[0] AuthPassword: got %q, want neighborKey", bgp.Neighbors[0].AuthPassword)
	}
	if bgp.Neighbors[1].AuthPassword != "groupKey" {
		t.Errorf("neighbor[1] AuthPassword: got %q, want groupKey", bgp.Neighbors[1].AuthPassword)
	}
}

// TestFRRAuthValueWhitespaceRejected is the #2889 fail-on-revert gate. A BGP
// neighbor password or an OSPF/RIP/IS-IS authentication key containing a
// space cannot be expressed as a single FRR/vtysh token (FRR's command lexer
// splits on whitespace and has no quoting), so it must be rejected at commit
// rather than rendered into a broken frr.conf line. Reverting the gate (i.e.
// dropping validateFRRAuthValuesStrict / emitting the value unquoted) makes
// the "want commit error" subtests compile cleanly and turns this RED.
func TestFRRAuthValueWhitespaceRejected(t *testing.T) {
	t.Run("bgp-password-with-space-rejected", func(t *testing.T) {
		_, err := compileSet(t, []string{
			"set protocols bgp local-as 65001",
			"set protocols bgp group external peer-as 65002",
			`set protocols bgp group external neighbor 10.0.2.1 authentication-key "my secret pass"`,
		})
		if err == nil {
			t.Fatal("expected commit rejection of a BGP password containing a space, got nil")
		}
		if !strings.Contains(err.Error(), "neighbor 10.0.2.1 authentication-key") {
			t.Errorf("error should name the offending field, got: %v", err)
		}
	})

	t.Run("bgp-password-with-tab-rejected", func(t *testing.T) {
		_, err := compileSet(t, []string{
			"set protocols bgp local-as 65001",
			"set protocols bgp group external peer-as 65002",
			"set protocols bgp group external neighbor 10.0.2.1 authentication-key \"tab\tpass\"",
		})
		if err == nil {
			t.Fatal("expected commit rejection of a BGP password containing a tab, got nil")
		}
	})

	t.Run("ospf-key-with-space-rejected", func(t *testing.T) {
		_, err := compileSet(t, []string{
			"set protocols ospf area 0.0.0.0 interface trust0 authentication md5 1 key \"two words\"",
		})
		if err == nil {
			t.Fatal("expected commit rejection of an OSPF auth key containing a space, got nil")
		}
		if !strings.Contains(err.Error(), "authentication-key") {
			t.Errorf("error should name the auth field, got: %v", err)
		}
	})

	t.Run("spaceless-password-accepted", func(t *testing.T) {
		// A space-less secret is unchanged — it must still compile cleanly.
		_, err := compileSet(t, []string{
			"set protocols bgp local-as 65001",
			"set protocols bgp group external peer-as 65002",
			`set protocols bgp group external neighbor 10.0.2.1 authentication-key "s3cr3t!pass.word@1"`,
		})
		if err != nil {
			t.Fatalf("space-less BGP password should compile, got: %v", err)
		}
	})
}

func TestOSPFBFDSetSyntax(t *testing.T) {
	cmds := []string{"set protocols ospf area 0.0.0.0 interface trust0 bfd-liveness-detection minimum-interval 100"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospf := cfg.Protocols.OSPF
	if ospf == nil {
		t.Fatal("OSPF config is nil")
	}
	iface := ospf.Areas[0].Interfaces[0]
	if !iface.BFD {
		t.Error("OSPF interface BFD should be true")
	}
}

// TestOSPFv3BFDHierarchical verifies the hierarchical AST shape carries
// bfd-liveness-detection (minimum-interval + multiplier) into the compiled
// OSPFv3Interface (#2474 — OSPFv3 BFD parity with OSPFv2).
func TestOSPFv3BFDHierarchical(t *testing.T) {
	input := `
protocols {
    ospf3 {
        router-id 10.0.0.1;
        area 0.0.0.0 {
            interface trust0 {
                cost 5;
                bfd-liveness-detection {
                    minimum-interval 250;
                    multiplier 4;
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospf3 := cfg.Protocols.OSPFv3
	if ospf3 == nil {
		t.Fatal("OSPFv3 config is nil")
	}
	if len(ospf3.Areas) != 1 || len(ospf3.Areas[0].Interfaces) != 1 {
		t.Fatalf("unexpected area/interface count: %+v", ospf3.Areas)
	}
	iface := ospf3.Areas[0].Interfaces[0]
	if !iface.BFD {
		t.Error("OSPFv3 interface BFD should be true")
	}
	if iface.BFDInterval != 250 {
		t.Errorf("OSPFv3 BFDInterval: got %d, want 250", iface.BFDInterval)
	}
	if iface.BFDMultiplier != 4 {
		t.Errorf("OSPFv3 BFDMultiplier: got %d, want 4", iface.BFDMultiplier)
	}
}

// TestOSPFv3BFDSetSyntax verifies the flat-set AST shape (ParseSetCommand +
// SetPath) carries bfd-liveness-detection into the compiled OSPFv3Interface.
func TestOSPFv3BFDSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols ospf3 area 0.0.0.0 interface trust0 cost 5",
		"set protocols ospf3 area 0.0.0.0 interface trust0 bfd-liveness-detection minimum-interval 300",
		"set protocols ospf3 area 0.0.0.0 interface trust0 bfd-liveness-detection multiplier 3",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospf3 := cfg.Protocols.OSPFv3
	if ospf3 == nil {
		t.Fatal("OSPFv3 config is nil")
	}
	iface := ospf3.Areas[0].Interfaces[0]
	if !iface.BFD {
		t.Error("OSPFv3 interface BFD should be true")
	}
	if iface.BFDInterval != 300 {
		t.Errorf("OSPFv3 BFDInterval: got %d, want 300", iface.BFDInterval)
	}
	if iface.BFDMultiplier != 3 {
		t.Errorf("OSPFv3 BFDMultiplier: got %d, want 3", iface.BFDMultiplier)
	}
}

func TestBGPBFDSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp group external peer-as 65002", "set protocols bgp group external bfd-liveness-detection minimum-interval 200", "set protocols bgp group external neighbor 10.0.2.1", "set protocols bgp group external neighbor 10.0.3.1 bfd-liveness-detection minimum-interval 100"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if len(bgp.Neighbors) != 2 {
		t.Fatalf("neighbors: got %d, want 2", len(bgp.Neighbors))
	}
	if !bgp.Neighbors[0].BFD {
		t.Error("neighbor[0] should have BFD enabled (inherited)")
	}
	if bgp.Neighbors[0].BFDInterval != 200 {
		t.Errorf("neighbor[0] BFDInterval: got %d, want 200", bgp.Neighbors[0].BFDInterval)
	}
	if !bgp.Neighbors[1].BFD {
		t.Error("neighbor[1] should have BFD enabled")
	}
	if bgp.Neighbors[1].BFDInterval != 100 {
		t.Errorf("neighbor[1] BFDInterval: got %d, want 100", bgp.Neighbors[1].BFDInterval)
	}
}

func TestOSPFAreaTypeSetSyntax(t *testing.T) {
	cmds := []string{"set protocols ospf area 0.0.0.0 interface trust0", "set protocols ospf area 0.0.0.1 interface dmz0", "set protocols ospf area 0.0.0.1 area-type stub", "set protocols ospf area 0.0.0.2 interface untrust0", "set protocols ospf area 0.0.0.2 area-type nssa", "set protocols ospf area 0.0.0.3 interface tunnel0", "set protocols ospf area 0.0.0.3 area-type stub no-summaries"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospf := cfg.Protocols.OSPF
	if ospf == nil {
		t.Fatal("OSPF config is nil")
	}
	if len(ospf.Areas) != 4 {
		t.Fatalf("area count: got %d, want 4", len(ospf.Areas))
	}
	if ospf.Areas[0].AreaType != "" {
		t.Errorf("area 0 should have no type, got %q", ospf.Areas[0].AreaType)
	}
	if ospf.Areas[1].AreaType != "stub" {
		t.Errorf("area 1 AreaType: got %q, want stub", ospf.Areas[1].AreaType)
	}
	if ospf.Areas[1].NoSummary {
		t.Error("area 1 should not have NoSummary")
	}
	if ospf.Areas[2].AreaType != "nssa" {
		t.Errorf("area 2 AreaType: got %q, want nssa", ospf.Areas[2].AreaType)
	}
	if ospf.Areas[3].AreaType != "stub" {
		t.Errorf("area 3 AreaType: got %q, want stub", ospf.Areas[3].AreaType)
	}
	if !ospf.Areas[3].NoSummary {
		t.Error("area 3 should have NoSummary")
	}
}

func TestBGPRouteReflectorSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp cluster-id 10.0.0.1", "set protocols bgp group ibgp peer-as 65001", "set protocols bgp group ibgp neighbor 10.0.0.2 route-reflector-client", "set protocols bgp group ibgp neighbor 10.0.0.3"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if bgp.ClusterID != "10.0.0.1" {
		t.Errorf("ClusterID: got %q, want 10.0.0.1", bgp.ClusterID)
	}
	if len(bgp.Neighbors) != 2 {
		t.Fatalf("neighbor count: got %d, want 2", len(bgp.Neighbors))
	}
	if !bgp.Neighbors[0].RouteReflectorClient {
		t.Error("neighbor 10.0.0.2 should be route-reflector-client")
	}
	if bgp.Neighbors[1].RouteReflectorClient {
		t.Error("neighbor 10.0.0.3 should not be route-reflector-client")
	}
}

func TestISISAuthSetSyntax(t *testing.T) {
	cmds := []string{"set protocols isis net 49.0001.0100.0000.0001.00", "set protocols isis authentication-type md5", "set protocols isis authentication-key isisSecret", "set protocols isis interface trust0"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	isis := cfg.Protocols.ISIS
	if isis == nil {
		t.Fatal("ISIS config is nil")
	}
	if isis.AuthType != "md5" {
		t.Errorf("AuthType: got %q, want md5", isis.AuthType)
	}
	if isis.AuthKey != "isisSecret" {
		t.Errorf("AuthKey: got %q, want isisSecret", isis.AuthKey)
	}
}

func TestISISInterfaceAuthSetSyntax(t *testing.T) {
	cmds := []string{"set protocols isis net 49.0001.0100.0000.0001.00", "set protocols isis interface trust0 authentication-type md5", "set protocols isis interface trust0 authentication-key ifaceSecret", "set protocols isis interface trust0 metric 100", "set protocols isis interface dmz0 authentication-type simple", "set protocols isis interface dmz0 authentication-key plainpw"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	isis := cfg.Protocols.ISIS
	if isis == nil {
		t.Fatal("ISIS config is nil")
	}
	if len(isis.Interfaces) != 2 {
		t.Fatalf("interfaces: got %d, want 2", len(isis.Interfaces))
	}
	trust := isis.Interfaces[0]
	if trust.AuthType != "md5" {
		t.Errorf("trust0 AuthType: got %q, want md5", trust.AuthType)
	}
	if trust.AuthKey != "ifaceSecret" {
		t.Errorf("trust0 AuthKey: got %q, want ifaceSecret", trust.AuthKey)
	}
	if trust.Metric != 100 {
		t.Errorf("trust0 Metric: got %d, want 100", trust.Metric)
	}
	dmz := isis.Interfaces[1]
	if dmz.AuthType != "simple" {
		t.Errorf("dmz0 AuthType: got %q, want simple", dmz.AuthType)
	}
	if dmz.AuthKey != "plainpw" {
		t.Errorf("dmz0 AuthKey: got %q, want plainpw", dmz.AuthKey)
	}
}

func TestISISWideMetricsOverloadSetSyntax(t *testing.T) {
	cmds := []string{"set protocols isis net 49.0001.0100.0000.0001.00", "set protocols isis wide-metrics-only", "set protocols isis overload", "set protocols isis interface trust0"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	isis := cfg.Protocols.ISIS
	if isis == nil {
		t.Fatal("ISIS config is nil")
	}
	if !isis.WideMetricsOnly {
		t.Error("WideMetricsOnly: got false, want true")
	}
	if !isis.Overload {
		t.Error("Overload: got false, want true")
	}
}

// #9408: this test USED to author `reference-bandwidth 10g` and then assert
// only that `ospf != nil`. It exercised exactly the spelling that was being
// silently dropped and said nothing about whether the value survived — the
// tree's own coverage concealed the defect it walked through. It now asserts
// the compiled value, in the unit the compiled field names.
func TestOSPFReferenceBandwidthSetSyntax(t *testing.T) {
	compileRefBw := func(t *testing.T, token string) (*Config, error) {
		t.Helper()
		tree := &ConfigTree{}
		for _, cmd := range []string{
			"set protocols ospf reference-bandwidth " + token,
			"set protocols ospf area 0.0.0.0 interface trust0",
		} {
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%v): %v", path, err)
			}
		}
		return CompileConfig(tree)
	}

	// The SUFFIX form. Junos units are bits/s, so 10g is 10 Gbps, which is
	// 10000 Mbps in FRR's `auto-cost reference-bandwidth`.
	cfg, err := compileRefBw(t, "10g")
	if err != nil {
		t.Fatalf("CompileConfig(10g): %v", err)
	}
	ospf := cfg.Protocols.OSPF
	if ospf == nil {
		t.Fatal("OSPF config is nil")
	}
	if ospf.ReferenceBandwidthMbps != 10000 {
		t.Errorf("ReferenceBandwidthMbps for 10g: got %d, want 10000 (10 Gbps in FRR's Mbps unit)", ospf.ReferenceBandwidthMbps)
	}

	// The PLAIN-INTEGER form naming the same bandwidth. Junos units are
	// bits/s, so 10 Gbps is 10000000000 — NOT 10000, which names 10 kbps and
	// is rejected by the #9408 gate (covered in
	// TestOSPFReferenceBandwidth9408).
	cfg2, err := compileRefBw(t, "10000000000")
	if err != nil {
		t.Fatalf("CompileConfig(10000000000): %v", err)
	}
	if cfg2.Protocols.OSPF.ReferenceBandwidthMbps != 10000 {
		t.Errorf("ReferenceBandwidthMbps for 10000000000: got %d, want 10000", cfg2.Protocols.OSPF.ReferenceBandwidthMbps)
	}

	// The two spellings name ONE bandwidth and must compile identically.
	if ospf.ReferenceBandwidthMbps != cfg2.Protocols.OSPF.ReferenceBandwidthMbps {
		t.Errorf("suffix and plain-integer spellings of 10 Gbps disagree: %d vs %d",
			ospf.ReferenceBandwidthMbps, cfg2.Protocols.OSPF.ReferenceBandwidthMbps)
	}
}

func TestOSPFPassiveDefaultSetSyntax(t *testing.T) {
	cmds := []string{"set protocols ospf passive", "set protocols ospf area 0.0.0.0 interface trust0 no-passive", "set protocols ospf area 0.0.0.0 interface dmz0"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospf := cfg.Protocols.OSPF
	if ospf == nil {
		t.Fatal("OSPF config is nil")
	}
	if !ospf.PassiveDefault {
		t.Error("PassiveDefault should be true")
	}
	if len(ospf.Areas) != 1 {
		t.Fatalf("expected 1 area, got %d", len(ospf.Areas))
	}
	area := ospf.Areas[0]
	if len(area.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(area.Interfaces))
	}
	var trust, dmz *OSPFInterface
	// trust0 should have NoPassive=true.
	for _, iface := range area.Interfaces {
		switch iface.Name {
		case "trust0":
			trust = iface
		case "dmz0":
			dmz = iface
		}
	}
	if trust == nil || !trust.NoPassive {
		t.Error("trust0 should have NoPassive=true")
	}
	if dmz == nil || dmz.NoPassive {
		t.Error("dmz0 should NOT have NoPassive set")
	}
}

func TestOSPFNetworkTypeSetSyntax(t *testing.T) {
	cmds := []string{"set protocols ospf area 0.0.0.0 interface trust0 interface-type point-to-point", "set protocols ospf area 0.0.0.0 interface dmz0"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospf := cfg.Protocols.OSPF
	if ospf == nil {
		t.Fatal("OSPF config is nil")
	}
	area := ospf.Areas[0]
	var trust, dmz *OSPFInterface
	for _, iface := range area.Interfaces {
		switch iface.Name {
		case "trust0":
			trust = iface
		case "dmz0":
			dmz = iface
		}
	}
	if trust == nil || trust.NetworkType != "point-to-point" {
		t.Errorf("trust0 NetworkType: got %q, want \"point-to-point\"", trust.NetworkType)
	}
	if dmz == nil || dmz.NetworkType != "" {
		t.Errorf("dmz0 NetworkType: got %q, want \"\"", dmz.NetworkType)
	}
}

func TestBGPGracefulRestartSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp graceful-restart", "set protocols bgp group external peer-as 65002", "set protocols bgp group external neighbor 10.0.0.2"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if !bgp.GracefulRestart {
		t.Error("GracefulRestart should be true")
	}
}

func TestBGPMultipathSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp multipath", "set protocols bgp multipath multiple-as", "set protocols bgp group external peer-as 65002", "set protocols bgp group external neighbor 10.0.0.2"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if bgp.Multipath != 64 {
		t.Errorf("Multipath = %d, want 64", bgp.Multipath)
	}
	if !bgp.MultipathMultipleAS {
		t.Error("MultipathMultipleAS should be true")
	}
	if bgp.MultipathIBGP {
		t.Error("MultipathIBGP should default false without `multipath ibgp`")
	}
}

// TestBGPMultipathIBGPSetSyntax pins the #2978 parse path: `set protocols bgp
// multipath ibgp` compiles to BGPConfig.MultipathIBGP=true (and still sets the
// generic Multipath count), so the renderer can emit FRR `maximum-paths ibgp`.
func TestBGPMultipathIBGPSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp multipath ibgp",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external neighbor 10.0.0.2",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if bgp.Multipath != 64 {
		t.Errorf("Multipath = %d, want 64", bgp.Multipath)
	}
	if !bgp.MultipathIBGP {
		t.Error("MultipathIBGP should be true with `multipath ibgp`")
	}
}

func TestBGPDefaultOriginateSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp group external peer-as 65002", "set protocols bgp group external default-originate", "set protocols bgp group external family inet", "set protocols bgp group external neighbor 10.0.0.2"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	if !bgp.Neighbors[0].DefaultOriginate {
		t.Error("DefaultOriginate should be true (inherited from group)")
	}
}

func TestBGPDefaultOriginatePerNeighborSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp group external peer-as 65002", "set protocols bgp group external family inet", "set protocols bgp group external neighbor 10.0.0.2 default-originate"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	if !bgp.Neighbors[0].DefaultOriginate {
		t.Error("DefaultOriginate should be true (per-neighbor override)")
	}
}

func TestBGPLogUpdownSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp log-updown", "set protocols bgp group external peer-as 65002", "set protocols bgp group external neighbor 10.0.0.2"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if !bgp.LogNeighborChanges {
		t.Error("LogNeighborChanges should be true")
	}
}

func TestBGPAllowASInSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp group external peer-as 65002", "set protocols bgp group external loops 2", "set protocols bgp group external family inet", "set protocols bgp group external neighbor 10.0.0.2"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	if bgp.Neighbors[0].AllowASIn != 2 {
		t.Errorf("AllowASIn = %d, want 2", bgp.Neighbors[0].AllowASIn)
	}
}

func TestBGPAllowASInPerNeighborSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp group external peer-as 65002", "set protocols bgp group external family inet", "set protocols bgp group external neighbor 10.0.0.2 loops 3"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	if bgp.Neighbors[0].AllowASIn != 3 {
		t.Errorf("AllowASIn = %d, want 3", bgp.Neighbors[0].AllowASIn)
	}
}

func TestBGPRemovePrivateASSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp group external peer-as 65002", "set protocols bgp group external remove-private", "set protocols bgp group external family inet", "set protocols bgp group external neighbor 10.0.0.2"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	if !bgp.Neighbors[0].RemovePrivateAS {
		t.Error("RemovePrivateAS should be true (inherited from group)")
	}
}

func TestBGPRemovePrivateASPerNeighborSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp group external peer-as 65002", "set protocols bgp group external family inet", "set protocols bgp group external neighbor 10.0.0.2 remove-private"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	if !bgp.Neighbors[0].RemovePrivateAS {
		t.Error("RemovePrivateAS should be true (per-neighbor override)")
	}
}

func TestOSPFv3SetSyntax(t *testing.T) {
	cmds := []string{"set protocols ospf3 router-id 10.0.0.1", "set protocols ospf3 area 0.0.0.0 interface trust0 passive", "set protocols ospf3 area 0.0.0.0 interface trust0 cost 10", "set protocols ospf3 area 0.0.0.0 interface dmz0 cost 1", "set protocols ospf3 export connected"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospfv3 := cfg.Protocols.OSPFv3
	if ospfv3 == nil {
		t.Fatal("OSPFv3 config is nil")
	}
	if ospfv3.RouterID != "10.0.0.1" {
		t.Errorf("RouterID = %q, want %q", ospfv3.RouterID, "10.0.0.1")
	}
	if len(ospfv3.Areas) != 1 {
		t.Fatalf("expected 1 area, got %d", len(ospfv3.Areas))
	}
	area := ospfv3.Areas[0]
	if area.ID != "0.0.0.0" {
		t.Errorf("area ID = %q, want %q", area.ID, "0.0.0.0")
	}
	if len(area.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(area.Interfaces))
	}
	trust := area.Interfaces[0]
	if trust.Name != "trust0" {
		t.Errorf("iface name = %q, want %q", trust.Name, "trust0")
	}
	if !trust.Passive {
		t.Error("trust0 should be passive")
	}
	if trust.Cost != 10 {
		t.Errorf("trust0 cost = %d, want 10", trust.Cost)
	}
	dmz := area.Interfaces[1]
	if dmz.Name != "dmz0" {
		t.Errorf("iface name = %q, want %q", dmz.Name, "dmz0")
	}
	if dmz.Passive {
		t.Error("dmz0 should not be passive")
	}
	if dmz.Cost != 1 {
		t.Errorf("dmz0 cost = %d, want 1", dmz.Cost)
	}
	if len(ospfv3.Export) != 1 || ospfv3.Export[0] != "connected" {
		t.Errorf("Export = %v, want [connected]", ospfv3.Export)
	}
}

func TestGRETunnelKeepaliveSetSyntax(t *testing.T) {
	cmds := []string{"set interfaces gre0 tunnel source 10.0.0.1", "set interfaces gre0 tunnel destination 10.0.0.2", "set interfaces gre0 tunnel keepalive 10", "set interfaces gre0 tunnel keepalive-retry 5", "set interfaces gre0 tunnel key 100", "set interfaces gre0 unit 0 family inet address 10.10.10.1/30"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["gre0"]
	if ifc == nil {
		t.Fatal("gre0 interface not found")
	}
	tc := ifc.Tunnel
	if tc == nil {
		t.Fatal("tunnel config is nil")
	}
	if tc.Source != "10.0.0.1" {
		t.Errorf("Source = %q, want 10.0.0.1", tc.Source)
	}
	if tc.Destination != "10.0.0.2" {
		t.Errorf("Destination = %q, want 10.0.0.2", tc.Destination)
	}
	if tc.Keepalive != 10 {
		t.Errorf("Keepalive = %d, want 10", tc.Keepalive)
	}
	if tc.KeepaliveRetry != 5 {
		t.Errorf("KeepaliveRetry = %d, want 5", tc.KeepaliveRetry)
	}
	if tc.Key != 100 {
		t.Errorf("Key = %d, want 100", tc.Key)
	}
}

func TestBGPDampingSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp damping", "set protocols bgp damping half-life 10", "set protocols bgp damping reuse 500", "set protocols bgp damping suppress 3000", "set protocols bgp damping max-suppress 45", "set protocols bgp group ext peer-as 65002", "set protocols bgp group ext neighbor 10.0.2.1"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if !bgp.Dampening {
		t.Error("Dampening not enabled")
	}
	if bgp.DampeningHalfLife != 10 {
		t.Errorf("DampeningHalfLife = %d, want 10", bgp.DampeningHalfLife)
	}
	if bgp.DampeningReuse != 500 {
		t.Errorf("DampeningReuse = %d, want 500", bgp.DampeningReuse)
	}
	if bgp.DampeningSuppress != 3000 {
		t.Errorf("DampeningSuppress = %d, want 3000", bgp.DampeningSuppress)
	}
	if bgp.DampeningMaxSuppress != 45 {
		t.Errorf("DampeningMaxSuppress = %d, want 45", bgp.DampeningMaxSuppress)
	}
}

func TestBGPPrefixLimitSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp group external peer-as 65002", "set protocols bgp group external family inet unicast prefix-limit maximum 1000", "set protocols bgp group external family inet6 unicast prefix-limit maximum 500", "set protocols bgp group external neighbor 10.0.0.2"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	n := bgp.Neighbors[0]
	if !n.FamilyInet {
		t.Error("FamilyInet should be true")
	}
	// #2454: 10.0.0.2 is an IPv4 address, so it must NOT inherit the group's
	// inet6 family flag (that would activate it under ipv6 unicast, invalid
	// without RFC 5549). The inherited PrefixLimitInet6 below stays populated
	// but is inert because FamilyInet6 is false.
	if n.FamilyInet6 {
		t.Error("IPv4 neighbor must NOT inherit group FamilyInet6 (#2454)")
	}
	if n.PrefixLimitInet != 1000 {
		t.Errorf("PrefixLimitInet = %d, want 1000", n.PrefixLimitInet)
	}
	if n.PrefixLimitInet6 != 500 {
		t.Errorf("PrefixLimitInet6 = %d, want 500", n.PrefixLimitInet6)
	}
}

func TestBGPPrefixLimitPerNeighborSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp group external peer-as 65002", "set protocols bgp group external family inet unicast", "set protocols bgp group external neighbor 10.0.0.2 family inet unicast prefix-limit maximum 2000"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	n := bgp.Neighbors[0]
	if n.PrefixLimitInet != 2000 {
		t.Errorf("PrefixLimitInet = %d, want 2000", n.PrefixLimitInet)
	}
}

func TestOSPFVirtualLinkSetSyntax(t *testing.T) {
	cmds := []string{"set protocols ospf area 0.0.0.1 interface trust0", "set protocols ospf area 0.0.0.1 virtual-link 10.0.0.2"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospf := cfg.Protocols.OSPF
	if ospf == nil {
		t.Fatal("OSPF config is nil")
	}
	if len(ospf.Areas) != 1 {
		t.Fatalf("expected 1 area, got %d", len(ospf.Areas))
	}
	area := ospf.Areas[0]
	if len(area.VirtualLinks) != 1 {
		t.Fatalf("expected 1 virtual-link, got %d", len(area.VirtualLinks))
	}
	vl := area.VirtualLinks[0]
	if vl.NeighborID != "10.0.0.2" {
		t.Errorf("NeighborID = %q, want 10.0.0.2", vl.NeighborID)
	}
	if vl.TransitArea != "0.0.0.1" {
		t.Errorf("TransitArea = %q, want 0.0.0.1", vl.TransitArea)
	}
}

func TestOSPFVirtualLinkWithTransitAreaSetSyntax(t *testing.T) {
	cmds := []string{"set protocols ospf area 0.0.0.1 interface trust0", "set protocols ospf area 0.0.0.1 virtual-link 10.0.0.2 transit-area 0.0.0.3"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospf := cfg.Protocols.OSPF
	if ospf == nil {
		t.Fatal("OSPF config is nil")
	}
	area := ospf.Areas[0]
	if len(area.VirtualLinks) != 1 {
		t.Fatalf("expected 1 virtual-link, got %d", len(area.VirtualLinks))
	}
	vl := area.VirtualLinks[0]
	if vl.NeighborID != "10.0.0.2" {
		t.Errorf("NeighborID = %q, want 10.0.0.2", vl.NeighborID)
	}
	if vl.TransitArea != "0.0.0.3" {
		t.Errorf("TransitArea = %q, want 0.0.0.3", vl.TransitArea)
	}
}

func TestLLDPSetSyntax(t *testing.T) {
	cmds := []string{"set protocols lldp interface trust0", "set protocols lldp interface untrust0", "set protocols lldp transmit-interval 15", "set protocols lldp hold-multiplier 5"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	lldpCfg := cfg.Protocols.LLDP
	if lldpCfg == nil {
		t.Fatal("LLDP config is nil")
	}
	if len(lldpCfg.Interfaces) != 2 {
		t.Fatalf("interfaces: got %d, want 2", len(lldpCfg.Interfaces))
	}
	if lldpCfg.Interfaces[0].Name != "trust0" || lldpCfg.Interfaces[1].Name != "untrust0" {
		t.Errorf("interfaces: got %v, want [trust0 untrust0]", lldpCfg.Interfaces)
	}
	if lldpCfg.Interval != 15 {
		t.Errorf("interval: got %d, want 15", lldpCfg.Interval)
	}
	if lldpCfg.HoldMultiplier != 5 {
		t.Errorf("hold-multiplier: got %d, want 5", lldpCfg.HoldMultiplier)
	}
}

func TestLLDPHierarchicalSyntax(t *testing.T) {
	input := `protocols {
    lldp {
        interface trust0;
        interface dmz0;
        transmit-interval 10;
        hold-multiplier 3;
        disable;
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	lldpCfg := cfg.Protocols.LLDP
	if lldpCfg == nil {
		t.Fatal("LLDP config is nil")
	}
	if len(lldpCfg.Interfaces) != 2 {
		t.Fatalf("interfaces: got %d, want 2", len(lldpCfg.Interfaces))
	}
	if lldpCfg.Interval != 10 {
		t.Errorf("interval: got %d, want 10", lldpCfg.Interval)
	}
	if lldpCfg.HoldMultiplier != 3 {
		t.Errorf("hold-multiplier: got %d, want 3", lldpCfg.HoldMultiplier)
	}
	if !lldpCfg.Disable {
		t.Error("expected Disable=true")
	}
}

func TestLLDPDisableSetSyntax(t *testing.T) {
	cmds := []string{"set protocols lldp disable"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	lldpCfg := cfg.Protocols.LLDP
	if lldpCfg == nil {
		t.Fatal("LLDP config is nil")
	}
	if !lldpCfg.Disable {
		t.Error("expected Disable=true")
	}
}

func TestPortMirroringHierarchical(t *testing.T) {
	input := `forwarding-options {
    port-mirroring {
        instance mirror1 {
            input {
                rate 100;
                ingress {
                    interface trust0;
                    interface dmz0;
                }
            }
            output {
                interface monitor0;
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	pm := cfg.ForwardingOptions.PortMirroring
	if pm == nil {
		t.Fatal("PortMirroring is nil")
	}
	inst, ok := pm.Instances["mirror1"]
	if !ok {
		t.Fatal("instance mirror1 not found")
	}
	if inst.InputRate != 100 {
		t.Errorf("InputRate = %d, want 100", inst.InputRate)
	}
	if len(inst.Input) != 2 {
		t.Fatalf("len(Input) = %d, want 2", len(inst.Input))
	}
	if inst.Input[0] != "trust0" || inst.Input[1] != "dmz0" {
		t.Errorf("Input = %v, want [trust0 dmz0]", inst.Input)
	}
	if inst.Output != "monitor0" {
		t.Errorf("Output = %q, want monitor0", inst.Output)
	}
}

func TestPortMirroringFlatSet(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{"set forwarding-options port-mirroring instance span1 input rate 50", "set forwarding-options port-mirroring instance span1 input ingress interface wan0", "set forwarding-options port-mirroring instance span1 output interface monitor0"}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pm := cfg.ForwardingOptions.PortMirroring
	if pm == nil {
		t.Fatal("PortMirroring is nil")
	}
	inst, ok := pm.Instances["span1"]
	if !ok {
		t.Fatal("instance span1 not found")
	}
	if inst.InputRate != 50 {
		t.Errorf("InputRate = %d, want 50", inst.InputRate)
	}
	if len(inst.Input) != 1 || inst.Input[0] != "wan0" {
		t.Errorf("Input = %v, want [wan0]", inst.Input)
	}
	if inst.Output != "monitor0" {
		t.Errorf("Output = %q, want monitor0", inst.Output)
	}
}

func TestPortMirroringSetSyntaxMultiInput(t *testing.T) {
	cmds := []string{"set forwarding-options port-mirroring instance span1 input ingress interface trust0", "set forwarding-options port-mirroring instance span1 input ingress interface untrust0", "set forwarding-options port-mirroring instance span1 input rate 10", "set forwarding-options port-mirroring instance span1 output interface monitor0"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		tokens, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand failed for %q: %v", cmd, err)
		}
		if err := tree.SetPath(tokens); err != nil {
			t.Fatalf("SetPath failed for %q: %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.ForwardingOptions.PortMirroring == nil {
		t.Fatal("expected PortMirroring")
	}
	inst, ok := cfg.ForwardingOptions.PortMirroring.Instances["span1"]
	if !ok {
		t.Fatal("expected span1 instance")
	}
	if inst.InputRate != 10 {
		t.Errorf("rate = %d, want 10", inst.InputRate)
	}
	if len(inst.Input) != 2 {
		t.Errorf("input count = %d, want 2", len(inst.Input))
	}
	if inst.Output != "monitor0" {
		t.Errorf("output = %q, want monitor0", inst.Output)
	}
}

// compilePortMirroringSet is a flat-set helper: it runs each `set` command
// through ParseSetCommand + tree.SetPath (NEVER NewParser — the parser merges
// newline-separated set lines into one node) then compiles the tree.
func compilePortMirroringSet(t *testing.T, cmds ...string) (*Config, error) {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return CompileConfig(tree)
}

// #3972: an invalid port-mirroring entry (negative rate, duplicate ingress
// source) must be a HARD commit reject naming the bad entry — NOT a green
// commit that later fail-closes the WHOLE mirror table with only a warn in the
// snapshot builder. RED-on-revert: pre-#3972 the compiler silently accepted a
// negative rate (InputRate=-5) and a cross-instance duplicate ingress, the
// commit went green, and buildMirrorConfigSnapshots then dropped every valid
// mirror session. These tests go RED against that behavior.
func TestPortMirroringRejectsNegativeRateFlatSet(t *testing.T) {
	// 3 valid instances + 1 with a negative rate.
	cfg, err := compilePortMirroringSet(t,
		"set forwarding-options port-mirroring instance span1 input rate 10",
		"set forwarding-options port-mirroring instance span1 input ingress interface ge-0/0/0.0",
		"set forwarding-options port-mirroring instance span1 output interface mon0",
		"set forwarding-options port-mirroring instance span2 input rate 20",
		"set forwarding-options port-mirroring instance span2 input ingress interface ge-0/0/1.0",
		"set forwarding-options port-mirroring instance span2 output interface mon0",
		"set forwarding-options port-mirroring instance span3 input ingress interface ge-0/0/2.0",
		"set forwarding-options port-mirroring instance span3 output interface mon0",
		"set forwarding-options port-mirroring instance bad input rate -5",
		"set forwarding-options port-mirroring instance bad input ingress interface ge-0/0/3.0",
		"set forwarding-options port-mirroring instance bad output interface mon0",
	)
	if err == nil {
		t.Fatalf("CompileConfig succeeded, want reject for negative rate; PortMirroring=%+v", cfg.ForwardingOptions.PortMirroring)
	}
	if !strings.Contains(err.Error(), `instance "bad"`) || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("error = %v, want a specific negative-rate reject naming instance \"bad\"", err)
	}
}

func TestPortMirroringRejectsNonNumericRateFlatSet(t *testing.T) {
	_, err := compilePortMirroringSet(t,
		"set forwarding-options port-mirroring instance span1 input rate notanumber",
		"set forwarding-options port-mirroring instance span1 input ingress interface ge-0/0/0.0",
		"set forwarding-options port-mirroring instance span1 output interface mon0",
	)
	if err == nil || !strings.Contains(err.Error(), `instance "span1"`) || !strings.Contains(err.Error(), "invalid input rate") {
		t.Fatalf("error = %v, want invalid-input-rate reject naming instance \"span1\"", err)
	}
}

// A duplicate ingress source across two instances is rejected — the mirror
// table contract is one output per ingress interface. Names are normalized so
// the vSRX ("ge-0/0/0.0") and Linux ("ge-0-0-0.0") spellings collide.
func TestPortMirroringRejectsDuplicateIngressFlatSet(t *testing.T) {
	_, err := compilePortMirroringSet(t,
		"set forwarding-options port-mirroring instance span1 input ingress interface ge-0/0/0.0",
		"set forwarding-options port-mirroring instance span1 output interface mon0",
		"set forwarding-options port-mirroring instance span2 input ingress interface ge-0-0-0.0",
		"set forwarding-options port-mirroring instance span2 output interface mon1",
	)
	if err == nil {
		t.Fatal("CompileConfig succeeded, want reject for duplicate ingress interface across instances")
	}
	if !strings.Contains(err.Error(), `"span1"`) || !strings.Contains(err.Error(), `"span2"`) {
		t.Fatalf("error = %v, want a duplicate-ingress reject naming both instances", err)
	}
}

// An all-valid config compiles every instance. rate 0 (mirror every packet) is
// valid per the #1376 design, so it is NOT rejected.
func TestPortMirroringAllValidFlatSetCompilesAllEntries(t *testing.T) {
	cfg, err := compilePortMirroringSet(t,
		"set forwarding-options port-mirroring instance span1 input rate 10",
		"set forwarding-options port-mirroring instance span1 input ingress interface ge-0/0/0.0",
		"set forwarding-options port-mirroring instance span1 output interface mon0",
		"set forwarding-options port-mirroring instance span2 input rate 20",
		"set forwarding-options port-mirroring instance span2 input ingress interface ge-0/0/1.0",
		"set forwarding-options port-mirroring instance span2 output interface mon0",
		"set forwarding-options port-mirroring instance span3 input rate 0",
		"set forwarding-options port-mirroring instance span3 input ingress interface ge-0/0/2.0",
		"set forwarding-options port-mirroring instance span3 output interface mon1",
	)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pm := cfg.ForwardingOptions.PortMirroring
	if pm == nil || len(pm.Instances) != 3 {
		t.Fatalf("PortMirroring = %+v, want 3 instances", pm)
	}
	if got := pm.Instances["span3"].InputRate; got != 0 {
		t.Fatalf("span3 InputRate = %d, want 0 (mirror all)", got)
	}
	for _, name := range []string{"span1", "span2", "span3"} {
		if pm.Instances[name] == nil {
			t.Fatalf("instance %q missing after compile", name)
		}
	}
}

func TestPortMirroringHierarchicalSimple(t *testing.T) {
	input := `forwarding-options {
    port-mirroring {
        instance span1 {
            input {
                rate 5;
                ingress {
                    interface trust0;
                }
            }
            output {
                interface monitor0;
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.ForwardingOptions.PortMirroring == nil {
		t.Fatal("expected PortMirroring")
	}
	inst := cfg.ForwardingOptions.PortMirroring.Instances["span1"]
	if inst == nil {
		t.Fatal("expected span1")
	}
	if inst.InputRate != 5 {
		t.Errorf("rate = %d, want 5", inst.InputRate)
	}
	if inst.Output != "monitor0" {
		t.Errorf("output = %q, want monitor0", inst.Output)
	}
}

func TestIPIPTunnelSetSyntax(t *testing.T) {
	cmds := []string{"set interfaces ip-0/0/0 tunnel source 10.0.0.1", "set interfaces ip-0/0/0 tunnel destination 10.0.0.2", "set interfaces ip-0/0/0 tunnel ttl 128", "set interfaces ip-0/0/0 unit 0 family inet address 10.10.10.1/30"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	// #4785 half 1: `mode ipip` is now REJECTED on the strict commit path, so
	// this test compiles through the TOLERANT path — the one a persisted or
	// peer-synced config still takes. The subject here is unchanged and is not
	// commit acceptance: it is that the tunnel fields parse and the mode is
	// inferred/honored correctly. Commit rejection is pinned by
	// TestIpipTunnelRejectedAtCommit_4785.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["ip-0/0/0"]
	if ifc == nil {
		t.Fatal("ip-0/0/0 interface not found")
	}
	tc := ifc.Tunnel
	if tc == nil {
		t.Fatal("tunnel config is nil")
	}
	if tc.Mode != "ipip" {
		t.Errorf("Mode = %q, want %q (auto-detected from ip- prefix)", tc.Mode, "ipip")
	}
	if tc.Source != "10.0.0.1" {
		t.Errorf("Source = %q, want 10.0.0.1", tc.Source)
	}
	if tc.Destination != "10.0.0.2" {
		t.Errorf("Destination = %q, want 10.0.0.2", tc.Destination)
	}
	if tc.TTL != 128 {
		t.Errorf("TTL = %d, want 128", tc.TTL)
	}
}

func TestIPIPTunnelExplicitMode(t *testing.T) {
	cmds := []string{"set interfaces gr-0/0/0 tunnel source 10.0.0.1", "set interfaces gr-0/0/0 tunnel destination 10.0.0.2", "set interfaces gr-0/0/0 tunnel mode ipip", "set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	// #4785 half 1: `mode ipip` is now REJECTED on the strict commit path, so
	// this test compiles through the TOLERANT path — the one a persisted or
	// peer-synced config still takes. The subject here is unchanged and is not
	// commit acceptance: it is that the tunnel fields parse and the mode is
	// inferred/honored correctly. Commit rejection is pinned by
	// TestIpipTunnelRejectedAtCommit_4785.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatal("gr-0/0/0 interface not found")
	}
	tc := ifc.Tunnel
	if tc == nil {
		t.Fatal("tunnel config is nil")
	}
	if tc.Mode != "ipip" {
		t.Errorf("Mode = %q, want %q (explicitly set)", tc.Mode, "ipip")
	}
}

func TestGRETunnelRoutingInstanceDestination(t *testing.T) {
	cmds := []string{"set interfaces gr-0/0/0 tunnel source 10.0.0.1", "set interfaces gr-0/0/0 tunnel destination 10.0.0.2", "set interfaces gr-0/0/0 tunnel routing-instance destination dmz-vr", "set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatal("gr-0/0/0 interface not found")
	}
	tc := ifc.Tunnel
	if tc == nil {
		t.Fatal("tunnel config is nil")
	}
	if tc.RoutingInstance != "dmz-vr" {
		t.Errorf("RoutingInstance = %q, want %q", tc.RoutingInstance, "dmz-vr")
	}
}

func TestPointToPointFlag(t *testing.T) {
	cmds := []string{"set interfaces gr-0/0/0 tunnel source 10.0.0.1", "set interfaces gr-0/0/0 tunnel destination 10.0.0.2", "set interfaces gr-0/0/0 unit 0 point-to-point", "set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatal("gr-0/0/0 interface not found")
	}
	unit := ifc.Units[0]
	if unit == nil {
		t.Fatal("unit 0 not found")
	}
	if !unit.PointToPoint {
		t.Error("PointToPoint should be true")
	}
}

func TestGlobalInterfaceRoutesRibGroup(t *testing.T) {
	// The ISP instances are defined so the import-rib references resolve
	// (#2226 strict gate); the test's purpose is the rib-group parse shape.
	input := `routing-instances {
    Comcast-BCI { instance-type virtual-router; }
    ATT { instance-type virtual-router; }
    Atherton-Fiber { instance-type virtual-router; }
    sfmix { instance-type virtual-router; }
}
routing-options {
    interface-routes {
        rib-group {
            inet Other-ISPS;
            inet6 Other-ISP6;
        }
    }
    rib-groups {
        Other-ISPS {
            import-rib [ Comcast-BCI.inet.0 inet.0 ATT.inet.0 Atherton-Fiber.inet.0 sfmix.inet.0 ];
        }
        Other-ISP6 {
            import-rib [ Comcast-BCI.inet6.0 inet6.0 ATT.inet6.0 Atherton-Fiber.inet6.0 ];
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RoutingOptions.InterfaceRoutesRibGroup != "Other-ISPS" {
		t.Errorf("InterfaceRoutesRibGroup = %q, want Other-ISPS", cfg.RoutingOptions.InterfaceRoutesRibGroup)
	}
	if cfg.RoutingOptions.InterfaceRoutesRibGroupV6 != "Other-ISP6" {
		t.Errorf("InterfaceRoutesRibGroupV6 = %q, want Other-ISP6", cfg.RoutingOptions.InterfaceRoutesRibGroupV6)
	}
	rg, ok := cfg.RoutingOptions.RibGroups["Other-ISPS"]
	if !ok {
		t.Fatal("rib-group Other-ISPS not found")
	}
	if len(rg.ImportRibs) != 5 {
		t.Fatalf("Other-ISPS ImportRibs = %d, want 5", len(rg.ImportRibs))
	}
	rg6, ok := cfg.RoutingOptions.RibGroups["Other-ISP6"]
	if !ok {
		t.Fatal("rib-group Other-ISP6 not found")
	}
	if len(rg6.ImportRibs) != 4 {
		t.Fatalf("Other-ISP6 ImportRibs = %d, want 4", len(rg6.ImportRibs))
	}
}

func TestGlobalInterfaceRoutesRibGroupSetSyntax(t *testing.T) {
	lines := []string{
		// Define the ISP instances so the import-rib references resolve
		// (#2226 strict gate); the test's purpose is the parse shape.
		"set routing-instances Comcast-BCI instance-type virtual-router",
		"set routing-instances Other-GigabitPro instance-type virtual-router",
		"set routing-instances bv-firehouse-vpn instance-type virtual-router",
		"set routing-instances Comcast-GigabitPro instance-type virtual-router",
		"set routing-instances ATT instance-type virtual-router",
		"set routing-instances Atherton-Fiber instance-type virtual-router",
		"set routing-instances sfmix instance-type virtual-router",
		"set routing-options interface-routes rib-group inet Other-ISPS", "set routing-options interface-routes rib-group inet6 Other-ISP6", "set routing-options rib-groups Other-ISPS import-rib Comcast-BCI.inet.0", "set routing-options rib-groups Other-ISPS import-rib inet.0", "set routing-options rib-groups Other-ISPS import-rib Other-GigabitPro.inet.0", "set routing-options rib-groups Other-ISPS import-rib bv-firehouse-vpn.inet.0", "set routing-options rib-groups Other-ISPS import-rib Comcast-GigabitPro.inet.0", "set routing-options rib-groups Other-ISPS import-rib ATT.inet.0", "set routing-options rib-groups Other-ISPS import-rib Atherton-Fiber.inet.0", "set routing-options rib-groups Other-ISPS import-rib sfmix.inet.0", "set routing-options rib-groups Other-ISP6 import-rib Comcast-BCI.inet6.0", "set routing-options rib-groups Other-ISP6 import-rib inet6.0", "set routing-options rib-groups Other-ISP6 import-rib Comcast-GigabitPro.inet6.0", "set routing-options rib-groups Other-ISP6 import-rib ATT.inet6.0", "set routing-options rib-groups Other-ISP6 import-rib Atherton-Fiber.inet6.0"}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RoutingOptions.InterfaceRoutesRibGroup != "Other-ISPS" {
		t.Errorf("InterfaceRoutesRibGroup = %q, want Other-ISPS", cfg.RoutingOptions.InterfaceRoutesRibGroup)
	}
	if cfg.RoutingOptions.InterfaceRoutesRibGroupV6 != "Other-ISP6" {
		t.Errorf("InterfaceRoutesRibGroupV6 = %q, want Other-ISP6", cfg.RoutingOptions.InterfaceRoutesRibGroupV6)
	}
	rg := cfg.RoutingOptions.RibGroups["Other-ISPS"]
	if rg == nil {
		t.Fatal("rib-group Other-ISPS not found")
	}
	if len(rg.ImportRibs) != 8 {
		t.Fatalf("Other-ISPS ImportRibs = %d, want 8: %v", len(rg.ImportRibs), rg.ImportRibs)
	}
	rg6 := cfg.RoutingOptions.RibGroups["Other-ISP6"]
	if rg6 == nil {
		t.Fatal("rib-group Other-ISP6 not found")
	}
	if len(rg6.ImportRibs) != 5 {
		t.Fatalf("Other-ISP6 ImportRibs = %d, want 5: %v", len(rg6.ImportRibs), rg6.ImportRibs)
	}
}

func TestIPv6NextTableStaticRoutes(t *testing.T) {
	lines := []string{
		// The next-table target routing-instances must be defined or the
		// #5693 definedness gate rejects the commit.
		"set routing-instances Comcast-GigabitPro instance-type virtual-router",
		"set routing-instances ATT instance-type virtual-router",
		// #9810: one unclaimed unit (N=1) so the per-ingress window gate admits the leaks.
		"set interfaces ge-0/0/0 unit 0",
		"set routing-options rib inet6.0 static route ::/0 next-table Comcast-GigabitPro.inet6.0",
		"set routing-options rib inet6.0 static route 2001:db8::/32 next-table ATT.inet6.0",
		"set routing-options static route 0.0.0.0/0 next-table Comcast-GigabitPro.inet.0",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RoutingOptions.Inet6StaticRoutes) != 2 {
		t.Fatalf("Inet6StaticRoutes = %d, want 2", len(cfg.RoutingOptions.Inet6StaticRoutes))
	}
	r0 := cfg.RoutingOptions.Inet6StaticRoutes[0]
	if r0.Destination != "::/0" {
		t.Errorf("v6 route 0 dest = %q, want ::/0", r0.Destination)
	}
	if r0.NextTable != "Comcast-GigabitPro" {
		t.Errorf("v6 route 0 next-table = %q, want Comcast-GigabitPro", r0.NextTable)
	}
	r1 := cfg.RoutingOptions.Inet6StaticRoutes[1]
	if r1.NextTable != "ATT" {
		t.Errorf("v6 route 1 next-table = %q, want ATT", r1.NextTable)
	}
	if len(cfg.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("StaticRoutes = %d, want 1", len(cfg.RoutingOptions.StaticRoutes))
	}
	if cfg.RoutingOptions.StaticRoutes[0].NextTable != "Comcast-GigabitPro" {
		t.Errorf("v4 route next-table = %q", cfg.RoutingOptions.StaticRoutes[0].NextTable)
	}
}

func TestLLDPPerInterfaceDisable(t *testing.T) {
	input := `
protocols {
    lldp {
        interface eth0;
        interface eth1 {
            disable;
        }
        transmit-interval 60;
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocols.LLDP == nil {
		t.Fatal("LLDP is nil")
	}
	if len(cfg.Protocols.LLDP.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(cfg.Protocols.LLDP.Interfaces))
	}
	if cfg.Protocols.LLDP.Interfaces[0].Name != "eth0" {
		t.Errorf("interface[0] name = %q, want eth0", cfg.Protocols.LLDP.Interfaces[0].Name)
	}
	if cfg.Protocols.LLDP.Interfaces[0].Disable {
		t.Error("eth0 should not be disabled")
	}
	if cfg.Protocols.LLDP.Interfaces[1].Name != "eth1" {
		t.Errorf("interface[1] name = %q, want eth1", cfg.Protocols.LLDP.Interfaces[1].Name)
	}
	if !cfg.Protocols.LLDP.Interfaces[1].Disable {
		t.Error("eth1 should be disabled")
	}
	if cfg.Protocols.LLDP.Interval != 60 {
		t.Errorf("interval = %d, want 60", cfg.Protocols.LLDP.Interval)
	}
}

func TestLLDPPerInterfaceDisableSetSyntax(t *testing.T) {
	lines := []string{"set protocols lldp interface eth0", "set protocols lldp interface eth1 disable", "set protocols lldp transmit-interval 60"}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocols.LLDP == nil {
		t.Fatal("LLDP is nil")
	}
	if len(cfg.Protocols.LLDP.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(cfg.Protocols.LLDP.Interfaces))
	}
	found := false
	for _, iface := range cfg.Protocols.LLDP.Interfaces {
		if iface.Name == "eth1" {
			found = true
			if !iface.Disable {
				t.Error("eth1 should be disabled")
			}
		}
	}
	if !found {
		t.Error("eth1 not found in interfaces")
	}
}

func TestGenerateRoutes(t *testing.T) {
	input := `
routing-options {
    generate {
        route 192.168.0.0/16 {
            policy export-to-isp;
        }
        route 10.0.0.0/8 {
            discard;
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RoutingOptions.GenerateRoutes) != 2 {
		t.Fatalf("expected 2 generate routes, got %d", len(cfg.RoutingOptions.GenerateRoutes))
	}
	gr0 := cfg.RoutingOptions.GenerateRoutes[0]
	if gr0.Prefix != "192.168.0.0/16" {
		t.Errorf("route[0] prefix = %q, want 192.168.0.0/16", gr0.Prefix)
	}
	if gr0.Policy != "export-to-isp" {
		t.Errorf("route[0] policy = %q, want export-to-isp", gr0.Policy)
	}
	gr1 := cfg.RoutingOptions.GenerateRoutes[1]
	if gr1.Prefix != "10.0.0.0/8" {
		t.Errorf("route[1] prefix = %q, want 10.0.0.0/8", gr1.Prefix)
	}
	if !gr1.Discard {
		t.Error("route[1] should have discard=true")
	}
}

func TestGenerateRoutesSetSyntax(t *testing.T) {
	lines := []string{"set routing-options generate route 192.168.0.0/16 policy export-to-isp", "set routing-options generate route 10.0.0.0/8 discard"}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RoutingOptions.GenerateRoutes) != 2 {
		t.Fatalf("expected 2 generate routes, got %d", len(cfg.RoutingOptions.GenerateRoutes))
	}
	found := false
	for _, gr := range cfg.RoutingOptions.GenerateRoutes {
		if gr.Prefix == "10.0.0.0/8" && gr.Discard {
			found = true
		}
	}
	if !found {
		t.Error("10.0.0.0/8 discard route not found")
	}
}

func TestBridgeDomains_Hierarchical(t *testing.T) {
	input := `bridge-domains {
    bd0 {
        vlan-id-list 100;
        vlan-id-list 200;
        routing-interface irb.0;
    }
    bd1 {
        vlan-id-list 300;
        domain-type bridge;
    }
}
interfaces {
    irb {
        unit 0 {
            family inet {
                address 10.0.100.1/24;
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if len(cfg.BridgeDomains) != 2 {
		t.Fatalf("expected 2 bridge domains, got %d", len(cfg.BridgeDomains))
	}
	var bd0, bd1 *BridgeDomainConfig
	// Find bd0.
	for _, bd := range cfg.BridgeDomains {
		switch bd.Name {
		case "bd0":
			bd0 = bd
		case "bd1":
			bd1 = bd
		}
	}
	if bd0 == nil {
		t.Fatal("missing bridge domain bd0")
	}
	if len(bd0.VlanIDs) != 2 || bd0.VlanIDs[0] != 100 || bd0.VlanIDs[1] != 200 {
		t.Errorf("bd0 vlan IDs: %v", bd0.VlanIDs)
	}
	if bd0.RoutingInterface != "irb.0" {
		t.Errorf("bd0 routing-interface: %q", bd0.RoutingInterface)
	}
	if bd1 == nil {
		t.Fatal("missing bridge domain bd1")
	}
	if len(bd1.VlanIDs) != 1 || bd1.VlanIDs[0] != 300 {
		t.Errorf("bd1 vlan IDs: %v", bd1.VlanIDs)
	}
	if bd1.DomainType != "bridge" {
		t.Errorf("bd1 domain-type: %q", bd1.DomainType)
	}
	if bd1.RoutingInterface != "" {
		t.Errorf("bd1 routing-interface should be empty: %q", bd1.RoutingInterface)
	}
}

func TestBridgeDomains_FlatSet(t *testing.T) {
	cmds := []string{"set bridge-domains bd0 vlan-id-list 100", "set bridge-domains bd0 vlan-id-list 200", "set bridge-domains bd0 routing-interface irb.0", "set bridge-domains bd1 vlan-id-list 300", "set bridge-domains bd1 domain-type bridge", "set interfaces irb unit 0 family inet address 10.0.100.1/24"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if len(cfg.BridgeDomains) != 2 {
		t.Fatalf("expected 2 bridge domains, got %d", len(cfg.BridgeDomains))
	}
	var bd0 *BridgeDomainConfig
	for _, bd := range cfg.BridgeDomains {
		if bd.Name == "bd0" {
			bd0 = bd
			break
		}
	}
	if bd0 == nil {
		t.Fatal("missing bridge domain bd0")
	}
	if len(bd0.VlanIDs) != 2 {
		t.Fatalf("bd0 expected 2 vlan IDs, got %d: %v", len(bd0.VlanIDs), bd0.VlanIDs)
	}
	if bd0.VlanIDs[0] != 100 || bd0.VlanIDs[1] != 200 {
		t.Errorf("bd0 vlan IDs: %v", bd0.VlanIDs)
	}
	if bd0.RoutingInterface != "irb.0" {
		t.Errorf("bd0 routing-interface: %q", bd0.RoutingInterface)
	}
	irbIfc := cfg.Interfaces.Interfaces["irb"]
	if irbIfc == nil {
		t.Fatal("missing irb interface config")
	}
	u0 := irbIfc.Units[0]
	if u0 == nil {
		t.Fatal("missing irb unit 0")
	}
	if len(u0.Addresses) != 1 || u0.Addresses[0] != "10.0.100.1/24" {
		t.Errorf("irb.0 addresses: %v", u0.Addresses)
	}
}

func TestBridgeDomains_FormatRoundTrip(t *testing.T) {
	cmds := []string{"set bridge-domains bd0 vlan-id-list 100", "set bridge-domains bd0 vlan-id-list 200", "set bridge-domains bd0 routing-interface irb.0"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	output := tree.Format()
	t.Logf("Formatted:\n%s", output)
	parser := NewParser(output)
	tree2, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("re-parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if len(cfg.BridgeDomains) != 1 {
		t.Fatalf("expected 1 bridge domain, got %d", len(cfg.BridgeDomains))
	}
	bd := cfg.BridgeDomains[0]
	if bd.Name != "bd0" {
		t.Errorf("expected bd0, got %q", bd.Name)
	}
	if len(bd.VlanIDs) != 2 {
		t.Errorf("expected 2 vlans, got %d", len(bd.VlanIDs))
	}
	if bd.RoutingInterface != "irb.0" {
		t.Errorf("routing-interface: %q", bd.RoutingInterface)
	}
}

func TestBridgeDomains_InvalidVlanID(t *testing.T) {
	input := `bridge-domains {
    bd0 {
        vlan-id-list 5000;
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected error for invalid vlan ID 5000")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIRBToBridge(t *testing.T) {
	bds := []*BridgeDomainConfig{{Name: "bd0", VlanIDs: []int{100, 200}, RoutingInterface: "irb.0"}, {Name: "bd1", VlanIDs: []int{300}}, {Name: "bd2", VlanIDs: []int{400}, RoutingInterface: "irb.2"}}
	m := IRBToBridge(bds)
	if m["irb.0"] != "br-bd0" {
		t.Errorf("irb.0 -> %q, expected br-bd0", m["irb.0"])
	}
	if m["irb.2"] != "br-bd2" {
		t.Errorf("irb.2 -> %q, expected br-bd2", m["irb.2"])
	}
	if _, ok := m["irb.1"]; ok {
		t.Error("irb.1 should not be in map (bd1 has no routing-interface)")
	}
}

func TestOSPFBFDIntervalMultiplierSetSyntax(t *testing.T) {
	cmds := []string{"set protocols ospf area 0.0.0.0 interface trust0 bfd-liveness-detection minimum-interval 300", "set protocols ospf area 0.0.0.0 interface trust0 bfd-liveness-detection multiplier 3"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospf := cfg.Protocols.OSPF
	if ospf == nil {
		t.Fatal("OSPF config is nil")
	}
	iface := ospf.Areas[0].Interfaces[0]
	if !iface.BFD {
		t.Error("OSPF interface BFD should be true")
	}
	if iface.BFDInterval != 300 {
		t.Errorf("BFDInterval: got %d, want 300", iface.BFDInterval)
	}
	if iface.BFDMultiplier != 3 {
		t.Errorf("BFDMultiplier: got %d, want 3", iface.BFDMultiplier)
	}
}

func TestISISBFDSetSyntax(t *testing.T) {
	cmds := []string{"set protocols isis net 49.0001.0100.0000.0001.00", "set protocols isis interface trust0 bfd-liveness-detection minimum-interval 300", "set protocols isis interface trust0 bfd-liveness-detection multiplier 4"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	isis := cfg.Protocols.ISIS
	if isis == nil {
		t.Fatal("IS-IS config is nil")
	}
	if len(isis.Interfaces) != 1 {
		t.Fatalf("interfaces: got %d, want 1", len(isis.Interfaces))
	}
	iface := isis.Interfaces[0]
	if !iface.BFD {
		t.Error("IS-IS interface BFD should be true")
	}
	if iface.BFDInterval != 300 {
		t.Errorf("BFDInterval: got %d, want 300", iface.BFDInterval)
	}
	if iface.BFDMultiplier != 4 {
		t.Errorf("BFDMultiplier: got %d, want 4", iface.BFDMultiplier)
	}
}

func TestBGPBFDMultiplierSetSyntax(t *testing.T) {
	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp group external peer-as 65002", "set protocols bgp group external bfd-liveness-detection minimum-interval 200", "set protocols bgp group external bfd-liveness-detection multiplier 5", "set protocols bgp group external neighbor 10.0.2.1", "set protocols bgp group external neighbor 10.0.3.1 bfd-liveness-detection multiplier 4"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if len(bgp.Neighbors) != 2 {
		t.Fatalf("neighbors: got %d, want 2", len(bgp.Neighbors))
	}
	if bgp.Neighbors[0].BFDMultiplier != 5 {
		t.Errorf("neighbor[0] BFDMultiplier: got %d, want 5", bgp.Neighbors[0].BFDMultiplier)
	}
	if bgp.Neighbors[0].BFDInterval != 200 {
		t.Errorf("neighbor[0] BFDInterval: got %d, want 200", bgp.Neighbors[0].BFDInterval)
	}
	if bgp.Neighbors[1].BFDMultiplier != 4 {
		t.Errorf("neighbor[1] BFDMultiplier: got %d, want 4", bgp.Neighbors[1].BFDMultiplier)
	}
}

func TestIPIPTunnelWithRoutingInstance(t *testing.T) {
	cmds := []string{"set interfaces ip-0/0/0 unit 0 tunnel source 209.237.133.186", "set interfaces ip-0/0/0 unit 0 tunnel destination 107.161.208.15", "set interfaces ip-0/0/0 unit 0 tunnel routing-instance destination Atherton-Fiber", "set interfaces ip-0/0/0 unit 0 family inet mtu 1456", "set interfaces ip-0/0/0 unit 0 family inet address 10.255.192.26/30"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	// #4785 half 1: `mode ipip` is now REJECTED on the strict commit path, so
	// this test compiles through the TOLERANT path — the one a persisted or
	// peer-synced config still takes. The subject here is unchanged and is not
	// commit acceptance: it is that the tunnel fields parse and the mode is
	// inferred/honored correctly. Commit rejection is pinned by
	// TestIpipTunnelRejectedAtCommit_4785.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["ip-0/0/0"]
	if ifc == nil {
		t.Fatal("ip-0/0/0 interface not found")
	}
	unit0, ok := ifc.Units[0]
	if !ok {
		t.Fatal("unit 0 not found")
	}
	if unit0.Tunnel == nil {
		t.Fatal("unit 0 tunnel config is nil")
	}
	if unit0.Tunnel.Mode != "ipip" {
		t.Errorf("Mode = %q, want %q (auto-detected from ip- prefix)", unit0.Tunnel.Mode, "ipip")
	}
	if unit0.Tunnel.Name != "ip-0-0-0" {
		t.Errorf("Name = %q, want %q", unit0.Tunnel.Name, "ip-0-0-0")
	}
	if unit0.Tunnel.RoutingInstance != "Atherton-Fiber" {
		t.Errorf("RoutingInstance = %q, want Atherton-Fiber", unit0.Tunnel.RoutingInstance)
	}
	if unit0.Tunnel.Source != "209.237.133.186" {
		t.Errorf("Source = %q, want 209.237.133.186", unit0.Tunnel.Source)
	}
	if len(unit0.Tunnel.Addresses) != 1 || unit0.Tunnel.Addresses[0] != "10.255.192.26/30" {
		t.Errorf("Addresses = %v, want [10.255.192.26/30]", unit0.Tunnel.Addresses)
	}
}

func TestTunnelNameMap(t *testing.T) {
	cmds := []string{"set interfaces gre0 tunnel source 10.0.0.1", "set interfaces gre0 tunnel destination 10.0.0.2", "set interfaces gre0 unit 0 family inet address 10.10.10.1/30", "set interfaces gr-0/0/0 unit 0 tunnel source 1.1.1.1", "set interfaces gr-0/0/0 unit 0 tunnel destination 2.2.2.2", "set interfaces gr-0/0/0 unit 0 family inet address 10.0.0.1/30", "set interfaces gr-0/0/0 unit 1 tunnel source 3.3.3.3", "set interfaces gr-0/0/0 unit 1 tunnel destination 4.4.4.4", "set interfaces gr-0/0/0 unit 1 family inet address 10.0.1.1/30"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	nameMap := cfg.TunnelNameMap()
	if got, want := nameMap["gre0.0"], "gre0"; got != want {
		t.Errorf("TunnelNameMap[gre0.0] = %q, want %q", got, want)
	}
	if got, want := nameMap["gr-0/0/0.0"], "gr-0-0-0"; got != want {
		t.Errorf("TunnelNameMap[gr-0/0/0.0] = %q, want %q", got, want)
	}
	if got, want := nameMap["gr-0/0/0.1"], "gr-0-0-0u1"; got != want {
		t.Errorf("TunnelNameMap[gr-0/0/0.1] = %q, want %q", got, want)
	}
}

// #1910 r1 (Codex/AGY convergent High): a unit with its OWN per-unit
// tunnel stanza keeps its compiler-assigned uN device name even when
// an interface-level tunnel coexists on the same interface — the
// compiler creates BOTH devices, and mapping the unit ref to the base
// name would make step 0a / the RIListMember veto / ResolveKernelIfName
// target the wrong device.
func TestTunnelNameMapPerUnitNotShadowedByInterfaceLevel(t *testing.T) {
	cmds := []string{
		"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
		"set interfaces gr-0/0/0 unit 1 tunnel source 3.3.3.3",
		"set interfaces gr-0/0/0 unit 1 tunnel destination 4.4.4.4",
		"set interfaces gr-0/0/0 unit 1 family inet address 10.0.1.1/30",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	nameMap := cfg.TunnelNameMap()
	// Unit 0 has no per-unit tunnel: shares the interface device.
	if got, want := nameMap["gr-0/0/0.0"], "gr-0-0-0"; got != want {
		t.Errorf("TunnelNameMap[gr-0/0/0.0] = %q, want %q", got, want)
	}
	// Unit 1 has its own tunnel: the real per-unit uN device, NOT the
	// interface-level base name.
	if got, want := nameMap["gr-0/0/0.1"], "gr-0-0-0u1"; got != want {
		t.Errorf("TunnelNameMap[gr-0/0/0.1] = %q, want %q", got, want)
	}
}

// #1910 r1 (Codex/AGY convergent High): interface-level WireGuard
// tunnels have no GRE-style source, so the Source!="" interface-level
// gate must not drop them (the #1736 collectAppliedTunnels twin). All
// units of wg0 share the single persistent TUN device.
func TestTunnelNameMapWireguardInterfaceLevel(t *testing.T) {
	cmds := []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key 1111111111111111111111111111111111111111111111111111111111111111",
		"set interfaces wg0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg0 unit 0 family inet address 10.66.0.1/24",
		"set interfaces wg0 unit 1 family inet address 10.66.1.1/24",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	nameMap := cfg.TunnelNameMap()
	if got, want := nameMap["wg0.0"], "wg0"; got != want {
		t.Errorf("TunnelNameMap[wg0.0] = %q, want %q", got, want)
	}
	if got, want := nameMap["wg0.1"], "wg0"; got != want {
		t.Errorf("TunnelNameMap[wg0.1] = %q, want %q", got, want)
	}
}

func TestInterfaceLevelTunnelLinuxName(t *testing.T) {
	cmds := []string{"set interfaces gr-0/0/0 tunnel source 10.0.0.1", "set interfaces gr-0/0/0 tunnel destination 10.0.0.2", "set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatal("gr-0/0/0 not found")
	}
	if ifc.Tunnel == nil {
		t.Fatal("interface-level tunnel is nil")
	}
	if ifc.Tunnel.Name != "gr-0-0-0" {
		t.Errorf("Tunnel.Name = %q, want %q (LinuxIfName should replace /)", ifc.Tunnel.Name, "gr-0-0-0")
	}
}

func TestQualifiedNextHopFlatSet(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{"set routing-options static route ::/0 qualified-next-hop fe80::2d0:f6ff:feda:c180 interface reth2.0"}
	for _, line := range lines {
		tokens, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(tokens); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(cfg.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("got %d static routes, want 1", len(cfg.RoutingOptions.StaticRoutes))
	}
	sr := cfg.RoutingOptions.StaticRoutes[0]
	if sr.Destination != "::/0" {
		t.Errorf("Destination = %q, want ::/0", sr.Destination)
	}
	if len(sr.NextHops) != 1 {
		t.Fatalf("got %d next-hops, want 1", len(sr.NextHops))
	}
	nh := sr.NextHops[0]
	if nh.Address != "fe80::2d0:f6ff:feda:c180" {
		t.Errorf("Address = %q, want fe80::2d0:f6ff:feda:c180", nh.Address)
	}
	if nh.Interface != "reth2.0" {
		t.Errorf("Interface = %q, want reth2.0", nh.Interface)
	}
}

func TestQualifiedNextHopHierarchical(t *testing.T) {
	input := `
routing-options {
    static {
        route ::/0 {
            qualified-next-hop fe80::2d0:f6ff:feda:c180 {
                interface reth2.0;
            }
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(cfg.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("got %d static routes, want 1", len(cfg.RoutingOptions.StaticRoutes))
	}
	sr := cfg.RoutingOptions.StaticRoutes[0]
	if len(sr.NextHops) != 1 {
		t.Fatalf("got %d next-hops, want 1", len(sr.NextHops))
	}
	nh := sr.NextHops[0]
	if nh.Address != "fe80::2d0:f6ff:feda:c180" {
		t.Errorf("Address = %q, want fe80::2d0:f6ff:feda:c180", nh.Address)
	}
	if nh.Interface != "reth2.0" {
		t.Errorf("Interface = %q, want reth2.0", nh.Interface)
	}
}

func TestRoutingInstanceRibInet6(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{"set routing-instances ATT instance-type virtual-router", "set routing-instances ATT routing-options rib ATT.inet6.0 static route ::/0 qualified-next-hop fe80::2d0:f6ff:feda:c180 interface reth2.0"}
	for _, line := range lines {
		tokens, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(tokens); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("got %d routing instances, want 1", len(cfg.RoutingInstances))
	}
	ri := cfg.RoutingInstances[0]
	if ri.Name != "ATT" {
		t.Errorf("Name = %q, want ATT", ri.Name)
	}
	if len(ri.Inet6StaticRoutes) != 1 {
		t.Fatalf("got %d inet6 static routes, want 1", len(ri.Inet6StaticRoutes))
	}
	sr := ri.Inet6StaticRoutes[0]
	if sr.Destination != "::/0" {
		t.Errorf("Destination = %q, want ::/0", sr.Destination)
	}
	if len(sr.NextHops) != 1 {
		t.Fatalf("got %d next-hops, want 1", len(sr.NextHops))
	}
	nh := sr.NextHops[0]
	if nh.Address != "fe80::2d0:f6ff:feda:c180" {
		t.Errorf("Address = %q, want fe80::2d0:f6ff:feda:c180", nh.Address)
	}
	if nh.Interface != "reth2.0" {
		t.Errorf("Interface = %q, want reth2.0", nh.Interface)
	}
}

// #1432 S2a: the minimal `tunnel wireguard { ... }` stanza compiles to
// the TunnelConfig Wg* fields via parseTunnelWireguard.
func TestWireGuardTunnelSetSyntax(t *testing.T) {
	cmds := []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key a01010101010101010101010101010101010101010101010101010101010101a",
		"set interfaces wg0 tunnel wireguard peer b02020202020202020202020202020202020202020202020202020202020202b allowed-ips 10.0.0.0/24",
		"set interfaces wg0 tunnel wireguard peer b02020202020202020202020202020202020202020202020202020202020202b allowed-ips 10.0.1.0/24",
		"set interfaces wg0 tunnel wireguard peer b02020202020202020202020202020202020202020202020202020202020202b endpoint 203.0.113.1:51820",
		"set interfaces wg0 tunnel wireguard peer b02020202020202020202020202020202020202020202020202020202020202b persistent-keepalive 25",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["wg0"]
	if ifc == nil || ifc.Tunnel == nil {
		t.Fatal("wg0 tunnel config not found")
	}
	tc := ifc.Tunnel
	if tc.Mode != "wireguard" {
		t.Errorf("Mode = %q, want wireguard", tc.Mode)
	}
	if tc.WgListenPort != 51820 {
		t.Errorf("WgListenPort = %d, want 51820", tc.WgListenPort)
	}
	if tc.WgLocalPrivkeyHex != "a01010101010101010101010101010101010101010101010101010101010101a" {
		t.Errorf("WgLocalPrivkeyHex not parsed: %q", tc.WgLocalPrivkeyHex)
	}
	if len(tc.WgPeers) != 1 {
		t.Fatalf("WgPeers = %v, want 1 peer", tc.WgPeers)
	}
	peer := tc.WgPeers[0]
	if peer.PublicKeyHex != "b02020202020202020202020202020202020202020202020202020202020202b" {
		t.Errorf("WgPeers[0].PublicKeyHex = %q", peer.PublicKeyHex)
	}
	if len(peer.AllowedIPs) != 2 {
		t.Errorf("WgPeers[0].AllowedIPs = %v, want 2 entries", peer.AllowedIPs)
	}
	if peer.Endpoint != "203.0.113.1:51820" {
		t.Errorf("WgPeers[0].Endpoint = %q", peer.Endpoint)
	}
	if peer.KeepaliveSecs != 25 {
		t.Errorf("WgPeers[0].KeepaliveSecs = %d, want 25", peer.KeepaliveSecs)
	}
}

// TestPolicyTermMultiProtocolFlatSet exercises the flat-set / inline-keys
// compile path: "from protocol [ bgp ospf static ]" must keep ALL listed
// protocols, not just the first. Regression for #2008 H18 — the old scalar
// FromProtocol field silently discarded every protocol after the first.
func TestPolicyTermMultiProtocolFlatSet(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{
		"set policy-options policy-statement EXPORT-ALL term t1 from protocol [ bgp ospf static ]",
		"set policy-options policy-statement EXPORT-ALL term t1 then accept",
	}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["EXPORT-ALL"]
	if ps == nil {
		t.Fatal("EXPORT-ALL policy-statement not found")
	}
	if len(ps.Terms) != 1 {
		t.Fatalf("got %d terms, want 1", len(ps.Terms))
	}
	got := ps.Terms[0].FromProtocols
	want := []string{"bgp", "ospf", "static"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FromProtocols (flat-set) = %v, want %v", got, want)
	}
	if ps.Terms[0].Action != "accept" {
		t.Errorf("action = %q, want accept", ps.Terms[0].Action)
	}
}

// TestPolicyTermMultiProtocolHierarchical exercises the hierarchical compile
// path for the same multi-protocol "from protocol [ ... ]" list. Both the
// flat-set and hierarchical walks must collect every protocol (#2008 H18).
func TestPolicyTermMultiProtocolHierarchical(t *testing.T) {
	input := `
policy-options {
    policy-statement EXPORT-ALL {
        term t1 {
            from {
                protocol [ bgp ospf static ];
            }
            then accept;
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["EXPORT-ALL"]
	if ps == nil {
		t.Fatal("EXPORT-ALL policy-statement not found")
	}
	if len(ps.Terms) != 1 {
		t.Fatalf("got %d terms, want 1", len(ps.Terms))
	}
	got := ps.Terms[0].FromProtocols
	want := []string{"bgp", "ospf", "static"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FromProtocols (hierarchical) = %v, want %v", got, want)
	}
}

// TestPolicyTermMultiProtocolSeparateSetCommands exercises the dual-AST
// flat-set hazard called out by Copilot on #2011: an operator can add each
// protocol with its own "set ... from protocol <X>" command rather than a
// single bracket-list. Each separate SetPath lands a distinct
// ["protocol","<X>"] node under the term's "from" block. Before the fix the
// schema marked "from protocol" as a single-value leaf, so SetPath REPLACED
// the previous protocol on each command and only the last one survived; the
// term silently matched a single protocol instead of the operator's three.
// With "from protocol" marked multi the protocols become sibling leaves and
// the compiler collects every one.
func TestPolicyTermMultiProtocolSeparateSetCommands(t *testing.T) {
	tree := &ConfigTree{}
	// IMPORTANT: build via ParseSetCommand + SetPath in a loop (the documented
	// way to test flat-set syntax). NewParser() with newlines would merge all
	// lines into one node and would not reproduce the separate-command shape.
	cmds := []string{
		"set policy-options policy-statement EXPORT-ALL term t1 from protocol bgp",
		"set policy-options policy-statement EXPORT-ALL term t1 from protocol ospf",
		"set policy-options policy-statement EXPORT-ALL term t1 from protocol static",
		"set policy-options policy-statement EXPORT-ALL term t1 then accept",
	}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["EXPORT-ALL"]
	if ps == nil {
		t.Fatal("EXPORT-ALL policy-statement not found")
	}
	if len(ps.Terms) != 1 {
		t.Fatalf("got %d terms, want 1", len(ps.Terms))
	}
	got := ps.Terms[0].FromProtocols
	want := []string{"bgp", "ospf", "static"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FromProtocols (separate set commands) = %v, want %v", got, want)
	}
	if ps.Terms[0].Action != "accept" {
		t.Errorf("action = %q, want accept", ps.Terms[0].Action)
	}
}

// TestBGPGroupFamilyGatedByNeighborAddressVersion is the fail-on-revert guard
// for #2454: group-level address-family flags must be gated by each neighbor's
// own address version when inherited. A dual-stack group (family inet AND
// family inet6) must NOT mark a bare IPv4 neighbor FamilyInet6 (which made the
// renderer emit `neighbor <ipv4> activate` under `address-family ipv6 unicast`
// — invalid without RFC 5549 extended-nexthop), nor a bare IPv6 neighbor
// FamilyInet. Revert the address-version gate in compiler_protocols.go and the
// FamilyInet6/FamilyInet assertions below flip and fail.
func TestBGPGroupFamilyGatedByNeighborAddressVersion(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group dual peer-as 65002",
		"set protocols bgp group dual family inet unicast",
		"set protocols bgp group dual family inet6 unicast",
		"set protocols bgp group dual neighbor 10.0.0.2",
		"set protocols bgp group dual neighbor 2001:db8::2",
	}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Protocols.BGP == nil {
		t.Fatal("BGP config is nil")
	}
	var v4, v6 *BGPNeighbor
	for _, n := range cfg.Protocols.BGP.Neighbors {
		switch n.Address {
		case "10.0.0.2":
			v4 = n
		case "2001:db8::2":
			v6 = n
		}
	}
	if v4 == nil {
		t.Fatal("missing IPv4 neighbor 10.0.0.2")
	}
	if v6 == nil {
		t.Fatal("missing IPv6 neighbor 2001:db8::2")
	}

	// IPv4 neighbor inherits ONLY the group's inet flag.
	if !v4.FamilyInet {
		t.Error("IPv4 neighbor should inherit group FamilyInet")
	}
	if v4.FamilyInet6 {
		t.Error("IPv4 neighbor must NOT inherit group FamilyInet6 (#2454: invalid v6-unicast activation of an IPv4 address)")
	}

	// IPv6 neighbor inherits ONLY the group's inet6 flag.
	if !v6.FamilyInet6 {
		t.Error("IPv6 neighbor should inherit group FamilyInet6")
	}
	if v6.FamilyInet {
		t.Error("IPv6 neighbor must NOT inherit group FamilyInet (#2454: invalid v4-unicast activation of an IPv6 address)")
	}
}

// TestBGPGroupFamilyV4OnlyNoOverGate guards against over-gating: a v4-only
// group with an IPv4 neighbor must still keep the v4 family so the renderer
// activates it under ipv4-unicast — the no-over-gate regression check from
// #2454 (agy-10 was refuted: FRR default ipv4-unicast covers a family-less
// neighbor, but an explicit family inet group must still surface FamilyInet).
func TestBGPGroupFamilyV4OnlyNoOverGate(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group up peer-as 65002",
		"set protocols bgp group up family inet unicast",
		"set protocols bgp group up neighbor 10.0.0.2",
	}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("expected 1 BGP neighbor, got %+v", cfg.Protocols.BGP)
	}
	n := cfg.Protocols.BGP.Neighbors[0]
	if !n.FamilyInet {
		t.Error("v4-only group: IPv4 neighbor must keep FamilyInet (no over-gate)")
	}
	if n.FamilyInet6 {
		t.Error("v4-only group: IPv4 neighbor must not have FamilyInet6")
	}
}

// TestBGPGroupFamilyUnparseableAddressInheritsBoth documents the edge-case
// choice from #2454: a neighbor whose address is not a literal IP (a hostname
// or peer-group template) cannot be classified by version, so it preserves the
// pre-#2454 behavior of inheriting BOTH group family flags rather than silently
// dropping a family. The compiler must NOT crash on the unparseable address.
func TestBGPGroupFamilyUnparseableAddressInheritsBoth(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group dual peer-as 65002",
		"set protocols bgp group dual family inet unicast",
		"set protocols bgp group dual family inet6 unicast",
		"set protocols bgp group dual neighbor peer.example.com",
	}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("expected 1 BGP neighbor, got %+v", cfg.Protocols.BGP)
	}
	n := cfg.Protocols.BGP.Neighbors[0]
	if n.Address != "peer.example.com" {
		t.Fatalf("unexpected neighbor address %q", n.Address)
	}
	if !n.FamilyInet || !n.FamilyInet6 {
		t.Errorf("unparseable address should inherit BOTH group families, got inet=%v inet6=%v", n.FamilyInet, n.FamilyInet6)
	}
}
