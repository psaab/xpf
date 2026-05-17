package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestLexer(t *testing.T) {
	input := `security {
    zones {
        security-zone trust {
            interfaces {
                eth0.0;
            }
        }
    }
}`
	lex := NewLexer(input)
	expected := []struct {
		typ TokenType
		val string
	}{{TokenIdentifier, "security"}, {TokenLBrace, "{"}, {TokenIdentifier, "zones"}, {TokenLBrace, "{"}, {TokenIdentifier, "security-zone"}, {TokenIdentifier, "trust"}, {TokenLBrace, "{"}, {TokenIdentifier, "interfaces"}, {TokenLBrace, "{"}, {TokenIdentifier, "eth0.0"}, {TokenSemicolon, ";"}, {TokenRBrace, "}"}, {TokenRBrace, "}"}, {TokenRBrace, "}"}, {TokenRBrace, "}"}, {TokenEOF, ""}}
	for i, exp := range expected {
		tok := lex.Next()
		if tok.Type != exp.typ {
			t.Errorf("token %d: expected type %s, got %s (value=%q)", i, exp.typ, tok.Type, tok.Value)
		}
		if exp.val != "" && tok.Value != exp.val {
			t.Errorf("token %d: expected value %q, got %q", i, exp.val, tok.Value)
		}
	}
}

func TestLexerComments(t *testing.T) {
	input := `# this is a comment
security {
    /* block comment */
    zones {
        // line comment
        security-zone trust;
    }
}`
	lex := NewLexer(input)
	tok := lex.Next()
	if tok.Type != TokenIdentifier || tok.Value != "security" {
		t.Errorf("expected 'security', got %s %q", tok.Type, tok.Value)
	}
}

func TestBracketList(t *testing.T) {
	input := `security {
    policies {
        from-zone trust to-zone untrust {
            policy allow-all {
                match {
                    source-address any;
                    destination-address [ server1 server2 server3 ];
                    application [ junos-http junos-https ];
                }
                then {
                    permit;
                }
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
	if len(cfg.Security.Policies) == 0 {
		t.Fatal("no policies compiled")
	}
	pol := cfg.Security.Policies[0]
	if len(pol.Policies) == 0 {
		t.Fatal("no policies compiled")
	}
	rule := pol.Policies[0]
	if len(rule.Match.DestinationAddresses) != 3 {
		t.Errorf("expected 3 dst addresses, got %d: %v", len(rule.Match.DestinationAddresses), rule.Match.DestinationAddresses)
	}
	if len(rule.Match.Applications) != 2 {
		t.Errorf("expected 2 applications, got %d: %v", len(rule.Match.Applications), rule.Match.Applications)
	}
}

func TestParseHierarchical(t *testing.T) {
	input := `security {
    zones {
        security-zone trust {
            interfaces {
                eth0.0;
            }
            host-inbound-traffic {
                system-services {
                    ssh;
                    ping;
                }
            }
        }
        security-zone untrust {
            interfaces {
                eth1.0;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                match {
                    source-address any;
                    destination-address any;
                    application junos-http;
                }
                then {
                    permit;
                    log {
                        session-init;
                    }
                }
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	secNode := tree.FindChild("security")
	if secNode == nil {
		t.Fatal("missing 'security' node")
	}
	zonesNode := secNode.FindChild("zones")
	if zonesNode == nil {
		t.Fatal("missing 'zones' node")
	}
	trustZones := zonesNode.FindChildren("security-zone")
	if len(trustZones) != 2 {
		t.Fatalf("expected 2 security-zone nodes, got %d", len(trustZones))
	}
	if trustZones[0].Keys[1] != "trust" {
		t.Errorf("expected first zone 'trust', got %q", trustZones[0].Keys[1])
	}
	if trustZones[1].Keys[1] != "untrust" {
		t.Errorf("expected second zone 'untrust', got %q", trustZones[1].Keys[1])
	}
	ifacesNode := trustZones[0].FindChild("interfaces")
	if ifacesNode == nil || len(ifacesNode.Children) != 1 {
		t.Fatal("trust zone missing interfaces")
	}
	if ifacesNode.Children[0].Keys[0] != "eth0.0" {
		t.Errorf("expected interface 'eth0.0', got %q", ifacesNode.Children[0].Keys[0])
	}
	polNode := secNode.FindChild("policies")
	if polNode == nil {
		t.Fatal("missing 'policies' node")
	}
	zpNode := polNode.FindChild("from-zone")
	if zpNode == nil {
		t.Fatal("missing 'from-zone' node")
	}
	if zpNode.Keys[1] != "trust" || zpNode.Keys[3] != "untrust" {
		t.Errorf("expected from-zone trust to-zone untrust, got %v", zpNode.Keys)
	}
}

func TestCompileConfig(t *testing.T) {
	input := `security {
    zones {
        security-zone trust {
            interfaces {
                eth0.0;
            }
        }
        security-zone untrust {
            interfaces {
                eth1.0;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                match {
                    source-address any;
                    destination-address any;
                    application junos-http;
                }
                then {
                    permit;
                }
            }
        }
    }
    address-book {
        global {
            address web-server 10.0.1.100/32;
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
	if len(cfg.Security.Zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(cfg.Security.Zones))
	}
	trustZone := cfg.Security.Zones["trust"]
	if trustZone == nil {
		t.Fatal("missing trust zone")
	}
	if len(trustZone.Interfaces) != 1 || trustZone.Interfaces[0] != "eth0.0" {
		t.Errorf("trust zone interfaces: %v", trustZone.Interfaces)
	}
	if len(cfg.Security.Policies) != 1 {
		t.Fatalf("expected 1 zone-pair policy, got %d", len(cfg.Security.Policies))
	}
	zpp := cfg.Security.Policies[0]
	if zpp.FromZone != "trust" || zpp.ToZone != "untrust" {
		t.Errorf("zone pair: from=%s to=%s", zpp.FromZone, zpp.ToZone)
	}
	if len(zpp.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(zpp.Policies))
	}
	pol := zpp.Policies[0]
	if pol.Name != "allow-web" {
		t.Errorf("policy name: %s", pol.Name)
	}
	if pol.Action != PolicyPermit {
		t.Errorf("policy action: %d", pol.Action)
	}
	if len(pol.Match.Applications) != 1 || pol.Match.Applications[0] != "junos-http" {
		t.Errorf("policy applications: %v", pol.Match.Applications)
	}
	if cfg.Security.AddressBook == nil {
		t.Fatal("missing address book")
	}
	addr := cfg.Security.AddressBook.Addresses["web-server"]
	if addr == nil {
		t.Fatal("missing web-server address")
	}
	if addr.Value != "10.0.1.100/32" {
		t.Errorf("address value: %s", addr.Value)
	}
}

func TestSetCommand(t *testing.T) {
	path, err := ParseSetCommand("set security zones security-zone trust interfaces eth0.0")
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"security", "zones", "security-zone", "trust", "interfaces", "eth0.0"}
	if len(path) != len(expected) {
		t.Fatalf("expected %d parts, got %d: %v", len(expected), len(path), path)
	}
	for i := range expected {
		if path[i] != expected[i] {
			t.Errorf("part %d: expected %q, got %q", i, expected[i], path[i])
		}
	}
}

func TestFormatCanonicalOrder(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set security policies from-zone trust to-zone untrust policy p1 then reject", "set security policies from-zone trust to-zone untrust policy p1 then log session-init", "set security policies from-zone trust to-zone untrust policy p1 match source-address any", "set security policies from-zone trust to-zone untrust policy p1 match destination-address any", "set security policies from-zone trust to-zone untrust policy p1 match application any"}
	for _, cmd := range setCommands {
		parts, _ := ParseSetCommand(cmd)
		tree.SetPath(parts)
	}
	output := tree.Format()
	matchPos := strings.Index(output, "match {")
	thenPos := strings.Index(output, "then {")
	if matchPos < 0 || thenPos < 0 {
		t.Fatalf("expected both match and then in output:\n%s", output)
	}
	if matchPos > thenPos {
		t.Errorf("match should come before then in canonical output:\n%s", output)
	}
}

func TestFormatRoundTrip(t *testing.T) {
	input := `security {
    zones {
        security-zone trust {
            interfaces {
                eth0.0;
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
	output := tree.Format()
	inputNorm := strings.TrimSpace(input)
	outputNorm := strings.TrimSpace(output)
	if inputNorm != outputNorm {
		t.Errorf("format round-trip mismatch:\n--- input ---\n%s\n--- output ---\n%s", inputNorm, outputNorm)
	}
}

func TestFormatRoundTripQuotedKeys(t *testing.T) {
	input := `groups {
    node0 {
        interfaces {
            ge-0-0-0 {
                unit 0 {
                    family inet {
                        address 10.0.1.10/24;
                    }
                }
            }
        }
    }
}
apply-groups "${node}";
`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("initial parse errors: %v", errs)
	}
	output := tree.Format()
	tree2, errs2 := NewParser(output).Parse()
	if len(errs2) > 0 {
		t.Fatalf("re-parse errors after Format: %v\nformatted output:\n%s", errs2, output)
	}
	output2 := tree2.Format()
	if output != output2 {
		t.Errorf("double round-trip mismatch:\n--- first ---\n%s\n--- second ---\n%s", output, output2)
	}
}

func TestFormatSetQuotedKeys(t *testing.T) {
	input := `apply-groups "${node}";
`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	setOutput := tree.FormatSet()
	if !strings.Contains(setOutput, `"${node}"`) {
		t.Errorf("FormatSet missing quoted ${node}:\n%s", setOutput)
	}
}

func TestSetPathSchema(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set security zones security-zone trust interfaces eth0.0", "set security zones security-zone trust host-inbound-traffic system-services ssh", "set security zones security-zone trust host-inbound-traffic system-services ping", "set security zones security-zone trust screen untrust-screen", "set security zones security-zone untrust interfaces eth1.0", "set security policies from-zone trust to-zone untrust policy allow-web match source-address any", "set security policies from-zone trust to-zone untrust policy allow-web match destination-address any", "set security policies from-zone trust to-zone untrust policy allow-web match application junos-http", "set security policies from-zone trust to-zone untrust policy allow-web then permit", "set security policies from-zone trust to-zone untrust policy allow-web then log session-init", "set security policies from-zone trust to-zone untrust policy allow-web then count", "set security screen ids-option myscreen tcp land", "set security screen ids-option myscreen icmp ping-death", "set security address-book global address srv1 10.0.1.10/32", "set security address-book global address-set servers address srv1", "set interfaces eth0 unit 0 family inet address 10.0.1.1/24", "set applications application my-app protocol tcp", "set applications application my-app destination-port 8080"}
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
	if len(cfg.Security.Zones) != 2 {
		t.Errorf("expected 2 zones, got %d", len(cfg.Security.Zones))
	}
	trustZone := cfg.Security.Zones["trust"]
	if trustZone == nil {
		t.Fatal("missing trust zone")
	}
	if len(trustZone.Interfaces) != 1 || trustZone.Interfaces[0] != "eth0.0" {
		t.Errorf("trust zone interfaces: %v", trustZone.Interfaces)
	}
	if trustZone.ScreenProfile != "untrust-screen" {
		t.Errorf("trust zone screen profile: %q", trustZone.ScreenProfile)
	}
	if trustZone.HostInboundTraffic == nil {
		t.Fatal("trust zone missing host-inbound-traffic")
	}
	if len(trustZone.HostInboundTraffic.SystemServices) != 2 {
		t.Errorf("expected 2 system-services, got %d", len(trustZone.HostInboundTraffic.SystemServices))
	}
	if len(cfg.Security.Policies) != 1 {
		t.Fatalf("expected 1 zone-pair policy, got %d", len(cfg.Security.Policies))
	}
	zpp := cfg.Security.Policies[0]
	if zpp.FromZone != "trust" || zpp.ToZone != "untrust" {
		t.Errorf("zone pair: from=%s to=%s", zpp.FromZone, zpp.ToZone)
	}
	pol := zpp.Policies[0]
	if pol.Action != PolicyPermit {
		t.Errorf("policy action: %d", pol.Action)
	}
	if pol.Log == nil || !pol.Log.SessionInit {
		t.Error("policy should have log session-init")
	}
	if !pol.Count {
		t.Error("policy should have count")
	}
	screen := cfg.Security.Screen["myscreen"]
	if screen == nil {
		t.Fatal("missing screen profile myscreen")
	}
	if !screen.TCP.Land {
		t.Error("screen should have tcp land")
	}
	if !screen.ICMP.PingDeath {
		t.Error("screen should have icmp ping-death")
	}
	if cfg.Security.AddressBook == nil {
		t.Fatal("missing address book")
	}
	addr := cfg.Security.AddressBook.Addresses["srv1"]
	if addr == nil || addr.Value != "10.0.1.10/32" {
		t.Errorf("address srv1: %+v", addr)
	}
	addrSet := cfg.Security.AddressBook.AddressSets["servers"]
	if addrSet == nil || len(addrSet.Addresses) != 1 {
		t.Errorf("address-set servers: %+v", addrSet)
	}
	ifc := cfg.Interfaces.Interfaces["eth0"]
	if ifc == nil {
		t.Fatal("missing interface eth0")
	}
	unit := ifc.Units[0]
	if unit == nil || len(unit.Addresses) != 1 || unit.Addresses[0] != "10.0.1.1/24" {
		t.Errorf("interface eth0 unit 0: %+v", unit)
	}
	app := cfg.Applications.Applications["my-app"]
	if app == nil {
		t.Fatal("missing application my-app")
	}
	if app.Protocol != "tcp" || app.DestinationPort != "8080" {
		t.Errorf("application my-app: proto=%s port=%s", app.Protocol, app.DestinationPort)
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
	if len(cfg2.Security.Zones) != len(cfg.Security.Zones) {
		t.Error("round-trip zone count mismatch")
	}
}

func TestSetPathSingleValueDedup(t *testing.T) {
	tree := &ConfigTree{}
	sysNode := &Node{Keys: []string{"system"}, Children: []*Node{{Keys: []string{"host-name", "old-fw1"}, IsLeaf: true}, {Keys: []string{"host-name", "old-fw2"}, IsLeaf: true}, {Keys: []string{"host-name", "old-fw3"}, IsLeaf: true}, {Keys: []string{"domain-name", "example.com"}, IsLeaf: true}}}
	tree.Children = append(tree.Children, sysNode)
	path, err := ParseSetCommand("set system host-name new-fw")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	var hostNames []string // Count host-name entries in the system node.

	for _, child := range sysNode.Children {
		if child.IsLeaf && len(child.Keys) > 0 && child.Keys[0] == "host-name" {
			hostNames = append(hostNames, child.Keys[1])
		}
	}
	if len(hostNames) != 1 {
		t.Fatalf("expected 1 host-name entry, got %d: %v", len(hostNames), hostNames)
	}
	if hostNames[0] != "new-fw" {
		t.Errorf("expected host-name new-fw, got %s", hostNames[0])
	}
	var hasDomain bool
	// Verify domain-name is preserved.
	for _, child := range sysNode.Children {
		if child.IsLeaf && len(child.Keys) > 0 && child.Keys[0] == "domain-name" {
			hasDomain = true
		}
	}
	if !hasDomain {
		t.Error("domain-name entry was incorrectly removed")
	}
}

func TestDeletePath(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set security zones security-zone trust interfaces eth0.0", "set security zones security-zone trust interfaces eth2.0", "set security zones security-zone trust host-inbound-traffic system-services ssh", "set security zones security-zone untrust interfaces eth1.0", "set security address-book global address srv1 10.0.1.10/32", "set security address-book global address srv2 10.0.2.10/32", "set security policies from-zone trust to-zone untrust policy allow-web match source-address any", "set security policies from-zone trust to-zone untrust policy allow-web match destination-address any", "set security policies from-zone trust to-zone untrust policy allow-web match application junos-http", "set security policies from-zone trust to-zone untrust policy allow-web then permit"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	path, _ := ParseSetCommand("delete security zones security-zone trust interfaces eth2.0")
	if err := tree.DeletePath(path); err != nil {
		t.Fatalf("delete interface leaf: %v", err)
	}
	setOut := tree.FormatSet()
	if strings.Contains(setOut, "eth2.0") {
		t.Error("eth2.0 should have been deleted")
	}
	if !strings.Contains(setOut, "eth0.0") {
		t.Error("eth0.0 should still exist")
	}
	path, _ = ParseSetCommand("delete security address-book global address srv1")
	if err := tree.DeletePath(path); err != nil {
		t.Fatalf("delete address by prefix: %v", err)
	}
	setOut = tree.FormatSet()
	if strings.Contains(setOut, "srv1") {
		t.Error("srv1 should have been deleted")
	}
	if !strings.Contains(setOut, "srv2") {
		t.Error("srv2 should still exist")
	}
	path, _ = ParseSetCommand("delete security zones security-zone untrust")
	if err := tree.DeletePath(path); err != nil {
		t.Fatalf("delete container: %v", err)
	}
	setOut = tree.FormatSet()
	if strings.Contains(setOut, "security-zone untrust") {
		t.Error("untrust zone should have been deleted")
	}
	if !strings.Contains(setOut, "security-zone trust") {
		t.Error("trust zone should still exist")
	}
	path, _ = ParseSetCommand("delete security zones security-zone nonexistent")
	if err := tree.DeletePath(path); err == nil {
		t.Error("deleting nonexistent path should return error")
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig after deletions: %v", err)
	}
	if len(cfg.Security.Zones) != 1 {
		t.Errorf("expected 1 zone after deletions, got %d", len(cfg.Security.Zones))
	}
	if cfg.Security.Zones["trust"] == nil {
		t.Error("trust zone should remain after deletions")
	}
	if len(cfg.Security.Zones["trust"].Interfaces) != 1 {
		t.Errorf("trust zone should have 1 interface, got %d", len(cfg.Security.Zones["trust"].Interfaces))
	}
}

func TestInsertBeforeAfter(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set security policies from-zone trust to-zone untrust policy first match source-address any", "set security policies from-zone trust to-zone untrust policy first then permit", "set security policies from-zone trust to-zone untrust policy second match source-address any", "set security policies from-zone trust to-zone untrust policy second then permit", "set security policies from-zone trust to-zone untrust policy third match source-address any", "set security policies from-zone trust to-zone untrust policy third then permit"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	getPolicyOrder := func() []string {
		var policies *[]* // Navigate to from-zone trust to-zone untrust
		Node
		for _, c := range tree.Children {
			if len(c.Keys) > 0 && c.Keys[0] == "security" {
				for _, c2 := range c.Children {
					if len(c2.Keys) > 0 && c2.Keys[0] == "policies" {
						for _, c3 := range c2.Children {
							if len(c3.Keys) >= 4 && c3.Keys[1] == "trust" && c3.Keys[3] == "untrust" {
								policies = &c3.Children
								break
							}
						}
					}
				}
			}
		}
		if policies == nil {
			t.Fatal("could not find policies node")
		}
		var names []string
		for _, p := range *policies {
			if len(p.Keys) >= 2 {
				names = append(names, p.Keys[1])
			}
		}
		return names
	}
	order := getPolicyOrder()
	if len(order) != 3 || order[0] != "first" || order[1] != "second" || order[2] != "third" {
		t.Fatalf("initial order wrong: %v", order)
	}
	elemPath := []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "third"}
	refPath := []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "first"}
	if err := tree.InsertBefore(elemPath, refPath); err != nil {
		t.Fatalf("InsertBefore: %v", err)
	}
	order = getPolicyOrder()
	if len(order) != 3 || order[0] != "third" || order[1] != "first" || order[2] != "second" {
		t.Fatalf("after InsertBefore: expected [third first second], got %v", order)
	}
	elemPath = []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "first"}
	refPath = []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "second"}
	if err := tree.InsertAfter(elemPath, refPath); err != nil {
		t.Fatalf("InsertAfter: %v", err)
	}
	order = getPolicyOrder()
	if len(order) != 3 || order[0] != "third" || order[1] != "second" || order[2] != "first" {
		t.Fatalf("after InsertAfter: expected [third second first], got %v", order)
	}
	elemPath = []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "nonexistent"}
	refPath = []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "first"}
	if err := tree.InsertBefore(elemPath, refPath); err == nil {
		t.Error("inserting nonexistent element should return error")
	}
	elemPath = []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "first"}
	refPath = []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "nonexistent"}
	if err := tree.InsertBefore(elemPath, refPath); err == nil {
		t.Error("inserting before nonexistent reference should return error")
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig after inserts: %v", err)
	}
	var zonePair *ZonePairPolicies
	for _, zp := range cfg.Security.Policies {
		if zp.FromZone == "trust" && zp.ToZone == "untrust" {
			zonePair = zp
			break
		}
	}
	if zonePair == nil {
		t.Fatal("zone pair trust->untrust not found after insert")
	}
	if len(zonePair.Policies) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(zonePair.Policies))
	}
	if zonePair.Policies[0].Name != "third" || zonePair.Policies[1].Name != "second" || zonePair.Policies[2].Name != "first" {
		t.Errorf("compiled policy order wrong: %s, %s, %s", zonePair.Policies[0].Name, zonePair.Policies[1].Name, zonePair.Policies[2].Name)
	}
}

func TestInsertFirewallFilterTerms(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set firewall family inet filter my-filter term allow-ssh from protocol tcp", "set firewall family inet filter my-filter term allow-ssh from destination-port 22", "set firewall family inet filter my-filter term allow-ssh then accept", "set firewall family inet filter my-filter term allow-http from protocol tcp", "set firewall family inet filter my-filter term allow-http from destination-port 80", "set firewall family inet filter my-filter term allow-http then accept", "set firewall family inet filter my-filter term deny-all then discard"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	elemPath := []string{"firewall", "family", "inet", "filter", "my-filter", "term", "deny-all"}
	refPath := []string{"firewall", "family", "inet", "filter", "my-filter", "term", "allow-ssh"}
	if err := tree.InsertBefore(elemPath, refPath); err != nil {
		t.Fatalf("InsertBefore: %v", err)
	}
	out := tree.FormatSet()
	denyIdx := strings.Index(out, "term deny-all")
	sshIdx := strings.Index(out, "term allow-ssh")
	httpIdx := strings.Index(out, "term allow-http")
	if denyIdx < 0 || sshIdx < 0 || httpIdx < 0 {
		t.Fatalf("missing terms in output:\n%s", out)
	}
	if denyIdx >= sshIdx {
		t.Errorf("deny-all should be before allow-ssh")
	}
	if sshIdx >= httpIdx {
		t.Errorf("allow-ssh should be before allow-http")
	}
}

func TestApplicationSet(t *testing.T) {
	input := `applications {
    application my-app {
        protocol tcp;
        destination-port 8080;
    }
    application-set web-apps {
        application junos-http;
        application junos-https;
        application my-app;
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                eth0.0;
            }
        }
        security-zone untrust {
            interfaces {
                eth1.0;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                match {
                    source-address any;
                    destination-address any;
                    application web-apps;
                }
                then {
                    permit;
                }
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
	if len(cfg.Applications.ApplicationSets) != 1 {
		t.Fatalf("expected 1 application-set, got %d", len(cfg.Applications.ApplicationSets))
	}
	as := cfg.Applications.ApplicationSets["web-apps"]
	if as == nil {
		t.Fatal("missing application-set web-apps")
	}
	if len(as.Applications) != 3 {
		t.Errorf("expected 3 members, got %d: %v", len(as.Applications), as.Applications)
	}
	expanded, err := ExpandApplicationSet("web-apps", &cfg.Applications)
	if err != nil {
		t.Fatalf("expand error: %v", err)
	}
	if len(expanded) != 3 {
		t.Errorf("expected 3 expanded apps, got %d: %v", len(expanded), expanded)
	}
	pol := cfg.Security.Policies[0].Policies[0]
	if len(pol.Match.Applications) != 1 || pol.Match.Applications[0] != "web-apps" {
		t.Errorf("policy apps: %v", pol.Match.Applications)
	}
	tree2 := &ConfigTree{}
	setCommands := []string{"set applications application-set web-apps application junos-http", "set applications application-set web-apps application junos-https"}
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
	as2 := cfg2.Applications.ApplicationSets["web-apps"]
	if as2 == nil {
		t.Fatal("missing application-set from set syntax")
	}
	if len(as2.Applications) != 2 {
		t.Errorf("expected 2 members from set syntax, got %d", len(as2.Applications))
	}
}

func TestNestedApplicationSet(t *testing.T) {
	input := `applications {
    application app-a {
        protocol tcp;
        destination-port 80;
    }
    application app-b {
        protocol tcp;
        destination-port 443;
    }
    application app-c {
        protocol udp;
        destination-port 53;
    }
    application-set inner-set {
        application app-a;
        application app-b;
    }
    application-set outer-set {
        application inner-set;
        application app-c;
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
	expanded, err := ExpandApplicationSet("outer-set", &cfg.Applications)
	if err != nil {
		t.Fatalf("expand error: %v", err)
	}
	if len(expanded) != 3 {
		t.Fatalf("expected 3 expanded apps, got %d: %v", len(expanded), expanded)
	}
	want := map[string]bool{"app-a": true, "app-b": true, "app-c": true}
	for _, a := range expanded {
		if !want[a] {
			t.Errorf("unexpected expanded app: %q", a)
		}
	}
	inner, err := ExpandApplicationSet("inner-set", &cfg.Applications)
	if err != nil {
		t.Fatalf("inner expand error: %v", err)
	}
	if len(inner) != 2 {
		t.Fatalf("inner: expected 2 apps, got %d: %v", len(inner), inner)
	}
}

func TestFormatSet(t *testing.T) {
	input := `security {
    zones {
        security-zone trust {
            interfaces {
                eth0.0;
            }
        }
    }
}`
	parser := NewParser(input)
	tree, _ := parser.Parse()
	setOutput := tree.FormatSet()
	if !strings.Contains(setOutput, "set security zones security-zone trust interfaces eth0.0") {
		t.Errorf("set format missing expected line:\n%s", setOutput)
	}
}

func TestRPMConfig(t *testing.T) {
	input := `services {
    rpm {
        probe isp-comcast {
            test icmp-check {
                probe-type icmp-ping;
                target 1.1.1.1;
                probe-interval 5;
                probe-count 3;
                test-interval 30;
                thresholds {
                    successive-loss 3;
                }
            }
            test http-check {
                probe-type http-get;
                target http://1.1.1.1;
                test-interval 60;
            }
        }
        probe isp-att {
            test tcp-check {
                probe-type tcp-ping;
                target 8.8.8.8;
                destination-port 443;
                source-address 10.0.1.1;
                routing-instance att-vr;
                thresholds {
                    successive-loss 5;
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
		t.Fatalf("compile error: %v", err)
	}
	if cfg.Services.RPM == nil {
		t.Fatal("expected RPM to be non-nil")
	}
	if len(cfg.Services.RPM.Probes) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(cfg.Services.RPM.Probes))
	}
	comcast := cfg.Services.RPM.Probes["isp-comcast"]
	if comcast == nil {
		t.Fatal("expected probe isp-comcast")
	}
	if len(comcast.Tests) != 2 {
		t.Fatalf("expected 2 tests, got %d", len(comcast.Tests))
	}
	icmpTest := comcast.Tests["icmp-check"]
	if icmpTest == nil {
		t.Fatal("expected test icmp-check")
	}
	if icmpTest.ProbeType != "icmp-ping" {
		t.Errorf("probe type: got %q, want icmp-ping", icmpTest.ProbeType)
	}
	if icmpTest.Target != "1.1.1.1" {
		t.Errorf("target: got %q, want 1.1.1.1", icmpTest.Target)
	}
	if icmpTest.ProbeInterval != 5 {
		t.Errorf("probe-interval: got %d, want 5", icmpTest.ProbeInterval)
	}
	if icmpTest.ProbeCount != 3 {
		t.Errorf("probe-count: got %d, want 3", icmpTest.ProbeCount)
	}
	if icmpTest.TestInterval != 30 {
		t.Errorf("test-interval: got %d, want 30", icmpTest.TestInterval)
	}
	if icmpTest.ThresholdSuccessive != 3 {
		t.Errorf("successive-loss: got %d, want 3", icmpTest.ThresholdSuccessive)
	}
	httpTest := comcast.Tests["http-check"]
	if httpTest == nil {
		t.Fatal("expected test http-check")
	}
	if httpTest.ProbeType != "http-get" {
		t.Errorf("probe type: got %q, want http-get", httpTest.ProbeType)
	}
	att := cfg.Services.RPM.Probes["isp-att"]
	if att == nil {
		t.Fatal("expected probe isp-att")
	}
	tcpTest := att.Tests["tcp-check"]
	if tcpTest == nil {
		t.Fatal("expected test tcp-check")
	}
	if tcpTest.ProbeType != "tcp-ping" {
		t.Errorf("probe type: got %q, want tcp-ping", tcpTest.ProbeType)
	}
	if tcpTest.Target != "8.8.8.8" {
		t.Errorf("target: got %q, want 8.8.8.8", tcpTest.Target)
	}
	if tcpTest.DestPort != 443 {
		t.Errorf("dest port: got %d, want 443", tcpTest.DestPort)
	}
	if tcpTest.SourceAddress != "10.0.1.1" {
		t.Errorf("source-address: got %q, want 10.0.1.1", tcpTest.SourceAddress)
	}
	if tcpTest.RoutingInstance != "att-vr" {
		t.Errorf("routing-instance: got %q, want att-vr", tcpTest.RoutingInstance)
	}
	if tcpTest.ThresholdSuccessive != 5 {
		t.Errorf("successive-loss: got %d, want 5", tcpTest.ThresholdSuccessive)
	}
	tree2 := &ConfigTree{}
	setCommands := []string{"set services rpm probe monitor test ping-test probe-type icmp-ping", "set services rpm probe monitor test ping-test target 8.8.4.4", "set services rpm probe monitor test ping-test probe-interval 10", "set services rpm probe monitor test ping-test test-interval 60"}
	for _, cmd := range setCommands {
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
	if cfg2.Services.RPM == nil {
		t.Fatal("set syntax: expected RPM")
	}
	monitor := cfg2.Services.RPM.Probes["monitor"]
	if monitor == nil {
		t.Fatal("set syntax: expected probe monitor")
	}
	pingTest := monitor.Tests["ping-test"]
	if pingTest == nil {
		t.Fatal("set syntax: expected test ping-test")
	}
	if pingTest.ProbeType != "icmp-ping" {
		t.Errorf("set syntax probe type: got %q, want icmp-ping", pingTest.ProbeType)
	}
	if pingTest.Target != "8.8.4.4" {
		t.Errorf("set syntax target: got %q, want 8.8.4.4", pingTest.Target)
	}
	if pingTest.ProbeInterval != 10 {
		t.Errorf("set syntax probe-interval: got %d, want 10", pingTest.ProbeInterval)
	}
	if pingTest.TestInterval != 60 {
		t.Errorf("set syntax test-interval: got %d, want 60", pingTest.TestInterval)
	}
}

func TestRPMTargetURLAndProbeLimit(t *testing.T) {
	input := `services {
    rpm {
        probe web-check {
            test http-url {
                probe-type http-get;
                target url http://10.0.1.1/health;
                probe-limit 5;
            }
            test plain-ip {
                probe-type icmp-ping;
                target 8.8.8.8;
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
	probe := cfg.Services.RPM.Probes["web-check"]
	if probe == nil {
		t.Fatal("expected probe web-check")
	}
	httpTest := probe.Tests["http-url"]
	if httpTest == nil {
		t.Fatal("expected test http-url")
	}
	if httpTest.Target != "http://10.0.1.1/health" {
		t.Errorf("target url: got %q, want http://10.0.1.1/health", httpTest.Target)
	}
	if httpTest.ProbeLimit != 5 {
		t.Errorf("probe-limit: got %d, want 5", httpTest.ProbeLimit)
	}
	plainTest := probe.Tests["plain-ip"]
	if plainTest == nil {
		t.Fatal("expected test plain-ip")
	}
	if plainTest.Target != "8.8.8.8" {
		t.Errorf("plain target: got %q, want 8.8.8.8", plainTest.Target)
	}
	tree2 := &ConfigTree{}
	setCommands := []string{"set services rpm probe web2 test url-test probe-type http-get", "set services rpm probe web2 test url-test target url http://example.com", "set services rpm probe web2 test url-test probe-limit 3"}
	for _, cmd := range setCommands {
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
	probe2 := cfg2.Services.RPM.Probes["web2"]
	if probe2 == nil {
		t.Fatal("set syntax: expected probe web2")
	}
	urlTest := probe2.Tests["url-test"]
	if urlTest == nil {
		t.Fatal("set syntax: expected test url-test")
	}
	if urlTest.Target != "http://example.com" {
		t.Errorf("set syntax target url: got %q, want http://example.com", urlTest.Target)
	}
	if urlTest.ProbeLimit != 3 {
		t.Errorf("set syntax probe-limit: got %d, want 3", urlTest.ProbeLimit)
	}
}

func TestRPMRootProbeLimitSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set services rpm probe-limit 3",
		"set services rpm probe web2 test inherited target 8.8.8.8",
		"set services rpm probe web2 test explicit target 1.1.1.1",
		"set services rpm probe web2 test explicit probe-limit 7",
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
		t.Fatalf("set-command compile error: %v", err)
	}
	probe := cfg.Services.RPM.Probes["web2"]
	if probe == nil {
		t.Fatal("expected probe web2")
	}
	if got := probe.Tests["inherited"].ProbeLimit; got != 3 {
		t.Fatalf("inherited probe-limit = %d, want 3", got)
	}
	if got := probe.Tests["explicit"].ProbeLimit; got != 7 {
		t.Fatalf("explicit probe-limit = %d, want 7", got)
	}
}

func TestMultipleSNATRules(t *testing.T) {
	input := `security {
    zones {
        security-zone trust {
            interfaces { eth0.0; }
        }
        security-zone untrust {
            interfaces { eth1.0; }
        }
    }
    nat {
        source {
            pool wan-pool {
                address 203.0.113.1/32;
            }
            pool backup-pool {
                address 203.0.113.2/32;
            }
            rule-set trust-to-untrust {
                from zone trust;
                to zone untrust;
                rule web-traffic {
                    match {
                        source-address 10.0.1.0/24;
                        destination-address 0.0.0.0/0;
                    }
                    then {
                        source-nat {
                            pool wan-pool;
                        }
                    }
                }
                rule backup-traffic {
                    match {
                        source-address 10.0.2.0/24;
                    }
                    then {
                        source-nat {
                            pool backup-pool;
                        }
                    }
                }
                rule default-snat {
                    match {
                        source-address 0.0.0.0/0;
                    }
                    then {
                        source-nat {
                            interface;
                        }
                    }
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
		t.Fatalf("compile error: %v", err)
	}
	if len(cfg.Security.NAT.Source) != 1 {
		t.Fatalf("expected 1 source rule-set, got %d", len(cfg.Security.NAT.Source))
	}
	rs := cfg.Security.NAT.Source[0]
	if rs.FromZone != "trust" || rs.ToZone != "untrust" {
		t.Errorf("rule-set zones: from=%s to=%s", rs.FromZone, rs.ToZone)
	}
	if len(rs.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rs.Rules))
	}
	r1 := rs.Rules[0]
	if r1.Name != "web-traffic" {
		t.Errorf("rule 1 name: %s", r1.Name)
	}
	if r1.Match.SourceAddress != "10.0.1.0/24" {
		t.Errorf("rule 1 src: %s", r1.Match.SourceAddress)
	}
	if r1.Then.PoolName != "wan-pool" {
		t.Errorf("rule 1 pool: %s", r1.Then.PoolName)
	}
	r3 := rs.Rules[2]
	if r3.Name != "default-snat" {
		t.Errorf("rule 3 name: %s", r3.Name)
	}
	if !r3.Then.Interface {
		t.Error("rule 3 should use interface SNAT")
	}
	if cfg.Security.NAT.SourcePools == nil {
		t.Fatal("source pools nil")
	}
	if len(cfg.Security.NAT.SourcePools) != 2 {
		t.Errorf("expected 2 source pools, got %d", len(cfg.Security.NAT.SourcePools))
	}
}

func TestSetPathFamilyCompoundKey(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set interfaces reth1 unit 0 family inet address 10.0.89.1/24", "set interfaces reth1 unit 0 family inet6 address 2001:559:8585:ef01::1/64", "set interfaces reth1 unit 0 family inet6 address 2001:559:8585:df01::1/64"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	unit0 := tree.Children[0].Children[0].Children[0]
	if unit0 == nil {
		t.Fatal("missing unit 0")
	}
	for _, child := range unit0.Children {
		if len(child.Keys) == 1 && child.Keys[0] == "family" {
			t.Errorf("found bare 'family' node — should be compound key ['family','inet'] or ['family','inet6']")
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["reth1"]
	if ifc == nil {
		t.Fatal("missing interface reth1")
	}
	unit := ifc.Units[0]
	if unit == nil {
		t.Fatal("missing unit 0")
	}
	if len(unit.Addresses) != 3 {
		t.Errorf("expected 3 addresses, got %d: %v", len(unit.Addresses), unit.Addresses)
	}
}

func TestEdgeCases(t *testing.T) {
	input := `security {
    zones {
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("empty block parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("empty block compile error: %v", err)
	}
	if len(cfg.Security.Zones) != 0 {
		t.Errorf("expected 0 zones from empty block, got %d", len(cfg.Security.Zones))
	}
	input2 := `security {
    zones {
        security-zone test {
            interfaces {
                eth0.0;
            }
        }
    }
}
`
	parser2 := NewParser(input2)
	tree2, errs2 := parser2.Parse()
	if len(errs2) > 0 {
		t.Fatalf("trailing semicolon parse errors: %v", errs2)
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("trailing semicolon compile error: %v", err)
	}
	if len(cfg2.Security.Zones) != 1 {
		t.Errorf("expected 1 zone, got %d", len(cfg2.Security.Zones))
	}
	tree3 := &ConfigTree{}
	deepCommands := []string{"set routing-instances deep-vr instance-type virtual-router", "set routing-instances deep-vr routing-options static route 10.0.0.0/8 next-hop 192.168.1.1", "set routing-instances deep-vr protocols ospf area 0.0.0.0 interface eth0", "set routing-instances deep-vr protocols bgp local-as 65001", "set routing-instances deep-vr protocols bgp group peer peer-as 65002", "set routing-instances deep-vr protocols bgp group peer neighbor 10.1.0.1"}
	for _, cmd := range deepCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree3.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	cfg3, err := CompileConfig(tree3)
	if err != nil {
		t.Fatalf("deep config compile error: %v", err)
	}
	if len(cfg3.RoutingInstances) != 1 {
		t.Errorf("expected 1 routing instance, got %d", len(cfg3.RoutingInstances))
	}
	ri := cfg3.RoutingInstances[0]
	if ri.BGP == nil || ri.BGP.LocalAS != 65001 {
		t.Error("deep config: BGP not compiled correctly")
	}
}

func TestConfigValidation(t *testing.T) {
	input := `
security {
    zones {
        security-zone trust {
            interfaces { eth0; }
        }
    }
    policies {
        from-zone trust to-zone nonexistent {
            policy test {
                match {
                    source-address any;
                    destination-address bad-addr;
                    application bad-app;
                }
                then { permit; }
            }
        }
    }
    screen {
        ids-option myscreen {
            tcp { land; }
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
	if len(cfg.Warnings) == 0 {
		t.Fatal("expected validation warnings, got none")
	}
	var foundZone, foundAddr, foundApp bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "nonexistent") && strings.Contains(w, "zone") {
			foundZone = true
		}
		if strings.Contains(w, "bad-addr") {
			foundAddr = true
		}
		if strings.Contains(w, "bad-app") {
			foundApp = true
		}
	}
	if !foundZone {
		t.Error("missing warning for nonexistent zone")
	}
	if !foundAddr {
		t.Error("missing warning for bad-addr")
	}
	if !foundApp {
		t.Error("missing warning for bad-app")
	}
}

func TestConfigValidationClean(t *testing.T) {
	input := `
interfaces {
    eth0 {
        unit 0 { family inet { address 10.0.1.1/24; } }
    }
    eth1 {
        unit 0 { family inet { address 10.0.2.1/24; } }
    }
}
security {
    zones {
        security-zone trust {
            interfaces { eth0; }
            screen myscreen;
        }
        security-zone untrust {
            interfaces { eth1; }
        }
    }
    screen {
        ids-option myscreen {
            tcp { land; }
        }
    }
    address-book {
        global {
            address srv1 10.0.1.10/32;
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow {
                match {
                    source-address any;
                    destination-address srv1;
                    application junos-http;
                }
                then { permit; }
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
	if len(cfg.Warnings) > 0 {
		t.Errorf("expected no warnings, got: %v", cfg.Warnings)
	}
}

func TestConfigValidationCrossRef(t *testing.T) {
	input := `
interfaces {
    eth0 { unit 0 { family inet { address 10.0.1.1/24; } } }
}
security {
    zones {
        security-zone trust {
            interfaces { eth0; }
        }
        security-zone untrust {
            interfaces { missing-iface; }
        }
    }
    nat {
        source {
            rule-set test {
                from zone trust;
                to zone untrust;
                rule snat {
                    match { source-address 0.0.0.0/0; }
                    then { source-nat { pool { missing-pool; } } }
                }
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy sched-test {
                match { source-address any; destination-address any; application any; }
                then { permit; }
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
	var foundIfaceWarn, foundPoolWarn bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "missing-iface") && strings.Contains(w, "not in interfaces") {
			foundIfaceWarn = true
		}
		if strings.Contains(w, "missing-pool") && strings.Contains(w, "not defined") {
			foundPoolWarn = true
		}
	}
	if !foundIfaceWarn {
		t.Errorf("missing warning for zone referencing unconfigured interface, got: %v", cfg.Warnings)
	}
	if !foundPoolWarn {
		t.Errorf("missing warning for SNAT referencing undefined pool, got: %v", cfg.Warnings)
	}
}

func TestPolicySchedulerMissingReferenceWarns(t *testing.T) {
	input := `security {
    policies {
        from-zone trust to-zone untrust {
            policy sched-test {
                match { source-address any; destination-address any; application any; }
                then { permit; }
                scheduler-name missing-sched;
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
		t.Fatalf("CompileConfig returned error for warning-only missing scheduler reference: %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, `policy "sched-test": scheduler "missing-sched" not defined`) {
		t.Fatalf("CompileConfig warnings = %v, want missing scheduler warning", cfg.Warnings)
	}
}

func TestMultiTermApplication(t *testing.T) {
	input := `applications {
    application ssh-long {
        description "Long SSH sessions";
        term 22 alg ssh protocol tcp destination-port 22 inactivity-timeout 86400;
        term 2222 alg ssh protocol tcp destination-port 2222 inactivity-timeout 86400;
    }
    application FaceTime {
        term 41642_65535 protocol udp source-port 41642-65535 destination-port 3478-3497;
        term 0_41640 protocol udp source-port 0-41640 destination-port 3478-3497;
    }
    application simple-app {
        protocol tcp;
        destination-port 8080;
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
	as, ok := cfg.Applications.ApplicationSets["ssh-long"]
	if !ok {
		t.Fatal("multi-term app 'ssh-long' should create an implicit application-set")
	}
	if len(as.Applications) != 2 {
		t.Fatalf("ssh-long set: expected 2 members, got %d", len(as.Applications))
	}
	term22 := cfg.Applications.Applications["ssh-long-22"]
	if term22 == nil {
		t.Fatal("missing term app ssh-long-22")
	}
	if term22.Protocol != "tcp" {
		t.Errorf("ssh-long-22 protocol: got %q, want tcp", term22.Protocol)
	}
	if term22.DestinationPort != "22" {
		t.Errorf("ssh-long-22 dest-port: got %q, want 22", term22.DestinationPort)
	}
	if term22.ALG != "ssh" {
		t.Errorf("ssh-long-22 ALG: got %q, want ssh", term22.ALG)
	}
	if term22.InactivityTimeout != 86400 {
		t.Errorf("ssh-long-22 timeout: got %d, want 86400", term22.InactivityTimeout)
	}
	ft := cfg.Applications.Applications["FaceTime-41642_65535"]
	if ft == nil {
		t.Fatal("missing term app FaceTime-41642_65535")
	}
	if ft.SourcePort != "41642-65535" {
		t.Errorf("FaceTime source-port: got %q, want 41642-65535", ft.SourcePort)
	}
	if ft.DestinationPort != "3478-3497" {
		t.Errorf("FaceTime dest-port: got %q, want 3478-3497", ft.DestinationPort)
	}
	if _, isSet := cfg.Applications.ApplicationSets["simple-app"]; isSet {
		t.Error("simple-app should NOT be an application-set")
	}
	simpleApp := cfg.Applications.Applications["simple-app"]
	if simpleApp == nil {
		t.Fatal("missing simple-app")
	}
	if simpleApp.Protocol != "tcp" || simpleApp.DestinationPort != "8080" {
		t.Errorf("simple-app: got proto=%q port=%q", simpleApp.Protocol, simpleApp.DestinationPort)
	}
}

func TestMultiProtocolTerm(t *testing.T) {
	input := `applications {
    application myicmp {
        term 26619 {
            timeout 1800;
            protocol junos-icmp-all;
            protocol icmp;
            protocol icmp6;
            inactivity-timeout 1800;
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
	as, ok := cfg.Applications.ApplicationSets["myicmp"]
	if !ok {
		t.Fatal("multi-protocol term should create an implicit application-set")
	}
	if len(as.Applications) != 2 {
		t.Fatalf("expected 2 members (icmp, icmpv6), got %d: %v", len(as.Applications), as.Applications)
	}
	for _, name := range as.Applications {
		app := cfg.Applications.Applications[name]
		if app == nil {
			t.Fatalf("missing sub-term %q", name)
		}
		if app.InactivityTimeout != 1800 {
			t.Errorf("%s timeout: got %d, want 1800", name, app.InactivityTimeout)
		}
		if app.Protocol != "icmp" && app.Protocol != "icmpv6" {
			t.Errorf("%s protocol: got %q, want icmp or icmpv6", name, app.Protocol)
		}
	}
}

func TestMultiProtocolTermSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set applications application myicmp term 26619 timeout 1800", "set applications application myicmp term 26619 protocol junos-icmp-all", "set applications application myicmp term 26619 protocol icmp", "set applications application myicmp term 26619 protocol icmp6", "set applications application myicmp term 26619 inactivity-timeout 1800"}
	for _, cmd := range setCommands {
		parts, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("parse set %q: %v", cmd, err)
		}
		tree.SetPath(parts)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	as, ok := cfg.Applications.ApplicationSets["myicmp"]
	if !ok {
		t.Fatal("should create implicit application-set")
	}
	if len(as.Applications) != 2 {
		t.Fatalf("expected 2 members, got %d: %v", len(as.Applications), as.Applications)
	}
	for _, name := range as.Applications {
		app := cfg.Applications.Applications[name]
		if app == nil {
			t.Fatalf("missing sub-term %q", name)
		}
		if app.InactivityTimeout != 1800 {
			t.Errorf("%s timeout: got %d, want 1800", name, app.InactivityTimeout)
		}
	}
}

func TestMultiTermApplicationSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set applications application plex term 32400 protocol tcp destination-port 32400 inactivity-timeout 1800", "set applications application plex term 32480 protocol tcp destination-port 32480", "set applications application plex term 5001-udp protocol udp destination-port 5001"}
	for _, cmd := range setCommands {
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
	as, ok := cfg.Applications.ApplicationSets["plex"]
	if !ok {
		t.Fatal("multi-term 'plex' should create an implicit application-set")
	}
	if len(as.Applications) != 3 {
		t.Fatalf("plex set: expected 3 members, got %d", len(as.Applications))
	}
	term := cfg.Applications.Applications["plex-32400"]
	if term == nil {
		t.Fatal("missing plex-32400")
	}
	if term.InactivityTimeout != 1800 {
		t.Errorf("plex-32400 timeout: got %d, want 1800", term.InactivityTimeout)
	}
}

func TestFormatPath(t *testing.T) {
	input := `interfaces {
    wan0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    trust0 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                trust0.0;
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	out := tree.FormatPath([]string{"interfaces"})
	if !strings.Contains(out, "wan0") || !strings.Contains(out, "trust0") {
		t.Errorf("FormatPath(interfaces) should contain both interfaces, got:\n%s", out)
	}
	if strings.Contains(out, "security") {
		t.Error("FormatPath(interfaces) should not contain security section")
	}
	out = tree.FormatPath([]string{"interfaces", "wan0"})
	if !strings.Contains(out, "10.0.1.1/24") {
		t.Errorf("FormatPath(interfaces, wan0) should contain wan0 address, got:\n%s", out)
	}
	if strings.Contains(out, "trust0") {
		t.Error("FormatPath(interfaces, wan0) should not contain trust0")
	}
	out = tree.FormatPath([]string{"interfaces", "nonexistent"})
	if out != "" {
		t.Errorf("FormatPath for non-existent should return empty, got:\n%s", out)
	}
	out = tree.FormatPath(nil)
	if !strings.Contains(out, "interfaces") || !strings.Contains(out, "security") {
		t.Error("FormatPath(nil) should return full config")
	}
}

func TestTCPMSSHierarchical(t *testing.T) {
	input := `
security {
    flow {
        tcp-mss {
            ipsec-vpn {
                mss 1360;
            }
            gre-in {
                mss 1360;
            }
            gre-out {
                mss 1360;
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Security.Flow.TCPMSSIPsecVPN != 1360 {
		t.Errorf("TCPMSSIPsecVPN = %d, want 1360", cfg.Security.Flow.TCPMSSIPsecVPN)
	}
	if cfg.Security.Flow.TCPMSSGreIn != 1360 {
		t.Errorf("TCPMSSGreIn = %d, want 1360", cfg.Security.Flow.TCPMSSGreIn)
	}
	if cfg.Security.Flow.TCPMSSGreOut != 1360 {
		t.Errorf("TCPMSSGreOut = %d, want 1360", cfg.Security.Flow.TCPMSSGreOut)
	}
}

func TestRouterDiscoveryProtocolSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{"set security zones security-zone trust interfaces trust0", "set security zones security-zone trust host-inbound-traffic protocols router-discovery", "set security zones security-zone trust host-inbound-traffic protocols ospf"} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	trust := cfg.Security.Zones["trust"]
	if trust == nil {
		t.Fatal("trust zone not found")
	}
	if trust.HostInboundTraffic == nil {
		t.Fatal("host-inbound-traffic is nil")
	}
	protos := trust.HostInboundTraffic.Protocols
	if len(protos) != 2 {
		t.Fatalf("protocols = %v, want [router-discovery ospf]", protos)
	}
	found := false
	for _, p := range protos {
		if p == "router-discovery" {
			found = true
		}
	}
	if !found {
		t.Errorf("router-discovery not in protocols: %v", protos)
	}
}

func TestInterfaceDescriptionAndRedundantParent(t *testing.T) {
	input := `interfaces {
    ge-0/0/0 {
        description "Uplink to core";
        gigether-options {
            redundant-parent reth0;
        }
    }
    reth0 {
        description "Redundant Ethernet 0";
        unit 0 {
            description "Management VLAN";
            family inet {
                address 10.0.1.1/24;
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
		t.Fatalf("CompileConfig: %v", err)
	}
	ge := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ge == nil {
		t.Fatal("ge-0/0/0 not found")
	}
	if ge.Description != "Uplink to core" {
		t.Errorf("ge description = %q, want %q", ge.Description, "Uplink to core")
	}
	if ge.RedundantParent != "reth0" {
		t.Errorf("redundant-parent = %q, want reth0", ge.RedundantParent)
	}
	reth := cfg.Interfaces.Interfaces["reth0"]
	if reth == nil {
		t.Fatal("reth0 not found")
	}
	if reth.Description != "Redundant Ethernet 0" {
		t.Errorf("reth description = %q, want %q", reth.Description, "Redundant Ethernet 0")
	}
	unit0 := reth.Units[0]
	if unit0 == nil {
		t.Fatal("reth0 unit 0 not found")
	}
	if unit0.Description != "Management VLAN" {
		t.Errorf("unit description = %q, want %q", unit0.Description, "Management VLAN")
	}
}

func TestInterfacePointToPointAndMTU(t *testing.T) {
	input := `interfaces {
    gr-0/0/0 {
        unit 0 {
            point-to-point;
            tunnel {
                source 10.0.0.1;
                destination 10.0.0.2;
                routing-instance {
                    destination my-vrf;
                }
            }
            family inet {
                mtu 1456;
                address 10.255.0.1/30;
            }
            family inet6 {
                mtu 1436;
                address fe80::1/64;
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
		t.Fatalf("CompileConfig: %v", err)
	}
	gr := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if gr == nil {
		t.Fatal("gr-0/0/0 not found")
	}
	unit0 := gr.Units[0]
	if unit0 == nil {
		t.Fatal("unit 0 not found")
	}
	if !unit0.PointToPoint {
		t.Error("point-to-point should be true")
	}
	if unit0.MTU != 1436 {
		t.Errorf("MTU = %d, want 1436", unit0.MTU)
	}
	if unit0.Tunnel == nil {
		t.Fatal("tunnel not set on unit 0")
	}
	if unit0.Tunnel.Source != "10.0.0.1" {
		t.Errorf("tunnel source = %q, want 10.0.0.1", unit0.Tunnel.Source)
	}
	if unit0.Tunnel.Destination != "10.0.0.2" {
		t.Errorf("tunnel destination = %q, want 10.0.0.2", unit0.Tunnel.Destination)
	}
	if unit0.Tunnel.RoutingInstance != "my-vrf" {
		t.Errorf("tunnel routing-instance = %q, want my-vrf", unit0.Tunnel.RoutingInstance)
	}
	if unit0.Tunnel.Name != "gr-0-0-0" {
		t.Errorf("tunnel Name = %q, want gr-0-0-0", unit0.Tunnel.Name)
	}
}

func TestInterfaceDescriptionSetSyntax(t *testing.T) {
	cmds := []string{"set interfaces ge-0/0/0 description \"Uplink to core\"", "set interfaces ge-0/0/0 gigether-options redundant-parent reth0", "set interfaces gr-0/0/0 unit 0 point-to-point", "set interfaces gr-0/0/0 unit 0 description \"Tunnel unit\"", "set interfaces gr-0/0/0 unit 0 family inet mtu 1420", "set interfaces gr-0/0/0 unit 0 family inet address 10.0.0.1/30"}
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
	ge := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ge == nil {
		t.Fatal("ge-0/0/0 not found")
	}
	if ge.Description != "Uplink to core" {
		t.Errorf("ge description = %q, want %q", ge.Description, "Uplink to core")
	}
	if ge.RedundantParent != "reth0" {
		t.Errorf("redundant-parent = %q, want reth0", ge.RedundantParent)
	}
	gr := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if gr == nil {
		t.Fatal("gr-0/0/0 not found")
	}
	unit0 := gr.Units[0]
	if unit0 == nil {
		t.Fatal("gr unit 0 not found")
	}
	if !unit0.PointToPoint {
		t.Error("point-to-point should be true")
	}
	if unit0.Description != "Tunnel unit" {
		t.Errorf("unit description = %q, want %q", unit0.Description, "Tunnel unit")
	}
	if unit0.MTU != 1420 {
		t.Errorf("MTU = %d, want 1420", unit0.MTU)
	}
}

func TestInterfaceRedundancyAndFabric(t *testing.T) {
	input := `
interfaces {
    reth0 {
        redundant-ether-options {
            redundancy-group 1;
        }
        unit 0 {
            family inet {
                address 10.0.0.1/24 {
                    primary;
                    preferred;
                }
            }
        }
    }
    fab0 {
        fabric-options {
            member-interfaces {
                ge-0/0/7;
                ge-7/0/7;
            }
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	reth := cfg.Interfaces.Interfaces["reth0"]
	if reth == nil {
		t.Fatal("reth0 not found")
	}
	if reth.RedundancyGroup != 1 {
		t.Errorf("redundancy-group = %d, want 1", reth.RedundancyGroup)
	}
	unit0 := reth.Units[0]
	if unit0 == nil {
		t.Fatal("reth0 unit 0 not found")
	}
	if unit0.PrimaryAddress != "10.0.0.1/24" {
		t.Errorf("primary address = %q, want 10.0.0.1/24", unit0.PrimaryAddress)
	}
	fab := cfg.Interfaces.Interfaces["fab0"]
	if fab == nil {
		t.Fatal("fab0 not found")
	}
	if len(fab.FabricMembers) != 2 {
		t.Fatalf("fabric members = %d, want 2", len(fab.FabricMembers))
	}
	if fab.FabricMembers[0] != "ge-0/0/7" {
		t.Errorf("fabric member[0] = %q", fab.FabricMembers[0])
	}
}

func TestEventOptions(t *testing.T) {
	input := `event-options {
    policy disable-on-ping-failure {
        events [ ping_test_failed ping_probe_failed ];
        within 30 {
            trigger until 4;
        }
        within 25 {
            trigger on 3;
        }
        attributes-match {
            ping_test_failed.test-owner matches Comcast-GigabitPro;
            ping_test_failed.test-name matches one-one-one-one;
        }
        then {
            change-configuration {
                commands {
                    "set routing-options static route 0.0.0.0/0 next-table ATT.inet.0";
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
	if len(cfg.EventOptions) != 1 {
		t.Fatalf("EventOptions = %d, want 1", len(cfg.EventOptions))
	}
	ep := cfg.EventOptions[0]
	if ep.Name != "disable-on-ping-failure" {
		t.Errorf("Name = %q", ep.Name)
	}
	if len(ep.Events) < 2 {
		t.Fatalf("Events = %d, want >= 2", len(ep.Events))
	}
	if len(ep.WithinClauses) != 2 {
		t.Fatalf("WithinClauses = %d, want 2", len(ep.WithinClauses))
	}
	if ep.WithinClauses[0].Seconds != 30 {
		t.Errorf("within[0].Seconds = %d, want 30", ep.WithinClauses[0].Seconds)
	}
	if ep.WithinClauses[0].TriggerUntil != 4 {
		t.Errorf("within[0].TriggerUntil = %d, want 4", ep.WithinClauses[0].TriggerUntil)
	}
	if ep.WithinClauses[1].Seconds != 25 {
		t.Errorf("within[1].Seconds = %d, want 25", ep.WithinClauses[1].Seconds)
	}
	if ep.WithinClauses[1].TriggerOn != 3 {
		t.Errorf("within[1].TriggerOn = %d, want 3", ep.WithinClauses[1].TriggerOn)
	}
	if len(ep.AttributesMatch) != 2 {
		t.Fatalf("AttributesMatch = %d, want 2", len(ep.AttributesMatch))
	}
	if len(ep.ThenCommands) != 1 {
		t.Fatalf("ThenCommands = %d, want 1", len(ep.ThenCommands))
	}
}

func TestInlineJflowSourceAddress(t *testing.T) {
	input := `forwarding-options {
    sampling {
        instance jflow-inst {
            input {
                rate 10000;
            }
            family inet {
                output {
                    flow-server 192.168.1.1 {
                        port 4739;
                        version9 {
                            template {
                                ipv4-template;
                            }
                        }
                    }
                    inline-jflow {
                        source-address 192.168.99.1;
                    }
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
	if cfg.ForwardingOptions.Sampling == nil {
		t.Fatal("Sampling is nil")
	}
	inst, ok := cfg.ForwardingOptions.Sampling.Instances["jflow-inst"]
	if !ok {
		t.Fatal("instance jflow-inst not found")
	}
	if inst.FamilyInet == nil {
		t.Fatal("FamilyInet is nil")
	}
	if !inst.FamilyInet.InlineJflow {
		t.Error("InlineJflow should be true")
	}
	if inst.FamilyInet.InlineJflowSourceAddress != "192.168.99.1" {
		t.Errorf("InlineJflowSourceAddress = %q, want 192.168.99.1", inst.FamilyInet.InlineJflowSourceAddress)
	}
	if len(inst.FamilyInet.FlowServers) == 0 {
		t.Fatal("no flow servers")
	}
	if inst.FamilyInet.FlowServers[0].Version9Template != "ipv4-template" {
		t.Errorf("Version9Template = %q, want ipv4-template", inst.FamilyInet.FlowServers[0].Version9Template)
	}
}

func TestRibGroups(t *testing.T) {
	input := `routing-options {
    rib-groups {
        Other-ISPS {
            import-rib [ ATT.inet.0 inet.0 ];
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
	if cfg.RoutingOptions.RibGroups == nil {
		t.Fatal("RibGroups is nil")
	}
	rg, ok := cfg.RoutingOptions.RibGroups["Other-ISPS"]
	if !ok {
		t.Fatal("rib-group Other-ISPS not found")
	}
	if len(rg.ImportRibs) != 2 {
		t.Fatalf("ImportRibs = %d, want 2", len(rg.ImportRibs))
	}
	if rg.ImportRibs[0] != "ATT.inet.0" {
		t.Errorf("ImportRibs[0] = %q, want ATT.inet.0", rg.ImportRibs[0])
	}
}

func TestMultipleRoutingInstances(t *testing.T) {
	input := `routing-instances {
    tunnel-vr {
        instance-type virtual-router;
        interface tunnel0;
        routing-options {
            static {
                route 10.0.50.0/24 { next-hop 10.0.40.1; }
            }
        }
    }
    dmz-vr {
        instance-type virtual-router;
        interface dmz0;
        routing-options {
            interface-routes {
                rib-group inet dmz-leak;
            }
            static {
                route 0.0.0.0/0 { next-hop 10.0.30.1; }
            }
        }
    }
}
routing-options {
    rib-groups {
        dmz-leak {
            import-rib [ dmz-vr.inet.0 inet.0 ];
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
	if len(cfg.RoutingInstances) != 2 {
		t.Fatalf("RoutingInstances = %d, want 2", len(cfg.RoutingInstances))
	}
	for _, ri := range cfg.RoutingInstances {
		if ri.TableID != 100 && ri.TableID != 101 {
			t.Errorf("instance %s: TableID = %d, want 100 or 101", ri.Name, ri.TableID)
		}
	}
	var dmzVR *RoutingInstanceConfig
	// Find dmz-vr and verify rib-group reference.
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "dmz-vr" {
			dmzVR = ri
			break
		}
	}
	if dmzVR == nil {
		t.Fatal("dmz-vr not found")
	}
	if dmzVR.InterfaceRoutesRibGroup != "dmz-leak" {
		t.Errorf("dmz-vr InterfaceRoutesRibGroup = %q, want dmz-leak", dmzVR.InterfaceRoutesRibGroup)
	}
	if len(dmzVR.StaticRoutes) != 1 {
		t.Fatalf("dmz-vr StaticRoutes = %d, want 1", len(dmzVR.StaticRoutes))
	}
	if dmzVR.StaticRoutes[0].Destination != "0.0.0.0/0" {
		t.Errorf("dmz-vr route destination = %q, want 0.0.0.0/0", dmzVR.StaticRoutes[0].Destination)
	}
	rg, ok := cfg.RoutingOptions.RibGroups["dmz-leak"]
	if !ok {
		t.Fatal("rib-group dmz-leak not found")
	}
	if len(rg.ImportRibs) != 2 {
		t.Fatalf("ImportRibs = %d, want 2", len(rg.ImportRibs))
	}
	if rg.ImportRibs[0] != "dmz-vr.inet.0" {
		t.Errorf("ImportRibs[0] = %q, want dmz-vr.inet.0", rg.ImportRibs[0])
	}
	if rg.ImportRibs[1] != "inet.0" {
		t.Errorf("ImportRibs[1] = %q, want inet.0", rg.ImportRibs[1])
	}
	var tunnelVR *RoutingInstanceConfig
	// Verify tunnel-vr.
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "tunnel-vr" {
			tunnelVR = ri
			break
		}
	}
	if tunnelVR == nil {
		t.Fatal("tunnel-vr not found")
	}
	if len(tunnelVR.Interfaces) != 1 || tunnelVR.Interfaces[0] != "tunnel0" {
		t.Errorf("tunnel-vr Interfaces = %v, want [tunnel0]", tunnelVR.Interfaces)
	}
}

func TestMultipleRoutingInstancesSetSyntax(t *testing.T) {
	lines := []string{"set routing-instances tunnel-vr instance-type virtual-router", "set routing-instances tunnel-vr interface tunnel0", "set routing-instances tunnel-vr routing-options static route 10.0.50.0/24 next-hop 10.0.40.1", "set routing-instances dmz-vr instance-type virtual-router", "set routing-instances dmz-vr interface dmz0", "set routing-instances dmz-vr routing-options interface-routes rib-group inet dmz-leak", "set routing-instances dmz-vr routing-options static route 0.0.0.0/0 next-hop 10.0.30.1", "set routing-options rib-groups dmz-leak import-rib dmz-vr.inet.0", "set routing-options rib-groups dmz-leak import-rib inet.0"}
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
	if len(cfg.RoutingInstances) != 2 {
		t.Fatalf("RoutingInstances = %d, want 2", len(cfg.RoutingInstances))
	}
	var dmzVR *RoutingInstanceConfig
	// Find dmz-vr.
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "dmz-vr" {
			dmzVR = ri
			break
		}
	}
	if dmzVR == nil {
		t.Fatal("dmz-vr not found")
	}
	if dmzVR.InterfaceRoutesRibGroup != "dmz-leak" {
		t.Errorf("InterfaceRoutesRibGroup = %q, want dmz-leak", dmzVR.InterfaceRoutesRibGroup)
	}
	rg, ok := cfg.RoutingOptions.RibGroups["dmz-leak"]
	if !ok {
		t.Fatal("rib-group dmz-leak not found")
	}
	if len(rg.ImportRibs) != 2 {
		t.Fatalf("ImportRibs = %d, want 2", len(rg.ImportRibs))
	}
}

func TestPreferredAddress(t *testing.T) {
	input := `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24 {
                    primary;
                    preferred;
                }
                address 10.0.0.2/24;
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
	iface := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if iface == nil {
		t.Fatal("interface ge-0/0/0 not found")
	}
	unit := iface.Units[0]
	if unit.PrimaryAddress != "10.0.0.1/24" {
		t.Errorf("PrimaryAddress = %q, want 10.0.0.1/24", unit.PrimaryAddress)
	}
	if unit.PreferredAddress != "10.0.0.1/24" {
		t.Errorf("PreferredAddress = %q, want 10.0.0.1/24", unit.PreferredAddress)
	}
}

func TestFlowTraceoptions(t *testing.T) {
	input := `security {
    flow {
        traceoptions {
            file flowtrace.log size 100000 files 2;
            flag basic-datapath;
            flag session;
            packet-filter f0 {
                destination-prefix 104.21.54.91/32;
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
	to := cfg.Security.Flow.Traceoptions
	if to == nil {
		t.Fatal("Traceoptions is nil")
	}
	if to.File != "flowtrace.log" {
		t.Errorf("File = %q, want flowtrace.log", to.File)
	}
	if to.FileSize != 100000 {
		t.Errorf("FileSize = %d, want 100000", to.FileSize)
	}
	if to.FileCount != 2 {
		t.Errorf("FileCount = %d, want 2", to.FileCount)
	}
	if len(to.Flags) != 2 {
		t.Fatalf("Flags = %d, want 2", len(to.Flags))
	}
	if to.Flags[0] != "basic-datapath" || to.Flags[1] != "session" {
		t.Errorf("Flags = %v", to.Flags)
	}
	if len(to.PacketFilters) != 1 {
		t.Fatalf("PacketFilters = %d, want 1", len(to.PacketFilters))
	}
	if to.PacketFilters[0].DestinationPrefix != "104.21.54.91/32" {
		t.Errorf("DestinationPrefix = %q", to.PacketFilters[0].DestinationPrefix)
	}
}

func TestFormatJSON(t *testing.T) {
	input := `system {
    host-name fw1;
    name-server 8.8.8.8;
}
interfaces {
    eth0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    eth1 {
        unit 0 {
            family inet {
                dhcp;
            }
        }
    }
}`
	parser := NewParser(input)
	tree, err := parser.Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	jsonOut := tree.FormatJSON()
	if jsonOut == "" || jsonOut == "{}\n" {
		t.Fatal("FormatJSON returned empty object")
	}
	var obj map[ // Verify it's valid JSON.
	string]interface{}
	if err := json.Unmarshal([]byte(jsonOut), &obj); err != nil {
		t.Fatalf("FormatJSON output is not valid JSON: %v\n%s", err, jsonOut)
	}
	sys, ok := obj["system"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected system object, got %T", obj["system"])
	}
	if sys["host-name"] != "fw1" {
		t.Errorf("host-name = %v, want fw1", sys["host-name"])
	}
	if sys["name-server"] != "8.8.8.8" {
		t.Errorf("name-server = %v, want 8.8.8.8", sys["name-server"])
	}
	ifaces, ok := obj["interfaces"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected interfaces object, got %T", obj["interfaces"])
	}
	if _, ok := ifaces["eth0"]; !ok {
		t.Error("interfaces missing eth0")
	}
	if _, ok := ifaces["eth1"]; !ok {
		t.Error("interfaces missing eth1")
	}
}

func TestFormatXML(t *testing.T) {
	input := `system {
    host-name fw1;
    name-server 8.8.8.8;
}
security {
    zones {
        security-zone trust {
            interfaces {
                eth0;
            }
        }
    }
}`
	parser := NewParser(input)
	tree, err := parser.Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	xmlOut := tree.FormatXML()
	if xmlOut == "" {
		t.Fatal("FormatXML returned empty string")
	}
	if !strings.Contains(xmlOut, "<?xml") {
		t.Error("FormatXML missing XML declaration")
	}
	if !strings.Contains(xmlOut, "<configuration>") {
		t.Error("FormatXML missing <configuration> root")
	}
	if !strings.Contains(xmlOut, "</configuration>") {
		t.Error("FormatXML missing </configuration> closing")
	}
	if !strings.Contains(xmlOut, "<system>") {
		t.Error("FormatXML missing <system>")
	}
	if !strings.Contains(xmlOut, "<host-name>fw1</host-name>") {
		t.Error("FormatXML missing <host-name>fw1</host-name>")
	}
	if !strings.Contains(xmlOut, "<name-server>8.8.8.8</name-server>") {
		t.Error("FormatXML missing <name-server>8.8.8.8</name-server>")
	}
	if !strings.Contains(xmlOut, "<security-zone>") {
		t.Error("FormatXML missing <security-zone>")
	}
	if !strings.Contains(xmlOut, "<name>trust</name>") {
		t.Error("FormatXML missing <name>trust</name>")
	}
	if !strings.Contains(xmlOut, "<eth0/>") {
		t.Error("FormatXML missing <eth0/> self-closing tag")
	}
}

func TestDomainNameAndSearch(t *testing.T) {
	input := `system {
    host-name fw1;
    domain-name example.com;
    domain-search {
        corp.example.com;
        dev.example.com;
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
	if cfg.System.DomainName != "example.com" {
		t.Errorf("DomainName = %q, want example.com", cfg.System.DomainName)
	}
	if len(cfg.System.DomainSearch) != 2 {
		t.Fatalf("DomainSearch len = %d, want 2", len(cfg.System.DomainSearch))
	}
	if cfg.System.DomainSearch[0] != "corp.example.com" {
		t.Errorf("DomainSearch[0] = %q, want corp.example.com", cfg.System.DomainSearch[0])
	}
	if cfg.System.DomainSearch[1] != "dev.example.com" {
		t.Errorf("DomainSearch[1] = %q, want dev.example.com", cfg.System.DomainSearch[1])
	}
	tree2 := &ConfigTree{}
	for _, cmd := range []string{"set system domain-name example.org", "set system domain-search corp.example.org", "set system domain-search dev.example.org"} {
		if err := tree2.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg2, err2 := CompileConfig(tree2)
	if err2 != nil {
		t.Fatal(err2)
	}
	if cfg2.System.DomainName != "example.org" {
		t.Errorf("flat: DomainName = %q, want example.org", cfg2.System.DomainName)
	}
	if len(cfg2.System.DomainSearch) != 2 {
		t.Fatalf("flat: DomainSearch len = %d, want 2", len(cfg2.System.DomainSearch))
	}
}

func TestDPDKConfig(t *testing.T) {
	lines := []string{"set system dataplane-type dpdk", "set system dataplane cores 2-5", "set system dataplane memory 2048", "set system dataplane socket-mem \"1024,1024\"", "set system dataplane rx-mode adaptive", "set system dataplane rx-mode idle-threshold 256", "set system dataplane rx-mode resume-threshold 32", "set system dataplane rx-mode sleep-timeout 100", "set system dataplane ports 0000:03:00.0 interface wan0", "set system dataplane ports 0000:03:00.0 rx-mode polling", "set system dataplane ports 0000:03:00.0 cores 2-3", "set system dataplane ports 0000:06:00.0 interface trust0"}
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
	if cfg.System.DataplaneType != "dpdk" {
		t.Errorf("DataplaneType = %q, want dpdk", cfg.System.DataplaneType)
	}
	dp := cfg.System.DPDKDataplane
	if dp == nil {
		t.Fatal("DPDKDataplane is nil")
	}
	if dp.Cores != "2-5" {
		t.Errorf("Cores = %q, want 2-5", dp.Cores)
	}
	if dp.Memory != 2048 {
		t.Errorf("Memory = %d, want 2048", dp.Memory)
	}
	if dp.SocketMem != "1024,1024" {
		t.Errorf("SocketMem = %q, want 1024,1024", dp.SocketMem)
	}
	if dp.RXMode != "adaptive" {
		t.Errorf("RXMode = %q, want adaptive", dp.RXMode)
	}
	if dp.AdaptiveConfig == nil {
		t.Fatal("AdaptiveConfig is nil")
	}
	if dp.AdaptiveConfig.IdleThreshold != 256 {
		t.Errorf("IdleThreshold = %d, want 256", dp.AdaptiveConfig.IdleThreshold)
	}
	if dp.AdaptiveConfig.ResumeThreshold != 32 {
		t.Errorf("ResumeThreshold = %d, want 32", dp.AdaptiveConfig.ResumeThreshold)
	}
	if dp.AdaptiveConfig.SleepTimeout != 100 {
		t.Errorf("SleepTimeout = %d, want 100", dp.AdaptiveConfig.SleepTimeout)
	}
	if len(dp.Ports) != 2 {
		t.Fatalf("Ports len = %d, want 2", len(dp.Ports))
	}
	if dp.Ports[0].PCIAddress != "0000:03:00.0" {
		t.Errorf("Port[0].PCIAddress = %q, want 0000:03:00.0", dp.Ports[0].PCIAddress)
	}
	if dp.Ports[0].Interface != "wan0" {
		t.Errorf("Port[0].Interface = %q, want wan0", dp.Ports[0].Interface)
	}
	if dp.Ports[0].RXMode != "polling" {
		t.Errorf("Port[0].RXMode = %q, want polling", dp.Ports[0].RXMode)
	}
	if dp.Ports[0].Cores != "2-3" {
		t.Errorf("Port[0].Cores = %q, want 2-3", dp.Ports[0].Cores)
	}
	if dp.Ports[1].PCIAddress != "0000:06:00.0" {
		t.Errorf("Port[1].PCIAddress = %q, want 0000:06:00.0", dp.Ports[1].PCIAddress)
	}
	if dp.Ports[1].Interface != "trust0" {
		t.Errorf("Port[1].Interface = %q, want trust0", dp.Ports[1].Interface)
	}
}

func TestUserspaceDataplaneConfig(t *testing.T) {
	lines := []string{"set system dataplane-type userspace", "set system dataplane binary /usr/local/bin/xpf-userspace-dp", "set system dataplane control-socket /run/xpf/userspace-dp.sock", "set system dataplane state-file /run/xpf/userspace-dp.json", "set system dataplane workers 4", "set system dataplane ring-entries 2048"}
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
	if cfg.System.DataplaneType != "userspace" {
		t.Fatalf("DataplaneType = %q, want userspace", cfg.System.DataplaneType)
	}
	dp := cfg.System.UserspaceDataplane
	if dp == nil {
		t.Fatal("UserspaceDataplane is nil")
	}
	if dp.Binary != "/usr/local/bin/xpf-userspace-dp" {
		t.Errorf("Binary = %q", dp.Binary)
	}
	if dp.ControlSocket != "/run/xpf/userspace-dp.sock" {
		t.Errorf("ControlSocket = %q", dp.ControlSocket)
	}
	if dp.StateFile != "/run/xpf/userspace-dp.json" {
		t.Errorf("StateFile = %q", dp.StateFile)
	}
	if dp.Workers != 4 {
		t.Errorf("Workers = %d, want 4", dp.Workers)
	}
	if dp.RingEntries != 2048 {
		t.Errorf("RingEntries = %d, want 2048", dp.RingEntries)
	}
	// Default: omitting rss-indirection leaves RSSIndirectionDisabled at
	// zero value (false), i.e. D3 enabled. This pins the "safe default"
	// semantic for the PR #797 kill switch.
	if dp.RSSIndirectionDisabled {
		t.Errorf("RSSIndirectionDisabled = true by default, want false")
	}
}

func TestUserspaceDataplaneSharedUMEMConfig(t *testing.T) {
	artifact := t.TempDir() + "/phase0.json"
	if err := os.WriteFile(artifact, []byte(`{"passed":true,"kernel_release":"test-kernel","selected_interfaces":["ge-0/0/1","ge-0/0/2"],"driver_name":{"ge-0/0/1":"mlx5_core","ge-0/0/2":"mlx5_core"},"mtu":{"ge-0/0/1":1500,"ge-0/0/2":1500}}`), 0644); err != nil {
		t.Fatal(err)
	}
	lines := []string{
		"set system dataplane-type userspace",
		"set system dataplane shared-umem mode cross-nic",
		"set system dataplane shared-umem interface ge-0/0/1",
		"set system dataplane shared-umem interface ge-0/0/2",
		"set system dataplane shared-umem phase0-artifact-file " + artifact,
	}
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
	dp := cfg.System.UserspaceDataplane
	if dp == nil || dp.SharedUMEM == nil {
		t.Fatal("SharedUMEM config not compiled")
	}
	if dp.SharedUMEM.Mode != "cross-nic" {
		t.Fatalf("SharedUMEM.Mode = %q, want cross-nic", dp.SharedUMEM.Mode)
	}
	if got := strings.Join(dp.SharedUMEM.Interfaces, ","); got != "ge-0-0-1,ge-0-0-2" {
		t.Fatalf("SharedUMEM.Interfaces = %q", got)
	}
	if passed, ok := dp.SharedUMEM.Phase0Artifact["passed"].(bool); !ok || !passed {
		t.Fatalf("SharedUMEM.Phase0Artifact[passed] = %#v", dp.SharedUMEM.Phase0Artifact["passed"])
	}
	if got := strings.Join(sharedUMEMArtifactStringArray(t, dp.SharedUMEM.Phase0Artifact, "selected_interfaces"), ","); got != "ge-0-0-1,ge-0-0-2" {
		t.Fatalf("SharedUMEM.Phase0Artifact[selected_interfaces] = %q", got)
	}
	mtu, ok := dp.SharedUMEM.Phase0Artifact["mtu"].(map[string]interface{})
	if !ok {
		t.Fatalf("SharedUMEM.Phase0Artifact[mtu] = %#v", dp.SharedUMEM.Phase0Artifact["mtu"])
	}
	if _, ok := mtu["ge-0-0-1"]; !ok {
		t.Fatalf("SharedUMEM.Phase0Artifact[mtu] was not Linux-name normalized: %#v", mtu)
	}
	driverName, ok := dp.SharedUMEM.Phase0Artifact["driver_name"].(map[string]interface{})
	if !ok {
		t.Fatalf("SharedUMEM.Phase0Artifact[driver_name] = %#v", dp.SharedUMEM.Phase0Artifact["driver_name"])
	}
	if _, ok := driverName["ge-0-0-1"]; !ok {
		t.Fatalf("SharedUMEM.Phase0Artifact[driver_name] was not Linux-name normalized: %#v", driverName)
	}
}

func TestUserspaceDataplaneSharedUMEMRejectsNullArtifact(t *testing.T) {
	artifact := t.TempDir() + "/phase0.json"
	if err := os.WriteFile(artifact, []byte(`null`), 0644); err != nil {
		t.Fatal(err)
	}
	lines := []string{
		"set system dataplane-type userspace",
		"set system dataplane shared-umem mode cross-nic",
		"set system dataplane shared-umem interface ge-0/0/1",
		"set system dataplane shared-umem phase0-artifact-file " + artifact,
	}
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
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "top-level value must be a JSON object") {
		t.Fatalf("CompileConfig error = %v, want null artifact rejection", err)
	}
}

func TestUserspaceDataplaneSharedUMEMRejectsOversizedArtifact(t *testing.T) {
	artifact := t.TempDir() + "/phase0.json"
	file, err := os.Create(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(sharedUMEMPhase0ArtifactMaxBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = readSharedUMEMPhase0Artifact(artifact)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readSharedUMEMPhase0Artifact error = %v, want size rejection", err)
	}
}

func TestUserspaceDataplaneSharedUMEMRejectsArtifactKeyCollision(t *testing.T) {
	artifact := t.TempDir() + "/phase0.json"
	if err := os.WriteFile(artifact, []byte(`{"passed":true,"driver_name":{"ge-0/0/1":"mlx5_core","ge-0-0-1":"mlx5_core"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := readSharedUMEMPhase0Artifact(artifact)
	if err == nil || !strings.Contains(err.Error(), "duplicate driver_name key after Linux interface-name normalization: ge-0-0-1") {
		t.Fatalf("readSharedUMEMPhase0Artifact error = %v, want normalized-key collision", err)
	}
}

func TestUserspaceDataplaneSharedUMEMRejectsArtifactArrayCollision(t *testing.T) {
	artifact := t.TempDir() + "/phase0.json"
	if err := os.WriteFile(artifact, []byte(`{"passed":true,"selected_interfaces":["ge-0/0/1","ge-0-0-1"]}`), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := readSharedUMEMPhase0Artifact(artifact)
	if err == nil || !strings.Contains(err.Error(), "duplicate selected_interfaces entry after Linux interface-name normalization: ge-0-0-1") {
		t.Fatalf("readSharedUMEMPhase0Artifact error = %v, want normalized-array collision", err)
	}
}

func TestUserspaceDataplaneSharedUMEMGroupMergesWithBaseDataplane(t *testing.T) {
	artifact := t.TempDir() + "/phase0.json"
	if err := os.WriteFile(artifact, []byte(`{"passed":true}`), 0644); err != nil {
		t.Fatal(err)
	}
	lines := []string{
		"set groups node0 system dataplane shared-umem mode cross-nic",
		"set groups node0 system dataplane shared-umem interface ge-0/0/1",
		"set groups node0 system dataplane shared-umem phase0-artifact-file " + artifact,
		"set apply-groups node0",
		"set system dataplane-type userspace",
		"set system dataplane binary /usr/local/bin/xpf-userspace-dp",
		"set system dataplane workers 6",
	}
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
	dp := cfg.System.UserspaceDataplane
	if dp == nil {
		t.Fatal("UserspaceDataplane is nil")
	}
	if dp.Binary != "/usr/local/bin/xpf-userspace-dp" || dp.Workers != 6 {
		t.Fatalf("base dataplane fields were not compiled: binary=%q workers=%d", dp.Binary, dp.Workers)
	}
	if dp.SharedUMEM == nil || dp.SharedUMEM.Mode != "cross-nic" {
		t.Fatalf("group shared-umem was overwritten: %#v", dp.SharedUMEM)
	}
	if got := strings.Join(dp.SharedUMEM.Interfaces, ","); got != "ge-0-0-1" {
		t.Fatalf("SharedUMEM.Interfaces = %q", got)
	}
}

func sharedUMEMArtifactStringArray(t *testing.T, artifact map[string]interface{}, key string) []string {
	t.Helper()
	values, ok := artifact[key].([]interface{})
	if !ok {
		t.Fatalf("SharedUMEM.Phase0Artifact[%s] = %#v", key, artifact[key])
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		s, ok := value.(string)
		if !ok {
			t.Fatalf("SharedUMEM.Phase0Artifact[%s] contains non-string %#v", key, value)
		}
		out = append(out, s)
	}
	return out
}

// #797 HIGH/MEDIUM: operator must be able to toggle D3 RSS indirection
// via a first-class config knob. Setting `rss-indirection disable`
// must compile to RSSIndirectionDisabled=true; `enable` (or anything
// other than "disable") must leave it false.
func TestUserspaceDataplaneRSSIndirectionDisable(t *testing.T) {
	cases := []struct {
		name    string
		setLine string
		want    bool
	}{
		{"disable_sets_true", "set system dataplane rss-indirection disable", true},
		{"enable_leaves_false", "set system dataplane rss-indirection enable", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := &ConfigTree{}
			base := []string{
				"set system dataplane-type userspace",
				"set system dataplane binary /usr/local/bin/xpf-userspace-dp",
				"set system dataplane control-socket /run/xpf/userspace-dp.sock",
				"set system dataplane state-file /run/xpf/userspace-dp.json",
				"set system dataplane workers 4",
				tc.setLine,
			}
			for _, line := range base {
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
			dp := cfg.System.UserspaceDataplane
			if dp == nil {
				t.Fatal("UserspaceDataplane is nil")
			}
			if dp.RSSIndirectionDisabled != tc.want {
				t.Fatalf("RSSIndirectionDisabled=%v, want %v",
					dp.RSSIndirectionDisabled, tc.want)
			}
		})
	}
}

// #801: Phase-B Step-0 knobs — cpu-governor, netdev-budget,
// coalescence adaptive/rx-usecs/tx-usecs. All live under `system
// dataplane` alongside the existing rss-indirection switch.
func TestUserspaceDataplaneStep0Knobs(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set system dataplane-type userspace",
		"set system dataplane binary /usr/local/bin/xpf-userspace-dp",
		"set system dataplane control-socket /run/xpf/userspace-dp.sock",
		"set system dataplane state-file /run/xpf/userspace-dp.json",
		"set system dataplane workers 4",
		"set system dataplane cpu-governor performance",
		"set system dataplane netdev-budget 600",
		"set system dataplane coalescence adaptive disable",
		"set system dataplane coalescence rx-usecs 16",
		"set system dataplane coalescence tx-usecs 32",
	}
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
	dp := cfg.System.UserspaceDataplane
	if dp == nil {
		t.Fatal("UserspaceDataplane is nil")
	}
	if dp.CPUGovernor != "performance" {
		t.Errorf("CPUGovernor=%q, want performance", dp.CPUGovernor)
	}
	if dp.NetdevBudget != 600 {
		t.Errorf("NetdevBudget=%d, want 600", dp.NetdevBudget)
	}
	if !dp.CoalescenceAdaptiveExplicit {
		t.Error("CoalescenceAdaptiveExplicit=false, want true (operator wrote the knob)")
	}
	if !dp.CoalescenceAdaptiveDisabled {
		t.Error("CoalescenceAdaptiveDisabled=false, want true (explicit disable)")
	}
	if dp.CoalescenceRXUsecs != 16 {
		t.Errorf("CoalescenceRXUsecs=%d, want 16", dp.CoalescenceRXUsecs)
	}
	if dp.CoalescenceTXUsecs != 32 {
		t.Errorf("CoalescenceTXUsecs=%d, want 32", dp.CoalescenceTXUsecs)
	}
}

// #801: `coalescence adaptive enable` is the operator override. It
// must set Explicit=true AND Disabled=false so the daemon re-enables
// adaptive (mirror of the default).
func TestUserspaceDataplaneCoalescenceAdaptiveEnable(t *testing.T) {
	tree := &ConfigTree{}
	base := []string{
		"set system dataplane-type userspace",
		"set system dataplane binary /usr/local/bin/xpf-userspace-dp",
		"set system dataplane control-socket /run/xpf/userspace-dp.sock",
		"set system dataplane state-file /run/xpf/userspace-dp.json",
		"set system dataplane workers 4",
		"set system dataplane coalescence adaptive enable",
	}
	for _, line := range base {
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
	dp := cfg.System.UserspaceDataplane
	if !dp.CoalescenceAdaptiveExplicit {
		t.Error("Explicit=false, want true")
	}
	if dp.CoalescenceAdaptiveDisabled {
		t.Error("Disabled=true for `adaptive enable`, want false")
	}
}

// #801: omitting every knob must leave the defaults at zero so
// daemon.resolvedHostTunables can substitute the issue's defaults
// without colliding with an operator value.
func TestUserspaceDataplaneStep0Knobs_OmittedDefaultsToZero(t *testing.T) {
	tree := &ConfigTree{}
	base := []string{
		"set system dataplane-type userspace",
		"set system dataplane binary /usr/local/bin/xpf-userspace-dp",
		"set system dataplane control-socket /run/xpf/userspace-dp.sock",
		"set system dataplane state-file /run/xpf/userspace-dp.json",
		"set system dataplane workers 4",
	}
	for _, line := range base {
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
	dp := cfg.System.UserspaceDataplane
	if dp.CPUGovernor != "" {
		t.Errorf("CPUGovernor=%q, want empty (omitted)", dp.CPUGovernor)
	}
	if dp.NetdevBudget != 0 {
		t.Errorf("NetdevBudget=%d, want 0 (omitted)", dp.NetdevBudget)
	}
	if dp.CoalescenceAdaptiveExplicit {
		t.Error("Explicit=true, want false (omitted)")
	}
	if dp.CoalescenceRXUsecs != 0 || dp.CoalescenceTXUsecs != 0 {
		t.Errorf("RX/TX usecs = %d/%d, want 0/0 (omitted)",
			dp.CoalescenceRXUsecs, dp.CoalescenceTXUsecs)
	}
}

func TestRIPAuthSetSyntax(t *testing.T) {
	cmds := []string{"set protocols rip neighbor trust0", "set protocols rip authentication-type md5", "set protocols rip authentication-key ripSecret"}
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
	rip := cfg.Protocols.RIP
	if rip == nil {
		t.Fatal("RIP config is nil")
	}
	if rip.AuthType != "md5" {
		t.Errorf("AuthType: got %q, want md5", rip.AuthType)
	}
	if rip.AuthKey != "ripSecret" {
		t.Errorf("AuthKey: got %q, want ripSecret", rip.AuthKey)
	}
}

func TestInterfaceDuplexSetSyntax(t *testing.T) {
	cmds := []string{"set interfaces trust0 speed 1g", "set interfaces trust0 duplex full", "set interfaces trust0 mtu 9000", "set interfaces trust0 description \"LAN interface\""}
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
	ifc := cfg.Interfaces.Interfaces["trust0"]
	if ifc == nil {
		t.Fatal("trust0 interface not found")
	}
	if ifc.Speed != "1g" {
		t.Errorf("Speed = %q, want \"1g\"", ifc.Speed)
	}
	if ifc.Duplex != "full" {
		t.Errorf("Duplex = %q, want \"full\"", ifc.Duplex)
	}
	if ifc.MTU != 9000 {
		t.Errorf("MTU = %d, want 9000", ifc.MTU)
	}
	if ifc.Description != "LAN interface" {
		t.Errorf("Description = %q, want \"LAN interface\"", ifc.Description)
	}
}

func TestMetricTypeAndCommunityListSetSyntax(t *testing.T) {
	cmds := []string{"set policy-options community MY-COMM members 65000:100", "set policy-options community MY-COMM members 65000:200", "set policy-options community NO-EXPORT members no-export", "set policy-options policy-statement OSPF-EXPORT term t1 from protocol direct", "set policy-options policy-statement OSPF-EXPORT term t1 from community MY-COMM", "set policy-options policy-statement OSPF-EXPORT term t1 then metric-type 1", "set policy-options policy-statement OSPF-EXPORT term t1 then metric 100", "set policy-options policy-statement OSPF-EXPORT term t1 then accept", "set policy-options policy-statement OSPF-EXPORT term t2 then metric-type 2", "set policy-options policy-statement OSPF-EXPORT term t2 then reject"}
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
	comm := cfg.PolicyOptions.Communities["MY-COMM"]
	if comm == nil {
		t.Fatal("MY-COMM community not found")
	}
	if len(comm.Members) != 2 {
		t.Fatalf("MY-COMM members = %d, want 2", len(comm.Members))
	}
	if comm.Members[0] != "65000:100" || comm.Members[1] != "65000:200" {
		t.Errorf("MY-COMM members = %v, want [65000:100, 65000:200]", comm.Members)
	}
	noExp := cfg.PolicyOptions.Communities["NO-EXPORT"]
	if noExp == nil {
		t.Fatal("NO-EXPORT community not found")
	}
	if len(noExp.Members) != 1 || noExp.Members[0] != "no-export" {
		t.Errorf("NO-EXPORT members = %v, want [no-export]", noExp.Members)
	}
	ps := cfg.PolicyOptions.PolicyStatements["OSPF-EXPORT"]
	if ps == nil {
		t.Fatal("OSPF-EXPORT not found")
	}
	if len(ps.Terms) != 2 {
		t.Fatalf("got %d terms, want 2", len(ps.Terms))
	}
	t1 := ps.Terms[0]
	if t1.FromProtocol != "direct" {
		t.Errorf("t1 from protocol = %q, want direct", t1.FromProtocol)
	}
	if t1.FromCommunity != "MY-COMM" {
		t.Errorf("t1 from community = %q, want MY-COMM", t1.FromCommunity)
	}
	if t1.MetricType != 1 {
		t.Errorf("t1 metric-type = %d, want 1", t1.MetricType)
	}
	if t1.Metric != 100 {
		t.Errorf("t1 metric = %d, want 100", t1.Metric)
	}
	if t1.Action != "accept" {
		t.Errorf("t1 action = %q, want accept", t1.Action)
	}
	t2 := ps.Terms[1]
	if t2.MetricType != 2 {
		t.Errorf("t2 metric-type = %d, want 2", t2.MetricType)
	}
	if t2.Action != "reject" {
		t.Errorf("t2 action = %q, want reject", t2.Action)
	}
}

func TestASPathSetSyntax(t *testing.T) {
	cmds := []string{`set policy-options as-path AS65000 "65000"`, `set policy-options as-path TRANSIT "65[0-9]+"`, "set policy-options policy-statement FILTER-AS term t1 from as-path AS65000", "set policy-options policy-statement FILTER-AS term t1 then accept", "set policy-options policy-statement FILTER-AS then reject"}
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
	if cfg.PolicyOptions.ASPaths == nil {
		t.Fatal("ASPaths map is nil")
	}
	ap := cfg.PolicyOptions.ASPaths["AS65000"]
	if ap == nil {
		t.Fatal("AS65000 as-path not found")
	}
	if ap.Regex != "65000" {
		t.Errorf("AS65000 regex = %q, want 65000", ap.Regex)
	}
	tr := cfg.PolicyOptions.ASPaths["TRANSIT"]
	if tr == nil {
		t.Fatal("TRANSIT as-path not found")
	}
	if tr.Regex != "65[0-9]+" {
		t.Errorf("TRANSIT regex = %q, want 65[0-9]+", tr.Regex)
	}
	ps := cfg.PolicyOptions.PolicyStatements["FILTER-AS"]
	if ps == nil {
		t.Fatal("FILTER-AS not found")
	}
	if len(ps.Terms) != 1 {
		t.Fatalf("got %d terms, want 1", len(ps.Terms))
	}
	if ps.Terms[0].FromASPath != "AS65000" {
		t.Errorf("from as-path = %q, want AS65000", ps.Terms[0].FromASPath)
	}
	if ps.Terms[0].Action != "accept" {
		t.Errorf("action = %q, want accept", ps.Terms[0].Action)
	}
	if ps.DefaultAction != "reject" {
		t.Errorf("default action = %q, want reject", ps.DefaultAction)
	}
}

func TestApplyGroupsHierarchical(t *testing.T) {
	input := `
groups {
    common {
        system {
            host-name my-firewall;
        }
        security {
            zones {
                security-zone trust {
                    interfaces {
                        eth0.0;
                    }
                }
            }
        }
    }
}
apply-groups common;
interfaces {
    eth0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.System.HostName != "my-firewall" {
		t.Errorf("hostname = %q, want my-firewall", cfg.System.HostName)
	}
	trustZone := cfg.Security.Zones["trust"]
	if trustZone == nil {
		t.Fatal("expected trust zone from group")
	}
	if len(trustZone.Interfaces) != 1 || trustZone.Interfaces[0] != "eth0.0" {
		t.Errorf("trust zone interfaces: %v", trustZone.Interfaces)
	}
	iface := cfg.Interfaces.Interfaces["eth0"]
	if iface == nil {
		t.Fatal("expected eth0 interface")
	}
}

func TestApplyGroupsSetSyntax(t *testing.T) {
	setCommands := []string{"set groups common system host-name fw1", "set groups common security screen ids-option myscreen tcp land", "set apply-groups common", "set interfaces eth0 unit 0 family inet address 10.0.1.1/24"}
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
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
		t.Fatalf("compile: %v", err)
	}
	if cfg.System.HostName != "fw1" {
		t.Errorf("hostname = %q, want fw1", cfg.System.HostName)
	}
	sp := cfg.Security.Screen["myscreen"]
	if sp == nil {
		t.Fatal("expected myscreen profile")
	}
	if !sp.TCP.Land {
		t.Error("expected land screen")
	}
}

func TestApplyGroupsMergeDoesNotOverride(t *testing.T) {
	input := `
groups {
    defaults {
        system {
            host-name group-name;
        }
    }
}
apply-groups defaults;
system {
    host-name explicit-name;
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.System.HostName != "explicit-name" {
		t.Errorf("hostname = %q, want explicit-name", cfg.System.HostName)
	}
}

func TestApplyGroupsMissingReference(t *testing.T) {
	input := `
apply-groups nonexistent;
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected error for undefined group reference")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should mention group name: %v", err)
	}
}

func TestApplyGroupsCircularReference(t *testing.T) {
	input := `
groups {
    grp-a {
        system {
            host-name from-a;
        }
    }
}
apply-groups grp-a;
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.System.HostName != "from-a" {
		t.Errorf("hostname = %q, want from-a", cfg.System.HostName)
	}
}

func TestApplyGroupsMultiple(t *testing.T) {
	setCommands := []string{"set groups net-settings interfaces eth0 unit 0 family inet address 10.0.1.1/24", "set groups sec-settings security screen ids-option basic tcp land", "set apply-groups net-settings", "set apply-groups sec-settings", "set system host-name test-fw"}
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
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
		t.Fatalf("compile: %v", err)
	}
	if cfg.System.HostName != "test-fw" {
		t.Errorf("hostname = %q, want test-fw", cfg.System.HostName)
	}
	iface := cfg.Interfaces.Interfaces["eth0"]
	if iface == nil {
		t.Fatal("expected eth0 from net-settings group")
	}
	sp := cfg.Security.Screen["basic"]
	if sp == nil {
		t.Fatal("expected basic screen from sec-settings group")
	}
}

func TestApplyGroupsFormatSet(t *testing.T) {
	setCommands := []string{"set groups common system host-name fw1", "set apply-groups common"}
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	output := tree.FormatSet()
	if !strings.Contains(output, "set groups common system host-name fw1") {
		t.Errorf("FormatSet missing groups line, got:\n%s", output)
	}
	if !strings.Contains(output, "set apply-groups common") {
		t.Errorf("FormatSet missing apply-groups line, got:\n%s", output)
	}
}

func TestApplyGroupsWildcard(t *testing.T) {
	setCommands := []string{"set security policies from-zone trust to-zone untrust policy allow-all match source-address any", "set security policies from-zone trust to-zone untrust policy allow-all match destination-address any", "set security policies from-zone trust to-zone untrust policy allow-all match application any", "set security policies from-zone trust to-zone untrust policy allow-all then permit", "set security policies from-zone dmz to-zone untrust policy dmz-out match source-address any", "set security policies from-zone dmz to-zone untrust policy dmz-out match destination-address any", "set security policies from-zone dmz to-zone untrust policy dmz-out match application any", "set security policies from-zone dmz to-zone untrust policy dmz-out then permit", "set groups default-deny-template security policies from-zone <*> to-zone <*> policy default-deny then log session-init", "set apply-groups default-deny-template"}
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	findPolicies := func(from, to string) *ZonePairPolicies {
		for _, zp := range cfg.Security.Policies {
			if zp.FromZone == from && zp.ToZone == to {
				return zp
			}
		}
		return nil
	}
	trustUntrust := findPolicies("trust", "untrust")
	if trustUntrust == nil {
		t.Fatal("expected trust->untrust policies")
	}
	foundDeny := false
	for _, p := range trustUntrust.Policies {
		if p.Name == "default-deny" {
			foundDeny = true
			if p.Log == nil || !p.Log.SessionInit {
				t.Error("default-deny policy missing session-init log")
			}
		}
	}
	if !foundDeny {
		t.Error("wildcard group did not merge default-deny into trust->untrust")
	}
	dmzUntrust := findPolicies("dmz", "untrust")
	if dmzUntrust == nil {
		t.Fatal("expected dmz->untrust policies")
	}
	foundDeny = false
	for _, p := range dmzUntrust.Policies {
		if p.Name == "default-deny" {
			foundDeny = true
		}
	}
	if !foundDeny {
		t.Error("wildcard group did not merge default-deny into dmz->untrust")
	}
}

func TestCompilePreservesGroups(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set groups my-group system host-name test", "set apply-groups my-group"}
	for _, cmd := range setCommands {
		parts, _ := ParseSetCommand(cmd)
		tree.SetPath(parts)
	}
	if tree.FindChild("groups") == nil {
		t.Fatal("groups node missing before compile")
	}
	_, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if tree.FindChild("groups") == nil {
		t.Error("groups node stripped by CompileConfig")
	}
	if tree.FindChild("apply-groups") == nil {
		t.Error("apply-groups node stripped by CompileConfig")
	}
}

func TestExpandGroupsWithNodeVar(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{`set groups node0 system host-name fw0`, `set groups node0 chassis cluster node 0`, `set groups node0 interfaces hb0 unit 0 family inet address 10.99.0.1/30`, `set groups node1 system host-name fw1`, `set groups node1 chassis cluster node 1`, `set groups node1 interfaces hb0 unit 0 family inet address 10.99.0.2/30`, `set apply-groups "${node}"`, `set security zones security-zone trust interfaces trust0.0`}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	clone0 := tree.Clone()
	vars0 := map[string]string{"node": "node0"}
	if err := clone0.ExpandGroupsWithVars(vars0); err != nil {
		t.Fatalf("ExpandGroupsWithVars node0: %v", err)
	}
	out0 := clone0.Format()
	if !strings.Contains(out0, "host-name fw0") {
		t.Errorf("node0 expansion should contain fw0 hostname:\n%s", out0)
	}
	if strings.Contains(out0, "host-name fw1") {
		t.Errorf("node0 expansion should NOT contain fw1 hostname:\n%s", out0)
	}
	clone1 := tree.Clone()
	vars1 := map[string]string{"node": "node1"}
	if err := clone1.ExpandGroupsWithVars(vars1); err != nil {
		t.Fatalf("ExpandGroupsWithVars node1: %v", err)
	}
	out1 := clone1.Format()
	if !strings.Contains(out1, "host-name fw1") {
		t.Errorf("node1 expansion should contain fw1 hostname:\n%s", out1)
	}
	if strings.Contains(out1, "host-name fw0") {
		t.Errorf("node1 expansion should NOT contain fw0 hostname:\n%s", out1)
	}
}

func TestCompileConfigForNode(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{`set groups node0 system host-name fw0`, `set groups node0 chassis cluster node 0`, `set groups node0 interfaces hb0 unit 0 family inet address 10.99.0.1/30`, `set groups node1 system host-name fw1`, `set groups node1 chassis cluster node 1`, `set groups node1 interfaces hb0 unit 0 family inet address 10.99.0.2/30`, `set apply-groups "${node}"`, `set chassis cluster cluster-id 1`}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg0, err := CompileConfigForNode(tree, 0)
	if err != nil {
		t.Fatalf("CompileConfigForNode(0): %v", err)
	}
	if cfg0.System.HostName != "fw0" {
		t.Errorf("node0 hostname = %q, want fw0", cfg0.System.HostName)
	}
	if cfg0.Chassis.Cluster == nil || cfg0.Chassis.Cluster.NodeID != 0 {
		t.Errorf("node0 NodeID = %v, want 0", cfg0.Chassis.Cluster)
	}
	cfg1, err := CompileConfigForNode(tree, 1)
	if err != nil {
		t.Fatalf("CompileConfigForNode(1): %v", err)
	}
	if cfg1.System.HostName != "fw1" {
		t.Errorf("node1 hostname = %q, want fw1", cfg1.System.HostName)
	}
	if cfg1.Chassis.Cluster == nil || cfg1.Chassis.Cluster.NodeID != 1 {
		t.Errorf("node1 NodeID = %v, want 1", cfg1.Chassis.Cluster)
	}
	if tree.FindChild("groups") == nil {
		t.Error("groups node stripped from original tree")
	}
	if tree.FindChild("apply-groups") == nil {
		t.Error("apply-groups node stripped from original tree")
	}
}

func TestCompileConfigForNodeBackwardCompat(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{`set groups node0 system host-name fw0`, `set apply-groups "${node}"`}
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
		t.Fatalf("CompileConfig() unexpected error: %v", err)
	}
	if cfg.System.HostName != "fw0" {
		t.Fatalf("hostname = %q, want fw0", cfg.System.HostName)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, `"${node}"`) && strings.Contains(w, "node0") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected node placeholder warning, got %v", cfg.Warnings)
	}
}

func TestExpandGroupsWithVarsNilPreservesBackwardCompat(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set groups common system host-name test-fw", "set apply-groups common"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if err := tree.ExpandGroupsWithVars(nil); err != nil {
		t.Fatalf("ExpandGroupsWithVars(nil): %v", err)
	}
	out := tree.Format()
	if !strings.Contains(out, "host-name test-fw") {
		t.Errorf("nil vars should still expand literal group names:\n%s", out)
	}
}

func TestFormatInheritance(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set security policies from-zone trust to-zone untrust policy allow-all match source-address any", "set security policies from-zone trust to-zone untrust policy allow-all match destination-address any", "set security policies from-zone trust to-zone untrust policy allow-all match application any", "set security policies from-zone trust to-zone untrust policy allow-all then permit", "set groups default-deny-template security policies from-zone <*> to-zone <*> policy default-deny match source-address any", "set groups default-deny-template security policies from-zone <*> to-zone <*> policy default-deny match destination-address any", "set groups default-deny-template security policies from-zone <*> to-zone <*> policy default-deny match application any", "set groups default-deny-template security policies from-zone <*> to-zone <*> policy default-deny then reject", "set groups default-deny-template security policies from-zone <*> to-zone <*> policy default-deny then log session-init", "set groups default-deny-template security policies from-zone <*> to-zone <*> policy default-deny then log session-close", "set apply-groups default-deny-template"}
	for _, cmd := range setCommands {
		parts, _ := ParseSetCommand(cmd)
		tree.SetPath(parts)
	}
	output := tree.FormatInheritance()
	if !strings.Contains(output, "## 'default-deny' was inherited from group 'default-deny-template'") {
		t.Errorf("expected inheritance annotation in output:\n%s", output)
	}
	if !strings.Contains(output, "policy allow-all") {
		t.Error("expected explicit policy allow-all in output")
	}
	allowAllIdx := strings.Index(output, "policy allow-all")
	precedingLines := output[:allowAllIdx]
	lastNewline := strings.LastIndex(precedingLines, "\n")
	lineBeforeAllowAll := ""
	if lastNewline >= 0 {
		lineBeforeAllowAll = precedingLines[lastNewline:]
	}
	if strings.Contains(lineBeforeAllowAll, "inherited") {
		t.Error("explicit policy allow-all should not have inheritance annotation")
	}
	if tree.FindChild("groups") == nil {
		t.Error("groups node should not be removed from original tree")
	}
}

func TestApplyGroupsBracketList(t *testing.T) {
	input := `
groups {
    grp-host {
        system {
            host-name from-group;
        }
    }
    grp-screen {
        security {
            screen {
                ids-option basic {
                    tcp {
                        land;
                    }
                }
            }
        }
    }
}
apply-groups [ grp-host grp-screen ];
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.System.HostName != "from-group" {
		t.Errorf("hostname = %q, want from-group", cfg.System.HostName)
	}
	if cfg.Security.Screen["basic"] == nil {
		t.Fatal("expected screen profile 'basic' from grp-screen group")
	}
}

func TestApplyGroupsBracketListWithVars(t *testing.T) {
	input := `
groups {
    node0 {
        system {
            host-name fw0;
        }
    }
    node1 {
        system {
            host-name fw1;
        }
    }
    common {
        security {
            screen {
                ids-option basic {
                    tcp {
                        land;
                    }
                }
            }
        }
    }
}
apply-groups [ "${node}" common ];
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	clone0 := tree.Clone()
	vars0 := map[string]string{"node": "node0"}
	if err := clone0.ExpandGroupsWithVars(vars0); err != nil {
		t.Fatalf("ExpandGroupsWithVars node0: %v", err)
	}
	cfg0, err := compileExpanded(clone0)
	if err != nil {
		t.Fatalf("compile node0: %v", err)
	}
	if cfg0.System.HostName != "fw0" {
		t.Errorf("node0 hostname = %q, want fw0", cfg0.System.HostName)
	}
	if cfg0.Security.Screen["basic"] == nil {
		t.Error("node0: expected screen profile 'basic' from common group")
	}
	clone1 := tree.Clone()
	vars1 := map[string]string{"node": "node1"}
	if err := clone1.ExpandGroupsWithVars(vars1); err != nil {
		t.Fatalf("ExpandGroupsWithVars node1: %v", err)
	}
	cfg1, err := compileExpanded(clone1)
	if err != nil {
		t.Fatalf("compile node1: %v", err)
	}
	if cfg1.System.HostName != "fw1" {
		t.Errorf("node1 hostname = %q, want fw1", cfg1.System.HostName)
	}
}

func TestApplyGroupsNested(t *testing.T) {
	input := `
groups {
    allow-out {
        security {
            policies {
                from-zone <*> to-zone <*> {
                    policy allow-all-out {
                        match {
                            source-address any;
                            destination-address any;
                            application any;
                        }
                        then {
                            permit;
                        }
                    }
                }
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                trust0.0;
            }
        }
        security-zone untrust {
            interfaces {
                untrust0.0;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            apply-groups allow-out;
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pair := findZonePair(cfg.Security.Policies, "trust→untrust")
	if pair == nil {
		t.Fatal("expected trust→untrust zone pair")
	}
	found := false
	for _, pol := range pair.Policies {
		if pol.Name == "allow-all-out" {
			found = true
			if len(pol.Match.SourceAddresses) == 0 || pol.Match.SourceAddresses[0] != "any" {
				t.Error("allow-all-out: expected source-address any")
			}
		}
	}
	if !found {
		t.Error("expected policy 'allow-all-out' from nested apply-groups")
	}
}

func TestApplyGroupsNestedBracketList(t *testing.T) {
	input := `
groups {
    allow-icmp {
        security {
            policies {
                from-zone <*> to-zone <*> {
                    policy allow-icmp-in {
                        match {
                            source-address any;
                            destination-address any;
                            application junos-icmp-all;
                        }
                        then {
                            permit;
                        }
                    }
                }
            }
        }
    }
    default-deny {
        security {
            policies {
                from-zone <*> to-zone <*> {
                    policy deny-all {
                        match {
                            source-address any;
                            destination-address any;
                            application any;
                        }
                        then {
                            deny;
                        }
                    }
                }
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                trust0.0;
            }
        }
        security-zone untrust {
            interfaces {
                untrust0.0;
            }
        }
    }
    policies {
        from-zone untrust to-zone trust {
            apply-groups [ allow-icmp default-deny ];
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pair := findZonePair(cfg.Security.Policies, "untrust→trust")
	if pair == nil {
		t.Fatal("expected untrust→trust zone pair")
	}
	names := make([]string, len(pair.Policies))
	for i, pol := range pair.Policies {
		names[i] = pol.Name
	}
	foundICMP := false
	foundDeny := false
	for _, n := range names {
		if n == "allow-icmp-in" {
			foundICMP = true
		}
		if n == "deny-all" {
			foundDeny = true
		}
	}
	if !foundICMP {
		t.Errorf("expected policy 'allow-icmp-in' from nested bracket-list apply-groups, got %v", names)
	}
	if !foundDeny {
		t.Errorf("expected policy 'deny-all' from nested bracket-list apply-groups, got %v", names)
	}
}

func TestApplyGroupsMixedTopAndNested(t *testing.T) {
	input := `
groups {
    common {
        system {
            host-name test-fw;
        }
    }
    outbound {
        security {
            policies {
                from-zone <*> to-zone <*> {
                    policy allow-out {
                        match {
                            source-address any;
                            destination-address any;
                            application any;
                        }
                        then {
                            permit;
                        }
                    }
                }
            }
        }
    }
}
apply-groups common;
security {
    zones {
        security-zone trust {
            interfaces {
                trust0.0;
            }
        }
        security-zone untrust {
            interfaces {
                untrust0.0;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            apply-groups outbound;
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.System.HostName != "test-fw" {
		t.Errorf("hostname = %q, want test-fw", cfg.System.HostName)
	}
	pair := findZonePair(cfg.Security.Policies, "trust→untrust")
	if pair == nil {
		t.Fatal("expected trust→untrust zone pair")
	}
	found := false
	for _, pol := range pair.Policies {
		if pol.Name == "allow-out" {
			found = true
		}
	}
	if !found {
		t.Error("expected policy 'allow-out' from nested apply-groups")
	}
}

func TestApplyGroupsNestedNoMatchSilent(t *testing.T) {
	input := `
groups {
    hostname-only {
        system {
            host-name from-group;
        }
    }
}
system {
    host-name explicit;
}
security {
    zones {
        security-zone trust {
            interfaces {
                trust0.0;
            }
        }
        security-zone untrust {
            interfaces {
                untrust0.0;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            apply-groups hostname-only;
            policy explicit-policy {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.System.HostName != "explicit" {
		t.Errorf("hostname = %q, want explicit", cfg.System.HostName)
	}
	pair := findZonePair(cfg.Security.Policies, "trust→untrust")
	if pair == nil {
		t.Fatal("expected trust→untrust zone pair")
	}
	if len(pair.Policies) != 1 || pair.Policies[0].Name != "explicit-policy" {
		t.Errorf("expected just explicit-policy, got %d policies", len(pair.Policies))
	}
}

func TestApplyGroupsNestedSetSyntax(t *testing.T) {
	setCommands := []string{"set groups allow-out security policies from-zone <*> to-zone <*> policy allow-all-out match source-address any", "set groups allow-out security policies from-zone <*> to-zone <*> policy allow-all-out match destination-address any", "set groups allow-out security policies from-zone <*> to-zone <*> policy allow-all-out match application any", "set groups allow-out security policies from-zone <*> to-zone <*> policy allow-all-out then permit", "set security zones security-zone trust interfaces trust0.0", "set security zones security-zone untrust interfaces untrust0.0", "set security policies from-zone trust to-zone untrust apply-groups allow-out"}
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
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
		t.Fatalf("compile: %v", err)
	}
	pair := findZonePair(cfg.Security.Policies, "trust→untrust")
	if pair == nil {
		t.Fatal("expected trust→untrust zone pair")
	}
	found := false
	for _, pol := range pair.Policies {
		if pol.Name == "allow-all-out" {
			found = true
		}
	}
	if !found {
		t.Error("expected policy 'allow-all-out' from nested apply-groups (set syntax)")
	}
}

func TestApplyGroupsVsrxHAConf(t *testing.T) {
	data, err := os.ReadFile("../../vsrx-ha.conf")
	if err != nil {
		t.Skipf("vsrx-ha.conf not found: %v", err)
	}
	tree, errs := NewParser(string(data)).Parse()
	if len(errs) > 0 {
		t.Logf("parse warnings (%d): %v", len(errs), errs)
	}
	cfg, err := CompileConfigForNode(tree, 0)
	if err != nil {
		t.Fatalf("compile node0: %v", err)
	}
	if cfg.System.HostName != "vsrx-ernie" {
		t.Errorf("node0 hostname = %q, want vsrx-ernie", cfg.System.HostName)
	}
	if len(cfg.Security.Policies) == 0 {
		t.Fatal("expected zone pair policies after group expansion")
	}
	totalPolicies := 0
	for _, zpp := range cfg.Security.Policies {
		totalPolicies += len(zpp.Policies)
	}
	if totalPolicies < 10 {
		t.Errorf("expected many policies from group expansion, got %d", totalPolicies)
	}
	t.Logf("compiled %d zone pairs with %d total policies", len(cfg.Security.Policies), totalPolicies)
}

func TestCompileLocalVsrxConf(t *testing.T) {
	data, err := os.ReadFile("../../vsrx.conf")
	if err != nil {
		t.Skipf("vsrx.conf not found: %v", err)
	}
	tree, errs := NewParser(string(data)).Parse()
	if len(errs) > 0 {
		t.Logf("parse warnings (%d): %v", len(errs), errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile vsrx.conf: %v", err)
	}
	if len(cfg.Warnings) == 0 {
		t.Log("compiled vsrx.conf with no warnings")
	}
}

func TestParserAcceptsSSHKnownHostTokens(t *testing.T) {
	input := `system {
    ssh-known-hosts {
        host skull.sf.saab.org,2001:559:8585:100::253 {
            ecdsa-sha2-nistp256-key AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOzePLJ+YX/jjDmcAr2E4oB/RJ/6aCPsl39581dbjpCEDhdW6ahp+JDUUsHsHkYdJ0qw6cG8qlUbjezKfB3O4Rw=;
        }
    }
}`
	_, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
}

func TestAnnotationFormatText(t *testing.T) {
	tree := &ConfigTree{Children: []*Node{{Keys: []string{"system"}, Children: []*Node{{Keys: []string{"host-name", "fw1"}, IsLeaf: true, Annotation: "Primary firewall"}, {Keys: []string{"domain-name", "example.com"}, IsLeaf: true}}}, {Keys: []string{"security"}, Annotation: "Security configuration", Children: []*Node{{Keys: []string{"log"}, Children: []*Node{{Keys: []string{"mode", "stream"}, IsLeaf: true}}}}}}}
	out := tree.Format()
	if !strings.Contains(out, "/* Primary firewall */") {
		t.Errorf("missing host-name annotation in:\n%s", out)
	}
	if !strings.Contains(out, "/* Security configuration */") {
		t.Errorf("missing security annotation in:\n%s", out)
	}
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if strings.Contains(line, "domain-name") {
			if i > 0 && strings.Contains(lines[i-1], "/*") {
				t.Errorf("domain-name should not have annotation, but preceding line is: %s", lines[i-1])
			}
		}
	}
}

func TestAnnotationClone(t *testing.T) {
	tree := &ConfigTree{Children: []*Node{{Keys: []string{"system"}, Children: []*Node{{Keys: []string{"host-name", "fw1"}, IsLeaf: true, Annotation: "Test comment"}}}}}
	cloned := tree.Clone()
	if cloned.Children[0].Children[0].Annotation != "Test comment" {
		t.Error("annotation not preserved in clone")
	}
	cloned.Children[0].Children[0].Annotation = "Modified"
	if tree.Children[0].Children[0].Annotation != "Test comment" {
		t.Error("clone shares annotation with original")
	}
}

func TestValidatePortSpec(t *testing.T) {
	tests := []struct {
		spec string
		ok   bool
	}{{"80", true}, {"8080-8090", true}, {"1", true}, {"65535", true}, {"http", true}, {"HTTPS", true}, {"dns", true}, {"1024-65535", true}, {"0", false}, {"99999", false}, {"abc", false}, {"8090-8080", false}, {"", true}, {"foo-bar", false}}
	for _, tt := range tests {
		err := validatePortSpec(tt.spec)
		if (err == nil) != tt.ok {
			t.Errorf("validatePortSpec(%q) = %v, want ok=%v", tt.spec, err, tt.ok)
		}
	}
}

func TestValidateProtocol(t *testing.T) {
	tests := []struct {
		proto string
		ok    bool
	}{{"tcp", true}, {"udp", true}, {"icmp", true}, {"icmp6", true}, {"gre", true}, {"47", true}, {"0", true}, {"255", true}, {"256", false}, {"-1", false}, {"bogus", false}}
	for _, tt := range tests {
		err := validateProtocol(tt.proto)
		if (err == nil) != tt.ok {
			t.Errorf("validateProtocol(%q) = %v, want ok=%v", tt.proto, err, tt.ok)
		}
	}
}

func TestValidateConfigApplicationPorts(t *testing.T) {
	cfg := &Config{}
	cfg.Applications.Applications = map[string]*Application{"good-app": {Name: "good-app", Protocol: "tcp", DestinationPort: "8080-8090", SourcePort: "1024-65535"}, "bad-port": {Name: "bad-port", Protocol: "tcp", DestinationPort: "99999"}, "bad-proto": {Name: "bad-proto", Protocol: "bogus"}}
	cfg.Applications.ApplicationSets = map[string]*ApplicationSet{}
	cfg.Security.Zones = map[string]*ZoneConfig{}
	cfg.Security.NAT.Source = nil
	cfg.Security.NAT.Destination = nil
	warnings := ValidateConfig(cfg)
	var foundPort, foundProto bool
	for _, w := range warnings {
		if strings.Contains(w, "bad-port") && strings.Contains(w, "99999") {
			foundPort = true
		}
		if strings.Contains(w, "bad-proto") && strings.Contains(w, "bogus") {
			foundProto = true
		}
	}
	if !foundPort {
		t.Error("expected warning about bad-port with invalid port 99999")
	}
	if !foundProto {
		t.Error("expected warning about bad-proto with invalid protocol")
	}
}

// TestValidateConfig_ArchiveSitesPasswordWarns pins #651: when an
// operator configures `archive-sites <url> password "$9$..."`, bpfrx
// must warn at commit time rather than silently accept. Runtime
// archival shells out to `scp -o BatchMode=yes` and cannot use inline
// passwords, so the password is ignored; the warning exists to make
// that no-op visible instead of failing opaquely at transfer time.
func TestValidateConfig_ArchiveSitesPasswordWarns(t *testing.T) {
	cfg := &Config{}
	cfg.Applications.Applications = map[string]*Application{}
	cfg.Applications.ApplicationSets = map[string]*ApplicationSet{}
	cfg.Security.Zones = map[string]*ZoneConfig{}
	cfg.System.Archival = &ArchivalConfig{
		ArchiveSites: []string{
			"scp://alice@host1/configs",
			"scp://bob@host2/configs",
		},
		ArchiveSitesWithPassword: []string{
			"scp://alice@host1/configs",
		},
	}

	warnings := ValidateConfig(cfg)

	sawPasswordWarn := false
	wrongURLWarn := false
	for _, w := range warnings {
		if strings.Contains(w, "scp://alice@host1/configs") && strings.Contains(w, "inline password") {
			sawPasswordWarn = true
		}
		// bob did not configure a password; should not warn.
		if strings.Contains(w, "scp://bob@host2/configs") && strings.Contains(w, "inline password") {
			wrongURLWarn = true
		}
	}
	if !sawPasswordWarn {
		t.Error("expected warning about scp://alice@host1/configs inline password")
	}
	if wrongURLWarn {
		t.Error("should NOT warn about host2 — no password was configured")
	}
}

func TestLo0FilterExtraction(t *testing.T) {
	input := `interfaces {
    lo0 {
        unit 0 {
            family inet {
                filter {
                    input filter-management;
                }
            }
            family inet6 {
                filter {
                    input filter-management6;
                }
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.System.Lo0FilterInputV4 != "filter-management" {
		t.Errorf("Lo0FilterInputV4 = %q, want filter-management", cfg.System.Lo0FilterInputV4)
	}
	if cfg.System.Lo0FilterInputV6 != "filter-management6" {
		t.Errorf("Lo0FilterInputV6 = %q, want filter-management6", cfg.System.Lo0FilterInputV6)
	}
}

func TestLo0FilterExtractionSet(t *testing.T) {
	lines := []string{"set interfaces lo0 unit 0 family inet filter input mgmt-v4", "set interfaces lo0 unit 0 family inet6 filter input mgmt-v6"}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.System.Lo0FilterInputV4 != "mgmt-v4" {
		t.Errorf("Lo0FilterInputV4 = %q, want mgmt-v4", cfg.System.Lo0FilterInputV4)
	}
	if cfg.System.Lo0FilterInputV6 != "mgmt-v6" {
		t.Errorf("Lo0FilterInputV6 = %q, want mgmt-v6", cfg.System.Lo0FilterInputV6)
	}
}

func TestHostInboundRouterDiscovery(t *testing.T) {
	lines := []string{"set security zones security-zone trust host-inbound-traffic system-services ping", "set security zones security-zone trust host-inbound-traffic protocols bgp", "set security zones security-zone trust host-inbound-traffic protocols router-discovery", "set security zones security-zone trust interfaces trust0"}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	trust := cfg.Security.Zones["trust"]
	if trust == nil {
		t.Fatal("trust zone is nil")
	}
	if trust.HostInboundTraffic == nil {
		t.Fatal("host-inbound-traffic is nil")
	}
	protos := trust.HostInboundTraffic.Protocols
	found := map[string]bool{}
	for _, p := range protos {
		found[p] = true
	}
	if !found["bgp"] {
		t.Error("missing protocol bgp")
	}
	if !found["router-discovery"] {
		t.Error("missing protocol router-discovery")
	}
}

func TestNat66SourceRules(t *testing.T) {
	input := `security {
    nat {
        source {
            rule-set internal-to-internet {
                from zone trust;
                to zone untrust;
                rule nat66-iface {
                    match {
                        source-address ::/0;
                    }
                    then {
                        source-nat {
                            interface;
                        }
                    }
                }
            }
        }
    }
    zones {
        security-zone trust {
            interfaces trust0;
        }
        security-zone untrust {
            interfaces untrust0;
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	rs := cfg.Security.NAT.Source
	if len(rs) != 1 {
		t.Fatalf("expected 1 SNAT rule-set, got %d", len(rs))
	}
	rules := rs[0].Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name != "nat66-iface" {
		t.Errorf("rule name = %q, want nat66-iface", rules[0].Name)
	}
	if rules[0].Match.SourceAddress != "::/0" {
		t.Errorf("source-address = %q, want ::/0", rules[0].Match.SourceAddress)
	}
	if !rules[0].Then.Interface {
		t.Error("expected interface SNAT")
	}
}

func TestThreeColorPolicer(t *testing.T) {
	input := `firewall {
    three-color-policer tcp-3color {
        two-rate {
            color-blind;
            committed-information-rate 10m;
            committed-burst-size 100k;
            peak-information-rate 50m;
            peak-burst-size 500k;
        }
    }
    three-color-policer sr-3color {
        single-rate {
            committed-information-rate 5m;
            committed-burst-size 50k;
            excess-burst-size 200k;
        }
    }
}
`
	p := NewParser(input)
	tree, err := p.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg, cerr := CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("compile error: %v", cerr)
	}
	if len(cfg.Firewall.ThreeColorPolicers) != 2 {
		t.Fatalf("expected 2 three-color policers, got %d", len(cfg.Firewall.ThreeColorPolicers))
	}
	tcp := cfg.Firewall.ThreeColorPolicers["tcp-3color"]
	if tcp == nil {
		t.Fatal("tcp-3color policer not found")
	}
	if !tcp.TwoRate {
		t.Error("expected TwoRate=true")
	}
	if !tcp.ColorBlind {
		t.Error("expected ColorBlind=true")
	}
	if tcp.CIR != 1250000 {
		t.Errorf("CIR = %d, want 1250000", tcp.CIR)
	}
	if tcp.CBS != 100000 {
		t.Errorf("CBS = %d, want 100000", tcp.CBS)
	}
	if tcp.PIR != 6250000 {
		t.Errorf("PIR = %d, want 6250000", tcp.PIR)
	}
	if tcp.PBS != 500000 {
		t.Errorf("PBS = %d, want 500000", tcp.PBS)
	}
	sr := cfg.Firewall.ThreeColorPolicers["sr-3color"]
	if sr == nil {
		t.Fatal("sr-3color policer not found")
	}
	if sr.TwoRate {
		t.Error("expected TwoRate=false for single-rate")
	}
	if sr.CIR != 625000 {
		t.Errorf("CIR = %d, want 625000", sr.CIR)
	}
	if sr.CBS != 50000 {
		t.Errorf("CBS = %d, want 50000", sr.CBS)
	}
	if sr.PBS != 200000 {
		t.Errorf("PBS = %d, want 200000", sr.PBS)
	}
}

func TestThreeColorPolicerSetSyntax(t *testing.T) {
	lines := []string{"set firewall three-color-policer my-3c two-rate color-blind", "set firewall three-color-policer my-3c two-rate committed-information-rate 10m", "set firewall three-color-policer my-3c two-rate committed-burst-size 100k", "set firewall three-color-policer my-3c two-rate peak-information-rate 50m", "set firewall three-color-policer my-3c two-rate peak-burst-size 500k"}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	tcp := cfg.Firewall.ThreeColorPolicers["my-3c"]
	if tcp == nil {
		t.Fatal("my-3c policer not found")
	}
	if !tcp.TwoRate {
		t.Error("expected TwoRate=true")
	}
	if !tcp.ColorBlind {
		t.Error("expected ColorBlind=true")
	}
	if tcp.CIR != 1250000 {
		t.Errorf("CIR = %d, want 1250000", tcp.CIR)
	}
	if tcp.PIR != 6250000 {
		t.Errorf("PIR = %d, want 6250000", tcp.PIR)
	}
}

func TestThreeColorPolicerStrictValidation(t *testing.T) {
	tests := []struct {
		name    string
		lines   []string
		wantErr string
	}{
		{
			name: "missing committed rate",
			lines: []string{
				"set firewall three-color-policer bad single-rate committed-burst-size 100k",
				"set firewall three-color-policer bad single-rate excess-burst-size 200k",
			},
			wantErr: "committed-information-rate",
		},
		{
			name: "two-rate missing peak rate",
			lines: []string{
				"set firewall three-color-policer bad two-rate committed-information-rate 10m",
				"set firewall three-color-policer bad two-rate committed-burst-size 100k",
				"set firewall three-color-policer bad two-rate peak-burst-size 200k",
			},
			wantErr: "peak-information-rate",
		},
		{
			name: "peak below committed",
			lines: []string{
				"set firewall three-color-policer bad two-rate committed-information-rate 10m",
				"set firewall three-color-policer bad two-rate committed-burst-size 100k",
				"set firewall three-color-policer bad two-rate peak-information-rate 1m",
				"set firewall three-color-policer bad two-rate peak-burst-size 200k",
			},
			wantErr: "peak-information-rate must be >= committed-information-rate",
		},
		{
			name: "peak burst below committed burst",
			lines: []string{
				"set firewall three-color-policer bad two-rate committed-information-rate 10m",
				"set firewall three-color-policer bad two-rate committed-burst-size 200k",
				"set firewall three-color-policer bad two-rate peak-information-rate 20m",
				"set firewall three-color-policer bad two-rate peak-burst-size 100k",
			},
			wantErr: "peak-burst-size must be >= committed-burst-size",
		},
		{
			name: "ambiguous single and two rate",
			lines: []string{
				"set firewall three-color-policer bad single-rate committed-information-rate 10m",
				"set firewall three-color-policer bad single-rate committed-burst-size 100k",
				"set firewall three-color-policer bad single-rate excess-burst-size 200k",
				"set firewall three-color-policer bad two-rate committed-information-rate 10m",
				"set firewall three-color-policer bad two-rate committed-burst-size 100k",
				"set firewall three-color-policer bad two-rate peak-information-rate 20m",
				"set firewall three-color-policer bad two-rate peak-burst-size 200k",
			},
			wantErr: "cannot configure both single-rate and two-rate",
		},
		{
			name: "ambiguous color mode",
			lines: []string{
				"set firewall three-color-policer bad single-rate color-blind",
				"set firewall three-color-policer bad single-rate color-aware",
				"set firewall three-color-policer bad single-rate committed-information-rate 10m",
				"set firewall three-color-policer bad single-rate committed-burst-size 100k",
				"set firewall three-color-policer bad single-rate excess-burst-size 200k",
			},
			wantErr: "cannot configure both color-blind and color-aware",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := &ConfigTree{}
			for _, line := range tt.lines {
				cmd, err := ParseSetCommand(line)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", line, err)
				}
				if err := tree.SetPath(cmd); err != nil {
					t.Fatalf("SetPath(%q): %v", line, err)
				}
			}
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("CompileConfig error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestThreeColorPolicerStrictValidation_HierarchicalDuplicateSameModeSiblings(t *testing.T) {
	input := `firewall {
    three-color-policer bad {
        single-rate {
            color-blind;
            committed-information-rate 10m;
            committed-burst-size 100k;
            excess-burst-size 200k;
        }
        single-rate {
            color-aware;
        }
    }
}
`
	p := NewParser(input)
	tree, err := p.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	_, compileErr := CompileConfig(tree)
	if compileErr == nil {
		t.Fatal("CompileConfig succeeded, want ambiguous color mode error")
	}
	if !strings.Contains(compileErr.Error(), "cannot configure both color-blind and color-aware") {
		t.Fatalf("CompileConfig error = %v", compileErr)
	}
}

func TestLogicalInterfacePolicer(t *testing.T) {
	input := `firewall {
    policer shared-rate {
        logical-interface-policer;
        if-exceeding {
            bandwidth-limit 1m;
            burst-size-limit 15k;
        }
        then discard;
    }
}
`
	p := NewParser(input)
	tree, err := p.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg, cerr := CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("compile error: %v", cerr)
	}
	pol := cfg.Firewall.Policers["shared-rate"]
	if pol == nil {
		t.Fatal("shared-rate policer not found")
	}
	if !pol.LogicalInterfacePolicer {
		t.Error("expected LogicalInterfacePolicer=true")
	}
}

func TestParseBandwidthBps(t *testing.T) {
	tests := []struct {
		input string
		want  uint64
	}{{"1g", 1000000000}, {"10G", 10000000000}, {"100m", 100000000}, {"500k", 500000}, {"10000", 10000}, {"10.0g", 10000000000}, {"12.5g", 12500000000}, {"", 0}, {"abc", 0}}
	for _, tc := range tests {
		got := parseBandwidthBps(tc.input)
		if got != tc.want {
			t.Errorf("parseBandwidthBps(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestParseBandwidthLimit(t *testing.T) {
	tests := []struct {
		input string
		want  uint64
	}{
		{"1g", 125000000},
		{"10.0g", 1250000000},
		{"12.5g", 1562500000},
		{"100m", 12500000},
		{"500k", 62500},
		{"10000", 1250},
		{"", 0},
		{"abc", 0},
	}
	for _, tc := range tests {
		got := parseBandwidthLimit(tc.input)
		if got != tc.want {
			t.Errorf("parseBandwidthLimit(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestCompleteSetPathFromZoneToZone(t *testing.T) {
	tests := []struct {
		name   string
		tokens []string
		want   string
	}{{name: "from-zone value shows zone hint", tokens: []string{ // expected completion name (single match)
		"security", "policies", "from-zone"}, want: ""}, {name: "after from-zone value shows to-zone keyword", tokens: []string{"security", "policies", "from-zone", "trust"}, want: "to-zone"}, {name: "partial to-zone completes", tokens: []string{"security", "policies", "from-zone", "trust", "to"}, want: "to-zone"}, {name: "show configuration sub-path policies", tokens: []string{"security", "po"}, want: "policies"}, {name: "show configuration sub-path nat", tokens: []string{"security", "na"}, want: "nat"}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := CompleteSetPathWithValues(tc.tokens, nil)
			if tc.want == "" {
				return
			}
			if results == nil {
				t.Fatalf("got nil completions, want %q", tc.want)
			}
			found := false
			for _, r := range results {
				if r.Name == tc.want {
					found = true
					break
				}
			}
			if !found {
				names := make([]string, len(results))
				for i, r := range results {
					names[i] = r.Name
				}
				t.Errorf("expected %q in completions, got %v", tc.want, names)
			}
		})
	}
}
