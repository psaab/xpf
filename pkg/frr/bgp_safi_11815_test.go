package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestGenerateProtocols_BGPLabeledUnicastDoesNotActivateUnicast11815(t *testing.T) {
	for _, tc := range []struct {
		name   string
		peer   string
		family string
	}{
		{name: "IPv4 labeled-unicast", peer: "192.0.2.1", family: "inet"},
		{name: "IPv6 labeled-unicast", peer: "2001:db8::1", family: "inet6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := &config.ConfigTree{}
			for _, command := range []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group external peer-as 65002",
				"set protocols bgp group external family " + tc.family + " labeled-unicast",
				"set protocols bgp group external loops 2",
				"set protocols bgp group external neighbor " + tc.peer,
			} {
				path, err := config.ParseSetCommand(command)
				if err != nil {
					t.Fatalf("parse %q: %v", command, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("set %q: %v", command, err)
				}
			}
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
				t.Fatalf("compiled BGP neighbor missing: %+v", cfg.Protocols.BGP)
			}
			rendered := New().generateProtocols(nil, nil, cfg.Protocols.BGP, nil, nil, "", 0, nil, nil)
			for _, line := range strings.Split(rendered, "\n") {
				if strings.TrimSpace(line) == "neighbor "+tc.peer+" activate" {
					t.Fatalf("labeled-unicast peer was activated under a unicast AF:\n%s", rendered)
				}
			}
			if !strings.Contains(rendered, "no neighbor "+tc.peer+" activate\n") {
				t.Fatalf("FRR default activation was not explicitly disabled for labeled-only peer:\n%s", rendered)
			}
			if strings.Contains(rendered, "address-family ipv6 unicast\n") {
				t.Fatalf("IPv6 labeled-only peer was activated under IPv6 unicast:\n%s", rendered)
			}
		})
	}
}

func TestGenerateProtocols_BGPExplicitUnicastStillActivates11815(t *testing.T) {
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{{
			Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true,
		}},
	}
	rendered := New().generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if !strings.Contains(rendered, "address-family ipv4 unicast\n") ||
		!strings.Contains(rendered, "neighbor 192.0.2.1 activate\n") {
		t.Fatalf("explicit unicast neighbor stopped activating:\n%s", rendered)
	}
}

func TestGenerateProtocols_BGPMergedNeighborUnsupportedSAFIDoesNotActivate11815(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, command := range []string{
		"set policy-options policy-statement PS term t1 then accept",
		"set protocols bgp local-as 65000",
		"set protocols bgp group G type external",
		"set protocols bgp group G peer-as 65001",
		"set protocols bgp group G neighbor 10.0.2.2",
		"set protocols bgp group G neighbor 10.0.2.2 import PS",
		"set protocols bgp group G neighbor 10.0.2.2 family inet labeled-unicast",
	} {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("parse %q: %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("set %q: %v", command, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("repeated neighbor nodes compiled to %+v; want one merged neighbor", cfg.Protocols.BGP)
	}
	n := cfg.Protocols.BGP.Neighbors[0]
	if n.FamilyInet || !n.UnsupportedInetSAFI {
		t.Fatalf("merged neighbor family inet=%v unsupported=%v; want unsupported SAFI inert", n.FamilyInet, n.UnsupportedInetSAFI)
	}
	if len(n.Import) != 1 || n.Import[0] != "PS" {
		t.Fatalf("merged neighbor import policies = %v; want preserved PS policy", n.Import)
	}
	rendered := New().generateProtocols(nil, nil, cfg.Protocols.BGP, nil, nil, "", 0, &cfg.PolicyOptions, nil)
	if count := strings.Count(rendered, "neighbor 10.0.2.2 remote-as 65001"); count != 1 {
		t.Fatalf("rendered remote-as declaration count = %d, want one merged declaration:\n%s", count, rendered)
	}
	for _, line := range strings.Split(rendered, "\n") {
		if strings.TrimSpace(line) == "neighbor 10.0.2.2 activate" {
			t.Fatalf("unsupported SAFI peer activated as unicast:\n%s", rendered)
		}
	}
	if !strings.Contains(rendered, "no neighbor 10.0.2.2 activate\n") {
		t.Fatalf("FRR default unicast activation was not disabled:\n%s", rendered)
	}
}
