package frr

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9667: a bare-token `protocols bgp export` rendered only under `router bgp`,
// whose redistribute grammar (BGP_NODE) is IPv4-only. A dual-family source's
// IPv6 routes never entered BGP, and an IPv6-only source rendered nothing.

// bgpBlocks9667 splits the rendered BGP section into the router-level lines and
// the body of `address-family ipv6 unicast` ("" and false when not opened).
func bgpBlocks9667(t *testing.T, got string) (top, af6 string, hasAF6 bool) {
	t.Helper()
	start := strings.Index(got, "router bgp ")
	if start < 0 {
		t.Fatalf("no router bgp section:\n%s", got)
	}
	section := got[start:]
	if end := strings.Index(section, "exit\n!\n"); end >= 0 {
		section = section[:end]
	}
	const hdr = " address-family ipv6 unicast\n"
	i := strings.Index(section, hdr)
	if i < 0 {
		return section, "", false
	}
	rest := section[i+len(hdr):]
	if j := strings.Index(rest, " exit-address-family\n"); j >= 0 {
		rest = rest[:j]
	}
	top = section[:i]
	if k := strings.Index(top, " address-family "); k >= 0 {
		top = top[:k]
	}
	return top, rest, true
}

func hasLine9667(block, line string) bool {
	for _, l := range strings.Split(block, "\n") {
		if l == line {
			return true
		}
	}
	return false
}

func TestBGPBareTokenRedistributesEachFamily_9667(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:   65001,
		RouterID:  "1.1.1.1",
		Export:    []string{"static", "ospf", "ospf6", "direct", "bgp"},
		Neighbors: []*config.BGPNeighbor{{Address: "10.0.2.1", PeerAS: 65002}},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	top, af6, ok := bgpBlocks9667(t, got)
	if !ok {
		t.Fatalf("IPv6-capable bare tokens must open `address-family ipv6 unicast` even with no IPv6 neighbor:\n%s", got)
	}
	for _, want := range []string{" redistribute static", " redistribute ospf", " redistribute connected"} {
		if !hasLine9667(top, want) {
			t.Errorf("router bgp (IPv4 grammar) missing %q:\n%s", want, top)
		}
	}
	if hasLine9667(top, " redistribute ospf6") {
		t.Errorf("router bgp must not carry the IPv6-only ospf6 source:\n%s", top)
	}
	for _, want := range []string{"  redistribute static", "  redistribute ospf6", "  redistribute connected"} {
		if !hasLine9667(af6, want) {
			t.Errorf("address-family ipv6 unicast missing %q:\n%s", want, af6)
		}
	}
	if hasLine9667(af6, "  redistribute ospf") {
		t.Errorf("address-family ipv6 unicast must not carry the IPv4-only ospf source:\n%s", af6)
	}
	if strings.Contains(got, "redistribute bgp") {
		t.Errorf("BGP must not redistribute itself in either family:\n%s", got)
	}
}

// TestBGPIPv4OnlyBareTokensOpenNoIPv6Block_9667 is the control: IPv4-only
// sources leave the rendered config without an IPv6 address family.
func TestBGPIPv4OnlyBareTokensOpenNoIPv6Block_9667(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{LocalAS: 65001, RouterID: "1.1.1.1", Export: []string{"ospf", "rip"},
		Neighbors: []*config.BGPNeighbor{{Address: "10.0.2.1", PeerAS: 65002}}}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "address-family ipv6 unicast") {
		t.Errorf("IPv4-only sources must not open an IPv6 address family:\n%s", got)
	}
}

// TestBGPIPv6RedistributeSharesTheNeighborBlock_9667: with an IPv6 neighbor the
// redistribute lines join the existing block rather than opening a second one.
func TestBGPIPv6RedistributeSharesTheNeighborBlock_9667(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{LocalAS: 65001, RouterID: "1.1.1.1", Export: []string{"static"},
		Neighbors: []*config.BGPNeighbor{{Address: "2001:db8::2", PeerAS: 65002, FamilyInet6: true}}}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if n := strings.Count(got, "address-family ipv6 unicast"); n != 1 {
		t.Fatalf("want exactly one ipv6 unicast block, got %d:\n%s", n, got)
	}
	_, af6, _ := bgpBlocks9667(t, got)
	if !hasLine9667(af6, "  redistribute static") || !hasLine9667(af6, "  neighbor 2001:db8::2 activate") {
		t.Errorf("the block must carry both the neighbor and the redistribution:\n%s", af6)
	}
}

// TestRedistEntriesAtNodesAreCovered_9667 extends the #9510 census to the
// node-aware entry point: every caller passes a node the family table knows, and
// the only non-literal caller is redistributeEntries' pass-through.
func TestRedistEntriesAtNodesAreCovered_9667(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	callRE := regexp.MustCompile(`\.redistributeEntriesAt\(`)
	passRE := regexp.MustCompile(`\.redistributeEntriesAt\(export, po, self, self, bgpAcceptDefault\)`)
	litRE := regexp.MustCompile(`\.redistributeEntriesAt\([^,()]+,\s*[^,()]+,\s*"([a-z0-9-]+)",\s*"([a-z0-9-]+)",`)
	calls, pass := 0, 0
	nodes := map[string]int{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		calls += len(callRE.FindAllIndex(b, -1))
		pass += len(passRE.FindAllIndex(b, -1))
		for _, mm := range litRE.FindAllSubmatch(b, -1) {
			nodes[string(mm[2])]++
		}
	}
	lit := 0
	for _, c := range nodes {
		lit += c
	}
	if pass != 1 || calls != pass+lit {
		t.Fatalf("redistributeEntriesAt: %d calls, %d pass-through, %d literal nodes %v; a call this census cannot read is a node the filter cannot see", calls, pass, lit, nodes)
	}
	if nodes["bgp-ipv6"] == 0 {
		t.Fatal("positive control: the BGP IPv6 address-family caller was not found")
	}
	for node := range nodes {
		if _, ok := frrRedistNodeAFI[node]; !ok {
			t.Errorf("caller passes node %q, which frrRedistNodeAFI has no row for", node)
		}
	}
}

// TestCommitGateAndRendererAgreeOnBareTokenFamilies_9667 is the class cell: for
// every export use site and every bare protocol keyword, the strict commit gate
// accepts the token exactly when the renderer writes a redistribute line for it.
// Self-redistribution (dropped at render by design, #2943) is excluded.
func TestCommitGateAndRendererAgreeOnBareTokenFamilies_9667(t *testing.T) {
	type site struct {
		name, self, base, export string
		exports                  func(*config.Config) []string
	}
	sites := []site{
		{"ospf", "ospf", "set protocols ospf area 0.0.0.0 interface ge-0/0/0.0", "set protocols ospf export %s",
			func(c *config.Config) []string { return c.Protocols.OSPF.Export }},
		{"ospf3", "ospf6", "set protocols ospf3 area 0.0.0.0 interface ge-0/0/0.0", "set protocols ospf3 export %s",
			func(c *config.Config) []string { return c.Protocols.OSPFv3.Export }},
		{"rip", "rip", "set protocols rip group g neighbor ge-0/0/0.0", "set protocols rip redistribute %s",
			func(c *config.Config) []string { return c.Protocols.RIP.Redistribute }},
		{"isis", "isis", "set protocols isis interface ge-0/0/0.0", "set protocols isis export %s",
			func(c *config.Config) []string { return c.Protocols.ISIS.Export }},
		{"bgp", "bgp", "set protocols bgp local-as 65001", "set protocols bgp export %s",
			func(c *config.Config) []string { return c.Protocols.BGP.Export }},
	}
	tokens := []string{"direct", "static", "kernel", "ospf", "ospf6", "rip", "ripng", "isis", "bgp"}
	build := func(cmds []string) *config.ConfigTree {
		tree := &config.ConfigTree{}
		for _, c := range cmds {
			p, err := config.ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		return tree
	}
	m := New()
	for _, s := range sites {
		for _, tok := range tokens {
			kw, _ := config.FRRRoutingProtocolKeyword(tok)
			if kw == s.self {
				continue
			}
			cmds := []string{s.base, fmt.Sprintf(s.export, tok)}
			_, strictErr := config.CompileConfig(build(cmds))
			if strictErr != nil && !strings.Contains(strictErr.Error(), fmt.Sprintf("%q", tok)) {
				t.Fatalf("%s/%s: strict refusal is not the export gate, so this row cannot adjudicate: %v", s.name, tok, strictErr)
			}
			cfg, err := config.CompileConfigLenient(build(cmds))
			if err != nil {
				t.Fatalf("%s/%s: lenient compile: %v", s.name, tok, err)
			}
			if ex := s.exports(cfg); len(ex) != 1 || ex[0] != tok {
				t.Fatalf("%s/%s: precondition: the compiled export list must carry the token, got %v", s.name, tok, ex)
			}
			out := m.generateProtocols(cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.BGP,
				cfg.Protocols.RIP, cfg.Protocols.ISIS, "", 0, &cfg.PolicyOptions, nil)
			rendered := false
			for _, l := range strings.Split(out, "\n") {
				f := strings.Fields(l)
				if len(f) >= 2 && f[0] == "redistribute" {
					for _, x := range f[1:] {
						if x == kw {
							rendered = true
						}
					}
				}
			}
			if accepted := strictErr == nil; accepted != rendered {
				t.Errorf("%s export %s: strict commit accepted=%v but rendered=%v (%v)", s.name, tok, accepted, rendered, strictErr)
			}
		}
	}
}
