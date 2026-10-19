package config

import (
	"strings"
	"testing"
)

// #15671: `protocols ndp` is in the vendored Junos 24.4
// host-inbound-protocols-object-type enumeration but was missing from
// KnownHostInboundProtocols, so strict commit rejected it while ND
// (ICMPv6 133-136) was globally admitted regardless. These cells pin
// the token, its family-scoped tuples, and `except` subtraction.

func TestHostInboundNDP15671KnownAndCommits(t *testing.T) {
	if !KnownHostInboundProtocols["ndp"] {
		t.Fatal("ndp must be in KnownHostInboundProtocols")
	}
	if HostInboundProtocolFamily["ndp"] != "ip6" {
		t.Fatalf("ndp family = %q, want ip6", HostInboundProtocolFamily["ndp"])
	}
	tree := buildTree(t, []string{
		"set security zones security-zone trust host-inbound-traffic protocols ndp",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected protocols ndp: %v", err)
	}
	got := cfg.Security.Zones["trust"].HostInboundTraffic.Protocols
	if len(got) != 1 || got[0] != "ndp" {
		t.Fatalf("compiled protocols = %v, want [ndp]", got)
	}
}

func TestHostInboundNDP15671MatchTuples(t *testing.T) {
	v6 := HostInboundProtocolMatch("ndp", "ip6")
	if len(v6) != 4 {
		t.Fatalf("ndp ip6 matches = %v, want 4 ICMPv6 types", v6)
	}
	seen := map[uint8]bool{}
	for _, m := range v6 {
		if m.Proto != HostInboundProtoICMPv6 || m.ICMPType == nil {
			t.Fatalf("ndp match = %+v, want icmpv6 type match", m)
		}
		seen[*m.ICMPType] = true
	}
	for _, typ := range []uint8{133, 134, 135, 136} {
		if !seen[typ] {
			t.Errorf("ndp ip6 missing ICMPv6 type %d", typ)
		}
	}
	if seen[137] {
		t.Error("ndp must not admit Redirect 137")
	}
	if got := HostInboundProtocolMatch("ndp", "ip"); len(got) != 0 {
		t.Errorf("ndp ip matches = %v, want none (IPv6-only)", got)
	}
}

func TestHostInboundNDP15671ExceptSubtracts(t *testing.T) {
	got := hostInboundFilterExcept([]string{"all"}, []string{"ndp"}, true)
	for _, tok := range got {
		if tok == "ndp" {
			t.Fatalf("all except ndp kept ndp: %v", got)
		}
		for _, m := range HostInboundProtocolMatch(tok, "ip6") {
			if m.Proto == HostInboundProtoICMPv6 && m.ICMPType != nil && *m.ICMPType >= 133 && *m.ICMPType <= 136 {
				t.Fatalf("surviving token %q still admits ND type %d after ndp except", tok, *m.ICMPType)
			}
		}
	}
	// Hierarchical except form compiles to all-minus-ndp.
	tree, errs := NewParser(`security { zones { security-zone trust { host-inbound-traffic { protocols { all; ndp { except; } } } } } }`).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile all except ndp: %v", err)
	}
	for _, tok := range cfg.Security.Zones["trust"].HostInboundTraffic.Protocols {
		if tok == "ndp" {
			t.Fatalf("compiled protocols kept ndp after except: %v", cfg.Security.Zones["trust"].HostInboundTraffic.Protocols)
		}
	}
	if !strings.Contains(strings.Join(cfg.Security.Zones["trust"].HostInboundTraffic.Protocols, ","), "ospf") {
		t.Fatal("all except ndp lost unrelated protocols")
	}
}

func TestHostInboundNDP15671YANGOracle(t *testing.T) {
	src := junosSchemaModuleSource(t)
	enums := junosSchemaGroupingEnums(t, src, "host-inbound-protocols-object-type")
	found := false
	for _, e := range enums {
		if e == "ndp" {
			found = true
		}
		if !KnownHostInboundProtocols[e] {
			t.Errorf("YANG protocols enum %q not in KnownHostInboundProtocols", e)
		}
	}
	if !found {
		t.Fatal("vendored YANG host-inbound-protocols-object-type lacks ndp — oracle broken")
	}
}

// Compiled `protocols all` + `ndp except` must carry the exclusion on
// the stanza so dataplane views can withdraw the ND default.
func TestHostInboundNDP15671CompiledExceptCarried(t *testing.T) {
	tree, errs := NewParser(`security { zones { security-zone trust { host-inbound-traffic { protocols { all; ndp { except; } } } } } }`).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	hib := cfg.Security.Zones["trust"].HostInboundTraffic
	found := false
	for _, tok := range hib.ProtocolsExceptTokens() {
		if tok == "ndp" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ProtocolsExceptTokens = %v, want ndp", hib.ProtocolsExceptTokens())
	}
}
