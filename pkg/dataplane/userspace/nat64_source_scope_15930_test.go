package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15930: NAT64 source scope must be fail-closed end-to-end (Cox C1/C3 +
// DP F3/F4). A poisoned/unresolvable source-address name must NEVER widen
// to any-source (the builder used to clear the list, and Rust reads an
// empty list as unconstrained), and an explicit `match source-address
// any` must match any source (it used to ship verbatim and match
// nothing). Fixtures are strict: name->empty set and DNS-name with zero
// answers must yield a never-match wire shape; a valid named source is
// the control.

// nat64ScopeCfg15930 builds a one-rule NAT64 config with the given
// literal/source-name selectors and address-book entries (may be nil).
func nat64ScopeCfg15930(sources, names []string, addresses map[string]*config.Address, sets map[string]*config.AddressSet) *config.Config {
	cfg := &config.Config{}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses:   addresses,
		AddressSets: sets,
	}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p64": {Name: "p64", Addresses: []string{"100.64.0.1/32"}},
	}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{{
		Name:               "rs1",
		Prefix:             "64:ff9b::/96",
		SourcePool:         "p64",
		SourceAddresses:    sources,
		SourceAddressNames: names,
	}}
	return cfg
}

func nat64Snap15930(t *testing.T, cfg *config.Config) NAT64RuleSnapshot {
	t.Helper()
	snaps := buildNAT64Snapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	return snaps[0]
}

// neverMatch15930 reports whether the wire shape can only match NOTHING:
// constrained, with no entry the Rust IPv6 parser can accept.
func neverMatch15930(s NAT64RuleSnapshot) bool {
	if !s.SourceConstrained {
		return false
	}
	for _, a := range s.SourceAddresses {
		if a == "::/0" || strings.HasPrefix(a, "2001:") {
			return false
		}
	}
	return len(s.SourceAddresses) > 0
}

// matchAny15930 reports whether the wire shape matches any IPv6 source:
// either unconstrained or carrying the canonical ::/0.
func matchAny15930(s NAT64RuleSnapshot) bool {
	if !s.SourceConstrained {
		return true
	}
	for _, a := range s.SourceAddresses {
		if a == "::/0" {
			return true
		}
	}
	return false
}

func TestNAT64PoisonedNameFailsClosed15930(t *testing.T) {
	// DNS-name whose resolution yielded zero answers: UsableValues is
	// empty, expandBookNameRecursive poisons the closure. This is the
	// C1 transient-DNS-failure shape.
	cfg := nat64ScopeCfg15930(nil, []string{"dns-clients"}, map[string]*config.Address{
		"dns-clients": {Name: "dns-clients", DNSName: "clients.example.net", DNSAddresses: nil},
	}, nil)
	s := nat64Snap15930(t, cfg)
	if !neverMatch15930(s) {
		t.Fatalf("poisoned DNS name widened or vanished: constrained=%v addrs=%v, want never-match sentinel", s.SourceConstrained, s.SourceAddresses)
	}
	if len(s.SourceAddresses) != 1 || !strings.HasPrefix(s.SourceAddresses[0], natUnresolvedAddressNamePrefix) {
		t.Fatalf("SourceAddresses = %v, want [%s<name>]", s.SourceAddresses, natUnresolvedAddressNamePrefix)
	}
}

func TestNAT64EmptyNamedSetFailsClosed15930(t *testing.T) {
	// A defined address-set with NO members: name->empty set.
	cfg := nat64ScopeCfg15930(nil, []string{"empty-set"}, nil, map[string]*config.AddressSet{
		"empty-set": {Name: "empty-set"},
	})
	s := nat64Snap15930(t, cfg)
	if !neverMatch15930(s) {
		t.Fatalf("empty named set widened: constrained=%v addrs=%v, want never-match", s.SourceConstrained, s.SourceAddresses)
	}
}

func TestNAT64UnknownMemberSetFailsClosed15930(t *testing.T) {
	cfg := nat64ScopeCfg15930(nil, []string{"bad-set"}, nil, map[string]*config.AddressSet{
		"bad-set": {Name: "bad-set", UnknownMembers: []string{"addres"}},
	})
	s := nat64Snap15930(t, cfg)
	if !neverMatch15930(s) {
		t.Fatalf("unknown-member set widened: constrained=%v addrs=%v, want never-match", s.SourceConstrained, s.SourceAddresses)
	}
}

func TestNAT64UndefinedNameLiteralPlusPoison15930(t *testing.T) {
	// Literal + poisoned name: the poison must NOT clear the side to
	// unconstrained, and must NOT leave the surviving literal subset
	// (that would silently narrow differently than authored — the
	// whole side fails closed, as SNAT does).
	cfg := nat64ScopeCfg15930([]string{"2001:db8:2::/48"}, []string{"nosuchname"}, nil, nil)
	s := nat64Snap15930(t, cfg)
	if !neverMatch15930(s) {
		t.Fatalf("literal+poison must fail closed as a whole: constrained=%v addrs=%v", s.SourceConstrained, s.SourceAddresses)
	}
	for _, a := range s.SourceAddresses {
		if a == "2001:db8:2::/48" {
			t.Fatalf("surviving literal subset shipped alongside poison: %v", s.SourceAddresses)
		}
	}
}

func TestNAT64ValidNamedSourceControl15930(t *testing.T) {
	cfg := nat64ScopeCfg15930(nil, []string{"clients-v6"}, map[string]*config.Address{
		"clients-v6": {Name: "clients-v6", Value: "2001:db8:1::/48"},
	}, nil)
	s := nat64Snap15930(t, cfg)
	if !s.SourceConstrained || len(s.SourceAddresses) != 1 || s.SourceAddresses[0] != "2001:db8:1::/48" {
		t.Fatalf("valid named source control broken: constrained=%v addrs=%v", s.SourceConstrained, s.SourceAddresses)
	}
}

func TestNAT64DNSNameWithAnswersControl15930(t *testing.T) {
	cfg := nat64ScopeCfg15930(nil, []string{"dns-clients"}, map[string]*config.Address{
		"dns-clients": {Name: "dns-clients", DNSName: "clients.example.net", DNSAddresses: []string{"2001:db8:9::/48"}},
	}, nil)
	s := nat64Snap15930(t, cfg)
	if !s.SourceConstrained || len(s.SourceAddresses) != 1 || s.SourceAddresses[0] != "2001:db8:9::/48" {
		t.Fatalf("DNS name with answers must resolve: constrained=%v addrs=%v", s.SourceConstrained, s.SourceAddresses)
	}
}

func TestNAT64ExplicitAnyMatchesAny15930(t *testing.T) {
	for _, sources := range [][]string{{"any"}, {"any6"}, {"any-ipv6"}, {"::/0"}} {
		s := nat64Snap15930(t, nat64ScopeCfg15930(sources, nil, nil, nil))
		if !matchAny15930(s) {
			t.Fatalf("source-address %v must match any: constrained=%v addrs=%v", sources, s.SourceConstrained, s.SourceAddresses)
		}
		if len(s.SourceAddresses) != 1 || s.SourceAddresses[0] != "::/0" {
			t.Fatalf("source-address %v must lower to [::/0], got %v", sources, s.SourceAddresses)
		}
	}
	// Omitted selector control: unconstrained, empty list.
	s := nat64Snap15930(t, nat64ScopeCfg15930(nil, nil, nil, nil))
	if s.SourceConstrained || len(s.SourceAddresses) != 0 {
		t.Fatalf("omitted selector must stay unconstrained: constrained=%v addrs=%v", s.SourceConstrained, s.SourceAddresses)
	}
	// Constrained literal control: NOT match-any.
	s = nat64Snap15930(t, nat64ScopeCfg15930([]string{"2001:db8:1::/48"}, nil, nil, nil))
	if matchAny15930(s) || !s.SourceConstrained {
		t.Fatalf("constrained literal must not match any: constrained=%v addrs=%v", s.SourceConstrained, s.SourceAddresses)
	}
}

func TestNAT64MixedAnyWins15930(t *testing.T) {
	// Junos list semantics (triple-review fold): a v6-covering wildcard
	// ANYWHERE in the authored selector makes the whole side match-any;
	// stripping it beside narrower entries would narrow the authored
	// scope. Covers literal+wildcard in both orders, wildcard + valid
	// name, and a name resolving to ::/0.
	addresses := map[string]*config.Address{
		"clients-v6": {Name: "clients-v6", Value: "2001:db8:1::/48"},
		"all-v6":     {Name: "all-v6", Value: "::/0"},
	}
	for _, tc := range []struct {
		name    string
		sources []string
		names   []string
	}{
		{"any-first", []string{"any", "2001:db8:1::/48"}, nil},
		{"any-last", []string{"2001:db8:1::/48", "any"}, nil},
		{"any6-mixed", []string{"any6", "2001:db8:1::/48"}, nil},
		{"slash0-mixed", []string{"2001:db8:1::/48", "::/0"}, nil},
		{"any-plus-valid-name", []string{"any"}, []string{"clients-v6"}},
		{"name-resolves-slash0", nil, []string{"all-v6"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := nat64Snap15930(t, nat64ScopeCfg15930(tc.sources, tc.names, addresses, nil))
			if !matchAny15930(s) {
				t.Fatalf("mixed selector %v/%v must match any: constrained=%v addrs=%v", tc.sources, tc.names, s.SourceConstrained, s.SourceAddresses)
			}
			if len(s.SourceAddresses) != 1 || s.SourceAddresses[0] != "::/0" || s.SourceConstrained {
				t.Fatalf("mixed selector must lower to unconstrained [::/0], got constrained=%v addrs=%v", s.SourceConstrained, s.SourceAddresses)
			}
		})
	}
	// Poison still wins over a literal wildcard: an authored-but-
	// unusable name beside `any` stays fail-closed, never silently
	// dropped into match-any.
	s := nat64Snap15930(t, nat64ScopeCfg15930([]string{"any"}, []string{"nosuchname"}, nil, nil))
	if !neverMatch15930(s) {
		t.Fatalf("any + poisoned name must fail closed: constrained=%v addrs=%v", s.SourceConstrained, s.SourceAddresses)
	}
}

func TestNAT64Any4NeverMatchesV6_15930(t *testing.T) {
	// An IPv4-only wildcard beside nothing else can never match an IPv6
	// NAT64 source; it must not widen to any-IPv6.
	s := nat64Snap15930(t, nat64ScopeCfg15930([]string{"any4"}, nil, nil, nil))
	if matchAny15930(s) {
		t.Fatalf("any4 widened to any IPv6 source: constrained=%v addrs=%v", s.SourceConstrained, s.SourceAddresses)
	}
	if !s.SourceConstrained {
		t.Fatalf("any4 must stay constrained (never-match): addrs=%v", s.SourceAddresses)
	}
}
