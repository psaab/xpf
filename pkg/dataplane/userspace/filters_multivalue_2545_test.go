package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2545: a firewall-filter term carrying several `from protocol` / `from dscp`
// / `from icmp-type` / `from icmp-code` values must emit ALL of them into the
// wire snapshot vectors (the Rust matcher does set membership). Before the fix
// the typed term stored a scalar (last value won), so only one value reached
// the dataplane.
func TestFilterSnapshotMultiValueEmitted(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"mv": {Name: "mv", Terms: []*config.FirewallFilterTerm{{
			Name:      "t",
			Protocols: []string{"tcp", "udp"},
			DSCPs:     []string{"ef", "af43"},
			ICMPTypes: []int{8, 0},
			ICMPCodes: []int{3, 4},
			Action:    config.FilterActionDiscard,
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
		t.Fatalf("expected 1 filter with 1 term, got %#v", snaps)
	}
	term := snaps[0].Terms[0]

	if len(term.Protocols) != 2 {
		t.Errorf("protocols = %v, want both tcp+udp emitted (#2545)", term.Protocols)
	}
	// ef = 46, af43 = 38.
	if len(term.DSCPValues) != 2 {
		t.Errorf("dscp_values = %v, want both ef+af43 emitted (#2545)", term.DSCPValues)
	}
	if len(term.ICMPTypes) != 2 {
		t.Errorf("icmp_types = %v, want [8 0] emitted (#2545)", term.ICMPTypes)
	}
	if len(term.ICMPCodes) != 2 {
		t.Errorf("icmp_codes = %v, want [3 4] emitted (#2545)", term.ICMPCodes)
	}
}

// An empty criterion must serialize to an empty wire vector (unconstrained =
// match-any), never a bogus zero entry.
func TestFilterSnapshotMultiValueEmptyStaysEmpty(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"mv": {Name: "mv", Terms: []*config.FirewallFilterTerm{{
			Name: "t", Action: config.FilterActionAccept,
		}}},
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if len(term.Protocols) != 0 || len(term.DSCPValues) != 0 ||
		len(term.ICMPTypes) != 0 || len(term.ICMPCodes) != 0 {
		t.Errorf("unconstrained term must emit empty vectors, got proto=%v dscp=%v itype=%v icode=%v",
			term.Protocols, term.DSCPValues, term.ICMPTypes, term.ICMPCodes)
	}
}
