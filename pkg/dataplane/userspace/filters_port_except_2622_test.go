package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2622: a firewall-filter term carrying `from source-port-except` /
// `from destination-port-except` must emit those values into the dedicated wire
// snapshot vectors (`source_ports_except` / `destination_ports_except`), which
// the Rust compiler turns into a negated port matcher. Before the fix there was
// no leaf at all; this asserts the snapshot builder wires the typed slices onto
// the wire term.
//
// FAIL-ON-REVERT: drop the two append lines from filters.go and these vectors
// come back empty.
func TestFilterSnapshotPortExceptEmitted(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"pe": {Name: "pe", Terms: []*config.FirewallFilterTerm{{
			Name:              "t",
			Protocols:         []string{"tcp"},
			DestPortsExcept:   []string{"80", "443"},
			SourcePortsExcept: []string{"22"},
			Action:            config.FilterActionDiscard,
		}}},
	}
	snaps := authoredFilterSnapshots18728(t, buildFirewallFilterSnapshots(cfg))
	if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
		t.Fatalf("expected 1 filter with 1 term, got %#v", snaps)
	}
	term := snaps[0].Terms[0]
	if len(term.DestPortsExcept) != 2 ||
		term.DestPortsExcept[0] != "80" || term.DestPortsExcept[1] != "443" {
		t.Errorf("destination_ports_except = %v, want [80 443] (#2622)", term.DestPortsExcept)
	}
	if len(term.SourcePortsExcept) != 1 || term.SourcePortsExcept[0] != "22" {
		t.Errorf("source_ports_except = %v, want [22] (#2622)", term.SourcePortsExcept)
	}
}

// An unconstrained term emits empty except vectors (match-any), never a bogus
// entry — the positive and except port slices are independent.
func TestFilterSnapshotPortExceptEmptyStaysEmpty(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"pe": {Name: "pe", Terms: []*config.FirewallFilterTerm{{
			Name: "t", Action: config.FilterActionAccept,
		}}},
	}
	term := authoredFilterSnapshots18728(t, buildFirewallFilterSnapshots(cfg))[0].Terms[0]
	if len(term.SourcePortsExcept) != 0 || len(term.DestPortsExcept) != 0 {
		t.Errorf("unconstrained term must emit empty except vectors, got src=%v dst=%v",
			term.SourcePortsExcept, term.DestPortsExcept)
	}
}
