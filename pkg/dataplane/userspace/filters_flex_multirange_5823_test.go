package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5823: a firewall-filter term that names MORE THAN ONE flexible-match-range
// range is unrepresentable on the wire (the matcher supports one). The strict
// commit gate rejects it, but a tolerant-load / peer-sync config can still carry
// it. The snapshot builder must NOT silently emit only the first range
// (fail-OPEN); it poisons the term to match NOTHING by emitting an
// UNREPRESENTABLE flex-match (a non-layer-3/4 match-start → FlexMatchStart::
// Unsupported → flex_matches() returns false in the Rust matcher).
//
// FAIL-ON-REVERT: dropping the len(FlexMatchRangeNames) > 1 poison arm in
// buildFilterTermSnapshots makes the builder emit the first range's real
// FlexMatch, so MatchStart is layer-3 (or "") — the term matches the first
// range instead of nothing, and this assert FAILS.
func TestFilterSnapshotMultiRangePoisonedToMatchNothing_5823(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"edge": {Name: "edge", Terms: []*config.FirewallFilterTerm{{
			Name:   "multi",
			Action: config.FilterActionAccept,
			// The first range is compiled into FlexMatch (as today), but two
			// ranges were named — the cardinality marker drives the poison.
			FlexMatch: &config.FlexMatchConfig{
				MatchStart: "layer-3",
				ByteOffset: 6,
				BitLength:  16,
				Value:      0x0800,
				Mask:       0xFFFF,
				ValueSet:   true,
				MaskSet:    true,
			},
			FlexMatchRangeNames: []string{"r1", "r2"},
		}}},
	}
	fm := buildFirewallFilterSnapshots(cfg)[0].Terms[0].FlexMatch
	if fm == nil {
		t.Fatal("a multi-range term must still emit a FlexMatch (the fail-closed poison), not drop it")
	}
	if fm.MatchStart != flexMatchStartUnrepresentable {
		t.Fatalf("multi-range term must be poisoned to an UNREPRESENTABLE match-start "+
			"(match nothing), got MatchStart=%q — the builder is enforcing only the first "+
			"range (fail-open)", fm.MatchStart)
	}
	// Length must stay in the representable 1..=4 range so flex_enabled is true
	// (the matcher then evaluates the term and, seeing an unsupported start,
	// fails it closed). A length outside 1..=4 would instead reject the WHOLE
	// snapshot — not the intended per-term match-nothing.
	if fm.Length < 1 || fm.Length > 4 {
		t.Fatalf("poison FlexMatch length %d must be 1..=4 so flex stays ENABLED and the "+
			"term is evaluated to false, not snapshot-rejected", fm.Length)
	}
	// The first range's real value must NOT leak onto the wire.
	if fm.Value == 0x0800 && fm.Mask == 0xFFFF && fm.Offset == 6 {
		t.Fatal("the first range's real match leaked onto the wire — the term is not poisoned")
	}
}

// A SINGLE range is unaffected — the builder emits the real flex-match
// byte-identically (no poison, MatchStart is the normal layer-3 => "" mapping).
func TestFilterSnapshotSingleRangeNotPoisoned_5823(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"edge": {Name: "edge", Terms: []*config.FirewallFilterTerm{{
			Name:   "one",
			Action: config.FilterActionDiscard,
			FlexMatch: &config.FlexMatchConfig{
				MatchStart: "layer-3",
				ByteOffset: 6,
				BitLength:  16,
				Value:      0x0800,
				Mask:       0xFFFF,
				ValueSet:   true,
				MaskSet:    true,
			},
			FlexMatchRangeNames: []string{"only"},
		}}},
	}
	fm := buildFirewallFilterSnapshots(cfg)[0].Terms[0].FlexMatch
	if fm == nil {
		t.Fatal("single-range FlexMatch must be emitted")
	}
	if fm.MatchStart == flexMatchStartUnrepresentable {
		t.Fatal("a single-range term must NOT be poisoned")
	}
	if fm.Offset != 6 || fm.Length != 2 || fm.Value != 0x0800 || fm.Mask != 0xFFFF {
		t.Fatalf("single-range wire fields changed: %+v", fm)
	}
}
