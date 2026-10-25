package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16849: a value-less (or out-of-width) flexible-match-range on a
// discard/reject term must refuse the whole candidate snapshot via
// FromUnrepresentable — poisoning the term to match-nothing would let
// its traffic fall through to later terms or the implicit accept. The
// Rust preflight rejects on FromUnrepresentable and retains prior-good.
//
// RED-on-revert: drop the FlexMatchValid arm in buildFilterTermSnapshots
// and the discard/reject rows lose the marker.

func flexCfg16849(action config.FilterAction, fm *config.FlexMatchConfig) *config.Config {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f1": {Name: "f1", Terms: []*config.FirewallFilterTerm{
			{Name: "drop-x", Action: action, FlexMatch: fm, FlexMatchRangeNames: []string{"r1"}},
			{Name: "rest", Action: config.FilterActionAccept},
		}},
	}
	return cfg
}

func TestFlexInvalidDiscardRejectRefusesSnapshot16849(t *testing.T) {
	missing := &config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 9, BitLength: 8, ValueMissing: true}
	for _, action := range []config.FilterAction{config.FilterActionDiscard, config.FilterActionReject} {
		snaps := buildFirewallFilterSnapshots(flexCfg16849(action, missing))
		term := snaps[0].Terms[0]
		if !term.FromUnrepresentable {
			t.Errorf("%s value-less flex term must set FromUnrepresentable (#16849), got %+v", action, term)
		}
		if term.FlexMatch == nil || term.FlexMatch.MatchStart != flexMatchStartUnrepresentable {
			t.Errorf("%s value-less flex term must keep the sentinel as defense-in-depth, got %+v", action, term.FlexMatch)
		}
	}
	// Out-of-width also refuses.
	wide := &config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 9, BitLength: 4, Value: 0x40, Mask: 0xFF, ValueSet: true, MaskSet: true}
	if term := buildFirewallFilterSnapshots(flexCfg16849(config.FilterActionDiscard, wide))[0].Terms[0]; !term.FromUnrepresentable {
		t.Errorf("out-of-width flex term must set FromUnrepresentable, got %+v", term)
	}
	// Valued control stays live and unmarked.
	ok := &config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 9, BitLength: 8, Value: 0x11, Mask: 0xFF, ValueSet: true, MaskSet: true}
	term := buildFirewallFilterSnapshots(flexCfg16849(config.FilterActionDiscard, ok))[0].Terms[0]
	if term.FromUnrepresentable {
		t.Errorf("valued control must not refuse, got %+v", term)
	}
	if term.FlexMatch == nil || term.FlexMatch.MatchStart == flexMatchStartUnrepresentable || term.FlexMatch.Value != 0x11 {
		t.Errorf("valued control must stay live, got %+v", term.FlexMatch)
	}
	// Accept value-less also refuses (action-agnostic whole-snapshot refusal).
	if term := buildFirewallFilterSnapshots(flexCfg16849(config.FilterActionAccept, missing))[0].Terms[0]; !term.FromUnrepresentable {
		t.Errorf("accept value-less flex term must set FromUnrepresentable, got %+v", term)
	}
}
