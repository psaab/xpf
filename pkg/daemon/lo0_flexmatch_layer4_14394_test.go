package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Regression for #14394 (DR8-H3): a lo0 filter term with
// `match-start layer-4` must render an @th-based rule in BOTH renderers
// (text oracle + netlink spec), and a term with an unrepresentable
// match-start must render no accept/widening rule. Before the fix both
// renderers dropped MatchStart and rendered at the L3 (@nh) base, so the
// parity gate passed while both were wrong.

func TestLo0FlexMatchLayer4RendersTh14394(t *testing.T) {
	fm := config.FlexMatchConfig{MatchStart: "layer-4", ByteOffset: 0, BitLength: 8, Value: 0x11, Mask: 0xff}
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"flexf": {Terms: []*config.FirewallFilterTerm{
			{Name: "flex", Protocols: []string{"tcp"}, FlexMatch: &fm, Action: "accept"},
			{Name: "deny-rest", Action: "discard"},
		}},
	}
	oracle := buildLo0FilterPayload(cfg, "flexf", "")
	if !strings.Contains(oracle, "@th,0,8 & 0xff == 0x11") {
		t.Fatalf("oracle must render layer-4 at the transport base (@th), got:\n%s", oracle)
	}
	if strings.Contains(oracle, "@nh,") {
		t.Fatalf("oracle still renders a layer-4 term at the network base (@nh):\n%s", oracle)
	}
	// Netlink spec must carry MatchStart through. The nftables unit test
	// pins the TH payload base for the same DTO value; here the DTO
	// carrying the field plus the @th oracle is the daemon-side half.
	spec := toNftLo0Spec(cfg, "flexf", "")
	if len(spec.V4Terms) == 0 || spec.V4Terms[0].FlexMatch == nil {
		t.Fatalf("netlink spec lost the flex-match: %+v", spec.V4Terms)
	}
	if got := spec.V4Terms[0].FlexMatch.MatchStart; got != "layer-4" {
		t.Fatalf("netlink spec FlexMatch.MatchStart = %q, want %q — the DTO dropped the field (#14394)", got, "layer-4")
	}
}

func TestLo0FlexMatchLayer3StillRendersNh14394(t *testing.T) {
	fm := config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 6, BitLength: 8, Value: 1, Mask: 0xff}
	got := nftRule(t, &config.FirewallFilterTerm{
		Name: "flex-l3", FlexMatch: &fm, Action: "accept",
	}, "ip", map[string]*config.PrefixList{})
	if !strings.Contains(got, "@nh,") {
		t.Fatalf("layer-3 control must still render @nh, got %q", got)
	}
	if strings.Contains(got, "@th,") {
		t.Fatalf("layer-3 control must not render @th, got %q", got)
	}
	// Empty match-start is the layer-3 default.
	fm2 := config.FlexMatchConfig{MatchStart: "", ByteOffset: 6, BitLength: 8, Value: 1, Mask: 0xff}
	got = nftRule(t, &config.FirewallFilterTerm{
		Name: "flex-empty", FlexMatch: &fm2, Action: "accept",
	}, "ip", map[string]*config.PrefixList{})
	if !strings.Contains(got, "@nh,") {
		t.Fatalf("empty match-start must render @nh (layer-3 default), got %q", got)
	}
}

func TestLo0FlexMatchUnrepresentableStartMatchesNothing14394(t *testing.T) {
	for _, start := range []string{"payload", "bogus"} {
		fm := config.FlexMatchConfig{MatchStart: start, ByteOffset: 6, BitLength: 8, Value: 1, Mask: 0xff}
		term := &config.FirewallFilterTerm{
			Name: "flex-bad-start", FlexMatch: &fm, Action: "accept",
		}
		if !lo0FlexMatchUnrepresentable(term) {
			t.Errorf("match-start %q: lo0FlexMatchUnrepresentable = false, want true", start)
		}
		got := nftRule(t, term, "ip", map[string]*config.PrefixList{})
		if got != "" {
			t.Errorf("match-start %q: oracle rendered %q, want \"\" (match-nothing, no widening rule)", start, got)
		}
		// Netlink converter must mark it unrepresentable so the plan
		// emits no rule for the term.
		specTerm := toNftLo0Term(term, nil)
		if !specTerm.FlexMatchUnrepresentable {
			t.Errorf("match-start %q: netlink spec FlexMatchUnrepresentable = false, want true", start)
		}
	}
	// A representable layer-4 term must NOT be marked unrepresentable.
	okTerm := &config.FirewallFilterTerm{
		Name:      "flex-l4",
		FlexMatch: &config.FlexMatchConfig{MatchStart: "layer-4", ByteOffset: 0, BitLength: 8, Value: 1, Mask: 0xff},
		Action:    "accept",
	}
	if lo0FlexMatchUnrepresentable(okTerm) {
		t.Errorf("layer-4 must be representable in the oracle check")
	}
	if toNftLo0Term(okTerm, nil).FlexMatchUnrepresentable {
		t.Errorf("layer-4 must not be marked unrepresentable in the netlink spec")
	}
}
