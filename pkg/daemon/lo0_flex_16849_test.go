package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16849: an invalid flexible-match-range (value-less / out-of-width) on a
// lo0 term must refuse the whole load on both mirrors — the text oracle
// emits the constant refusal bareword and the netlink DTO carries
// FromUnrepresentable — instead of matching nothing and falling through.

func TestLo0FlexInvalidRefuses16849(t *testing.T) {
	missing := &config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 9, BitLength: 8, ValueMissing: true}
	term := &config.FirewallFilterTerm{Name: "drop-x", Action: config.FilterActionDiscard, FlexMatch: missing, FlexMatchRangeNames: []string{"r1"}}
	cfg := lo0Cfg9875(term)
	payload := buildLo0FilterPayload(cfg, "protect-re", "")
	if !strings.Contains(payload, nftRefuseUnrepresentableFrom) {
		t.Fatalf("text oracle must refuse an invalid flex term (#16849); payload:\n%s", payload)
	}
	// #18746: key the no-verdict check on the term's OWN lines. Since #16841
	// (2fa9d69062) every lo0 chain opens with `ip6 hoplimit 0 fib daddr type
	// { local, anycast } drop`, so "no ` drop` anywhere in the payload" can never
	// hold, and this cell was red from the day it landed.
	lo0OwnLinesRefuseWithoutVerdict18746(t, term)
	lowered := lowerLo0Term9875(t, cfg)
	if !lowered.FromUnrepresentable {
		t.Fatalf("netlink DTO must carry FromUnrepresentable for an invalid flex term, got %+v", lowered)
	}
	// Valued control renders live on both mirrors.
	ok := &config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 9, BitLength: 8, Value: 0x11, Mask: 0xFF, ValueSet: true, MaskSet: true}
	okCfg := lo0Cfg9875(&config.FirewallFilterTerm{Name: "ok", Action: config.FilterActionDiscard, FlexMatch: ok, FlexMatchRangeNames: []string{"r1"}})
	okPayload := buildLo0FilterPayload(okCfg, "protect-re", "")
	if strings.Contains(okPayload, nftRefuseUnrepresentableFrom) {
		t.Fatalf("valued control must not refuse; payload:\n%s", okPayload)
	}
	if lowered := lowerLo0Term9875(t, okCfg); lowered.FromUnrepresentable {
		t.Fatalf("valued control must not carry FromUnrepresentable, got %+v", lowered)
	}
}

// lo0TermOwnLines18746 returns the lo0 text-oracle lines one term contributes:
// the lines of the payload rendered with [control, term] that the payload
// rendered with [control] alone lacks (a multiset difference). It keys a check
// on the term's OWN lines, so rules every chain carries (the #16841 zero-hop
// DROP, an implicit final discard) appear in both renders and drop out.
func lo0TermOwnLines18746(t *testing.T, term *config.FirewallFilterTerm) []string {
	t.Helper()
	control := &config.FirewallFilterTerm{Name: "control-ssh", Protocols: []string{"tcp"}, DestinationPorts: []string{"22"}, Action: config.FilterActionAccept}
	render := func(terms ...*config.FirewallFilterTerm) []string {
		cfg := &config.Config{}
		cfg.System.Lo0FilterInputV4 = "protect-re"
		cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{"protect-re": {Name: "protect-re", Terms: terms}}
		return strings.Split(buildLo0FilterPayload(cfg, "protect-re", ""), "\n")
	}
	base := map[string]int{}
	for _, l := range render(control) {
		base[l]++
	}
	var own []string
	for _, l := range render(control, term) {
		if base[l] > 0 {
			base[l]--
			continue
		}
		own = append(own, l)
	}
	return own
}

// lo0OwnLinesRefuseWithoutVerdict18746 checks the refused term's own lines: the
// refusal bareword and no verdict at all.
func lo0OwnLinesRefuseWithoutVerdict18746(t *testing.T, term *config.FirewallFilterTerm) {
	t.Helper()
	own := lo0TermOwnLines18746(t, term)
	refused := false
	for _, l := range own {
		if strings.Contains(l, nftRefuseUnrepresentableFrom) {
			refused = true
		}
		for _, verdict := range []string{" drop", " accept", " reject", " jump ", " goto "} {
			if strings.Contains(l, verdict) {
				t.Errorf("the refused term %q emits a verdict on its own line %q", term.Name, strings.TrimSpace(l))
			}
		}
	}
	if !refused {
		t.Errorf("the refused term %q does not carry the refusal bareword on its own lines: %q", term.Name, own)
	}
}
