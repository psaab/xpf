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
	if strings.Contains(payload, " drop") {
		t.Fatalf("text oracle must not emit a verdict for an invalid flex term; payload:\n%s", payload)
	}
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
