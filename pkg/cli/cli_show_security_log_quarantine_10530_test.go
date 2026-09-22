package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
)

func TestShowSecurityLogQuarantineQualifier10530(t *testing.T) {
	id := config.StableZoneID("z174")
	store := newPolicyHitCountCLIStore(t, true)
	cfg := store.ActiveConfig()
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"},
		"z174":  {Name: "z174"},
		"z214":  {Name: "z214"},
	}
	eb := logging.NewEventBuffer(16)
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", InZone: id, OutZone: id, SrcAddr: "10.0.0.1:1", DstAddr: "10.0.0.2:2"})
	c := &CLI{store: store, eventBuf: eb, dp: &quarantineSessionCLIDP10530{Manager: nil, result: &dataplane.ApplyResult{
		ZoneIDs: map[string]uint16{"trust": config.StableZoneID("trust"), "z174": id, "z214": id},
	}}}
	out := captureStdout(t, func() {
		if err := c.showSecurityLog([]string{"zone", "z214"}); err != nil {
			t.Fatalf("showSecurityLog: %v", err)
		}
	})
	if !strings.Contains(out, config.ZoneQuarantineReferenceQualifier) {
		t.Fatalf("quarantined CLI event text lacks reference qualifier:\n%s", out)
	}
	if !strings.Contains(out, "z174 "+config.ZoneQuarantineReferenceQualifier) {
		t.Fatalf("quarantined fallback survivor name lacks qualifier:\n%s", out)
	}
}
