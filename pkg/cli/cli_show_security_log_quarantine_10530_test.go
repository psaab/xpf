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
	result := &dataplane.ApplyResult{
		ZoneIDs: map[string]uint16{"trust": config.StableZoneID("trust"), "z174": id, "z214": id},
	}
	for i := range 100 {
		eb := logging.NewEventBuffer(16)
		eb.Add(logging.EventRecord{Type: "SESSION_OPEN", InZone: id, OutZone: id, SrcAddr: "10.0.0.1:1", DstAddr: "10.0.0.2:2"})
		c := &CLI{store: store, eventBuf: eb, dp: &quarantineSessionCLIDP10530{Manager: nil, result: result}}
		out := captureStdout(t, func() {
			if err := c.showSecurityLog([]string{"zone", "z214"}); err != nil {
				t.Fatalf("iteration %d showSecurityLog: %v", i, err)
			}
		})
		if !strings.Contains(out, config.ZoneQuarantineReferenceQualifier) {
			t.Fatalf("iteration %d quarantined CLI event text lacks reference qualifier:\n%s", i, out)
		}
		if !strings.Contains(out, "z174 "+config.ZoneQuarantineReferenceQualifier) {
			t.Fatalf("iteration %d quarantined fallback survivor name lacks qualifier:\n%s", i, out)
		}
	}
	storedEB := logging.NewEventBuffer(16)
	storedEB.Add(logging.EventRecord{
		Type: "SESSION_OPEN", InZone: id, OutZone: id,
		InZoneName: "z174", OutZoneName: "z174",
	})
	storedCLI := &CLI{store: store, eventBuf: storedEB, dp: &quarantineSessionCLIDP10530{Manager: nil, result: result}}
	storedOut := captureStdout(t, func() {
		if err := storedCLI.showSecurityLog([]string{"zone", "z214"}); err != nil {
			t.Fatalf("stored-name showSecurityLog: %v", err)
		}
	})
	if !strings.Contains(storedOut, "z174 "+config.ZoneQuarantineReferenceQualifier) {
		t.Fatalf("stored survivor name lacks filter qualifier:\n%s", storedOut)
	}

	ordinaryID := config.StableZoneID("trust")
	eb := logging.NewEventBuffer(16)
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", InZone: ordinaryID, OutZone: ordinaryID, SrcAddr: "10.0.0.3:3", DstAddr: "10.0.0.4:4"})
	ordinary := &CLI{store: store, eventBuf: eb, dp: &quarantineSessionCLIDP10530{Manager: nil, result: result}}
	out := captureStdout(t, func() {
		if err := ordinary.showSecurityLog([]string{"zone", "z214", "zone", "trust"}); err != nil {
			t.Fatalf("ordinary duplicate-zone showSecurityLog: %v", err)
		}
	})
	if strings.Contains(out, config.ZoneQuarantineReferenceQualifier) ||
		!strings.Contains(out, `source-zone-name="trust"`) {
		t.Fatalf("last duplicate zone filter did not win ordinary control:\n%s", out)
	}
}
