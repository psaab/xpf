package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

type natApplyResultCLIDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
	calls  int
}

func (d *natApplyResultCLIDP) IsLoaded() bool {
	return true
}

func (d *natApplyResultCLIDP) LastApplyResult() *dataplane.ApplyResult {
	d.calls++
	return d.result.Clone()
}

func (d *natApplyResultCLIDP) ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{Packets: uint64(counterID), Bytes: uint64(counterID) * 100}, nil
}

func TestShowNATSourceRuleAllReadsApplyResultOnce(t *testing.T) {
	dp := &natApplyResultCLIDP{
		Manager: dataplane.New(),
		result: &dataplane.ApplyResult{
			NATCounterIDs: map[string]uint32{
				"trust-to-untrust/r1": 11,
				"trust-to-untrust/r2": 12,
			},
		},
	}
	c := &CLI{dp: dp}
	cfg := &config.Config{
		Security: config.SecurityConfig{
			NAT: config.NATConfig{
				Source: []*config.NATRuleSet{{
					Name:     "trust-to-untrust",
					FromZone: "trust",
					ToZone:   "untrust",
					Rules: []*config.NATRule{
						{Name: "r1", Match: config.NATMatch{SourceAddress: "10.0.0.0/8"}, Then: config.NATThen{Interface: true}},
						{Name: "r2", Match: config.NATMatch{SourceAddress: "172.16.0.0/12"}, Then: config.NATThen{Interface: true}},
					},
				}},
			},
		},
	}

	out := captureStdout(t, func() {
		if err := c.showNATSourceRuleAll(cfg); err != nil {
			t.Fatalf("showNATSourceRuleAll() error = %v", err)
		}
	})

	if dp.calls != 1 {
		t.Fatalf("LastApplyResult() calls = %d, want 1", dp.calls)
	}
	if !strings.Contains(out, "Translation hits: 11 packets") || !strings.Contains(out, "Translation hits: 12 packets") {
		t.Fatalf("output = %q, want counters for both rules", out)
	}
}
