package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

type natApplyResultCLIDP struct {
	*dataplane.Manager
	result       *dataplane.ApplyResult
	calls        int
	counterReads int
}

func (d *natApplyResultCLIDP) IsLoaded() bool {
	return true
}

func (d *natApplyResultCLIDP) LastApplyResult() *dataplane.ApplyResult {
	d.calls++
	return d.result.Clone()
}

func (d *natApplyResultCLIDP) ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error) {
	d.counterReads++
	return dataplane.CounterValue{Packets: uint64(counterID), Bytes: uint64(counterID) * 100}, nil
}

func TestShowNATSourceRuleAllReadsApplyResultOnce(t *testing.T) {
	dp := &natApplyResultCLIDP{
		Manager: dataplane.New(),
		result: &dataplane.ApplyResult{
			NATCounterIDs: map[string]uint32{
				dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "trust-to-untrust", "r1"): 11,
				dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "trust-to-untrust", "r2"): 12,
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

func TestNATRuleCounterReadsRequireInstalledRule11743(t *testing.T) {
	sourceKey := dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "rs1", "r1")
	destKey := dataplane.NATCounterKey(dataplane.NATCounterTypeDest, "drs1", "dr1")
	renderers := []struct {
		name string
		src  bool
		call func(*CLI, *config.Config) error
	}{
		{"source rule-set", true, func(c *CLI, cfg *config.Config) error {
			return c.showNATSourceRuleSet(cfg, "rs1")
		}},
		{"source rule all", true, func(c *CLI, cfg *config.Config) error {
			return c.showNATSourceRuleAll(cfg)
		}},
		{"destination", false, func(c *CLI, cfg *config.Config) error {
			return c.showNATDestination(cfg, nil)
		}},
		{"destination pool", false, func(c *CLI, cfg *config.Config) error {
			return c.showNATDestinationPool(cfg, "")
		}},
		{"destination rule-set", false, func(c *CLI, cfg *config.Config) error {
			return c.showNATDestinationRuleSet(cfg, "drs1")
		}},
		{"destination rule all", false, func(c *CLI, cfg *config.Config) error {
			return c.showNATDestinationRuleAll(cfg)
		}},
		{"destination summary", false, func(c *CLI, cfg *config.Config) error {
			return c.showNATDestinationSummary(cfg)
		}},
	}

	for _, renderer := range renderers {
		for _, state := range []struct {
			name     string
			cfg      *config.Config
			wantRead int
		}{
			{"disarmed", func() *config.Config {
				if renderer.src {
					return disarmedSourceCfg()
				}
				return disarmedDestCfg()
			}(), 0},
			{"armed", func() *config.Config {
				if renderer.src {
					return armedSourceCfg()
				}
				return armedDestCfg()
			}(), 1},
		} {
			t.Run(renderer.name+"/"+state.name, func(t *testing.T) {
				dp := &natApplyResultCLIDP{
					Manager: dataplane.New(),
					result: &dataplane.ApplyResult{NATCounterIDs: map[string]uint32{
						sourceKey: 11,
						destKey:   12,
					}},
				}
				c := &CLI{dp: dp}
				out := captureStdout(t, func() {
					if err := renderer.call(c, state.cfg); err != nil {
						t.Fatalf("render: %v", err)
					}
				})
				if dp.counterReads != state.wantRead {
					t.Errorf("ReadNATRuleCounter calls = %d, want %d; output:\n%s",
						dp.counterReads, state.wantRead, out)
				}
				if renderer.name == "destination pool" &&
					!strings.Contains(out, "Referenced by: drs1/dr1 (from untrust)") {
					t.Errorf("destination pool output missing Referenced-by line; output:\n%s", out)
				}
			})
		}
	}
}

type destinationSummarySessionCLIDP13243 struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *destinationSummarySessionCLIDP13243) IsLoaded() bool { return true }

func (d *destinationSummarySessionCLIDP13243) LastApplyResult() *dataplane.ApplyResult {
	return d.result
}

func (d *destinationSummarySessionCLIDP13243) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	fn(dataplane.SessionKey{}, dataplane.SessionValue{
		Flags: dataplane.SessFlagDNAT, IngressZone: 8, EgressZone: 9,
	})
	return nil
}

func TestShowNATDestinationSummaryCountsFromZoneOnly13243(t *testing.T) {
	dp := &destinationSummarySessionCLIDP13243{
		Manager: dataplane.New(),
		result: &dataplane.ApplyResult{ZoneIDs: map[string]uint16{
			"untrust": 8, "dmz": 9,
		}},
	}
	cfg := &config.Config{Security: config.SecurityConfig{NAT: config.NATConfig{
		Destination: &config.DestinationNATConfig{
			Pools: map[string]*config.NATPool{"p": {Name: "p", Address: "10.0.0.1"}},
			RuleSets: []*config.NATRuleSet{{
				Name: "dnat-rs", FromZone: "untrust",
				Rules: []*config.NATRule{{Name: "r1", Then: config.NATThen{PoolName: "p"}}},
			}},
		},
	}}}
	c := &CLI{dp: dp}
	out := captureStdout(t, func() {
		if err := c.showNATDestinationSummary(cfg); err != nil {
			t.Fatalf("showNATDestinationSummary: %v", err)
		}
	})
	wantRow := fmt.Sprintf("%-30s %-12d", "untrust -> ", 1)
	if !strings.Contains(out, wantRow) {
		t.Fatalf("destination summary missing %q:\n%s", wantRow, out)
	}
}
