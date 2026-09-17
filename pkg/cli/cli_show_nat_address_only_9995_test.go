package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #9995: address-only (`port no-translation`) pools have no port utilization to
// measure — `reserve_address_only` never touches port occupancy, so UsedPorts
// is permanently 0 — yet both CLI renders derived Available/Utilization from
// `used` without consulting inapplicability, printing fabricated full
// availability and 0.0% utilization.
//
// FAIL-ON-REVERT: delete the PortNoTranslation gate in either renderer and the
// p1 leg reds (measured-looking 0.0%/full-availability figures return).

type addrOnlyCLIDP9995 struct {
	*dataplane.Manager
	poolIDs map[string]uint8
	status  dpuserspace.ProcessStatus
}

func (d *addrOnlyCLIDP9995) IsLoaded() bool { return true }
func (d *addrOnlyCLIDP9995) LastApplyResult() *dataplane.ApplyResult {
	return &dataplane.ApplyResult{PoolIDs: d.poolIDs}
}
func (d *addrOnlyCLIDP9995) ReadNATPortCounter(uint32) (uint64, error)  { return 0, nil }
func (d *addrOnlyCLIDP9995) Status() (dpuserspace.ProcessStatus, error) { return d.status, nil }

func addrOnlyCLI9995(pools ...dpuserspace.SourceNATPoolStatus) *CLI {
	ids := map[string]uint8{}
	for i, p := range pools {
		ids[p.PoolName] = uint8(i)
	}
	return &CLI{dp: &addrOnlyCLIDP9995{
		Manager: dataplane.New(),
		poolIDs: ids,
		status:  dpuserspace.ProcessStatus{SourceNATPools: pools},
	}}
}

// addrOnlySourceCfg9995: p1 is address-only, p2 is a normal PAT pool (the
// measurable control — its render must stay numeric).
func addrOnlySourceCfg9995() *config.Config {
	return &config.Config{Security: config.SecurityConfig{NAT: config.NATConfig{
		SourcePools: map[string]*config.NATPool{
			"p1": {Name: "p1", Addresses: []string{"192.0.2.10"}, PortNoTranslation: true},
			"p2": {Name: "p2", Addresses: []string{"192.0.2.11"}},
		},
		Source: []*config.NATRuleSet{{
			Name: "rs", FromZone: "trust", ToZone: "untrust",
			Rules: []*config.NATRule{
				{Name: "r1", Then: config.NATThen{Type: config.NATSource, PoolName: "p1"}},
				{Name: "r2", Then: config.NATThen{Type: config.NATSource, PoolName: "p2"}},
			},
		}},
	}}}
}

func summaryRow9995(t *testing.T, out, pool string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == pool {
			return line
		}
	}
	t.Fatalf("summary rendered no row for pool %q, so the assertion is not about the gate:\n%s", pool, out)
	return ""
}

func TestSourceNATSummaryAddressOnlyNotApplicable9995(t *testing.T) {
	c := addrOnlyCLI9995(
		// The helper genuinely reports 0 used ports for an address-only
		// pool — that zero is MEASURED, which is exactly why the derived
		// Available/Utilization figures look trustworthy and are not.
		dpuserspace.SourceNATPoolStatus{PoolName: "p1", UsedPorts: 0},
		dpuserspace.SourceNATPoolStatus{PoolName: "p2", UsedPorts: 100},
	)
	out := captureStdout(t, func() {
		if err := c.showNATSourceSummary(addrOnlySourceCfg9995()); err != nil {
			t.Fatalf("summary: %v", err)
		}
	})

	p1 := summaryRow9995(t, out, "p1")
	if got := strings.Count(p1, "NOT APPLICABLE"); got != 4 {
		t.Errorf("address-only pool summary must gate ports/used/available/utilization (4 N/A values), got %d in %q.\nfull output:\n%s",
			got, p1, out)
	}
	if strings.Contains(p1, "0.0%") {
		t.Errorf("address-only pool summary row renders a fabricated 0.0%% utilization: %q", p1)
	}

	// Control: the measurable PAT pool must stay numeric, or the gate is
	// suppressing every pool rather than the inapplicable ones.
	p2 := summaryRow9995(t, out, "p2")
	if strings.Contains(p2, "NOT APPLICABLE") {
		t.Errorf("measurable pool summary row must stay numeric, got %q", p2)
	}
	if !strings.Contains(p2, "%") {
		t.Errorf("measurable pool summary row lost its utilization figure: %q", p2)
	}
}

func TestSourceNATDetailAddressOnlyNotApplicable9995(t *testing.T) {
	c := addrOnlyCLI9995(
		dpuserspace.SourceNATPoolStatus{PoolName: "p1", UsedPorts: 0},
		dpuserspace.SourceNATPoolStatus{PoolName: "p2", UsedPorts: 100},
	)
	cfg := addrOnlySourceCfg9995()

	out := captureStdout(t, func() {
		if err := c.showNATSourcePool(cfg, "p1"); err != nil {
			t.Fatalf("detail p1: %v", err)
		}
	})
	if !strings.Contains(out, "Pool name: p1") {
		t.Fatalf("detail fixture did not render pool p1, so the assertion is not about the gate:\n%s", out)
	}
	if !strings.Contains(out, "Port range: NOT APPLICABLE") {
		t.Errorf("address-only pool detail must gate the irrelevant port range, got:\n%s", out)
	}
	if !strings.Contains(out, "Ports allocated: NOT APPLICABLE") {
		t.Errorf("address-only pool detail must show \"Ports allocated: NOT APPLICABLE\", got:\n%s", out)
	}
	if !strings.Contains(out, "Ports available: NOT APPLICABLE") {
		t.Errorf("address-only pool detail must show \"Ports available: NOT APPLICABLE\", got:\n%s", out)
	}
	if !strings.Contains(out, "Utilization: NOT APPLICABLE") {
		t.Errorf("address-only pool detail must show \"Utilization: NOT APPLICABLE\", got:\n%s", out)
	}
	if strings.Contains(out, "Utilization: 0.0%") {
		t.Errorf("address-only pool detail renders a fabricated 0.0%% utilization:\n%s", out)
	}

	// Control: the measurable PAT pool must stay numeric.
	ctrl := captureStdout(t, func() {
		if err := c.showNATSourcePool(cfg, "p2"); err != nil {
			t.Fatalf("detail p2: %v", err)
		}
	})
	if strings.Contains(ctrl, "NOT APPLICABLE") {
		t.Errorf("measurable pool detail must stay numeric, got:\n%s", ctrl)
	}
	if !strings.Contains(ctrl, "Utilization: ") || !strings.Contains(ctrl, "%") {
		t.Errorf("measurable pool detail lost its utilization figure:\n%s", ctrl)
	}
}
