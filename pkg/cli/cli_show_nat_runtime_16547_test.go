package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #16547: CLI source-NAT views must annotate the runtime quarantine. The
// fixture pool is usable by definition (armedSourceCfg), so only the
// runtime verdict can produce the banner.

type natVerdictsCLIDP struct {
	*dataplane.Manager
	verdicts dpuserspace.AppliedNATSnapshotVerdicts
}

func (d *natVerdictsCLIDP) IsLoaded() bool { return true }
func (d *natVerdictsCLIDP) AppliedNATSnapshotVerdicts() dpuserspace.AppliedNATSnapshotVerdicts {
	return d.verdicts
}

func runtimeQuarantineCLI() *CLI {
	return &CLI{dp: &natVerdictsCLIDP{Manager: dataplane.New(), verdicts: dpuserspace.AppliedNATSnapshotVerdicts{
		Available:      true,
		SourceNATRules: map[string]string{"r1": "iface_snat_egress_overlap"},
		SourceNATPools: map[string]string{"p1": "iface_snat_egress_overlap"},
		NAT64Rules:     map[string]string{},
	}}}
}

func TestCLINATRuntimeQuarantine16547(t *testing.T) {
	cfg := armedSourceCfg()
	c := runtimeQuarantineCLI()

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"ruleAll", func() error { return c.showNATSourceRuleAll(cfg, "") }},
		{"ruleSet", func() error { return c.showNATSourceRuleSet(cfg, "rs1") }},
		{"summary", func() error { return c.showNATSourceSummary(cfg) }},
		{"poolDetail", func() error { return c.showNATSourcePool(cfg, "") }},
		{"ruleDetail", func() error { return c.showNATSourceRuleDetail(cfg) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				if err := tc.call(); err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
			})
			if tc.name == "poolDetail" {
				// Pool detail renders the verdict as "Unusable: ..." rather
				// than the NOT INSTALLED banner.
				if !strings.Contains(out, "Unusable:") || !strings.Contains(out, "interface") {
					t.Errorf("poolDetail renders a runtime-quarantined pool as armed:\n%s", out)
				}
				return
			}
			if !strings.Contains(out, "NOT INSTALLED") {
				t.Errorf("%s renders a runtime-quarantined rule as armed:\n%s", tc.name, out)
			}
			if !strings.Contains(out, "interface") {
				t.Errorf("%s banner does not name the interface overlap:\n%s", tc.name, out)
			}
			if strings.Contains(out, "Translation hits:") && tc.name == "ruleAll" {
				t.Errorf("%s prints a hit counter for a quarantined rule:\n%s", tc.name, out)
			}
		})
	}

	// Default view (pools + rules) must annotate too.
	out := captureStdout(t, func() {
		if err := c.showNATSource(cfg, nil); err != nil {
			t.Fatalf("showNATSource: %v", err)
		}
	})
	if !strings.Contains(out, "NOT INSTALLED") {
		t.Errorf("default source view renders quarantined rule as armed:\n%s", out)
	}
}

func TestCLINATRuntimeControlArmed16547(t *testing.T) {
	cfg := armedSourceCfg()
	// No runtime provider at all.
	c := &CLI{}
	out := captureStdout(t, func() {
		if err := c.showNATSourceRuleAll(cfg, ""); err != nil {
			t.Fatalf("ruleAll: %v", err)
		}
	})
	if strings.Contains(out, "NOT INSTALLED") {
		t.Errorf("armed control annotated without a runtime verdict:\n%s", out)
	}
}
