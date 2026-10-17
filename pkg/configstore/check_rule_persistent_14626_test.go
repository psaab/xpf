package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14626: the decisive strict-commit check named by the re-reviewers —
// `rule R then source-nat pool P persistent-nat permit any-remote-host` must
// either take effect or reject/warn; it must not commit clean and inert.
// RED on revert: CheckText returns a config whose rule has no effective
// persistence and no warning.

const rulePNATText14626 = `security {
    zones { security-zone trust; security-zone untrust; }
    nat { source {
        pool p1 { address 198.51.100.1/32; }
        rule-set rs1 {
            from zone trust;
            to zone untrust;
            rule r1 {
                match { source-address 10.0.0.0/24; }
                then { source-nat pool p1 persistent-nat permit any-remote-host; }
            }
        }
    } }
}`

func TestCheckTextRuleLevelPersistentNATTakesEffect14626(t *testing.T) {
	cfg, err := CheckText(rulePNATText14626, -1)
	if err != nil {
		t.Fatalf("CheckText(rule-level persistent-nat) rejected: %v", err)
	}
	var rule *config.NATRule
	for _, rs := range cfg.Security.NAT.Source {
		for _, r := range rs.Rules {
			if r.Name == "r1" {
				rule = r
			}
		}
	}
	if rule == nil {
		t.Fatalf("rule r1 missing from %+v", cfg.Security.NAT.Source)
	}
	eff, ok := rule.EffectivePersistentNAT(cfg)
	if !ok || eff == nil {
		t.Fatalf("strict CheckText accepted an INERT rule-level persistent-nat tail (#14626): effective=%v warnings=%v", eff, cfg.Warnings)
	}
	if eff.Permit != config.PersistentNATPermitAnyRemoteHost || eff.InactivityTimeout != 300 {
		t.Fatalf("effective = %+v, want any-remote-host/300", eff)
	}
	if cfg.Security.NAT.SourcePools["p1"].PersistentNAT != nil {
		t.Fatalf("pool mutated by rule tail: %+v", cfg.Security.NAT.SourcePools["p1"].PersistentNAT)
	}
}

func TestCheckTextRuleLevelPersistentNATConflictRejected14626(t *testing.T) {
	conflict := strings.Replace(rulePNATText14626,
		"pool p1 { address 198.51.100.1/32; }",
		"pool p1 { address 198.51.100.1/32; persistent-nat { permit target-host; } }", 1)
	if _, err := CheckText(conflict, -1); err == nil {
		t.Fatal("CheckText accepted a rule tail conflicting with its pool (#14626)")
	} else if !strings.Contains(err.Error(), "#14626") {
		t.Fatalf("error = %q, want #14626 cite", err)
	}
}
