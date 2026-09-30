package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// totalCapConfig11081 builds sets x rulesPerSet single-span policies.
func totalCapConfig11081(sets, rulesPerSet int) *config.Config {
	cfg := &config.Config{}
	for s := 0; s < sets; s++ {
		zpp := &config.ZonePairPolicies{FromZone: "trust", ToZone: "untrust"}
		for r := 0; r < rulesPerSet; r++ {
			zpp.Policies = append(zpp.Policies, &config.Policy{Name: "p"})
		}
		cfg.Security.Policies = append(cfg.Security.Policies, zpp)
	}
	return cfg
}

// TestPolicyTotalExpansionCap11081 pins the total expanded-rule ceiling:
// beyond MaxTotalPolicyRuleExpansion the walk fails LOUD with the count
// (not a silent linear-scan slowdown); at the cap it compiles.
func TestPolicyTotalExpansionCap11081(t *testing.T) {
	over := totalCapConfig11081(300, 220) // 66000 > 65536, each set under 256
	err := walkPolicyRuleSlots(over, func(slot policyRuleSlot) error { return nil })
	if err == nil {
		t.Fatal("66000-rule config must fail the total cap")
	}
	if !strings.Contains(err.Error(), "66000") || !strings.Contains(err.Error(), "65536") {
		t.Fatalf("cap error must state actual and ceiling, got: %v", err)
	}

	atCap := totalCapConfig11081(256, 256) // exactly 65536
	if err := walkPolicyRuleSlots(atCap, func(slot policyRuleSlot) error { return nil }); err != nil {
		t.Fatalf("at-cap config must compile, got: %v", err)
	}
}
