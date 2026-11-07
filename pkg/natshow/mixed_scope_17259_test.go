package natshow

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Kimi delta: one *StaticNATRule shared by a zone (installed) and an
// interface (scope-unsupported) expansion must render per-expansion.
func TestNPTv6MixedScopeExpansionsRenderPerScope17259(t *testing.T) {
	rule := &config.StaticNATRule{
		Name: "n1", Match: "2602:fd41:70::/48", Then: "fd35:1940:27::/48",
		IsNPTv6: true,
	}
	// Model the two expansions as the compiler does: same rule pointer,
	// two rule-sets — zone expansion installed, interface unsupported
	// (NPTv6ScopeUnsupported keys off the rule-set's FromInterface).
	zoneRS := &config.StaticNATRuleSet{Name: "nrs", FromZone: "untrust", Rules: []*config.StaticNATRule{rule}}
	ifaceRS := &config.StaticNATRuleSet{Name: "nrs", FromInterface: "ge-0/0/1", Rules: []*config.StaticNATRule{rule}}
	installed := map[nptv6RuleKey]bool{
		{rs: zoneRS, rule: rule}:  true,
		{rs: ifaceRS, rule: rule}: false,
	}
	if got := staticRuleNotInstalledReason(zoneRS, rule, installed); got != "" {
		t.Errorf("zone expansion reason = %q, want installed", got)
	}
	if got := staticRuleNotInstalledReason(ifaceRS, rule, installed); got == "" {
		t.Error("interface expansion reason = installed, want NOT INSTALLED (scope)")
	}
	if !strings.Contains(staticRuleNotInstalledReason(ifaceRS, rule, installed), "cannot honor") {
		t.Errorf("interface reason should name the scope cause, got %q", staticRuleNotInstalledReason(ifaceRS, rule, installed))
	}
}
