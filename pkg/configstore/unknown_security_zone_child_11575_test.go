package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const unknownZoneEnforcementConfig11575 = `interfaces {
 ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } }
}
security {
 screen { ids-option safe { tcp { land; } } }
 zones { security-zone trust {
  interfaces { ge-0/0/0.0; }
  screen safe;
  screeen;
 } }
}
`

func TestStoreSyncApplyWarnsAndUnbindsUnknownZoneEnforcement11575(t *testing.T) {
	store := newTestStore(t)
	compiled, err := store.SyncApply(unknownZoneEnforcementConfig11575, nil)
	if err != nil {
		t.Fatalf("SyncApply rejected tolerated unknown zone child: %v", err)
	}
	zone := compiled.Security.Zones["trust"]
	if zone == nil || !zone.DroppedEnforcementChild {
		t.Fatalf("SyncApply did not retain the enforcement poison marker: %+v", zone)
	}
	if len(zone.Interfaces) != 0 {
		t.Fatalf("SyncApply left the poisoned zone bound to interfaces: %v", zone.Interfaces)
	}
	if zone.ScreenProfile != "" || zone.ScreenProfileConfigured {
		t.Fatalf("SyncApply claims a healthy screen policy after dropping its keyword: %+v", zone)
	}
	found := false
	for _, warning := range compiled.Warnings {
		if strings.Contains(warning, `security zone "trust"`) && strings.Contains(warning, `"screeen"`) && strings.Contains(warning, "unbound") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("SyncApply warnings do not name zone, keyword, and unbound disposition: %v", compiled.Warnings)
	}

	tree, parseErrs := config.NewParser(unknownZoneEnforcementConfig11575).Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("parse strict config: %v", parseErrs)
	}
	if _, err := store.compileTree(tree); err == nil || !config.IsUnknownSecurityZoneChildSchemaError(err) || !strings.Contains(err.Error(), "screeen") {
		t.Fatalf("strict compile error = %v, want closed-world rejection of screeen", err)
	}
}
