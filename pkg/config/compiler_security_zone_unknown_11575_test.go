package config

import (
	"strings"
	"testing"
)

func unknownZoneChildConfig11575(t *testing.T, keyword string) *ConfigTree {
	t.Helper()
	text := `interfaces {
 ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } }
}
security {
 screen { ids-option safe { tcp { land; } } }
 zones { security-zone trust {
  interfaces { ge-0/0/0.0; }
  screen safe;
  ` + keyword + `;
 } }
}
`
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse config: %v", errs)
	}
	return tree
}

func TestUnknownEnforcementZoneChildUnbindsOnTolerantCompile11575(t *testing.T) {
	for _, keyword := range []string{
		"screeen", "ids-profile", "adress-book", "SCREEN", "scr", "host-inbound",
		"address-set", "addr-book", "s", "sc", "in", "ho", "tc",
	} {
		t.Run(keyword, func(t *testing.T) {
			tree := unknownZoneChildConfig11575(t, keyword)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile rejected unknown zone child: %v", err)
			}
			zone := cfg.Security.Zones["trust"]
			if zone == nil || !zone.DroppedEnforcementChild {
				t.Fatalf("zone did not retain enforcement poison marker: %+v", zone)
			}
			if len(zone.Interfaces) != 0 {
				t.Fatalf("poisoned zone remains bound to interfaces: %v", zone.Interfaces)
			}
			if zone.ScreenProfile != "" || zone.ScreenProfileConfigured {
				t.Fatalf("poisoned zone claims a healthy screen binding: %+v", zone)
			}
			if cfg.Security.Screen["safe"] == nil {
				t.Fatal("enabled screen profile fixture disappeared")
			}
			foundWarning := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, `security zone "trust"`) && strings.Contains(warning, `"`+keyword+`"`) && strings.Contains(warning, "unbound") {
					foundWarning = true
					break
				}
			}
			if !foundWarning {
				t.Fatalf("compiled warnings do not name the zone, keyword, and unbound disposition: %v", cfg.Warnings)
			}

			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), keyword) {
				t.Fatalf("strict compile err = %v, want rejection naming %q", err, keyword)
			}
		})
	}
}

func TestUnknownNonEnforcementZoneChildWarnsWithoutUnbinding11575(t *testing.T) {
	tree := unknownZoneChildConfig11575(t, "description-typo")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected unknown zone child: %v", err)
	}
	zone := cfg.Security.Zones["trust"]
	if zone == nil || zone.DroppedEnforcementChild {
		t.Fatalf("harmless metadata typo poisoned the zone: %+v", zone)
	}
	if len(zone.Interfaces) != 1 || zone.Interfaces[0] != "ge-0/0/0.0" {
		t.Fatalf("non-enforcement typo changed zone membership: %v", zone.Interfaces)
	}
	foundWarning := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, `security zone "trust"`) && strings.Contains(warning, `"description-typo"`) {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("compiled warning does not name the zone and unknown keyword: %v", cfg.Warnings)
	}
}
