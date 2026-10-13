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
		"zz", "IDS-PROFILE", "SCRN", "Scr", "adress", "addresss", "addresses",
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

// TestUnknownNonEnforcementZoneChildWarnsAndUnbinds12623 pins the owner
// decision (#12623, option (b) from #12218): on the tolerant path ANY unknown
// zone child unbinds the zone, not only spellings the #11575 distance/prefix
// heuristic judged enforcement-bearing. This reverses
// TestUnknownNonEnforcementZoneChildWarnsWithoutUnbinding11575.
func TestUnknownNonEnforcementZoneChildWarnsAndUnbinds12623(t *testing.T) {
	tree := unknownZoneChildConfig11575(t, "description-typo")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected unknown zone child: %v", err)
	}
	zone := cfg.Security.Zones["trust"]
	if zone == nil || !zone.DroppedEnforcementChild {
		t.Fatalf("unknown non-enforcement typo did not poison the zone: %+v", zone)
	}
	if len(zone.Interfaces) != 0 {
		t.Fatalf("unknown zone child left zone membership bound: %v", zone.Interfaces)
	}
	if zone.ScreenProfile != "" || zone.ScreenProfileConfigured {
		t.Fatalf("unknown zone child left screen binding: %+v", zone)
	}
	foundWarning := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, `security zone "trust"`) && strings.Contains(warning, `"description-typo"`) && strings.Contains(warning, "unbound") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("compiled warning does not name the zone, unknown keyword, and unbound disposition: %v", cfg.Warnings)
	}
}

// TestDistantZoneChildSpellingsUnbind12623 covers the #12623 spellings the
// #11575 heuristic misses: each must unbind on the tolerant path.
func TestDistantZoneChildSpellingsUnbind12623(t *testing.T) {
	for _, keyword := range []string{
		"addr-set", "addrset", "adr-book", "adress", "addresss", "adresses",
		"addresses", "addressbk", "adressbok", "abook", "book", "adr",
		"scerne", "scr-profile", "scren-profile", "host-inbound-services",
		"hostinbound", "host_inbound", "inbound-traffic", "rst", "ifaces",
		"interfaces-list",
	} {
		t.Run(keyword, func(t *testing.T) {
			tree := unknownZoneChildConfig11575(t, keyword)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile rejected unknown zone child: %v", err)
			}
			zone := cfg.Security.Zones["trust"]
			if zone == nil || !zone.DroppedEnforcementChild {
				t.Fatalf("distant spelling %q did not poison the zone: %+v", keyword, zone)
			}
			if len(zone.Interfaces) != 0 || zone.ScreenProfile != "" || zone.ScreenProfileConfigured {
				t.Fatalf("distant spelling %q left zone bound: %+v", keyword, zone)
			}
			foundWarning := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, `security zone "trust"`) && strings.Contains(warning, `"`+keyword+`"`) && strings.Contains(warning, "unbound") {
					foundWarning = true
					break
				}
			}
			if !foundWarning {
				t.Fatalf("compiled warnings do not name zone, %q, and unbound disposition: %v", keyword, cfg.Warnings)
			}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), keyword) {
				t.Fatalf("strict compile err = %v, want rejection naming %q", err, keyword)
			}
		})
	}
}

func TestUnknownPackedEnforcementZoneChildUnbinds11575(t *testing.T) {
	for _, statement := range []string{
		"replace: screen safe",
		"protect: screen safe",
		"set screen safe",
		"foo screen safe",
		"foo SCREEN safe",
		"foo IDS-PROFILE safe",
		"foo SCRN safe",
		"foo Scr safe",
	} {
		t.Run(statement, func(t *testing.T) {
			tree := unknownZoneChildConfig11575(t, statement)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile rejected packed unknown zone child: %v", err)
			}
			zone := cfg.Security.Zones["trust"]
			if zone == nil || !zone.DroppedEnforcementChild {
				t.Fatalf("packed enforcement tail did not poison zone: %+v", zone)
			}
			if len(zone.Interfaces) != 0 || zone.ScreenProfile != "" || zone.ScreenProfileConfigured {
				t.Fatalf("packed enforcement tail left zone bound: %+v", zone)
			}
			head := strings.Fields(statement)[0]
			foundWarning := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, `"`+head+`"`) && strings.Contains(warning, "unbound") {
					foundWarning = true
					break
				}
			}
			if !foundWarning {
				t.Fatalf("compiled warnings do not name the packed head and unbound disposition: %v", cfg.Warnings)
			}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), head) {
				t.Fatalf("strict compile err = %v, want rejection naming %q", err, head)
			}
		})
	}
}

// TestUnknownPackedShortTailUnbinds12623: under #12623 option (b) a packed
// statement's unknown head unbinds regardless of its tail tokens. This
// reverses TestUnknownPackedShortNonEnforcementTailDoesNotUnbind11575.
func TestUnknownPackedShortTailUnbinds12623(t *testing.T) {
	tree := unknownZoneChildConfig11575(t, "foo xy safe")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected packed unknown zone child: %v", err)
	}
	zone := cfg.Security.Zones["trust"]
	if zone == nil || !zone.DroppedEnforcementChild {
		t.Fatalf("packed unknown head did not poison the zone: %+v", zone)
	}
	if len(zone.Interfaces) != 0 {
		t.Fatalf("packed unknown head left zone membership bound: %v", zone.Interfaces)
	}
	if zone.ScreenProfile != "" || zone.ScreenProfileConfigured {
		t.Fatalf("packed unknown head left screen binding: %+v", zone)
	}
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "foo") {
		t.Fatalf("strict compile err = %v, want rejection naming foo", err)
	}
}
