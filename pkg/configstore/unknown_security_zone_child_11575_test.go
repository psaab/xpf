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

func TestStoreSyncApplyUnbindsMisnestedZoneAddressEntries12218(t *testing.T) {
	const configTemplate = `interfaces {
 ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } }
}
security {
 address-book { global {
  address local 10.0.0.1/32;
  address global 203.0.113.0/24;
  address-set grp { address global; }
 } }
 screen { ids-option safe { tcp { land; } } }
 zones { security-zone trust {
  interfaces { ge-0/0/0.0; }
  screen safe;
  $ZONE_CHILD$
 } security-zone untrust; }
 policies { from-zone trust to-zone untrust {
  policy deny-grp { match { source-address grp; destination-address any; application any; } then { deny; } }
 } }
}
`
	configWith := func(zoneChild string) string {
		return strings.Replace(configTemplate, "$ZONE_CHILD$", zoneChild, 1)
	}
	findDeny := func(t *testing.T, compiled *config.Config) *config.Policy {
		t.Helper()
		for _, pair := range compiled.Security.Policies {
			if pair == nil || pair.FromZone != "trust" || pair.ToZone != "untrust" {
				continue
			}
			for _, policy := range pair.Policies {
				if policy != nil && policy.Name == "deny-grp" {
					return policy
				}
			}
		}
		t.Fatal("SyncApply omitted the deny-grp policy")
		return nil
	}

	t.Run("correct-local-book-control", func(t *testing.T) {
		store := newTestStore(t)
		text := configWith(`address-book {
   address local 10.0.0.1/32;
   address-set grp { address local; }
  }`)
		compiled, err := store.SyncApply(text, nil)
		if err != nil {
			t.Fatalf("SyncApply rejected valid local address book: %v", err)
		}
		policy := findDeny(t, compiled)
		if len(policy.Match.SourceAddresses) != 1 || policy.Match.SourceAddresses[0] != "zone-local/trust/grp" {
			t.Fatalf("valid zone-local deny source = %v, want [zone-local/trust/grp]", policy.Match.SourceAddresses)
		}
		zone := compiled.Security.Zones["trust"]
		if zone == nil || zone.DroppedEnforcementChild || len(zone.Interfaces) != 1 {
			t.Fatalf("valid zone-local book changed zone binding: %+v", zone)
		}
	})

	for _, tc := range []struct {
		name       string
		zoneChild  string
		unknownKey string
	}{
		{name: "misnested-address-set", zoneChild: "address-set grp { address local; }", unknownKey: "address-set"},
		{name: "misnested-addr-book", zoneChild: "addr-book { address-set grp { address local; } }", unknownKey: "addr-book"},
		{name: "two-byte-screen-prefix", zoneChild: "sc safe;", unknownKey: "sc"},
		{name: "one-byte-screen-prefix", zoneChild: "s safe;", unknownKey: "s"},
		{name: "addr-set", zoneChild: "addr-set grp;", unknownKey: "addr-set"},
		{name: "addrset", zoneChild: "addrset grp;", unknownKey: "addrset"},
		{name: "adr-book", zoneChild: "adr-book grp;", unknownKey: "adr-book"},
		{name: "adress", zoneChild: "adress grp;", unknownKey: "adress"},
		{name: "addresss", zoneChild: "addresss grp;", unknownKey: "addresss"},
		{name: "adresses", zoneChild: "adresses grp;", unknownKey: "adresses"},
		{name: "addresses", zoneChild: "addresses grp;", unknownKey: "addresses"},
		{name: "addressbk", zoneChild: "addressbk grp;", unknownKey: "addressbk"},
		{name: "adressbok", zoneChild: "adressbok grp;", unknownKey: "adressbok"},
		{name: "abook", zoneChild: "abook grp;", unknownKey: "abook"},
		{name: "book", zoneChild: "book grp;", unknownKey: "book"},
		{name: "adr", zoneChild: "adr grp;", unknownKey: "adr"},
		{name: "scerne", zoneChild: "scerne grp;", unknownKey: "scerne"},
		{name: "scr-profile", zoneChild: "scr-profile grp;", unknownKey: "scr-profile"},
		{name: "scren-profile", zoneChild: "scren-profile grp;", unknownKey: "scren-profile"},
		{name: "host-inbound-services", zoneChild: "host-inbound-services grp;", unknownKey: "host-inbound-services"},
		{name: "hostinbound", zoneChild: "hostinbound grp;", unknownKey: "hostinbound"},
		{name: "host_inbound", zoneChild: "host_inbound grp;", unknownKey: "host_inbound"},
		{name: "inbound-traffic", zoneChild: "inbound-traffic grp;", unknownKey: "inbound-traffic"},
		{name: "rst", zoneChild: "rst grp;", unknownKey: "rst"},
		{name: "ifaces", zoneChild: "ifaces grp;", unknownKey: "ifaces"},
		{name: "interfaces-list", zoneChild: "interfaces-list grp;", unknownKey: "interfaces-list"},
		{name: "adr-book-reproducer", zoneChild: "adr-book { address-set grp { address local; } }", unknownKey: "adr-book"},
		{name: "addrset-reproducer", zoneChild: "addrset grp { address local; }", unknownKey: "addrset"},
		{name: "addr-set-reproducer", zoneChild: "addr-set grp { address local; }", unknownKey: "addr-set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newTestStore(t)
			compiled, err := store.SyncApply(configWith(tc.zoneChild), nil)
			if err != nil {
				t.Fatalf("SyncApply rejected tolerated unknown zone child: %v", err)
			}
			zone := compiled.Security.Zones["trust"]
			if zone == nil || !zone.DroppedEnforcementChild || len(zone.Interfaces) != 0 {
				t.Fatalf("SyncApply left zone bound after dropping %q: %+v", tc.unknownKey, zone)
			}
			if zone.ScreenProfile != "" || zone.ScreenProfileConfigured {
				t.Fatalf("SyncApply retained screen binding after dropping %q: %+v", tc.unknownKey, zone)
			}
			foundUnknown := false
			for _, unknown := range zone.UnknownZoneChildren {
				if unknown == tc.unknownKey {
					foundUnknown = true
					break
				}
			}
			if !foundUnknown {
				t.Fatalf("SyncApply unknown children = %v, want %q", zone.UnknownZoneChildren, tc.unknownKey)
			}
			foundWarning := false
			for _, warning := range compiled.Warnings {
				if strings.Contains(warning, `security zone "trust"`) &&
					strings.Contains(warning, `"`+tc.unknownKey+`"`) &&
					strings.Contains(warning, "unbound") {
					foundWarning = true
					break
				}
			}
			if !foundWarning {
				t.Fatalf("SyncApply warnings do not name zone, unknown child, and unbound disposition: %v", compiled.Warnings)
			}
			globalSet := compiled.Security.AddressBook.AddressSets["grp"]
			if globalSet == nil {
				t.Fatal("same-named global grp set fixture disappeared")
			}
			policy := findDeny(t, compiled)
			if len(policy.Match.SourceAddresses) != 1 || policy.Match.SourceAddresses[0] != "grp" {
				t.Fatalf("poisoned deny source = %v, want the unqualified reference demonstrating global fallback is blocked by zone unbinding", policy.Match.SourceAddresses)
			}
		})
	}
}
