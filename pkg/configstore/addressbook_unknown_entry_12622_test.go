package configstore

import (
	"strings"
	"testing"
)

func TestSyncApplyWarnsOnUnknownZoneAddressBookEntry12622(t *testing.T) {
	const text = `interfaces {
 ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } }
}
security {
 address-book { global {
  address local 10.0.0.1/32;
  address-set grp { address local; }
 } }
 zones { security-zone trust {
  interfaces { ge-0/0/0.0; }
  address-book {
   address local 10.0.0.9/32;
   adress-set grp { address local; }
  }
 } security-zone untrust; }
 policies { from-zone trust to-zone untrust {
  policy deny-grp { match { source-address grp; destination-address any; application any; } then { deny; } }
 } }
}
`
	store := newTestStore(t)
	cfg, err := store.SyncApply(text, nil)
	if err != nil {
		t.Fatalf("SyncApply rejected tolerated config: %v", err)
	}
	zone := cfg.Security.Zones["trust"]
	if zone == nil || !zone.DroppedEnforcementChild || len(zone.Interfaces) != 0 {
		t.Fatalf("typo'd local book did not disable zone: %+v", zone)
	}
	warned := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, `zone "trust"`) && strings.Contains(warning, "adress-set") && strings.Contains(warning, "grp") {
			warned = true
			break
		}
	}
	if !warned {
		t.Fatalf("compiled config warnings omit typo'd zone entry: %v", cfg.Warnings)
	}
	if _, ok := cfg.Security.AddressBook.CollidingNames["zone-local/trust/grp"]; !ok {
		t.Fatalf("zone-local dropped reference not quarantined: %v", cfg.Security.AddressBook.CollidingNames)
	}
}
