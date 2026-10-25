package config

import (
	"reflect"
	"testing"
)

// #15933: CloneForDNSRefresh must give the refresh path a private copy of
// every mutable DNS-resolution field, so resolver writes never land on the
// published config the clone was taken from. FAIL-ON-REVERT: reverting to
// a shallow copy (or aliasing the address maps) makes Refresh into the
// clone mutate the original below.

func dnsRefreshFixture15933(t *testing.T) *Config {
	t.Helper()
	restore := SetLookupAddressDNSNameForTest(func(fqdn string) ([]string, error) {
		switch fqdn {
		case "global.example.com":
			return []string{"10.0.0.1"}, nil
		case "local.example.com":
			return []string{"10.0.0.2"}, nil
		}
		return nil, nil
	})
	defer restore()
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address svc dns-name global.example.com",
		"set security address-book global address plain 192.0.2.1/32",
		"set security zones security-zone trust address-book address svc dns-name local.example.com",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	// #16601: compile is cache-only; populate the premise answers with
	// the off-lock refresh the daemon now performs before apply.
	restore2 := SetLookupAddressDNSNameForTest(func(fqdn string) ([]string, error) {
		switch fqdn {
		case "global.example.com":
			return []string{"10.0.0.1"}, nil
		case "local.example.com":
			return []string{"10.0.0.2"}, nil
		}
		return nil, nil
	})
	RefreshDNSAddressBooks(cfg)
	restore2()
	return cfg
}

func TestCloneForDNSRefreshIsolatesPublishedConfig15933(t *testing.T) {
	cfg := dnsRefreshFixture15933(t)
	// Premise: the compiled global book carries the global entry and the
	// folded zone-local copy as distinct identities.
	if got := cfg.Security.AddressBook.Addresses["svc"].UsableValues(); !reflect.DeepEqual(got, []string{"10.0.0.1/32"}) {
		t.Fatalf("premise global svc = %v", got)
	}
	folded := ZoneLocalQualify("trust", "svc")
	if got := cfg.Security.AddressBook.Addresses[folded].UsableValues(); !reflect.DeepEqual(got, []string{"10.0.0.2/32"}) {
		t.Fatalf("premise folded %s = %v", folded, got)
	}

	clone := cfg.CloneForDNSRefresh()
	if clone == cfg {
		t.Fatal("clone aliases the published config")
	}

	// Refresh the clone with new answers; the original must not move.
	restore := SetLookupAddressDNSNameForTest(func(fqdn string) ([]string, error) {
		switch fqdn {
		case "global.example.com":
			return []string{"10.9.9.9"}, nil
		case "local.example.com":
			return []string{"10.8.8.8"}, nil
		}
		return nil, nil
	})
	defer restore()
	RefreshDNSAddressBooks(clone)

	if got := clone.Security.AddressBook.Addresses["svc"].UsableValues(); !reflect.DeepEqual(got, []string{"10.9.9.9/32"}) {
		t.Errorf("clone global svc = %v, want refreshed", got)
	}
	if got := clone.Security.AddressBook.Addresses[folded].UsableValues(); !reflect.DeepEqual(got, []string{"10.8.8.8/32"}) {
		t.Errorf("clone folded svc = %v, want refreshed", got)
	}
	if got := cfg.Security.AddressBook.Addresses["svc"].UsableValues(); !reflect.DeepEqual(got, []string{"10.0.0.1/32"}) {
		t.Errorf("PUBLISHED global svc mutated by clone refresh: %v", got)
	}
	if got := cfg.Security.AddressBook.Addresses[folded].UsableValues(); !reflect.DeepEqual(got, []string{"10.0.0.2/32"}) {
		t.Errorf("PUBLISHED folded svc mutated by clone refresh: %v", got)
	}
	if z := cfg.Security.Zones["trust"]; z == nil || z.AddressBook == nil {
		t.Fatalf("zone trust book missing: %+v", cfg.Security.Zones["trust"])
	} else if got := z.AddressBook.Addresses["svc"].UsableValues(); !reflect.DeepEqual(got, []string{"10.0.0.2/32"}) {
		t.Errorf("PUBLISHED zone-local svc mutated by clone refresh: %v", got)
	}
	// Non-DNS entries are shared by design; the clone must not mint copies
	// that could diverge.
	if clone.Security.AddressBook.Addresses["plain"] != cfg.Security.AddressBook.Addresses["plain"] {
		t.Errorf("non-DNS entry was cloned; want shared")
	}
	if got := cfg.CloneForDNSRefresh(); got == nil {
		t.Error("clone of valid cfg is nil")
	}
	var nilCfg *Config
	if got := nilCfg.CloneForDNSRefresh(); got != nil {
		t.Errorf("clone of nil = %v, want nil", got)
	}
}
