package dataplane

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCompileUserspaceShim_DynamicAddressAndZoneLocalAddressBook is the
// #14335 regression: a config referencing a security dynamic-address
// binding, or a zone-attached address-book entry/set, must succeed through
// CompileUserspaceShim (the production userspace path), not abort in the
// legacy pre-mutation validation. It also pins that a same-named zone-local
// entry wins over the global entry and that a name defined only in another
// zone does not leak, and that the legacy (non-shim) compiler stays
// fail-closed on dynamic bindings.
func TestCompileUserspaceShim_DynamicAddressAndZoneLocalAddressBook(t *testing.T) {
	origPinPath := linkPinPath
	linkPinPath = t.TempDir()
	t.Cleanup(func() { linkPinPath = origPinPath })

	newCfg := func() *config.Config {
		cfg := &config.Config{}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"trust": {
				Name: "trust",
				AddressBook: &config.AddressBook{
					Addresses: map[string]*config.Address{
						"web-server": {Name: "web-server", Value: "10.0.1.100/32"},
						"local-only": {Name: "local-only", Value: "10.0.2.5/32"},
					},
					AddressSets: map[string]*config.AddressSet{
						"local-set": {Name: "local-set", Addresses: []string{"web-server", "10.9.9.0/24"}},
					},
				},
			},
			"untrust": {Name: "untrust"},
			"dmz":     {Name: "dmz"},
		}
		cfg.Security.AddressBook = &config.AddressBook{
			Addresses: map[string]*config.Address{
				"web-server": {Name: "web-server", Value: "10.9.9.9/32"},
			},
		}
		cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
			"threat-feed": {Name: "threat-feed", FeedNames: []string{"threat"}},
		}
		cfg.Security.Policies = []*config.ZonePairPolicies{
			{
				FromZone: "trust", ToZone: "untrust",
				Policies: []*config.Policy{
					{
						Name:   "dynamic-src",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"threat-feed"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"any"},
						},
					},
					{
						Name:   "zone-local-src",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"web-server", "local-set"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"any"},
						},
					},
				},
			},
			{
				FromZone: "untrust", ToZone: "trust",
				Policies: []*config.Policy{
					{
						Name:   "zone-local-dst",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"web-server"},
							Applications:         []string{"any"},
						},
					},
				},
			},
		}
		cfg.Security.GlobalPolicies = []*config.Policy{
			{
				Name:   "global-feeds-and-global-book",
				Action: config.PolicyPermit,
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"threat-feed"},
					DestinationAddresses: []string{"web-server"},
					Applications:         []string{"any"},
				},
			},
		}
		return cfg
	}

	// Drive the exact production shim compile: CompileConfig against
	// userspaceShimCompileDataplane (no-op setters), including its #4960
	// pre-pass and the pre-mutation snapshot callback. The trailing
	// bpffs pin sweeps in CompileUserspaceShim need root/bpffs and are
	// orthogonal to address resolution.
	m := New()
	m.loaded.Store(true)
	preflightRan := false
	result, err := CompileConfig(userspaceShimCompileDataplane{Manager: m}, newCfg(), false, func(r *CompileResult) error {
		preflightRan = true
		if r == nil {
			t.Fatal("preflight result is nil")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("CompileUserspaceShim(dynamic-address + zone-local book): %v", err)
	}
	if !preflightRan {
		t.Fatal("CompileUserspaceShim did not run the pre-mutation snapshot check")
	}
	if result == nil {
		t.Fatal("CompileUserspaceShim returned nil result")
	}

	// On the shim the dynamic and zone-local tokens must resolve to non-any,
	// non-aliasing IDs, with zone-local winning over the same-named global.
	dynID := result.AddrIDs["threat-feed"]
	if dynID == 0 {
		t.Fatalf("dynamic binding was not allocated an address ID on the shim; AddrIDs=%v", result.AddrIDs)
	}
	localWebID := result.AddrIDs["zone-local/trust/web-server"]
	globalWebID := result.AddrIDs["web-server"]
	if localWebID == 0 || globalWebID == 0 {
		t.Fatalf("zone-local and global web-server IDs missing: local=%d global=%d AddrIDs=%v", localWebID, globalWebID, result.AddrIDs)
	}
	if localWebID == globalWebID {
		t.Fatalf("zone-local web-server aliased the global entry (id %d); zone-local must win distinctly", localWebID)
	}
	if result.AddrIDs["zone-local/trust/local-set"] == 0 {
		t.Fatalf("zone-local address-set was not compiled; AddrIDs=%v", result.AddrIDs)
	}

	// A name defined only in trust's book must not leak to a policy from dmz.
	leak := newCfg()
	leak.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "dmz", ToZone: "untrust",
		Policies: []*config.Policy{{
			Name:   "leak",
			Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"local-only"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
		}},
	}}
	leak.Security.GlobalPolicies = nil
	m2 := New()
	m2.loaded.Store(true)
	if _, err := CompileConfig(userspaceShimCompileDataplane{Manager: m2}, leak, false, func(*CompileResult) error { return nil }); err == nil || !strings.Contains(err.Error(), `address "local-only" not found`) {
		t.Fatalf("zone-local name leaked across zones or failed differently: %v", err)
	}

	// Fail-closed is preserved off the shim: a plain legacy dataplane
	// (neither shim nor validation marker) must still reject a dynamic
	// binding rather than widening it to match-any. The #4960 pre-pass
	// itself is keyed to the shim production path, so it accepts here;
	// legacy rejection is pinned at the compiler entry it guards.
	legacyCfg := newCfg()
	legacyCfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust", ToZone: "untrust",
		Policies: []*config.Policy{{
			Name:   "legacy-dynamic",
			Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"threat-feed"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
		}},
	}}
	legacyCfg.Security.GlobalPolicies = nil
	dp := &dp13162{}
	res := &CompileResult{
		ZoneIDs: make(map[string]uint16), AddrIDs: make(map[string]uint32),
		AppIDs: make(map[string]uint32), implicitSets: make(map[string]uint32),
		nextAddrID: 1,
	}
	assignZoneIDs(res, legacyCfg)
	if err := compileAddressBook(dp, legacyCfg, res); err != nil {
		t.Fatalf("compileAddressBook(legacy): %v", err)
	}
	if err := compilePolicies(dp, legacyCfg, res); err == nil || !strings.Contains(err.Error(), "no feed prefixes") {
		t.Fatalf("legacy compiler must stay fail-closed on dynamic bindings, got %v", err)
	}
}
