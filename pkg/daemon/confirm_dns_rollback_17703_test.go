package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #17703: a remaining failed dns-name entry is not evidence that DNS caused
// every refusal in the refreshed rollback target. Static refusals must remain
// on the refused-target path rather than enter DNS-only deferral.

func mixedRefusal17703(t *testing.T, dnsReferenced, staticRefusal bool) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.System.HostName = "mixed-target"
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"api": {Name: "api", DNSName: "api-17703.example.invalid", DNSLookupFailed: true},
		},
		AddressSets: map[string]*config.AddressSet{},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust"},
		"untrust": {Name: "untrust"},
	}
	dst := "any"
	if dnsReferenced {
		dst = "api"
	}
	toZone := "untrust"
	if staticRefusal {
		toZone = "gone" // undefined zone: static whole-snapshot refusal
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   toZone,
		Policies: []*config.Policy{{
			Name:   "bad1",
			Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:            []string{"any"},
				DestinationAddresses:       []string{dst},
				DestinationAddressExcluded: dnsReferenced,
				Applications:               []string{"any"},
			},
		}},
	}}
	return cfg
}

func refreshRefusedDNS17703(t *testing.T, cfg *config.Config) *config.Config {
	t.Helper()
	return config.RefreshDNSForPreflight(cfg)
}

func compileDNSRefusalTarget17703(t *testing.T) *config.Config {
	t.Helper()
	tree, parseErrors := config.NewParser(dnsRefusalTarget17703(t, false)).Parse()
	if len(parseErrors) != 0 {
		t.Fatalf("parse DNS target: %v", parseErrors)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient(DNS target): %v", err)
	}
	return cfg
}

func dnsRefusalTarget17703(t *testing.T, withStaticRefusal bool) string {
	t.Helper()
	tree := &config.ConfigTree{}
	lines := []string{
		"set system host-name mixed-target",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address api dns-name api-17703.example.invalid",
		"set security policies from-zone trust to-zone untrust policy dns match source-address any",
		"set security policies from-zone trust to-zone untrust policy dns match destination-address api",
		"set security policies from-zone trust to-zone untrust policy dns match destination-address-excluded",
		"set security policies from-zone trust to-zone untrust policy dns match application any",
		"set security policies from-zone trust to-zone untrust policy dns then permit",
	}
	if withStaticRefusal {
		lines = append(lines,
			"set security policies from-zone trust to-zone gone policy bad1 match source-address any",
			"set security policies from-zone trust to-zone gone policy bad1 match destination-address any",
			"set security policies from-zone trust to-zone gone policy bad1 match application any",
			"set security policies from-zone trust to-zone gone policy bad1 then permit",
		)
	}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree.Format()
}

func TestRollbackTargetRefusedOnlyForDNSMixedRefusal17703(t *testing.T) {
	restore := config.SetLookupAddressDNSNameForTest(func(string) ([]string, error) {
		return nil, errors.New("dial udp: no upstream")
	})
	defer restore()

	t.Run("unrelated failed dns entry does not make static refusal dns-only", func(t *testing.T) {
		target := mixedRefusal17703(t, false, true)
		refreshed := refreshRefusedDNS17703(t, target)
		reasons := dpuserspace.PolicyContentRejectionReasons(refreshed, nil)
		if len(reasons) == 0 {
			t.Fatal("precondition: refreshed clone must be refused (undefined zone)")
		}
		if !targetHasUnavailableDNSResolution(refreshed) {
			t.Fatal("precondition: refreshed clone must still carry a failed dns entry")
		}
		if rollbackTargetRefusedOnlyForDNSRefreshed(target, refreshed) {
			t.Fatalf("a static refusal coincident with an unrelated failed dns entry must not be DNS-only: reasons=%v", reasons)
		}
		if rollbackTargetRefusedOnlyForDNS(target) {
			t.Fatal("rollbackTargetRefusedOnlyForDNS must not classify the mixed refusal as DNS-only")
		}
		if addr := refreshed.Security.AddressBook.Addresses["api"]; !addr.DNSLookupFailed || len(addr.DNSAddresses) != 0 {
			t.Fatalf("DNS attribution probe must not mutate the refreshed clone: %+v", addr)
		}
	})

	t.Run("dns-unavailable target retains dns classification", func(t *testing.T) {
		target := compileDNSRefusalTarget17703(t)
		if !targetHasUnavailableDNSResolution(target) {
			t.Fatal("precondition: fresh compile must not have resolved the DNS name")
		}
		refreshed := config.RefreshDNSForPreflight(target)
		if !targetHasUnavailableDNSResolution(refreshed) {
			t.Fatal("precondition: DNS refresh must leave the failed lookup visible")
		}
		if !rollbackTargetRefusedOnlyForDNSRefreshed(target, refreshed) {
			t.Fatal("a DNS-unavailable target must retain DNS classification")
		}
	})

	t.Run("mixed dns-caused and static refusal enters refused-target safe state", func(t *testing.T) {
		s, _, stopDNS := recoveredDNS16612(t, dnsRefusalTarget17703(t, true), false)
		defer stopDNS()
		d, applied := newDNSDaemon16612(t, s)
		target, _, ok := s.PendingRollbackTarget(s.ConfirmGenForTesting())
		if !ok || target == nil || !targetHasUnavailableDNSResolution(target) {
			t.Fatal("precondition: mixed target must retain a failed dns-name entry")
		}
		s.InvokeRollbackTimerForTesting(s.ConfirmGenForTesting())
		if got := hostName9615(s); got != "mixed-target" {
			t.Fatalf("store must promote the refused rollback target, got %q", got)
		}
		if s.IsConfirmPending() {
			t.Fatal("a mixed DNS/static refusal must not be deferred as DNS-only")
		}
		if len(*applied) != 0 {
			t.Fatalf("a refused mixed target must not be applied: %v", *applied)
		}
		if !d.inBootstrap() {
			t.Fatal("a mixed DNS/static refusal must take the bootstrap/lifeline safe state")
		}
	})
}

