package daemon

import (
	"net/netip"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

// #14598: a PD at 60% of its lifetime must not advertise more than the
// remaining 40%. #15057 moved the decay to send time: buildRAConfigs now
// carries the granted lifetimes plus the absolute expiry (Obtained+
// granted), and pkg/ra computes the remainder when it emits the RA.
// This test pins the producer half — granted (not decayed) lifetimes
// with expiry = Obtained+100s; the wire half lives in pkg/ra
// TestBuildRA_15057_RemainingFromExpiryAtSendTime.
func TestBuildRAConfigsDecayedLifetimes14598(t *testing.T) {
	obtained := time.Now().Add(-60 * time.Second)
	mgr := dhcp.NewManagerForTesting(nil)
	mgr.SeedDelegatedPrefixesForRATesting("ge-0/0/3", "trust0", []dhcp.DelegatedPrefix{{
		Interface:         "ge-0/0/3",
		Prefix:            netip.MustParsePrefix("2001:db8:1000::/48"),
		PreferredLifetime: 100 * time.Second,
		ValidLifetime:     100 * time.Second,
		Obtained:          obtained,
	}})
	d := &Daemon{dhcp: mgr}
	ras := d.buildRAConfigs(&config.Config{})
	var found *config.RAPrefix
	for _, ra := range ras {
		if ra.Interface == "trust0" {
			for _, p := range ra.Prefixes {
				found = p
			}
		}
	}
	if found == nil {
		t.Fatal("no RA prefix for trust0")
	}
	if found.ValidLifetime != 100 || found.PreferredLife != 100 {
		t.Fatalf("carried lifetimes = valid %d / pref %d, want granted 100/100 (decay is at send time, #15057)", found.ValidLifetime, found.PreferredLife)
	}
	if want := obtained.Add(100 * time.Second).UnixNano(); found.ValidExpiresAt != want {
		t.Fatalf("ValidExpiresAt = %d, want %d (Obtained+100s)", found.ValidExpiresAt, want)
	}
	// Control: fresh PD at 0% elapsed keeps near-full lifetimes.
	mgr2 := dhcp.NewManagerForTesting(nil)
	mgr2.SeedDelegatedPrefixesForRATesting("ge-0/0/3", "trust0", []dhcp.DelegatedPrefix{{
		Interface:         "ge-0/0/3",
		Prefix:            netip.MustParsePrefix("2001:db8:1000::/48"),
		PreferredLifetime: 3600 * time.Second,
		ValidLifetime:     7200 * time.Second,
		Obtained:          time.Now(),
	}})
	d2 := &Daemon{dhcp: mgr2}
	ras2 := d2.buildRAConfigs(&config.Config{})
	var fresh *config.RAPrefix
	for _, ra := range ras2 {
		if ra.Interface == "trust0" {
			for _, p := range ra.Prefixes {
				fresh = p
			}
		}
	}
	if fresh == nil || fresh.ValidLifetime < 7100 || fresh.PreferredLife < 3500 {
		t.Fatalf("fresh advertised = %+v, want near 3600/7200", fresh)
	}
	// Expired PD produces no prefix.
	mgr3 := dhcp.NewManagerForTesting(nil)
	mgr3.SeedDelegatedPrefixesForRATesting("ge-0/0/3", "trust0", []dhcp.DelegatedPrefix{{
		Interface:         "ge-0/0/3",
		Prefix:            netip.MustParsePrefix("2001:db8:1000::/48"),
		PreferredLifetime: time.Second,
		ValidLifetime:     time.Second,
		Obtained:          time.Now().Add(-2 * time.Second),
	}})
	d3 := &Daemon{dhcp: mgr3}
	ras3 := d3.buildRAConfigs(&config.Config{})
	for _, ra := range ras3 {
		if ra.Interface == "trust0" && len(ra.Prefixes) != 0 {
			t.Fatalf("expired PD advertised: %+v", ra.Prefixes)
		}
	}
}
