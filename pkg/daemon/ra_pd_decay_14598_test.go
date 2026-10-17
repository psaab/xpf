package daemon

import (
	"net/netip"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

// #14598: buildRAConfigs must advertise decayed remaining lifetimes.
// A PD at 60% of its lifetime is advertised with <=40% remaining.
func TestBuildRAConfigsDecayedLifetimes14598(t *testing.T) {
	mgr := dhcp.NewManagerForTesting(nil)
	mgr.SeedDelegatedPrefixesForRATesting("ge-0/0/3", "trust0", []dhcp.DelegatedPrefix{{
		Interface:         "ge-0/0/3",
		Prefix:            netip.MustParsePrefix("2001:db8:1000::/48"),
		PreferredLifetime: 100 * time.Second,
		ValidLifetime:     100 * time.Second,
		Obtained:          time.Now().Add(-60 * time.Second),
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
	if found.ValidLifetime <= 0 || found.ValidLifetime > 40 {
		t.Fatalf("advertised ValidLifetime = %d, want (0,40]", found.ValidLifetime)
	}
	if found.PreferredLife < 0 || found.PreferredLife > 40 {
		t.Fatalf("advertised PreferredLife = %d, want [0,40]", found.PreferredLife)
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
