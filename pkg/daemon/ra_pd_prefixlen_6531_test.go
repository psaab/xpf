package daemon

// #6531, MIDDLE LEG of the PD → RA chain: a STORED delegated prefix →
// Daemon.buildRAConfigs → config.RAPrefix.
//
// The #6531 fix lives at the DHCPv6 decoder (pkg/dhcp extractDelegatedPrefixes),
// and its pkg/dhcp tests stop at DeriveSubPrefix while the pkg/ra tests start
// from a statically built config.RAPrefix. Neither of them crosses this hop, so
// nothing exercised the code that actually turns a delegation into an
// advertisement (#6581 review). These tests call the real buildRAConfigs.
//
// Both are documentation of the consumer seam and the blast radius, NOT
// RED-on-revert guards: they are GREEN before and after the pkg/dhcp fix (the
// first is an over-reach guard; the second pins current unguarded behavior,
// exactly like pkg/ra's TestBuildRA_6587_ConfiguredZeroPrefixStillAdvertised,
// renamed from TestBuildRA_6531_ZeroPrefixWouldBeAdvertised when #6587 gave
// pkg/ra a provenance-scoped floor). The
// RED-on-revert coverage for the guard itself lives in
// pkg/dhcp/dhcpv6_iapd_prefixlen_6531_test.go.

import (
	"net/netip"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

// raPrefixesFor6531 seeds one delegated prefix on a WAN source pointed at
// downstream RA interface "trust0", runs the real buildRAConfigs over an
// otherwise empty config, and returns the RA prefixes it produced for that
// interface.
//
// The seam sets no sub-prefix length, so DeriveSubPrefix returns the delegation
// unchanged — which is what makes the delegated length itself observable here.
func raPrefixesFor6531(t *testing.T, delegated netip.Prefix) []*config.RAPrefix {
	t.Helper()

	mgr := dhcp.NewManagerForTesting(nil)
	mgr.SeedDelegatedPrefixesForRATesting("ge-0/0/3", "trust0", []dhcp.DelegatedPrefix{{
		Interface:         "ge-0/0/3",
		Prefix:            delegated,
		PreferredLifetime: 3600 * time.Second,
		ValidLifetime:     7200 * time.Second,
	}})

	d := &Daemon{dhcp: mgr}
	ras := d.buildRAConfigs(&config.Config{})

	for _, ra := range ras {
		if ra.Interface == "trust0" {
			return ra.Prefixes
		}
	}
	t.Fatalf("buildRAConfigs produced no RA config for trust0; got %d configs", len(ras))
	return nil
}

// Over-reach guard: a normal delegation must still become an advertised
// prefix, on-link + autonomous, with the delegation's lifetimes carried over.
// GREEN under a revert of the pkg/dhcp guard.
func TestBuildRAConfigs_6531_DelegatedPrefixBecomesRAPrefix(t *testing.T) {
	pfxs := raPrefixesFor6531(t, netip.MustParsePrefix("2606:4700:4700:900d::/64"))

	if len(pfxs) != 1 {
		t.Fatalf("got %d RA prefixes %v, want exactly the delegated one", len(pfxs), pfxs)
	}
	got := pfxs[0]
	if got.Prefix != "2606:4700:4700:900d::/64" {
		t.Errorf("advertised prefix = %q, want %q", got.Prefix, "2606:4700:4700:900d::/64")
	}
	if !got.OnLink || !got.Autonomous {
		t.Errorf("OnLink = %v, Autonomous = %v, want both true — buildRAConfigs "+
			"hard-sets these for every PD-derived prefix", got.OnLink, got.Autonomous)
	}
	if got.ValidLifetime != 7200 || got.PreferredLife != 3600 {
		t.Errorf("lifetimes = valid %d / preferred %d, want 7200 / 3600 — the "+
			"delegation's lifetimes must reach the advertisement",
			got.ValidLifetime, got.PreferredLife)
	}
}

// The blast radius, measured at THIS hop: buildRAConfigs has exactly one
// rejection — `if !subPrefix.IsValid()` (daemon_ra.go) — and a /0 passes it.
//
// This is the load-bearing reason the #6531 guard must sit at the DHCPv6
// decoder: 2001:db8:bad::/0 is precisely what the unguarded decoder produced
// from a wire prefix-length of 129..255, netip.Prefix reports it as VALID, and
// DeriveSubPrefix returns it unchanged, so the only check on this path waves it
// through as on-link + autonomous. GREEN before and after the fix.
func TestBuildRAConfigs_6531_ZeroPrefixSurvivesTheIsValidGuard(t *testing.T) {
	pfxs := raPrefixesFor6531(t, netip.MustParsePrefix("2001:db8:bad::/0"))

	if len(pfxs) != 1 {
		t.Fatalf("got %d RA prefixes %v, want 1 — buildRAConfigs gained a "+
			"prefix-length filter; re-check whether the #6531 guard in pkg/dhcp "+
			"is still the only thing keeping a delegated /0 off the wire", len(pfxs), pfxs)
	}
	got := pfxs[0]
	if got.Prefix != "2001:db8:bad::/0" {
		t.Fatalf("advertised prefix = %q, want %q — see above", got.Prefix, "2001:db8:bad::/0")
	}
	if !got.OnLink || !got.Autonomous {
		t.Errorf("OnLink = %v, Autonomous = %v, want both true "+
			"(this is what makes a /0 a LAN-wide hijack)", got.OnLink, got.Autonomous)
	}
}

// TestBuildRAConfigs_6587_StampsDelegatedProvenance binds the WIRING for the
// #6587 floor.
//
// pkg/ra's tests construct config.RAPrefix values directly, so they prove the
// floor WORKS and say nothing about whether anything sets the flag it keys on.
// Deleting `Delegated: true` from buildRAConfigs leaves every one of them green
// while the floor silently stops firing — a delegated /0 reaches the LAN again
// and the only thing that changed is one struct field nobody asserts.
//
// It also asserts the operator-authored side stays FALSE from the same run, so
// the flag cannot be satisfied by stamping every prefix true.
func TestBuildRAConfigs_6587_StampsDelegatedProvenance(t *testing.T) {
	mgr := dhcp.NewManagerForTesting(nil)
	mgr.SeedDelegatedPrefixesForRATesting("ge-0/0/3", "trust0", []dhcp.DelegatedPrefix{{
		Interface:         "ge-0/0/3",
		Prefix:            netip.MustParsePrefix("2606:4700:4700:9000::/64"),
		PreferredLifetime: 3600 * time.Second,
		ValidLifetime:     7200 * time.Second,
	}})

	// An operator-authored prefix on a DIFFERENT interface, present in the
	// same buildRAConfigs run.
	cfg := &config.Config{}
	cfg.Protocols.RouterAdvertisement = []*config.RAInterfaceConfig{{
		Interface: "dmz0",
		Prefixes:  []*config.RAPrefix{{Prefix: "2001:db8:dmz::/64", OnLink: true, Autonomous: true}},
	}}

	d := &Daemon{dhcp: mgr}
	ras := d.buildRAConfigs(cfg)

	var sawPD, sawConfigured bool
	for _, ra := range ras {
		for _, p := range ra.Prefixes {
			switch ra.Interface {
			case "trust0":
				sawPD = true
				if !p.Delegated {
					t.Errorf("PD-derived prefix %s on %s has Delegated=false. The #6587 "+
						"floor keys on this flag, so it never fires and a delegated /0 "+
						"reaches the LAN — while every pkg/ra test stays green, because "+
						"they set the flag themselves", p.Prefix, ra.Interface)
				}
			case "dmz0":
				sawConfigured = true
				if p.Delegated {
					t.Errorf("operator-authored prefix %s on %s has Delegated=true. The "+
						"floor would then refuse a legitimate `::/0` — the exact "+
						"over-reach the provenance exists to prevent", p.Prefix, ra.Interface)
				}
			}
		}
	}
	if !sawPD {
		t.Fatal("no PD-derived prefix in the output — the fixture does not exercise the " +
			"stamping path, so this test proves nothing")
	}
	if !sawConfigured {
		t.Fatal("no operator-authored prefix in the output — the false-side control is " +
			"vacuous")
	}
}
