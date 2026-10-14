package daemon

// #10856 phase 2 wiring: the configured-prefix overlap policy has three
// hops, and each is asserted where its seam lives:
//
//   - config.ConfiguredIPv6Prefixes (unit-tested in pkg/config) collects the
//     static interface / RA / NAT64 prefixes;
//   - reconcileDHCPClients installs that set on the DHCP manager, whose
//     decoder refuses an overlapping IA_PD at extraction (pkg/dhcp tests);
//   - buildRAConfigs stamps the same set on every RA config, whose sender
//     refuses an overlapping DELEGATED PIO at emission (pkg/ra tests).
//
// The cells here bind the two daemon hops — deleting either call leaves the
// pkg/dhcp and pkg/ra cells green while the policy stops being fed.

import (
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

func overlapPolicyConfig10856() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Addresses: []string{"2606:4700:1111::1/64"}},
		}},
	}
	cfg.Protocols.RouterAdvertisement = []*config.RAInterfaceConfig{{
		Interface: "trust0",
		Prefixes:  []*config.RAPrefix{{Prefix: "2606:4700:2222::/64", OnLink: true, Autonomous: true}},
	}}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{{Name: "n64", Prefix: "64:ff9b:1::/96"}}
	return cfg
}

// reconcileDHCPClients installs the configured-prefix set BEFORE the client
// reconcile, so a client (re)started by the same apply decodes replies
// against the new configuration.
func TestReconcileInstallsProtectedPDOverlapSet10856(t *testing.T) {
	mgr := dhcp.NewManagerForTesting(nil)
	d := &Daemon{dhcp: mgr} // opts zero-value: NoDataplane=false
	d.reconcileDHCPClients(overlapPolicyConfig10856())

	got := mgr.ProtectedIPv6PrefixesForTesting()
	want := []netip.Prefix{
		netip.MustParsePrefix("2606:4700:1111::/64"),
		netip.MustParsePrefix("2606:4700:2222::/64"),
		netip.MustParsePrefix("64:ff9b:1::/96"),
	}
	if len(got) != len(want) {
		t.Fatalf("manager protected set = %v, want %v", got, want)
	}
	sort.Slice(got, func(i, j int) bool { return got[i].String() < got[j].String() })
	sort.Slice(want, func(i, j int) bool { return want[i].String() < want[j].String() })
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("manager protected set = %v, want %v", got, want)
		}
	}

	// A config with no configured v6 prefixes clears the set — a removed
	// address must not keep refusing its delegations forever.
	d.reconcileDHCPClients(&config.Config{})
	if got := mgr.ProtectedIPv6PrefixesForTesting(); len(got) != 0 {
		t.Fatalf("protected set after empty config = %v, want empty", got)
	}
}

// buildRAConfigs stamps the box-wide protected set on EVERY RA config —
// the static one and a PD-created one alike — so the sender can refuse a
// delegated PIO overlapping configured space on any interface.
func TestBuildRAConfigsStampsProtectedPrefixes10856(t *testing.T) {
	mgr := dhcp.NewManagerForTesting(nil)
	mgr.SeedDelegatedPrefixesForRATesting("ge-0/0/3", "lan0", []dhcp.DelegatedPrefix{{
		Interface:     "ge-0/0/3",
		Prefix:        netip.MustParsePrefix("2606:4700:9999::/48"),
		ValidLifetime: 2 * time.Hour, // only presence matters here
	}})
	d := &Daemon{dhcp: mgr}
	ras := d.buildRAConfigs(overlapPolicyConfig10856())

	want := []string{"2606:4700:1111::/64", "2606:4700:2222::/64", "64:ff9b:1::/96"}
	sawStatic, sawPD := false, false
	for _, ra := range ras {
		got := append([]string(nil), ra.ProtectedPrefixes...)
		sort.Strings(got)
		if len(got) != len(want) {
			t.Fatalf("RA %s ProtectedPrefixes = %v, want %v", ra.Interface, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("RA %s ProtectedPrefixes = %v, want %v", ra.Interface, got, want)
			}
		}
		switch ra.Interface {
		case "trust0":
			sawStatic = true
		case "lan0":
			sawPD = true
		}
	}
	if !sawStatic || !sawPD {
		t.Fatalf("fixture must exercise both RA kinds (static=%v PD=%v); configs: %d", sawStatic, sawPD, len(ras))
	}

	// The PD-derived prefix itself must NOT be protected: a delegation can
	// never collide with itself, and marking it would refuse every sub-prefix
	// derived from it.
	for _, p := range []string{"2606:4700:9999::/48", "2606:4700:9999::/64"} {
		for _, ra := range ras {
			for _, prot := range ra.ProtectedPrefixes {
				if prot == p {
					t.Fatalf("PD-derived prefix %s leaked into the protected set", p)
				}
			}
		}
	}
}
