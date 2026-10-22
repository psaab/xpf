package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// lo0_addr_failclosed_6512_test.go is the daemon half of the #6512 proof. The
// nftables half (pkg/nftables/netlink_lo0_addrs_6512_test.go) proves the
// production builder FAILS CLOSED on a malformed address token; this half proves
// the token actually REACHES that builder on the production path and that a
// failed install is handled fail-closed. The seam between the halves is
// nftInstaller.InstallLo0, the injection point #6387 PR-3 established for every
// fail-closed lo0/host-inbound regression test.
//
// Production call path: applyLo0Filter -> toNftLo0Spec ->
// nftInstaller.InstallLo0(spec) -> buildLo0FilterNetlink -> lo0AddrScope ->
// filterFamilyAddrs.

// TestMalformedPrefixListEntryReachesLo0Builder6512 pins the reachability half.
//
// A malformed entry inside a referenced `policy-options prefix-list` is NOT
// rejected by the strict commit gate: validateFilterAddressLiteralsStrict checks
// literal `from source-address` / `destination-address` tokens only, and
// validateFirewallPrefixListReferencesStrict validates that the REFERENCE
// resolves, not that its entries parse. So this list reaches the lowering on the
// ORDINARY commit path, not only on the lenient / peer-sync path — and it
// carries no #6463 AddressUnrepresentable marker either, since that marker is
// derived from term.UnknownAddresses (literals only). That is why #6512 is fixed
// by detecting the token in the builder rather than by consuming the marker.
func TestMalformedPrefixListEntryReachesLo0Builder6512(t *testing.T) {
	cfg := &config.Config{}
	cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{
		"mgmt": {Name: "mgmt", Prefixes: []string{"10.0.0.0/8", "10.0.0.0/99"}},
	}
	cfg.System.Lo0FilterInputV4 = "protect-re"
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-re": {Name: "protect-re", Terms: []*config.FirewallFilterTerm{
			{Name: "block-mgmt", SourcePrefixLists: []config.PrefixListRef{{Name: "mgmt"}}, Action: config.FilterActionDiscard},
		}},
	}

	var got xnft.Lo0FilterSpec
	calls := 0
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0: func(s xnft.Lo0FilterSpec) error { got = s; calls++; return nil },
	}
	defer func() { nftInstaller = orig }()

	if err := d6512().applyLo0Filter(cfg); err != nil {
		t.Fatalf("applyLo0Filter: %v", err)
	}
	if calls != 1 {
		t.Fatalf("InstallLo0 call count = %d, want 1", calls)
	}
	if len(got.V4Terms) != 1 {
		t.Fatalf("want 1 lowered v4 term, got %d", len(got.V4Terms))
	}
	term := got.V4Terms[0]
	if !term.SrcConstrained {
		t.Fatal("the source direction must stay CONSTRAINED — an unconstrained direction matches every address")
	}
	if !sliceContains(term.SrcAddrs, "10.0.0.0/99") {
		t.Fatalf("the malformed prefix-list entry must reach the builder verbatim (that is what "+
			"makes the narrowing possible); SrcAddrs = %v", term.SrcAddrs)
	}
	if !sliceContains(term.SrcAddrs, "10.0.0.0/8") {
		t.Fatalf("the well-formed entry must reach the builder too — this is the PARTIAL list "+
			"shape; SrcAddrs = %v", term.SrcAddrs)
	}
}

// TestLo0AddressBuildFailureFencesAndSurfaces6512 pins the consequence half: an
// InstallLo0 that fails closed on a malformed address is handled exactly like
// any other lo0 install failure — the cold-boot fail-closed fence goes in (no
// real filter is loaded) and the error is surfaced so the commit fails rather
// than silently reporting a filter that never loaded. This is why failing closed
// is not a brick (#1960): the box still boots (the boot apply logs+discards the
// error) with a fence that exempts every lifeline interface, instead of a kernel
// filter that differs from what the operator wrote.
func TestLo0AddressBuildFailureFencesAndSurfaces6512(t *testing.T) {
	cfg := lo0FenceTestConfig()
	injected := errors.New(`lo0 filter term "block-mgmt" source-address (except=false): malformed address "10.0.0.0/99" (neither an IP nor a CIDR prefix)`)

	fences := 0
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0:              func(xnft.Lo0FilterSpec) error { return injected },
		lo0ColdBootFence: func(xnft.FenceSpec) error { fences++; return nil },
	}
	defer func() { nftInstaller = orig }()

	d := d6512()
	err := d.applyLo0Filter(cfg)
	if err == nil {
		t.Fatal("a fail-closed address build must be surfaced as a commit error, got nil")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("the returned error must wrap the build failure, got %v", err)
	}
	if fences != 1 {
		t.Fatalf("cold-boot fence install count = %d, want 1", fences)
	}
	if d.lo0Enforced.Load() {
		t.Fatal("a failed install must not record a real filter as loaded")
	}
}

func d6512() *Daemon { return &Daemon{} }
