package daemon

import (
	"errors"
	"net"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
)

// withFailClosedBootLinkList stubs the link enumeration seam used by
// installFailClosedBootHostFences.
func withFailClosedBootLinkList(t *testing.T, fn func() ([]netlink.Link, error)) {
	t.Helper()
	prev := failClosedBootLinkList
	failClosedBootLinkList = fn
	t.Cleanup(func() { failClosedBootLinkList = prev })
}

// withFailClosedBootAddrList stubs the per-link address-listing seam.
func withFailClosedBootAddrList(t *testing.T, fn func(netlink.Link, int) ([]netlink.Addr, error)) {
	t.Helper()
	prev := failClosedBootAddrList
	failClosedBootAddrList = fn
	t.Cleanup(func() { failClosedBootAddrList = prev })
}

// withFailClosedBootDetect stubs lifeline (default-route NIC) detection.
func withFailClosedBootDetect(t *testing.T, fn func() (string, bool, error)) {
	t.Helper()
	prev := detectLifelineInterfaceFn
	detectLifelineInterfaceFn = fn
	t.Cleanup(func() { detectLifelineInterfaceFn = prev })
}

// withFailClosedBootLifelineFile points the lifeline record at an absent file
// so the protected set resolves to the fxp0 default (plus the stubbed
// default-route NIC), without touching sysfs.
func withFailClosedBootLifelineFile(t *testing.T) {
	t.Helper()
	prev := lifelineRecordFileForTest
	lifelineRecordFileForTest = filepath.Join(t.TempDir(), "lifeline-interface-absent")
	t.Cleanup(func() { lifelineRecordFileForTest = prev })
}

// withFailClosedBootNft installs a recording fake nft installer.
func withFailClosedBootNft(t *testing.T, fake *fakeNftInstaller) {
	t.Helper()
	prev := nftInstaller
	nftInstaller = fake
	t.Cleanup(func() { nftInstaller = prev })
}

func failClosedBootTestLink(name string, loopback bool) *testLink {
	attrs := netlink.LinkAttrs{Name: name}
	if loopback {
		attrs.Flags = net.FlagLoopback
	}
	return &testLink{attrs: attrs}
}

func failClosedBootTestAddr(t *testing.T, cidr string) netlink.Addr {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", cidr, err)
	}
	return netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: ipNet.Mask}}
}

// failClosedBootFixture wires the standard three-link box: fxp0 management
// (10.0.0.1/24), one addressed data port (ge-0-0-0, v4+v6), and loopback. It
// returns the daemon under test (empty store: no compiled config, exactly the
// #1960/#10297 fail-closed state) and the recording installer.
func failClosedBootFixture(t *testing.T) (*Daemon, *fakeNftInstaller) {
	t.Helper()
	withFailClosedBootLifelineFile(t)
	withFailClosedBootDetect(t, func() (string, bool, error) { return "fxp0", true, nil })
	fxp0 := failClosedBootTestLink("fxp0", false)
	data := failClosedBootTestLink("ge-0-0-0", false)
	lo := failClosedBootTestLink("lo", true)
	withFailClosedBootLinkList(t, func() ([]netlink.Link, error) {
		return []netlink.Link{fxp0, data, lo}, nil
	})
	addrs := map[string][]netlink.Addr{
		"fxp0":     {failClosedBootTestAddr(t, "10.0.0.1/24")},
		"ge-0-0-0": {failClosedBootTestAddr(t, "192.0.2.10/24"), failClosedBootTestAddr(t, "2001:db8::10/64")},
		"lo":       {failClosedBootTestAddr(t, "127.0.0.1/8"), failClosedBootTestAddr(t, "::1/128")},
	}
	withFailClosedBootAddrList(t, func(link netlink.Link, _ int) ([]netlink.Addr, error) {
		return addrs[link.Attrs().Name], nil
	})
	fake := &fakeNftInstaller{}
	withFailClosedBootNft(t, fake)
	return &Daemon{store: &configstore.Store{}}, fake
}

// TestFailClosedBootFencesLiveDataAddrs is the #10732 regression cell: on a
// fail-closed cold boot (committed config uncompilable, #1960, or active.json
// absent with history, #10297) the daemon must install host-input fences
// covering the live data addresses — the bootstrap path suppresses the only
// apply path that installs the real rulesets, and networkd has already applied
// the retained 10-xpf-*.network files, so without this the box answers
// host-bound services on every data address with zero enforcement.
//
// The initManagers call site gates this helper on failClosedLoad; this cell
// exercises its live-address scope and both real fence-installer call paths.
// Reverting the helper to a no-op makes the assertions below fail.
func TestFailClosedBootFencesLiveDataAddrs(t *testing.T) {
	d, fake := failClosedBootFixture(t)
	var hostSpecs, lo0Specs []xnft.FenceSpec
	fake.coldBootFence = func(s xnft.FenceSpec) error {
		hostSpecs = append(hostSpecs, s)
		return nil
	}
	fake.lo0ColdBootFence = func(s xnft.FenceSpec) error {
		lo0Specs = append(lo0Specs, s)
		return nil
	}

	d.installFailClosedBootHostFences(true)

	if len(hostSpecs) != 1 {
		t.Fatalf("fail-closed boot must install exactly one host-inbound fence, got %d", len(hostSpecs))
	}
	if len(lo0Specs) != 1 {
		t.Fatalf("fail-closed boot must install exactly one lo0 fence, got %d", len(lo0Specs))
	}
	for name, specs := range map[string][]xnft.FenceSpec{"host-inbound": hostSpecs, "lo0": lo0Specs} {
		v4 := fenceViewAddrs(specs[0], false)
		v6 := fenceViewAddrs(specs[0], true)
		if !sliceContains(v4, "192.0.2.10") {
			t.Errorf("%s fence must drop the live data v4 address; fenced v4: %v", name, v4)
		}
		if !sliceContains(v6, "2001:db8::10") {
			t.Errorf("%s fence must drop the live data v6 address; fenced v6: %v", name, v6)
		}
		if sliceContains(v4, "10.0.0.1") {
			t.Errorf("%s fence must NOT drop the management address; fenced v4: %v", name, v4)
		}
		if sliceContains(v4, "127.0.0.1") || sliceContains(v6, "::1") {
			t.Errorf("%s fence must NOT drop loopback; fenced v4: %v v6: %v", name, v4, v6)
		}
	}
	// The host-inbound fence is the retained enforcement until the first
	// compilable commit replaces it, so the day-2 coverage bookkeeping must
	// describe it (#5789); the lo0 fence is never a real filter (#6476).
	if !d.hostInboundEnforced.Load() {
		t.Errorf("address-scoped host-inbound fence must set hostInboundEnforced")
	}
	for _, key := range []string{
		hostInboundDropAddrKey('4', "192.0.2.10"),
		hostInboundDropAddrKey('6', "2001:db8::10"),
	} {
		if _, ok := d.hostInboundCoveredAddrs[key]; !ok {
			t.Errorf("hostInboundCoveredAddrs must cover %q; got %v", key, d.hostInboundCoveredAddrs)
		}
	}
	if d.lo0Enforced.Load() {
		t.Errorf("fence must NOT set lo0Enforced (a fence is not a real filter)")
	}
}

// TestFailClosedBootNoFenceWhenNotFailClosed guards the fresh-install and
// normal paths: a bootstrap for any reason OTHER than a fail-closed load
// (never-committed box, foreign host) must stay untouched and reachable.
func TestFailClosedBootNoFenceWhenNotFailClosed(t *testing.T) {
	d, fake := failClosedBootFixture(t)
	calls := 0
	fake.coldBootFence = func(xnft.FenceSpec) error { calls++; return nil }
	fake.lo0ColdBootFence = func(xnft.FenceSpec) error { calls++; return nil }

	d.installFailClosedBootHostFences(false)

	if calls != 0 {
		t.Fatalf("non-fail-closed boot must install no fences, got %d installs", calls)
	}
	if d.hostInboundEnforced.Load() {
		t.Fatalf("non-fail-closed boot must not set hostInboundEnforced")
	}
}

// TestFailClosedBootSkipsFenceWhenMgmtUnknown proves the #6789 discipline: an
// unreadable route table leaves the management NIC UNKNOWN (not "none"), and
// fencing on that guess could drop new management connections — so no fence
// is installed. Status quo, loudly logged; never a lockout.
func TestFailClosedBootSkipsFenceWhenMgmtUnknown(t *testing.T) {
	d, fake := failClosedBootFixture(t)
	withFailClosedBootDetect(t, func() (string, bool, error) {
		return "", false, errors.New("route list family 2: netlink unavailable")
	})
	calls := 0
	fake.coldBootFence = func(xnft.FenceSpec) error { calls++; return nil }
	fake.lo0ColdBootFence = func(xnft.FenceSpec) error { calls++; return nil }

	d.installFailClosedBootHostFences(true)

	if calls != 0 {
		t.Fatalf("unknown management NIC must install no fences, got %d installs", calls)
	}
}

// TestFailClosedBootSkipsFenceOnLinkListError proves an incomplete observation
// has no representation: a failed link enumeration must not yield a fence
// (an empty fence shell would report protection while covering nothing).
func TestFailClosedBootSkipsFenceOnLinkListError(t *testing.T) {
	d, fake := failClosedBootFixture(t)
	withFailClosedBootLinkList(t, func() ([]netlink.Link, error) {
		return nil, errors.New("netlink unavailable")
	})
	calls := 0
	fake.coldBootFence = func(xnft.FenceSpec) error { calls++; return nil }
	fake.lo0ColdBootFence = func(xnft.FenceSpec) error { calls++; return nil }

	d.installFailClosedBootHostFences(true)

	if calls != 0 {
		t.Fatalf("failed link enumeration must install no fences, got %d installs", calls)
	}
}

// TestFailClosedBootSkipsFenceOnAddrListError covers the per-link half of the
// same discipline: one unreadable link vetoes the whole fence.
func TestFailClosedBootSkipsFenceOnAddrListError(t *testing.T) {
	d, fake := failClosedBootFixture(t)
	withFailClosedBootAddrList(t, func(link netlink.Link, _ int) ([]netlink.Addr, error) {
		if link.Attrs().Name == "ge-0-0-0" {
			return nil, errors.New("address list unavailable")
		}
		return []netlink.Addr{failClosedBootTestAddr(t, "10.0.0.1/24")}, nil
	})
	calls := 0
	fake.coldBootFence = func(xnft.FenceSpec) error { calls++; return nil }
	fake.lo0ColdBootFence = func(xnft.FenceSpec) error { calls++; return nil }

	d.installFailClosedBootHostFences(true)

	if calls != 0 {
		t.Fatalf("failed per-link address read must install no fences, got %d installs", calls)
	}
}

// TestFailClosedBootWithholdsMgmtSharedAddress proves Finding-A parity with
// BuildFenceAddrSets (#6492): an address ALSO present on management is
// withheld everywhere — fencing it would drop new management connections,
// and the fence carries no per-service accepts to let them back in.
func TestFailClosedBootWithholdsMgmtSharedAddress(t *testing.T) {
	d, fake := failClosedBootFixture(t)
	withFailClosedBootAddrList(t, func(link netlink.Link, _ int) ([]netlink.Addr, error) {
		switch link.Attrs().Name {
		case "fxp0":
			return []netlink.Addr{failClosedBootTestAddr(t, "10.0.0.1/24")}, nil
		case "ge-0-0-0":
			return []netlink.Addr{
				failClosedBootTestAddr(t, "10.0.0.1/24"),
				failClosedBootTestAddr(t, "192.0.2.10/24"),
			}, nil
		default:
			return nil, nil
		}
	})
	var hostSpecs []xnft.FenceSpec
	fake.coldBootFence = func(s xnft.FenceSpec) error {
		hostSpecs = append(hostSpecs, s)
		return nil
	}

	d.installFailClosedBootHostFences(true)

	if len(hostSpecs) != 1 {
		t.Fatalf("expected one host-inbound fence, got %d", len(hostSpecs))
	}
	v4 := fenceViewAddrs(hostSpecs[0], false)
	if sliceContains(v4, "10.0.0.1") {
		t.Fatalf("management-shared address must be withheld, not fenced; fenced v4: %v", v4)
	}
	if !sliceContains(v4, "192.0.2.10") {
		t.Fatalf("non-shared data address must still be fenced; fenced v4: %v", v4)
	}
}

// TestFailClosedBootNoDataAddressesInstallsNothing covers the addressed-mgmt-
// only box: with nothing to fence, no (zero-drop) fence shell is installed.
func TestFailClosedBootNoDataAddressesInstallsNothing(t *testing.T) {
	d, fake := failClosedBootFixture(t)
	withFailClosedBootAddrList(t, func(link netlink.Link, _ int) ([]netlink.Addr, error) {
		if link.Attrs().Name == "fxp0" {
			return []netlink.Addr{failClosedBootTestAddr(t, "10.0.0.1/24")}, nil
		}
		return nil, nil
	})
	calls := 0
	fake.coldBootFence = func(xnft.FenceSpec) error { calls++; return nil }
	fake.lo0ColdBootFence = func(xnft.FenceSpec) error { calls++; return nil }

	d.installFailClosedBootHostFences(true)

	if calls != 0 {
		t.Fatalf("no data addresses must install no fences, got %d installs", calls)
	}
}

// TestFailClosedBootFenceInstallFailureStillTriesLo0 proves best-effort: a
// failed host-inbound fence install must not skip the lo0 fence, and neither
// failure may abort the boot (the management control plane must come up so
// the operator can fix the config).
func TestFailClosedBootFenceInstallFailureStillTriesLo0(t *testing.T) {
	d, fake := failClosedBootFixture(t)
	fake.coldBootFence = func(xnft.FenceSpec) error { return errors.New("nft unavailable") }
	lo0Calls := 0
	fake.lo0ColdBootFence = func(xnft.FenceSpec) error { lo0Calls++; return nil }

	d.installFailClosedBootHostFences(true) // must not panic or abort

	if lo0Calls != 1 {
		t.Fatalf("lo0 fence must still be attempted after a host-inbound fence failure, got %d calls", lo0Calls)
	}
}
