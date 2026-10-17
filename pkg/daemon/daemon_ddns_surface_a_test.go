package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcp"
)

// #2691 P2 daemon-level Surface A tests: scope construction from the committed
// per-interface bindings + provider catalog (with RG attribution), and the
// per-RG HA gate. Fail-on-revert: prove a binding resolves to a scoped publish
// record and that an HA-owned (reth) interface scope is keyed on its RG.

func TestBuildSurfaceAScopesFromConfig(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set system services dynamic-dns provider corp-2136 backend rfc2136",
		"set system services dynamic-dns provider corp-2136 update-server 192.0.2.53",
		"set system services dynamic-dns forced-refresh 24h",
		"set interfaces ge-0/0/2 unit 50 family inet dynamic-dns provider corp-2136",
		"set interfaces ge-0/0/2 unit 50 family inet dynamic-dns hostname wan.example.net",
		"set interfaces ge-0/0/2 unit 50 family inet dynamic-dns address-source dhcp",
		"set interfaces ge-0/0/2 unit 50 family inet6 dynamic-dns provider corp-2136",
		"set interfaces ge-0/0/2 unit 50 family inet6 dynamic-dns hostname wan6.example.net",
		// A binding whose provider is undefined must be skipped.
		"set interfaces ge-0/0/3 unit 0 family inet dynamic-dns provider ghost",
		"set interfaces ge-0/0/3 unit 0 family inet dynamic-dns hostname ghost.example.net",
	})
	d := &Daemon{store: store}
	cfg := d.store.ActiveConfig()
	scopes, _ := d.buildSurfaceAScopes(cfg)

	byFQDN := map[string]ddns.SurfaceAScope{}
	for _, s := range scopes {
		byFQDN[s.FQDN] = s
	}
	if _, ok := byFQDN["ghost.example.net"]; ok {
		t.Fatal("a binding referencing an undefined provider must be skipped")
	}
	v4, ok := byFQDN["wan.example.net"]
	if !ok {
		t.Fatalf("inet binding scope missing; got %d scopes", len(scopes))
	}
	if v4.Key.Family != ddns.FamilyV4 || v4.Key.Interface != "ge-0/0/2" || v4.Key.Unit != 50 {
		t.Fatalf("inet scope key mismatch: %+v", v4.Key)
	}
	if v4.Source != ddns.AddressSourceDHCP {
		t.Fatalf("inet scope source = %q, want dhcp", v4.Source)
	}
	if v4.Provider == nil || v4.Provider.UpdateServer != "192.0.2.53" {
		t.Fatalf("inet scope provider not resolved: %+v", v4.Provider)
	}
	if v4.ForcedRefresh.Hours() != 24 {
		t.Fatalf("forced-refresh not threaded into the scope: %v", v4.ForcedRefresh)
	}
	v6, ok := byFQDN["wan6.example.net"]
	if !ok {
		t.Fatal("inet6 binding scope missing")
	}
	if v6.Key.Family != ddns.FamilyV6 {
		t.Fatalf("inet6 scope family mismatch: %+v", v6.Key)
	}
	if v4.Source == ddns.AddressSourceInterface {
		t.Fatal("inet scope should be dhcp, not interface default")
	}
}

func TestBuildSurfaceAScopesAttributesRG(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster node 0",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set system services dynamic-dns provider corp-2136 backend rfc2136",
		"set system services dynamic-dns provider corp-2136 update-server 192.0.2.53",
		"set interfaces reth0 unit 80 family inet dynamic-dns provider corp-2136",
		"set interfaces reth0 unit 80 family inet dynamic-dns hostname vip.example.net",
	})
	d := &Daemon{store: store, cluster: cluster.NewManager(0, 1)}
	cfg := d.store.ActiveConfig()
	scopes, _ := d.buildSurfaceAScopes(cfg)
	if len(scopes) != 1 {
		t.Fatalf("expected one reth scope, got %d", len(scopes))
	}
	if scopes[0].Key.RGOwner != 1 {
		t.Fatalf("a reth0 (RG1) binding must attribute RGOwner=1, got %d", scopes[0].Key.RGOwner)
	}
}

func TestSurfaceAGatePerRG(t *testing.T) {
	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cluster.NewManager(0, 1),
	}
	// Node 0. RG1 is not master yet → an RG1 scope is gated CLOSED. RG0 is not
	// tracked yet, so the RG0/non-HA scope falls back to the lowest-node-ID
	// writer — node 0 is the writer, so it is admitted here (#2972).
	gate := d.surfaceAGate()
	if gate == nil {
		t.Fatal("cluster daemon must produce a per-RG gate")
	}
	if gate(ddns.ScopeKey{RGOwner: 1}) {
		t.Fatal("RG1 scope must be gated closed when not master for RG1")
	}
	if !gate(ddns.ScopeKey{RGOwner: 0}) {
		t.Fatal("RG0/non-HA scope must be admitted on node 0 (lowest-node-ID fallback)")
	}
}

// TestSurfaceAGateRG0SingleWriter is the #2972 fail-on-revert gate. An
// RG0/non-HA Surface A scope (RGOwner==0) must be admitted by EXACTLY ONE node
// in an active-active cluster — the node that is RG0 primary — not by every node
// that happens to master some data RG. Before the fix, surfaceAGate admitted
// every RGOwner==0 scope unconditionally, so both nodes double-wrote the same
// configured FQDN. Reverting surfaceARG0Writer to `return true` turns this RED
// (both nodes would admit the RG0 scope).
func TestSurfaceAGateRG0SingleWriter(t *testing.T) {
	// Active-active: node 0 masters RG0 (control plane) + RG1; node 1 masters
	// RG2. Both pass the node-level writer gate (each masters some RG), so both
	// would build the identical RGOwner==0 scope.
	node0 := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cluster.NewManager(0, 1),
	}
	node0.getOrCreateRGState(0).SetCluster(true) // RG0 primary
	node0.getOrCreateRGState(1).SetCluster(true) // RG1 primary
	node0.getOrCreateRGState(2).SetCluster(false)

	node1 := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cluster.NewManager(1, 0),
	}
	node1.getOrCreateRGState(0).SetCluster(false) // RG0 secondary
	node1.getOrCreateRGState(1).SetCluster(false)
	node1.getOrCreateRGState(2).SetCluster(true) // RG2 primary

	g0 := node0.surfaceAGate()
	g1 := node1.surfaceAGate()
	if g0 == nil || g1 == nil {
		t.Fatal("cluster daemons must produce per-RG gates")
	}

	rg0Scope := ddns.ScopeKey{RGOwner: 0}
	a0 := g0(rg0Scope)
	a1 := g1(rg0Scope)
	if a0 == a1 {
		t.Fatalf("RG0/non-HA scope must be admitted by exactly one node; node0=%v node1=%v (double-write)", a0, a1)
	}
	if !a0 {
		t.Fatal("the RG0-primary node (node 0) must be the writer for the RG0/non-HA scope")
	}

	// Failover: RG0 moves to node 1. The single writer must follow it.
	node0.getOrCreateRGState(0).SetCluster(false)
	node1.getOrCreateRGState(0).SetCluster(true)
	if node0.surfaceAGate()(rg0Scope) {
		t.Fatal("after RG0 failover, the old RG0-primary (node 0) must stop writing the RG0 scope")
	}
	if !node1.surfaceAGate()(rg0Scope) {
		t.Fatal("after RG0 failover, the new RG0-primary (node 1) must become the RG0 scope writer")
	}
}

// TestSurfaceAGateRG0FallbackNoRG0 covers the non-standard cluster where RG0 is
// not a tracked group (only data RGs). The RG0/non-HA scope must still have a
// single deterministic writer — the lowest node ID — not be admitted by every
// node (#2972).
func TestSurfaceAGateRG0FallbackNoRG0(t *testing.T) {
	node0 := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cluster.NewManager(0, 1),
	}
	node0.getOrCreateRGState(1).SetCluster(true) // masters RG1, no RG0 tracked

	node1 := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cluster.NewManager(1, 0),
	}
	node1.getOrCreateRGState(2).SetCluster(true) // masters RG2, no RG0 tracked

	rg0Scope := ddns.ScopeKey{RGOwner: 0}
	if !node0.surfaceAGate()(rg0Scope) {
		t.Fatal("with no RG0 tracked, the lowest-node-ID node (node 0) must write the RG0 scope")
	}
	if node1.surfaceAGate()(rg0Scope) {
		t.Fatal("with no RG0 tracked, a non-lowest node (node 1) must NOT write the RG0 scope (double-write)")
	}
}

func TestSurfaceAStandaloneGateNil(t *testing.T) {
	d := &Daemon{} // no cluster
	if d.surfaceAGate() != nil {
		t.Fatal("standalone daemon must return a nil gate (every scope writable)")
	}
}

func TestStaticUnitAddr(t *testing.T) {
	// Genuinely globally-routable unicast addresses are accepted.
	unit := &config.InterfaceUnit{Addresses: []string{"198.51.99.5/24", "2606:4700:4700::1111/64"}}
	a4, ok := staticUnitAddr(unit, true)
	if !ok || a4 != netip.MustParseAddr("198.51.99.5") {
		t.Fatalf("v4 static addr = %v ok=%v", a4, ok)
	}
	a6, ok := staticUnitAddr(unit, false)
	if !ok || a6 != netip.MustParseAddr("2606:4700:4700::1111") {
		t.Fatalf("v6 static addr = %v ok=%v", a6, ok)
	}
	// Link-local / loopback are skipped.
	llUnit := &config.InterfaceUnit{Addresses: []string{"fe80::1/64"}}
	if _, ok := staticUnitAddr(llUnit, false); ok {
		t.Fatal("link-local must not be selected as a Surface A address")
	}
}

// TestStaticUnitAddrPublicGate is the #2776 fail-on-revert gate for the
// Surface A static-address fallback. A configured static address that is NOT
// globally-routable unicast (multicast, reserved, ULA, CGNAT, documentation,
// IANA special-purpose) must be SKIPPED — never published as the router's
// A/AAAA record — and a genuine public static address must be selected. This
// goes RED if the ddns.IsPublicAddr gate is removed from staticUnitAddr: each
// rejected entry below would then be returned ok=true.
func TestStaticUnitAddrPublicGate(t *testing.T) {
	rejectV4 := []string{
		"224.0.0.1/24",       // 224/4 multicast
		"240.0.0.1/24",       // 240/4 reserved-for-future-use
		"10.1.2.3/24",        // 10/8 private
		"100.64.0.1/24",      // 100.64/10 CGNAT
		"192.0.2.5/24",       // 192.0.2/24 TEST-NET-1 documentation
		"203.0.113.5/24",     // 203.0.113/24 TEST-NET-3 documentation
		"198.18.0.1/24",      // 198.18/15 benchmarking
		"255.255.255.255/32", // limited broadcast
	}
	for _, cidr := range rejectV4 {
		u := &config.InterfaceUnit{Addresses: []string{cidr}}
		if a, ok := staticUnitAddr(u, true); ok {
			t.Errorf("staticUnitAddr(%s) = %v ok=true, want skipped (non-public)", cidr, a)
		}
	}
	rejectV6 := []string{
		"ff02::1/64",     // ff00::/8 multicast
		"fc00::1/64",     // fc00::/7 ULA
		"fd00::1/64",     // fc00::/7 ULA
		"2001:db8::1/64", // 2001:db8::/32 documentation
		"64:ff9b::1/96",  // 64:ff9b::/96 NAT64 well-known
	}
	for _, cidr := range rejectV6 {
		u := &config.InterfaceUnit{Addresses: []string{cidr}}
		if a, ok := staticUnitAddr(u, false); ok {
			t.Errorf("staticUnitAddr(%s) = %v ok=true, want skipped (non-public)", cidr, a)
		}
	}
	// A genuine public static address IS selected, even when listed after a
	// rejected one (the gate skips, it does not abort the scan).
	mixed := &config.InterfaceUnit{Addresses: []string{"224.0.0.1/24", "8.8.4.4/24"}}
	a, ok := staticUnitAddr(mixed, true)
	if !ok || a != netip.MustParseAddr("8.8.4.4") {
		t.Fatalf("public addr after a rejected one = %v ok=%v, want 8.8.4.4 ok=true", a, ok)
	}
}

// mkAddr builds a synthetic netlink.Addr with the given CIDR and IFA_F_* flags
// for selectInterfaceAddr table tests (no kernel interface required).
func mkAddr(cidr string, flags int) netlink.Addr {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	ipnet.IP = ip
	return netlink.Addr{IPNet: ipnet, Flags: flags}
}

// TestSelectInterfaceAddrLifetime is the #2775 fail-on-revert gate for IPv6
// address-lifetime-aware selection. observeInterfaceAddr (via this pure helper)
// must honor RFC 4862 address state:
//
//   - PREFER a `preferred` address over a `deprecated` one. Goes RED if the
//     lifetime-preference logic is reverted (a deprecated address wrongly
//     selected over a preferred one).
//   - fall back to `deprecated` only when no preferred exists (never blackhole).
//   - NEVER select tentative / dadfailed / optimistic (DAD not succeeded).
//   - the selected address STILL passes ddns.IsPublicAddr (composes with #2776):
//     a preferred-but-ULA address is rejected.
func TestSelectInterfaceAddrLifetime(t *testing.T) {
	pref6 := netip.MustParseAddr("2606:4700:4700::1111")
	dep6 := netip.MustParseAddr("2606:4700:4700::2222")
	pref4 := netip.MustParseAddr("198.51.99.5")

	tests := []struct {
		name  string
		addrs []netlink.Addr
		af4   bool
		want  netip.Addr
		ok    bool
	}{
		{
			// Core fail-on-revert: preferred wins over deprecated even though the
			// deprecated address is listed FIRST (netlink order must not decide).
			name: "prefer preferred over deprecated (deprecated listed first)",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::2222/64", unix.IFA_F_DEPRECATED),
				mkAddr("2606:4700:4700::1111/64", 0),
			},
			af4:  false,
			want: pref6,
			ok:   true,
		},
		{
			// Only deprecated available → use it (never blackhole).
			name: "deprecated only falls back, no blackhole",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::2222/64", unix.IFA_F_DEPRECATED),
			},
			af4:  false,
			want: dep6,
			ok:   true,
		},
		{
			// tentative / dadfailed / optimistic are never publishable, even if
			// they are the only globally-routable addresses present.
			name: "tentative never selected",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::1111/64", unix.IFA_F_TENTATIVE),
			},
			af4:  false,
			want: netip.Addr{},
			ok:   false,
		},
		{
			name: "dadfailed never selected",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::1111/64", unix.IFA_F_DADFAILED),
			},
			af4:  false,
			want: netip.Addr{},
			ok:   false,
		},
		{
			name: "optimistic never selected",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::1111/64", unix.IFA_F_OPTIMISTIC),
			},
			af4:  false,
			want: netip.Addr{},
			ok:   false,
		},
		{
			// Composition with #2776: a preferred ULA is still rejected; the
			// preferred GUA listed after it is selected.
			name: "preferred-but-ULA rejected, GUA selected",
			addrs: []netlink.Addr{
				mkAddr("fd00::1/64", 0),
				mkAddr("2606:4700:4700::1111/64", 0),
			},
			af4:  false,
			want: pref6,
			ok:   true,
		},
		{
			// A tentative preferred + a deprecated valid → deprecated wins (the
			// tentative is skipped, the deprecated is the only usable address).
			name: "tentative preferred skipped, deprecated used",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::1111/64", unix.IFA_F_TENTATIVE),
				mkAddr("2606:4700:4700::2222/64", unix.IFA_F_DEPRECATED),
			},
			af4:  false,
			want: dep6,
			ok:   true,
		},
		{
			// #2975 fail-on-revert: a SLAAC privacy/temporary preferred address
			// listed FIRST must NOT be selected when a stable permanent preferred
			// address exists. Goes RED if IFA_F_TEMPORARY is dropped from the skip
			// mask (the temporary 0xdead address would win on netlink order).
			name: "temporary skipped, permanent preferred selected (temporary first)",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::dead/64", unix.IFA_F_TEMPORARY),
				mkAddr("2606:4700:4700::1111/64", 0),
			},
			af4:  false,
			want: pref6,
			ok:   true,
		},
		{
			// A temporary address as the ONLY candidate is rejected outright — a
			// rotating privacy identifier must never be published, even at the
			// cost of no answer (it would blackhole on the next rotation anyway).
			name: "temporary only is rejected (never publish privacy identifier)",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::dead/64", unix.IFA_F_TEMPORARY),
			},
			af4:  false,
			want: netip.Addr{},
			ok:   false,
		},
		{
			// Composition: a temporary preferred + a deprecated permanent → the
			// temporary is skipped and the deprecated permanent is the only usable
			// answer (never blackhole). Confirms the temporary skip does not
			// accidentally promote a temporary into the deprecated fallback slot.
			name: "temporary preferred skipped, deprecated permanent used",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::dead/64", unix.IFA_F_TEMPORARY),
				mkAddr("2606:4700:4700::2222/64", unix.IFA_F_DEPRECATED),
			},
			af4:  false,
			want: dep6,
			ok:   true,
		},
		{
			// A deprecated temporary address (privacy address mid-rotation) is
			// skipped twice over — neither TEMPORARY nor DEPRECATED may publish.
			name: "deprecated temporary never used as fallback",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::dead/64", unix.IFA_F_TEMPORARY|unix.IFA_F_DEPRECATED),
			},
			af4:  false,
			want: netip.Addr{},
			ok:   false,
		},
		{
			// IPv4 family filter + preferred selection.
			name: "v4 preferred selected, v6 ignored",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::1111/64", 0),
				mkAddr("198.51.99.5/24", 0),
			},
			af4:  true,
			want: pref4,
			ok:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := selectInterfaceAddr(tc.addrs, tc.af4)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("selectInterfaceAddr() = %v, %v; want %v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestObserveInterfaceAddrTransientVsDefinitive is the #2840 fail-on-revert gate
// for the transient-vs-definitive contract of observeInterfaceAddr. The netlink
// reads are injected via the netlinkLinkByName / netlinkAddrList seams so no
// real kernel interface is required.
//
// The load-bearing distinction:
//
//   - A LinkByName ERROR or an AddrList ERROR is a TRANSIENT read failure →
//     (zero, false): the engine leaves the scope untouched (no publish, no
//     withdraw). It MUST NOT fall back to the configured static — publishing a
//     "configured" address that we could not confirm is "active" points DNS at a
//     possibly-stale address during a transient link outage. This case goes RED
//     if reverted to returning (static, true) on a link-read error (the #2840
//     bug).
//   - An interface that reads SUCCESSFULLY but yields no usable dynamic address
//     IS the legitimate static-use case → the static fallback applies
//     (present-but-addressless), and a present-but-addressless interface with NO
//     usable static is (zero, true) = definitively-none → the engine withdraws.
//   - A normal dynamic address is returned as-is.
func TestObserveInterfaceAddrTransientVsDefinitive(t *testing.T) {
	staticV4 := netip.MustParseAddr("198.51.99.7")
	dynV4 := netip.MustParseAddr("198.51.99.9")
	unitWithStatic := &config.InterfaceUnit{Addresses: []string{"198.51.99.7/24"}}

	// Save and restore the netlink seams.
	origLink := netlinkLinkByName
	origAddr := netlinkAddrList
	t.Cleanup(func() {
		netlinkLinkByName = origLink
		netlinkAddrList = origAddr
	})

	// fakeLink is a minimal netlink.Link for the AddrList seam to consume.
	fakeLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-2"}}

	d := &Daemon{}

	t.Run("LinkByName error is transient (no static publish)", func(t *testing.T) {
		netlinkLinkByName = func(string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}
		netlinkAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
			t.Fatal("AddrList must not be called after a LinkByName error")
			return nil, nil
		}
		got, ok := d.observeInterfaceAddr("ge-0-0-2", true, unitWithStatic)
		// FAIL-ON-REVERT: if observeInterfaceAddr is reverted to returning the
		// static on a LinkByName error, ok becomes true (and got == staticV4)
		// and this assertion fails.
		if ok || got.IsValid() {
			t.Fatalf("LinkByName error: got (%v, %v); want (zero, false) transient (static must NOT be published)", got, ok)
		}
	})

	t.Run("AddrList error is transient (no static publish)", func(t *testing.T) {
		netlinkLinkByName = func(string) (netlink.Link, error) {
			return fakeLink, nil
		}
		netlinkAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
			return nil, errors.New("netlink hiccup")
		}
		got, ok := d.observeInterfaceAddr("ge-0-0-2", true, unitWithStatic)
		if ok || got.IsValid() {
			t.Fatalf("AddrList error: got (%v, %v); want (zero, false) transient (static must NOT be published)", got, ok)
		}
	})

	t.Run("present-but-addressless falls back to static", func(t *testing.T) {
		netlinkLinkByName = func(string) (netlink.Link, error) {
			return fakeLink, nil
		}
		netlinkAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
			return nil, nil // successful read, no addresses
		}
		got, ok := d.observeInterfaceAddr("ge-0-0-2", true, unitWithStatic)
		if !ok || got != staticV4 {
			t.Fatalf("present-but-addressless: got (%v, %v); want (%v, true) static fallback", got, ok, staticV4)
		}
	})

	t.Run("present-but-addressless with no static is definitively-none", func(t *testing.T) {
		netlinkLinkByName = func(string) (netlink.Link, error) {
			return fakeLink, nil
		}
		netlinkAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
			return nil, nil
		}
		got, ok := d.observeInterfaceAddr("ge-0-0-2", true, &config.InterfaceUnit{})
		if !ok || got.IsValid() {
			t.Fatalf("addressless, no static: got (%v, %v); want (zero, true) definitively-none", got, ok)
		}
	})

	t.Run("normal dynamic address is returned", func(t *testing.T) {
		netlinkLinkByName = func(string) (netlink.Link, error) {
			return fakeLink, nil
		}
		netlinkAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
			return []netlink.Addr{mkAddr("198.51.99.9/24", 0)}, nil
		}
		got, ok := d.observeInterfaceAddr("ge-0-0-2", true, unitWithStatic)
		if !ok || got != dynV4 {
			t.Fatalf("dynamic address: got (%v, %v); want (%v, true)", got, ok, dynV4)
		}
	})
}

// TestForceDDNSUpdateOwnerGate is the #3276 fail-on-revert proof for the
// operator `request system dynamic-dns update` verb's owner gate. On a standalone
// node (no cluster) the force is accepted; on a node that is BACKUP for every RG
// the force is a no-op with a clear "not the active writer" message — the RG
// owner publishes, never the standby (#2972). Revert the ddnsWriterGateOpen check
// in ForceDDNSUpdate and the backup case returns ok=true → this test goes RED.
func TestForceDDNSUpdateOwnerGate(t *testing.T) {
	t.Run("standalone forces an update", func(t *testing.T) {
		d := &Daemon{
			rgStates: make(map[int]*rgStateMachine),
			surfaceA: surfaceAState{mgr: ddns.NewSurfaceAManager()},
		}
		ok, msg := d.ForceDDNSUpdate(true)
		if !ok {
			t.Fatalf("standalone force must be accepted; got ok=false msg=%q", msg)
		}
		if !strings.Contains(msg, "forced") {
			t.Fatalf("standalone force message = %q, want it to mention a forced update", msg)
		}
	})

	t.Run("backup for all RGs is a gated no-op", func(t *testing.T) {
		d := &Daemon{
			rgStates: make(map[int]*rgStateMachine),
			cluster:  cluster.NewManager(0, 1),
			surfaceA: surfaceAState{mgr: ddns.NewSurfaceAManager()},
		}
		d.getOrCreateRGState(1).SetCluster(false)
		d.getOrCreateRGState(2).SetCluster(false)
		ok, msg := d.ForceDDNSUpdate(true)
		if ok {
			t.Fatalf("a node BACKUP for all RGs must NOT force a publish; got ok=true msg=%q", msg)
		}
		if !strings.Contains(msg, "not the active writer") {
			t.Fatalf("backup gate message = %q, want a clear not-the-active-writer message", msg)
		}
	})

	t.Run("master for one RG forces an update", func(t *testing.T) {
		d := &Daemon{
			rgStates: make(map[int]*rgStateMachine),
			cluster:  cluster.NewManager(0, 1),
			surfaceA: surfaceAState{mgr: ddns.NewSurfaceAManager()},
		}
		d.getOrCreateRGState(1).SetCluster(false)
		d.getOrCreateRGState(2).SetCluster(true)
		ok, _ := d.ForceDDNSUpdate(true)
		if !ok {
			t.Fatal("a node MASTER for >=1 RG must accept the force-now verb")
		}
	})
}

// TestSurfaceAObserverDHCPPublicGate is the #3732 fail-closed regression: the
// DHCP address source must run its lease address through the SAME
// ddns.IsPublicAddr gate the interface / static / checkip sources apply. A
// non-public DHCP lease (RFC1918, CGNAT 100.64/10, ULA fc00::/7) must NOT be
// published to public DNS — it becomes a DEFINITIVE "no address of this family"
// observation (Addr invalid, ok=true) so the engine withdraws any stale record
// rather than publishing an unroutable/private one. A globally-routable lease
// still publishes unchanged (no over-gating).
//
// RED-on-revert: drop the ddns.IsPublicAddr gate from the DHCP branch and the
// private / CGNAT / ULA cases below flip to publishing the private address
// (obs.Addr becomes valid), failing this test.
func TestSurfaceAObserverDHCPPublicGate(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces ge-0/0/2 unit 0 family inet dynamic-dns provider p",
		"set interfaces ge-0/0/2 unit 0 family inet dynamic-dns hostname wan.example.net",
		"set interfaces ge-0/0/2 unit 0 family inet dynamic-dns address-source dhcp",
		"set interfaces ge-0/0/2 unit 0 family inet6 dynamic-dns provider p",
		"set interfaces ge-0/0/2 unit 0 family inet6 dynamic-dns hostname wan6.example.net",
		"set interfaces ge-0/0/2 unit 0 family inet6 dynamic-dns address-source dhcp",
		"set system services dynamic-dns provider p backend rfc2136",
		"set system services dynamic-dns provider p update-server 192.0.2.53",
	})
	cfg := store.ActiveConfig()

	ifc := cfg.Interfaces.Interfaces["ge-0/0/2"]
	if ifc == nil || ifc.Units[0] == nil {
		t.Fatalf("test config did not produce ge-0/0/2 unit 0")
	}
	linuxName := surfaceALinuxIfName(cfg, "ge-0/0/2", ifc.Units[0])

	cases := []struct {
		name     string
		family   ddns.Family
		af       dhcp.AddressFamily
		lease    string // lease address (CIDR); "" ⇒ no lease seeded
		wantPub  bool   // true ⇒ expect the address published
		wantAddr string // expected published bare address when wantPub
	}{
		{"v4 private rfc1918 not published", ddns.FamilyV4, dhcp.AFInet, "192.168.7.10/24", false, ""},
		{"v4 cgnat not published", ddns.FamilyV4, dhcp.AFInet, "100.64.5.10/24", false, ""},
		{"v4 public published", ddns.FamilyV4, dhcp.AFInet, "8.8.8.8/24", true, "8.8.8.8"},
		{"v6 ula not published", ddns.FamilyV6, dhcp.AFInet6, "fd12:3456::1/64", false, ""},
		{"v6 public published", ddns.FamilyV6, dhcp.AFInet6, "2606:4700:4700::1111/64", true, "2606:4700:4700::1111"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mgr := dhcp.NewManagerForTesting(nil)
			if tc.lease != "" {
				mgr.SeedLeaseForTesting(linuxName, tc.af,
					&dhcp.Lease{Address: netip.MustParsePrefix(tc.lease)})
			}
			d := &Daemon{store: store, dhcp: mgr}
			scope := ddns.SurfaceAScope{
				Key: ddns.ScopeKey{
					Family:    tc.family,
					Interface: "ge-0/0/2",
					Unit:      0,
				},
				Source: ddns.AddressSourceDHCP,
				FQDN:   "wan.example.net",
			}
			obs, ok := d.surfaceAObserver(cfg)(context.Background(), scope)
			if !ok {
				t.Fatalf("DHCP observation must be definitive (ok=true); got ok=false")
			}
			if tc.wantPub {
				if !obs.Addr.IsValid() {
					t.Fatalf("public lease %s must be published; got no address", tc.lease)
				}
				if obs.Addr.String() != tc.wantAddr {
					t.Fatalf("published address = %s, want %s", obs.Addr, tc.wantAddr)
				}
			} else {
				if obs.Addr.IsValid() {
					t.Fatalf("non-public lease %s must NOT be published; "+
						"got %s (public gate bypassed — #3732 fail-open)",
						tc.lease, obs.Addr)
				}
			}
		})
	}
}

// TestSurfaceAObserverCheckIPHonorsReconcileContext is the #3736 fail-on-revert
// proof for the checkip source: the per-probe timeout MUST derive from the
// reconcile/pass context, not context.Background(). A checkip endpoint that
// black-holes (accepts the connection but never responds) is probed while the
// caller's ctx carries a short deadline. With the fix the derived context is
// context.WithTimeout(ctx, ...), so the parent's deadline fires and the probe
// aborts promptly (a transient miss, ok=false). Revert to
// context.WithTimeout(context.Background(), surfaceACheckIPTimeout) and the
// parent deadline is ignored — the probe blocks on the hung endpoint for the
// full 10s and the bounded wait below fires t.Fatal.
func TestSurfaceAObserverCheckIPHonorsReconcileContext(t *testing.T) {
	// A checkip endpoint that black-holes: it accepts the request and blocks
	// until the client cancels (the fix) or the test tears down (a revert).
	// Plaintext is refused before any fetch since #14372, so the endpoint is
	// TLS and the probe blocks inside the TLS handshake (the production
	// client does not trust the test CA) — the reconcile ctx must abort the
	// in-flight probe either way, which is the #3736 property under test.
	done := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-done:
		}
	}))
	// Cleanups run LIFO: close(done) first so any blocked handler unblocks, THEN
	// srv.Close() (which waits for in-flight handlers) can return.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(done) })

	d := &Daemon{surfaceA: surfaceAState{mgr: ddns.NewSurfaceAManager()}}
	cfg := &config.Config{}
	scope := ddns.SurfaceAScope{
		Key: ddns.ScopeKey{
			Family:    ddns.FamilyV4,
			Interface: "ge-0/0/2",
			Unit:      0,
		},
		Source: ddns.AddressSourceCheckIP,
		FQDN:   "wan.example.net",
		Provider: &config.DDNSProvider{
			Name:       "corp",
			CheckIPURL: srv.URL,
		},
	}

	// A reconcile ctx with a short deadline; the in-flight probe must inherit it.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	type result struct {
		obs ddns.AddressObservation
		ok  bool
	}
	resCh := make(chan result, 1)
	go func() {
		obs, ok := d.surfaceAObserver(cfg)(ctx, scope)
		resCh <- result{obs, ok}
	}()

	select {
	case r := <-resCh:
		if r.ok {
			t.Fatalf("a checkip probe aborted by the reconcile ctx must be a transient miss (ok=false); got ok=true addr=%v", r.obs.Addr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("checkip observer ignored the reconcile ctx deadline and blocked on the hung endpoint " +
			"(context.Background regression, #3736)")
	}
}

// TestSurfaceACheckIPNoURLDoesNotFallBackToInterface is the #4423 H08
// fail-on-revert proof: a binding that selects `address-source checkip` while
// its provider has NO checkip-url must NOT silently fall back to the interface
// address (which would publish the WRONG address for a behind-NAT / multi-WAN
// router). The scope must keep Source=checkip, and the observer must return a
// transient miss (ok=false) — it must NOT read and publish the interface
// address even when the interface has a perfectly public one.
//
// RED-on-revert: restore `if prov.CheckIPURL != "" { src = checkip }` in
// buildSurfaceAScopes and the scope becomes Source=interface; the observer then
// reads the seeded 8.8.8.8 interface address and returns it (ok=true).
func TestSurfaceACheckIPNoURLDoesNotFallBackToInterface(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set system services dynamic-dns provider nourl backend rfc2136",
		"set system services dynamic-dns provider nourl update-server 192.0.2.53",
		"set interfaces ge-0/0/2 unit 50 family inet dynamic-dns provider nourl",
		"set interfaces ge-0/0/2 unit 50 family inet dynamic-dns hostname wan.example.net",
		"set interfaces ge-0/0/2 unit 50 family inet dynamic-dns address-source checkip",
	})
	d := &Daemon{store: store}
	cfg := d.store.ActiveConfig()
	scopes, _ := d.buildSurfaceAScopes(cfg)
	if len(scopes) != 1 {
		t.Fatalf("expected one scope, got %d", len(scopes))
	}
	if scopes[0].Source != ddns.AddressSourceCheckIP {
		t.Fatalf("checkip binding with a urlless provider must KEEP source=checkip, got %q "+
			"(silent fallback to interface = #4423 H08)", scopes[0].Source)
	}

	// The interface has a genuinely public address. The observer must still NOT
	// publish it — a missing checkip-url is fail-closed, not a fallback.
	origLink := netlinkLinkByName
	origAddr := netlinkAddrList
	defer func() { netlinkLinkByName = origLink; netlinkAddrList = origAddr }()
	netlinkLinkByName = func(string) (netlink.Link, error) { return &netlink.Dummy{}, nil }
	netlinkAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{mkAddr("8.8.8.8/24", 0)}, nil
	}

	obs, ok := d.surfaceAObserver(cfg)(context.Background(), scopes[0])
	if ok {
		t.Fatalf("a checkip scope with no checkip-url must be a transient miss (ok=false); "+
			"got ok=true addr=%v (interface fallback = #4423 H08)", obs.Addr)
	}
}

// TestBuildSurfaceAScopesInvalidBindingsVisible is the #4423 M09 fail-on-revert
// proof: a structurally-incomplete binding (no hostname / no provider /
// undefined provider) builds no scope but must NOT vanish — it is returned as a
// synthesized `invalid` status row so the operator can still see it. RED-on-
// revert: drop the noteInvalid calls in buildSurfaceAScopes and the invalid
// slice comes back empty.
func TestBuildSurfaceAScopesInvalidBindingsVisible(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set system services dynamic-dns provider corp-2136 backend rfc2136",
		"set system services dynamic-dns provider corp-2136 update-server 192.0.2.53",
		// undefined provider
		"set interfaces ge-0/0/3 unit 0 family inet dynamic-dns provider ghost",
		"set interfaces ge-0/0/3 unit 0 family inet dynamic-dns hostname ghost.example.net",
		// missing hostname (valid provider)
		"set interfaces ge-0/0/4 unit 0 family inet dynamic-dns provider corp-2136",
	})
	d := &Daemon{store: store}
	cfg := d.store.ActiveConfig()
	scopes, invalid := d.buildSurfaceAScopes(cfg)
	if len(scopes) != 0 {
		t.Fatalf("neither incomplete binding may build a scope; got %d scopes", len(scopes))
	}
	byFQDN := map[string]ddns.SurfaceAStatusView{}
	byProv := map[string]ddns.SurfaceAStatusView{}
	for _, v := range invalid {
		if v.State != ddns.SurfaceAStateInvalid {
			t.Fatalf("invalid row must have state %q, got %q", ddns.SurfaceAStateInvalid, v.State)
		}
		byFQDN[v.FQDN] = v
		byProv[v.Provider] = v
	}
	if len(invalid) != 2 {
		t.Fatalf("both incomplete bindings must be surfaced; got %d invalid rows: %+v", len(invalid), invalid)
	}
	ghost, ok := byFQDN["ghost.example.net"]
	if !ok || !strings.Contains(ghost.LastError, "undefined provider") {
		t.Fatalf("undefined-provider binding must be visible with a reason; got %+v", ghost)
	}
	// missing-hostname binding: FQDN is "", provider corp-2136.
	mh, ok := byProv["corp-2136"]
	if !ok || !strings.Contains(mh.LastError, "no hostname") {
		t.Fatalf("missing-hostname binding must be visible with a reason; got %+v", mh)
	}
}

// TestSurfaceAObserverDHCPTransientGapNoWithdraw is the #4423 M10 fail-on-revert
// proof: a missing DHCP lease is a DEFINITIVE loss (withdraw) ONLY when the unit
// is no longer DHCP-configured for the family. While the unit is still
// DHCP-configured, a missing lease is a TRANSIENT gap (bring-up / renewal /
// client-restart on an option change) and must be observed ok=false — never a
// withdraw — so a benign DHCP option change does not blackhole the record.
//
// RED-on-revert: restore the unconditional `return {..DHCP}, true` on lease==nil
// and the DHCP-configured case below flips to a definitive (ok=true) loss.
func TestSurfaceAObserverDHCPTransientGapNoWithdraw(t *testing.T) {
	// (a) Unit IS DHCP-configured (family inet dhcp) but has no lease yet.
	storeDHCP := testStoreWithSetConfig(t, []string{
		"set interfaces ge-0/0/2 unit 0 family inet dhcp",
		"set interfaces ge-0/0/2 unit 0 family inet dynamic-dns provider p",
		"set interfaces ge-0/0/2 unit 0 family inet dynamic-dns hostname wan.example.net",
		"set interfaces ge-0/0/2 unit 0 family inet dynamic-dns address-source dhcp",
		"set system services dynamic-dns provider p backend rfc2136",
		"set system services dynamic-dns provider p update-server 192.0.2.53",
	})
	cfgDHCP := storeDHCP.ActiveConfig()
	d1 := &Daemon{store: storeDHCP, dhcp: dhcp.NewManagerForTesting(nil)} // no lease seeded
	scope := ddns.SurfaceAScope{
		Key:    ddns.ScopeKey{Family: ddns.FamilyV4, Interface: "ge-0/0/2", Unit: 0},
		Source: ddns.AddressSourceDHCP,
		FQDN:   "wan.example.net",
	}
	if _, ok := d1.surfaceAObserver(cfgDHCP)(context.Background(), scope); ok {
		t.Fatal("a missing lease while the unit is STILL DHCP-configured must be a TRANSIENT " +
			"observation (ok=false), never a definitive withdraw (#4423 M10)")
	}

	// (b) Same binding, but the unit is NOT DHCP-configured (no family inet dhcp).
	// A missing lease is now definitive (interface reconfigured away from DHCP).
	storeNoDHCP := testStoreWithSetConfig(t, []string{
		"set interfaces ge-0/0/2 unit 0 family inet dynamic-dns provider p",
		"set interfaces ge-0/0/2 unit 0 family inet dynamic-dns hostname wan.example.net",
		"set interfaces ge-0/0/2 unit 0 family inet dynamic-dns address-source dhcp",
		"set system services dynamic-dns provider p backend rfc2136",
		"set system services dynamic-dns provider p update-server 192.0.2.53",
	})
	cfgNoDHCP := storeNoDHCP.ActiveConfig()
	d2 := &Daemon{store: storeNoDHCP, dhcp: dhcp.NewManagerForTesting(nil)}
	obs, ok := d2.surfaceAObserver(cfgNoDHCP)(context.Background(), scope)
	if !ok {
		t.Fatal("a missing lease when the unit is NOT DHCP-configured must be a DEFINITIVE " +
			"observation (ok=true) so a stale record is withdrawn")
	}
	if obs.Addr.IsValid() {
		t.Fatalf("definitive no-lease observation must carry no address; got %v", obs.Addr)
	}
}

// TestBuildSurfaceAScopesDeterministicOrder is the #4423 M12 fail-on-revert
// proof: the scope slice must arrive in a deterministic (sorted) order, not the
// Go-map-iteration-random order of the interface walk. Reconcile processes
// scopes in slice order, and two scopes targeting the same FQDN resolve to a
// nondeterministic winner without a stable order. RED-on-revert: remove the
// sort.Slice at the end of buildSurfaceAScopes and repeated calls yield varying
// orders (this test's determinism check fails on some run).
func TestBuildSurfaceAScopesDeterministicOrder(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set system services dynamic-dns provider p backend rfc2136",
		"set system services dynamic-dns provider p update-server 192.0.2.53",
		"set interfaces ge-0/0/4 unit 0 family inet dynamic-dns provider p",
		"set interfaces ge-0/0/4 unit 0 family inet dynamic-dns hostname d.example.net",
		"set interfaces ge-0/0/1 unit 0 family inet dynamic-dns provider p",
		"set interfaces ge-0/0/1 unit 0 family inet dynamic-dns hostname a.example.net",
		"set interfaces ge-0/0/2 unit 7 family inet dynamic-dns provider p",
		"set interfaces ge-0/0/2 unit 7 family inet dynamic-dns hostname b7.example.net",
		"set interfaces ge-0/0/2 unit 3 family inet dynamic-dns provider p",
		"set interfaces ge-0/0/2 unit 3 family inet dynamic-dns hostname b3.example.net",
		"set interfaces ge-0/0/3 unit 0 family inet dynamic-dns provider p",
		"set interfaces ge-0/0/3 unit 0 family inet dynamic-dns hostname c.example.net",
	})
	d := &Daemon{store: store}
	cfg := d.store.ActiveConfig()

	key := func(scopes []ddns.SurfaceAScope) string {
		var b strings.Builder
		for _, s := range scopes {
			fmt.Fprintf(&b, "%s/%d;", s.Key.Interface, s.Key.Unit)
		}
		return b.String()
	}
	// Explicit total-order expectation (interface, then unit).
	want := "ge-0/0/1/0;ge-0/0/2/3;ge-0/0/2/7;ge-0/0/3/0;ge-0/0/4/0;"
	for i := 0; i < 40; i++ {
		scopes, _ := d.buildSurfaceAScopes(cfg)
		if got := key(scopes); got != want {
			t.Fatalf("run %d: scope order = %q, want deterministic %q (#4423 M12)", i, got, want)
		}
	}
}

// TestObserveInterfaceAddrDHCPRestartTransient_6555 is the #6555 fail-on-revert
// gate: the DEFAULT Surface A address source (`interface`) must not report a
// DHCP client-restart address-gone window as a DEFINITIVE loss, because the
// engine answers a definitive loss with a wire withdraw of the public A/AAAA
// record (surface_a.go: !obs.Addr.IsValid() -> withdrawScopeLocked ->
// backend.DeleteLease). A routine DHCP option change restarts the client, whose
// finishClient removes the leased address, and the removal itself nudges a
// Surface A pass ~2s later — squarely inside the DORA re-acquire window.
//
// The `dhcp` source already carried this guard (#4423 M10); the default one did
// not. Both now read the same committed-config predicate
// (unitRunsDHCPForFamily), so they cannot drift.
//
// Deleting the `len(addrs) == 0 && unitRunsDHCPForFamily(...)` guard from
// observeInterfaceAddr makes cases (a) and (c) go red.
func TestObserveInterfaceAddrDHCPRestartTransient_6555(t *testing.T) {
	origLink := netlinkLinkByName
	origAddr := netlinkAddrList
	t.Cleanup(func() {
		netlinkLinkByName = origLink
		netlinkAddrList = origAddr
	})
	fakeLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-2"}}
	netlinkLinkByName = func(string) (netlink.Link, error) { return fakeLink, nil }
	d := &Daemon{}

	noAddrs := func(netlink.Link, int) ([]netlink.Addr, error) { return nil, nil }

	// (a) v4: unit still `family inet dhcp`, kernel reports no IPv4 at all —
	// the client-restart flush window. TRANSIENT: retain, never withdraw.
	netlinkAddrList = noAddrs
	if got, ok := d.observeInterfaceAddr("ge-0-0-2", true, &config.InterfaceUnit{DHCP: true}); ok || got.IsValid() {
		t.Fatalf("(a) DHCPv4 unit with no address: got (%v, %v); want (zero, false) transient — a definitive verdict here withdraws the public A record on every DHCP option change", got, ok)
	}

	// (b) v4: the unit was reconfigured AWAY from DHCP, so the absence is real.
	// This must stay DEFINITIVE — the guard must not swallow a genuine loss.
	netlinkAddrList = noAddrs
	if got, ok := d.observeInterfaceAddr("ge-0-0-2", true, &config.InterfaceUnit{}); !ok || got.IsValid() {
		t.Fatalf("(b) non-DHCP unit with no address: got (%v, %v); want (zero, true) definitively-none", got, ok)
	}

	// (c) v6 uses the DHCPv6 flag, not the v4 one. A guard keyed on the wrong
	// field would pass (a) and (b) and still leave the v6 default source
	// withdrawing AAAA on every DHCPv6 restart.
	netlinkAddrList = noAddrs
	if got, ok := d.observeInterfaceAddr("ge-0-0-2", false, &config.InterfaceUnit{DHCPv6: true}); ok || got.IsValid() {
		t.Fatalf("(c) DHCPv6 unit with no v6 address: got (%v, %v); want (zero, false) transient", got, ok)
	}

	// (d) CROSS-FAMILY: a v4-only DHCP unit asked about v6 must stay definitive.
	// A guard that ignored the family argument would wrongly go transient here
	// and never withdraw a stale AAAA.
	netlinkAddrList = noAddrs
	if got, ok := d.observeInterfaceAddr("ge-0-0-2", false, &config.InterfaceUnit{DHCP: true}); !ok || got.IsValid() {
		t.Fatalf("(d) v4-DHCP unit asked about v6: got (%v, %v); want (zero, true) definitively-none", got, ok)
	}

	// (e) A configured static still WINS over the transient guard: it is a real
	// address, and the pre-existing present-but-addressless static fallback must
	// not be shadowed by the new branch (guard placement — it sits AFTER
	// staticUnitAddr).
	netlinkAddrList = noAddrs
	unit := &config.InterfaceUnit{DHCP: true, Addresses: []string{"198.51.99.7/24"}}
	want := netip.MustParseAddr("198.51.99.7")
	if got, ok := d.observeInterfaceAddr("ge-0-0-2", true, unit); !ok || got != want {
		t.Fatalf("(e) DHCP unit with a configured static: got (%v, %v); want (%v, true) static fallback", got, ok, want)
	}

	// (f) SCOPE BOUNDARY: the family HAS an address, it was merely rejected by
	// selectInterfaceAddr (here IFA_F_TENTATIVE). That is NOT the restart window
	// and stays DEFINITIVE — the same posture the `dhcp` source takes for a
	// non-public lease. Widening the guard to "selectInterfaceAddr found nothing"
	// would flip this and is a separate behaviour choice.
	netlinkAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{mkAddr("2001:db8::1/64", unix.IFA_F_TENTATIVE)}, nil
	}
	if got, ok := d.observeInterfaceAddr("ge-0-0-2", false, &config.InterfaceUnit{DHCPv6: true}); !ok || got.IsValid() {
		t.Fatalf("(f) tentative-only v6 on a DHCPv6 unit: got (%v, %v); want (zero, true) definitive — the guard must key on an EMPTY family list, not on selection failure", got, ok)
	}
}
