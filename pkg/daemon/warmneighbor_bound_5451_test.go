package daemon

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// warmNeighborTestStore is a minimal SessionStore that yields a fixed set of
// IPv4/IPv6 destination IPs to warmNeighborCache. Only ForEachV4/ForEachV6 are
// exercised; the rest of the interface is embedded (nil) and never called.
type warmNeighborTestStore struct {
	dataplane.SessionStore
	v4 [][4]byte
	v6 [][16]byte
}

func (s *warmNeighborTestStore) ForEachV4(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for _, ip := range s.v4 {
		// SrcIP == DstIP so each session contributes exactly one unique IP.
		if !fn(dataplane.SessionKey{SrcIP: ip, DstIP: ip}, dataplane.SessionValue{}) {
			return nil
		}
	}
	return nil
}

func (s *warmNeighborTestStore) ForEachV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for _, ip := range s.v6 {
		if !fn(dataplane.SessionKeyV6{SrcIP: ip, DstIP: ip}, dataplane.SessionValueV6{}) {
			return nil
		}
	}
	return nil
}

// warmNeighborTestDP is a minimal RuntimeDataPlane whose Sessions() returns the
// injected store. warmNeighborCache only touches the dataplane's Sessions().
type warmNeighborTestDP struct {
	dataplane.RuntimeDataPlane
	store dataplane.SessionStore
}

func (d *warmNeighborTestDP) Sessions() dataplane.SessionStore { return d.store }

// countingWarmDialer records every socket opened and every destination probed
// so the test can assert (a) the socket high-water mark is bounded by a
// constant and (b) every unique IP was warmed.
type countingWarmDialer struct {
	mu       sync.Mutex
	opens    int                   // total sockets opened (the resource high-water)
	probedV4 map[netip.Addr]int    // dst -> probe count (udp4 socket)
	probedV6 map[netip.Addr]int    // dst -> probe count (udp6 socket)
	boundTo  map[netip.Addr]string // dst -> interface its socket was bound to (#18617)
}

func newCountingWarmDialer() *countingWarmDialer {
	return &countingWarmDialer{
		probedV4: map[netip.Addr]int{},
		probedV6: map[netip.Addr]int{},
		boundTo:  map[netip.Addr]string{},
	}
}

func (c *countingWarmDialer) open(network, ifname string) (neighborWarmConn, error) {
	c.mu.Lock()
	c.opens++
	c.mu.Unlock()
	return &countingWarmConn{dialer: c, network: network, ifname: ifname}, nil
}

type countingWarmConn struct {
	dialer  *countingWarmDialer
	network string
	ifname  string
}

func (c *countingWarmConn) probe(dst netip.AddrPort) error {
	c.dialer.mu.Lock()
	defer c.dialer.mu.Unlock()
	if c.network == "udp6" {
		c.dialer.probedV6[dst.Addr()]++
	} else {
		c.dialer.probedV4[dst.Addr()]++
	}
	c.dialer.boundTo[dst.Addr()] = c.ifname
	return nil
}

func (c *countingWarmConn) Close() error { return nil }

// TestWarmNeighborCacheBoundsSocketsAtCGNATScale is the #5451 regression guard.
// With a large session table (500 unique v4 + 500 unique v6 destinations) the
// warmup must open a CONSTANT number of sockets (one reusable socket per
// family), not one per unique IP, while still warming every destination.
//
// Fail-on-revert: restoring the pre-#5451 open-per-IP loop drives `opens` to
// ~1000 (one socket per unique IP), tripping the neighborWarmMaxSockets bound.
func TestWarmNeighborCacheBoundsSocketsAtCGNATScale(t *testing.T) {
	const n = 500

	v4 := make([][4]byte, 0, n)
	wantV4 := map[netip.Addr]bool{}
	for i := 0; i < n; i++ {
		// 100.64.0.0/10 (CGNAT) — global-unicast, non-private, passes the filter.
		ip := [4]byte{100, 64, byte(i / 256), byte(i % 256)}
		v4 = append(v4, ip)
		wantV4[netip.AddrFrom4(ip)] = true
	}

	v6 := make([][16]byte, 0, n)
	wantV6 := map[netip.Addr]bool{}
	for i := 0; i < n; i++ {
		// 2001:db8::/32 documentation range — global unicast.
		var ip [16]byte
		ip[0], ip[1] = 0x20, 0x01
		ip[2], ip[3] = 0x0d, 0xb8
		ip[14] = byte(i / 256)
		ip[15] = byte(i % 256)
		v6 = append(v6, ip)
		wantV6[netip.AddrFrom16(ip)] = true
	}

	dialer := newCountingWarmDialer()
	d := &Daemon{
		neighborWarmDialer: dialer,
	}
	d.setDataplane(&warmNeighborTestDP{store: &warmNeighborTestStore{v4: v4, v6: v6}}) // #2114: publish through the cell

	// #18617: the warm-up probes only on-link endpoints of a held prefix, so
	// put every test endpoint on one held non-RETH unit. Its own addresses
	// sit outside the generated ranges so none of them is "owned".
	cfg, in := oneUnitWarmConfig5451()
	d.neighborWarmPlanInputs = in
	d.warmNeighborCacheFor(cfg)

	// (a) Bound: sockets opened must be a small constant per interface, NOT
	// ~one per IP. Every endpoint is on one interface here.
	if dialer.opens > neighborWarmSocketsPerInterface {
		t.Errorf("opened %d sockets for %d unique IPs on one interface; want <= %d (socket per family, not per IP)",
			dialer.opens, 2*n, neighborWarmSocketsPerInterface)
	}

	// (b) Coverage: every unique destination must be warmed exactly once — no
	// correctness regression from the resource bound.
	if err := assertWarmedExactly(dialer.probedV4, wantV4); err != nil {
		t.Errorf("v4 coverage: %v", err)
	}
	if err := assertWarmedExactly(dialer.probedV6, wantV6); err != nil {
		t.Errorf("v6 coverage: %v", err)
	}
}

// TestWarmNeighborCacheNoSocketsWhenEmpty confirms the warmup opens no sockets
// when there are no sessions (lazy per-family open).
func TestWarmNeighborCacheNoSocketsWhenEmpty(t *testing.T) {
	dialer := newCountingWarmDialer()
	d := &Daemon{
		neighborWarmDialer: dialer,
	}
	d.setDataplane(&warmNeighborTestDP{store: &warmNeighborTestStore{}}) // #2114: publish through the cell
	d.warmNeighborCache()
	if dialer.opens != 0 {
		t.Errorf("opened %d sockets for an empty session table; want 0", dialer.opens)
	}
}

func assertWarmedExactly(got map[netip.Addr]int, want map[netip.Addr]bool) error {
	if len(got) != len(want) {
		return fmt.Errorf("warmed %d distinct IPs, want %d", len(got), len(want))
	}
	for ip := range want {
		c, ok := got[ip]
		if !ok {
			return fmt.Errorf("IP %v was never warmed", ip)
		}
		if c != 1 {
			return fmt.Errorf("IP %v warmed %d times, want exactly 1", ip, c)
		}
	}
	return nil
}

// oneUnitWarmConfig5451 is a single non-RETH unit whose prefixes (held by the
// kernel) contain every endpoint the #5451 cell generates.
func oneUnitWarmConfig5451() (*config.Config, neighborWarmPlanInputs) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Addresses: []string{"100.127.255.254/10", "2001:db8:ffff::1/32"}},
		}},
	}
	in := neighborWarmPlanInputs{
		rgPrimary: func(int) bool { return false },
		localAddrs: func(ifname string) []netip.Prefix {
			if ifname != "ge-0-0-1" {
				return nil
			}
			return []netip.Prefix{
				netip.MustParsePrefix("100.127.255.254/10"),
				netip.MustParsePrefix("2001:db8:ffff::1/32"),
			}
		},
	}
	return cfg, in
}
