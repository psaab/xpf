package flowexport

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// renumberConn is a net.Conn fake for the #15073 stale-source legs: it
// reports a mutable LocalAddr (the implicit source captured at dial time)
// and succeeds on Write until failErr is armed, modelling the IPv4
// EADDRNOTAVAIL-class failure that follows renumbering. It also carries
// the dialed-at dial identity so a test can prove the live socket was
// swapped, not merely re-labelled.

type errBox struct{ err error }
type renumberConn struct {
	net.Conn
	mu          sync.Mutex
	local       string
	err         error
	closed      atomic.Bool
	closeCalls  atomic.Int64
	writes      atomic.Int64
	deadlineSet atomic.Int64
}

func (c *renumberConn) Write(b []byte) (int, error) {
	c.writes.Add(1)
	c.mu.Lock()
	err := c.err
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *renumberConn) Close() error {
	c.closed.Store(true)
	c.closeCalls.Add(1)
	return nil
}

func (c *renumberConn) SetWriteDeadline(time.Time) error {
	c.deadlineSet.Add(1)
	return nil
}

func (c *renumberConn) LocalAddr() net.Addr {
	c.mu.Lock()
	s := c.local
	c.mu.Unlock()
	if s == "" {
		return nil
	}
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil
	}
	return a
}

func (c *renumberConn) setErr(err error) {
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
}

func (c *renumberConn) setLocal(s string) {
	c.mu.Lock()
	c.local = s
	c.mu.Unlock()
}

// withLocalAddrs installs the assigned-address view for the duration of fn
// and restores the previous seam afterwards.
func withLocalAddrs(t *testing.T, fn func() ([]net.Addr, error)) {
	t.Helper()
	orig := localAddrsFn
	localAddrsFn = fn
	t.Cleanup(func() { localAddrsFn = orig })
}

func assignedAddrs(ips ...string) func() ([]net.Addr, error) {
	return func() ([]net.Addr, error) {
		out := make([]net.Addr, 0, len(ips))
		for _, s := range ips {
			ip := net.ParseIP(s)
			if ip == nil {
				continue
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
		if len(out) == 0 {
			out = append(out, &net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 8)})
		}
		return out, nil
	}
}

// withDialSeams15073 swaps the no-source dial seam so each dial returns a
// fresh renumberConn bound to the next local address in locals (cycling),
// counting dials. The k-th dial (0-based) gets locals[k%len(locals)].
func withDialSeams15073(t *testing.T, locals []string) (*atomic.Int64, func() []*renumberConn) {
	t.Helper()
	var dialCount atomic.Int64
	var mu sync.Mutex
	var made []*renumberConn
	origCtx := dialUDPContext
	origResolved := dialUDPResolvedContext
	origResolveCtx := resolveUDPAddrContext
	dialUDPContext = func(_ context.Context, _ string, _ *net.UDPAddr, _ string) (net.Conn, error) {
		n := dialCount.Add(1) - 1
		nc := &renumberConn{local: locals[int(n)%len(locals)]}
		mu.Lock()
		made = append(made, nc)
		mu.Unlock()
		return nc, nil
	}
	dialUDPResolvedContext = func(_ context.Context, _ string, _, _ *net.UDPAddr) (net.Conn, error) {
		return dialUDPContext(context.Background(), "udp", nil, "")
	}
	resolveUDPAddrContext = func(_ context.Context, _, address string) (*net.UDPAddr, error) {
		return net.ResolveUDPAddr("udp", address)
	}
	t.Cleanup(func() {
		dialUDPContext, dialUDPResolvedContext, resolveUDPAddrContext = origCtx, origResolved, origResolveCtx
	})
	return &dialCount, func() []*renumberConn {
		mu.Lock()
		defer mu.Unlock()
		return append([]*renumberConn(nil), made...)
	}
}

func newRedialTestConns(cc *collectorConn) *collectorConns {
	return &collectorConns{conns: []*collectorConn{cc}}
}

// TestCollectorRedial_WriteFailureRedials15073 is the #15073 RED/GREEN
// guard for the IPv4 leg: a proven-healthy collector socket whose implicit
// source was renumbered away fails its next write; writeAll must re-dial
// (re-resolving and re-picking the live source S2) and deliver THIS packet
// from S2 on the same flush, instead of parking the collector on the dead
// socket until a daemon restart.
//
// RED on base: writeAll only marks the collector unhealthy and retries the
// same conn — the dial count stays 1, the collector reads unhealthy, and
// writeAll reports no success.
func TestCollectorRedial_WriteFailureRedials15073(t *testing.T) {
	origProbe := unhealthyProbeInterval
	unhealthyProbeInterval = 30 * time.Second
	t.Cleanup(func() { unhealthyProbeInterval = origProbe })
	origGrace := staleSourceGrace
	staleSourceGrace = 0
	t.Cleanup(func() { staleSourceGrace = origGrace })

	// S1 assigned at dial time, removed by renumbering; only S2 assigned now.
	withLocalAddrs(t, assignedAddrs("192.0.2.2"))
	dials, made := withDialSeams15073(t, []string{"192.0.2.1:40001", "192.0.2.2:40002"})

	cc, err := dialCollectors([]CollectorConfig{{Address: "192.0.2.99:2055"}})
	if err != nil {
		t.Fatalf("dialCollectors: %v", err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials after build = %d, want 1", got)
	}
	oldConn := made()[0]
	oldConn.setErr(errors.New("write udp 192.0.2.1:40001->192.0.2.99:2055: sendto: cannot assign requested address"))

	if ok := cc.writeAll([]byte("pkt"), "send"); !ok {
		t.Fatal("writeAll = false after renumbering; want redial + delivery from S2 on the same flush (#15073)")
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("dials after failed write = %d, want 2 (one re-dial onto the live source)", got)
	}
	if !oldConn.closed.Load() {
		t.Fatal("old (stale-source) conn was not closed after the re-dial swap")
	}
	if got := made()[1].writes.Load(); got != 1 {
		t.Fatalf("fresh conn writes = %d, want 1 (this packet retried on the new source)", got)
	}
	h := cc.health()
	if len(h) != 1 || !h[0].Healthy {
		t.Fatalf("health after redial = %+v, want the collector healthy on S2", h)
	}
	// Next flush goes straight to the new socket with no extra dial.
	if ok := cc.writeAll([]byte("pkt2"), "send"); !ok {
		t.Fatal("writeAll after redial = false; want steady delivery from S2")
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("dials after steady flush = %d, want 2 (no churn once re-dialed)", got)
	}
	if got := made()[1].writes.Load(); got != 2 {
		t.Fatalf("fresh conn writes after steady flush = %d, want 2", got)
	}
}

// TestCollectorRedial_StaleSourceHealth15073 is the #15073 RED/GREEN guard
// for the IPv6 leg: writes keep succeeding from the removed address, so no
// write ever fails — but health must report the collector unhealthy (its
// source is no longer assigned) instead of the exported-looking healthy
// state, and the next writeAll must re-dial onto the live source and send
// from it.
//
// RED on base: health() returns the stale write state (healthy=true) and
// writeAll never re-dials (dial count stays 1, packet leaves from S1).
func TestCollectorRedial_StaleSourceHealth15073(t *testing.T) {
	origProbe := unhealthyProbeInterval
	unhealthyProbeInterval = 30 * time.Second
	t.Cleanup(func() { unhealthyProbeInterval = origProbe })
	origGrace := staleSourceGrace
	staleSourceGrace = 0
	t.Cleanup(func() { staleSourceGrace = origGrace })

	withLocalAddrs(t, assignedAddrs("2001:db8::2"))
	dials, made := withDialSeams15073(t, []string{"[2001:db8::1]:40001", "[2001:db8::2]:40002"})

	cc, err := dialCollectors([]CollectorConfig{{Address: "[2001:db8::99]:4739"}})
	if err != nil {
		t.Fatalf("dialCollectors: %v", err)
	}
	// Healthy write BEFORE renumbering is modelled: the socket's source
	// is S1 which the view above no longer assigns (renumbered to S2).
	h := cc.health()
	if len(h) != 1 {
		t.Fatalf("health entries = %d, want 1", len(h))
	}
	if h[0].Healthy {
		t.Fatalf("stale-source collector reads healthy (source 2001:db8::1 no longer assigned); health = %+v (#15073 v6 leg)", h[0])
	}
	if h[0].LastError == "" {
		t.Fatal("stale-source health carries no error; want the not-assigned reason surfaced")
	}

	// Next probe cycle re-dials and writes from S2.
	if ok := cc.writeAll([]byte("pkt"), "send"); !ok {
		t.Fatal("writeAll = false; want re-dial onto S2 and delivery (#15073)")
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("dials = %d, want 2 (canary re-dial onto the live source)", got)
	}
	if !made()[0].closed.Load() {
		t.Fatal("stale-source conn not closed after canary re-dial")
	}
	if got := made()[1].writes.Load(); got != 1 {
		t.Fatalf("S2 conn writes = %d, want 1 (packet sent from the new source)", got)
	}
	if h := cc.health(); !h[0].Healthy {
		t.Fatalf("health after canary redial = %+v, want healthy on S2", h[0])
	}
}

// TestCollectorRedial_StillAssignedNoChurn15073 is the adjacent control:
// a collector whose source is STILL assigned must never be re-dialed —
// neither by the canary nor after an ordinary write failure (destination
// unreachable with a live source keeps today's unhealthy+backoff path).
func TestCollectorRedial_StillAssignedNoChurn15073(t *testing.T) {
	origProbe := unhealthyProbeInterval
	unhealthyProbeInterval = 30 * time.Second
	t.Cleanup(func() { unhealthyProbeInterval = origProbe })
	origGrace := staleSourceGrace
	staleSourceGrace = 0
	t.Cleanup(func() { staleSourceGrace = origGrace })

	withLocalAddrs(t, assignedAddrs("192.0.2.1"))
	dials, made := withDialSeams15073(t, []string{"192.0.2.1:40001", "192.0.2.2:40002"})

	cc, err := dialCollectors([]CollectorConfig{{Address: "192.0.2.99:2055"}})
	if err != nil {
		t.Fatalf("dialCollectors: %v", err)
	}
	if ok := cc.writeAll([]byte("a"), "send"); !ok {
		t.Fatal("writeAll = false with a live source; want success")
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1 (no canary churn while source still assigned)", got)
	}
	if h := cc.health(); !h[0].Healthy {
		t.Fatalf("health = %+v, want healthy", h[0])
	}

	// Ordinary failure with the source still assigned: no redial, just
	// the pre-existing unhealthy + backoff behaviour.
	made()[0].setErr(errors.New("write udp: connection refused"))
	if ok := cc.writeAll([]byte("b"), "send"); ok {
		t.Fatal("writeAll = true on a refused write; want false")
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials after live-source failure = %d, want 1 (no redial churn)", got)
	}
	if made()[0].closed.Load() {
		t.Fatal("live-source conn closed on an ordinary failure; want it retained")
	}
	h := cc.health()
	if h[0].Healthy {
		t.Fatalf("health = %+v, want unhealthy after refused write", h[0])
	}
	if h[0].WriteFailures != 1 {
		t.Fatalf("failures = %d, want 1", h[0].WriteFailures)
	}
}

// TestCollectorRedial_RedialFailureParksUnhealthy15073 proves the failure
// side of the recovery: when the re-dial itself fails (destination now
// unresolvable / source still unbindable), the collector parks unhealthy
// with the redial error recorded — it neither spins dialing per flush nor
// reports the stale healthy state — and a later successful probe recovers
// it on the fresh socket.
func TestCollectorRedial_RedialFailureParksUnhealthy15073(t *testing.T) {
	origProbe := unhealthyProbeInterval
	unhealthyProbeInterval = 30 * time.Second
	t.Cleanup(func() { unhealthyProbeInterval = origProbe })
	origGrace := staleSourceGrace
	staleSourceGrace = 0
	t.Cleanup(func() { staleSourceGrace = origGrace })

	withLocalAddrs(t, assignedAddrs("192.0.2.2"))

	var dialCount atomic.Int64
	var dialErr atomic.Value // error
	dialErr.Store(errBox{err: errors.New("dial collector 192.0.2.99:2055: no such host")})
	origCtx := dialUDPContext
	origResolved := dialUDPResolvedContext
	origResolveCtx := resolveUDPAddrContext
	first := &renumberConn{local: "192.0.2.1:40001"}
	second := &renumberConn{local: "192.0.2.2:40002"}
	dialUDPContext = func(_ context.Context, _ string, _ *net.UDPAddr, _ string) (net.Conn, error) {
		n := dialCount.Add(1)
		if n == 1 {
			return first, nil
		}
		if box, _ := dialErr.Load().(errBox); box.err != nil {
			return nil, box.err
		}
		return second, nil
	}
	dialUDPResolvedContext = func(ctx context.Context, network string, laddr, raddr *net.UDPAddr) (net.Conn, error) {
		return dialUDPContext(ctx, network, laddr, raddr.String())
	}
	resolveUDPAddrContext = func(_ context.Context, _, address string) (*net.UDPAddr, error) {
		return net.ResolveUDPAddr("udp", address)
	}
	t.Cleanup(func() {
		dialUDPContext, dialUDPResolvedContext, resolveUDPAddrContext = origCtx, origResolved, origResolveCtx
	})

	cc, err := dialCollectors([]CollectorConfig{{Address: "192.0.2.99:2055"}})
	if err != nil {
		t.Fatalf("dialCollectors: %v", err)
	}
	// Canary: healthy but stale -> re-dial fails -> parked unhealthy.
	cc.writeAll([]byte("a"), "send")
	h := cc.health()
	if h[0].Healthy {
		t.Fatalf("health = %+v, want unhealthy after failed stale re-dial", h[0])
	}
	if h[0].LastError == "" {
		t.Fatal("failed re-dial left no LastError; want the dial error recorded")
	}
	dialsAfterPark := dialCount.Load()
	// Inside the backoff window: skipped, no dial spin.
	cc.writeAll([]byte("b"), "send")
	cc.writeAll([]byte("c"), "send")
	if got := dialCount.Load(); got != dialsAfterPark {
		t.Fatalf("dials spun during backoff: %d -> %d, want parked", dialsAfterPark, got)
	}
	if h := cc.health(); h[0].WriteSkipped != 3 {
		t.Fatalf("skipped = %d, want 3 (initial park write plus parked probes)", h[0].WriteSkipped)
	}

	// Backoff elapses and the dial recovers: probe re-dials onto S2,
	// the write lands, and the collector is healthy again.
	dialErr.Store(errBox{})
	cc.conns[0].mu.Lock()
	cc.conns[0].nextRetryAt = time.Now().Add(-time.Second)
	cc.conns[0].dialedAt = time.Now().Add(-3 * time.Minute)
	cc.conns[0].mu.Unlock()
	if ok := cc.writeAll([]byte("d"), "send"); !ok {
		t.Fatal("writeAll = false after dial recovery; want delivery from S2")
	}
	if dialCount.Load() < 2 {
		t.Fatalf("dials = %d, want >=2 (build + recovery dial)", dialCount.Load())
	}
	h2 := cc.health()
	if h2[0].WriteAttempts == 0 {
		t.Fatalf("health after recovery = %+v, want the recovered probe attempted", h2[0])
	}
}

// TestCollectorRedial_SourceBoundCollector15073 proves the re-dial keeps
// the configured source bind: a source-bound collector re-dials through
// the resolved (source,destination) path with its pinned source, not the
// OS-selected path.
func TestCollectorRedial_SourceBoundCollector15073(t *testing.T) {
	origProbe := unhealthyProbeInterval
	unhealthyProbeInterval = 0
	t.Cleanup(func() { unhealthyProbeInterval = origProbe })

	withLocalAddrs(t, assignedAddrs("127.0.0.1"))

	cc, err := dialCollectors([]CollectorConfig{
		{Address: "127.0.0.1:2055", SourceAddress: "127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("dialCollectors source-bound: %v", err)
	}
	defer cc.close()
	h := cc.health()
	if len(h) != 1 || h[0].SourceAddress != "127.0.0.1" {
		t.Fatalf("health = %+v, want source-bound 127.0.0.1", h)
	}
	if ok := cc.writeAll([]byte("pkt"), "send"); !ok {
		t.Fatal("writeAll = false for a live source-bound collector; want success")
	}
	if h := cc.health(); !h[0].Healthy {
		t.Fatalf("health = %+v, want healthy", h[0])
	}
}
