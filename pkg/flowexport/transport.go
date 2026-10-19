package flowexport

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// collectorConn is one UDP connection to a single collector plus the
// per-collector write-health state surfaced through status / metrics /
// the show command (#2464). Flow export is forensics/compliance data;
// a collector going unreachable was previously invisible (every failed
// Write was debug-logged and dropped), so the exporter kept counting
// "exported" while the operator got no warning. The counters here make
// that loss observable.
//
// addr is the collector destination ("host:port") used as the label /
// identity in every surface. The atomic counters (attempts / failures)
// are bumped lock-free from the export-flush goroutine; the mutex guards
// the string/time fields and the healthy edge-detect flag so a concurrent
// status reader gets a consistent snapshot (run -race).
type collectorConn struct {
	addr string
	// srcAddr is the local bind (source) address this connection was
	// dialed with ("" = OS-selected). Surfaced in the health snapshot so
	// an operator can tell which source-bound connection failed when two
	// same-family collectors bind distinct sources (#3745).
	srcAddr string

	attempts atomic.Uint64
	failures atomic.Uint64
	// skipped counts writes NOT attempted because the collector is unhealthy
	// and still inside its probe-backoff window (#4423 H07 follow-up). It makes
	// the backoff observable: a persistently-dead collector's skipped count
	// climbs while attempts/failures do not, distinguishing "skipped for
	// backoff" from a real per-flush failure.
	skipped atomic.Uint64

	mu              sync.RWMutex
	conn            net.Conn
	lastError       string
	lastErrorTime   time.Time
	lastFailureTime time.Time
	lastSuccessTime time.Time
	// healthy tracks the last observed reachability so writeAll logs only
	// on the unhealthy<->healthy EDGE, not on every failed (or recovered)
	// write. A collector starts healthy (optimistic): the first failure is
	// the transition that warns. consecFail counts consecutive failures so
	// the recovery edge is unambiguous.
	healthy    bool
	consecFail uint64
	// nextRetryAt is the earliest time writeAll will re-probe this collector
	// after a failed write (#4423 H07 follow-up). While unhealthy and before
	// nextRetryAt the collector is SKIPPED, so a persistently-blocked collector
	// costs one bounded probe per unhealthyProbeInterval instead of a full
	// collectorWriteTimeout stall on every flush. Zero on a healthy collector.
	nextRetryAt time.Time
	// dialedAt is stamped on every (re)dial (#15073): after a renumber
	// drops the old source the canary cannot spot the drop until the
	// stale grace below has elapsed on the current socket.
	dialedAt time.Time
	// stale tracks a parked, known-stale redial failure so health() can
	// report the collector unhealthy while it is dead rather than
	// leaving the stale write state visible (#15073).
	stale bool
}

// localAddrsFn enumerates the host's currently assigned addresses. It is the
// canary seam: tests inject the renumbering view so a write-failure redial and
// a still-assigned check never touch the real interface table (#15073). Nil in
// production selects net.InterfaceAddrs.
var localAddrsFn func() ([]net.Addr, error)

func realLocalAddrs() ([]net.Addr, error) { return net.InterfaceAddrs() }

// staleSourceGrace is the quiet window after a (re)dial during which a
// proven-write failure still redials unconditionally rather than taking the
// cheaper still-assigned check (#15073): most often a renumber drops the old
// source only once the replacement address exists, so an EADDRNOTAVAIL-class
// failure right behind the new bind lands in this grace too.
var staleSourceGrace = 2 * time.Minute

// addrIsAssigned reports whether the IP literal ip (from a dialed socket's
// LocalAddr) is still among the host's assigned addresses. A bare IP with no
// CIDR matches an assigned address whose IP equals it or whose prefix
// contains it.
func addrIsAssigned(ip string) bool {
	addrsFn := localAddrsFn
	if addrsFn == nil {
		addrsFn = realLocalAddrs
	}
	addrs, err := addrsFn()
	if err != nil || len(addrs) == 0 {
		return true // enumeration failure: never churn or mark stale on no data
	}
	needle, err := netip.ParseAddr(ip)
	if err != nil {
		return true
	}
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			if v.IP != nil {
				if addr, ok := netipxFromIP(v.IP); ok && (addr == needle || netip.PrefixFrom(addr, addr.BitLen()).Contains(needle)) {
					return true
				}
				if pfx, err := netip.ParsePrefix(v.String()); err == nil && pfx.Contains(needle) {
					return true
				}
			}
		case *net.IPAddr:
			if v.IP != nil {
				if addr, ok := netipxFromIP(v.IP); ok && addr == needle {
					return true
				}
			}
		}
	}
	return false
}

func netipxFromIP(ip net.IP) (netip.Addr, bool) {
	if ip4 := ip.To4(); ip4 != nil {
		return netip.AddrFrom4([4]byte(ip4)), true
	}
	if ip16 := ip.To16(); ip16 != nil {
		return netip.AddrFrom16([16]byte(ip16)), true
	}
	return netip.Addr{}, false
}

// localAddrOf returns conn.LocalAddr(), recovering the panic a fake conn
// with a nil embedded net.Conn raises so health/write paths never crash on
// a test double (#15073).
func localAddrOf(conn net.Conn) (addr net.Addr) {
	defer func() {
		if recover() != nil {
			addr = nil
		}
	}()
	return conn.LocalAddr()
}

// sourceStale reports whether c's currently dialed source is no longer
// assigned. c.mu must NOT be held. No staleness signal exists while netip
// parsing fails or enumeration yields nothing.
func (c *collectorConn) sourceStale() bool {
	c.mu.RLock()
	stale, dialedAt, conn := c.stale, c.dialedAt, c.conn
	c.mu.RUnlock()
	if stale && !dialedAt.IsZero() && time.Since(dialedAt) < staleSourceGrace {
		return false
	}
	if conn == nil {
		return false
	}
	la := localAddrOf(conn)
	if la == nil {
		return false
	}
	host, _, err := net.SplitHostPort(la.String())
	if err != nil {
		return false
	}
	return !addrIsAssigned(host)
}

// ExporterCollectorHealth is one collector's write-health snapshot
// annotated with the protocol family ("netflow-v9" / "ipfix"), the
// sampling instance, and the template group it belongs to (#2464). It is
// the cross-package shape surfaced through the daemon to the REST status,
// gRPC show, and Prometheus collector. It lives here (not pkg/daemon) so
// pkg/api and pkg/grpcapi — which must not import pkg/daemon — can name
// the return type of the injected accessor callback.
type ExporterCollectorHealth struct {
	Protocol string `json:"protocol"`
	Instance string `json:"instance"`
	Template string `json:"template"`
	Family   string `json:"family"`
	CollectorHealth
}

// CollectorHealth is an immutable snapshot of one collector's write-health
// state, returned by collectorConns.health() and surfaced through the
// status response, Prometheus metrics, and the show command (#2464).
type CollectorHealth struct {
	Address string `json:"address"`
	// SourceAddress is the local bind (source) address this collector's
	// connection was dialed with; empty when the OS selected it. It
	// disambiguates two same-family collectors that bind distinct
	// sources (#3745) so a source-bound connection failure is
	// identifiable in the CLI / REST / Prometheus surfaces.
	SourceAddress string `json:"source_address,omitempty"`
	WriteAttempts uint64 `json:"write_attempts"`
	WriteFailures uint64 `json:"write_failures"`
	// WriteSkipped is the count of writes NOT attempted because the collector
	// was unhealthy and still inside its probe-backoff window (#4423). A
	// climbing value (while attempts/failures hold) is the signal that a dead
	// collector is being skipped rather than re-attempted every flush.
	WriteSkipped    uint64    `json:"write_skipped"`
	Healthy         bool      `json:"healthy"`
	LastError       string    `json:"last_error,omitempty"`
	LastErrorTime   time.Time `json:"last_error_time,omitempty"`
	LastFailureTime time.Time `json:"last_failure_time,omitempty"`
	LastSuccessTime time.Time `json:"last_success_time,omitempty"`
}

// collectorConns owns the set of UDP connections to the configured
// collectors. Both the NetFlow v9 and IPFIX exporters share this
// connection-management code: the dial loop, the per-packet fan-out
// write, and teardown are identical between the two protocols.
type collectorConns struct {
	conns []*collectorConn
}

// Context-aware indirection seams let tests inject resolver and dial failures
// while observing connection teardown without uncancellable production
// goroutines. resolveUDPAddrContext performs bounded lookup;
// dialUDPResolvedContext handles an explicit source/destination pair; and
// dialUDPContext handles the original destination for no-source collectors,
// preserving the standard resolver's candidate-list fallback. The legacy
// dialUDP and resolveUDPAddr seams remain for existing teardown tests.
var (
	dialUDP = func(network string, laddr, raddr *net.UDPAddr) (net.Conn, error) {
		return net.DialUDP(network, laddr, raddr)
	}
	resolveUDPAddr         = net.ResolveUDPAddr
	dialUDPContext         = dialUDPWithContext
	dialUDPResolvedContext = dialUDPResolvedWithContext
	resolveUDPAddrContext  = resolveUDPAddrWithContext
	lookupIPAddrContext    = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return net.DefaultResolver.LookupIPAddr(ctx, host)
	}
)

// collectorDialTimeout bounds each collector's resolve plus dial operation.
// A flow-export reconcile builds exporters while holding its family mutex, so
// a resolver outage must not park the commit indefinitely (#9913). Keep this
// aligned with the syslog transport bound from #9326.
var collectorDialTimeout = 5 * time.Second

// resolveUDPAddrWithContext resolves a UDP endpoint while honoring ctx. The
// standard net.ResolveUDPAddr helper has no context and performs an unbounded
// hostname lookup, so literals take its fast parser path while hostnames use
// Resolver.LookupIPAddr with the caller's deadline.
func resolveUDPAddrWithContext(ctx context.Context, network, address string) (*net.UDPAddr, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return net.ResolveUDPAddr(network, address)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return net.ResolveUDPAddr(network, address)
	}

	ips, err := lookupIPAddrContext(ctx, host)
	if err != nil {
		return nil, err
	}
	candidate, ok := firstResolveIP(network, ips)
	if !ok {
		return nil, fmt.Errorf("lookup %s: no suitable address", host)
	}
	ipHost := candidate.IP.String()
	if candidate.Zone != "" {
		ipHost += "%" + candidate.Zone
	}
	resolved, err := net.ResolveUDPAddr(network, net.JoinHostPort(ipHost, port))
	if err != nil {
		return nil, err
	}
	return resolved, nil
}

// firstResolveIP mirrors net's forResolve selection after family filtering:
// prefer the first address in the requested family, falling back to the first
// result otherwise. Plain UDP/IPv4 resolution prefers IPv4; UDP6 prefers IPv6.
func firstResolveIP(network string, ips []net.IPAddr) (net.IPAddr, bool) {
	if len(ips) == 0 {
		return net.IPAddr{}, false
	}
	wantV6 := len(network) > 0 && network[len(network)-1] == '6'
	for _, ip := range ips {
		isV4 := ip.IP.To4() != nil
		if (wantV6 && !isV4) || (!wantV6 && isV4) {
			return ip, true
		}
	}
	return ips[0], true
}

// dialUDPWithContext opens a UDP connection to an original destination while
// honoring ctx. It is used by collectors without a configured source address,
// so the net package retains its candidate-list fallback.
func dialUDPWithContext(ctx context.Context, network string, laddr *net.UDPAddr, address string) (net.Conn, error) {
	dialer := &net.Dialer{LocalAddr: laddr}
	return dialer.DialContext(ctx, network, address)
}

// dialUDPResolvedWithContext opens a UDP connection to an already-resolved
// destination while honoring ctx. It preserves the source-bound path's prior
// ResolveUDPAddr -> DialUDP behavior and error taxonomy.
func dialUDPResolvedWithContext(ctx context.Context, network string, laddr, raddr *net.UDPAddr) (net.Conn, error) {
	dialer := &net.Dialer{LocalAddr: laddr}
	return dialer.DialContext(ctx, network, raddr.String())
}

// dialCollectors opens a UDP connection to every collector in the list.
// When a collector specifies a SourceAddress the local bind address is
// pinned; otherwise the OS selects it. On any resolve or dial error all
// already opened connections are closed and the error is returned, so a
// partial failure mid-loop never leaks the connections opened before it.
//
// Every collector gets a fresh context with collectorDialTimeout. This keeps
// the existing fatal-on-build-error behavior while making both DNS lookup and
// socket dial finite on the reconcile path (#9913).
func dialCollectors(collectors []CollectorConfig) (*collectorConns, error) {
	cc := &collectorConns{}
	// fail closes every connection opened so far and returns err as-is
	// (call sites wrap err with collector context). Callers
	// must return its result without retaining cc, so no descriptor opened
	// in this loop survives an error return.
	fail := func(err error) (*collectorConns, error) {
		cc.close()
		return nil, err
	}
	for _, c := range collectors {
		now := time.Now()
		conn, err := dialCollector(c)
		if err != nil {
			return fail(err)
		}
		// A collector starts healthy (optimistic) so the FIRST failed write
		// is the unhealthy edge that warns (#2464).
		cc.conns = append(cc.conns, &collectorConn{conn: conn, addr: c.Address, srcAddr: c.SourceAddress, healthy: true, dialedAt: now})
	}
	return cc, nil
}

// dialCollector dials a single collector, source-bound when cfg carries a
// SourceAddress and OS-selected otherwise (#15073). It is the single dial
// path shared by dialCollectors (build) and redialCollector (recovery), so a
// re-dial re-resolves the destination and re-picks the implicit source
// exactly as a fresh build would.
func dialCollector(cfg CollectorConfig) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), collectorDialTimeout)
	defer cancel()
	var conn net.Conn
	var err error
	if cfg.SourceAddress != "" {
		// A misconfigured SourceAddress must be surfaced, not
		// silently dropped to a nil local bind (which would let
		// the OS pick an arbitrary source and mask the
		// misconfiguration). JoinHostPort brackets an IPv6
		// source-address literal so the context-aware resolver can
		// parse it; "addr:0" leaves an IPv6 address unbracketed
		// and unparseable (sibling of #2183).
		laddr, err2 := resolveUDPAddrContext(ctx, "udp", net.JoinHostPort(cfg.SourceAddress, "0"))
		if err2 != nil {
			return nil, fmt.Errorf("resolve collector %s source-address %s: %w", cfg.Address, cfg.SourceAddress, err2)
		}
		raddr, err2 := resolveUDPAddrContext(ctx, "udp", cfg.Address)
		if err2 != nil {
			return nil, fmt.Errorf("resolve collector %s: %w", cfg.Address, err2)
		}
		conn, err = dialUDPResolvedContext(ctx, "udp", laddr, raddr)
	} else {
		// Pass the hostname directly to DialContext so the net
		// package retains its candidate-list fallback behavior.
		conn, err = dialUDPContext(ctx, "udp", nil, cfg.Address)
	}
	if err != nil {
		return nil, fmt.Errorf("dial collector %s: %w", cfg.Address, err)
	}
	return conn, nil
}

// redialCollector re-dials c's collector and swaps the live socket on
// success, closing the old one (#15073). On failure it reports the error and
// leaves the old socket and c.cfg untouched, so the caller can park the
// collector unhealthy and retry at the normal probe cadence. The old socket
// is retired only after the replacement is confirmed usable for a write.
func (c *collectorConn) redialCollector() (net.Conn, error) {
	return dialCollector(CollectorConfig{Address: c.addr, SourceAddress: c.srcAddr})
}

// collectorWriteTimeout BOUNDS how long a single collector write may block
// before it is abandoned as a failure (#4423 H07). writeAll runs in the ONE
// per-exporter Run goroutine that ALSO drives every other collector in the
// group, the periodic template refresh, the 100ms batch flush, and the
// shutdown drain. A connected-UDP Write is normally instantaneous, but it can
// block indefinitely on a full socket send buffer (ENOBUFS / a congested or
// down egress path parks the goroutine in the netpoller until the buffer
// drains). Without a deadline that single blocked write stalls ALL of the
// above INDEFINITELY — the other collectors starve, templates stop refreshing,
// the batch backs up, and ctx-cancel shutdown hangs past the unit
// TimeoutStopSec.
//
// The deadline does NOT eliminate the stall — it caps it: a slow collector can
// still block the shared goroutine by AT MOST collectorWriteTimeout per
// ATTEMPTED write (the datagram is then dropped, best-effort UDP, and the
// collector is marked unhealthy #2464). The per-flush steady-state cost of a
// PERSISTENTLY-dead collector is then bounded further by the unhealthyProbe-
// Interval backoff below, which SKIPS an unhealthy collector between probes so
// it does not eat a fresh collectorWriteTimeout on every flush.
//
// A var, not a const, so tests can shrink it. 2s is far above any healthy UDP
// write yet well within the 20s systemd stop timeout even for several hung
// collectors.
var collectorWriteTimeout = 2 * time.Second

// unhealthyProbeInterval is how long a collector that failed a write is SKIPPED
// before writeAll re-probes it (#4423 H07 follow-up). Without this gate a
// persistently-blocked collector (its send buffer stays full) costs a fresh
// collectorWriteTimeout stall on EVERY flush/template-refresh, delaying the
// healthy collectors and the template/flush cadence forever — the deadline
// bounds a SINGLE stall but not the steady-state cost of a dead collector.
// Skipping an unhealthy collector until nextRetryAt drops that steady-state
// cost to one bounded probe per interval (a 2s-bounded write every 30s, not a
// 2s stall every 100ms). A recovered probe resumes normal per-flush writes. A
// var so tests can shrink it.
var unhealthyProbeInterval = 30 * time.Second

// defaultTemplateRefreshRate is the fallback template-refresh cadence used when
// an ExportConfig carries a non-positive TemplateRefreshRate (#4423 M10). The
// production resolver always fills at least 60s, but the public NewExporter /
// NewIPFIXExporter constructors accept any *ExportConfig, and time.NewTicker
// panics on a <= 0 duration.
const defaultTemplateRefreshRate = 60 * time.Second

// templateRefreshInterval clamps a template-refresh rate to a strictly
// positive duration so time.NewTicker never panics on a zero/negative rate
// (#4423 M10). A hand-built ExportConfig (tests, external callers) that left
// TemplateRefreshRate at 0 falls back to the default cadence instead of
// crashing the Run goroutine — and a panic there is fatal (it runs under
// `go e.Run(ctx)`).
func templateRefreshInterval(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultTemplateRefreshRate
	}
	return d
}

// writeAll transmits pkt to every collector connection and records the
// per-collector write-health (#2464). A failure to one collector does
// not stop delivery to the others (the export DATA path is unchanged —
// writes are still attempted to all collectors and failures are still
// non-fatal). It returns true if at least one collector write succeeded,
// so exporters only count a packet as exported when it reached a collector.
// Each write bumps the attempt counter, a success refreshes LastSuccessTime,
// and a failure records LastError/LastErrorTime + the failure counter.
//
// Each attempted write is BOUNDED by collectorWriteTimeout (#4423 H07) so a
// slow or blocked collector stalls the shared export goroutine — which also
// drives the other collectors, the template refresh, the batch flush, and the
// shutdown drain — by at most that timeout per attempt, never indefinitely.
// An already-unhealthy collector is additionally SKIPPED between probes
// (unhealthyProbeInterval), so its steady-state cost is one bounded probe per
// interval rather than a fresh timeout on every flush; skipped writes are
// counted (skipped) for observability.
//
// Logging is RATE-LIMITED to the unhealthy<->healthy EDGE, not every
// write: writeAll runs once per export flush (the v9/IPFIX batch ticker
// fires every 100ms) plus once per template refresh, so a per-write
// slog.Warn would flood the journal for an unreachable collector. The
// project logging rules forbid Warn/Info inside per-tick loops; a
// transition log fires once when a healthy collector starts failing and
// once when it recovers. errMsg disambiguates the protocol/path
// (template vs data) in the debug line kept for deep tracing.
func (cc *collectorConns) writeAll(pkt []byte, errMsg string) bool {
	// #15073: a still-healthy collector whose implicit source was
	// renumbered away keeps succeeding on IPv6 (and counts exported
	// with a dead source on IPv4) because the socket is never
	// re-dialed. Re-dial those canary-stale sockets BEFORE the write
	// fan-out so the write below lands on the live source; a failed
	// re-dial parks the collector unhealthy instead of writing from
	// the removed address. Unhealthy/probing sockets are handled by
	// the write-failure redial below, so the canary stays off them.
	for _, c := range cc.conns {
		c.mu.RLock()
		healthy := c.healthy
		c.mu.RUnlock()
		if !healthy {
			continue
		}
		if !c.sourceStale() {
			continue
		}
		if nc, rerr := c.redialCollector(); rerr != nil {
			now := time.Now()
			c.failures.Add(1)
			c.mu.Lock()
			wasHealthy := c.healthy
			c.healthy = false
			c.stale = true
			c.lastError = rerr.Error()
			c.lastErrorTime = now
			c.lastFailureTime = now
			c.consecFail++
			c.nextRetryAt = now.Add(unhealthyProbeInterval)
			c.mu.Unlock()
			slog.Debug(errMsg, "collector", c.addr, "err", rerr)
			if wasHealthy {
				slog.Warn("flow-export collector stale source; re-dial failed",
					"collector", c.addr, "err", rerr)
			}
		} else {
			c.mu.Lock()
			old := c.conn
			c.conn = nc
			c.dialedAt = time.Now()
			c.mu.Unlock()
			if old != nil {
				_ = old.Close()
			}
			slog.Info("flow-export collector re-dialed after source renumbering",
				"collector", c.addr)
		}
	}
	succeeded := false
	for _, c := range cc.conns {
		// Backoff gate: an unhealthy collector still inside its probe window is
		// SKIPPED, so a persistently-blocked collector does not cost a fresh
		// collectorWriteTimeout stall on every flush (#4423 H07 follow-up).
		c.mu.Lock()
		if !c.healthy && time.Now().Before(c.nextRetryAt) {
			c.mu.Unlock()
			c.skipped.Add(1)
			continue
		}
		c.mu.Unlock()

		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()
		// Bound the write so a full send buffer on one collector cannot park
		// the shared goroutine indefinitely (#4423 H07). A write that trips
		// the deadline returns a timeout error handled by the failure branch
		// below, exactly like any other unreachable-collector error.
		_ = conn.SetWriteDeadline(time.Now().Add(collectorWriteTimeout))
		_, err := conn.Write(pkt)
		c.attempts.Add(1)
		now := time.Now()
		if err != nil {
			// #15073: a write failure on a proven-healthy socket may
			// mean its implicit source was renumbered away (IPv4
			// EADDRNOTAVAIL / ENETUNREACH). Re-dial once — re-resolving
			// the destination and re-picking the live source — and
			// retry this packet on the fresh socket before parking
			// the collector. A collector whose source is still
			// assigned keeps today's behaviour (no churn).
			recovered := false
			c.mu.RLock()
			wasHealthyForRedial := c.healthy
			c.mu.RUnlock()
			if wasHealthyForRedial && c.sourceStale() {
				if nc, rerr := c.redialCollector(); rerr == nil {
					_ = nc.SetWriteDeadline(time.Now().Add(collectorWriteTimeout))
					if _, werr := nc.Write(pkt); werr == nil {
						c.mu.Lock()
						old := c.conn
						c.conn = nc
						c.dialedAt = time.Now()
						c.lastSuccessTime = now
						c.nextRetryAt = time.Time{}
						wasUnhealthy := !c.healthy
						c.healthy = true
						c.stale = false
						c.consecFail = 0
						c.mu.Unlock()
						if old != nil && old != nc {
							_ = old.Close()
						}
						succeeded = true
						recovered = true
						if wasUnhealthy {
							slog.Info("flow-export collector recovered", "collector", c.addr)
						}
					} else {
						_ = nc.Close()
					}
				}
			}
			if recovered {
				continue
			}
			c.failures.Add(1)
			c.mu.Lock()
			c.lastError = err.Error()
			c.lastErrorTime = now
			c.lastFailureTime = now
			c.consecFail++
			// Arm the backoff: skip this collector until the probe interval
			// elapses so the next flushes don't each eat a full timeout.
			c.nextRetryAt = now.Add(unhealthyProbeInterval)
			wasHealthy := c.healthy
			c.healthy = false
			c.mu.Unlock()
			// Keep the per-write debug line for deep tracing; emit a single
			// Warn only on the healthy->unhealthy edge.
			slog.Debug(errMsg, "collector", c.addr, "err", err)
			if wasHealthy {
				slog.Warn("flow-export collector unreachable",
					"collector", c.addr, "err", err)
			}
			continue
		}
		c.mu.Lock()
		c.lastSuccessTime = now
		// A successful (re)probe clears the backoff and resumes per-flush writes.
		c.nextRetryAt = time.Time{}
		wasUnhealthy := !c.healthy
		c.healthy = true
		c.stale = false
		c.consecFail = 0
		succeeded = true
		c.mu.Unlock()
		if wasUnhealthy {
			slog.Info("flow-export collector recovered", "collector", c.addr)
		}
	}
	return succeeded
}

// health returns an immutable snapshot of every collector's write-health
// for the status / metrics / show surfaces (#2464). Safe to call
// concurrently with writeAll.
func (cc *collectorConns) health() []CollectorHealth {
	if cc == nil {
		return nil
	}
	out := make([]CollectorHealth, 0, len(cc.conns))
	for _, c := range cc.conns {
		stale := c.sourceStale()
		c.mu.Lock()
		healthy := c.healthy && !stale
		lastErr := c.lastError
		if stale && lastErr == "" {
			lastErr = "flow-export collector source address no longer assigned"
		}
		out = append(out, CollectorHealth{
			Address:         c.addr,
			SourceAddress:   c.srcAddr,
			WriteAttempts:   c.attempts.Load(),
			WriteFailures:   c.failures.Load(),
			WriteSkipped:    c.skipped.Load(),
			Healthy:         healthy,
			LastError:       lastErr,
			LastErrorTime:   c.lastErrorTime,
			LastFailureTime: c.lastFailureTime,
			LastSuccessTime: c.lastSuccessTime,
		})
		c.mu.Unlock()
	}
	return out
}

// close shuts down all collector connections.
func (cc *collectorConns) close() {
	for _, c := range cc.conns {
		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()
		if conn != nil {
			_ = conn.Close()
		}
	}
}

// defaultFlowBatchCap bounds the number of pending flow records held per
// address family before add() starts dropping (#3747). The batch is drained
// every 100ms by the exporter Run goroutine, so under normal operation the
// depth stays well below this; the cap only bites when the drain is STOPPED
// or STALLED — the reconcile window (Run swapped out), a blocked/slow
// collector write, or a SESSION_CLOSE storm (scan / failover) outrunning the
// 100ms flush. Before #3747 add() appended without bound, so a stalled drain
// let the batch grow with the close-event rate → unbounded memory growth
// (DoS / OOM) with no depth or drop visibility. At the current FlowRecord
// size (~a few hundred bytes with its net.IP backing arrays) this cap bounds
// each family to tens of MB — a bounded, counted drop instead of an OOM.
const defaultFlowBatchCap = 65536

// flowBatch accumulates flow records pending export, split by address
// family. The export loop drains it on a periodic ticker (and on
// shutdown) and hands each non-empty slice to the protocol-specific
// send path. The split is by family, not by zone.
//
// The queue is BOUNDED per family (#3747): add() rejects a record once the
// target family is at capacity and counts the drop, so a stopped/stalled
// drain can no longer grow the batch without bound. dropped / maxDepth are
// atomics so the status/metrics accessors read them without contending on mu.
type flowBatch struct {
	mu sync.Mutex
	v4 []FlowRecord
	v6 []FlowRecord
	// capOverride is the per-family record cap; 0 means defaultFlowBatchCap.
	// Only tests set it (to a small value that makes the drop path reachable).
	capOverride int
	// dropped counts records rejected because the target family batch was at
	// capacity. Monotonic; surfaced through Dropped() for status/CLI/REST and
	// the xpf_flow_export_batch_dropped_total metric (#3747).
	dropped atomic.Uint64
	// maxDepth is the high-water mark of len(v4)+len(v6) observed by add().
	// It captures the worst-case backlog even after a later drain empties the
	// queue, so a transient stall is still visible after the fact (#3747).
	maxDepth atomic.Uint64

	// --- #4963 admission lease ---
	// The session-close callback loads the live exporter bundle then calls
	// ExportSessionClose -> add() on each group's exporter. A reconcile that
	// publishes a new bundle, cancels the old exporter's Run (which does its
	// FINAL flushBatches on ctx cancel and returns), and closes it can race a
	// callback that loaded the OLD bundle just before the swap: that late add()
	// would append into a batch nothing will ever drain again, silently
	// stranding a session-close record while every queue/collector metric looks
	// healthy. #3742 closed only the publish-before-teardown window; this is the
	// loaded-old-bundle residual.
	//
	// retired flips true when the owning exporter's generation is being torn
	// down (bundle already swapped/emptied, final flush imminent). inflight
	// counts add() calls that passed the retired gate. retire() sets retired
	// then spins until inflight drains, so a record admitted BEFORE the final
	// flush is guaranteed to still be in the batch that flush drains. A record
	// offered AFTER retire flips is rejected and counted (handoffDropped, plus
	// the injected fixed-cardinality sharedHandoff) instead of being silently
	// stranded. Allocation-free: plain atomics, no per-call allocation, and the
	// drain spin runs only on the rare day-2 reconcile teardown path.
	retired        atomic.Bool
	inflight       atomic.Int64
	handoffDropped atomic.Uint64
	// sharedHandoff, when injected by the daemon (SetHandoffCounter), is a
	// single family-level counter every exporter of a family increments on a
	// handoff reject, so drops on an exporter that has already left the live
	// bundle stay observable at fixed cardinality (one counter per family, not
	// one per retired-and-discarded exporter). Nil on a bare/zero-value batch.
	sharedHandoff *atomic.Uint64
	// inflightHook, when set (tests only), runs while an admitted add() holds
	// the lease. It exists to deterministically exercise the retire() drain
	// wait — production never sets it.
	inflightHook func()
	// maxDepthHook, when set (tests only), runs inside the high-water CAS loop
	// after each maxDepth.Load() and before the CompareAndSwap, receiving the
	// depth this add() observed. It exists to deterministically interleave two
	// concurrent updaters at the load-then-store window and prove the CAS-max
	// keeps the mark monotonic (#5048) — production never sets it.
	maxDepthHook func(depth uint64)
}

// batchCap returns the effective per-family record cap.
func (b *flowBatch) batchCap() int {
	if b.capOverride > 0 {
		return b.capOverride
	}
	return defaultFlowBatchCap
}

// add queues a record into the appropriate per-family batch. When the target
// family is already at capacity the record is DROPPED (drop-newest) and the
// dropped counter is incremented rather than growing the batch without bound
// (#3747).
//
// Drop-newest (reject the incoming record) is chosen over drop-oldest
// deliberately: it is O(1) with no slice shift or reallocation churn under
// sustained overflow, it never blocks the caller, and it leaves the happy
// path (below cap) a plain append — unchanged. The flow-close callback that
// calls add() runs on the event-reader path, so it MUST NOT block: dropping a
// record is strictly preferable to backpressuring into the session reap/close
// path. Which end is dropped barely matters for forensic value in a close
// storm (all closes are near-contemporaneous); O(1) non-blocking does.
func (b *flowBatch) add(fr FlowRecord) {
	// #4963 admission lease. Increment inflight BEFORE reading retired so
	// retire()'s drain can never slip between the gate check and the append:
	// if this add() observes retired==false it was sequenced before
	// retire()'s Store(true) (sync/atomic total order), therefore its inflight
	// increment is visible to retire()'s drain loop, which then waits for the
	// matching decrement below — so the record is guaranteed to be in the batch
	// the final flush drains. If retired is already set, reject the record and
	// count it (locally + on the injected family counter) rather than appending
	// it into a batch that will never be drained again.
	b.inflight.Add(1)
	if b.retired.Load() {
		b.inflight.Add(-1)
		b.handoffDropped.Add(1)
		if b.sharedHandoff != nil {
			b.sharedHandoff.Add(1)
		}
		return
	}
	defer b.inflight.Add(-1)
	if b.inflightHook != nil {
		b.inflightHook()
	}

	capN := b.batchCap()
	b.mu.Lock()
	dst := &b.v4
	if fr.IsIPv6 {
		dst = &b.v6
	}
	if len(*dst) >= capN {
		b.mu.Unlock()
		b.dropped.Add(1)
		return
	}
	*dst = append(*dst, fr)
	depth := uint64(len(b.v4) + len(b.v6))
	b.mu.Unlock()
	// Publish the high-water mark with a lock-free CAS-max loop. The mu
	// section above serializes the append, but this update runs OUTSIDE mu
	// (like the dropped/handoffDropped atomics), so a plain load-then-store
	// would race a concurrent adder: if A computes depth 1 and B computes
	// depth 2, both load an older value and B's store of 2 can be clobbered
	// by A's later store of 1, regressing the published maximum. CompareAndSwap
	// makes each update an atomic max(old, observed): retry until either our
	// value is no longer the larger one or the swap from the value we read
	// succeeds, so the mark is monotonic and never regresses (#5048).
	for {
		cur := b.maxDepth.Load()
		if b.maxDepthHook != nil {
			b.maxDepthHook(depth)
		}
		if depth <= cur || b.maxDepth.CompareAndSwap(cur, depth) {
			break
		}
	}
}

// retire flips the batch to the retired state and blocks until every add()
// that had already acquired the admission lease has finished, so a record
// admitted before the owning exporter's final flush is guaranteed to be drained
// by that flush (#4963). Records offered after retire returns are rejected and
// counted (handoffDropped / the injected family counter). Allocation-free: a
// bounded spin on the atomic inflight counter, drained in microseconds by the
// short add() critical section, only on the rare day-2 reconcile teardown path.
// One-way and idempotent — retired exporters are always discarded, never reused.
func (b *flowBatch) retire() {
	b.retired.Store(true)
	for b.inflight.Load() != 0 {
		runtime.Gosched()
	}
}

// setSharedHandoff injects the fixed-cardinality family-level handoff-drop
// counter (#4963). Called once at exporter construction, before Run starts, so
// it never races add().
func (b *flowBatch) setSharedHandoff(c *atomic.Uint64) { b.sharedHandoff = c }

// HandoffDropped returns the cumulative count of session-close records this
// batch rejected because they arrived after the owning exporter was retired
// (#4963) — records that would otherwise have been silently stranded.
func (b *flowBatch) HandoffDropped() uint64 { return b.handoffDropped.Load() }

// drain atomically removes and returns the accumulated v4 and v6
// records, resetting both batches to empty.
func (b *flowBatch) drain() (v4, v6 []FlowRecord) {
	b.mu.Lock()
	v4 = b.v4
	v6 = b.v6
	b.v4 = nil
	b.v6 = nil
	b.mu.Unlock()
	return v4, v6
}

// depth returns the current number of records pending across both families.
func (b *flowBatch) depth() uint64 {
	b.mu.Lock()
	d := uint64(len(b.v4) + len(b.v6))
	b.mu.Unlock()
	return d
}

// Dropped returns the cumulative count of records dropped because a family
// batch was at capacity (#3747).
func (b *flowBatch) Dropped() uint64 { return b.dropped.Load() }

// MaxDepth returns the high-water mark of the combined pending depth (#3747).
func (b *flowBatch) MaxDepth() uint64 { return b.maxDepth.Load() }

// ExporterBatchStats is one exporter's pending-batch queue stats (#3747),
// annotated with the protocol family, sampling instance, and template group
// it belongs to — the same identity the per-collector health snapshot carries
// (#2464). It is the cross-package shape surfaced through the daemon to REST
// status, gRPC show, and the Prometheus collector so an operator can see the
// export backlog depth and any dropped records. It lives here (not pkg/daemon)
// so pkg/api and pkg/grpcapi — which must not import pkg/daemon — can name the
// return type of the injected accessor callback.
type ExporterBatchStats struct {
	Protocol string `json:"protocol"`
	Instance string `json:"instance"`
	Template string `json:"template"`
	Family   string `json:"family"`
	// Depth is the current combined (v4+v6) pending record count.
	Depth uint64 `json:"depth"`
	// MaxDepth is the high-water mark of the combined pending depth.
	MaxDepth uint64 `json:"max_depth"`
	// Dropped is the cumulative count of records dropped at capacity.
	Dropped uint64 `json:"dropped"`
	// ExportedFlows and ExportedPackets count successfully written flow records
	// and data datagrams, excluding template refreshes (#13304).
	ExportedFlows   uint64 `json:"exported_flows"`
	ExportedPackets uint64 `json:"exported_packets"`
	// HandoffDropped is the cumulative count of session-close records this
	// exporter rejected because they arrived after it was retired during a
	// reconcile (#4963) — records that would otherwise have been silently
	// stranded in a batch nothing drains. Nonzero only transiently, on the
	// exporter generation being torn down; the fixed family total surfaced by
	// the daemon aggregates the same event across retired-and-discarded
	// exporters.
	HandoffDropped uint64 `json:"handoff_dropped"`
	// Data quality counters for exported records (#13305).
	RouteMaskUnresolved uint64 `json:"route_mask_unresolved"`
	EstimatedDurations  uint64 `json:"estimated_durations"`
	ClockSkewClamped    uint64 `json:"clock_skew_clamped"`
}

// SamplingStatsSnapshot is one sampling instance's exported decision totals.
type SamplingStatsSnapshot struct {
	Protocol     string
	Instance     string
	Evaluated    uint64
	Selected     uint64
	ZoneFiltered uint64
}
