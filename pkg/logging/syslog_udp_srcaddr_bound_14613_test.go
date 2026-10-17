package logging

// #14613: with a source-address, dialUDP resolved the collector hostname
// with net.ResolveUDPAddr + net.DialUDP — no context, no deadline — while
// the no-source branch used the 5 s Dialer from #9326. During a DNS outage
// the source branch stalls for resolver timeout x attempts x servers on
// every apply (both system syslog and security-log streams rebuild UDP
// clients on the commit path).
//
// The decisive check is structural, not wall-clock against real DNS:
// a package-level lookup seam that blocks until its context is cancelled
// proves the bound exists iff dialUDP returns promptly with a deadline
// error. RED evidence: with the fix's dialUDP source branch reverted to
// the net.ResolveUDPAddr + net.DialUDP pair (seam still present), the
// seam is never consulted — the blocking-resolver cells fail because the
// error does not wrap context.DeadlineExceeded, and the hostname control
// fails because resolution bypasses the seam and hits real DNS. That
// revert is exactly the defect. (Against a seam-less origin/master the
// file does not compile — undefined lookupSyslogIPAddr — which is the
// other RED form.)
import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// blockingLookup14613 returns only when ctx is cancelled — the shape of a
// black-holed resolver from the caller's point of view.
func blockingLookup14613(ctx context.Context, host string) ([]net.IPAddr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestUDPSourceAddrResolveBounded14613(t *testing.T) {
	origLookup := lookupSyslogIPAddr
	origTimeout := syslogDialTimeout
	lookupSyslogIPAddr = blockingLookup14613
	syslogDialTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		lookupSyslogIPAddr = origLookup
		syslogDialTimeout = origTimeout
	})

	// Watchdog: without a bound this blocks forever (the seam only
	// unblocks on ctx cancel, and nothing cancels). The goroutine leak
	// on failure is acceptable — the test has already failed, and the
	// process exits with it.
	done := make(chan error, 1)
	go func() {
		c := &SyslogClient{
			remoteAddr:        "collector-14613.invalid:514",
			sourceAddr:        "127.0.0.1",
			protocol:          "udp",
			writeTimeout:      defaultWriteTimeout,
			reconnectCooldown: defaultReconnectCooldown,
		}
		_, err := c.dialUDP()
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("#14613: source-address UDP dial to an unresolvable host " +
				"succeeded — the blocking resolver seam was not consulted or " +
				"its cancellation was swallowed")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("#14613: source-address UDP dial error = %v, want it to "+
				"wrap context.DeadlineExceeded (the 5 s bound firing)", err)
		}
		if !strings.Contains(err.Error(), "resolve remote") {
			t.Fatalf("#14613: error = %q, want the existing \"resolve remote\" "+
				"taxonomy preserved", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("#14613: source-address UDP dial did not return within 5 s " +
			"against a black-holed resolver — the #9326 bound does not cover " +
			"the source-address branch (net.ResolveUDPAddr/DialUDP carry " +
			"no deadline)")
	}
}

// The source bind itself must stay bounded and keep its taxonomy: a
// hostname-shaped source is impossible via the strict schema (IP literal
// only), but the tolerant load path can hand dialUDP anything, and its
// resolution must not be the unbounded one either.
func TestUDPSourceAddrSourceResolveBounded14613(t *testing.T) {
	origLookup := lookupSyslogIPAddr
	origTimeout := syslogDialTimeout
	lookupSyslogIPAddr = blockingLookup14613
	syslogDialTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		lookupSyslogIPAddr = origLookup
		syslogDialTimeout = origTimeout
	})

	done := make(chan error, 1)
	go func() {
		c := &SyslogClient{
			remoteAddr:        "127.0.0.1:514",
			sourceAddr:        "source-14613.invalid",
			protocol:          "udp",
			writeTimeout:      defaultWriteTimeout,
			reconnectCooldown: defaultReconnectCooldown,
		}
		_, err := c.dialUDP()
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("#14613: UDP dial with an unresolvable source host " +
				"succeeded — the source resolution was not bounded/consulted")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("#14613: source resolve error = %v, want wrap of "+
				"context.DeadlineExceeded", err)
		}
		if !strings.Contains(err.Error(), "resolve source") {
			t.Fatalf("#14613: error = %q, want \"resolve source\" taxonomy", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("#14613: source-address resolution did not return within " +
			"5 s against a black-holed resolver")
	}
}

// Control: the no-source branch was already bounded by #9326 and must stay
// that way — and the common source-bound case (IP literals both sides)
// must still construct a usable client with the source actually bound.
func TestUDPSourceAddrLiteralStillBinds14613(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().(*net.UDPAddr)

	c, err := NewSyslogClientTransport("127.0.0.1", addr.Port, "127.0.0.1", "udp", nil)
	if err != nil {
		t.Fatalf("#14613: source-bound UDP client to a literal collector "+
			"must construct; got %v", err)
	}
	defer c.Close()
	if got := c.SourceAddr(); got != "127.0.0.1" {
		t.Fatalf("SourceAddr = %q, want 127.0.0.1", got)
	}
	conn := c.loadConn()
	if conn == nil {
		t.Fatal("#14613: source-bound UDP client has no connection")
	}
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || !la.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("#14613: bound local addr = %v, want 127.0.0.1 source bind", conn.LocalAddr())
	}
	// The bound socket must actually deliver to the collector.
	if err := c.Send(SyslogInfo, "source-bound-14613"); err != nil {
		t.Fatalf("send over source-bound UDP client: %v", err)
	}
	buf := make([]byte, 2048)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("collector received nothing over the source-bound socket: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "source-bound-14613") {
		t.Fatalf("collector got %q, want the sent record", buf[:n])
	}
}

// Control: hostname resolution that SUCCEEDS still dials the resolved
// address (single-address selection, mirroring flowexport #10182) — the
// bound must not break the normal hostname path.
func TestUDPSourceAddrHostnameResolvesAndDials14613(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	origLookup := lookupSyslogIPAddr
	lookupSyslogIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "collector-14613.example" {
			return nil, &net.DNSError{Err: "unexpected host " + host, Name: host}
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	t.Cleanup(func() { lookupSyslogIPAddr = origLookup })

	c := &SyslogClient{
		hostname:          "xpf",
		remoteAddr:        net.JoinHostPort("collector-14613.example", fmt.Sprintf("%d", port)),
		sourceAddr:        "127.0.0.1",
		protocol:          "udp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
	}
	conn, err := c.dialUDP()
	if err != nil {
		t.Fatalf("#14613: hostname collector with source-address must dial "+
			"after bounded resolution; got %v", err)
	}
	defer conn.Close()
	ra, ok := conn.RemoteAddr().(*net.UDPAddr)
	if !ok || !ra.IP.Equal(net.ParseIP("127.0.0.1")) || ra.Port != port {
		t.Fatalf("#14613: dialed remote = %v, want resolved 127.0.0.1:%d", conn.RemoteAddr(), port)
	}
}
