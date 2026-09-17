package flowexport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestDialCollectors_SlowResolveReturnsWithinBound9913 is the #9913
// fail-on-revert cell for DNS resolution. The legacy resolver seam deliberately
// sleeps longer than the test timeout; with the fix, the context adapter sees
// cancellation and dialCollectors returns instead of parking the reconcile.
func TestDialCollectors_SlowResolveReturnsWithinBound9913(t *testing.T) {
	origTimeout := collectorDialTimeout
	collectorDialTimeout = 50 * time.Millisecond
	t.Cleanup(func() { collectorDialTimeout = origTimeout })

	slowResolve := func(string, string) (*net.UDPAddr, error) {
		time.Sleep(2 * time.Second)
		return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 2055}, nil
	}
	fastDial := func(string, *net.UDPAddr, *net.UDPAddr) (net.Conn, error) {
		return &fakeConn{}, nil
	}

	withSeams(t, slowResolve, fastDial, func() {
		done := make(chan error, 1)
		go func() {
			_, err := dialCollectors([]CollectorConfig{
				{Address: "192.0.2.10:2055", SourceAddress: "192.0.2.1"},
			})
			done <- err
		}()

		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("slow resolver error = %v, want context deadline", err)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("dialCollectors remained blocked on slow DNS beyond its 50ms context bound")
		}
	})
}

// TestDialCollectors_SlowDialReturnsWithinBound9913 is the corresponding
// socket-dial cell. DNS succeeds, but the dial seam blocks; the same context
// must stop it before the reconcile can remain parked.
func TestDialCollectors_SlowDialReturnsWithinBound9913(t *testing.T) {
	origTimeout := collectorDialTimeout
	collectorDialTimeout = 50 * time.Millisecond
	t.Cleanup(func() { collectorDialTimeout = origTimeout })

	resolve := func(network, address string) (*net.UDPAddr, error) {
		return net.ResolveUDPAddr(network, address)
	}
	slowDial := func(string, *net.UDPAddr, *net.UDPAddr) (net.Conn, error) {
		time.Sleep(2 * time.Second)
		return &fakeConn{}, nil
	}

	withSeams(t, resolve, slowDial, func() {
		done := make(chan error, 1)
		go func() {
			_, err := dialCollectors([]CollectorConfig{{Address: "127.0.0.1:2055"}})
			done <- err
		}()

		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("slow dial error = %v, want context deadline", err)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("dialCollectors remained blocked on slow dial beyond its 50ms context bound")
		}
	})
}

// TestDialCollectors_NormalResolveUnaffected9913 guards the ordinary path:
// context-aware resolution of a literal destination still opens one UDP
// connection and preserves the existing health/teardown setup.
func TestDialCollectors_NormalResolveUnaffected9913(t *testing.T) {
	resolve := func(network, address string) (*net.UDPAddr, error) {
		return net.ResolveUDPAddr(network, address)
	}
	dial := func(string, *net.UDPAddr, *net.UDPAddr) (net.Conn, error) {
		return &fakeConn{}, nil
	}

	withSeams(t, resolve, dial, func() {
		cc, err := dialCollectors([]CollectorConfig{{Address: "127.0.0.1:2055"}})
		if err != nil {
			t.Fatalf("normal collector resolve failed: %v", err)
		}
		if len(cc.conns) != 1 {
			t.Fatalf("opened %d collector connections, want 1", len(cc.conns))
		}
		cc.close()
	})
}

// TestDialCollectors_NormalHostnameResolveUnaffected9913 exercises the real
// context-aware resolver rather than the legacy test seam. localhost is a
// stable local name and UDP connect does not require a listener.
func TestDialCollectors_NormalHostnameResolveUnaffected9913(t *testing.T) {
	cc, err := dialCollectors([]CollectorConfig{{Address: "localhost:2055"}})
	if err != nil {
		t.Fatalf("normal hostname resolve failed: %v", err)
	}
	if len(cc.conns) != 1 {
		t.Fatalf("opened %d collector connections, want 1", len(cc.conns))
	}
	cc.close()
}
