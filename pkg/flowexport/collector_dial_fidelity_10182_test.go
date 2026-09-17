package flowexport

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// TestDialCollectors_SourceBoundDestResolveKeepsTaxonomy10182 pins the
// ORIGINAL error taxonomy for the source-bound branch: a destination DNS
// failure must surface as `resolve collector <addr>` (as before #9913), not
// as `dial collector <addr>`. The merged #9913 code passes c.Address
// directly to DialContext, so the failure takes the dial wrap path.
func TestDialCollectors_SourceBoundDestResolveKeepsTaxonomy10182(t *testing.T) {
	sentinel := errors.New("bad destination DNS 10182")
	resolve := func(_ string, addr string) (*net.UDPAddr, error) {
		if strings.HasPrefix(addr, "192.0.2.99") {
			return nil, sentinel
		}
		return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 2055}, nil
	}
	dialed := false
	dial := func(_ string, _ *net.UDPAddr, _ *net.UDPAddr) (net.Conn, error) {
		dialed = true
		return nil, errors.New("dial should not be reached")
	}

	withSeams(t, resolve, dial, func() {
		conns, err := dialCollectors([]CollectorConfig{
			{Address: "192.0.2.99:2055", SourceAddress: "192.0.2.1"},
		})
		if err == nil {
			t.Fatal("expected destination resolve error, got nil")
		}
		if !errors.Is(err, sentinel) {
			t.Fatalf("expected wrapped sentinel error, got %v", err)
		}
		if conns != nil {
			t.Fatalf("expected nil conns on resolve failure, got %v", conns)
		}
		if dialed {
			t.Fatal("dial must not be attempted when destination resolve fails")
		}
		if !strings.HasPrefix(err.Error(), "resolve collector 192.0.2.99:2055:") {
			t.Fatalf("error taxonomy = %q, want `resolve collector 192.0.2.99:2055:` prefix (got dial wrap = source-bound fidelity regression)", err.Error())
		}
		if strings.Contains(err.Error(), "dial collector") {
			t.Fatalf("error taxonomy = %q, must not contain `dial collector` for a destination resolve failure", err.Error())
		}
	})
}

// TestDialCollectors_SourceBoundDialsResolvedAddress10182 pins single-address
// selection for the source-bound branch: the destination must be resolved
// explicitly and the dial must receive the resolved IP literal, not the
// original hostname (which would let DialContext try every DNS candidate).
func TestDialCollectors_SourceBoundDialsResolvedAddress10182(t *testing.T) {
	origResolve, origDial, origStringDial := resolveUDPAddrContext, dialUDPResolvedContext, dialUDPContext
	t.Cleanup(func() {
		resolveUDPAddrContext, dialUDPResolvedContext, dialUDPContext = origResolve, origDial, origStringDial
	})

	wantRaddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 2055}
	resolveUDPAddrContext = func(_ context.Context, _ string, address string) (*net.UDPAddr, error) {
		if strings.HasSuffix(address, ":0") {
			return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1)}, nil
		}
		return wantRaddr, nil
	}
	var gotCtx context.Context
	var gotRaddr *net.UDPAddr
	var gotLaddr *net.UDPAddr
	dialUDPResolvedContext = func(ctx context.Context, _ string, laddr, raddr *net.UDPAddr) (net.Conn, error) {
		gotCtx, gotRaddr, gotLaddr = ctx, raddr, laddr
		return &fakeConn{}, nil
	}
	// The string dial seam is exclusive to the no-source branch. Failing fast
	// here keeps a source-bound regression off live DNS (no resolver stall).
	dialUDPContext = func(context.Context, string, *net.UDPAddr, string) (net.Conn, error) {
		return nil, errors.New("string dial seam must not be used for a source-bound dial")
	}

	cc, err := dialCollectors([]CollectorConfig{
		{Address: "collector-10182.invalid:2055", SourceAddress: "192.0.2.1"},
	})
	if err != nil {
		t.Fatalf("source-bound dial failed: %v", err)
	}
	defer cc.close()
	if len(cc.conns) != 1 {
		t.Fatalf("opened %d collector connections, want 1", len(cc.conns))
	}
	if gotRaddr == nil || !gotRaddr.IP.Equal(wantRaddr.IP) || gotRaddr.Port != wantRaddr.Port {
		t.Fatalf("source-bound dial raddr = %v, want resolved %v (must not pass original hostname to DialContext fallback)", gotRaddr, wantRaddr)
	}
	if gotLaddr == nil || gotLaddr.IP == nil || !gotLaddr.IP.Equal(net.IPv4(192, 0, 2, 1)) {
		t.Fatalf("source-bound local bind = %v, want 192.0.2.1", gotLaddr)
	}
	if gotCtx == nil {
		t.Fatal("resolved dial seam received nil context, want bounded dial context")
	}
	deadline, ok := gotCtx.Deadline()
	if !ok {
		t.Fatal("resolved dial seam context has no deadline, want collectorDialTimeout bound")
	}
	if remaining := time.Until(deadline); remaining <= 0 || remaining > collectorDialTimeout {
		t.Fatalf("resolved dial deadline in %v, want (0, %v]", remaining, collectorDialTimeout)
	}
}

// TestResolveUDPAddr_PrefersIPv4OverIPv610182 mirrors net's forResolve
// selection: prefer the first IPv4 result unless the hostname has no IPv4
// result, then retain the first IPv6 result.
func TestResolveUDPAddr_PrefersIPv4OverIPv610182(t *testing.T) {
	origLookup := lookupIPAddrContext
	t.Cleanup(func() { lookupIPAddrContext = origLookup })

	tests := []struct {
		name string
		ips  []net.IPAddr
		want net.IP
	}{
		{
			name: "ipv4 preferred over earlier ipv6",
			ips: []net.IPAddr{
				{IP: net.ParseIP("2001:db8::10")},
				{IP: net.ParseIP("192.0.2.10")},
			},
			want: net.IPv4(192, 0, 2, 10),
		},
		{
			name: "ipv6 fallback when no ipv4 result",
			ips: []net.IPAddr{
				{IP: net.ParseIP("2001:db8::20")},
				{IP: net.ParseIP("2001:db8::21")},
			},
			want: net.ParseIP("2001:db8::20"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookupIPAddrContext = func(context.Context, string) ([]net.IPAddr, error) {
				return tt.ips, nil
			}
			got, err := resolveUDPAddrWithContext(context.Background(), "udp", "dual-stack-10182.test:2055")
			if err != nil {
				t.Fatalf("resolve hostname: %v", err)
			}
			if !got.IP.Equal(tt.want) {
				t.Fatalf("resolved IP = %v, want %v", got.IP, tt.want)
			}
		})
	}
}
