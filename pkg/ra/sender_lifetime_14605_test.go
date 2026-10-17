package ra

import (
	"testing"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

// #14605 — the unset Router Lifetime must derive from the effective
// MaxRtrAdvInterval as min(3*max, 9000) per RFC 4861 §6.2.1, and
// inherited RDNSS/PREF64 lifetimes must be at least that floor
// (RFC 8106 §5.1: RDNSS SHOULD by default be >= 3*MaxRtrAdvInterval).
// RED on revert: restore the fixed 1800s unset default / raw optLifetime
// inheritance and the max=1800 rows decode RouterLifetime 1800s with an
// equal (single-interval) lifetime instead of 5400s.

func wireLifetimes14605(t *testing.T, cfg *config.RAInterfaceConfig) (router, rdnss, pref64 time.Duration) {
	t.Helper()
	cfg.Interface = "trust0"
	cfg.DNSServers = []string{"2001:db8::53"}
	cfg.NAT64Prefix = "64:ff9b::/96"
	s := newTestSender3895(cfg)
	ra := s.buildRA()
	wire, err := ndp.MarshalMessage(ra)
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	msg, err := ndp.ParseMessage(wire)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	decoded, ok := msg.(*ndp.RouterAdvertisement)
	if !ok {
		t.Fatalf("ParseMessage returned %T, want *ndp.RouterAdvertisement", msg)
	}
	router = decoded.RouterLifetime
	for _, opt := range decoded.Options {
		switch o := opt.(type) {
		case *ndp.RecursiveDNSServer:
			rdnss = o.Lifetime
		case *ndp.PREF64:
			pref64 = o.Lifetime
		}
	}
	if rdnss == 0 && pref64 == 0 {
		t.Fatal("RDNSS/PREF64 options missing from wire")
	}
	return router, rdnss, pref64
}

func TestBuildRA_14605_UnsetLifetimeDerivesFromMaxAdv(t *testing.T) {
	for _, tc := range []struct {
		maxAdv int
		want   time.Duration
	}{
		{0, 1800 * time.Second},    // default max 600 -> 3*600
		{600, 1800 * time.Second},  // canonical, unchanged
		{1800, 5400 * time.Second}, // was 1800 (== one interval, no loss tolerance)
	} {
		router, rdnss, pref64 := wireLifetimes14605(t, &config.RAInterfaceConfig{MaxAdvInterval: tc.maxAdv})
		if router != tc.want {
			t.Errorf("maxAdv=%d: RouterLifetime=%v, want %v (min(3*max,9000))", tc.maxAdv, router, tc.want)
		}
		if rdnss != tc.want {
			t.Errorf("maxAdv=%d: RDNSS lifetime=%v, want %v (>= 3*max per RFC 8106)", tc.maxAdv, rdnss, tc.want)
		}
		if pref64 != tc.want {
			t.Errorf("maxAdv=%d: PREF64 lifetime=%v, want %v", tc.maxAdv, pref64, tc.want)
		}
	}
	// PREF64 is quantized up to 8s (#12653), so a 3*4=12s floor wires as 16s.
	router, rdnss, pref64 := wireLifetimes14605(t, &config.RAInterfaceConfig{MaxAdvInterval: 4})
	if router != 12*time.Second || rdnss != 12*time.Second || pref64 != 16*time.Second {
		t.Errorf("maxAdv=4: router=%v RDNSS=%v PREF64=%v, want 12s/12s/16s (PREF64 ceil to 8s)", router, rdnss, pref64)
	}
}

func TestBuildRA_14605_ExplicitLifetimeAndInheritedFloor(t *testing.T) {
	// Explicit 0 keeps declining default-router duty, but RDNSS/PREF64
	// inherit the derived floor so DNS/NAT64 do not flap (#4119 + #14605).
	router, rdnss, pref64 := wireLifetimes14605(t, &config.RAInterfaceConfig{
		MaxAdvInterval: 1800, DefaultLifetime: 0, DefaultLifetimeSet: true,
	})
	if router != 0 {
		t.Errorf("explicit 0: RouterLifetime=%v, want 0", router)
	}
	if rdnss != 5400*time.Second || pref64 != 5400*time.Second {
		t.Errorf("explicit 0 max=1800: RDNSS=%v PREF64=%v, want 5400s floor", rdnss, pref64)
	}

	// Explicit legal lifetime >= floor is inherited verbatim.
	router, rdnss, pref64 = wireLifetimes14605(t, &config.RAInterfaceConfig{
		MaxAdvInterval: 600, DefaultLifetime: 9000, DefaultLifetimeSet: true,
	})
	if router != 9000*time.Second || rdnss != 9000*time.Second || pref64 != 9000*time.Second {
		t.Errorf("explicit 9000: router=%v RDNSS=%v PREF64=%v, want 9000s", router, rdnss, pref64)
	}

	// Tolerant-ingress-only shape (strict commit rejects it): a short
	// explicit router lifetime still reaches the wire verbatim, but the
	// inherited options stay at the 3*max floor instead of expiring
	// between RAs.
	router, rdnss, pref64 = wireLifetimes14605(t, &config.RAInterfaceConfig{
		MaxAdvInterval: 600, DefaultLifetime: 10, DefaultLifetimeSet: true,
	})
	if router != 10*time.Second {
		t.Errorf("explicit 10: RouterLifetime=%v, want 10s verbatim", router)
	}
	if rdnss != 1800*time.Second || pref64 != 1800*time.Second {
		t.Errorf("explicit 10 max=600: RDNSS=%v PREF64=%v, want 1800s floor", rdnss, pref64)
	}
}
