package dhcp

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
)

func TestRunDHCPv6RefreshesRAWhileWaitingForT2_11738(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	gateway := netip.MustParseAddr("fe80::1")
	t1 := make(chan time.Time, 1)
	t1 <- time.Now()
	t2 := make(chan time.Time, 1)
	m := &Manager{
		leases:               map[clientKey]*Lease{},
		delegatedPDs:         map[string][]DelegatedPrefix{},
		v6opts:               map[string]*DHCPv6Options{"wan0": {IATypes: []string{"ia-na"}}},
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
	}
	var afterCalls int
	m.afterForTest = func(time.Duration) <-chan time.Time {
		afterCalls++
		if afterCalls == 1 {
			return t1
		}
		return t2
	}
	var raTimers int
	m.raAfterForTest = func(time.Duration) <-chan time.Time {
		raTimers++
		if raTimers == 2 {
			ready := make(chan time.Time, 1)
			ready <- time.Now()
			return ready
		}
		return make(chan time.Time)
	}
	var samples int
	m.routerAdvertisementsForTest = func(context.Context, string) []observedRouter {
		samples++
		if samples == 1 {
			return []observedRouter{{addr: gateway, lifetime: time.Hour, pref: raPrefMedium}}
		}
		if samples == 2 {
			t2 <- time.Now()
			return []observedRouter{{addr: gateway, lifetime: 0, pref: raPrefMedium}}
		}
		return nil
	}
	var rebound bool
	var gatewayAtRebind netip.Addr
	m.doV6ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, prev *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		switch mode {
		case exchangeAcquire:
			return &dhcpv6Result{lease: raLease(netip.Addr{}, time.Now(), time.Hour)}, nil
		case exchangeRenew:
			return nil, errors.New("simulated T1 failure")
		case exchangeRebind:
			rebound = true
			if prev != nil {
				gatewayAtRebind = prev.Gateway
			}
			cancel()
			return nil, context.Canceled
		default:
			return nil, errors.New("unexpected exchange mode")
		}
	}

	m.runDHCPv6(ctx, "wan0")
	if !rebound {
		t.Fatal("T2 rebind did not run after a failed T1 and periodic RA sample")
	}
	if gatewayAtRebind.IsValid() {
		t.Fatalf("gateway at T2 rebind = %v, want withdrawn by the intervening lifetime-zero RA", gatewayAtRebind)
	}
}
func TestRunDHCPv6RefreshesRADuringHeldLeaseReacquireBackoff_11738(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gateway := netip.MustParseAddr("fe80::1")
	t1 := make(chan time.Time, 1)
	t1 <- time.Now()
	t2 := make(chan time.Time, 1)
	t2 <- time.Now()
	// Reacquisition backoff remains a real one-second production wait.
	m := &Manager{
		leases:               map[clientKey]*Lease{},
		delegatedPDs:         map[string][]DelegatedPrefix{},
		v6opts:               map[string]*DHCPv6Options{"wan0": {IATypes: []string{"ia-na"}}},
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
	}
	var afterCalls int
	m.afterForTest = func(time.Duration) <-chan time.Time {
		afterCalls++
		switch afterCalls {
		case 1:
			return t1
		case 2:
			return t2
		default:
			return make(chan time.Time)
		}
	}
	var raTimers int
	m.raAfterForTest = func(time.Duration) <-chan time.Time {
		raTimers++
		if raTimers == 3 {
			ready := make(chan time.Time, 1)
			ready <- time.Now()
			return ready
		}
		return make(chan time.Time)
	}
	var samples int
	m.routerAdvertisementsForTest = func(context.Context, string) []observedRouter {
		samples++
		if samples == 1 {
			return []observedRouter{{addr: gateway, lifetime: time.Hour, pref: raPrefMedium}}
		}
		if samples == 2 {
			return []observedRouter{{addr: gateway, lifetime: 0, pref: raPrefMedium}}
		}
		return nil
	}
	var acquireAttempts int
	var gatewayAtRetry netip.Addr
	m.doV6ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		switch mode {
		case exchangeAcquire:
			acquireAttempts++
			if acquireAttempts == 1 {
				return &dhcpv6Result{lease: raLease(netip.Addr{}, time.Now(), time.Hour)}, nil
			}
			if acquireAttempts == 2 {
				return nil, errors.New("simulated reacquisition failure")
			}
			m.mu.Lock()
			if held := m.leases[clientKey{iface: "wan0", family: AFInet6}]; held != nil {
				gatewayAtRetry = held.Gateway
			}
			m.mu.Unlock()
			cancel()
			return nil, context.Canceled
		case exchangeRenew, exchangeRebind:
			return nil, errors.New("simulated renewal and rebind failure")
		default:
			return nil, errors.New("unexpected exchange mode")
		}
	}

	m.runDHCPv6(ctx, "wan0")
	if acquireAttempts < 3 {
		t.Fatalf("reacquisition attempts = %d, want next attempt after RA refresh", acquireAttempts)
	}
	if gatewayAtRetry.IsValid() {
		t.Fatalf("held gateway before reacquisition retry = %v, want withdrawn during backoff", gatewayAtRetry)
	}
}

func TestV6ExchangeRejectsResultAfterContextExpiresDuringRA_11738(t *testing.T) {
	for _, tc := range []struct {
		name        string
		want        error
		prepare     func() (context.Context, context.CancelFunc)
		endSampling func(context.Context, context.CancelFunc)
	}{
		{
			name: "caller cancellation",
			want: context.Canceled,
			prepare: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			endSampling: func(_ context.Context, cancel context.CancelFunc) { cancel() },
		},
		{
			name: "lease deadline",
			want: context.DeadlineExceeded,
			prepare: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 20*time.Millisecond)
			},
			endSampling: func(ctx context.Context, _ context.CancelFunc) { <-ctx.Done() },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := tc.prepare()
			defer cancel()
			m := &Manager{
				doV6ExchangeForTest: func(context.Context, string, dhcpExchangeMode, *Lease, []DelegatedPrefix) (*dhcpv6Result, error) {
					return &dhcpv6Result{lease: raLease(netip.Addr{}, time.Now(), time.Hour)}, nil
				},
				routerAdvertisementsForTest: func(ctx context.Context, _ string) []observedRouter {
					tc.endSampling(ctx, cancel)
					return nil
				},
			}
			result, err := m.v6Exchange(ctx, "wan0", exchangeRenew, raLease(netip.Addr{}, time.Now(), time.Hour), nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("v6Exchange() error = %v, want %v (result=%+v)", err, tc.want, result)
			}
		})
	}
}

func TestRunDHCPv6DoesNotCommitExchangeAfterContextCancellation_11738(t *testing.T) {
	tests := []struct {
		name   string
		target dhcpExchangeMode
	}{
		{name: "acquire", target: exchangeAcquire},
		{name: "renew", target: exchangeRenew},
		{name: "rebind", target: exchangeRebind},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			target := tc.target
			m := &Manager{
				leases:               map[clientKey]*Lease{},
				delegatedPDs:         map[string][]DelegatedPrefix{},
				v6opts:               map[string]*DHCPv6Options{"wan0": {IATypes: []string{"ia-na"}}},
				waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
			}
			var timerCalls int
			m.afterForTest = func(time.Duration) <-chan time.Time {
				timerCalls++
				if target != exchangeAcquire && timerCalls == 1 {
					disarmRecompile(m)
				}
				return immediateAfter(0)
			}
			defer disarmRecompile(m)
			var samples int
			m.routerAdvertisementsForTest = func(context.Context, string) []observedRouter {
				samples++
				if target == exchangeAcquire && samples == 1 ||
					target != exchangeAcquire && samples == 2 {
					cancel()
				}
				return nil
			}
			m.doV6ExchangeForTest = func(callCtx context.Context, _ string, mode dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
				if err := callCtx.Err(); err != nil {
					return nil, err
				}
				if target == exchangeRebind && mode == exchangeRenew {
					return nil, errors.New("simulated T1 failure")
				}
				if mode == target || mode == exchangeAcquire {
					lease := raLease(netip.Addr{}, time.Now(), time.Hour)
					if mode == target && target != exchangeAcquire {
						lease.Address = netip.MustParsePrefix("2001:db8::99/128")
					}
					return &dhcpv6Result{lease: lease}, nil
				}
				return nil, errors.New("simulated exchange failure")
			}

			m.runDHCPv6(ctx, "wan0")
			if recompileArmed(m) {
				t.Fatalf("%s result was committed after its context expired during RA sampling", tc.name)
			}
		})
	}
}

func TestPeriodicRAApplyExpiresRIOWithoutResurrection_11738(t *testing.T) {
	now := time.Now()
	destination := netip.MustParsePrefix("2001:db8:7000::/48")
	route := LeaseRoute{Destination: destination, Gateway: netip.MustParseAddr("fe80::1")}
	prior := applyIPv6RouterAdvertisements(nil, raLease(netip.Addr{}, now, time.Hour), []observedRouter{{
		addr: route.Gateway,
		routes: []observedRouteInformation{{
			destination: destination,
			lifetime:    time.Second,
			observed:    now,
		}},
	}}, now)

	refreshed := applyIPv6RouterAdvertisements(prior, prior, nil, now.Add(time.Second))
	if len(refreshed.ClasslessRoutes) != 0 {
		t.Fatalf("periodic silent RA refresh retained or resurrected expired route: %+v", refreshed.ClasslessRoutes)
	}
	if _, ok := refreshed.raRouteExpires[leaseRouteKey(route)]; ok {
		t.Fatalf("periodic RA refresh retained expired-route metadata: %+v", refreshed.raRouteExpires)
	}
}

func TestRIODefaultAndBroadPrefixesRemainAvailableToTrustHatch_11738(t *testing.T) {
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "1")
	now := time.Now()
	observed := routeInformationOptions([]ndp.Option{
		&ndp.RouteInformation{PrefixLength: 0, Prefix: netip.MustParseAddr("::"), RouteLifetime: time.Hour},
		&ndp.RouteInformation{PrefixLength: 1, Prefix: netip.MustParseAddr("8000::"), RouteLifetime: time.Hour},
	}, now)
	if len(observed) != 2 {
		t.Fatalf("broad RIOs admitted with explicit trust override = %+v, want /0 and /1 retained", observed)
	}
	lease := applyIPv6RouterAdvertisements(nil, raLease(netip.Addr{}, now, time.Hour), []observedRouter{{
		addr:     netip.MustParseAddr("fe80::1"),
		lifetime: time.Hour,
		routes:   observed,
	}}, now)
	if len(lease.ClasslessRoutes) != 2 {
		t.Fatalf("broad RIOs lost before trust-hatch route installation: %+v", lease.ClasslessRoutes)
	}
}
