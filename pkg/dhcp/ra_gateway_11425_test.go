package dhcp

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

func raLease(gateway netip.Addr, obtained time.Time, lifetime time.Duration) *Lease {
	return &Lease{
		Interface:          "wan0",
		Family:             AFInet6,
		Address:            netip.MustParsePrefix("2001:db8::50/128"),
		LeaseTime:          lifetime,
		Obtained:           obtained,
		Gateway:            gateway,
		leaseExpiryApplies: true,
	}
}

func TestRunDHCPv6RetainsRouterOnRASilence11425(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gateway := netip.MustParseAddr("fe80::1")
	m := &Manager{
		leases:               map[clientKey]*Lease{},
		delegatedPDs:         map[string][]DelegatedPrefix{},
		v6opts:               map[string]*DHCPv6Options{"wan0": {IATypes: []string{"ia-na"}}},
		afterForTest:         immediateAfter,
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
	}
	var samples int
	m.routerAdvertisementsForTest = func(context.Context, string) []observedRouter {
		samples++
		if samples == 1 {
			return []observedRouter{{addr: gateway, lifetime: time.Hour, pref: raPrefMedium}}
		}
		return nil
	}
	var exchanges int
	var gatewayAtNextRenew netip.Addr
	m.doV6ExchangeForTest = func(_ context.Context, _ string, _ dhcpExchangeMode, prev *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		exchanges++
		switch exchanges {
		case 1:
			return &dhcpv6Result{lease: raLease(gateway, time.Now(), time.Hour)}, nil
		case 2:
			return &dhcpv6Result{lease: raLease(netip.Addr{}, time.Now(), time.Hour)}, nil
		default:
			if prev != nil {
				gatewayAtNextRenew = prev.Gateway
			}
			cancel()
			return nil, context.Canceled
		}
	}

	m.runDHCPv6(ctx, "wan0")
	if gatewayAtNextRenew != gateway {
		t.Fatalf("gateway after a silent RA at renewal = %v, want retained %v", gatewayAtNextRenew, gateway)
	}
}

func TestRunDHCPv6RouterLifetimeZeroWithdrawsGateway11425(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gateway := netip.MustParseAddr("fe80::1")
	m := &Manager{
		leases:               map[clientKey]*Lease{},
		delegatedPDs:         map[string][]DelegatedPrefix{},
		v6opts:               map[string]*DHCPv6Options{"wan0": {IATypes: []string{"ia-na"}}},
		afterForTest:         immediateAfter,
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
	}
	var samples int
	m.routerAdvertisementsForTest = func(context.Context, string) []observedRouter {
		samples++
		if samples == 1 {
			return []observedRouter{{addr: gateway, lifetime: time.Hour, pref: raPrefMedium}}
		}
		return []observedRouter{{addr: gateway, lifetime: 0, pref: raPrefMedium}}
	}
	var exchanges int
	var gatewayAtNextRenew netip.Addr
	m.doV6ExchangeForTest = func(_ context.Context, _ string, _ dhcpExchangeMode, prev *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		exchanges++
		switch exchanges {
		case 1, 2:
			return &dhcpv6Result{lease: raLease(gateway, time.Now(), time.Hour)}, nil
		default:
			if prev != nil {
				gatewayAtNextRenew = prev.Gateway
			}
			cancel()
			return nil, context.Canceled
		}
	}

	m.runDHCPv6(ctx, "wan0")
	if gatewayAtNextRenew.IsValid() {
		t.Fatalf("gateway after matching lifetime-0 RA = %v, want withdrawn", gatewayAtNextRenew)
	}
}

func TestCollectRouterAdvertisementsInstallsAndWithdrawsRIO11425(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ifi := &net.Interface{Name: "wan0", Index: 7}
	cm := &ipv6.ControlMessage{IfIndex: ifi.Index, HopLimit: ndp.HopLimit}
	routePrefix := netip.MustParseAddr("2001:db8:4000::")
	route := &ndp.RouteInformation{
		PrefixLength:  48,
		Prefix:        routePrefix,
		RouteLifetime: time.Hour,
	}
	reads := []routerAdvertisementRead{
		{message: &ndp.RouterAdvertisement{RouterLifetime: time.Hour, RouterSelectionPreference: ndp.High}, cm: cm, source: netip.MustParseAddr("fe80::1%wan0")},
		{message: &ndp.RouterAdvertisement{RouterLifetime: time.Hour, RouterSelectionPreference: ndp.Medium, Options: []ndp.Option{route}}, cm: cm, source: netip.MustParseAddr("fe80::2%wan0")},
		// An RA without a Route Information option is silence for the route,
		// not a withdrawal; the prior advertised RIO remains live.
		{message: &ndp.RouterAdvertisement{RouterLifetime: time.Hour, RouterSelectionPreference: ndp.Medium}, cm: cm, source: netip.MustParseAddr("fe80::2%wan0")},
	}
	readCount := 0
	conn := &fakeRouterDiscoveryConn{reads: reads, onRead: func() {
		readCount++
		if readCount == len(reads) {
			cancel()
		}
	}}
	observed := collectRouterAdvertisements(ctx, ifi, conn)
	if len(observed) != 2 {
		t.Fatalf("observed routers = %+v, want both high-default and RIO advertiser", observed)
	}
	if got := selectRAObservedRouter(observed); got != netip.MustParseAddr("fe80::1") {
		t.Fatalf("default router = %v, want highest-preference fe80::1", got)
	}
	var rioRouter *observedRouter
	for i := range observed {
		if observed[i].addr == netip.MustParseAddr("fe80::2") {
			rioRouter = &observed[i]
		}
	}
	if rioRouter == nil || len(rioRouter.routes) != 1 || rioRouter.routes[0].destination != netip.MustParsePrefix("2001:db8:4000::/48") {
		t.Fatalf("RIO after later option omission = %+v, want retained /48 route", rioRouter)
	}

	now := time.Now()
	prior := applyIPv6RouterAdvertisements(nil, raLease(netip.Addr{}, now, 2*time.Hour), observed, now)
	wantGateway := netip.MustParseAddr("fe80::1")
	if prior.Gateway != wantGateway {
		t.Fatalf("installed RA gateway = %v, want %v", prior.Gateway, wantGateway)
	}
	wantRoute := LeaseRoute{
		Destination: netip.MustParsePrefix("2001:db8:4000::/48"),
		Gateway:     netip.MustParseAddr("fe80::2"),
	}
	if len(prior.ClasslessRoutes) != 1 || prior.ClasslessRoutes[0].Destination != wantRoute.Destination || prior.ClasslessRoutes[0].Gateway != wantRoute.Gateway {
		t.Fatalf("installed RIO routes = %+v, want [%+v]", prior.ClasslessRoutes, wantRoute)
	}

	withdrawal := []observedRouter{{
		addr: netip.MustParseAddr("fe80::2"),
		routes: []observedRouteInformation{{
			destination: wantRoute.Destination,
			lifetime:    0,
			observed:    now,
		}},
	}}
	withdrawn := applyIPv6RouterAdvertisements(prior, raLease(netip.Addr{}, now, 2*time.Hour), withdrawal, now)
	if len(withdrawn.ClasslessRoutes) != 0 {
		t.Fatalf("classless routes after matching RIO lifetime-zero = %+v, want none", withdrawn.ClasslessRoutes)
	}
}

func TestIPv6RouterStateExpiresAtMinimumLifetime11425(t *testing.T) {
	now := time.Now()
	gateway := netip.MustParseAddr("fe80::1")
	destination := netip.MustParsePrefix("2001:db8:4000::/48")
	routeOutlivesLease := netip.MustParsePrefix("2001:db8:5000::/48")
	lease := raLease(netip.Addr{}, now, 3*time.Second)
	state := applyIPv6RouterAdvertisements(nil, lease, []observedRouter{{
		addr: gateway, lifetime: 10 * time.Second, pref: raPrefMedium, observed: now,
		routes: []observedRouteInformation{
			{destination: destination, lifetime: time.Second, observed: now},
			{destination: routeOutlivesLease, lifetime: 10 * time.Second, observed: now},
		},
	}}, now)
	if delay := nextIPv6RARefreshDelay(state, now); delay != time.Second {
		t.Fatalf("next RA refresh delay = %v, want earliest RIO lifetime 1s", delay)
	}
	expireIPv6RouterState(state, now.Add(time.Second))
	if len(state.ClasslessRoutes) != 1 || state.ClasslessRoutes[0].Destination != routeOutlivesLease || state.Gateway != gateway {
		t.Fatalf("after short RIO expiry: routes=%+v gateway=%v, want long RIO retained and gateway live", state.ClasslessRoutes, state.Gateway)
	}
	expireIPv6RouterState(state, now.Add(3*time.Second))
	if len(state.ClasslessRoutes) != 0 || state.Gateway.IsValid() {
		t.Fatalf("state after DHCP deadline: routes=%+v gateway=%v, want all RA state expired", state.ClasslessRoutes, state.Gateway)
	}

	stateless := raLease(netip.Addr{}, now, 3*time.Second)
	stateless.leaseExpiryApplies = false
	statelessState := applyIPv6RouterAdvertisements(nil, stateless, []observedRouter{{
		addr: gateway, lifetime: 10 * time.Second, pref: raPrefMedium, observed: now,
	}}, now)
	expireIPv6RouterState(statelessState, now.Add(3*time.Second))
	if statelessState.Gateway != gateway {
		t.Fatalf("synthetic stateless refresh interval expired RA gateway early: %v", statelessState.Gateway)
	}
}

func TestIPv6RARefreshRunsBeforeDHCPRenewal11425(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gateway := netip.MustParseAddr("fe80::1")
	m := &Manager{
		leases:               map[clientKey]*Lease{},
		delegatedPDs:         map[string][]DelegatedPrefix{},
		v6opts:               map[string]*DHCPv6Options{"wan0": {IATypes: []string{"ia-na"}}},
		afterForTest:         func(time.Duration) <-chan time.Time { return make(chan time.Time) },
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
	}
	var raSamples int
	m.routerAdvertisementsForTest = func(context.Context, string) []observedRouter {
		raSamples++
		if raSamples > 1 {
			cancel()
		}
		return []observedRouter{{addr: gateway, lifetime: time.Hour, pref: raPrefMedium}}
	}
	var refreshDelay time.Duration
	m.raAfterForTest = func(delay time.Duration) <-chan time.Time {
		refreshDelay = delay
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}
	m.doV6ExchangeForTest = func(_ context.Context, _ string, _ dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		return &dhcpv6Result{lease: raLease(netip.Addr{}, time.Now(), time.Hour)}, nil
	}

	m.runDHCPv6(ctx, "wan0")
	if raSamples < 2 {
		t.Fatalf("RA samples = %d, want acquisition plus periodic refresh before DHCP T1", raSamples)
	}
	if refreshDelay <= 0 || refreshDelay > raRefreshInterval {
		t.Fatalf("periodic RA refresh delay = %v, want positive delay no greater than %v", refreshDelay, raRefreshInterval)
	}
}

func TestClasslessSafetyGatesCoverIPv6RIO11425(t *testing.T) {
	for _, raw := range []string{"::/0", "::/1", "fe80::/10", "ff00::/8", "::1/128"} {
		prefix := netip.MustParsePrefix(raw)
		if !ClasslessRouteIsTooBroad(prefix) && !ClasslessRouteIsMartian(prefix) {
			t.Errorf("unsafe IPv6 RIO destination %s passed both classless safety gates", prefix)
		}
	}
	for _, raw := range []string{"fc00::/7", "2001:db8:4000::/48"} {
		prefix := netip.MustParsePrefix(raw)
		if ClasslessRouteIsTooBroad(prefix) || ClasslessRouteIsMartian(prefix) {
			t.Errorf("legitimate IPv6 RIO destination %s rejected by classless safety gates", prefix)
		}
	}
}

func TestHeldHighPreferenceRouterOutranksNewLowPreference11425(t *testing.T) {
	now := time.Now()
	high := netip.MustParseAddr("fe80::1")
	low := netip.MustParseAddr("fe80::2")
	prior := raLease(high, now, time.Hour)
	prior.raGatewayExpiresAt = now.Add(time.Hour)
	prior.raGatewayPreference = raPrefHigh
	updated := applyIPv6RouterAdvertisements(prior, raLease(netip.Addr{}, now, time.Hour), []observedRouter{{
		addr: low, lifetime: time.Hour, pref: raPrefLow, observed: now,
	}}, now)
	if updated.Gateway != high {
		t.Fatalf("gateway with unexpired held high-preference router and new low RA = %v, want %v", updated.Gateway, high)
	}
}
