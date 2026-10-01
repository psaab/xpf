package dhcp

import (
	"context"
	"net/netip"
	"time"
)

const raRefreshInterval = 30 * time.Second

type raRouteKey struct {
	destination netip.Prefix
	gateway     netip.Addr
}

func mergeObservedRouteInformation(prior, next []observedRouteInformation) []observedRouteInformation {
	if len(next) == 0 {
		return prior
	}
	merged := append([]observedRouteInformation(nil), prior...)
	for _, route := range next {
		found := false
		for i := range merged {
			if merged[i].destination == route.destination {
				merged[i] = route
				found = true
				break
			}
		}
		if !found {
			merged = append(merged, route)
		}
	}
	return merged
}

func applyIPv6RouterAdvertisements(prior, next *Lease, routers []observedRouter, now time.Time) *Lease {
	if next == nil {
		return nil
	}
	if prior == nil && len(routers) == 0 && next.raGatewayExpiresAt.IsZero() && len(next.raRouteExpires) == 0 {
		return next
	}
	updated := *next
	updated.ClasslessRoutes = nil
	updated.raRouteExpires = cloneRARouteExpiries(next.raRouteExpires)

	var held *Lease
	if prior != nil && prior.Family == AFInet6 {
		h := *prior
		h.ClasslessRoutes = append([]LeaseRoute(nil), prior.ClasslessRoutes...)
		h.raRouteExpires = cloneRARouteExpiries(prior.raRouteExpires)
		expireIPv6RouterState(&h, now)
		held = &h
		updated.leaseExpiryApplies = updated.leaseExpiryApplies || h.leaseExpiryApplies

		updated.Gateway = h.Gateway
		updated.raGatewayExpiresAt = h.raGatewayExpiresAt
		updated.raGatewayPreference = h.raGatewayPreference
		updated.raRouteExpires = cloneRARouteExpiries(h.raRouteExpires)
		for _, route := range h.ClasslessRoutes {
			upsertLeaseRoute(&updated.ClasslessRoutes, route)
		}
	}
	for _, route := range next.ClasslessRoutes {
		upsertLeaseRoute(&updated.ClasslessRoutes, route)
		key := leaseRouteKey(route)
		if expiry, ok := next.raRouteExpires[key]; ok {
			if updated.raRouteExpires == nil {
				updated.raRouteExpires = make(map[raRouteKey]time.Time)
			}
			updated.raRouteExpires[key] = expiry
		} else {
			delete(updated.raRouteExpires, key)
		}
	}

	if best := bestObservedRouter(routers); best >= 0 {
		router := routers[best]
		retainHeld := held != nil && held.Gateway.IsValid() &&
			router.addr != held.Gateway && router.pref <= held.raGatewayPreference &&
			!routerWithdrawn(routers, held.Gateway)
		if !retainHeld {
			updated.Gateway = router.addr
			updated.raGatewayExpiresAt = observedAt(router.observed, now).Add(router.lifetime)
			updated.raGatewayPreference = router.pref
		}
	} else if held != nil && routerWithdrawn(routers, held.Gateway) {
		updated.Gateway = netip.Addr{}
		updated.raGatewayExpiresAt = time.Time{}
		updated.raGatewayPreference = 0
	}

	for _, router := range routers {
		if !router.addr.Is6() || !router.addr.IsLinkLocalUnicast() {
			continue
		}
		for _, route := range router.routes {
			if !route.destination.IsValid() || !route.destination.Addr().Is6() {
				continue
			}
			gateway := router.addr.WithZone("")
			key := raRouteKey{destination: route.destination.Masked(), gateway: gateway}
			if route.lifetime <= 0 {
				removeLeaseRoute(&updated.ClasslessRoutes, key.destination, key.gateway)
				delete(updated.raRouteExpires, key)
				continue
			}
			if updated.raRouteExpires == nil {
				updated.raRouteExpires = make(map[raRouteKey]time.Time)
			}
			updated.raRouteExpires[key] = observedAt(route.observed, now).Add(route.lifetime)
			upsertLeaseRoute(&updated.ClasslessRoutes, LeaseRoute{
				Destination: key.destination,
				Gateway:     gateway,
			})
		}
	}

	expireIPv6RouterState(&updated, now)
	return &updated
}

func cloneRARouteExpiries(in map[raRouteKey]time.Time) map[raRouteKey]time.Time {
	if len(in) == 0 {
		return nil
	}
	out := make(map[raRouteKey]time.Time, len(in))
	for key, expiry := range in {
		out[key] = expiry
	}
	return out
}

func leaseRouteKey(route LeaseRoute) raRouteKey {
	return raRouteKey{destination: route.Destination, gateway: route.Gateway}
}

func bestObservedRouter(routers []observedRouter) int {
	best := -1
	for i, router := range routers {
		if !router.addr.Is6() || !router.addr.IsLinkLocalUnicast() || router.lifetime <= 0 {
			continue
		}
		if best < 0 || router.pref > routers[best].pref {
			best = i
		}
	}
	return best
}

func routerWithdrawn(routers []observedRouter, gateway netip.Addr) bool {
	if !gateway.IsValid() {
		return false
	}
	for _, router := range routers {
		if router.addr == gateway && router.lifetime <= 0 {
			return true
		}
	}
	return false
}

func observedAt(observed, fallback time.Time) time.Time {
	if observed.IsZero() {
		return fallback
	}
	return observed
}

func upsertLeaseRoute(routes *[]LeaseRoute, route LeaseRoute) {
	for i := range *routes {
		if (*routes)[i].Destination == route.Destination && (*routes)[i].Gateway == route.Gateway {
			(*routes)[i] = route
			return
		}
	}
	*routes = append(*routes, route)
}

func removeLeaseRoute(routes *[]LeaseRoute, destination netip.Prefix, gateway netip.Addr) {
	for i := 0; i < len(*routes); {
		if (*routes)[i].Destination == destination && (*routes)[i].Gateway == gateway {
			copy((*routes)[i:], (*routes)[i+1:])
			*routes = (*routes)[:len(*routes)-1]
			continue
		}
		i++
	}
}

func leaseDeadline(lease *Lease) time.Time {
	if lease == nil || !lease.leaseExpiryApplies || lease.LeaseTime <= 0 || lease.Obtained.IsZero() {
		return time.Time{}
	}
	return lease.Obtained.Add(lease.LeaseTime)
}

func raStateExpired(raExpiry, dhcpExpiry, now time.Time) bool {
	deadline := raExpiry
	if deadline.IsZero() || (!dhcpExpiry.IsZero() && dhcpExpiry.Before(deadline)) {
		deadline = dhcpExpiry
	}
	return !deadline.IsZero() && !now.Before(deadline)
}

func expireIPv6RouterState(lease *Lease, now time.Time) {
	if lease == nil || lease.Family != AFInet6 {
		return
	}
	dhcpExpiry := leaseDeadline(lease)
	if !lease.raGatewayExpiresAt.IsZero() && raStateExpired(lease.raGatewayExpiresAt, dhcpExpiry, now) {
		lease.Gateway = netip.Addr{}
		lease.raGatewayExpiresAt = time.Time{}
		lease.raGatewayPreference = 0
	}
	for i := 0; i < len(lease.ClasslessRoutes); {
		route := lease.ClasslessRoutes[i]
		key := leaseRouteKey(route)
		expiry := lease.raRouteExpires[key]
		if !expiry.IsZero() && raStateExpired(expiry, dhcpExpiry, now) {
			copy(lease.ClasslessRoutes[i:], lease.ClasslessRoutes[i+1:])
			lease.ClasslessRoutes = lease.ClasslessRoutes[:len(lease.ClasslessRoutes)-1]
			delete(lease.raRouteExpires, key)
			continue
		}
		i++
	}
}

func nextIPv6RARefreshDelay(lease *Lease, now time.Time) time.Duration {
	delay := raRefreshInterval
	if lease == nil || lease.Family != AFInet6 {
		return delay
	}
	dhcpExpiry := leaseDeadline(lease)
	consider := func(expiry time.Time) {
		if expiry.IsZero() {
			return
		}
		if !dhcpExpiry.IsZero() && dhcpExpiry.Before(expiry) {
			expiry = dhcpExpiry
		}
		if remaining := expiry.Sub(now); remaining < delay {
			delay = remaining
		}
	}
	consider(lease.raGatewayExpiresAt)
	for _, expiry := range lease.raRouteExpires {
		consider(expiry)
	}
	if delay < 0 {
		return 0
	}
	return delay
}

func (m *Manager) waitForIPv6TimerOrRA(
	ctx context.Context,
	timer <-chan time.Time,
	key clientKey,
	ifaceName string,
	lease *Lease,
) (*Lease, bool) {
	for {
		if ctx.Err() != nil {
			return lease, false
		}
		select {
		case <-timer:
			return lease, true
		case <-ctx.Done():
			return lease, false
		case <-m.afterRA(nextIPv6RARefreshDelay(lease, time.Now())):
			var refreshed bool
			lease, refreshed = m.refreshIPv6RouterState(ctx, key, ifaceName, lease)
			if !refreshed {
				return lease, false
			}
		}
	}
}

func (m *Manager) refreshIPv6RouterState(ctx context.Context, key clientKey, ifaceName string, lease *Lease) (*Lease, bool) {
	expired := *lease
	expired.ClasslessRoutes = append([]LeaseRoute(nil), lease.ClasslessRoutes...)
	expired.raRouteExpires = cloneRARouteExpiries(lease.raRouteExpires)
	expireIPv6RouterState(&expired, time.Now())
	if leaseContentChanged(lease, &expired) {
		m.commitRouterAdvertisementState(key, &expired, lease)
		lease = &expired
	}

	routers := m.observedRouterAdvertisements(ctx, ifaceName)
	if ctx.Err() != nil {
		return lease, false
	}
	refreshed := applyIPv6RouterAdvertisements(lease, lease, routers, time.Now())
	m.commitRouterAdvertisementState(key, refreshed, lease)
	return refreshed, true
}
