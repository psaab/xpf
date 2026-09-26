package dhcp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

const (
	raCollectWindow = 2 * time.Second
	raReadSlice     = 200 * time.Millisecond
	raPrefLow       = 0
	raPrefMedium    = 1
	raPrefHigh      = 2
)

type observedRouter struct {
	addr     netip.Addr
	lifetime time.Duration
	pref     int
}

// selectRAObservedRouter accepts only link-local default routers (positive
// Router Lifetime, RFC 4861 §4.2) and chooses the highest RFC 4191 preference.
// Equal-preference routers retain first-seen order.
func selectRAObservedRouter(routers []observedRouter) netip.Addr {
	best := -1
	for i, r := range routers {
		if !r.addr.Is6() || !r.addr.IsLinkLocalUnicast() || r.lifetime <= 0 {
			continue
		}
		if best < 0 || r.pref > routers[best].pref {
			best = i
		}
	}
	if best < 0 {
		return netip.Addr{}
	}
	return routers[best].addr
}

func raPreferenceRank(pref ndp.Preference) int {
	switch pref {
	case ndp.High:
		return raPrefHigh
	case ndp.Low:
		return raPrefLow
	default: // ndp parses the reserved value as Medium per RFC 4191 §2.2.
		return raPrefMedium
	}
}

// routerDiscoveryConn is the subset of ndp.Conn needed to solicit and
// collect Router Advertisements. Keeping the collector independent of the
// privileged socket makes its wire decisions testable without CAP_NET_RAW.
type routerDiscoveryConn interface {
	SetICMPFilter(*ipv6.ICMPFilter) error
	SetControlMessage(ipv6.ControlFlags, bool) error
	JoinGroup(netip.Addr) error
	WriteTo(ndp.Message, *ipv6.ControlMessage, netip.Addr) error
	SetReadDeadline(time.Time) error
	ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error)
}

// routerAdvertisements solicits routers directly; it does not depend on
// kernel RA route installation (managed links set IPv6AcceptRA=no).
func (m *Manager) routerAdvertisements(ctx context.Context, ifaceName string) []observedRouter {
	ifi, err := net.InterfaceByName(ifaceName)
	if err != nil {
		slog.Warn("DHCPv6: cannot find interface for Router Solicitation", "interface", ifaceName, "err", err)
		return nil
	}
	// ndp.Listen binds the interface's link-local address and configures
	// IPv6 hop limit and ICMPv6 checksum for this RS/RA exchange. Fail closed:
	// a neighbor flag alone cannot prove a default router's lifetime.
	conn, _, err := ndp.Listen(ifi, ndp.LinkLocal)
	if err != nil {
		slog.Warn("DHCPv6: cannot open NDP connection for router discovery", "interface", ifaceName, "err", err)
		return nil
	}
	defer conn.Close()
	return collectRouterAdvertisements(ctx, ifi, conn)
}

func collectRouterAdvertisements(ctx context.Context, ifi *net.Interface, conn routerDiscoveryConn) []observedRouter {
	var filter ipv6.ICMPFilter
	filter.SetAll(true)
	filter.Accept(ipv6.ICMPTypeRouterAdvertisement)
	if err := conn.SetICMPFilter(&filter); err != nil {
		slog.Debug("DHCPv6: cannot set RA filter", "interface", ifi.Name, "err", err)
	}
	if err := conn.SetControlMessage(ipv6.FlagInterface|ipv6.FlagHopLimit, true); err != nil {
		slog.Warn("DHCPv6: cannot validate received Router Advertisements", "interface", ifi.Name, "err", err)
		return nil
	}
	if err := conn.JoinGroup(netip.MustParseAddr("ff02::1")); err != nil {
		slog.Debug("DHCPv6: cannot join all-nodes multicast group", "interface", ifi.Name, "err", err)
	}
	allRouters := netip.MustParseAddr("ff02::2")
	rs := &ndp.RouterSolicitation{}
	if len(ifi.HardwareAddr) == 6 {
		rs.Options = []ndp.Option{&ndp.LinkLayerAddress{
			Direction: ndp.Source,
			Addr:      ifi.HardwareAddr,
		}}
	}
	send := func() {
		if err := conn.WriteTo(rs, nil, allRouters); err != nil {
			slog.Debug("DHCPv6: Router Solicitation send failed", "interface", ifi.Name, "err", err)
		}
	}

	result := make([]observedRouter, 0, 2)
	bySource := make(map[netip.Addr]int)
	record := func(addr netip.Addr, lifetime time.Duration, pref int) bool {
		if i, ok := bySource[addr]; ok {
			result[i].lifetime, result[i].pref = lifetime, pref
		} else {
			bySource[addr] = len(result)
			result = append(result, observedRouter{addr: addr, lifetime: lifetime, pref: pref})
		}
		return lifetime > 0 && pref == raPrefHigh
	}

	deadline := time.Now().Add(raCollectWindow)
	nextRS := time.Time{}
	sent := 0
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return result
		}
		now := time.Now()
		if sent < 2 && !now.Before(nextRS) {
			send()
			sent++
			nextRS = now.Add(time.Second)
		}
		readUntil := now.Add(raReadSlice)
		if sent < 2 && nextRS.Before(readUntil) {
			readUntil = nextRS
		}
		if deadline.Before(readUntil) {
			readUntil = deadline
		}
		if err := conn.SetReadDeadline(readUntil); err != nil {
			return result
		}
		msg, cm, src, err := conn.ReadFrom()
		if err != nil {
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				continue
			}
			slog.Debug("DHCPv6: NDP read failed during router discovery", "interface", ifi.Name, "err", err)
			return result
		}
		ra, ok := msg.(*ndp.RouterAdvertisement)
		if !ok || cm == nil || cm.IfIndex != ifi.Index || cm.HopLimit != ndp.HopLimit {
			continue
		}
		src = src.WithZone("")
		if !src.Is6() || !src.IsLinkLocalUnicast() {
			continue
		}
		if record(src, ra.RouterLifetime, raPreferenceRank(ra.RouterSelectionPreference)) {
			return result
		}
	}
	return result
}
