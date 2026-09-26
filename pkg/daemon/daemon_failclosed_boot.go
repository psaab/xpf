package daemon

import (
	"log/slog"
	"net"
	"sort"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/vishvananda/netlink"
)

var (
	failClosedBootLinkList = netlink.LinkList
	failClosedBootAddrList = netlink.AddrList
)

// installFailClosedBootHostFences covers the live host addresses before the
// daemon enters its steady-state bootstrap loop when the last committed config
// cannot be loaded (#1960/#10297). networkd has already applied the retained
// 10-xpf-*.network files, but bootstrap suppresses applyConfig — the only
// ordinary caller of the host-input fence builders. Derive the fence scope from
// live netlink addresses instead of the unavailable config. Preserve the known
// management interfaces and withhold any shared management addresses, because
// the cold-boot fences have no per-service accepts.
//
// This deliberately does not bring data links down or remove networkd files:
// either can strand an operator on the only reachable management address. The
// fenced addresses remain configured but host-bound services cannot accept new
// connections until a compilable commit replaces the fences with real policy.
func (d *Daemon) installFailClosedBootHostFences(failClosedLoad bool) {
	if !failClosedLoad {
		return
	}

	// The fail-closed load suppresses takeover, so retain the same lifeline
	// identity used by bootstrap naming. A route-observation error means we
	// cannot safely identify a non-fxp0 management interface; do not risk
	// fencing an unknown management address.
	lifeline, found, err := detectLifelineInterfaceFn()
	if err != nil {
		slog.Error("fail-closed boot: cannot identify management interface; skipping live-address host fences to preserve reachability",
			"err", err)
		return
	}

	links, err := failClosedBootLinkList()
	if err != nil {
		slog.Error("fail-closed boot: cannot enumerate interfaces; skipping live-address host fences",
			"err", err)
		return
	}
	protected := d.resolveProtectedInterfaces()
	if found && lifeline != "" {
		protected[lifeline] = true
	}

	seenLinks := make(map[string]bool, len(links))
	for _, link := range links {
		if link == nil || link.Attrs() == nil {
			slog.Error("fail-closed boot: interface enumeration returned an incomplete link; skipping live-address host fences")
			return
		}
		attrs := link.Attrs()
		if attrs.Name == "" {
			slog.Error("fail-closed boot: interface enumeration returned a nameless link; skipping live-address host fences")
			return
		}
		seenLinks[attrs.Name] = true
	}
	if found && lifeline != "" && !seenLinks[lifeline] {
		slog.Error("fail-closed boot: detected management interface is absent from the interface snapshot; skipping live-address host fences",
			"interface", lifeline)
		return
	}

	// Address reads must be complete before replacing either table. In
	// particular, an unreadable protected interface means the shared-address
	// exclusion is unknown, so proceeding could drop the management IP.
	managed := make(map[string]struct{})
	var dataV4, dataV6 []string
	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Flags&net.FlagLoopback != 0 || attrs.Name == "lo" {
			continue
		}
		addrs, err := failClosedBootAddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			slog.Error("fail-closed boot: cannot read interface addresses; skipping live-address host fences",
				"interface", attrs.Name, "err", err)
			return
		}
		for _, addr := range addrs {
			if addr.IPNet == nil || addr.IPNet.IP == nil {
				continue
			}
			ip := addr.IPNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			if protected[attrs.Name] {
				managed[ip.String()] = struct{}{}
				continue
			}
			if ip.To4() != nil {
				dataV4 = append(dataV4, ip.String())
			} else {
				dataV6 = append(dataV6, ip.String())
			}
		}
	}

	// A data address shared with a protected interface is withheld from both
	// fences: their destination-only drop rules cannot distinguish ingress, and
	// withholding matches the existing #6492 cold-boot fence contract.
	filterShared := func(addrs []string) ([]string, int) {
		filtered := make([]string, 0, len(addrs))
		withheld := 0
		seen := make(map[string]struct{}, len(addrs))
		for _, addr := range addrs {
			if _, shared := managed[addr]; shared {
				withheld++
				continue
			}
			if _, duplicate := seen[addr]; duplicate {
				continue
			}
			seen[addr] = struct{}{}
			filtered = append(filtered, addr)
		}
		sort.Strings(filtered)
		return filtered, withheld
	}
	dataV4, withheldV4 := filterShared(dataV4)
	dataV6, withheldV6 := filterShared(dataV6)
	if withheldV4+withheldV6 > 0 {
		slog.Warn("fail-closed boot: withheld live addresses shared with a management interface; the address-only fence would otherwise interrupt new management connections",
			"withheld_v4", withheldV4, "withheld_v6", withheldV6)
	}
	if len(dataV4)+len(dataV6) == 0 {
		slog.Info("fail-closed boot: no non-management live addresses to fence")
		return
	}

	// The previously committed config is unavailable, so all non-management
	// local addresses are treated as host-inbound drop destinations. Using the
	// existing fence installers keeps both rulesets in the same hook/priority
	// slots as their real counterparts, admits mandatory return/control traffic,
	// and preserves their established replacement semantics.
	sets := dpuserspace.FenceAddrSets{UnzonedV4: dataV4, UnzonedV6: dataV6}
	wgListenPorts := []uint16(nil) // no trustworthy config exists to derive WG ports
	if err := d.installHostInboundColdBootFence(sets, wgListenPorts); err != nil {
		slog.Error("fail-closed boot: live-address host-inbound fence failed; host services may remain reachable on data addresses until a successful config apply",
			"err", err, "v4", dataV4, "v6", dataV6)
	}
	if err := d.installLo0ColdBootFence(sets, wgListenPorts); err != nil {
		slog.Error("fail-closed boot: live-address lo0 fence failed; host services may remain reachable on data addresses until a successful config apply",
			"err", err, "v4", dataV4, "v6", dataV6)
	}
}
