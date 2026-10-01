package userspace

import (
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// BuildUnzonedHostInboundIngressNetdevsFromSnapshots returns unzoned physical
// ingress split into names visible as iifname and VRF slave names visible as
// sdifname. A VRF master can be shared with zone-owned ingress, so source denies
// for an unzoned member must match that member before the master's zone rules.
// Non-physical reinjection paths (xpf-usp0, loopback, and tunnel devices) remain
// outside this guard and keep destination-only policy.
func BuildUnzonedHostInboundIngressNetdevsFromSnapshots(cfg *config.Config, snaps []InterfaceSnapshot, views []ZoneHostInboundView) (iifnames, sdifnames []string) {
	if cfg == nil || len(snaps) == 0 {
		return nil, nil
	}
	lifelines := hostInboundLifelineSet(cfg)
	quarantined := quarantinedZoneNames(cfg)
	claimed := make(map[string]bool)
	for _, view := range views {
		for _, name := range view.IngressNetdevs {
			claimed[name] = true
		}
		for _, name := range view.IngressDenyNetdevs {
			claimed[name] = true
		}
	}
	// Loopback, tunnel, and lifeline identities remain outside this guard even
	// when multiple snapshot rows share their raw LinuxName.
	protected := make(map[string]bool, len(snaps))
	for _, snap := range snaps {
		netdev := snap.LinuxName
		if netdev == "" {
			continue
		}
		if netdev == "lo" || snap.Tunnel || snap.SecureTunnel ||
			hostInboundLifelineInterface(snap.Name, lifelines) {
			protected[netdev] = true
		}
	}
	vrfEnslaved := config.HostInboundVRFEnslavedNetdevs(cfg)
	seenIIF := make(map[string]bool, len(snaps))
	seenSDIF := make(map[string]bool, len(snaps))
	for _, snap := range snaps {
		netdev := snap.LinuxName
		if netdev == "" || protected[netdev] {
			continue
		}
		if snap.Zone != "" {
			if _, drop := quarantined[snap.Zone]; !drop {
				continue
			}
		}
		if vrfEnslaved[netdev] {
			// Views claim the LOCAL_IN VRF master, not this slave. Do not let a
			// zoned sibling's master claim hide the unzoned member.
			if claimed[netdev] || seenSDIF[netdev] {
				continue
			}
			seenSDIF[netdev] = true
			sdifnames = append(sdifnames, netdev)
			continue
		}
		if claimed[netdev] || seenIIF[netdev] {
			continue
		}
		seenIIF[netdev] = true
		iifnames = append(iifnames, netdev)
	}
	sort.Strings(iifnames)
	sort.Strings(sdifnames)
	return iifnames, sdifnames
}
