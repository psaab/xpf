package daemon

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

const fabricMTUFloor10216 = 9000

// These seams keep the configured-floor read/write/readback contract testable
// without CAP_NET_ADMIN. The production values are the netlink operations.
var (
	fabricLinkByName10216 = netlink.LinkByName
	fabricLinkSetMTU10216 = netlink.LinkSetMTU
)

func fabricMTU10216(configured int) int {
	if configured > fabricMTUFloor10216 {
		return configured
	}
	return fabricMTUFloor10216
}

func reconcileFabricMTU10216(name string, link netlink.Link, want int) error {
	if link == nil || link.Attrs() == nil {
		return fmt.Errorf("%s has no link attributes", name)
	}
	if link.Attrs().MTU != want {
		if err := fabricLinkSetMTU10216(link, want); err != nil {
			return fmt.Errorf("set MTU %d: %w", want, err)
		}
	}
	verified, err := fabricLinkByName10216(name)
	if err != nil {
		return fmt.Errorf("verify MTU %d: %w", want, err)
	}
	if verified == nil || verified.Attrs() == nil {
		return fmt.Errorf("verify MTU %d: link has no attributes", want)
	}
	if got := verified.Attrs().MTU; got != want {
		return fmt.Errorf("verify MTU %d: observed %d", want, got)
	}
	return nil
}

// reconcileFabricMTUPair10216 orders a parent/overlay transition so a jumbo
// overlay is lowered before its parent. Linux rejects lowering a parent below
// an attached upper device's MTU; increases remain parent-first because an
// IPVLAN cannot exceed its parent.
func reconcileFabricMTUPair10216(parentName string, parent netlink.Link, overlayName string, overlay netlink.Link, want int) error {
	lowerOverlayFirst := overlay != nil && overlay.Attrs() != nil && overlay.Attrs().MTU > want
	if lowerOverlayFirst {
		if err := reconcileFabricMTU10216(overlayName, overlay, want); err != nil {
			return fmt.Errorf("fabric IPVLAN %s MTU reconciliation: %w", overlayName, err)
		}
	}
	if err := reconcileFabricMTU10216(parentName, parent, want); err != nil {
		return fmt.Errorf("fabric parent %s MTU reconciliation: %w", parentName, err)
	}
	if overlay != nil && !lowerOverlayFirst {
		if err := reconcileFabricMTU10216(overlayName, overlay, want); err != nil {
			return fmt.Errorf("fabric IPVLAN %s MTU reconciliation: %w", overlayName, err)
		}
	}
	return nil
}
