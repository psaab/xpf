package daemon

import (
	"context"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// startTransitGateLinkWatch starts the always-on RTNL link subscription that
// closes the transit gate when a kernel device carrying an XDP link disappears
// outside an ApplyConfig. Relevant configured-interface events also wake one
// debounced snapshot refresher. Both goroutines are joined by Run's shutdown
// WaitGroup.
func (d *Daemon) startTransitGateLinkWatch(ctx context.Context, wg *sync.WaitGroup) {
	if d == nil || ctx == nil || wg == nil {
		return
	}
	refreshWake := make(chan string, 1)
	// #18573: the direct-VIP reconcile queues a refresh after it changes a
	// RETH address, so the helper never keeps SNATing from a removed one.
	d.interfaceLinkRefreshWake.Store(&refreshWake)
	wg.Add(2)
	go func() {
		defer wg.Done()
		d.transitGateLinkWatch(ctx, refreshWake)
	}()
	go func() {
		defer wg.Done()
		d.interfaceLinkSnapshotRefreshLoop(ctx, refreshWake)
	}()
}

// transitGateLinkWatch owns the subscription lifecycle via nlWatch
// (#17064). A closed update channel is terminal for the subscription
// (including ENOBUFS), so nlWatch backs off and resubscribes. Every
// successful or failed attempt reasserts the gate (OnGap +
// OnGapOnFailure share the reassert); DELLINK events wake the existing
// coalescing gate path instead of doing one full census per event.
func (d *Daemon) transitGateLinkWatch(ctx context.Context, refreshWake chan string) {
	d.transitGateWatch(refreshWake).Run(ctx)
}

// transitGateWatch builds the nlWatch for the transit gate so tests can
// drive one lifetime via runOne.
func (d *Daemon) transitGateWatch(refreshWake chan string) nlWatch[netlink.LinkUpdate] {
	subscribe := d.transitGateLinkSubscribe
	if subscribe == nil {
		subscribe = defaultLinkStateSubscribe
	}
	reassert := func() {
		d.reassertTransitGate("link-subscribe")
		d.queueInterfaceLinkSnapshotResync(refreshWake)
	}
	return nlWatch[netlink.LinkUpdate]{
		Name:           "transit-gate-link",
		Subscribe:      subscribe,
		Buf:            64,
		Backoff:        d.transitGateLinkResubBackoff,
		OnGap:          reassert,
		OnGapOnFailure: true,
		OnEvent: func(update netlink.LinkUpdate) {
			if update.Header.Type == unix.RTM_NEWLINK || update.Header.Type == unix.RTM_DELLINK {
				d.markRouteListenerImmediately()
				linuxName := ""
				if update.Link != nil {
					if attrs := update.Link.Attrs(); attrs != nil {
						linuxName = attrs.Name
					}
				}
				if linuxName == "" {
					d.queueInterfaceLinkSnapshotResync(refreshWake)
				} else {
					d.queueInterfaceLinkSnapshotRefresh(refreshWake, linuxName)
				}
			}
			if update.Header.Type == unix.RTM_DELLINK {
				d.signalTransitGateWake()
			}
		},
	}
}

// runTransitGateLinkSubscription owns one lifetime; kept as the named
// seam existing cells drive. True means retry, false means ctx done.
func (d *Daemon) runTransitGateLinkSubscription(ctx context.Context, refreshWake chan string) bool {
	watch := d.transitGateWatch(refreshWake)
	return watch.runOne(ctx)
}
