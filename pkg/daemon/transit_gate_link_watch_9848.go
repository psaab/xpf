package daemon

import (
	"context"
	"log/slog"
	"sync"
	"time"

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

// transitGateLinkWatch owns the subscription lifecycle. A closed update
// channel is terminal for the vishvananda/netlink subscription (including
// ENOBUFS), so back off and establish a fresh subscription. Every successful
// or failed attempt reasserts the gate; DELLINK events wake the existing
// coalescing gate path instead of doing one full census per event.
func (d *Daemon) transitGateLinkWatch(ctx context.Context, refreshWake chan string) {
	for {
		if !d.runTransitGateLinkSubscription(ctx, refreshWake) {
			return
		}
		backoff := d.transitGateLinkResubBackoff
		if backoff <= 0 {
			backoff = linkStateResubBackoffDefault
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

// runTransitGateLinkSubscription owns one netlink link subscription. It
// returns true when the subscription ended and the caller should retry, and
// false only when the Run context was cancelled.
func (d *Daemon) runTransitGateLinkSubscription(ctx context.Context, refreshWake chan string) bool {
	updates := make(chan netlink.LinkUpdate, 64)
	done := make(chan struct{})
	onErr := func(err error) {
		slog.Warn("transit gate link watcher: netlink receive error, resubscribing", "err", err)
	}

	subscribe := d.transitGateLinkSubscribe
	if subscribe == nil {
		subscribe = defaultLinkStateSubscribe
	}
	if err := subscribe(updates, done, onErr); err != nil {
		slog.Warn("transit gate link watcher: subscribe failed", "err", err)
		// A subscription implementation may have installed a done watcher
		// before failing; always release it before backing off.
		close(done)
		// A failed subscribe provides no event stream and may have followed a
		// dropped notification. Re-read kernel truth before retrying.
		d.reassertTransitGate("link-subscribe-failed")
		d.queueInterfaceLinkSnapshotResync(refreshWake)
		return true
	}
	defer close(done)

	// Resync after every subscribe. In particular, an ENOBUFS close means
	// notifications were dropped before the replacement socket was created.
	d.reassertTransitGate("link-subscribe")
	d.queueInterfaceLinkSnapshotResync(refreshWake)
	for {
		select {
		case <-ctx.Done():
			return false
		case update, ok := <-updates:
			if !ok {
				return true
			}
			if update.Header.Type == unix.RTM_NEWLINK || update.Header.Type == unix.RTM_DELLINK {
				// Link state feeds interface-only and tunnel ECMP liveness. Mark
				// the route coalescer so the overlay builder re-samples the
				// snapshot before its duplicate-content skip.
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
				// Coalesce a burst of unregisters through the existing
				// buffered wake path; the gate loop performs one fresh
				// kernel-truth census for the batch.
				d.signalTransitGateWake()
			}
		}
	}
}
