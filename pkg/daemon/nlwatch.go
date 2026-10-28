package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/vishvananda/netlink"
)

// nlWatchBackoffDefault is the single resubscribe backoff for every
// daemon netlink watcher (#17064). It replaces the per-owner spellings
// (linkStateResubBackoffDefault, fabricStateResubBackoffDefault and the
// 2s literals in the neighbor/route loops).
const nlWatchBackoffDefault = 2 * time.Second

// nlWatch is the one subscribe/resubscribe/catch-up lifecycle for a
// daemon netlink subscription (#17064, R4-Q33-01). Eight owners used to
// hand-write make chan+done, subscribe, close-on-failure, catch-up,
// select loop, !ok -> resubscribe and backoff; the "closed channel
// means dropped events" fix (#3950/#4031/#8915/#9010) then had to land
// copy by copy, and fabric + IPsec topology still never reported the
// receive error.
//
// Run owns: the update/done channels, logging every subscribe failure
// and every receive error under Name (wrapping OnReceiveError), calling
// OnGap after every successful (re)subscribe, and the stoppable backoff
// timer between lifetimes. It returns only on ctx cancellation.
//
// Per-owner semantics stay with the owner via the callbacks:
//   - OnEvent handles one streamed update.
//   - OnGap is the catch-up/re-sync after a (re)subscribe (events may
//     have been dropped). Owners that must also act on a subscribe
//     FAILURE (transit gate, rxvlan, IPsec topology) set OnGapOnFailure.
//   - OnReceiveError (optional) runs in addition to the Name log line
//     on a receive error (route: mark coalescer + counter; RPM: fan-in).
//   - Watch, when non-nil, is an extra select arm for owners with a
//     second event source in the same lifetime (neighbor safety tick,
//     rxvlan periodic audit, RPM ticker/retry/subscription-error fan-in).
//     WatchReady reports whether the arm is currently enabled (a nil
//     WatchC disables it). Returning true from Watch asks Run to end
//     this lifetime without resubscribing (clean stop).
//   - Enabled gates a conditional (re)subscribe (RPM subscribes only
//     when a verify function exists): a disabled watcher still selects
//     on ctx/Watch and retries Enabled on the backoff cadence.
//   - OnChannelClosed (optional) runs when the update channel closes
//     before Run backs off (IPsec: revoke + census on close).
//
// RcvBuf/options are not modelled here: Subscribe closes over the
// concrete netlink *SubscribeWithOptions call (see the default*
// helpers below), so each socket keeps its ListExisting/RcvBuf choice.
type nlWatch[U any] struct {
	Name string
	// Subscribe starts one subscription streaming into ch, closing ch
	// on termination and invoking onErr with the receive error first.
	// Nil selects the per-type default in runNLWatch1.
	Subscribe func(ch chan<- U, done <-chan struct{}, onErr func(error)) error
	// Buf is the update channel depth. Zero means 64.
	Buf int
	// Backoff is the resubscribe delay. Zero means nlWatchBackoffDefault.
	Backoff time.Duration

	OnEvent         func(U)
	OnGap           func()
	OnGapOnFailure  bool
	OnReceiveError  func(error)
	OnChannelClosed func()
	Enabled         func() bool
	Watch           func() <-chan time.Time
	WatchReady      func() bool
	// WatchTick handles one Watch firing. Return true to stop cleanly
	// (Run returns), false to continue this lifetime.
	WatchTick func() (stop bool)
}

func (w nlWatch[U]) backoff() time.Duration {
	if w.Backoff > 0 {
		return w.Backoff
	}
	return nlWatchBackoffDefault
}

// Run drives the lifecycle until ctx is cancelled.
func (w nlWatch[U]) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		if !w.runOne(ctx) {
			return
		}
		if !nlWatchBackoffWait(ctx, w.backoff()) {
			return
		}
	}
}

// nlWatchBackoffWait waits d or until ctx is done; false means stop.
func nlWatchBackoffWait(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// runOne owns one subscription lifetime. True means resubscribe after
// backoff; false means ctx cancelled / clean stop.
func (w nlWatch[U]) runOne(ctx context.Context) bool {
	if w.Enabled != nil && !w.Enabled() {
		// Conditional subscribe is off: still honour ctx and the
		// owner's Watch arm (RPM ticker must keep running), then
		// re-check Enabled after the backoff wait in Run.
		if w.Watch == nil {
			return true
		}
		for {
			if !w.watchEnabled() {
				return true
			}
			select {
			case <-ctx.Done():
				return false
			case <-w.Watch():
				if w.WatchTick != nil && w.WatchTick() {
					return false
				}
				if w.Enabled != nil && w.Enabled() {
					return true
				}
			}
		}
	}
	buf := w.Buf
	if buf <= 0 {
		buf = 64
	}
	updates := make(chan U, buf)
	done := make(chan struct{})
	onErr := func(err error) {
		slog.Warn("netlink receive error, resubscribing", "watcher", w.Name, "err", err)
		if w.OnReceiveError != nil {
			w.OnReceiveError(err)
		}
	}
	subscribe := w.Subscribe
	if subscribe == nil {
		subscribe = defaultNLSubscribe[U]()
	}
	if err := subscribe(updates, done, onErr); err != nil {
		slog.Warn("netlink subscribe failed", "watcher", w.Name, "err", err)
		close(done)
		if w.OnGapOnFailure && w.OnGap != nil {
			w.OnGap()
		}
		return true
	}
	defer close(done)
	if w.OnGap != nil {
		w.OnGap()
	}
	for {
		// A disabled Watch arm must not block: use a nil channel.
		var watchC <-chan time.Time
		if w.watchEnabled() {
			watchC = w.Watch()
		}
		select {
		case <-ctx.Done():
			return false
		case <-watchC:
			if w.WatchTick != nil && w.WatchTick() {
				return false
			}
		case update, ok := <-updates:
			if !ok {
				if w.OnChannelClosed != nil {
					w.OnChannelClosed()
				}
				return true
			}
			if w.OnEvent != nil {
				w.OnEvent(update)
			}
		}
	}
}

func (w nlWatch[U]) watchEnabled() bool {
	if w.Watch == nil {
		return false
	}
	if w.WatchReady != nil {
		return w.WatchReady()
	}
	return true
}

// defaultNLSubscribe is the default subscriber table: the only place
// production code calls a netlink *Subscribe* function (#17064
// acceptance). Each entry wires onErr as the ErrorCallback and keeps
// the socket options that owner historically used.
func defaultNLSubscribe[U any]() func(chan<- U, <-chan struct{}, func(error)) error {
	var zero U
	switch any(zero).(type) {
	case netlink.LinkUpdate:
		return func(ch chan<- U, done <-chan struct{}, onErr func(error)) error {
			return netlink.LinkSubscribeWithOptions(
				any(ch).(chan<- netlink.LinkUpdate), done,
				netlink.LinkSubscribeOptions{ErrorCallback: onErr})
		}
	case netlink.AddrUpdate:
		return func(ch chan<- U, done <-chan struct{}, onErr func(error)) error {
			return netlink.AddrSubscribeWithOptions(
				any(ch).(chan<- netlink.AddrUpdate), done,
				netlink.AddrSubscribeOptions{ErrorCallback: onErr})
		}
	case netlink.RouteUpdate:
		return func(ch chan<- U, done <-chan struct{}, onErr func(error)) error {
			return netlink.RouteSubscribeWithOptions(
				any(ch).(chan<- netlink.RouteUpdate), done,
				netlink.RouteSubscribeOptions{ListExisting: false, ErrorCallback: onErr})
		}
	case netlink.NeighUpdate:
		return func(ch chan<- U, done <-chan struct{}, onErr func(error)) error {
			return netlink.NeighSubscribeWithOptions(
				any(ch).(chan<- netlink.NeighUpdate), done,
				netlink.NeighSubscribeOptions{
					ListExisting:      true,
					ReceiveBufferSize: 1 << 20,
					ErrorCallback:     onErr,
				})
		}
	default:
		return func(chan<- U, <-chan struct{}, func(error)) error {
			return errNLWatchNoDefault
		}
	}
}

func bufOr(n int) int {
	if n <= 0 {
		return 64
	}
	return n
}

// runPairNL is the two-socket variant for owners whose catch-up must
// fire only once BOTH subscriptions are live and whose close of either
// socket must tear down both (fabric #4031). It shares nlWatch's log
// lines, done-close discipline and ordering with runOne: first
// subscribes, then second, then onGap once.
func runPairNL[A, B any](ctx context.Context, a nlWatch[A], b nlWatch[B], onGap func()) bool {
	aUpdates := make(chan A, bufOr(a.Buf))
	aDone := make(chan struct{})
	aOnErr := func(err error) {
		slog.Warn("netlink receive error, resubscribing", "watcher", a.Name, "err", err)
		if a.OnReceiveError != nil {
			a.OnReceiveError(err)
		}
	}
	aSub := a.Subscribe
	if aSub == nil {
		aSub = defaultNLSubscribe[A]()
	}
	if err := aSub(aUpdates, aDone, aOnErr); err != nil {
		slog.Warn("netlink subscribe failed", "watcher", a.Name, "err", err)
		close(aDone)
		return true
	}
	defer close(aDone)
	bUpdates := make(chan B, bufOr(b.Buf))
	bDone := make(chan struct{})
	bOnErr := func(err error) {
		slog.Warn("netlink receive error, resubscribing", "watcher", b.Name, "err", err)
		if b.OnReceiveError != nil {
			b.OnReceiveError(err)
		}
	}
	bSub := b.Subscribe
	if bSub == nil {
		bSub = defaultNLSubscribe[B]()
	}
	if err := bSub(bUpdates, bDone, bOnErr); err != nil {
		slog.Warn("netlink subscribe failed", "watcher", b.Name, "err", err)
		close(bDone)
		return true
	}
	defer close(bDone)
	if onGap != nil {
		onGap()
	}
	for {
		select {
		case <-ctx.Done():
			return false
		case update, ok := <-aUpdates:
			if !ok {
				return true
			}
			if a.OnEvent != nil {
				a.OnEvent(update)
			}
		case update, ok := <-bUpdates:
			if !ok {
				return true
			}
			if b.OnEvent != nil {
				b.OnEvent(update)
			}
		}
	}
}

var errNLWatchNoDefault = nlWatchNoDefaultError{}

type nlWatchNoDefaultError struct{}

func (nlWatchNoDefaultError) Error() string {
	return "nlwatch: no default netlink subscriber for update type"
}

// --- Shared default subscribers (production seams used as Subscribe) ---

// defaultLinkStateSubscribe subscribes to RTNLGRP_LINK updates wiring
// onErr as ErrorCallback (#3950). Shared by SNMP, transit-gate and
// rxvlan link watchers.
func defaultLinkStateSubscribe(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
	return netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
		ErrorCallback: onErr,
	})
}

// defaultFabricLinkSubscribe / defaultFabricNeighSubscribe are the
// fabric monitor's production subscribers (#4031), now with the
// receive-error callback fabric previously lacked (#17064).
func defaultFabricLinkSubscribe(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
	return netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
		ErrorCallback: onErr,
	})
}

func defaultFabricNeighSubscribe(ch chan<- netlink.NeighUpdate, done <-chan struct{}, onErr func(error)) error {
	return netlink.NeighSubscribeWithOptions(ch, done, netlink.NeighSubscribeOptions{
		ErrorCallback: onErr,
	})
}

func defaultProbePinLinkSubscribe(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onError func(error)) error {
	return netlink.LinkSubscribeWithOptions(ch, done,
		netlink.LinkSubscribeOptions{ErrorCallback: onError})
}

func defaultProbePinAddrSubscribe(ch chan<- netlink.AddrUpdate, done <-chan struct{}, onError func(error)) error {
	return netlink.AddrSubscribeWithOptions(ch, done,
		netlink.AddrSubscribeOptions{ErrorCallback: onError})
}

// defaultIpsecTopologyLinkSubscribe is the IPsec topology owner's
// production subscriber; previously a bare LinkSubscribe with no
// ErrorCallback and an unlogged subscribe error (#17064).
func defaultIpsecTopologyLinkSubscribe(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
	return netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
		ErrorCallback: onErr,
	})
}
