package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
)

// helperDownDemotionBound caps how long a demotion waits for the helper-side
// rg_active=false write when this node's helper control socket was silent at
// the start of the demotion (#18701). The VIPs are already released by then.
// One second is a third of the control deadline a silent round trip burns, and
// well above the healthy round trip measured under load (≤ 30 ms, #18685).
// When the control socket answers, nothing is bounded: the real write result
// decides (#18715 review).
var helperDownDemotionBound = time.Second

// errRGActiveWriteBoundExpired reports a helper-down write that did not finish
// within helperDownDemotionBound.
var errRGActiveWriteBoundExpired = errors.New("rg_active write not acknowledged within the helper-down bound")

// inflightRGActiveWrite is one in-flight helper-side rg_active write. A write that a
// caller stopped waiting for still runs to completion; only one runs per RG at
// a time (#18715 review), so a wedged helper never accumulates writes, and a
// caller that arrives while one is in flight for the same value joins it.
type inflightRGActiveWrite struct {
	active    bool
	done      chan struct{}
	err       error // valid once done is closed
	abandoned atomic.Bool
}

// startRGActiveWrite starts (or joins) the rg_active write for rgID. ctx is
// handed to SetRGActive; the controller honours it only at entry.
func (d *Daemon) startRGActiveWrite(ctx context.Context, ha dataplane.HAController, rgID int, active bool) *inflightRGActiveWrite {
	d.rgActiveWriteMu.Lock()
	if w := d.rgActiveWrites[rgID]; w != nil && w.active == active {
		d.rgActiveWriteMu.Unlock()
		return w
	}
	w := &inflightRGActiveWrite{active: active, done: make(chan struct{})}
	if d.rgActiveWrites == nil {
		d.rgActiveWrites = make(map[int]*inflightRGActiveWrite)
	}
	d.rgActiveWrites[rgID] = w
	d.rgActiveWriteMu.Unlock()
	go func() {
		w.err = ha.SetRGActive(ctx, rgID, active)
		close(w.done)
		d.rgActiveWriteMu.Lock()
		if d.rgActiveWrites[rgID] == w {
			delete(d.rgActiveWrites, rgID)
		}
		d.rgActiveWriteMu.Unlock()
		if w.abandoned.Load() {
			d.logLateRGActiveWrite(rgID, active, w.err)
		}
	}()
	return w
}

// await waits up to bound (0 = no bound) for the write. timedOut reports that
// the bound expired with the write still running.
func (w *inflightRGActiveWrite) await(ctx context.Context, bound time.Duration) (err error, timedOut bool) {
	if bound <= 0 {
		select {
		case <-w.done:
			return w.err, false
		case <-ctx.Done():
			return ctx.Err(), false
		}
	}
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case <-w.done:
		return w.err, false
	case <-timer.C:
		return errRGActiveWriteBoundExpired, true
	case <-ctx.Done():
		return ctx.Err(), false
	}
}

// logLateRGActiveWrite reports the outcome of a write the demotion stopped
// waiting for (#18715 review). The outcome is not recorded in the RG state
// machine: the reconcile loop owns that record and retries until a write it
// waited for lands. A late failure logs at Warn once per streak, then Debug.
func (d *Daemon) logLateRGActiveWrite(rgID int, active bool, err error) {
	d.rgActiveWriteMu.Lock()
	if d.rgActiveLateFail == nil {
		d.rgActiveLateFail = make(map[int]bool)
	}
	first := !d.rgActiveLateFail[rgID]
	d.rgActiveLateFail[rgID] = err != nil
	d.rgActiveWriteMu.Unlock()
	switch {
	case err == nil:
		slog.Info("cluster: the helper acknowledged an rg_active write the demotion had stopped waiting for (#18701)",
			"rg", rgID, "active", active)
	case first:
		slog.Warn("cluster: an rg_active write the demotion had stopped waiting for failed; the reconcile loop retries it (#18701)",
			"rg", rgID, "active", active, "err", err)
	default:
		slog.Debug("cluster: abandoned rg_active write failed again",
			"rg", rgID, "active", active, "err", err)
	}
}

// helperDownRGActiveWrite runs the rg_active write of a demotion with an
// unresponsive helper. silentAtEntry is the caller's ONE sample of the control
// socket, taken when the demotion started; it already decided whether the
// demotion prep ran, and it decides here whether the write is bounded.
//
//   - Control answering at entry: no bound. The real result decides: success
//     is a fence, an error is a refusal (#6371).
//   - Control silent at entry: wait helperDownDemotionBound. If the bound
//     expires, the control socket is sampled FRESH: if it answers now (the
//     helper recovered, or it was respawned) the real result is awaited after
//     all; if it is still silent the write is abandoned to the background,
//     its late outcome logged, and errRGActiveWriteBoundExpired returned.
//
// The fresh sample is deliberate: the entry sample may be seconds old by the
// time the bound expires, and acking a fence on "silent" needs the socket
// silent NOW (see helperDownFenceSilentAck).
func (d *Daemon) helperDownRGActiveWrite(ctx context.Context, ha dataplane.HAController, rgID int, active, silentAtEntry bool) error {
	if !silentAtEntry {
		return ha.SetRGActive(ctx, rgID, active)
	}
	w := d.startRGActiveWrite(ctx, ha, rgID, active)
	err, timedOut := w.await(ctx, helperDownDemotionBound)
	if !timedOut {
		return err
	}
	if !d.helperControlConfirmedSilent() {
		err, _ = w.await(ctx, 0)
		return err
	}
	w.abandoned.Store(true)
	return fmt.Errorf("rg_active=%v for redundancy group %d: %w (%s, helper control socket silent)",
		active, rgID, errRGActiveWriteBoundExpired, helperDownDemotionBound)
}

// helperDownFenceSilentAck decides whether a failed helper-down rg_active
// write may still be reported as an ACTUATED fence (#18715 review). All of:
// the control socket was silent when the demotion started, it is silent now
// (sampled fresh, failing closed when the surface is absent), and every direct
// VIP of the RG is confirmed off the interfaces. Then this node forwards
// nothing for the RG: no VIP attracts traffic, and a helper whose control
// thread is silent is assumed to forward nothing either (an assumption bounded
// by the 30 s silence kill, see pkg/daemon/README.md). A nil return means ack.
func (d *Daemon) helperDownFenceSilentAck(rgID int, silentAtEntry bool) error {
	if !silentAtEntry || !d.helperControlConfirmedSilent() {
		return errors.New("the helper control socket is answering, so a failed rg_active write is a refusal")
	}
	if err := d.directVIPsConfirmedAbsent(rgID); err != nil {
		return fmt.Errorf("direct VIPs not confirmed released: %w", err)
	}
	return nil
}

// releaseDirectVIPsHelperDown runs the direct-VIP reconcile for every RG of the
// cluster. Each reconcile keys on that RG's own local state
// (shouldOwnDirectVIPs), so it removes the VIPs, re-announce, and RA/DHCP
// services only of RGs this node no longer owns, and leaves an owned RG's
// VIPs in place. Used when the local helper is not answering, so that no RG's
// VIP release waits behind another RG's helper round trips (#18701).
func (d *Daemon) releaseDirectVIPsHelperDown(reason string) {
	if d.cluster == nil {
		return
	}
	for _, rg := range d.cluster.GroupStates() {
		d.reconcileDirectVIPOwnership(rg.GroupID, reason)
	}
}

// directVIPsConfirmedAbsent re-reads the kernel's addresses and returns nil
// only when no configured direct VIP of rgID is on its interface (#18715
// review). The release path (reconcileDirectVIPAddrs) skips a delete that
// fails and, when the address dump fails, falls back to a blind pass, and the
// ownership flag is cleared either way, so "released" there is not proof. A
// dump failure, a link lookup error other than "not found", or a VIP still
// present is an error. An interface that does not exist carries no VIP.
func (d *Daemon) directVIPsConfirmedAbsent(rgID int) error {
	if d.directVIPsConfirmAbsentFn != nil {
		return d.directVIPsConfirmAbsentFn(rgID)
	}
	if d.store == nil {
		return nil
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return nil
	}
	desired := cfg.RethVIPsForRG(rgID)
	if len(desired) == 0 {
		return nil
	}
	linkByName := d.linkByNameFn
	if linkByName == nil {
		linkByName = netlink.LinkByName
	}
	d.directVIPMu.Lock()
	defer d.directVIPMu.Unlock()
	rows, err := directVIPAddrDumpFn()
	if err != nil {
		return fmt.Errorf("address dump failed: %w", err)
	}
	for netdev, cidrs := range desired {
		link, err := linkByName(netdev)
		if err != nil {
			var notFound netlink.LinkNotFoundError
			if errors.As(err, &notFound) {
				continue
			}
			return fmt.Errorf("resolve %s: %w", netdev, err)
		}
		if link == nil || link.Attrs() == nil {
			return fmt.Errorf("resolve %s: no link attributes", netdev)
		}
		idx := link.Attrs().Index
		for _, cidr := range cidrs {
			p, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue // the reconcile reports a bad address; it is never installed
			}
			for _, row := range rows {
				if row.LinkIndex == idx && row.Prefix.Addr() == p.Addr() {
					return fmt.Errorf("VIP %s is still on %s", cidr, netdev)
				}
			}
		}
	}
	return nil
}

// helperElectionReasonSource is the optional surface that explains the
// #18697/#18685 verdict, for the #18701 demotion log line.
type helperElectionReasonSource interface {
	HelperElectionReason() string
}

func (d *Daemon) helperElectionReason() string {
	if src, ok := d.dataplane().(helperElectionReasonSource); ok {
		return src.HelperElectionReason()
	}
	return ""
}

// helperControlSource reports that the helper's control socket is not
// answering: no helper running after an unexpected exit, or the silence
// verdict. A frozen worker with an answering control thread is NOT this.
type helperControlSource interface {
	HelperControlUnresponsive() bool
}

// helperControlSilentForPrep decides whether to skip the demotion prep and
// bound the rg_active write. Without the surface it answers true: skipping a
// prep that would burn its 5 s against a helper nobody can see is the
// conservative choice there, and bounding the write commits to nothing,
// because a bounded write is acked only through helperControlConfirmedSilent.
func (d *Daemon) helperControlSilentForPrep() bool {
	if src, ok := d.dataplane().(helperControlSource); ok {
		return src.HelperControlUnresponsive()
	}
	return true
}

// helperControlConfirmedSilent decides whether a failed write may be acked as
// a fence. Without the surface it answers false (fail closed): no surface, no
// evidence that the helper forwards nothing (#18715 review).
func (d *Daemon) helperControlConfirmedSilent() bool {
	if src, ok := d.dataplane().(helperControlSource); ok {
		return src.HelperControlUnresponsive()
	}
	return false
}

// ownerlessConfirmBound caps the fresh rg_active=false write the ownerless
// accept waits for. It sits below the fence barrier's own timeout
// (defaultFailoverActuateTimeout), so a silent helper fails the confirm with
// its own reason instead of the barrier's generic timeout.
var ownerlessConfirmBound = 2 * time.Second

// acceptOwnerlessTransferOut serves a peer's transfer request for an RG this
// node does NOT own (#18715). Before #18715 that request was always rejected,
// which left an aborted transfer with no primary when the old owner (this
// node) did not re-promote: the requester's abort fence waits for exactly that.
//
// The request is accepted only when the RG is ownerless from this node's view
// too, judged under the cluster lock in the critical section that installs the
// hold (cluster.ManualFailoverOwnerless). The applied-ack then waits on a
// confirm-only barrier that the ordinary demotion event cannot resolve: it is
// resolved by confirmOwnerlessInactive, which needs a FRESH rg_active=false
// write to return success and every direct VIP of the RG confirmed absent.
// Anything else fails the barrier, the ack goes back failed, and the requester
// keeps its fence.
func (d *Daemon) acceptOwnerlessTransferOut(rgID int, reqID uint64) error {
	barrier := d.failoverActuations.armConfirmOnly(rgID, reqID)
	outcome, err := d.cluster.ManualFailoverOwnerless(rgID)
	if err != nil {
		d.disarmFailoverActuation(rgID, reqID, barrier)
		if errors.Is(err, cluster.ErrRemoteFailoverRejected) {
			slog.Info("cluster: rejected a transfer request for a redundancy group this node does not own",
				"rg", rgID, "req_id", reqID, "err", err)
		} else {
			slog.Warn("cluster: ownerless transfer request failed", "rg", rgID, "req_id", reqID, "err", err)
		}
		return err
	}
	if outcome == cluster.FailoverSuperseded {
		d.failFailoverActuation(rgID, reqID, barrier, cluster.ErrFailoverSuperseded)
	} else {
		slog.Warn("cluster: the peer asked for a redundancy group that neither node owns; "+
			"confirming this node's dataplane inactive for it before acknowledging (#18715)",
			"rg", rgID, "req_id", reqID)
		go func() {
			cause := d.confirmOwnerlessInactive(rgID)
			if cause != nil {
				slog.Warn("cluster: ownerless transfer not acknowledged; this node could not confirm its dataplane inactive (#18715)",
					"rg", rgID, "req_id", reqID, "err", cause)
			}
			d.failoverActuations.resolveRequest(rgID, reqID, barrier, cause)
		}()
	}
	// #5079: the same auto-restore lease as the ordinary path.
	d.cluster.ArmRemoteTransferOutLease([]int{rgID}, reqID)
	return nil
}

// confirmOwnerlessInactive proves this node forwards nothing for rgID: the
// RG state machine wants it inactive, a fresh rg_active=false write returns
// success, and every direct VIP is confirmed absent. nil means confirmed.
func (d *Daemon) confirmOwnerlessInactive(rgID int) error {
	s := d.getOrCreateRGState(rgID)
	if active, _ := s.CurrentDesired(); active {
		return fmt.Errorf("redundancy group %d is still desired active here (a VRRP instance is master)", rgID)
	}
	rt := d.dataplane()
	if rt == nil {
		return errors.New("no dataplane")
	}
	// A write already in flight for this RG is joined rather than doubled
	// (single-flight); it completes after this request arrived, so its
	// success is as fresh as a new write's.
	w := d.startRGActiveWrite(context.Background(), rt.HA(), rgID, false)
	if err, timedOut := w.await(context.Background(), ownerlessConfirmBound); err != nil {
		if timedOut {
			w.abandoned.Store(true)
		}
		return fmt.Errorf("fresh rg_active=false write: %w", err)
	}
	if d.isNoRethVRRP() {
		d.reconcileDirectVIPOwnership(rgID, "ownerless-transfer-confirm")
		if err := d.directVIPsConfirmedAbsent(rgID); err != nil {
			return fmt.Errorf("direct VIPs not confirmed released: %w", err)
		}
	}
	return nil
}
