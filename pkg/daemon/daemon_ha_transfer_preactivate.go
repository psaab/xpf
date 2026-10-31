package daemon

// Make-before-break transfer pre-activation, daemon side (#18559). The
// mechanism and its invariants are documented with the overlay in
// pkg/dataplane/userspace/manager_ha_preactivate.go; this file only decides
// which RGs qualify and sequences the route republish before the helper
// publish, mirroring the promotion path (#16270).

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// transferPreActivateTTL bounds a pre-activation that is never released (a
// bug, or a requester that stalls inside the request). A normal transfer
// releases it within about a second; the owner's request-ACK timeout is 20s,
// so a barrier slower than this TTL simply falls back to break-before-make.
// It also bounds how long both helpers can forward the RG at once.
const transferPreActivateTTL = 5 * time.Second

// transferPreActivator is the userspace dataplane surface the hook drives.
type transferPreActivator interface {
	BeginTransferPreActivation(rgIDs []int, until time.Time)
	PublishTransferPreActivation() error
	EndTransferPreActivation(rgIDs []int) (bool, error)
}

var errTransferPreActivationUnsupported = errors.New("dataplane has no transfer pre-activation")

// transferPreActivateLockWait bounds how long the pre-activation waits for
// applySem before it gives up and lets the transfer run break-before-make
// (#18569). The request has not been sent yet, so this wait is added to the
// operator's failover command; a commit in flight may hold the semaphore for
// seconds, and an apply that is stuck would otherwise hang the request.
const transferPreActivateLockWait = 500 * time.Millisecond

var errTransferPreActivationLockBusy = errors.New("apply semaphore busy")

// transferPreActivationEligible filters rgIDs to the RGs that may open early.
// Strict VIP ownership (#104) exists to forbid a dual-active window, so it
// keeps the old sequence.
func (d *Daemon) transferPreActivationEligible(rgIDs []int) []int {
	out := make([]int, 0, len(rgIDs))
	for _, rgID := range rgIDs {
		if rgID <= 0 {
			continue
		}
		if d.getOrCreateRGState(rgID).IsStrictVIPOwnership() {
			continue
		}
		out = append(out, rgID)
	}
	return out
}

// beginTransferPreActivation is the cluster Manager's transfer pre-activate
// hook. It runs on the requesting node before the request is sent.
func (d *Daemon) beginTransferPreActivation(rgIDs []int) error {
	pre, ok := d.dataplane().(transferPreActivator)
	if !ok || pre == nil {
		return errTransferPreActivationUnsupported
	}
	ids := d.transferPreActivationEligible(rgIDs)
	if len(ids) == 0 {
		return nil
	}
	// #18569: the applySem wait is bounded, and the TTL starts once the lock
	// is held. An unbounded wait under the daemon-lifetime context hung the
	// failover request behind a stuck apply, and a wait longer than the TTL
	// published an overlay that had already expired (make-before-break lost
	// with no log line).
	if d.applySem != nil {
		ctx, cancel := context.WithTimeout(d.applyCancelCtx(), transferPreActivateLockWait)
		err := d.applySem.Acquire(ctx, 1)
		cancel()
		if err != nil {
			slog.Warn("cluster: transfer pre-activation skipped, apply semaphore busy; the transfer runs break-before-make",
				"rgs", ids, "wait", transferPreActivateLockWait, "err", err)
			return errTransferPreActivationLockBusy
		}
	}
	pre.BeginTransferPreActivation(ids, time.Now().Add(transferPreActivateTTL))
	// Routes first: the connected prefixes of the RG must be in the helper
	// FIB before its forwarding opens, or the first redirected packet
	// resolves to the cluster terminal (#16270). republishConnectedRG reads
	// the overlay just marked.
	if d.applySem != nil {
		d.republishConnectedRG("transfer-preactivate")
		d.applySem.Release(1)
	}
	if err := pre.PublishTransferPreActivation(); err != nil {
		return err
	}
	slog.Info("cluster: transfer pre-activation opened local forwarding", "rgs", ids)
	return nil
}

// endTransferPreActivation is the matching release. After a successful
// transfer the promotion already superseded the overlay and this is free.
// After a failed one the helper is told the cluster truth again, and the
// connected prefixes the pre-activation published are withdrawn.
func (d *Daemon) endTransferPreActivation(rgIDs []int) {
	pre, ok := d.dataplane().(transferPreActivator)
	if !ok || pre == nil {
		return
	}
	reverted, err := pre.EndTransferPreActivation(rgIDs)
	if err != nil {
		slog.Warn("cluster: transfer pre-activation release failed; status poll retries",
			"rgs", rgIDs, "err", err)
	}
	if reverted {
		slog.Info("cluster: transfer pre-activation released without promotion", "rgs", rgIDs)
		d.scheduleConnectedRGRepublish("transfer-preactivate-release")
	}
}
