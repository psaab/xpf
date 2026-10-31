package daemon

// Make-before-break transfer pre-activation, daemon side (#18559). The
// mechanism and its invariants are documented with the overlay in
// pkg/dataplane/userspace/manager_ha_preactivate.go; this file only decides
// which RGs qualify and sequences the route republish before the helper
// publish, mirroring the promotion path (#16270).

import (
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
	pre.BeginTransferPreActivation(ids, time.Now().Add(transferPreActivateTTL))
	// Routes first: the connected prefixes of the RG must be in the helper
	// FIB before its forwarding opens, or the first redirected packet
	// resolves to the cluster terminal (#16270).
	d.republishConnectedRGSync(d.applyCancelCtx(), "transfer-preactivate")
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
