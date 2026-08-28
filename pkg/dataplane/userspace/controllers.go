package userspace

import (
	"context"
	"errors"

	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

type userspaceLinkController struct {
	manager *Manager
}

func (c userspaceLinkController) SetDeferWorkers(v bool) {
	if c.manager != nil {
		c.manager.SetDeferWorkers(v)
	}
}

// RecordDeferredWorkerArmDebt records the #5134 deferred-MAC worker-arm debt.
// It is not part of the LinkController interface; the daemon reaches it via an
// optional type assertion on d.dp.Link() (mirroring SetDeferWorkers).
func (c userspaceLinkController) RecordDeferredWorkerArmDebt() {
	if c.manager != nil {
		c.manager.RecordDeferredWorkerArmDebt()
	}
}

func (c userspaceLinkController) PrepareLinkCycle() error {
	if c.manager != nil {
		return c.manager.PrepareLinkCycle()
	}
	return nil
}

func (c userspaceLinkController) NotifyLinkCycle() error {
	if c.manager != nil {
		return c.manager.NotifyLinkCycle()
	}
	// No manager wired: no workers were joined, so there is nothing to rebind
	// and nothing to report. Mirrors PrepareLinkCycle's nil-manager reading.
	return nil
}

// NotifyLinkCycleKeepingLease is the #7007 repair-without-release. Same rebind,
// same error propagation, but the apply's link-cycle lease survives it — see
// Manager.NotifyLinkCycleKeepingLease for why an aborted RETH member must not
// end a lease its already-cycled sibling still depends on.
func (c userspaceLinkController) NotifyLinkCycleKeepingLease() error {
	if c.manager != nil {
		return c.manager.NotifyLinkCycleKeepingLease()
	}
	// No manager wired: nothing was joined, so there is nothing to rebind AND no
	// lease to keep. Mirrors NotifyLinkCycle's nil-manager reading.
	return nil
}

func (c userspaceLinkController) RenewLinkCycle() {
	if c.manager != nil {
		c.manager.RenewLinkCycle()
	}
}

// AbandonLinkCycle drops a lease the departing apply still holds (#6871 round
// 8). No manager wired: no lease was ever taken, so nothing was held.
func (c userspaceLinkController) AbandonLinkCycle() bool {
	if c.manager != nil {
		return c.manager.AbandonLinkCycle()
	}
	return false
}

type userspaceHAOps interface {
	UpdateRGActive(int, bool) error
	UpdateHAWatchdog(int, uint64) error
	UpdateFabricFwd(dataplane.FabricFwdInfo) error
	UpdateFabricFwd1(dataplane.FabricFwdInfo) error
	SyncFabricState()
}

type managerHAOps struct {
	manager *Manager
}

func (o managerHAOps) UpdateRGActive(rgID int, active bool) error {
	if o.manager == nil {
		return errors.New("nil userspace dataplane")
	}
	return o.manager.UpdateRGActive(rgID, active)
}

func (o managerHAOps) UpdateHAWatchdog(rgID int, timestamp uint64) error {
	if o.manager == nil {
		return errors.New("nil userspace dataplane")
	}
	return o.manager.UpdateHAWatchdog(rgID, timestamp)
}

func (o managerHAOps) UpdateFabricFwd(info dataplane.FabricFwdInfo) error {
	if o.manager == nil || o.manager.bpfShim == nil {
		return errors.New("nil userspace dataplane")
	}
	return o.manager.bpfShim.UpdateFabricFwd(info)
}

func (o managerHAOps) UpdateFabricFwd1(info dataplane.FabricFwdInfo) error {
	if o.manager == nil || o.manager.bpfShim == nil {
		return errors.New("nil userspace dataplane")
	}
	return o.manager.bpfShim.UpdateFabricFwd1(info)
}

func (o managerHAOps) SyncFabricState() {
	if o.manager != nil {
		o.manager.SyncFabricState()
	}
}

type userspaceHAController struct {
	manager userspaceHAOps
}

func (c userspaceHAController) SetRGActive(ctx context.Context, rgID int, active bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.manager == nil {
		return errors.New("nil userspace dataplane")
	}
	return c.manager.UpdateRGActive(rgID, active)
}

func (c userspaceHAController) SetHAWatchdog(ctx context.Context, rgID int, timestamp uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.manager == nil {
		return errors.New("nil userspace dataplane")
	}
	return c.manager.UpdateHAWatchdog(rgID, timestamp)
}

func (c userspaceHAController) SetFabricForwarding(ctx context.Context, id dataplane.FabricID, info dataplane.FabricFwdInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.manager == nil {
		return errors.New("nil userspace dataplane")
	}
	var err error
	if id == 1 {
		err = c.manager.UpdateFabricFwd1(info)
	} else {
		err = c.manager.UpdateFabricFwd(info)
	}
	if err != nil {
		return err
	}
	// The map update is committed at this point. Always push helper fabric
	// state after a successful fabric0 or fabric1 update so RuntimeDataPlane.HA
	// preserves the same "fresh helper view" contract for every fabric slot.
	c.manager.SyncFabricState()
	return nil
}

func (c userspaceHAController) SyncFabricState(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.manager == nil {
		return errors.New("nil userspace dataplane")
	}
	c.manager.SyncFabricState()
	return nil
}

type userspaceSessionStore struct {
	dataplane.SessionStore
	source dpruntime.SessionDeltaSource
}

func (s userspaceSessionStore) SessionDeltas() dpruntime.SessionDeltaSource {
	return s.source
}
