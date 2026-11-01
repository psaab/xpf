package userspace

// Make-before-break transfer pre-activation (#18559).
//
// A requested RG transfer used to be break-before-make: the owner cleared
// rg_active inside its #5640 fence, acknowledged, and only then did the
// requester promote and open its own helper forwarding. Everything the owner
// fabric-redirected in between reached the requester's fabric-ingress
// HA-inactive gate and was dropped (100-220 ms per RG on the loss cluster).
//
// The requester now opens its helper forwarding for the transferring data RGs
// BEFORE it sends the request. The overlay below changes only what the helper
// is told — the update_ha_state inventory and the connected-prefix verdict the
// route builder uses — and never haGroups or the rg_active BPF map, which keep
// the cluster truth. The daemon's own rg_active state machine is untouched, so
// a reconcile pass that writes rg_active=false for a still-secondary RG does
// not close the window, and none of the activation-keyed side effects (VIPs,
// GARP, services) run early.
//
// An entry ends in exactly three ways:
//   - the real promotion lands (UpdateRGActive true) or a real demotion lands
//     (UpdateRGActive true->false): the cluster truth supersedes the overlay;
//   - the requester releases it (EndTransferPreActivation) on a failed or
//     abandoned transfer, which republishes the effective inventory;
//   - its backstop deadline passes, after which it no longer counts and the
//     status poll's signature comparison republishes the effective view.

import (
	"sort"
	"time"
)

// BeginTransferPreActivation marks rgIDs pre-active until the deadline. It
// performs no I/O: the caller republishes the connected-RG routes (which now
// see these RGs as locally owned) and then calls PublishTransferPreActivation,
// the same routes-before-rg_active order the promotion path keeps (#16270).
// IDs <= 0 are ignored: RG0 owns no forwarding.
func (m *Manager) BeginTransferPreActivation(rgIDs []int, until time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rgID := range rgIDs {
		if rgID <= 0 {
			continue
		}
		if m.transferPreActive == nil {
			m.transferPreActive = make(map[int]time.Time)
		}
		m.transferPreActive[rgID] = until
	}
}

// PublishTransferPreActivation sends the effective HA inventory to the helper
// so the pre-active RGs start forwarding. A no-op without a running helper or
// an HA inventory.
func (m *Manager) PublishTransferPreActivation() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.haGroups) == 0 {
		return nil
	}
	return m.syncHAStateLocked()
}

// EndTransferPreActivation drops the pre-activation for rgIDs. When that
// removes an RG from the effective active set — the transfer failed, so the
// cluster still says secondary — the effective inventory is republished at
// once and the helper demotes it. An RG whose promotion already landed was
// cleared by UpdateRGActive and costs nothing here.
//
// It reports whether any RG fell out of the effective active set, i.e.
// whether the caller must withdraw what the pre-activation published.
func (m *Manager) EndTransferPreActivation(rgIDs []int) (bool, error) {
	if m == nil {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	changed := false
	for _, rgID := range rgIDs {
		// Keyed on the entry EXISTING, not on it still being live: an entry
		// past its deadline already stopped counting for the helper, but the
		// connected routes Begin published still mark the RG local until the
		// caller withdraws them (a request that failed after the deadline).
		if _, ok := m.transferPreActive[rgID]; !ok {
			continue
		}
		delete(m.transferPreActive, rgID)
		if group, ok := m.haGroups[rgID]; !ok || !group.Active {
			changed = true
		}
	}
	if !changed || len(m.haGroups) == 0 {
		return changed, nil
	}
	return true, m.syncHAStateLocked()
}

// TransferPreActiveRGs reports the RGs currently pre-active, sorted. For
// diagnostics and tests.
func (m *Manager) TransferPreActiveRGs() []int {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	out := make([]int, 0, len(m.transferPreActive))
	for rgID := range m.transferPreActive {
		if m.transferPreActiveLocked(rgID, now) {
			out = append(out, rgID)
		}
	}
	sort.Ints(out)
	return out
}

// transferPreActiveLocked reports whether rgID is pre-active at now.
func (m *Manager) transferPreActiveLocked(rgID int, now time.Time) bool {
	until, ok := m.transferPreActive[rgID]
	return ok && now.Before(until)
}

// supersedeTransferPreActiveLocked is called from UpdateRGActive: a real
// promotion or a real demotion of rgID replaces the overlay. Without the
// demotion arm a pre-activation still inside its deadline would keep the
// helper forwarding for an RG this node had just been told to give up,
// breaking the owner's #5640 fence on the NEXT transfer.
func (m *Manager) supersedeTransferPreActiveLocked(rgID int, prior HAGroupStatus, known, active bool) {
	if len(m.transferPreActive) == 0 {
		return
	}
	if active || (known && prior.Active) {
		delete(m.transferPreActive, rgID)
	}
}

// effectiveHAGroupLocked is the helper-facing view of one group: the cluster
// truth, plus Active for a live pre-activation.
func (m *Manager) effectiveHAGroupLocked(group HAGroupStatus, now time.Time) HAGroupStatus {
	if !group.Active && m.transferPreActiveLocked(group.RGID, now) {
		group.Active = true
	}
	return group
}

// effectiveHAGroupsLocked returns the helper-facing inventory sorted by RG.
func (m *Manager) effectiveHAGroupsLocked() []HAGroupStatus {
	now := time.Now()
	groups := make([]HAGroupStatus, 0, len(m.haGroups))
	for _, group := range m.haGroups {
		groups = append(groups, m.effectiveHAGroupLocked(group, now))
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].RGID < groups[j].RGID
	})
	return groups
}

// effectiveHAGroupMapLocked is effectiveHAGroupsLocked keyed by RG, for the
// signature and watchdog-inventory consumers.
func (m *Manager) effectiveHAGroupMapLocked() map[int]HAGroupStatus {
	if len(m.transferPreActive) == 0 {
		return m.haGroups
	}
	now := time.Now()
	out := make(map[int]HAGroupStatus, len(m.haGroups))
	for id, group := range m.haGroups {
		out[id] = m.effectiveHAGroupLocked(group, now)
	}
	return out
}

// routeRGPrimaryLocked wraps the cluster RG-primary provider for the route
// builders. Two kinds of RG are reported locally primary on top of the cluster
// verdict:
//
//   - a pre-active RG, so its connected prefixes enter the helper FIB before
//     its forwarding opens (#16270 order, #18559);
//   - an RG the current helper last ACKNOWLEDGED as active (#18620), so its
//     connected prefixes leave the helper FIB only after the helper has been
//     told the RG is inactive.
//
// The second arm is the demotion twin of #16270. The cluster verdict flips at
// the start of a demotion; the helper learns it only when UpdateRGActive(false)
// lands, tens of ms later. Any snapshot published in between used to withdraw
// the RG's connected rows while the helper still forwarded the RG. The first
// FIB-stale hit of a live session then re-resolved off the RG's interface and
// was revoked as stale source NAT. The next packet installed a transient local
// seed that shadowed the flow when the RG came back. On loss this happened on
// 11 of 13 such windows on the #18598 arm.
//
// Every route build runs under m.mu, and so does the UpdateRGActive publish
// that refreshes haWatchdogHelperInventory after the helper's ack. So this
// orders the withdrawal after the ack by construction, whichever publisher
// builds the snapshot: the cluster-state republish, the route listener, the
// ip-monitoring overlay, a commit, or the apply-time rebuild.
// The inventory is the helper's ACKNOWLEDGED state, not haGroups: a failed
// UpdateRGActive(false) has already written haGroups, but the helper may still
// forward the RG, and its rows must stay.
//
// Proxy-NDP responders deliberately keep the raw provider: a pre-active node
// must not answer for addresses its peer still owns.
func (m *Manager) routeRGPrimaryLocked() RGPrimaryProvider {
	provider := m.rgPrimaryProvider
	if provider == nil {
		return provider
	}
	held := m.helperActiveRGsLocked()
	if len(m.transferPreActive) > 0 {
		now := time.Now()
		for rgID := range m.transferPreActive {
			if m.transferPreActiveLocked(rgID, now) {
				if held == nil {
					held = make(map[int]bool, len(m.transferPreActive))
				}
				held[rgID] = true
			}
		}
	}
	if len(held) == 0 {
		return provider
	}
	return func(rgID int) (bool, bool) {
		if held[rgID] {
			return true, true
		}
		return provider(rgID)
	}
}

// helperActiveRGsLocked returns the data RGs that the current helper last
// acknowledged as active (#18620), or nil. A helper that has not acknowledged
// an inventory holds nothing, so the cluster verdict alone decides.
//
// The helperHAStatePublished check is redundant today: every reset clears the
// flag and the inventory together. It is kept as defence, so that a future
// reset that cleared only the flag still drops the hold.
func (m *Manager) helperActiveRGsLocked() map[int]bool {
	if !m.helperHAStatePublished || len(m.haWatchdogHelperInventory) == 0 {
		return nil
	}
	var held map[int]bool
	for _, group := range m.haWatchdogHelperInventory {
		if group.RGID <= 0 || !group.Active {
			continue
		}
		if held == nil {
			held = make(map[int]bool, len(m.haWatchdogHelperInventory))
		}
		held[group.RGID] = true
	}
	return held
}

// adoptHelperInventoryLocked records groups as the inventory the current
// helper just acknowledged. Every full-inventory ack (syncHAStateLocked and
// the UpdateRGActive publish) goes through here.
//
// #18620: an RG that leaves the hold must also leave the helper FIB. While it
// was held, a routes-only publish kept its connected rows. Without a publish
// after the ack, they would stay until something unrelated republished. That
// is reachable: a demotion whose rg_active write failed keeps the hold, and
// its cluster-state republish keeps the rows. The reconcile retry that later
// lands the write is not an ownership edge, so it schedules no republish.
// heldRGReleaseFn closes that, whichever path delivered the ack.
func (m *Manager) adoptHelperInventoryLocked(groups []HAGroupStatus) {
	before := m.helperActiveRGsLocked()
	m.helperHAStatePublished = true
	m.haWatchdogHelperInventory = append(m.haWatchdogHelperInventory[:0], groups...)
	if len(before) == 0 || m.heldRGReleaseFn == nil {
		return
	}
	after := m.helperActiveRGsLocked()
	var released []int
	for rgID := range before {
		if !after[rgID] {
			released = append(released, rgID)
		}
	}
	if len(released) == 0 {
		return
	}
	sort.Ints(released)
	m.heldRGReleaseFn(released)
}
