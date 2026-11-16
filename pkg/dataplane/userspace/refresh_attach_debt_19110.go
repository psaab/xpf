package userspace

import (
	"fmt"
	"log/slog"
	"sort"
	"time"
)

// #19110 (codex-d NEW P2-1): a FAILED #14133 refresh attach is readiness debt,
// and it is retried.
//
// The refresh path never waits under m.mu (zero refresh budgets,
// pkg/dataplane xdp_attach_occupancy_19110.go), so a refused attach
// (ErrXDPOccupied) or any other failed attach gives up at once and leaves the
// interface with no XDP shim. Its transit is dropped by the #10302 armed fence.
// Before this file, that failure was only a WARN:
//   - the status-loop revalidation flag and the daemon worker's retry debt both
//     cleared on a successful PUBLICATION, so nothing retried the attach;
//   - F4 records only unintended GENERIC fallbacks, so a member with no XDP at
//     all raised no readiness reason;
//   - the box-wide XSK liveness proof stays latched, and the #7191 coverage
//     proof runs only in a compile's attach pass.
//
// So a standby whose RETH member was recreated and refused could still
// advertise takeover-ready. Now:
//   - refreshAttachDebt holds the failures of the reconcile's latest pass. Each
//     pass attempts every admitted ingress ifindex that has no tracked link, so
//     a pass's failure set is exactly the current debt. An interface leaves the
//     debt when a pass attaches it, when another path attached it (it is then
//     tracked, so the pass skips it), or when it is no longer an admitted
//     ingress interface (removed from the configuration).
//   - A RETH data member in the debt is a takeover-readiness reason while the
//     peer is alive, scoped exactly like F4. A lone owner has no better node: it
//     gets an ERROR log, and the blocker metric (computed in the peer-alive
//     form) shows xdp_missing_data_member.
//   - The status loop retries the debt on a LATER tick, never by sleeping:
//     1 s after the first failure, doubling to 30 s. A successful compile makes
//     the debt due at once, so the next tick drops what the compile attached.
//   - Logs are on change: a new or changed failure is an ERROR (member) or a
//     WARN; an unchanged repeat is DEBUG; a cleared entry is INFO.

// missingDataMemberReasonMarker is the substring MapHATakeoverBlocker keys on.
const missingDataMemberReasonMarker = "has no XDP shim attached"

const (
	refreshAttachRetryMin = time.Second
	refreshAttachRetryMax = 30 * time.Second
)

// noteRefreshAttachOutcomeLocked records one reconcile pass's outcome:
// attempted is every ifindex the pass tried, failed the ones that ended with
// no attachment. Call it AFTER the pass re-resolved the F4 members, so the log
// can name a member. Caller holds m.mu.
func (m *Manager) noteRefreshAttachOutcomeLocked(attempted map[int]bool, failed map[int]error, now time.Time) {
	prev := m.refreshAttachDebt
	next := make(map[int]string, len(failed))
	for _, ifindex := range sortedKeys19110(failed) {
		why := failed[ifindex].Error()
		next[ifindex] = why
		if prev[ifindex] == why {
			slog.Debug("userspace: interface-link refresh attach still failing; retry owed",
				"ifindex", ifindex, "err", why, "issue", "#19110")
			continue
		}
		if name, member := m.genericDataMemberNames[ifindex]; member {
			slog.Error("RETH data member has no XDP shim after a failed interface-link refresh attach: this node "+
				"is not takeover-ready while a peer is alive, and as the owner it drops that member's transit "+
				"until a retry attaches it",
				"member", name, "ifindex", ifindex, "err", why, "issue", "#19110",
				"retry", "on a later status tick, 1 s doubling to 30 s; a successful commit also retries")
			continue
		}
		slog.Warn("userspace: failed to attach XDP shim during interface-link refresh; the interface stays "+
			"fail-closed and the attach is retried on a later status tick",
			"ifindex", ifindex, "err", why, "issue", "#14133")
	}
	for _, ifindex := range sortedKeys19110(prev) {
		if _, still := next[ifindex]; still {
			continue
		}
		how := "no longer a required ingress attachment, or attached by another path"
		if attempted[ifindex] {
			how = "attached on retry"
		}
		slog.Info("userspace: interface-link refresh attach debt cleared",
			"ifindex", ifindex, "member", m.genericDataMemberNames[ifindex], "how", how, "issue", "#19110")
	}
	switch {
	case len(next) == 0:
		m.refreshAttachDebt, m.refreshAttachBackoff, m.refreshAttachRetryAt = nil, 0, time.Time{}
		return
	case len(prev) == 0 || m.refreshAttachBackoff == 0:
		m.refreshAttachBackoff = refreshAttachRetryMin
	default:
		m.refreshAttachBackoff = min(2*m.refreshAttachBackoff, refreshAttachRetryMax)
	}
	m.refreshAttachDebt = next
	m.refreshAttachRetryAt = now.Add(m.refreshAttachBackoff)
}

// retryRefreshAttachDebtLocked re-runs the refresh reconcile against the
// published snapshot when attach debt is due. The status loop calls it once per
// tick: a retry is a later tick, never a sleep under m.mu. Caller holds m.mu.
func (m *Manager) retryRefreshAttachDebtLocked(now time.Time) {
	if len(m.refreshAttachDebt) == 0 || now.Before(m.refreshAttachRetryAt) || m.lastSnapshot == nil {
		return
	}
	m.reconcileInterfaceAttachmentsForRefreshLocked(m.lastSnapshot)
}

// makeRefreshAttachDebtDueLocked is called after a successful compile attach
// pass: the next status tick re-runs the reconcile, which drops every ifindex
// the compile attached. Caller holds m.mu.
func (m *Manager) makeRefreshAttachDebtDueLocked() {
	if len(m.refreshAttachDebt) > 0 {
		m.refreshAttachRetryAt = time.Time{}
	}
}

// missingDataMemberReasonsLocked is the readiness half: a configured RETH data
// member in the attach debt, while the peer is alive. Caller holds m.mu.
func (m *Manager) missingDataMemberReasonsLocked(peerAlive bool) []string {
	if !peerAlive || len(m.genericDataMemberNames) == 0 || len(m.refreshAttachDebt) == 0 {
		return nil
	}
	var reasons []string
	for ifindex, why := range m.refreshAttachDebt {
		if name, ok := m.genericDataMemberNames[ifindex]; ok {
			reasons = append(reasons, fmt.Sprintf(
				"userspace data interface %s (ifindex %d) %s: the interface-link refresh attach failed (%s); "+
					"retrying on a later status tick", name, ifindex, missingDataMemberReasonMarker, why))
		}
	}
	sort.Strings(reasons)
	return reasons
}

func sortedKeys19110[V any](m map[int]V) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
