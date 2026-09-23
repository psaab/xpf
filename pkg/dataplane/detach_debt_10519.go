package dataplane

import "sort"

// Detach debt (#10519) is the fail-closed fence half of the DetachXDP
// observability fix.
//
// DetachXDP fails in retained-link arms with opposite fence consequences from
// the close arm. Arm (a), the IFACE_FLAG_XDP_ATTACHED claim cleanup, and arm
// (a2), a substantive l.Unpin() failure, both fail BEFORE the link is closed
// or removed: the xdpLinks entry stays, the kernel program stays attached,
// and the fence census (AttachedXDPIfindexes / withAttachedXDPFence) keeps
// returning the ifindex — a stale pinhole for an interface the accepted
// snapshot intends detached. Arm (b), l.Close(), fails AFTER the entry is
// deleted: the census already omits the ifindex by absence (availability
// loss, never widening). An already-unpinned os.ErrNotExist from Unpin is
// benign and proceeds to Close. DetachTC likewise retains its tracked handle
// on substantive Unpin failure, but TC links are not XDP fence candidates and
// therefore do not enter detachDebt. A substantive XDP Close failure deletes
// xdpLinks and carries no debt, yielding availability loss; a substantive TC
// Close failure retains tcLinks without debt for retry.
//
// detachDebt records exactly the retained XDP-link population: intended-
// detached + detach-failed + still tracked. The census skips debt members, so
// the armed forward fence closes the pinhole instead of re-opening it on every
// install. The daemon reinstalls the fence on every transit-gate reassert
// (1 Hz tick plus event wakes), so the pinhole closes at most one tick after
// the debt is recorded; no observer wake is needed.
//
// Lifecycle:
//   - set by DetachXDP on the flag-clear or substantive-Unpin failure return,
//     under the XDP ownership write lease it already holds; an
//     os.ErrNotExist Unpin result is benign and proceeds to Close;
//   - pre-acceptance attach fallback detaches in compiler.go and
//     attachUserspaceShimXDP may transiently add debt for interfaces the
//     pending snapshot still intends to attach. The next post-acceptance
//     reconciliation clears debt for allowed members; until then the census
//     omission is the fail-closed availability window;
//   - cleared by DetachXDP on the no-link no-op and on every entry delete
//     (success and close-failure alike: an untracked ifindex is already
//     absent from the census, so debt for it is meaningless);
//   - cleared for allowed+tracked ifindexes by the userspace reconciler,
//     which runs only AFTER the new snapshot becomes the retained authority;
//   - cleared wholesale by Teardown alongside the link maps.
//
// AttachXDP deliberately does NOT clear debt: attachment runs BEFORE the new
// snapshot acceptance boundary, so clearing there would reopen the fence for
// an interface the retained snapshot still intends detached if the later
// apply fails — the same ordering invariant #5485 protects. Only a detach
// outcome under the ownership lease, or the post-acceptance reconciliation,
// may move this set.
//
// Guarded by m.mu, not the ownership lease: AttachedXDPIfindexes holds no
// lease, so lease-guarded debt would be unreadable exactly where the fence
// needs it. Lock order is ownership-lease -> m.mu, matching the existing
// xdpLinkFor/deleteXDPLink calls DetachXDP already makes under the write
// lease and the RLock -> m.mu order withAttachedXDPFence takes.

// detachXDPFlagClearFn is a narrow test seam around the claim-cleanup step of
// DetachXDP. Tests inject a flag-clear failure to reach arm (a) — retained
// link, live kernel attachment — without a privileged BPF map; production
// uses setXDPAttachedFlag unchanged. Same shape as the xdpLinkIfindexFn
// kernel-truth seam: package var, default set here, tests restore via
// t.Cleanup.
var detachXDPFlagClearFn func(m *Manager, ifindex int, attached bool) error = (*Manager).setXDPAttachedFlag

// SetDetachXDPFlagClearFnForTest replaces the DetachXDP claim-cleanup seam and
// returns a restore function. It is intended only for unprivileged tests that
// need to exercise the flag-clear failure arm.
func SetDetachXDPFlagClearFnForTest(fn func(*Manager, int, bool) error) (restore func()) {
	old := detachXDPFlagClearFn
	if fn == nil {
		detachXDPFlagClearFn = (*Manager).setXDPAttachedFlag
	} else {
		detachXDPFlagClearFn = fn
	}
	return func() {
		detachXDPFlagClearFn = old
	}
}

// SetDetachDebtForTest seeds fail-closed detach debt without a kernel handle.
// It is a test seam for verifying the alarm's sticky outstanding-debt branch.
func (m *Manager) SetDetachDebtForTest(ifindex int) {
	m.noteDetachDebt(ifindex)
}

// noteDetachDebt records ifindex as intended-detached but detach-failed.
// Caller holds the XDP ownership write lease (DetachXDP); the set itself is
// m.mu-guarded for the lease-less census readers.
func (m *Manager) noteDetachDebt(ifindex int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.detachDebt == nil {
		m.detachDebt = make(map[int]struct{})
	}
	m.detachDebt[ifindex] = struct{}{}
}

// ReconcileDetachDebt clears debt for the interfaces the accepted snapshot
// still adjudicates and returns the sorted debt census after that clear. It
// is the single post-acceptance bridge used by the userspace reconciler:
// AttachXDP must not clear debt before acceptance (#5485), while the alarm
// needs a lease-free census to stay latched across a no-new-error pass.
func (m *Manager) ReconcileDetachDebt(allowed []int) []int {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	for _, ifindex := range allowed {
		delete(m.detachDebt, ifindex)
	}
	if len(m.detachDebt) == 0 {
		m.mu.Unlock()
		return nil
	}
	out := make([]int, 0, len(m.detachDebt))
	for ifindex := range m.detachDebt {
		out = append(out, ifindex)
	}
	m.mu.Unlock()
	sort.Ints(out)
	return out
}
