package dataplane

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf/link"
)

// #9725: the transit gate follows the attached links, so the LINKS report.
//
// The gate opens kernel transit only while the dataplane is armed AND a shim XDP
// program is attached (pkg/daemon/transit_closed_until_attach_9725.go). It used
// to learn the count only where a CALLER re-read it: after each ApplyConfig and
// at the apply tail. Three review rounds each found another path that changed the
// set without one — the deferred-MAC reapply, the #5485 reconcile that detaches
// inside an apply, a hitless Close, a bootstrap-rollback Teardown — and each was
// the same defect, because the CALL SITES are an open set and the WRITERS are
// not. The writers are setXDPLink, deleteXDPLink, Close and Teardown; each
// reports here, so a path added later reports without knowing the gate exists.
//
// WHAT THE OBSERVER IS TOLD is the count that holds AFTER the change, and the
// daemon acts on that number rather than reading back. Two reasons: the report
// can run while the caller holds a lock a read-back would need, and after Close
// the handles cannot answer at all — every Info() fails, so a read-back would
// say "nothing attached" even for a hitless upgrade whose pinned programs are
// still forwarding.
//
// A CLOSING change reports BEFORE it happens (DetachXDP, Close, Teardown),
// because the gate must close before the program stops adjudicating. An OPENING
// one reports after, because the link must exist first.
//
// NOT A SUBSCRIPTION. This says nothing about links the kernel detaches on its
// own: an unregistered device keeps its handle and its map entry and nothing
// here fires (#9848). AttachedXDPLinkCount still asks the kernel per link, so
// the next report from any writer drops such a link from the count.

// SetAttachedLinksObserver registers fn as the single observer of attached-link
// changes, replacing any previous one; nil clears it. The daemon registers the
// runtime it PUBLISHES and clears the one it unpublishes, which is what keeps
// this per-instance — a package-level callback lets one daemon's detach drive
// another daemon's gate when two exist in a process.
func (m *Manager) SetAttachedLinksObserver(fn func(int)) {
	if m == nil {
		return
	}
	if fn == nil {
		m.attachedLinksObserver.Store(nil)
		return
	}
	m.attachedLinksObserver.Store(&fn)
}

// notifyAttachedLinks reports n attached links to the observer, if one is
// registered. Callers must NOT hold m.mu: the observer does kernel work.
func (m *Manager) notifyAttachedLinks(n int) {
	if m == nil {
		return
	}
	if fn := m.attachedLinksObserver.Load(); fn != nil {
		(*fn)(n)
	}
}

// notifyAttachedLinksFunc reports count() to the observer, and calls count ONLY
// when one is registered. The count asks the kernel per link (Info), so this is
// not merely an optimisation: a writer must not do a kernel round trip whose
// result nobody consumes, and a link handle that cannot answer Info must not be
// interrogated by a writer that was not asked to report.
func (m *Manager) notifyAttachedLinksFunc(count func() int) {
	if m == nil {
		return
	}
	if fn := m.attachedLinksObserver.Load(); fn != nil {
		(*fn)(count())
	}
}

// attachedXDPLinkCountExcluding is AttachedXDPLinkCount without the link for
// ifindex: what the count becomes once that one is detached. DetachXDP reports
// it BEFORE it unpins and closes, so the gate closes while the program is still
// attached rather than after. It is also why a close ERROR needs no special
// case: the entry is removed either way, and the report already happened.
func (m *Manager) attachedXDPLinkCountExcluding(ifindex int) int {
	if m == nil {
		return 0
	}
	n := 0
	for idx, l := range m.XDPLinks() {
		if idx != ifindex && xdpLinkAttached(l) {
			n++
		}
	}
	return n
}

// survivingPinnedXDPLinkCount counts the attached links that outlive a Close:
// the ones whose bpffs pin still names THIS link. A pinned link stays attached
// with no process holding it, which is what makes a hitless restart hitless; an
// unpinned one is detached by the kernel when the last handle closes.
//
// The pin is best effort — AttachXDP logs a failed Pin at Warn and still returns
// success — and a stop landing between removeUserspaceShimXDPLinkPins and the
// re-attach, or after an attach that failed, finds live links with no pins. So
// Close cannot assume its links survive.
func (m *Manager) survivingPinnedXDPLinkCount() int {
	if m == nil {
		return 0
	}
	n := 0
	for ifindex, l := range m.XDPLinks() {
		if xdpLinkAttached(l) && xdpLinkPinSurvivesSeam(ifindex, l) {
			n++
		}
	}
	return n
}

// xdpLinkPinSurvivesSeam reports whether the pin for ifindex names the SAME
// kernel object as the link this Manager holds. Identity matters: a bare
// existence check is satisfied by a stale pin left by an earlier daemon, or by
// a different object pinned at that path after this link's own Pin failed, and
// either would claim a link survives a Close that actually detaches it.
//
// Tests replace only this lookup, because a fake link has no kernel object; the
// decision over its result stays production code, as with xdpLinkIfindexSeam.
var xdpLinkPinSurvivesSeam = func(ifindex int, held link.Link) bool {
	pinned, err := link.LoadPinnedLink(filepath.Join(linkPinPath, xdpLinkPinName(ifindex)), nil)
	if err != nil {
		return false
	}
	defer pinned.Close()
	heldInfo, heldErr := held.Info()
	pinnedInfo, pinnedErr := pinned.Info()
	if heldErr != nil || pinnedErr != nil {
		return false
	}
	return heldInfo.ID == pinnedInfo.ID
}

// xdpLinkPinName is the pin file name AttachXDP writes for ifindex. Shared so
// the pin the attach creates and the pin this check looks for cannot drift.
func xdpLinkPinName(ifindex int) string {
	return fmt.Sprintf("xdp_%d", ifindex)
}
