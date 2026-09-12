package dataplane

import (
	"testing"

	"github.com/cilium/ebpf/link"
)

// UnpinnedAttachedXDPLinks decides whether a hitless stop may leave kernel
// transit open, so it must count exactly the links that do NOT survive a Close:
// still attached, and carrying no pin. Counting too many closes transit on a
// genuine hitless upgrade; counting too few leaves the node forwarding under no
// policy for the whole downtime.
func TestUnpinnedAttachedXDPLinksCountsOnlyLiveUnpinnedLinks9725(t *testing.T) {
	countEveryLink9725(t)
	m := newRaceManager6740()
	m.SetLinkForTest(7, fakeLink6740{}, nil)
	m.SetLinkForTest(9, fakeLink6740{}, nil)
	m.SetLinkForTest(11, nil, fakeLink6740{}) // a TC link is not an XDP link

	restore := SetXDPLinkPinnedForTest(map[int]bool{7: true})
	if got := m.UnpinnedAttachedXDPLinks(); got != 1 {
		t.Errorf("with ifindex 7 pinned and 9 not, the unpinned count is %d, want 1", got)
	}
	if got := m.AttachedXDPLinkCount(); got != 2 {
		t.Errorf("control: the attached count is %d, want 2 — the pin lookup must not change what is ATTACHED", got)
	}
	restore()

	restore = SetXDPLinkPinnedForTest(map[int]bool{7: true, 9: true})
	if got := m.UnpinnedAttachedXDPLinks(); got != 0 {
		t.Errorf("with every attached link pinned the unpinned count is %d, want 0: a hitless stop must leave "+
			"forwarding alone, because these links outlive the process", got)
	}
	restore()

	restore = SetXDPLinkPinnedForTest(nil)
	if got := m.UnpinnedAttachedXDPLinks(); got != 2 {
		t.Errorf("with no pins at all the unpinned count is %d, want 2", got)
	}
	restore()

	var none *Manager
	if got := none.UnpinnedAttachedXDPLinks(); got != 0 {
		t.Errorf("a nil Manager reports %d unpinned, want 0", got)
	}
}

// A link the kernel has already detached is not forwarding anything, so it must
// not be counted as unpinned either — otherwise a node whose NIC went away would
// close transit on an otherwise genuine hitless stop for a link that is not
// there. This is the same kernel read AttachedXDPLinkCount makes.
func TestAKernelDetachedLinkIsNotCountedAsUnpinned9725(t *testing.T) {
	m := newRaceManager6740()
	m.SetLinkForTest(7, fakeLink6740{}, nil)
	m.SetLinkForTest(9, fakeLink6740{}, nil)

	prev := xdpLinkIfindexSeam
	t.Cleanup(func() { xdpLinkIfindexSeam = prev })
	// One of the two reads live and the other reports ifindex 0, the shape an
	// unregistered device gives. WHICH one is unspecified: XDPLinks returns a map
	// and its iteration order is random. The assertion holds either way, because
	// exactly one live unpinned link remains in both orders.
	seen := 0
	xdpLinkIfindexSeam = func(l link.Link) (uint32, error) {
		seen++
		if seen == 1 {
			return 1, nil
		}
		return 0, nil
	}
	restore := SetXDPLinkPinnedForTest(nil) // neither is pinned
	t.Cleanup(restore)

	if got := m.UnpinnedAttachedXDPLinks(); got != 1 {
		t.Errorf("with one live unpinned link and one the kernel detached, the unpinned count is %d, want 1", got)
	}
}
