package dataplane

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/link"
)

// TestAttachedXDPLinkCountReadsTheLiveLinkMap9725: the #9725 transit gate opens on
// this count, so it must follow the link map both ways. A recorded link raises
// it, and a removed one lowers it.
func TestAttachedXDPLinkCountReadsTheLiveLinkMap9725(t *testing.T) {
	countEveryLink9725(t)
	m := newRaceManager6740()
	if got := m.AttachedXDPLinkCount(); got != 0 {
		t.Fatalf("a Manager with no links reports %d attached, want 0", got)
	}
	m.SetLinkForTest(7, fakeLink6740{}, nil)
	m.SetLinkForTest(9, fakeLink6740{}, nil)
	m.SetLinkForTest(11, nil, fakeLink6740{})
	if got := m.AttachedXDPLinkCount(); got != 2 {
		t.Errorf("after two XDP links and one TC link the count is %d, want 2", got)
	}
	m.deleteXDPLink(7)
	if got := m.AttachedXDPLinkCount(); got != 1 {
		t.Errorf("after one detach the count is %d, want 1", got)
	}
	var none *Manager
	if got := none.AttachedXDPLinkCount(); got != 0 {
		t.Errorf("a nil Manager reports %d attached, want 0", got)
	}
}

// closableLink9725 is a link DetachXDP can unpin and close, recording both.
type closableLink9725 struct {
	link.Link
	unpinned, closed int
}

func (l *closableLink9725) Unpin() error { l.unpinned++; return nil }
func (l *closableLink9725) Close() error { l.closed++; return nil }

// countEveryLink9725 treats every recorded link as kernel-attached, for cells about
// the map rather than the kernel.
func countEveryLink9725(t *testing.T) {
	t.Helper()
	t.Cleanup(CountEveryXDPLinkForTest())
}

// TestDetachXDPLowersTheAttachedLinkCount9725: the production detach path, not a
// direct map delete, must lower the count the #9725 gate reads, and must detach
// the link it was asked to.
func TestDetachXDPLowersTheAttachedLinkCount9725(t *testing.T) {
	countEveryLink9725(t)
	m := newRaceManager6740()
	gone, kept := &closableLink9725{}, &closableLink9725{}
	m.SetLinkForTest(7, gone, nil)
	m.SetLinkForTest(9, kept, nil)
	if err := m.DetachXDP(7); err != nil {
		t.Fatalf("DetachXDP: %v", err)
	}

	if got := m.AttachedXDPLinkCount(); got != 1 {
		t.Errorf("after DetachXDP of one of two links the count is %d, want 1", got)
	}
	if _, ok := m.XDPLinks()[9]; !ok || len(m.XDPLinks()) != 1 {
		t.Errorf("links left after DetachXDP(7): %v, want only ifindex 9", m.XDPLinks())
	}
	if gone.unpinned != 1 || gone.closed != 1 {
		t.Errorf("the detached link was unpinned %d and closed %d times, want once each", gone.unpinned, gone.closed)
	}
	if kept.unpinned != 0 || kept.closed != 0 {
		t.Errorf("the kept link was unpinned %d and closed %d times, want never", kept.unpinned, kept.closed)
	}
}

// kernelRead9725 is what the faked kernel read returns for one link.
type kernelRead9725 struct {
	ifindex uint32
	err     error
}

// TestALinkTheKernelDetachedIsNotCounted9725: when a device is unregistered, the
// kernel detaches its XDP program, and the bpf_link reports ifindex 0, while
// xpfd's handle and map entry survive. The #9725 gate must not count that link,
// nor a link whose info it cannot read. Only the kernel read is faked; the
// decision over it is the production one.
func TestALinkTheKernelDetachedIsNotCounted9725(t *testing.T) {
	m := newRaceManager6740()
	live, detached, unreadable := &closableLink9725{}, &closableLink9725{}, &closableLink9725{}
	m.SetLinkForTest(7, live, nil)
	m.SetLinkForTest(9, detached, nil)
	m.SetLinkForTest(11, unreadable, nil)
	// The unreadable link reports a nonzero ifindex beside its error, so a
	// decision that ignored the error would count it.
	kernel := map[link.Link]kernelRead9725{
		live:       {ifindex: 7},
		detached:   {ifindex: 0},
		unreadable: {ifindex: 11, err: errors.New("synthetic link info failure (#9725 test)")},
	}
	prev := xdpLinkIfindexSeam
	t.Cleanup(func() { xdpLinkIfindexSeam = prev })
	xdpLinkIfindexSeam = func(l link.Link) (uint32, error) {
		r := kernel[l]
		return r.ifindex, r.err
	}

	if got := m.AttachedXDPLinkCount(); got != 1 {
		t.Errorf("with one live link, one the kernel detached and one whose info fails, the count is %d, want 1", got)
	}
	kernel[live] = kernelRead9725{ifindex: 0}
	if got := m.AttachedXDPLinkCount(); got != 0 {
		t.Errorf("with every link detached by the kernel or unreadable, the count is %d, want 0", got)
	}
}
