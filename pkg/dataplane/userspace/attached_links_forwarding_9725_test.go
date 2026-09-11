package userspace

import (
	"testing"

	"github.com/cilium/ebpf/link"

	"github.com/psaab/xpf/pkg/dataplane"
)

type fakeLink9725 struct{ link.Link }

// TestTheAdapterForwardsTheAttachedLinkCount9725: the daemon publishes
// LegacyDataPlaneAdapter, and its #9725 transit gate opens only while the bpf
// shim holds an attached XDP link. A forwarder that drops or zeroes the count
// keeps kernel transit closed on every node.
func TestTheAdapterForwardsTheAttachedLinkCount9725(t *testing.T) {
	t.Cleanup(dataplane.CountEveryXDPLinkForTest())
	m := &Manager{bpfShim: dataplane.New()}
	adapter := NewLegacyDataPlaneAdapter(m)
	m.bpfShim.SetLinkForTest(3, fakeLink9725{}, nil)
	m.bpfShim.SetLinkForTest(4, fakeLink9725{}, nil)
	if got := adapter.AttachedXDPLinkCount(); got != 2 {
		t.Errorf("the adapter reports %d attached XDP links, want the shim's 2", got)
	}
	if got := NewLegacyDataPlaneAdapter(nil).AttachedXDPLinkCount(); got != 0 {
		t.Errorf("an adapter with no manager reports %d, want 0", got)
	}
	if got := (&Manager{}).AttachedXDPLinkCount(); got != 0 {
		t.Errorf("a manager with no shim reports %d, want 0", got)
	}
}

// closableLink9725 is a link DetachXDP can unpin and close, recording both.
type closableLink9725 struct {
	link.Link
	unpinned, closed int
}

func (l *closableLink9725) Unpin() error { l.unpinned++; return nil }
func (l *closableLink9725) Close() error { l.closed++; return nil }

// TestSyncInterfaceAttachmentsLowersTheAttachedLinkCount9725: the #5485 reconcile
// after a snapshot publish detaches the links of interfaces the snapshot no longer
// adjudicates. The #9725 gate must see that through the production path.
func TestSyncInterfaceAttachmentsLowersTheAttachedLinkCount9725(t *testing.T) {
	t.Cleanup(dataplane.CountEveryXDPLinkForTest())
	m := &Manager{bpfShim: dataplane.New()}
	obsolete, adjudicated := &closableLink9725{}, &closableLink9725{}
	m.bpfShim.SetLinkForTest(7, obsolete, nil)
	m.bpfShim.SetLinkForTest(8, adjudicated, nil)
	snap := &ConfigSnapshot{Interfaces: []InterfaceSnapshot{{Name: "ge-0-0-1", Ifindex: 8, Zone: "trust"}}}
	if got := buildUserspaceIngressIfindexes(snap); len(got) != 1 || got[0] != 8 {
		t.Fatalf("premise: the snapshot admits ingress on %v, want [8]", got)
	}

	m.syncInterfaceAttachments(&dataplane.CompileResult{}, snap)

	if got := m.AttachedXDPLinkCount(); got != 1 {
		t.Errorf("after the reconcile the count is %d, want 1: only ifindex 8 is still adjudicated", got)
	}
	if _, ok := m.bpfShim.XDPLinks()[8]; !ok || len(m.bpfShim.XDPLinks()) != 1 {
		t.Errorf("links left after the reconcile: %v, want only ifindex 8", m.bpfShim.XDPLinks())
	}
	if obsolete.closed != 1 || adjudicated.closed != 0 {
		t.Errorf("the reconcile closed the obsolete link %d times and the adjudicated one %d times, want 1 and 0",
			obsolete.closed, adjudicated.closed)
	}
}
