package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9804: the daemon publishes the ADAPTER, not the manager, so a capability the
// adapter does not forward is invisible. For the #9725 observer that is silent
// in the worst way: no link change ever reaches the gate, and every window this
// issue closes is open again with nothing to show for it.
func TestTheAdapterForwardsTheAttachedLinksObserver9725(t *testing.T) {
	t.Cleanup(dataplane.CountEveryXDPLinkForTest())
	m := &Manager{bpfShim: dataplane.New()}
	a := NewLegacyDataPlaneAdapter(m)

	var reports []int
	a.SetAttachedLinksObserver(func(n int) { reports = append(reports, n) })

	m.bpfShim.SetLinkForTest(7, &closableLink9725{}, nil)
	if err := m.bpfShim.DetachXDP(7); err != nil {
		t.Fatalf("DetachXDP: %v", err)
	}
	if len(reports) != 1 || reports[0] != 0 {
		t.Errorf("detaching the last link through the adapter-registered observer reported %v, want [0]", reports)
	}

	// Clearing must reach the shim too, or a dropped runtime keeps reporting.
	a.SetAttachedLinksObserver(nil)
	m.bpfShim.SetLinkForTest(9, &closableLink9725{}, nil)
	if err := m.bpfShim.DetachXDP(9); err != nil {
		t.Fatalf("DetachXDP: %v", err)
	}
	if len(reports) != 1 {
		t.Errorf("after clearing, the observer still received %v", reports)
	}

	var none *LegacyDataPlaneAdapter
	none.SetAttachedLinksObserver(func(int) {})
}
