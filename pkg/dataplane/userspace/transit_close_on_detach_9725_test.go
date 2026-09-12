package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9725: the #5485 attachment reconcile runs INSIDE ApplyConfig and can remove
// the last shim XDP link. The daemon re-reads the transit gate only when
// ApplyConfig returns, several fallible control steps later, so without this
// hook kernel transit stayed open with nothing attached for that whole interval.
//
// The three rows differ only in what the snapshot adjudicates, so a hook that
// fires unconditionally fails rows 2 and 3, and no hook at all fails row 1.
func TestTheReconcileClosesTransitWhenItDetachesTheLastLink9725(t *testing.T) {
	for _, tc := range []struct {
		name      string
		links     []int
		adjudicat []int
		wantCalls []string
	}{
		{
			name:      "the reconcile detaches the last link",
			links:     []int{7},
			adjudicat: nil,
			wantCalls: []string{"apply-detach"},
		},
		{
			name:      "a link is still attached afterwards",
			links:     []int{7, 8},
			adjudicat: []int{8},
			wantCalls: nil,
		},
		{
			name:      "the reconcile detaches nothing",
			links:     []int{8},
			adjudicat: []int{8},
			wantCalls: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(dataplane.CountEveryXDPLinkForTest())
			m := &Manager{bpfShim: dataplane.New()}
			for _, idx := range tc.links {
				m.bpfShim.SetLinkForTest(idx, &closableLink9725{}, nil)
			}
			snap := &ConfigSnapshot{}
			for _, idx := range tc.adjudicat {
				snap.Interfaces = append(snap.Interfaces,
					InterfaceSnapshot{Name: "ge-0-0-1", Ifindex: idx, Zone: "trust"})
			}

			var calls []string
			restore := SetTransitCloseOnLastDetachForTest(func(stage string) {
				calls = append(calls, stage)
			})
			t.Cleanup(restore)

			m.syncInterfaceAttachments(&dataplane.CompileResult{}, snap)

			if len(calls) != len(tc.wantCalls) {
				t.Fatalf("#9725: the reconcile closed transit %v, want %v. It must close the gate the moment "+
					"the last link goes, not leave it open until ApplyConfig returns past the helper-status, "+
					"HA-state and forwarding steps", calls, tc.wantCalls)
			}
			for i := range calls {
				if calls[i] != tc.wantCalls[i] {
					t.Errorf("close stage %d = %q, want %q", i, calls[i], tc.wantCalls[i])
				}
			}
			if got, want := m.AttachedXDPLinkCount(), len(tc.adjudicat); got != want {
				t.Errorf("control: %d link(s) attached after the reconcile, want %d", got, want)
			}
		})
	}
}

// A hook that is never wired closes nothing, which is the pre-#9725 behaviour —
// pinned so an unwired build degrades quietly rather than panicking.
func TestTheReconcileWithNoTransitHookIsANoOp9725(t *testing.T) {
	t.Cleanup(dataplane.CountEveryXDPLinkForTest())
	t.Cleanup(SetTransitCloseOnLastDetachForTest(nil))
	m := &Manager{bpfShim: dataplane.New()}
	m.bpfShim.SetLinkForTest(7, &closableLink9725{}, nil)
	m.syncInterfaceAttachments(&dataplane.CompileResult{}, &ConfigSnapshot{})
	if got := m.AttachedXDPLinkCount(); got != 0 {
		t.Errorf("the reconcile left %d link(s) attached, want 0", got)
	}
}

// #9804: a capability the adapter does not forward is invisible to the daemon,
// and the daemon reads the unpinned count through the ADAPTER it publishes. A
// missing forwarder would read 0 forever — indistinguishable from "every link is
// pinned", which is exactly the answer that leaves transit open.
func TestTheAdapterForwardsTheUnpinnedLinkCount9725(t *testing.T) {
	t.Cleanup(dataplane.CountEveryXDPLinkForTest())
	m := &Manager{bpfShim: dataplane.New()}
	m.bpfShim.SetLinkForTest(7, &closableLink9725{}, nil)
	t.Cleanup(dataplane.SetXDPLinkPinnedForTest(nil))

	a := NewLegacyDataPlaneAdapter(m)
	if got := a.UnpinnedAttachedXDPLinks(); got != 1 {
		t.Errorf("the adapter reports %d unpinned attached link(s), want 1: the daemon's hitless stop reads "+
			"this through the adapter, and an unforwarded capability reads 0 — the same answer as \"all pinned\"", got)
	}

	var none *LegacyDataPlaneAdapter
	if got := none.UnpinnedAttachedXDPLinks(); got != 0 {
		t.Errorf("a nil adapter reports %d, want 0", got)
	}
}
