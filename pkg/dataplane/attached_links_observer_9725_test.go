package dataplane

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/link"
)

// setXDPLinkPinSurvivesForTest makes the pin check answer true for exactly the
// given ifindexes, and returns the function that restores the previous lookup.
// Unexported and in the test file: only this package's cells use it, and the
// #7191 pre-arm census counts every EXPORTED *Manager method.
func setXDPLinkPinSurvivesForTest(surviving map[int]bool) (restore func()) {
	prev := xdpLinkPinSurvivesSeam
	xdpLinkPinSurvivesSeam = func(ifindex int, _ link.Link) bool { return surviving[ifindex] }
	return func() { xdpLinkPinSurvivesSeam = prev }
}

// setAttachedLinksObserverForTest registers fn and returns the restore func.
func (m *Manager) setAttachedLinksObserverForTest(fn func(int)) (restore func()) {
	prev := m.attachedLinksObserver.Load()
	m.SetAttachedLinksObserver(fn)
	return func() { m.attachedLinksObserver.Store(prev) }
}

// erroringCloseLink9725 closes with an error but is still removed from the map,
// which is what DetachXDP does deliberately so a stuck-close link cannot make a
// retry loop forever.
type erroringCloseLink9725 struct {
	link.Link
	unpinned, closed int
}

func (l *erroringCloseLink9725) Unpin() error { l.unpinned++; return nil }
func (l *erroringCloseLink9725) Close() error { l.closed++; return errors.New("stuck close") }

// The WRITERS report, because the call sites are an open set and the writers are
// not. Three review rounds each found a different call site that changed the
// attached set without re-reading the gate; this is the property that makes a
// path added later report without knowing the gate exists.
func TestTheLinkWritersReportTheAttachedCount9725(t *testing.T) {
	t.Run("a detach reports the count it LEAVES, before it closes", func(t *testing.T) {
		countEveryLink9725(t)
		m := newRaceManager6740()
		m.SetLinkForTest(7, &closableLink9725{}, nil)
		m.SetLinkForTest(9, &closableLink9725{}, nil)

		var reports []int
		defer m.setAttachedLinksObserverForTest(func(n int) { reports = append(reports, n) })()

		if err := m.DetachXDP(7); err != nil {
			t.Fatalf("DetachXDP(7): %v", err)
		}
		if len(reports) != 1 || reports[0] != 1 {
			t.Fatalf("detaching one of two links reported %v, want [1]", reports)
		}
		if err := m.DetachXDP(9); err != nil {
			t.Fatalf("DetachXDP(9): %v", err)
		}
		if len(reports) != 2 || reports[1] != 0 {
			t.Errorf("detaching the LAST link reported %v, want the second report to be 0 — the gate closes on "+
				"that number, and it must arrive before the program stops adjudicating", reports)
		}
	})

	t.Run("a detach whose Close FAILS still reports", func(t *testing.T) {
		countEveryLink9725(t)
		m := newRaceManager6740()
		stuck := &erroringCloseLink9725{}
		m.SetLinkForTest(7, stuck, nil)

		var reports []int
		defer m.setAttachedLinksObserverForTest(func(n int) { reports = append(reports, n) })()

		err := m.DetachXDP(7)
		if err == nil {
			t.Fatalf("premise: this link's Close must fail, so the report cannot depend on success")
		}
		if _, still := m.XDPLinks()[7]; still {
			t.Fatalf("premise: DetachXDP removes the map entry even when Close errors")
		}
		if len(reports) != 1 || reports[0] != 0 {
			t.Errorf("#9725: a detach whose Close errored reported %v, want [0]. The map entry is removed either "+
				"way, so a report conditioned on success leaves the gate open with nothing attached", reports)
		}
	})

	t.Run("an attach reports AFTER the link exists", func(t *testing.T) {
		countEveryLink9725(t)
		m := newRaceManager6740()
		var reports []int
		defer m.setAttachedLinksObserverForTest(func(n int) { reports = append(reports, n) })()

		m.setXDPLink(7, &closableLink9725{})
		if len(reports) != 1 || reports[0] != 1 {
			t.Errorf("recording a link reported %v, want [1]: an opening change reports after the link exists", reports)
		}
	})

	t.Run("Close reports what SURVIVES it", func(t *testing.T) {
		countEveryLink9725(t)
		for _, tc := range []struct {
			name      string
			surviving map[int]bool
			want      int
		}{
			{"both links survive: a hitless upgrade", map[int]bool{7: true, 9: true}, 2},
			{"one pin does not name its link", map[int]bool{7: true}, 1},
			{"nothing survives", nil, 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				m := newRaceManager6740()
				m.SetLinkForTest(7, &closableLink9725{}, nil)
				m.SetLinkForTest(9, &closableLink9725{}, nil)
				defer setXDPLinkPinSurvivesForTest(tc.surviving)()

				var reports []int
				defer m.setAttachedLinksObserverForTest(func(n int) { reports = append(reports, n) })()

				m.Close()
				if len(reports) != 1 || reports[0] != tc.want {
					t.Errorf("Close reported %v, want exactly [%d]. After Close no handle can answer, so the daemon "+
						"acts on this number rather than reading back — and a second, different report would move "+
						"the gate off it", reports, tc.want)
				}
			})
		}
	})

	t.Run("Teardown reports zero, because it destroys the pinned objects", func(t *testing.T) {
		countEveryLink9725(t)
		m := newRaceManager6740()
		m.SetLinkForTest(7, &closableLink9725{}, nil)
		// Every pin would otherwise say the link survives; Teardown must still
		// report zero, because Cleanup destroys the pinned objects themselves.
		defer setXDPLinkPinSurvivesForTest(map[int]bool{7: true})()

		var reports []int
		defer m.setAttachedLinksObserverForTest(func(n int) { reports = append(reports, n) })()

		m.Teardown()
		// The WHOLE sequence, not just the first report. Teardown used to report 0
		// and then call Close, which reported the survivors it still saw — so the
		// gate reopened in the middle of a teardown that was about to destroy
		// those very pins, and an assertion on reports[0] alone passed anyway.
		if len(reports) != 1 || reports[0] != 0 {
			t.Errorf("Teardown reported %v, want exactly [0]. Any later non-zero report reopens kernel transit "+
				"while the teardown is destroying the pinned objects that report claims are surviving", reports)
		}
	})

	t.Run("no observer registered is a no-op", func(t *testing.T) {
		countEveryLink9725(t)
		m := newRaceManager6740()
		m.SetLinkForTest(7, &closableLink9725{}, nil)
		if err := m.DetachXDP(7); err != nil {
			t.Errorf("DetachXDP with no observer: %v", err)
		}
		var none *Manager
		none.notifyAttachedLinks(0)
	})
}
