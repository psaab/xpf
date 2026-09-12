package dataplane

import (
	"errors"
	"sync"
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

// reportOrderLink9725 records how many reports had ARRIVED by the time the
// kernel detach (its Close) ran. The pre-detach report exists precisely so the
// gate closes while the program is still adjudicating, and that is an ordering
// property no count assertion can see.
type reportOrderLink9725 struct {
	link.Link
	reportsAtClose int
	seen           func() int
}

func (l *reportOrderLink9725) Unpin() error { return nil }
func (l *reportOrderLink9725) Close() error {
	if l.seen != nil {
		l.reportsAtClose = l.seen()
	}
	return nil
}

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

		// Each detach reports TWICE: "the count without me" before the kernel
		// detach, so the gate closes while the program still adjudicates, and the
		// true count after the map deletion, so that under concurrent detaches
		// some report actually carries the final state. Uncontended they agree.
		if err := m.DetachXDP(7); err != nil {
			t.Fatalf("DetachXDP(7): %v", err)
		}
		if len(reports) == 0 || reports[0] != 1 || reports[len(reports)-1] != 1 {
			t.Fatalf("detaching one of two links reported %v, want it to open and close on 1", reports)
		}
		if err := m.DetachXDP(9); err != nil {
			t.Fatalf("DetachXDP(9): %v", err)
		}
		if reports[len(reports)-1] != 0 {
			t.Errorf("detaching the LAST link reported %v, want the final report to be 0 — the gate closes on "+
				"that number, and the pre-detach report must arrive before the program stops adjudicating", reports)
		}
	})

	t.Run("the report reaches the gate BEFORE the kernel detach", func(t *testing.T) {
		countEveryLink9725(t)
		m := newRaceManager6740()
		var mu sync.Mutex
		var reports []int
		l := &reportOrderLink9725{seen: func() int {
			mu.Lock()
			defer mu.Unlock()
			return len(reports)
		}}
		m.SetLinkForTest(7, l, nil)
		defer m.setAttachedLinksObserverForTest(func(n int) {
			mu.Lock()
			reports = append(reports, n)
			mu.Unlock()
		})()

		if err := m.DetachXDP(7); err != nil {
			t.Fatalf("DetachXDP: %v", err)
		}
		if l.reportsAtClose == 0 {
			t.Errorf("#9725: the kernel detach ran with NO report delivered yet (reports by then: %d, all: %v). "+
				"A closing change must report before the program stops adjudicating, or transit stays open "+
				"across the detach", l.reportsAtClose, reports)
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
		if len(reports) == 0 || reports[0] != 0 || reports[len(reports)-1] != 0 {
			t.Errorf("#9725: a detach whose Close errored reported %v, want every report 0. The map entry is "+
				"removed either way, so a report conditioned on success leaves the gate open with nothing "+
				"attached", reports)
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

// #9725 round 12: two concurrent detaches each compute "the count without me"
// and then report. Unserialised, the HIGHER count can be delivered last, and the
// gate is left open on a number that no longer describes anything. The last
// report must be the one computed last — here, zero.
func TestConcurrentDetachesLeaveTheLastReportAccurate9725(t *testing.T) {
	countEveryLink9725(t)
	for range 50 {
		m := newRaceManager6740()
		const links = 4
		// Every link parks inside Close until all four have entered, so every
		// PRE-detach report ("the count without me") is computed while the map
		// still holds all four. Without the post-deletion report the final report
		// is then 3, deterministically, rather than by luck.
		var entered sync.WaitGroup
		entered.Add(links)
		release := make(chan struct{})
		for i := range links {
			m.SetLinkForTest(i+1, &barrierLink9725{entered: &entered, release: release}, nil)
		}
		var mu sync.Mutex
		var reports []int
		defer m.setAttachedLinksObserverForTest(func(n int) {
			mu.Lock()
			reports = append(reports, n)
			mu.Unlock()
		})()

		var wg sync.WaitGroup
		for i := range links {
			wg.Add(1)
			go func(ifindex int) { defer wg.Done(); _ = m.DetachXDP(ifindex) }(i + 1)
		}
		entered.Wait() // all four are inside Close, all pre-reports are in
		close(release)
		wg.Wait()

		mu.Lock()
		got := append([]int(nil), reports...)
		mu.Unlock()
		// Each detach reports twice: "the count without me" before the kernel
		// detach (fail-closed), and the true count after its map deletion. The
		// number of reports is therefore not the assertion — the LAST one is.
		if len(got) == 0 {
			t.Fatalf("no reports for %d detaches", links)
		}
		for _, n := range got {
			if n < 0 || n > links {
				t.Fatalf("report %d out of range for %d links: %v", n, links, got)
			}
		}
		if got[len(got)-1] != 0 {
			t.Fatalf("#9725: the LAST report after detaching every link was %d, want 0 (all reports: %v). "+
				"The gate acts on the last number it is given, so a stale higher count leaves kernel transit "+
				"open with nothing attached", got[len(got)-1], got)
		}
		if n := m.AttachedXDPLinkCount(); n != 0 {
			t.Fatalf("control: %d links still attached after detaching all %d", n, links)
		}
	}
}

// barrierLink9725 parks inside Close until every link has entered, then releases
// together. It makes the concurrent-detach interleaving deterministic instead of
// leaving it to the scheduler.
type barrierLink9725 struct {
	link.Link
	entered *sync.WaitGroup
	release chan struct{}
	once    sync.Once
}

func (l *barrierLink9725) Unpin() error { return nil }
func (l *barrierLink9725) Close() error {
	l.once.Do(func() {
		l.entered.Done()
		<-l.release
	})
	return nil
}
