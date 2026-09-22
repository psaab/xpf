package dataplane

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf/link"
)

type detachDebtTestLink10519 struct {
	link.Link
	closeErr error
	closed   bool
	unpinned bool
}

func (l *detachDebtTestLink10519) Unpin() error {
	l.unpinned = true
	return nil
}

func (l *detachDebtTestLink10519) Close() error {
	l.closed = true
	return l.closeErr
}

func installDetachDebtIfindexProbe10519(t *testing.T, want link.Link, ifindex int) {
	t.Helper()
	old := xdpLinkIfindexFn
	t.Cleanup(func() { xdpLinkIfindexFn = old })
	xdpLinkIfindexFn = func(got link.Link) (int, bool) {
		if got == want {
			return ifindex, true
		}
		return 0, false
	}
}

// T1: arm (a), IFACE_FLAG_XDP_ATTACHED claim cleanup failure. The link stays
// tracked and kernel-proven, but detach debt removes it from both fence census
// paths. Clearing the injected fault and retrying recovers the link and debt.
func TestDetachXDPFlagClearFailureClosesFenceAndRecovers10519(t *testing.T) {
	const ifindex = 10519
	m := New()
	l := &detachDebtTestLink10519{}
	m.SetLinkForTest(ifindex, l, nil)
	installDetachDebtIfindexProbe10519(t, l, ifindex)

	oldClear := detachXDPFlagClearFn
	t.Cleanup(func() { detachXDPFlagClearFn = oldClear })
	injected := errors.New("injected IFACE_FLAG_XDP_ATTACHED clear failure")
	detachXDPFlagClearFn = func(*Manager, int, bool) error { return injected }

	err := m.DetachXDP(ifindex)
	if err == nil || !strings.Contains(err.Error(), "clear flag") || !errors.Is(err, injected) {
		t.Fatalf("DetachXDP error = %v, want clear-flag wrapper containing injected fault", err)
	}
	if _, ok := m.XDPLinks()[ifindex]; !ok {
		t.Fatal("arm-(a) failure removed xdpLinks entry; retry state was not retained")
	}
	if got := m.ReconcileDetachDebt(nil); len(got) != 1 || got[0] != ifindex {
		t.Fatalf("detach debt = %v, want [%d]", got, ifindex)
	}
	if got := m.AttachedXDPIfindexes(); len(got) != 0 {
		t.Fatalf("AttachedXDPIfindexes = %v, want debt member omitted", got)
	}
	if err := WithAttachedXDPFence(m, func(got []int) error {
		if len(got) != 0 {
			t.Fatalf("WithAttachedXDPFence census = %v, want debt member omitted", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithAttachedXDPFence: %v", err)
	}

	// Recovery is the existing next reconciliation pass, not a synchronous
	// retry loop inside DetachXDP.
	detachXDPFlagClearFn = func(m *Manager, i int, attached bool) error {
		return m.setXDPAttachedFlag(i, attached)
	}
	if err := m.DetachXDP(ifindex); err != nil {
		t.Fatalf("DetachXDP recovery: %v", err)
	}
	if _, ok := m.XDPLinks()[ifindex]; ok {
		t.Fatal("successful retry retained xdpLinks entry")
	}
	if got := m.ReconcileDetachDebt(nil); len(got) != 0 {
		t.Fatalf("detach debt after recovery = %v, want empty", got)
	}
	if !l.closed || !l.unpinned {
		t.Fatalf("recovered link lifecycle = closed:%v unpinned:%v, want both", l.closed, l.unpinned)
	}
}

// T2: arm (b), link Close failure. The link registry is deleted before the
// error is returned, so the fence omits the ifindex both before and after the
// fix; this pins the fail-closed availability-loss shape.
func TestDetachXDPCloseFailureRemovesFenceCandidate10519(t *testing.T) {
	const ifindex = 10520
	m := New()
	l := &detachDebtTestLink10519{closeErr: errors.New("injected link close failure")}
	m.SetLinkForTest(ifindex, l, nil)
	installDetachDebtIfindexProbe10519(t, l, ifindex)

	err := m.DetachXDP(ifindex)
	if err == nil || !strings.Contains(err.Error(), "detach XDP from ifindex 10520") || !errors.Is(err, l.closeErr) {
		t.Fatalf("DetachXDP close error = %v, want indexed close failure", err)
	}
	if _, ok := m.XDPLinks()[ifindex]; ok {
		t.Fatal("close failure retained xdpLinks entry; fence would not fail closed")
	}
	if got := m.AttachedXDPIfindexes(); len(got) != 0 {
		t.Fatalf("AttachedXDPIfindexes = %v, want close-failure candidate omitted", got)
	}
	if got := m.ReconcileDetachDebt(nil); len(got) != 0 {
		t.Fatalf("detach debt after close failure = %v, want empty", got)
	}
}

// T6: TC retains its link on Close failure and returns the error. A healthy
// second pass removes it, preserving TC's existing retryable lifecycle shape
// while D1/D2 make the failure observable to the userspace reconciler.
func TestDetachTCCloseFailureRetainsAndRecovers10519(t *testing.T) {
	const ifindex = 10521
	m := New()
	closeErr := errors.New("injected TC close failure")
	l := &detachDebtTestLink10519{closeErr: closeErr}
	m.SetLinkForTest(ifindex, nil, l)

	if err := m.DetachTC(ifindex); err == nil || !strings.Contains(err.Error(), "detach TC from ifindex 10521") || !errors.Is(err, closeErr) {
		t.Fatalf("DetachTC error = %v, want indexed close failure", err)
	}
	if _, ok := m.TCLinks()[ifindex]; !ok {
		t.Fatal("TC close failure deleted tcLinks entry; retry state was not retained")
	}
	l.closeErr = nil
	if err := m.DetachTC(ifindex); err != nil {
		t.Fatalf("DetachTC recovery: %v", err)
	}
	if _, ok := m.TCLinks()[ifindex]; ok {
		t.Fatal("successful TC retry retained tcLinks entry")
	}
}
