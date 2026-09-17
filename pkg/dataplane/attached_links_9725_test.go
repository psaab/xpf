package dataplane

import (
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf/link"
)

type countLink9725 struct{ link.Link }

func TestAttachedXDPLinkCountUsesKernelTruth9725(t *testing.T) {
	m := New()
	attached := &countLink9725{}
	detached := &countLink9725{}
	uncertain := &countLink9725{}
	m.SetLinkForTest(1, attached, nil)
	m.SetLinkForTest(2, detached, nil)
	m.SetLinkForTest(3, uncertain, nil)

	old := xdpLinkAttachedFn
	t.Cleanup(func() { xdpLinkAttachedFn = old })
	xdpLinkAttachedFn = func(l link.Link) bool {
		switch l {
		case attached:
			return true
		case detached, uncertain:
			return false
		default:
			return false
		}
	}
	if got := m.AttachedXDPLinkCount(); got != 1 {
		t.Fatalf("AttachedXDPLinkCount = %d, want one kernel-proven link", got)
	}
}

func TestAttachedLinksObserverIsWakeOnly9725(t *testing.T) {
	m := New()
	var wakes atomic.Int32
	m.SetAttachedLinksObserver(func() { wakes.Add(1) })
	m.setXDPLink(7, &countLink9725{})
	m.deleteXDPLink(7)
	if got := wakes.Load(); got != 2 {
		t.Fatalf("wake callback count = %d, want one wake for attach and detach", got)
	}
}
