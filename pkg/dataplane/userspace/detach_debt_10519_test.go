package userspace

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/psaab/xpf/pkg/dataplane"
)

type reconcilerLink10519 struct {
	link.Link
	closeErr error
}

func (l *reconcilerLink10519) Unpin() error { return nil }
func (l *reconcilerLink10519) Close() error { return l.closeErr }

// T3: the reconciler joins XDP and TC errors, stamps every failing ifindex,
// and the acceptance caller records a sticky alarm plus LastApplyResult. A
// healthy subsequent pass clears both the per-apply field and the alarm.
func TestSyncInterfaceAttachmentsSurfacesAndRecovers10519(t *testing.T) {
	const xdpIfindex, tcIfindex = 10522, 10523
	m := New()
	xdpErr := errors.New("injected XDP close failure")
	tcErr := errors.New("injected TC close failure")
	m.bpfShim.SetLinkForTest(xdpIfindex, &reconcilerLink10519{closeErr: xdpErr}, nil)
	tcLink := &reconcilerLink10519{closeErr: tcErr}
	m.bpfShim.SetLinkForTest(tcIfindex, nil, tcLink)

	result := &dataplane.CompileResult{}
	want := []int{xdpIfindex, tcIfindex}
	err := m.syncInterfaceAttachments(result, &ConfigSnapshot{})
	if err == nil || !errors.Is(err, xdpErr) || !errors.Is(err, tcErr) {
		t.Fatalf("syncInterfaceAttachments error = %v, want joined XDP and TC failures", err)
	}
	if !reflect.DeepEqual(result.DetachedWithErrors, want) {
		t.Fatalf("DetachedWithErrors = %v, want %v", result.DetachedWithErrors, want)
	}
	apply := dataplane.ApplyResultFromCompileResult(result)
	if apply == nil || !reflect.DeepEqual(apply.DetachedWithErrors, want) {
		t.Fatalf("ApplyResult DetachedWithErrors = %v, want %v", apply.DetachedWithErrors, want)
	}
	apply.DetachedWithErrors[0] = -1
	if result.DetachedWithErrors[0] == -1 {
		t.Fatal("ApplyResult reused CompileResult DetachedWithErrors backing array")
	}
	apply.DetachedWithErrors = append([]int(nil), want...)

	m.mu.Lock()
	m.noteDetachDebtLocked(result, err)
	m.recordApplyResultLocked(apply, UserspaceCapabilities{}, 1)
	alarm := m.detachDebtAlarm
	m.mu.Unlock()
	if alarm == "" || !strings.Contains(alarm, "obsolete ifindex") {
		t.Fatalf("detachDebtAlarm = %q, want sticky indexed reconciliation error", alarm)
	}
	if got := m.LastApplyResult(); got == nil || !reflect.DeepEqual(got.DetachedWithErrors, want) {
		t.Fatalf("LastApplyResult().DetachedWithErrors = %v, want %v", got.DetachedWithErrors, want)
	}

	// The XDP close-failure entry was deleted (arm b), while TC retained its
	// entry and now recovers on the next compile pass.
	tcLink.closeErr = nil
	result = &dataplane.CompileResult{}
	if err := m.syncInterfaceAttachments(result, &ConfigSnapshot{}); err != nil {
		t.Fatalf("recovery syncInterfaceAttachments: %v", err)
	}
	if len(result.DetachedWithErrors) != 0 {
		t.Fatalf("recovery DetachedWithErrors = %v, want empty", result.DetachedWithErrors)
	}
	m.mu.Lock()
	m.noteDetachDebtLocked(result, nil)
	m.recordApplyResultLocked(dataplane.ApplyResultFromCompileResult(result), UserspaceCapabilities{}, 2)
	alarm = m.detachDebtAlarm
	m.mu.Unlock()
	if alarm != "" {
		t.Fatalf("detachDebtAlarm after recovery = %q, want clear", alarm)
	}
	if got := m.LastApplyResult(); got == nil || len(got.DetachedWithErrors) != 0 {
		t.Fatalf("LastApplyResult after recovery = %+v, want no detach errors", got)
	}
}

// T5: a configured row that is present for binding/RSS but absent from the
// ingress-adjudication set must be removed from the shim link set. The Rust
// cpumap_or_pass verdict is pinned by the ingress map builder tests; this leg
// pins the companion Go detach and no-obsolete-link result.
func TestBindingWithoutIngressEntryDetachesShimLinks10519(t *testing.T) {
	const ifindex = 10524
	m := New()
	m.bpfShim.SetLinkForTest(ifindex,
		&reconcilerLink10519{}, &reconcilerLink10519{})
	snapshot := &ConfigSnapshot{Interfaces: []InterfaceSnapshot{{
		Ifindex:      ifindex,
		LinuxName:    "st24",
		Name:         "st24.0",
		Zone:         "trust",
		SecureTunnel: true,
	}}}
	if got := buildUserspaceIngressIfindexes(snapshot); len(got) != 0 {
		t.Fatalf("ingress set = %v, want no entry for unadjudicated row", got)
	}
	result := &dataplane.CompileResult{}
	if err := m.syncInterfaceAttachments(result, snapshot); err != nil {
		t.Fatalf("syncInterfaceAttachments: %v", err)
	}
	if len(result.DetachedWithErrors) != 0 {
		t.Fatalf("DetachedWithErrors = %v, want clean detach", result.DetachedWithErrors)
	}
	if len(m.bpfShim.XDPLinks()) != 0 || len(m.bpfShim.TCLinks()) != 0 {
		t.Fatal("unadjudicated binding retained an XDP or TC link")
	}
}
