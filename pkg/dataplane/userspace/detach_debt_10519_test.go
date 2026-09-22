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
	unpinErr error
}

func (l *reconcilerLink10519) Unpin() error { return l.unpinErr }
func (l *reconcilerLink10519) Close() error { return l.closeErr }

// T3: the reconciler joins XDP and TC errors, stamps every failing ifindex,
// and the acceptance caller records a sticky alarm plus LastApplyResult. A
// healthy subsequent pass clears both the per-apply field and the alarm.
func TestSyncInterfaceAttachmentsSurfacesAndRecovers10519(t *testing.T) {
	const xdpIfindex, tcIfindex = 10522, 10523
	m := New()
	xdpErr := errors.New("injected XDP unpin failure")
	tcErr := errors.New("injected TC close failure")
	xdpLink := &reconcilerLink10519{unpinErr: xdpErr}
	m.bpfShim.SetLinkForTest(xdpIfindex, xdpLink, nil)
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

	// The XDP unpin-failure entry remains tracked for retry, while TC retained
	// its entry on Close failure; both recover on the next compile pass.
	xdpLink.unpinErr = nil
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

// T3b: the arm-(a) flag-clear failure is observable through the real
// post-acceptance reconciliation path, and its alarm remains latched while
// any detach debt survives a clean pass.
func TestSyncInterfaceAttachmentsLatchesAndClearsFlagDebt10519(t *testing.T) {
	const failedIfindex, seededIfindex = 10527, 10528
	m := New()
	xdpLink := &reconcilerLink10519{}
	m.bpfShim.SetLinkForTest(failedIfindex, xdpLink, nil)

	injected := errors.New("injected IFACE_FLAG_XDP_ATTACHED clear failure")
	restore := dataplane.SetDetachXDPFlagClearFnForTest(
		func(*dataplane.Manager, int, bool) error { return injected })
	defer restore()

	result := &dataplane.CompileResult{}
	err := m.syncInterfaceAttachments(result, &ConfigSnapshot{})
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("syncInterfaceAttachments error = %v, want injected flag-clear failure", err)
	}
	if !reflect.DeepEqual(result.DetachedWithErrors, []int{failedIfindex}) {
		t.Fatalf("DetachedWithErrors = %v, want [%d]", result.DetachedWithErrors, failedIfindex)
	}
	if got := m.bpfShim.ReconcileDetachDebt(nil); !reflect.DeepEqual(got, []int{failedIfindex}) {
		t.Fatalf("detach debt after flag-clear failure = %v, want [%d]", got, failedIfindex)
	}
	if got := m.bpfShim.AttachedXDPIfindexes(); len(got) != 0 {
		t.Fatalf("AttachedXDPIfindexes after flag-clear failure = %v, want debt omitted", got)
	}
	m.mu.Lock()
	m.noteDetachDebtLocked(result, err)
	alarm := m.detachDebtAlarm
	m.mu.Unlock()
	if alarm == "" || !strings.Contains(alarm, "obsolete ifindex") {
		t.Fatalf("detachDebtAlarm = %q, want indexed reconciliation error", alarm)
	}

	// A clean pass must not clear the alarm while unrelated detach debt
	// remains outstanding. Seed an untracked debt member to exercise the
	// census-guard branch directly.
	restore()
	m.bpfShim.SetDetachDebtForTest(seededIfindex)
	result = &dataplane.CompileResult{}
	if err := m.syncInterfaceAttachments(result, &ConfigSnapshot{}); err != nil {
		t.Fatalf("clean reconciliation with outstanding debt: %v", err)
	}
	m.mu.Lock()
	m.noteDetachDebtLocked(result, nil)
	alarm = m.detachDebtAlarm
	m.mu.Unlock()
	if alarm == "" {
		t.Fatal("clean reconciliation cleared detachDebtAlarm with outstanding debt")
	}
	if got := m.bpfShim.ReconcileDetachDebt(nil); !reflect.DeepEqual(got, []int{seededIfindex}) {
		t.Fatalf("outstanding detach debt after clean pass = %v, want [%d]", got, seededIfindex)
	}

	// Re-adjudicating the seeded interface is the post-acceptance recovery
	// boundary and must clear both the debt census and the sticky alarm.
	allowed := &ConfigSnapshot{Interfaces: []InterfaceSnapshot{{
		Ifindex:   seededIfindex,
		LinuxName: "ge-0-0-28",
		Name:      "ge-0-0-28.0",
		Zone:      "trust",
	}}}
	result = &dataplane.CompileResult{}
	if err := m.syncInterfaceAttachments(result, allowed); err != nil {
		t.Fatalf("allowed debt reconciliation: %v", err)
	}
	m.mu.Lock()
	m.noteDetachDebtLocked(result, nil)
	alarm = m.detachDebtAlarm
	m.mu.Unlock()
	if alarm != "" {
		t.Fatalf("detachDebtAlarm after allowed reaccept = %q, want clear", alarm)
	}
	if got := m.bpfShim.ReconcileDetachDebt(nil); len(got) != 0 {
		t.Fatalf("detach debt after allowed reaccept = %v, want empty", got)
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
