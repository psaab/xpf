package userspace

import (
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

// #17849 follow-up (review): the proxy-NDP absence branch must stay
// covered — with the map omitted, classifier sync must fail closed
// with the named error (a mutant swallowing the nil-map error goes
// RED here).
func TestClassifierSyncFailsClosedWithoutProxyNDPMap17849(t *testing.T) {
	m, ctrlMap, _ := injectClassifierManager16689(t, 2)
	removeShimMap17849(t, m, mapNameUserspaceProxyNDPv6)
	zero := uint32(0)
	if err := ctrlMap.Update(zero, userspaceCtrlValue{
		Enabled: 1, MetadataVersion: userspaceMetadataVersion, Workers: 1, QueueCount: 1,
		HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
	}, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed userspace_ctrl: %v", err)
	}
	m.ctrlWasEnabled = true
	snap := ingressDomainPlanSnapshot16689(30, 40)
	err := m.syncUserspaceClassifierMapsFailClosedLocked(snap)
	if err == nil || !strings.Contains(err.Error(), "userspace_proxy_ndp_v6_domain map not loaded") {
		t.Fatalf("absent proxy-NDP map must fail closed with the named error, got: %v", err)
	}
	var ctrl userspaceCtrlValue
	if lerr := ctrlMap.Lookup(zero, &ctrl); lerr != nil {
		t.Fatalf("lookup ctrl: %v", lerr)
	}
	if ctrl.Enabled != 0 {
		t.Fatalf("ctrl.Enabled = %d, want 0 (fail-closed on missing proxy-NDP map)", ctrl.Enabled)
	}
}

func removeShimMap17849(t *testing.T, m *Manager, name string) {
	t.Helper()
	mv := reflect.ValueOf(m.bpfShim).Elem().FieldByName("maps")
	rm := reflect.NewAt(mv.Type(), unsafe.Pointer(mv.UnsafeAddr())).Elem()
	rm.SetMapIndex(reflect.ValueOf(name), reflect.Value{})
	var _ = ebpf.UpdateAny
}
