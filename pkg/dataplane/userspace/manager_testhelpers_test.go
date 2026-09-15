package userspace

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
	"golang.org/x/sys/unix"
)

func hostToNetwork16(v uint16) uint16 {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], v)
	return binary.NativeEndian.Uint16(raw[:])
}

func injectShimMap(t *testing.T, bpfShim *dataplane.Manager, name string, m *ebpf.Map) {
	t.Helper()
	if bpfShim == nil {
		t.Fatal("injectShimMap: bpfShim manager is nil")
	}
	managerValue := reflect.ValueOf(bpfShim)
	if managerValue.Kind() != reflect.Ptr || managerValue.IsNil() {
		t.Fatalf("injectShimMap: expected non-nil pointer to dataplane.Manager, got %T", bpfShim)
	}
	managerElem := managerValue.Elem()
	if !managerElem.IsValid() || managerElem.Kind() != reflect.Struct {
		t.Fatalf("injectShimMap: expected dataplane.Manager struct, got kind %s", managerElem.Kind())
	}
	rv := managerElem.FieldByName("maps")
	if !rv.IsValid() {
		t.Fatal("injectShimMap: dataplane.Manager has no field named \"maps\"")
	}
	if !rv.CanAddr() {
		t.Fatal("injectShimMap: dataplane.Manager.maps is not addressable")
	}
	if rv.Kind() != reflect.Map {
		t.Fatalf("injectShimMap: dataplane.Manager.maps has kind %s, want map", rv.Kind())
	}
	rm := reflect.NewAt(rv.Type(), unsafe.Pointer(rv.UnsafeAddr())).Elem()
	if rm.IsNil() {
		rm.Set(reflect.MakeMap(rv.Type()))
	}
	key := reflect.ValueOf(name)
	value := reflect.ValueOf(m)
	if !key.Type().AssignableTo(rv.Type().Key()) {
		t.Fatalf("injectShimMap: cannot use key type %s for map key type %s", key.Type(), rv.Type().Key())
	}
	if !value.Type().AssignableTo(rv.Type().Elem()) {
		t.Fatalf("injectShimMap: cannot use value type %s for map element type %s", value.Type(), rv.Type().Elem())
	}
	rm.SetMapIndex(key, value)
}

func injectSessionMaps(t *testing.T, m *Manager) {
	t.Helper()
	sessionsMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:    ebpf.Hash,
		KeySize: uint32(unsafe.Sizeof(dataplane.SessionKey{})),
		// On-map conntrack ABI size (excludes sync-only Generation) — must
		// match the production registration, else the Manager's lookup copies
		// the registered value_size into the smaller bpfSessionValue buffer
		// (the #2360 OOB). Derive from the shared SSOT constant.
		ValueSize:  dataplane.ConntrackSessionValueSize,
		MaxEntries: 1024,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new sessions map", err)
	}
	t.Cleanup(func() { sessionsMap.Close() })
	injectShimMap(t, m.bpfShim, "sessions", sessionsMap)
	sessionsMapV6, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(dataplane.SessionKeyV6{})),
		ValueSize:  dataplane.ConntrackSessionValueSizeV6,
		MaxEntries: 1024,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new sessions_v6 map", err)
	}
	t.Cleanup(func() { sessionsMapV6.Close() })
	injectShimMap(t, m.bpfShim, "sessions_v6", sessionsMapV6)
}

func injectCtrlAndBindingMaps(t *testing.T, m *Manager) (*ebpf.Map, *ebpf.Map) {
	t.Helper()
	ctrlMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(userspaceCtrlValue{})),
		MaxEntries: 16,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new userspace_ctrl map", err)
	}
	t.Cleanup(func() { ctrlMap.Close() })
	injectShimMap(t, m.bpfShim, "userspace_ctrl", ctrlMap)

	bindingsMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(userspaceBindingValue{})),
		MaxEntries: 256,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new userspace_bindings map", err)
	}
	t.Cleanup(func() { bindingsMap.Close() })
	injectShimMap(t, m.bpfShim, "userspace_bindings", bindingsMap)
	return ctrlMap, bindingsMap
}

func injectUserspaceSessionMap(t *testing.T, m *Manager) *ebpf.Map {
	t.Helper()
	// #9770: the real ABI — 40-byte bare-tuple key (UserspaceSessionMapKey) and a u8
	// action value (1 REDIRECT, 2 PASS_TO_KERNEL). The old 4-byte/8-byte shape never
	// matched the map and made value-selective assertions meaningless.
	usMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    40,
		ValueSize:  1,
		MaxEntries: 256,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new userspace_sessions map", err)
	}
	t.Cleanup(func() { usMap.Close() })
	injectShimMap(t, m.bpfShim, "userspace_sessions", usMap)
	return usMap
}

func skipIfBPFMapUnavailable(t *testing.T, context string, err error) {
	t.Helper()
	msg := strings.ToLower(err.Error())
	if errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EACCES) ||
		strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "memlock") {
		t.Skipf("%s requires BPF map privileges: %v", context, err)
	}
	t.Fatalf("%s: %v", context, err)
}
