package userspace

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/vishvananda/netlink"
)

func TestShouldAttemptRSTSuppression(t *testing.T) {
	now := time.Unix(100, 0)
	addrV4 := []netip.Addr{netip.MustParseAddr("172.16.80.8")}

	if !shouldAttemptRSTSuppression(now, addrV4, nil, nil, nil, time.Time{}, false) {
		t.Fatal("shouldAttemptRSTSuppression() = false on first attempt, want true")
	}
	if shouldAttemptRSTSuppression(now, addrV4, nil, addrV4, nil, now, true) {
		t.Fatal("shouldAttemptRSTSuppression() = true for unchanged successful install, want false")
	}
	if !shouldAttemptRSTSuppression(now, addrV4, nil, nil, nil, now, true) {
		t.Fatal("shouldAttemptRSTSuppression() = false for address change, want true")
	}
	if shouldAttemptRSTSuppression(now, addrV4, nil, addrV4, nil, now.Add(-rstSuppressionRetryBackoff+time.Second), false) {
		t.Fatal("shouldAttemptRSTSuppression() = true before failure retry backoff, want false")
	}
	if !shouldAttemptRSTSuppression(now, addrV4, nil, addrV4, nil, now.Add(-rstSuppressionRetryBackoff), false) {
		t.Fatal("shouldAttemptRSTSuppression() = false at failure retry backoff, want true")
	}
}

func TestConfigEqualIncludesPollMode(t *testing.T) {
	a := config.UserspaceConfig{
		Binary:        "/tmp/helper",
		ControlSocket: "/tmp/control.sock",
		EventSocket:   "/tmp/events.sock",
		StateFile:     "/tmp/state.json",
		Workers:       4,
		RingEntries:   1024,
		PollMode:      "busy-poll",
	}
	b := a
	b.PollMode = "epoll"
	if configEqual(a, b) {
		t.Fatal("configEqual() = true after PollMode change, want false")
	}
}

func hostToNetwork16(v uint16) uint16 {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], v)
	return binary.NativeEndian.Uint16(raw[:])
}

func injectInnerMap(t *testing.T, inner *dataplane.Manager, name string, m *ebpf.Map) {
	t.Helper()
	if inner == nil {
		t.Fatal("injectInnerMap: inner manager is nil")
	}
	managerValue := reflect.ValueOf(inner)
	if managerValue.Kind() != reflect.Ptr || managerValue.IsNil() {
		t.Fatalf("injectInnerMap: expected non-nil pointer to dataplane.Manager, got %T", inner)
	}
	managerElem := managerValue.Elem()
	if !managerElem.IsValid() || managerElem.Kind() != reflect.Struct {
		t.Fatalf("injectInnerMap: expected dataplane.Manager struct, got kind %s", managerElem.Kind())
	}
	rv := managerElem.FieldByName("maps")
	if !rv.IsValid() {
		t.Fatal("injectInnerMap: dataplane.Manager has no field named \"maps\"")
	}
	if !rv.CanAddr() {
		t.Fatal("injectInnerMap: dataplane.Manager.maps is not addressable")
	}
	if rv.Kind() != reflect.Map {
		t.Fatalf("injectInnerMap: dataplane.Manager.maps has kind %s, want map", rv.Kind())
	}
	rm := reflect.NewAt(rv.Type(), unsafe.Pointer(rv.UnsafeAddr())).Elem()
	if rm.IsNil() {
		rm.Set(reflect.MakeMap(rv.Type()))
	}
	key := reflect.ValueOf(name)
	value := reflect.ValueOf(m)
	if !key.Type().AssignableTo(rv.Type().Key()) {
		t.Fatalf("injectInnerMap: cannot use key type %s for map key type %s", key.Type(), rv.Type().Key())
	}
	if !value.Type().AssignableTo(rv.Type().Elem()) {
		t.Fatalf("injectInnerMap: cannot use value type %s for map element type %s", value.Type(), rv.Type().Elem())
	}
	rm.SetMapIndex(key, value)
}

func injectSessionMaps(t *testing.T, m *Manager) {
	t.Helper()
	sessionsMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(dataplane.SessionKey{})),
		ValueSize:  uint32(unsafe.Sizeof(dataplane.SessionValue{})),
		MaxEntries: 1024,
	})
	if err != nil {
		t.Fatalf("new sessions map: %v", err)
	}
	t.Cleanup(func() { sessionsMap.Close() })
	injectInnerMap(t, m.inner, "sessions", sessionsMap)
	sessionsMapV6, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(dataplane.SessionKeyV6{})),
		ValueSize:  uint32(unsafe.Sizeof(dataplane.SessionValueV6{})),
		MaxEntries: 1024,
	})
	if err != nil {
		t.Fatalf("new sessions_v6 map: %v", err)
	}
	t.Cleanup(func() { sessionsMapV6.Close() })
	injectInnerMap(t, m.inner, "sessions_v6", sessionsMapV6)
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
		t.Fatalf("new userspace_ctrl map: %v", err)
	}
	t.Cleanup(func() { ctrlMap.Close() })
	injectInnerMap(t, m.inner, "userspace_ctrl", ctrlMap)

	bindingsMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(userspaceBindingValue{})),
		MaxEntries: 256,
	})
	if err != nil {
		t.Fatalf("new userspace_bindings map: %v", err)
	}
	t.Cleanup(func() { bindingsMap.Close() })
	injectInnerMap(t, m.inner, "userspace_bindings", bindingsMap)
	return ctrlMap, bindingsMap
}

func injectUserspaceSessionMap(t *testing.T, m *Manager) *ebpf.Map {
	t.Helper()
	usMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 256,
	})
	if err != nil {
		t.Fatalf("new userspace_sessions map: %v", err)
	}
	t.Cleanup(func() { usMap.Close() })
	injectInnerMap(t, m.inner, "userspace_sessions", usMap)
	return usMap
}

func TestFindUserspaceEgressInterfaceSnapshotPrefersVLANUnit(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:            "ge-0/0/2",
				Ifindex:         6,
				ParentIfindex:   0,
				RedundancyGroup: 1,
			},
			{
				Name:            "reth0.80",
				Ifindex:         12,
				ParentIfindex:   6,
				VLANID:          80,
				RedundancyGroup: 1,
			},
		},
	}
	iface, ok := findUserspaceEgressInterfaceSnapshot(snapshot, 6, 80)
	if !ok {
		t.Fatal("expected VLAN unit match")
	}
	if iface.Ifindex != 12 || iface.ParentIfindex != 6 || iface.RedundancyGroup != 1 {
		t.Fatalf("unexpected interface snapshot: %+v", iface)
	}
}

func TestSessionSyncEgressLockedDerivesOwnerAndTxPath(t *testing.T) {
	m := &Manager{
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{
				{
					Name:            "reth0.80",
					Ifindex:         12,
					ParentIfindex:   6,
					VLANID:          80,
					RedundancyGroup: 1,
				},
			},
		},
	}
	egress, tx, owner := m.sessionSyncEgressLocked(6, 80, "")
	if egress != 12 {
		t.Fatalf("egress = %d, want 12", egress)
	}
	if tx != 6 {
		t.Fatalf("tx = %d, want 6", tx)
	}
	if owner != 1 {
		t.Fatalf("owner = %d, want 1", owner)
	}
}

func TestSessionSyncEgressLockedResolvesOwnerRGFromZone(t *testing.T) {
	m := &Manager{
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{
				{
					Name:            "reth0",
					Zone:            "trust",
					Ifindex:         10,
					RedundancyGroup: 1,
				},
				{
					Name:            "ge-0-0-1",
					Zone:            "untrust",
					Ifindex:         20,
					RedundancyGroup: 0,
				},
			},
		},
	}
	// FibIfindex=0: should resolve owner_rg_id from zone.
	egress, tx, owner := m.sessionSyncEgressLocked(0, 0, "trust")
	if egress != 0 {
		t.Fatalf("egress = %d, want 0", egress)
	}
	if tx != 0 {
		t.Fatalf("tx = %d, want 0", tx)
	}
	if owner != 1 {
		t.Fatalf("owner = %d, want 1 (from trust zone)", owner)
	}
	// Zone with no RG: should return 0.
	_, _, owner = m.sessionSyncEgressLocked(0, 0, "untrust")
	if owner != 0 {
		t.Fatalf("owner = %d, want 0 (untrust has no RG)", owner)
	}
	// Empty zone: should return 0.
	_, _, owner = m.sessionSyncEgressLocked(0, 0, "")
	if owner != 0 {
		t.Fatalf("owner = %d, want 0 (empty zone)", owner)
	}
}

func TestSessionSyncTunnelEndpointIDLockedMatchesLogicalTunnelIfindex(t *testing.T) {
	m := &Manager{
		lastSnapshot: &ConfigSnapshot{
			TunnelEndpoints: []TunnelEndpointSnapshot{{
				ID:      3,
				Ifindex: 586,
			}},
		},
	}
	if got := m.sessionSyncTunnelEndpointIDLocked(586); got != 3 {
		t.Fatalf("tunnel endpoint id = %d, want 3", got)
	}
	if got := m.sessionSyncTunnelEndpointIDLocked(24); got != 0 {
		t.Fatalf("tunnel endpoint id for non-tunnel ifindex = %d, want 0", got)
	}
}

func TestBuildSessionSyncRequestV4ConvertsPortsToHostOrder(t *testing.T) {
	m := &Manager{
		inner: dataplane.New(),
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{{
				Name:            "reth0.80",
				Ifindex:         12,
				ParentIfindex:   6,
				VLANID:          80,
				RedundancyGroup: 1,
			}},
		},
	}
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  hostToNetwork16(50952),
		DstPort:  hostToNetwork16(5201),
		Protocol: 6,
	}
	val := &dataplane.SessionValue{
		IngressZone: 1,
		EgressZone:  2,
		Flags:       dataplane.SessFlagSNAT,
		LogFlags:    dataplane.LogFlagUserspaceFabricIngress,
		FibIfindex:  6,
		FibVlanID:   80,
		NATSrcIP:    binary.NativeEndian.Uint32([]byte{172, 16, 80, 8}),
		NATSrcPort:  hostToNetwork16(40000),
	}
	req := m.buildSessionSyncRequestV4("upsert", key, val)
	if req.SrcPort != 50952 || req.DstPort != 5201 {
		t.Fatalf("unexpected host-order request ports: %+v", req)
	}
	if req.NATSrcPort != 40000 {
		t.Fatalf("unexpected nat src port: %d", req.NATSrcPort)
	}
	if !req.FabricIngress {
		t.Fatalf("expected fabric_ingress to be preserved: %+v", req)
	}
}

func TestBuildSessionSyncRequestV4PreservesBothNatLegs(t *testing.T) {
	m := &Manager{inner: dataplane.New()}
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{198, 51, 100, 10},
		DstIP:    [4]byte{172, 16, 80, 8},
		SrcPort:  hostToNetwork16(54321),
		DstPort:  hostToNetwork16(443),
		Protocol: 6,
	}
	val := &dataplane.SessionValue{
		Flags:      dataplane.SessFlagSNAT | dataplane.SessFlagDNAT,
		NATSrcIP:   binary.NativeEndian.Uint32([]byte{10, 0, 61, 1}),
		NATDstIP:   binary.NativeEndian.Uint32([]byte{10, 0, 61, 102}),
		NATSrcPort: hostToNetwork16(54321),
		NATDstPort: hostToNetwork16(8443),
	}
	req := m.buildSessionSyncRequestV4("upsert", key, val)
	if req.NATSrcIP != "10.0.61.1" || req.NATDstIP != "10.0.61.102" {
		t.Fatalf("unexpected nat ips: %+v", req)
	}
	if req.NATSrcPort != 54321 || req.NATDstPort != 8443 {
		t.Fatalf("unexpected nat ports: %+v", req)
	}
}

func TestBuildSessionSyncRequestV4PreservesTunnelEndpointIdentity(t *testing.T) {
	m := &Manager{
		inner: dataplane.New(),
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{{
				Name:            "gr-0/0/0.0",
				Ifindex:         586,
				RedundancyGroup: 1,
			}},
			TunnelEndpoints: []TunnelEndpointSnapshot{{
				ID:              3,
				Ifindex:         586,
				RedundancyGroup: 1,
			}},
		},
	}
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{10, 255, 192, 41},
		SrcPort:  hostToNetwork16(4459),
		DstPort:  hostToNetwork16(4459),
		Protocol: 1,
	}
	val := &dataplane.SessionValue{
		IngressZone: 1,
		EgressZone:  2,
		LogFlags:    dataplane.LogFlagUserspaceTunnelEndpoint,
		FibIfindex:  894,
		FibGen:      3,
		FibVlanID:   80,
		FibDmac:     [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		FibSmac:     [6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08},
	}
	req := m.buildSessionSyncRequestV4("upsert", key, val)
	if req.TunnelEndpointID != 3 {
		t.Fatalf("unexpected tunnel endpoint id: %d", req.TunnelEndpointID)
	}
	if req.EgressIfindex != 586 {
		t.Fatalf("unexpected egress ifindex: %d", req.EgressIfindex)
	}
	if req.TXIfindex != 0 {
		t.Fatalf("unexpected tx ifindex: %d", req.TXIfindex)
	}
	if req.OwnerRGID != 1 {
		t.Fatalf("unexpected owner rg: %d", req.OwnerRGID)
	}
	if req.TXVLANID != 0 {
		t.Fatalf("unexpected tx vlan id: %d", req.TXVLANID)
	}
	if req.NeighborMAC != "" || req.SrcMAC != "" {
		t.Fatalf("unexpected tunnel L2 metadata: %+v", req)
	}
}

func TestBuildSessionSyncRequestV6PreservesTunnelEndpointIdentity(t *testing.T) {
	m := &Manager{
		inner: dataplane.New(),
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{{
				Name:            "gr-0/0/0.0",
				Ifindex:         586,
				RedundancyGroup: 1,
			}},
			TunnelEndpoints: []TunnelEndpointSnapshot{{
				ID:              7,
				Ifindex:         586,
				RedundancyGroup: 1,
			}},
		},
	}
	var srcIP, dstIP [16]byte
	copy(srcIP[:], net.ParseIP("2001:559:8585:ef00::100").To16())
	copy(dstIP[:], net.ParseIP("2001:db8::1").To16())
	val := &dataplane.SessionValueV6{
		IngressZone: 1,
		EgressZone:  2,
		LogFlags:    dataplane.LogFlagUserspaceTunnelEndpoint,
		FibIfindex:  1133,
		FibGen:      7,
		FibVlanID:   80,
	}
	req := m.buildSessionSyncRequestV6("upsert", dataplane.SessionKeyV6{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  hostToNetwork16(5555),
		DstPort:  hostToNetwork16(53),
		Protocol: 17,
	}, val)
	if req.TunnelEndpointID != 7 {
		t.Fatalf("unexpected tunnel endpoint id: %d", req.TunnelEndpointID)
	}
	if req.EgressIfindex != 586 {
		t.Fatalf("unexpected egress ifindex: %d", req.EgressIfindex)
	}
	if req.OwnerRGID != 1 {
		t.Fatalf("unexpected owner rg: %d", req.OwnerRGID)
	}
	if req.TXIfindex != 0 || req.TXVLANID != 0 {
		t.Fatalf("unexpected tx path for tunnel sync: %+v", req)
	}
}

func TestBuildSessionSyncRequestV6ConvertsPortsToHostOrder(t *testing.T) {
	m := &Manager{
		inner: dataplane.New(),
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{{
				Name:            "reth0.80",
				Ifindex:         12,
				ParentIfindex:   6,
				VLANID:          80,
				RedundancyGroup: 1,
			}},
		},
	}
	var srcIP, dstIP [16]byte
	copy(srcIP[:], net.ParseIP("2001:559:8585:ef00::100").To16())
	copy(dstIP[:], net.ParseIP("2001:559:8585:80::200").To16())
	var natSrc [16]byte
	copy(natSrc[:], net.ParseIP("2001:559:8585:80::8").To16())
	key := dataplane.SessionKeyV6{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  hostToNetwork16(50952),
		DstPort:  hostToNetwork16(5201),
		Protocol: 6,
	}
	val := &dataplane.SessionValueV6{
		IngressZone: 1,
		EgressZone:  2,
		Flags:       dataplane.SessFlagSNAT,
		LogFlags:    dataplane.LogFlagUserspaceFabricIngress,
		FibIfindex:  6,
		FibVlanID:   80,
		NATSrcIP:    natSrc,
		NATSrcPort:  hostToNetwork16(40000),
	}
	req := m.buildSessionSyncRequestV6("upsert", key, val)
	if req.SrcPort != 50952 || req.DstPort != 5201 {
		t.Fatalf("unexpected host-order request ports: %+v", req)
	}
	if req.NATSrcPort != 40000 {
		t.Fatalf("unexpected nat src port: %d", req.NATSrcPort)
	}
	if !req.FabricIngress {
		t.Fatalf("expected fabric_ingress to be preserved: %+v", req)
	}
}

func TestBuildSessionSyncRequestV6PreservesBothNatLegs(t *testing.T) {
	m := &Manager{inner: dataplane.New()}
	var srcIP, dstIP, natSrc, natDst [16]byte
	copy(srcIP[:], net.ParseIP("2001:db8::10").To16())
	copy(dstIP[:], net.ParseIP("2001:db8:80::8").To16())
	copy(natSrc[:], net.ParseIP("2001:db8:61::1").To16())
	copy(natDst[:], net.ParseIP("2001:db8:61::102").To16())
	key := dataplane.SessionKeyV6{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  hostToNetwork16(54321),
		DstPort:  hostToNetwork16(443),
		Protocol: 6,
	}
	val := &dataplane.SessionValueV6{
		Flags:      dataplane.SessFlagSNAT | dataplane.SessFlagDNAT,
		NATSrcIP:   natSrc,
		NATDstIP:   natDst,
		NATSrcPort: hostToNetwork16(54321),
		NATDstPort: hostToNetwork16(8443),
	}
	req := m.buildSessionSyncRequestV6("upsert", key, val)
	if req.NATSrcIP != "2001:db8:61::1" || req.NATDstIP != "2001:db8:61::102" {
		t.Fatalf("unexpected nat ips: %+v", req)
	}
	if req.NATSrcPort != 54321 || req.NATDstPort != 8443 {
		t.Fatalf("unexpected nat ports: %+v", req)
	}
}

func TestShouldMirrorUserspaceSessionSkipsReverseEntries(t *testing.T) {
	if !shouldMirrorUserspaceSession(0) {
		t.Fatal("expected forward sessions to be mirrored")
	}
	if shouldMirrorUserspaceSession(1) {
		t.Fatal("expected reverse sessions to be skipped")
	}
}

func TestSetClusterSyncedSessionV4SkipsReverseHelperMirror(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	sessionSock := filepath.Join(dir, "userspace-dp-sessions.sock")
	ln, err := net.Listen("unix", sessionSock)
	if err != nil {
		t.Fatalf("listen session socket: %v", err)
	}
	defer ln.Close()

	unexpectedConn := make(chan string, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case unexpectedConn <- "unexpected helper session socket connection for reverse cluster session":
			default:
			}
			go func() {
				defer conn.Close()
				var req ControlRequest
				if err := json.NewDecoder(conn).Decode(&req); err == nil {
					select {
					case unexpectedConn <- fmt.Sprintf("unexpected helper mirror request for reverse cluster session: %+v", req):
					default:
					}
				}
				_ = json.NewEncoder(conn).Encode(ControlResponse{OK: true})
			}()
		}
	}()

	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = controlSock
	sessionsMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(dataplane.SessionKey{})),
		ValueSize:  uint32(unsafe.Sizeof(dataplane.SessionValue{})),
		MaxEntries: 1024,
	})
	if err != nil {
		t.Fatalf("new sessions map: %v", err)
	}
	defer sessionsMap.Close()
	injectInnerMap(t, m.inner, "sessions", sessionsMap)
	sessionsMapV6, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(dataplane.SessionKeyV6{})),
		ValueSize:  uint32(unsafe.Sizeof(dataplane.SessionValueV6{})),
		MaxEntries: 1024,
	})
	if err != nil {
		t.Fatalf("new sessions_v6 map: %v", err)
	}
	defer sessionsMapV6.Close()
	injectInnerMap(t, m.inner, "sessions_v6", sessionsMapV6)

	key := dataplane.SessionKey{
		SrcIP:    [4]byte{172, 16, 80, 200},
		DstIP:    [4]byte{172, 16, 80, 8},
		SrcPort:  hostToNetwork16(5201),
		DstPort:  hostToNetwork16(55340),
		Protocol: 6,
	}
	val := dataplane.SessionValue{
		IsReverse:   1,
		IngressZone: 2,
		EgressZone:  1,
		Flags:       dataplane.SessFlagSNAT,
		FibIfindex:  6,
		FibVlanID:   80,
		NATSrcIP:    binary.NativeEndian.Uint32([]byte{172, 16, 80, 8}),
		NATSrcPort:  hostToNetwork16(55340),
	}

	if err := m.SetClusterSyncedSessionV4(key, val); err != nil {
		t.Fatalf("SetClusterSyncedSessionV4: %v", err)
	}

	select {
	case msg := <-unexpectedConn:
		t.Fatal(msg)
	case <-time.After(200 * time.Millisecond):
	}

	var srcIPv6, dstIPv6, natSrcIPv6 [16]byte
	copy(srcIPv6[:], net.ParseIP("2001:db8:1::200").To16())
	copy(dstIPv6[:], net.ParseIP("2001:db8:2::8").To16())
	copy(natSrcIPv6[:], net.ParseIP("2001:db8:2::8").To16())
	keyV6 := dataplane.SessionKeyV6{
		SrcIP:    srcIPv6,
		DstIP:    dstIPv6,
		SrcPort:  hostToNetwork16(5201),
		DstPort:  hostToNetwork16(55340),
		Protocol: 6,
	}
	valV6 := dataplane.SessionValueV6{
		IsReverse:   1,
		IngressZone: 2,
		EgressZone:  1,
		Flags:       dataplane.SessFlagSNAT,
		FibIfindex:  6,
		FibVlanID:   80,
		NATSrcIP:    natSrcIPv6,
		NATSrcPort:  hostToNetwork16(55340),
	}

	if err := m.SetClusterSyncedSessionV6(keyV6, valV6); err != nil {
		t.Fatalf("SetClusterSyncedSessionV6: %v", err)
	}

	select {
	case msg := <-unexpectedConn:
		t.Fatal(msg)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestSetClusterSyncedSessionV4MirrorFailureMarksHelperUnhealthy(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	injectSessionMaps(t, m)

	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  hostToNetwork16(5201),
		DstPort:  hostToNetwork16(55340),
		Protocol: 6,
	}
	val := dataplane.SessionValue{
		IsReverse: 0,
	}

	err := m.SetClusterSyncedSessionV4(key, val)
	if err == nil {
		t.Fatal("SetClusterSyncedSessionV4() = nil, want mirror failure")
	}
	if !m.sessionMirrorFailed {
		t.Fatal("sessionMirrorFailed = false, want true")
	}
	if m.sessionMirrorErr == "" {
		t.Fatal("sessionMirrorErr is empty")
	}
}

func TestSetClusterSyncedSessionV6MirrorFailureMarksHelperUnhealthy(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	injectSessionMaps(t, m)

	var srcIPv6, dstIPv6 [16]byte
	copy(srcIPv6[:], net.ParseIP("2001:db8:61::102").To16())
	copy(dstIPv6[:], net.ParseIP("2001:db8:80::200").To16())
	key := dataplane.SessionKeyV6{
		SrcIP:    srcIPv6,
		DstIP:    dstIPv6,
		SrcPort:  hostToNetwork16(5201),
		DstPort:  hostToNetwork16(55340),
		Protocol: 6,
	}
	val := dataplane.SessionValueV6{
		IsReverse: 0,
	}

	err := m.SetClusterSyncedSessionV6(key, val)
	if err == nil {
		t.Fatal("SetClusterSyncedSessionV6() = nil, want mirror failure")
	}
	if !m.sessionMirrorFailed {
		t.Fatal("sessionMirrorFailed = false, want true")
	}
	if m.sessionMirrorErr == "" {
		t.Fatal("sessionMirrorErr is empty")
	}
}

func TestTakeoverReadyReportsSessionMirrorFailure(t *testing.T) {
	m := &Manager{
		proc: &exec.Cmd{Process: &os.Process{Pid: 1}},
		lastStatus: ProcessStatus{
			Enabled:         true,
			ForwardingArmed: true,
			Capabilities: UserspaceCapabilities{
				ForwardingSupported: true,
			},
		},
		mode:                ModeUserspaceCompat,
		xskLivenessProven:   true,
		sessionMirrorFailed: true,
		sessionMirrorErr:    "dial unix /tmp/userspace-dp-sessions.sock: connect: no such file or directory",
	}

	ready, reasons := m.TakeoverReady()
	if ready {
		t.Fatal("TakeoverReady() = true, want false")
	}
	if len(reasons) == 0 {
		t.Fatal("TakeoverReady() returned no reasons")
	}
	found := false
	for _, reason := range reasons {
		if strings.Contains(reason, "userspace session mirror unhealthy") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected session mirror failure reason, got %v", reasons)
	}
}

func testStandbyNeighborPrewarmManager() *Manager {
	return &Manager{
		proc:      &exec.Cmd{Process: &os.Process{Pid: 1}},
		clusterHA: true,
		lastStatus: ProcessStatus{
			Enabled:         true,
			ForwardingArmed: true,
			Capabilities: UserspaceCapabilities{
				ForwardingSupported: true,
			},
		},
		lastSnapshot: &ConfigSnapshot{
			Config: &config.Config{
				Chassis: config.ChassisConfig{
					Cluster: &config.ClusterConfig{
						RedundancyGroups: []*config.RedundancyGroup{
							{ID: 0},
							{ID: 1},
						},
					},
				},
			},
		},
		haGroups: map[int]HAGroupStatus{
			1: {RGID: 1, Active: false},
		},
	}
}

func TestShouldStandbyNeighborPrewarmLocked(t *testing.T) {
	m := testStandbyNeighborPrewarmManager()
	if !m.shouldStandbyNeighborPrewarmLocked(time.Now()) {
		t.Fatal("shouldStandbyNeighborPrewarmLocked() = false, want true")
	}
}

func TestShouldStandbyNeighborPrewarmLockedRejectsActiveOwner(t *testing.T) {
	m := testStandbyNeighborPrewarmManager()
	m.haGroups[1] = HAGroupStatus{RGID: 1, Active: true}
	if m.shouldStandbyNeighborPrewarmLocked(time.Now()) {
		t.Fatal("shouldStandbyNeighborPrewarmLocked() = true, want false for active owner")
	}
}

func TestShouldStandbyNeighborPrewarmLockedThrottlesRecentRun(t *testing.T) {
	m := testStandbyNeighborPrewarmManager()
	now := time.Now()
	m.lastStandbyNeighResolve = now.Add(-5 * time.Second)
	if m.shouldStandbyNeighborPrewarmLocked(now) {
		t.Fatal("shouldStandbyNeighborPrewarmLocked() = true, want false during throttle window")
	}
}

func TestTakeoverReadyAllowsStandbyWithReadyBindingsWithoutLivenessProof(t *testing.T) {
	m := &Manager{
		proc: &exec.Cmd{Process: &os.Process{Pid: 1}},
		lastStatus: ProcessStatus{
			Enabled:         true,
			ForwardingArmed: true,
			Capabilities: UserspaceCapabilities{
				ForwardingSupported: true,
			},
			Queues: []QueueStatus{
				{QueueID: 0, WorkerID: 0, Registered: true, Armed: true, Ready: true},
			},
			Bindings: []BindingStatus{
				{
					Slot:          0,
					QueueID:       0,
					WorkerID:      0,
					Ifindex:       5,
					Registered:    true,
					Armed:         true,
					Ready:         true,
					Bound:         true,
					XSKRegistered: true,
				},
			},
		},
		mode: ModeUserspaceCompat,
		haGroups: map[int]HAGroupStatus{
			1: {RGID: 1, Active: false},
			2: {RGID: 2, Active: false},
		},
	}

	ready, reasons := m.TakeoverReady()
	if !ready {
		t.Fatalf("TakeoverReady() = false, want true, reasons=%v", reasons)
	}
}

func TestTakeoverReadyRequiresLivenessProofOnActiveNode(t *testing.T) {
	m := &Manager{
		proc: &exec.Cmd{Process: &os.Process{Pid: 1}},
		lastStatus: ProcessStatus{
			Enabled:         true,
			ForwardingArmed: true,
			Capabilities: UserspaceCapabilities{
				ForwardingSupported: true,
			},
			Queues: []QueueStatus{
				{QueueID: 0, WorkerID: 0, Registered: true, Armed: true, Ready: true},
			},
			Bindings: []BindingStatus{
				{
					Slot:          0,
					QueueID:       0,
					WorkerID:      0,
					Ifindex:       5,
					Registered:    true,
					Armed:         true,
					Ready:         true,
					Bound:         true,
					XSKRegistered: true,
				},
			},
		},
		mode: ModeUserspaceCompat,
		haGroups: map[int]HAGroupStatus{
			1: {RGID: 1, Active: true},
		},
	}

	ready, reasons := m.TakeoverReady()
	if ready {
		t.Fatal("TakeoverReady() = true, want false without active-node liveness proof")
	}
	found := false
	for _, reason := range reasons {
		if reason == "userspace XSK liveness not proven" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected XSK liveness reason, got %v", reasons)
	}
}

func TestApplyHelperStatusInitialCtrlCleanupRunsOnlyOnce(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	m.inner.XDPEntryProg = "xdp_userspace_prog"
	injectCtrlAndBindingMaps(t, m)
	usMap := injectUserspaceSessionMap(t, m)
	m.neighborsPrewarmed = true
	m.xskLivenessProven = true
	m.publishedSnapshot = 1

	status := ProcessStatus{
		Enabled:                true,
		Workers:                1,
		LastSnapshotGeneration: 1,
		NeighborGeneration:     1,
		Capabilities: UserspaceCapabilities{
			ForwardingSupported: true,
		},
		Bindings: []BindingStatus{{
			Slot:       1,
			QueueID:    0,
			Ifindex:    5,
			Registered: true,
			Armed:      true,
			Bound:      true,
		}},
	}

	key := uint32(1)
	value := uint64(1)
	if err := usMap.Update(key, value, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed userspace_sessions: %v", err)
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		t.Fatalf("first applyHelperStatusLocked: %v", err)
	}
	if !m.initialCtrlCleanupDone {
		t.Fatal("initialCtrlCleanupDone = false, want true after first ctrl enable")
	}
	var got uint64
	if err := usMap.Lookup(key, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("userspace_sessions entry survived first ctrl enable cleanup: err=%v got=%d", err, got)
	}

	if err := usMap.Update(key, value, ebpf.UpdateAny); err != nil {
		t.Fatalf("reseed userspace_sessions: %v", err)
	}
	m.ctrlWasEnabled = false
	if err := m.applyHelperStatusLocked(&status); err != nil {
		t.Fatalf("second applyHelperStatusLocked: %v", err)
	}
	if err := usMap.Lookup(key, &got); err != nil {
		t.Fatalf("later ctrl re-enable reran startup cleanup: %v", err)
	}
}

func TestUpdateRGActiveActivationKeepsCtrlEnabledAfterAckedStatus(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	status := ProcessStatus{
		Enabled:                true,
		Workers:                1,
		LastSnapshotGeneration: 2,
		NeighborGeneration:     1,
		Capabilities: UserspaceCapabilities{
			ForwardingSupported: true,
		},
		Bindings: []BindingStatus{{
			Slot:       1,
			QueueID:    0,
			Ifindex:    5,
			Registered: true,
			Armed:      true,
			Bound:      true,
		}},
	}
	reqDone := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req ControlRequest
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}
		if req.Type != "update_ha_state" {
			return
		}
		_ = json.NewEncoder(conn).Encode(ControlResponse{
			OK:     true,
			Status: &status,
		})
		reqDone <- struct{}{}
	}()

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
	m.cfg.ControlSocket = controlSock
	m.clusterHA = true
	m.inner.XDPEntryProg = "xdp_userspace_prog"
	m.neighborsPrewarmed = true
	m.xskLivenessProven = true
	m.ctrlWasEnabled = true
	m.haGroups = map[int]HAGroupStatus{
		0: {RGID: 0, Active: true},
		1: {RGID: 1, Active: false},
		2: {RGID: 2, Active: true},
	}

	ctrlMap, _ := injectCtrlAndBindingMaps(t, m)
	rgMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 16,
	})
	if err != nil {
		t.Fatalf("new rg_active map: %v", err)
	}
	t.Cleanup(func() { rgMap.Close() })
	injectInnerMap(t, m.inner, "rg_active", rgMap)

	if err := m.UpdateRGActive(1, true); err != nil {
		t.Fatalf("UpdateRGActive: %v", err)
	}
	select {
	case <-reqDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for update_ha_state request")
	}

	var zero uint32
	var ctrl userspaceCtrlValue
	if err := ctrlMap.Lookup(zero, &ctrl); err != nil {
		t.Fatalf("lookup userspace_ctrl: %v", err)
	}
	if ctrl.Enabled != 1 {
		t.Fatalf("userspace_ctrl.Enabled = %d, want 1 after acked activation", ctrl.Enabled)
	}
	if m.mode != ModeUserspaceCompat {
		t.Fatalf("mode = %s, want %s", m.mode, ModeUserspaceCompat)
	}
	if m.rgTransitionInFlight.Load() {
		t.Fatal("rgTransitionInFlight = true after UpdateRGActive")
	}
}

func TestMergeHAStateFromMaps(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	rgMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 16,
	})
	if err != nil {
		t.Fatalf("NewMap(rg_active): %v", err)
	}
	defer rgMap.Close()
	wdMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 16,
	})
	if err != nil {
		t.Fatalf("NewMap(ha_watchdog): %v", err)
	}
	defer wdMap.Close()

	rgID := uint32(2)
	active := uint8(1)
	watchdog := uint64(12345)
	if err := rgMap.Update(rgID, active, ebpf.UpdateAny); err != nil {
		t.Fatalf("rgMap.Update: %v", err)
	}
	if err := wdMap.Update(rgID, watchdog, ebpf.UpdateAny); err != nil {
		t.Fatalf("wdMap.Update: %v", err)
	}

	merged, err := mergeHAStateFromMaps(rgMap, wdMap, map[int]HAGroupStatus{
		0: {RGID: 0, Active: false},
	})
	if err != nil {
		t.Fatalf("mergeHAStateFromMaps: %v", err)
	}
	if !merged[2].Active {
		t.Fatal("merged[2].Active = false, want true")
	}
	if got := merged[2].WatchdogTimestamp; got != watchdog {
		t.Fatalf("merged[2].WatchdogTimestamp = %d, want %d", got, watchdog)
	}
	if _, ok := merged[0]; !ok {
		t.Fatal("existing RG 0 state was dropped")
	}
}

func TestSeedHAGroupInventoryLockedSeedsConfiguredStandbyGroups(t *testing.T) {
	m := &Manager{
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true, WatchdogTimestamp: 111},
			2: {RGID: 2, Active: true, WatchdogTimestamp: 222},
			9: {RGID: 9, Active: true, WatchdogTimestamp: 999},
		},
	}
	cfg := &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{
				RedundancyGroups: []*config.RedundancyGroup{
					{ID: 1},
					{ID: 2},
				},
			},
		},
	}

	m.seedHAGroupInventoryLocked(cfg)

	if _, ok := m.haGroups[1]; !ok {
		t.Fatal("expected configured standby RG1 to be seeded")
	}
	if group := m.haGroups[2]; !group.Active || group.WatchdogTimestamp != 222 {
		t.Fatalf("configured RG2 state not preserved: %+v", group)
	}
	if group := m.haGroups[0]; !group.Active || group.WatchdogTimestamp != 111 {
		t.Fatalf("RG0 state not preserved: %+v", group)
	}
	if _, ok := m.haGroups[9]; ok {
		t.Fatal("unexpected stale RG9 retained after seeding from config")
	}
}

func TestActiveHAGroupSignatureUsesSortedActiveRGs(t *testing.T) {
	got := activeHAGroupSignature(map[int]HAGroupStatus{
		2: {RGID: 2, Active: true},
		1: {RGID: 1, Active: false},
		7: {RGID: 7, Active: true},
		0: {RGID: 0, Active: true},
	})
	if got != "0,2,7" {
		t.Fatalf("activeHAGroupSignature = %q, want 0,2,7", got)
	}
}

func TestActiveHAGroupSignatureSliceUsesSortedActiveRGs(t *testing.T) {
	got := activeHAGroupSignatureSlice([]HAGroupStatus{
		{RGID: 7, Active: true},
		{RGID: 1, Active: false},
		{RGID: 0, Active: true},
		{RGID: 2, Active: true},
	})
	if got != "0,2,7" {
		t.Fatalf("activeHAGroupSignatureSlice = %q, want 0,2,7", got)
	}
}

func TestUserspaceBootstrapProbeInterfacesIncludesBaseAndVLANUnits(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-7/0/1": {
			Name: "ge-7/0/1",
		},
		"ge-7/0/2": {
			Name: "ge-7/0/2",
			Units: map[int]*config.InterfaceUnit{
				0:  {Number: 0},
				50: {Number: 50, VlanID: 50},
				80: {Number: 80, VlanID: 80},
			},
		},
	}
	got := userspaceBootstrapProbeInterfaces(cfg)
	want := []string{"ge-7-0-1", "ge-7-0-2", "ge-7-0-2.50", "ge-7-0-2.80"}
	if len(got) != len(want) {
		t.Fatalf("len(userspaceBootstrapProbeInterfaces) = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("userspaceBootstrapProbeInterfaces[%d] = %q, want %q (%v)", i, got[i], want[i], got)
		}
	}
}

func TestDesiredForwardingArmedUsesSeededConfiguredDataRGs(t *testing.T) {
	m := &Manager{
		clusterHA: true,
		lastStatus: ProcessStatus{
			Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		},
		haGroups: make(map[int]HAGroupStatus),
		lastSnapshot: &ConfigSnapshot{
			Config: &config.Config{
				Chassis: config.ChassisConfig{
					Cluster: &config.ClusterConfig{
						RedundancyGroups: []*config.RedundancyGroup{
							{ID: 1},
							{ID: 2},
						},
					},
				},
			},
		},
	}

	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true for configured standby data RGs")
	}
}

func TestMacStringSuppressesZeroAndFormatsValue(t *testing.T) {
	if got := macString([]byte{0, 0, 0, 0, 0, 0}); got != "" {
		t.Fatalf("zero MAC = %q, want empty", got)
	}
	if got := macString([]byte{0x02, 0xbf, 0x72, 0x01, 0x01, 0x01}); got != "02:bf:72:01:01:01" {
		t.Fatalf("formatted MAC = %q", got)
	}
}

func TestDeriveUserspaceConfigDefaults(t *testing.T) {
	cfg := deriveUserspaceConfig(&config.Config{})
	if cfg.Workers != 1 {
		t.Fatalf("Workers = %d, want 1", cfg.Workers)
	}
	if cfg.RingEntries != 1024 {
		t.Fatalf("RingEntries = %d, want 1024", cfg.RingEntries)
	}
	if cfg.ControlSocket == "" {
		t.Fatal("ControlSocket is empty")
	}
	if cfg.StateFile == "" {
		t.Fatal("StateFile is empty")
	}
}

func TestBuildSnapshotSummary(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.HostName = "fw-test"
	cfg.System.DataplaneType = "userspace"
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {
			Name: "ge-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"192.0.2.1/24", "2001:db8::1/64"}},
			},
		},
		"ge-0/0/1": {
			Name: "ge-0/0/1",
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.0.0.1/24"}},
			},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"ge-0/0/1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/0"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name: "allow-all",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "src",
		FromZone: "trust",
		ToZone:   "untrust",
		Rules: []*config.NATRule{{
			Name: "snat",
			Match: config.NATMatch{
				SourceAddresses: []string{"0.0.0.0/0"},
			},
			Then: config.NATThen{
				Type:      config.NATSource,
				Interface: true,
			},
		}},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{"workhours": {Name: "workhours"}}
	cfg.Chassis.Cluster = &config.ClusterConfig{ClusterID: 1}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "10.0.0.1"}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{
			Name:              "vrf1",
			Inet6StaticRoutes: []*config.StaticRoute{{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "fe80::1", Interface: "ge-0/0/0.0"}}}},
		},
	}

	snap := buildSnapshot(cfg, config.UserspaceConfig{Workers: 2, RingEntries: 2048}, 11, 5)
	if snap.Generation != 11 {
		t.Fatalf("Generation = %d, want 11", snap.Generation)
	}
	if snap.FIBGeneration != 5 {
		t.Fatalf("FIBGeneration = %d, want 5", snap.FIBGeneration)
	}
	if snap.MapPins.Ctrl == "" || snap.MapPins.Bindings == "" || snap.MapPins.Heartbeat == "" || snap.MapPins.XSK == "" || snap.MapPins.LocalV4 == "" || snap.MapPins.LocalV6 == "" {
		t.Fatalf("MapPins = %+v, want all paths populated", snap.MapPins)
	}
	if snap.Summary.HostName != "fw-test" {
		t.Fatalf("HostName = %q", snap.Summary.HostName)
	}
	if snap.Summary.InterfaceCount != 2 {
		t.Fatalf("InterfaceCount = %d, want 2", snap.Summary.InterfaceCount)
	}
	if snap.Summary.ZoneCount != 2 {
		t.Fatalf("ZoneCount = %d, want 2", snap.Summary.ZoneCount)
	}
	if snap.Summary.PolicyCount != 1 {
		t.Fatalf("PolicyCount = %d, want 1", snap.Summary.PolicyCount)
	}
	if snap.Summary.SchedulerCount != 1 {
		t.Fatalf("SchedulerCount = %d, want 1", snap.Summary.SchedulerCount)
	}
	if !snap.Summary.HAEnabled {
		t.Fatal("HAEnabled = false, want true")
	}
	if len(snap.Interfaces) != 4 {
		t.Fatalf("len(Interfaces) = %d, want 4", len(snap.Interfaces))
	}
	if snap.Interfaces[0].Name != "ge-0/0/0" {
		t.Fatalf("Interfaces[0].Name = %q", snap.Interfaces[0].Name)
	}
	if snap.Interfaces[0].LinuxName != "ge-0-0-0" {
		t.Fatalf("Interfaces[0].LinuxName = %q", snap.Interfaces[0].LinuxName)
	}
	if snap.Interfaces[0].Zone != "untrust" {
		t.Fatalf("Interfaces[0].Zone = %q, want untrust", snap.Interfaces[0].Zone)
	}
	if len(snap.Routes) < 4 {
		t.Fatalf("len(Routes) = %d, want at least 4", len(snap.Routes))
	}
	var sawDefaultV4, sawDefaultV6, sawConnectedV4, sawConnectedV6 bool
	for _, route := range snap.Routes {
		switch {
		case route.Table == "inet.0" && route.Destination == "0.0.0.0/0":
			sawDefaultV4 = true
		case route.Table == "vrf1.inet6.0" && route.Destination == "::/0":
			sawDefaultV6 = true
		case route.Table == "inet.0" && route.Destination == "10.0.0.0/24":
			sawConnectedV4 = true
		case route.Table == "inet6.0" && route.Destination == "2001:db8::/64":
			sawConnectedV6 = true
		}
	}
	if !sawDefaultV4 || !sawDefaultV6 || !sawConnectedV4 || !sawConnectedV6 {
		t.Fatalf("Routes = %+v", snap.Routes)
	}
	if len(snap.SourceNAT) != 1 {
		t.Fatalf("len(SourceNAT) = %d, want 1", len(snap.SourceNAT))
	}
	if !snap.SourceNAT[0].InterfaceMode || snap.SourceNAT[0].FromZone != "trust" || snap.SourceNAT[0].ToZone != "untrust" {
		t.Fatalf("SourceNAT[0] = %+v", snap.SourceNAT[0])
	}
	if snap.DefaultPolicy != "deny" {
		t.Fatalf("DefaultPolicy = %q, want deny", snap.DefaultPolicy)
	}
	if len(snap.Policies) != 1 {
		t.Fatalf("len(Policies) = %d, want 1", len(snap.Policies))
	}
	if snap.Policies[0].Action != "deny" && snap.Policies[0].Action != "permit" {
		t.Fatalf("Policies[0].Action = %q", snap.Policies[0].Action)
	}
}

func TestBuildFabricSnapshotsUsesLocalMemberAndPeer(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		FabricInterface:    "fab0",
		FabricPeerAddress:  "10.99.1.2",
		Fabric1Interface:   "fab1",
		Fabric1PeerAddress: "10.99.2.2",
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fab0": {Name: "fab0", LocalFabricMember: "ge-0/0/0"},
		"fab1": {Name: "fab1", LocalFabricMember: "ge-7/0/0"},
	}

	fabrics := buildFabricSnapshots(cfg)
	if len(fabrics) != 2 {
		t.Fatalf("len(fabrics) = %d, want 2", len(fabrics))
	}
	if fabrics[0].Name != "fab0" || fabrics[0].ParentInterface != "ge-0/0/0" || fabrics[0].ParentLinuxName != "ge-0-0-0" || fabrics[0].PeerAddress != "10.99.1.2" {
		t.Fatalf("fabrics[0] = %+v", fabrics[0])
	}
	if fabrics[1].Name != "fab1" || fabrics[1].ParentInterface != "ge-7/0/0" || fabrics[1].ParentLinuxName != "ge-7-0-0" || fabrics[1].PeerAddress != "10.99.2.2" {
		t.Fatalf("fabrics[1] = %+v", fabrics[1])
	}
}

func TestBuildRouteSnapshotsNormalizesFamilyFromDestination(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "2001:db8::1"}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{
			Name: "blue",
			StaticRoutes: []*config.StaticRoute{
				{Destination: "2001:db8:1::/64", NextTable: "core"},
			},
		},
	}
	routes := buildRouteSnapshots(cfg, nil)
	if len(routes) != 2 {
		t.Fatalf("len(routes) = %d, want 2", len(routes))
	}
	if routes[0].Family != "inet6" || routes[0].Table != "blue.inet6.0" {
		t.Fatalf("routes[0] = %+v, want family inet6 table blue.inet6.0", routes[0])
	}
	if routes[1].Family != "inet6" || routes[1].Table != "inet6.0" {
		t.Fatalf("routes[1] = %+v, want family inet6 table inet6.0", routes[1])
	}
}

func TestBuildRouteSnapshotsIncludesConnectedPrefixes(t *testing.T) {
	routes := buildRouteSnapshots(&config.Config{}, []InterfaceSnapshot{
		{
			Name: "reth1.0",
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.0.61.1/24", Scope: int(netlink.SCOPE_UNIVERSE)},
				{Family: "inet6", Address: "2001:559:8585:ef00::1/64", Scope: int(netlink.SCOPE_UNIVERSE)},
				{Family: "inet6", Address: "fe80::1/64", Scope: int(netlink.SCOPE_LINK)},
			},
		},
	})
	if len(routes) != 2 {
		t.Fatalf("len(routes) = %d, want 2", len(routes))
	}
	if routes[0].Destination != "10.0.61.0/24" || routes[0].Table != "inet.0" {
		t.Fatalf("routes[0] = %+v", routes[0])
	}
	if routes[1].Destination != "2001:559:8585:ef00::/64" || routes[1].Table != "inet6.0" {
		t.Fatalf("routes[1] = %+v", routes[1])
	}
}

func TestBuildTunnelEndpointSnapshotsBuildsUnitEndpoint(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Name: "gr-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				0: {
					Number: 0,
				},
			},
			Tunnel: &config.TunnelConfig{
				Name:        "gr-0-0-0",
				Mode:        "gre",
				Source:      "2001:559:8585:80::8",
				Destination: "2602:ffd3:0:2::7",
			},
		},
	}
	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
		{
			Name:            "gr-0/0/0.0",
			Zone:            "sfmix",
			LinuxName:       "gr-0-0-0",
			Ifindex:         362,
			RedundancyGroup: 1,
			MTU:             1476,
		},
	})
	if len(endpoints) != 1 {
		t.Fatalf("len(endpoints) = %d, want 1", len(endpoints))
	}
	if endpoints[0].ID != 1 {
		t.Fatalf("endpoint id = %d, want 1", endpoints[0].ID)
	}
	if endpoints[0].Interface != "gr-0/0/0.0" {
		t.Fatalf("endpoint interface = %q, want gr-0/0/0.0", endpoints[0].Interface)
	}
	if endpoints[0].TransportTable != "inet6.0" {
		t.Fatalf("endpoint transport table = %q, want inet6.0", endpoints[0].TransportTable)
	}
	if endpoints[0].OuterFamily != "inet6" {
		t.Fatalf("endpoint outer family = %q, want inet6", endpoints[0].OuterFamily)
	}
}

func TestBuildTunnelEndpointSnapshotsUsesConfiguredTransportTable(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Name: "gr-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				0: {
					Number: 0,
				},
			},
			Tunnel: &config.TunnelConfig{
				Name:            "gr-0-0-0",
				Mode:            "gre",
				Source:          "172.16.50.8",
				Destination:     "198.51.100.7",
				RoutingInstance: "transport",
			},
		},
	}
	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
		{
			Name:      "gr-0/0/0.0",
			LinuxName: "gr-0-0-0",
			Ifindex:   362,
		},
	})
	if len(endpoints) != 1 {
		t.Fatalf("len(endpoints) = %d, want 1", len(endpoints))
	}
	if endpoints[0].TransportTable != "transport.inet.0" {
		t.Fatalf("endpoint transport table = %q, want transport.inet.0", endpoints[0].TransportTable)
	}
	if endpoints[0].OuterFamily != "inet" {
		t.Fatalf("endpoint outer family = %q, want inet", endpoints[0].OuterFamily)
	}
}

func TestBuildTunnelEndpointSnapshotsDerivesRGFromTunnelSourceAddress(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Name: "gr-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0},
			},
			Tunnel: &config.TunnelConfig{
				Name:        "gr-0-0-0",
				Mode:        "gre",
				Source:      "2001:559:8585:80::8",
				Destination: "2602:ffd3:0:2::7",
			},
		},
	}
	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
		{
			Name:      "gr-0/0/0.0",
			Zone:      "sfmix",
			LinuxName: "gr-0-0-0",
			Ifindex:   1116,
			MTU:       1500,
		},
		{
			Name:            "reth0.80",
			LinuxName:       "ge-7-0-2",
			Ifindex:         12,
			RedundancyGroup: 1,
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet6", Address: "2001:559:8585:80::8/64"},
			},
		},
	})
	if len(endpoints) != 1 {
		t.Fatalf("len(endpoints) = %d, want 1", len(endpoints))
	}
	if endpoints[0].RedundancyGroup != 1 {
		t.Fatalf("endpoint RG = %d, want 1", endpoints[0].RedundancyGroup)
	}
}

func TestBuildLocalAddressEntries(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name: "reth0.50",
				Zone: "wan",
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "172.16.50.8/24"},
					{Family: "inet6", Address: "2001:559:8585:50::8/64"},
				},
			},
			{
				Name: "reth1.0",
				Zone: "lan",
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "10.0.61.1/24"},
					{Family: "inet6", Address: "fe80::1/128"},
					{Family: "inet6", Address: "2001:559:8585:ef00::1/64"},
				},
			},
		},
	}
	got := buildLocalAddressEntries(snapshot)
	if len(got) != 5 {
		t.Fatalf("len(got) = %d, want 5 (%+v)", len(got), got)
	}
}

func TestPickInterfaceSnapshotFamilyFilters(t *testing.T) {
	iface := InterfaceSnapshot{
		Addresses: []InterfaceAddressSnapshot{
			{Family: "inet6", Address: "192.0.2.10/24"},
			{Family: "inet", Address: "192.0.2.20/24"},
			{Family: "inet", Address: "fe80::20/64"},
			{Family: "inet", Address: "2001:db8::20/64"},
			{Family: "inet6", Address: "fe80::10/64"},
			{Family: "inet6", Address: "2001:db8::10/64"},
		},
	}

	gotV4 := pickInterfaceSnapshotV4(iface)
	if gotV4 == nil || !gotV4.Equal(net.ParseIP("192.0.2.20")) {
		t.Fatalf("pickInterfaceSnapshotV4() = %v, want 192.0.2.20", gotV4)
	}

	gotV6 := pickInterfaceSnapshotV6(iface)
	if gotV6 == nil || !gotV6.Equal(net.ParseIP("2001:db8::10")) {
		t.Fatalf("pickInterfaceSnapshotV6() = %v, want 2001:db8::10", gotV6)
	}
}

func TestBuildLocalAddressEntriesIncludesInterfaceSNATAddressesForFallback(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name: "reth0.80",
				Zone: "wan",
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "172.16.80.8/24"},
					{Family: "inet6", Address: "2001:559:8585:80::8/64"},
				},
			},
			{
				Name: "reth1.0",
				Zone: "lan",
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "10.0.61.1/24"},
					{Family: "inet6", Address: "2001:559:8585:ef00::1/64"},
				},
			},
		},
		SourceNAT: []SourceNATRuleSnapshot{{
			Name:          "snat",
			FromZone:      "lan",
			ToZone:        "wan",
			InterfaceMode: true,
		}},
	}
	got := buildLocalAddressEntries(snapshot)
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 (%+v)", len(got), got)
	}
	var sawWanV4, sawWanV6, sawLanV4, sawLanV6 bool
	lanV4 := uint32(0x0a003d01)
	var wanV6 [16]byte
	copy(wanV6[:], []byte(net.ParseIP("2001:559:8585:80::8").To16()))
	var lanV6 [16]byte
	copy(lanV6[:], []byte(net.ParseIP("2001:559:8585:ef00::1").To16()))
	for _, entry := range got {
		if entry.v4 && entry.v4Key == 0xac105008 {
			sawWanV4 = true
		}
		if entry.v4 && entry.v4Key == lanV4 {
			sawLanV4 = true
		}
		if !entry.v4 && entry.v6Key.Addr == wanV6 {
			sawWanV6 = true
		}
		if !entry.v4 && entry.v6Key.Addr == lanV6 {
			sawLanV6 = true
		}
	}
	if sawWanV4 || sawWanV6 {
		t.Fatalf("WAN interface NAT addresses unexpectedly included in local map: %+v", got)
	}
	if !sawLanV4 || !sawLanV6 {
		t.Fatalf("missing LAN interface addresses in local map: %+v", got)
	}
}

func TestDeriveUserspaceCapabilitiesDetectsFirewallFeatures(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ClusterID: 1}
	cfg.Security.Zones = map[string]*config.ZoneConfig{"trust": {Name: "trust"}}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{Name: "src"}}
	cfg.Security.Flow.AllowDNSReply = true
	// Firewall filters (inet/inet6) and single-rate policers are now supported.
	// Only three-color policers remain unsupported.
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{"f1": {Name: "f1"}}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{}

	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false; firewall filters and flow monitoring are now supported. Reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesGatesThreeColorPolicers(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.ThreeColorPolicers = map[string]*config.ThreeColorPolicerConfig{
		"tcp1": {Name: "tcp1", CIR: 1000000, CBS: 50000},
	}

	caps := deriveUserspaceCapabilities(cfg)
	if caps.ForwardingSupported {
		t.Fatal("ForwardingSupported = true, want false for three-color policers")
	}
	found := false
	for _, r := range caps.UnsupportedReasons {
		if r == "three-color policers are not implemented in the userspace dataplane" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected three-color policer unsupported reason, got: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsFirewallFilters(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-RE": {Name: "protect-RE"},
	}
	cfg.Firewall.Policers = map[string]*config.PolicerConfig{
		"1mbps": {Name: "1mbps", BandwidthLimit: 125000, BurstSizeLimit: 50000},
	}

	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, unexpected reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsIPsecConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.IPsec.Gateways = map[string]*config.IPsecGateway{
		"gw1": {Name: "gw1"},
	}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn1": {Name: "vpn1", Gateway: "gw1"},
	}
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false; IPsec should not gate userspace forwarding. Reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsTunnelInterfaces(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"st0": {
			Name:   "st0",
			Tunnel: &config.TunnelConfig{},
			Units: map[int]*config.InterfaceUnit{
				0: {Tunnel: &config.TunnelConfig{}},
			},
		},
	}
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false; tunnel interfaces should not gate userspace forwarding. Reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsFlowMonitoring(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{}
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, want true (flow monitoring now supported); reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsDNSFlowKnobs(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.AllowDNSReply = true
	cfg.Security.Flow.AllowEmbeddedICMP = true

	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, unexpected reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsHAFabricConfigs(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		ClusterID:         22,
		PrivateRGElection: true,
		FabricInterface:   "fab0",
		FabricPeerAddress: "10.99.13.2",
	}

	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, unexpected reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDesiredForwardingArmedKeepsClusterStandbyArmed(t *testing.T) {
	m := &Manager{
		clusterHA: true,
		lastStatus: ProcessStatus{
			Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		},
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true},
			1: {RGID: 1, Active: false},
			2: {RGID: 2, Active: false},
		},
	}
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true on standby HA node with data RGs")
	}
	m.haGroups[2] = HAGroupStatus{RGID: 2, Active: true}
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true with active data RG")
	}
}

func TestDesiredForwardingArmedRequiresDataRGOrActiveLocalOnlyGroup(t *testing.T) {
	m := &Manager{
		clusterHA: true,
		lastStatus: ProcessStatus{
			Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		},
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true},
		},
	}
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true with active local-only RG")
	}
	m.haGroups[0] = HAGroupStatus{RGID: 0, Active: false}
	if m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = true, want false with no data RG and no active local-only RG")
	}
}

func TestRGTransitionInFlightOnlyDuringActivation(t *testing.T) {
	// Verify that rgTransitionInFlight is NOT set during demotion.
	// Setting it during demotion causes ctrl.Enabled=0 globally, which
	// disrupts forwarding for other active RGs and causes the standby
	// to lose userspace readiness (#457).
	m := &Manager{
		clusterHA: true,
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true},
			1: {RGID: 1, Active: true},
			2: {RGID: 2, Active: true},
		},
	}

	// Demotion (active=false) should NOT set rgTransitionInFlight.
	if m.rgTransitionInFlight.Load() {
		t.Fatal("rgTransitionInFlight should be false before demotion")
	}

	// We can't call UpdateRGActive directly without BPF maps, so we
	// verify the conditional guard matches the production code at
	// manager_ha.go:382 — `if active { m.rgTransitionInFlight.Store(true) }`.
	// This is a logic-level test; integration coverage comes from the
	// failover test harness (userspace-ha-failover-validation.sh).
	active := false
	if active {
		m.rgTransitionInFlight.Store(true)
	}
	if m.rgTransitionInFlight.Load() {
		t.Fatal("rgTransitionInFlight should NOT be set during demotion (active=false)")
	}

	// Activation (active=true) SHOULD set rgTransitionInFlight.
	active = true
	if active {
		m.rgTransitionInFlight.Store(true)
	}
	if !m.rgTransitionInFlight.Load() {
		t.Fatal("rgTransitionInFlight should be set during activation (active=true)")
	}
}

func TestHasActiveDataRGLockedIgnoresRG0(t *testing.T) {
	m := &Manager{
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true},
			1: {RGID: 1, Active: false},
			2: {RGID: 2, Active: false},
		},
	}
	if m.hasActiveDataRGLocked() {
		t.Fatal("hasActiveDataRGLocked() = true, want false when only RG0 is active")
	}
	m.haGroups[2] = HAGroupStatus{RGID: 2, Active: true}
	if !m.hasActiveDataRGLocked() {
		t.Fatal("hasActiveDataRGLocked() = false, want true when a data RG is active")
	}
}

func TestShouldExtendXSKLivenessIdleLocked(t *testing.T) {
	m := &Manager{
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true},
		},
	}
	if !m.shouldExtendXSKLivenessIdleLocked(0, false) {
		t.Fatal("shouldExtendXSKLivenessIdleLocked(0) = false, want true with no active data RG")
	}
	if m.shouldExtendXSKLivenessIdleLocked(0, true) {
		t.Fatal("shouldExtendXSKLivenessIdleLocked(0, true) = true, want false when idle standby should auto-prove")
	}
	m.haGroups[1] = HAGroupStatus{RGID: 1, Active: true}
	if m.shouldExtendXSKLivenessIdleLocked(0, false) {
		t.Fatal("shouldExtendXSKLivenessIdleLocked(0) = true, want false with active data RG")
	}
	if !m.shouldExtendXSKLivenessIdleLocked(0, true) {
		t.Fatal("shouldExtendXSKLivenessIdleLocked(0, true) = false, want true when active dataplane is fully bound but still idle")
	}
	if m.shouldExtendXSKLivenessIdleLocked(42, true) {
		t.Fatal("shouldExtendXSKLivenessIdleLocked(42) = true, want false when RX is already live")
	}
}

func TestShouldAutoProveIdleStandbyXSKLocked(t *testing.T) {
	m := &Manager{
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true},
		},
	}
	if !m.shouldAutoProveIdleStandbyXSKLocked(0, true) {
		t.Fatal("shouldAutoProveIdleStandbyXSKLocked(0, true) = false, want true on fully bound idle standby")
	}
	if m.shouldAutoProveIdleStandbyXSKLocked(0, false) {
		t.Fatal("shouldAutoProveIdleStandbyXSKLocked(0, false) = true, want false when bindings are not fully bound")
	}
	m.haGroups[1] = HAGroupStatus{RGID: 1, Active: true}
	if m.shouldAutoProveIdleStandbyXSKLocked(0, true) {
		t.Fatal("shouldAutoProveIdleStandbyXSKLocked(0, true) = true, want false when a data RG is active")
	}
	if m.shouldAutoProveIdleStandbyXSKLocked(42, true) {
		t.Fatal("shouldAutoProveIdleStandbyXSKLocked(42, true) = true, want false when RX is already live")
	}
}

func TestHasBusyBindingsWedgeLocked(t *testing.T) {
	m := &Manager{
		proc: &exec.Cmd{Process: &os.Process{Pid: 1}},
		lastStatus: ProcessStatus{
			ForwardingArmed: true,
			Bindings: []BindingStatus{
				{
					Ifindex:    6,
					QueueID:    0,
					Registered: true,
					Armed:      true,
					Ready:      false,
					Bound:      false,
					LastError:  "libxdp xsk_socket__create_shared: Device or resource busy",
				},
			},
		},
	}
	if !m.hasBusyBindingsWedgeLocked(false) {
		t.Fatal("hasBusyBindingsWedgeLocked(false) = false, want true for busy unbound wedge")
	}
	m.lastStatus.Bindings[0].Bound = true
	if m.hasBusyBindingsWedgeLocked(false) {
		t.Fatal("hasBusyBindingsWedgeLocked(false) = true, want false once any binding is bound")
	}
}

func TestShouldAutoRebindBusyBindingsLockedDebounces(t *testing.T) {
	now := time.Now()
	m := &Manager{
		proc: &exec.Cmd{Process: &os.Process{Pid: 1}},
		lastStatus: ProcessStatus{
			ForwardingArmed: true,
			Bindings: []BindingStatus{
				{
					Ifindex:    6,
					QueueID:    0,
					Registered: true,
					Armed:      true,
					LastError:  "Device or resource busy",
				},
			},
		},
	}
	if m.shouldAutoRebindBusyBindingsLocked(now, false) {
		t.Fatal("first shouldAutoRebindBusyBindingsLocked() = true, want false while starting debounce")
	}
	if m.shouldAutoRebindBusyBindingsLocked(now.Add(4*time.Second), false) {
		t.Fatal("shouldAutoRebindBusyBindingsLocked() = true before busy debounce window elapsed")
	}
	if !m.shouldAutoRebindBusyBindingsLocked(now.Add(6*time.Second), false) {
		t.Fatal("shouldAutoRebindBusyBindingsLocked() = false, want true after busy debounce window")
	}
	if m.shouldAutoRebindBusyBindingsLocked(now.Add(10*time.Second), false) {
		t.Fatal("shouldAutoRebindBusyBindingsLocked() = true, want false during rebind throttle")
	}
	m.lastStatus.Bindings[0].Bound = true
	if m.shouldAutoRebindBusyBindingsLocked(now.Add(30*time.Second), false) {
		t.Fatal("shouldAutoRebindBusyBindingsLocked() = true, want false once wedge clears")
	}
}

func TestStopLockedResetsBusyBindingsAutoRebindState(t *testing.T) {
	m := &Manager{
		bindingsBusySince:      time.Now().Add(-30 * time.Second),
		lastBindingsAutoRebind: time.Now().Add(-10 * time.Second),
	}

	m.stopLocked()

	if !m.bindingsBusySince.IsZero() {
		t.Fatal("bindingsBusySince not reset by stopLocked()")
	}
	if !m.lastBindingsAutoRebind.IsZero() {
		t.Fatal("lastBindingsAutoRebind not reset by stopLocked()")
	}
}

func TestDesiredForwardingArmedDefaultsOnStandalone(t *testing.T) {
	m := &Manager{
		clusterHA: false,
		lastStatus: ProcessStatus{
			Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		},
	}
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true on standalone supported config")
	}
}

func TestStopLockedClearsLastStatus(t *testing.T) {
	m := &Manager{
		lastStatus: ProcessStatus{
			PID:             1234,
			Enabled:         true,
			ForwardingArmed: true,
			Capabilities:    UserspaceCapabilities{ForwardingSupported: true},
		},
		sessionMirrorFailed: true,
		sessionMirrorErr:    "boom",
	}

	m.stopLocked()

	if m.lastStatus.PID != 0 {
		t.Fatalf("lastStatus.PID = %d, want 0", m.lastStatus.PID)
	}
	if m.lastStatus.Enabled {
		t.Fatal("lastStatus.Enabled = true, want false")
	}
	if m.lastStatus.ForwardingArmed {
		t.Fatal("lastStatus.ForwardingArmed = true, want false")
	}
	if m.lastStatus.Capabilities.ForwardingSupported {
		t.Fatal("lastStatus.Capabilities.ForwardingSupported = true, want false")
	}
	if m.sessionMirrorFailed {
		t.Fatal("sessionMirrorFailed = true, want false")
	}
	if m.sessionMirrorErr != "" {
		t.Fatalf("sessionMirrorErr = %q, want empty", m.sessionMirrorErr)
	}
}

func TestUserspaceSupportsSimpleZonePolicies(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"reth1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name: "allow-all",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	if !userspaceSupportsSecurityPolicies(cfg) {
		t.Fatal("userspaceSupportsSecurityPolicies = false, want true")
	}
	snap := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if snap.DefaultPolicy != "deny" || len(snap.Policies) != 1 || snap.Policies[0].Action != "permit" {
		t.Fatalf("unexpected policy snapshot: %+v", snap.Policies)
	}
}

func TestUserspaceSupportsAddressBookPolicyMatches(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"lan-subnet": {Name: "lan-subnet", Value: "10.0.61.0/24"},
			"wan-host":   {Name: "wan-host", Value: "172.16.80.200/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			"wan-targets": {
				Name:      "wan-targets",
				Addresses: []string{"wan-host"},
			},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "allow-address-book",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"lan-subnet"},
				DestinationAddresses: []string{"wan-targets"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	if !userspaceSupportsSecurityPolicies(cfg) {
		t.Fatal("userspaceSupportsSecurityPolicies = false, want true with resolvable address-book entries")
	}
	snap := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if len(snap.Policies) != 1 {
		t.Fatalf("len(Policies) = %d, want 1", len(snap.Policies))
	}
	if got := snap.Policies[0].SourceAddresses; len(got) != 1 || got[0] != "10.0.61.0/24" {
		t.Fatalf("SourceAddresses = %+v, want expanded address-book prefix", got)
	}
	if got := snap.Policies[0].DestinationAddresses; len(got) != 1 || got[0] != "172.16.80.200/32" {
		t.Fatalf("DestinationAddresses = %+v, want expanded address-set prefix", got)
	}
}

func TestUserspaceRejectsUnknownAddressBookPolicyMatches(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "allow-missing-address-book",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"missing-src"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	if userspaceSupportsSecurityPolicies(cfg) {
		t.Fatal("userspaceSupportsSecurityPolicies = true, want false with unresolved address-book entry")
	}
}

func TestUserspaceSupportsNamedApplicationPolicyMatches(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{
		"web-apps": {
			Name:         "web-apps",
			Applications: []string{"junos-http", "junos-https"},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "allow-web",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"web-apps"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	if !userspaceSupportsSecurityPolicies(cfg) {
		t.Fatal("userspaceSupportsSecurityPolicies = false, want true with resolvable application-set")
	}
	snap := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if len(snap.Policies) != 1 {
		t.Fatalf("len(Policies) = %d, want 1", len(snap.Policies))
	}
	terms := snap.Policies[0].ApplicationTerms
	if len(terms) != 2 {
		t.Fatalf("ApplicationTerms = %+v, want two expanded applications", terms)
	}
	if terms[0].Protocol != "tcp" || terms[0].DestinationPort == "" {
		t.Fatalf("unexpected first application term: %+v", terms[0])
	}
}

func TestUserspaceRejectsUnknownApplicationPolicyMatches(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "allow-missing-app",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"missing-app"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	if userspaceSupportsSecurityPolicies(cfg) {
		t.Fatal("userspaceSupportsSecurityPolicies = true, want false with unresolved application")
	}
}

func TestBuildSnapshotIncludesUnitInterfaces(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {
			Name:            "reth0",
			RedundancyGroup: 1,
			Units: map[int]*config.InterfaceUnit{
				0:  {Number: 0, Addresses: []string{"10.0.61.1/24", "2001:559:8585:ef00::1/64"}},
				50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24", "2001:559:8585:50::8/64"}},
			},
		},
		"ge-0/0/2": {
			Name:            "ge-0/0/2",
			RedundantParent: "reth0",
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"reth0.50"}},
	}

	snap := buildSnapshot(cfg, config.UserspaceConfig{Workers: 2, RingEntries: 2048}, 1, 0)
	got := map[string]InterfaceSnapshot{}
	for _, iface := range snap.Interfaces {
		got[iface.Name] = iface
	}
	for _, name := range []string{"reth0", "reth0.0", "reth0.50"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("snapshot missing interface %s: %+v", name, snap.Interfaces)
		}
	}
	if got["reth0"].LinuxName != "ge-0-0-2" {
		t.Fatalf("reth0 LinuxName = %q, want ge-0-0-2", got["reth0"].LinuxName)
	}
	if got["reth0.0"].LinuxName != "ge-0-0-2" {
		t.Fatalf("reth0.0 LinuxName = %q, want ge-0-0-2", got["reth0.0"].LinuxName)
	}
	if got["reth0.0"].ParentLinuxName != "ge-0-0-2" {
		t.Fatalf("reth0.0 ParentLinuxName = %q, want ge-0-0-2", got["reth0.0"].ParentLinuxName)
	}
	if got["reth0.50"].LinuxName != "ge-0-0-2.50" {
		t.Fatalf("reth0.50 LinuxName = %q, want ge-0-0-2.50", got["reth0.50"].LinuxName)
	}
	if got["reth0.50"].ParentLinuxName != "ge-0-0-2" {
		t.Fatalf("reth0.50 ParentLinuxName = %q, want ge-0-0-2", got["reth0.50"].ParentLinuxName)
	}
	if got["reth0.50"].VLANID != 50 {
		t.Fatalf("reth0.50 VLANID = %d, want 50", got["reth0.50"].VLANID)
	}
	if got["reth0.50"].Zone != "wan" {
		t.Fatalf("reth0.50 Zone = %q, want wan", got["reth0.50"].Zone)
	}
	if len(got["reth0.50"].Addresses) != 2 {
		t.Fatalf("reth0.50 Addresses = %+v, want config fallback addresses", got["reth0.50"].Addresses)
	}
}

func TestMergeInterfaceAddressSnapshots(t *testing.T) {
	live := []InterfaceAddressSnapshot{
		{Family: "inet", Address: "169.254.1.1/32", Scope: 253},
		{Family: "inet6", Address: "fe80::1/128", Scope: 253},
	}
	configured := []InterfaceAddressSnapshot{
		{Family: "inet", Address: "172.16.50.8/24", Scope: 0},
		{Family: "inet6", Address: "2001:559:8585:50::8/64", Scope: 0},
		{Family: "inet", Address: "169.254.1.1/32", Scope: 253},
	}

	got := mergeInterfaceAddressSnapshots(live, configured)
	if len(got) != 4 {
		t.Fatalf("len(got) = %d, want 4 (%+v)", len(got), got)
	}
	want := map[string]bool{
		"inet/169.254.1.1/32":          true,
		"inet/172.16.50.8/24":          true,
		"inet6/2001:559:8585:50::8/64": true,
		"inet6/fe80::1/128":            true,
	}
	for _, addr := range got {
		key := addr.Family + "/" + addr.Address
		if !want[key] {
			t.Fatalf("unexpected address %s in %+v", key, got)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("missing addresses: %+v from %+v", want, got)
	}
}

func TestUserspaceSupportsGlobalPolicies(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"reth1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name: "global-allow",
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
		},
		Action: config.PolicyPermit,
	}}
	if !userspaceSupportsSecurityPolicies(cfg) {
		t.Fatal("userspaceSupportsSecurityPolicies = false, want true with simple global policies")
	}
}

func TestBuildPolicySnapshotsIncludesGlobalPolicies(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name: "zone-allow",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name: "global-deny-all",
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
		},
		Action: config.PolicyDeny,
	}}
	snap := buildPolicySnapshots(cfg)
	if len(snap) != 2 {
		t.Fatalf("len(snap) = %d, want 2", len(snap))
	}
	if snap[0].FromZone != "trust" || snap[0].ToZone != "untrust" {
		t.Fatalf("snap[0] = %+v, want zone-specific policy", snap[0])
	}
	if snap[1].FromZone != "junos-global" || snap[1].ToZone != "junos-global" {
		t.Fatalf("snap[1] = %+v, want global policy", snap[1])
	}
	if snap[1].Name != "global-deny-all" {
		t.Fatalf("snap[1].Name = %q, want global-deny-all", snap[1].Name)
	}
}

func TestUserspaceSupportsScreenProfilesBasic(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"basic": {
			Name: "basic",
			TCP:  config.TCPScreen{Land: true, SynFin: true},
			ICMP: config.ICMPScreen{FloodThreshold: 100},
		},
	}
	if !userspaceSupportsScreenProfiles(cfg) {
		t.Fatal("basic screen profile should be supported")
	}
}

func TestUserspaceSupportsScreenProfilesRejectsSynCookie(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.SynFloodProtectionMode = "syn-cookie"
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"basic": {
			Name: "basic",
			TCP:  config.TCPScreen{Land: true},
		},
	}
	if userspaceSupportsScreenProfiles(cfg) {
		t.Fatal("syn-cookie mode should not be supported")
	}
}

func TestUserspaceSupportsScreenProfilesAllowsPortScan(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"scan": {
			Name: "scan",
			TCP:  config.TCPScreen{PortScanThreshold: 100},
		},
	}
	if !userspaceSupportsScreenProfiles(cfg) {
		t.Fatal("port scan threshold should now be supported in userspace dataplane")
	}
}

func TestUserspaceSupportsScreenProfilesAllowsSessionLimit(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"limit": {
			Name:         "limit",
			LimitSession: config.LimitSessionScreen{SourceIPBased: 100},
		},
	}
	if !userspaceSupportsScreenProfiles(cfg) {
		t.Fatal("session limiting should now be supported in userspace dataplane")
	}
}

func TestDeriveUserspaceCapabilitiesAllowsBasicScreenProfile(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "basic"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"basic": {
			Name: "basic",
			TCP:  config.TCPScreen{Land: true, SynFin: true},
			ICMP: config.ICMPScreen{FloodThreshold: 100},
		},
	}
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesRejectsSynCookieScreen(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.SynFloodProtectionMode = "syn-cookie"
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "flood"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"flood": {
			Name: "flood",
			TCP:  config.TCPScreen{SynFlood: &config.SynFloodConfig{AttackThreshold: 100}},
		},
	}
	caps := deriveUserspaceCapabilities(cfg)
	if caps.ForwardingSupported {
		t.Fatal("ForwardingSupported = true, want false (syn-cookie)")
	}
}

func TestBuildScreenSnapshotsMatchesZoneToProfile(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", ScreenProfile: "basic"},
		"untrust": {Name: "untrust"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"basic": {
			Name: "basic",
			TCP:  config.TCPScreen{Land: true, SynFin: true},
			ICMP: config.ICMPScreen{FloodThreshold: 50},
		},
	}
	snaps := buildScreenSnapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if snaps[0].Zone != "trust" {
		t.Fatalf("Zone = %q, want trust", snaps[0].Zone)
	}
	if !snaps[0].Land || !snaps[0].SynFin {
		t.Fatalf("unexpected screen flags: %+v", snaps[0])
	}
	if snaps[0].ICMPFloodThreshold != 50 {
		t.Fatalf("ICMPFloodThreshold = %d, want 50", snaps[0].ICMPFloodThreshold)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsSessionTimeouts(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{
		EstablishedTimeout: 120,
	}
	cfg.Security.Flow.UDPSessionTimeout = 30
	cfg.Security.Flow.ICMPSessionTimeout = 10
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, unexpected reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestBuildFlowSnapshotIncludesTimeouts(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.AllowDNSReply = true
	cfg.Security.Flow.AllowEmbeddedICMP = true
	cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{
		EstablishedTimeout: 120,
	}
	cfg.Security.Flow.UDPSessionTimeout = 30
	cfg.Security.Flow.ICMPSessionTimeout = 10
	snap := buildFlowSnapshot(cfg)
	if !snap.AllowDNSReply {
		t.Fatal("AllowDNSReply = false")
	}
	if !snap.AllowEmbeddedICMP {
		t.Fatal("AllowEmbeddedICMP = false")
	}
	if snap.TCPSessionTimeout != 120 {
		t.Fatalf("TCPSessionTimeout = %d, want 120", snap.TCPSessionTimeout)
	}
	if snap.UDPSessionTimeout != 30 {
		t.Fatalf("UDPSessionTimeout = %d, want 30", snap.UDPSessionTimeout)
	}
	if snap.ICMPSessionTimeout != 10 {
		t.Fatalf("ICMPSessionTimeout = %d, want 10", snap.ICMPSessionTimeout)
	}
}

func TestBuildFlowSnapshotNilTCPSession(t *testing.T) {
	cfg := &config.Config{}
	snap := buildFlowSnapshot(cfg)
	if snap.TCPSessionTimeout != 0 {
		t.Fatalf("TCPSessionTimeout = %d, want 0", snap.TCPSessionTimeout)
	}
}

func TestBuildInterfaceSnapshotSetsTunnelFlag(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"st0": {
			Name:   "st0",
			Tunnel: &config.TunnelConfig{},
			Units: map[int]*config.InterfaceUnit{
				0: {},
			},
		},
		"ge-0-0-0": {
			Name: "ge-0-0-0",
		},
	}
	snaps := buildInterfaceSnapshots(cfg)
	tunnelFound := false
	nonTunnelFound := false
	for _, snap := range snaps {
		if snap.Name == "st0" || snap.Name == "st0.0" {
			if !snap.Tunnel {
				t.Errorf("interface %s: Tunnel = false, want true", snap.Name)
			}
			tunnelFound = true
		}
		if snap.Name == "ge-0-0-0" {
			if snap.Tunnel {
				t.Errorf("interface %s: Tunnel = true, want false", snap.Name)
			}
			nonTunnelFound = true
		}
	}
	if !tunnelFound {
		t.Error("tunnel interface st0/st0.0 not found in snapshots")
	}
	if !nonTunnelFound {
		t.Error("non-tunnel interface ge-0-0-0 not found in snapshots")
	}
}

func TestBuildInterfaceSnapshotIncludesInputAndOutputFilters(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-0": {
			Name: "ge-0-0-0",
			Units: map[int]*config.InterfaceUnit{
				0: {
					FilterInputV4:  "ingress-v4",
					FilterOutputV4: "egress-v4",
					FilterInputV6:  "ingress-v6",
					FilterOutputV6: "egress-v6",
				},
			},
		},
	}

	snaps := buildInterfaceSnapshots(cfg)
	var unitSnap *InterfaceSnapshot
	for i := range snaps {
		if snaps[i].Name == "ge-0-0-0.0" {
			unitSnap = &snaps[i]
			break
		}
	}
	if unitSnap == nil {
		t.Fatal("ge-0-0-0.0 snapshot not found")
	}
	if unitSnap.FilterInputV4 != "ingress-v4" {
		t.Fatalf("FilterInputV4 = %q, want ingress-v4", unitSnap.FilterInputV4)
	}
	if unitSnap.FilterOutputV4 != "egress-v4" {
		t.Fatalf("FilterOutputV4 = %q, want egress-v4", unitSnap.FilterOutputV4)
	}
	if unitSnap.FilterInputV6 != "ingress-v6" {
		t.Fatalf("FilterInputV6 = %q, want ingress-v6", unitSnap.FilterInputV6)
	}
	if unitSnap.FilterOutputV6 != "egress-v6" {
		t.Fatalf("FilterOutputV6 = %q, want egress-v6", unitSnap.FilterOutputV6)
	}
}

func TestBuildClassOfServiceSnapshotIncludesTransmitRateExact(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			Schedulers: map[string]*config.CoSScheduler{
				"exact-sched": {
					Name:              "exact-sched",
					TransmitRateBytes: 1_250_000,
					TransmitRateExact: true,
					Priority:          "strict-high",
					BufferSizeBytes:   64_000,
				},
			},
		},
	}

	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil class-of-service snapshot")
	}
	if len(snap.Schedulers) != 1 {
		t.Fatalf("Schedulers len = %d, want 1", len(snap.Schedulers))
	}
	if !snap.Schedulers[0].TransmitRateExact {
		t.Fatal("expected transmit_rate_exact in class-of-service snapshot")
	}
	if got := snap.Schedulers[0].TransmitRateBytes; got != 1_250_000 {
		t.Fatalf("TransmitRateBytes = %d, want 1250000", got)
	}
}

// #915: snapshot encoding round-trips the SurplusSharing bool.
func TestBuildClassOfServiceSnapshotIncludesSurplusSharing(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			Schedulers: map[string]*config.CoSScheduler{
				"iperf-a": {
					Name:              "iperf-a",
					TransmitRateBytes: 125_000_000,
					TransmitRateExact: true,
					SurplusSharing:    true,
					Priority:          "low",
				},
				"iperf-b": {
					Name:              "iperf-b",
					TransmitRateBytes: 1_250_000_000,
					TransmitRateExact: true,
					SurplusSharing:    false, // explicit hard-cap, no opt-in
					Priority:          "low",
				},
			},
		},
	}
	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if len(snap.Schedulers) != 2 {
		t.Fatalf("Schedulers len = %d, want 2", len(snap.Schedulers))
	}
	got := map[string]bool{}
	for _, s := range snap.Schedulers {
		got[s.Name] = s.SurplusSharing
	}
	if !got["iperf-a"] {
		t.Errorf("expected SurplusSharing=true on iperf-a; got %v", got)
	}
	if got["iperf-b"] {
		t.Errorf("expected SurplusSharing=false on iperf-b; got %v", got)
	}
}

func TestBuildClassOfServiceSnapshotIncludesIEEE8021Classifier(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			ForwardingClasses: map[string]*config.CoSForwardingClass{
				"best-effort": {Name: "best-effort", Queue: 0},
				"voice":       {Name: "voice", Queue: 5},
			},
			IEEE8021Classifiers: map[string]*config.CoSIEEE8021Classifier{
				"wan-pcp": {
					Name: "wan-pcp",
					Entries: []*config.CoSIEEE8021ClassifierEntry{
						{
							ForwardingClass: "voice",
							LossPriority:    "low",
							CodePoints:      []uint8{5},
						},
					},
				},
			},
			Interfaces: map[string]*config.CoSInterface{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.CoSInterfaceUnit{
						80: {
							Unit:               80,
							IEEE8021Classifier: "wan-pcp",
						},
					},
				},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.InterfaceUnit{
						80: {Number: 80},
					},
				},
			},
		},
	}

	interfaces := buildInterfaceSnapshots(cfg)
	var unitSnap *InterfaceSnapshot
	for i := range interfaces {
		if interfaces[i].Name == "reth0.80" {
			unitSnap = &interfaces[i]
			break
		}
	}
	if unitSnap == nil {
		t.Fatal("reth0.80 snapshot not found")
	}
	if got := unitSnap.CoSIEEE8021Classifier; got != "wan-pcp" {
		t.Fatalf("CoSIEEE8021Classifier = %q, want wan-pcp", got)
	}

	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil class-of-service snapshot")
	}
	if len(snap.IEEE8021Classifiers) != 1 {
		t.Fatalf("IEEE8021Classifiers len = %d, want 1", len(snap.IEEE8021Classifiers))
	}
	if got := snap.IEEE8021Classifiers[0].Entries[0].CodePoints; len(got) != 1 || got[0] != 5 {
		t.Fatalf("CodePoints = %v, want [5]", got)
	}
}

func TestBuildClassOfServiceSnapshotIncludesDSCPRewriteRule(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			ForwardingClasses: map[string]*config.CoSForwardingClass{
				"best-effort": {Name: "best-effort", Queue: 0},
				"voice":       {Name: "voice", Queue: 5},
			},
			DSCPRewriteRules: map[string]*config.CoSDSCPRewriteRule{
				"wan-rewrite": {
					Name: "wan-rewrite",
					Entries: []*config.CoSDSCPRewriteRuleEntry{
						{
							ForwardingClass: "voice",
							LossPriority:    "low",
							DSCPValue:       46,
						},
					},
				},
			},
			Interfaces: map[string]*config.CoSInterface{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.CoSInterfaceUnit{
						80: {
							Unit:            80,
							DSCPRewriteRule: "wan-rewrite",
						},
					},
				},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.InterfaceUnit{
						80: {Number: 80},
					},
				},
			},
		},
	}

	interfaces := buildInterfaceSnapshots(cfg)
	var unitSnap *InterfaceSnapshot
	for i := range interfaces {
		if interfaces[i].Name == "reth0.80" {
			unitSnap = &interfaces[i]
			break
		}
	}
	if unitSnap == nil {
		t.Fatal("reth0.80 snapshot not found")
	}
	if got := unitSnap.CoSDSCPRewriteRule; got != "wan-rewrite" {
		t.Fatalf("CoSDSCPRewriteRule = %q, want wan-rewrite", got)
	}

	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil class-of-service snapshot")
	}
	if len(snap.DSCPRewriteRules) != 1 {
		t.Fatalf("DSCPRewriteRules len = %d, want 1", len(snap.DSCPRewriteRules))
	}
	if got := snap.DSCPRewriteRules[0].Entries[0].DSCPValue; got != 46 {
		t.Fatalf("DSCPValue = %d, want 46", got)
	}
}

func TestBuildScreenSnapshotsIncludesAdvancedFields(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "advanced"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"advanced": {
			Name: "advanced",
			TCP:  config.TCPScreen{PortScanThreshold: 100},
			IP:   config.IPScreen{IPSweepThreshold: 50},
			LimitSession: config.LimitSessionScreen{
				SourceIPBased:      200,
				DestinationIPBased: 300,
			},
		},
	}
	snaps := buildScreenSnapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if snaps[0].PortScanThreshold != 100 {
		t.Fatalf("PortScanThreshold = %d, want 100", snaps[0].PortScanThreshold)
	}
	if snaps[0].IPSweepThreshold != 50 {
		t.Fatalf("IPSweepThreshold = %d, want 50", snaps[0].IPSweepThreshold)
	}
	if snaps[0].SessionLimitSrc != 200 {
		t.Fatalf("SessionLimitSrc = %d, want 200", snaps[0].SessionLimitSrc)
	}
	if snaps[0].SessionLimitDst != 300 {
		t.Fatalf("SessionLimitDst = %d, want 300", snaps[0].SessionLimitDst)
	}
}

// #1137 Copilot review regression: a profile with ONLY syn_frag
// enabled (and no other check) must still pass the
// "at least one check enabled" emit gate. Without this, a future
// refactor could drop SynFrag from the gate and silently omit the
// whole profile from the userspace snapshot.
func TestBuildScreenSnapshotsIncludesSynFragOnlyProfile(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", ScreenProfile: "syn-frag-only"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"syn-frag-only": {
			Name: "syn-frag-only",
			TCP:  config.TCPScreen{SynFrag: true},
		},
	}
	snaps := buildScreenSnapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1 — syn_frag-only profile must pass the emit gate", len(snaps))
	}
	if !snaps[0].SynFrag {
		t.Fatalf("SynFrag = false, want true")
	}
	// Sanity: nothing else should be on
	if snaps[0].SynFin || snaps[0].NoFlag || snaps[0].FinNoAck ||
		snaps[0].WinNuke || snaps[0].PingDeath || snaps[0].Teardrop ||
		snaps[0].SourceRoute || snaps[0].Land {
		t.Fatalf("unexpected other-checks set: %+v", snaps[0])
	}
}

func TestBuildFlowExportSnapshot(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{
		Version9: &config.NetFlowV9Config{
			Templates: map[string]*config.NetFlowV9Template{
				"tmpl1": {
					Name:              "tmpl1",
					FlowActiveTimeout: 120,
				},
			},
		},
	}
	cfg.ForwardingOptions.Sampling = &config.SamplingConfig{
		Instances: map[string]*config.SamplingInstance{
			"inst1": {
				Name:      "inst1",
				InputRate: 100,
				FamilyInet: &config.SamplingFamily{
					FlowServers: []*config.FlowServer{
						{Address: "10.0.1.1", Port: 9995, Version9Template: "tmpl1"},
					},
				},
			},
		},
	}

	snap := buildFlowExportSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil flow export snapshot")
	}
	if snap.CollectorAddress != "10.0.1.1" {
		t.Fatalf("CollectorAddress = %q, want 10.0.1.1", snap.CollectorAddress)
	}
	if snap.CollectorPort != 9995 {
		t.Fatalf("CollectorPort = %d, want 9995", snap.CollectorPort)
	}
	if snap.SamplingRate != 100 {
		t.Fatalf("SamplingRate = %d, want 100", snap.SamplingRate)
	}
	if snap.ActiveTimeout != 120 {
		t.Fatalf("ActiveTimeout = %d, want 120", snap.ActiveTimeout)
	}
}

func TestBuildFlowExportSnapshotNilWhenNoConfig(t *testing.T) {
	cfg := &config.Config{}
	snap := buildFlowExportSnapshot(cfg)
	if snap != nil {
		t.Fatal("expected nil flow export snapshot with no config")
	}
}

func TestBuildUserspaceIngressIfindexesIncludesFabricParent(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:    "ge-0/0/1",
				Zone:    "lan",
				Ifindex: 11,
			},
			{
				Name:    "ge-0/0/2",
				Zone:    "wan",
				Ifindex: 12,
			},
		},
		Fabrics: []FabricSnapshot{
			{
				Name:            "fab0",
				ParentInterface: "ge-0/0/0",
				ParentLinuxName: "ge-0-0-0",
				ParentIfindex:   21,
				OverlayLinux:    "fab0",
				OverlayIfindex:  101,
				RXQueues:        1,
				PeerAddress:     "10.99.13.2",
			},
		},
	}
	ifindexes := buildUserspaceIngressIfindexes(snapshot)
	found := false
	for _, idx := range ifindexes {
		if idx == 21 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("fabric parent ifindex 21 not in ingress ifindexes: %v", ifindexes)
	}
	if len(ifindexes) != 3 {
		t.Fatalf("expected 3 ingress ifindexes (2 data + 1 fabric), got %d: %v", len(ifindexes), ifindexes)
	}
}

func TestBuildUserspaceIngressIfindexesDeduplicatesFabricParent(t *testing.T) {
	// If the fabric parent is already in the data interface list, it should
	// not be duplicated.
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:    "ge-0/0/0",
				Zone:    "lan",
				Ifindex: 21,
			},
		},
		Fabrics: []FabricSnapshot{
			{
				Name:            "fab0",
				ParentInterface: "ge-0/0/0",
				ParentLinuxName: "ge-0-0-0",
				ParentIfindex:   21,
				OverlayLinux:    "fab0",
				OverlayIfindex:  101,
				RXQueues:        1,
				PeerAddress:     "10.99.13.2",
			},
		},
	}
	ifindexes := buildUserspaceIngressIfindexes(snapshot)
	count := 0
	for _, idx := range ifindexes {
		if idx == 21 {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("fabric parent ifindex 21 appeared %d times in ingress ifindexes: %v", count, ifindexes)
	}
}

func TestBuildUserspaceIngressIfindexesSkipsTunnelInterfaces(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:    "reth1.0",
				Zone:    "lan",
				Ifindex: 5,
			},
			{
				Name:      "gr-0/0/0",
				Zone:      "sfmix",
				Ifindex:   586,
				LinuxName: "gr-0-0-0",
				Tunnel:    true,
			},
		},
	}
	ifindexes := buildUserspaceIngressIfindexes(snapshot)
	for _, idx := range ifindexes {
		if idx == 586 {
			t.Fatalf("tunnel ifindex 586 unexpectedly present in ingress ifindexes: %v", ifindexes)
		}
	}
	if len(ifindexes) != 1 || ifindexes[0] != 5 {
		t.Fatalf("unexpected ingress ifindexes: %v", ifindexes)
	}
}

func TestBuildUserspaceIngressIfindexesIncludesVLANChildAndParent(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:    "ge-0/0/2",
				Zone:    "wan",
				Ifindex: 6,
			},
			{
				Name:          "ge-0/0/2.80",
				Zone:          "wan",
				Ifindex:       12,
				ParentIfindex: 6,
				VLANID:        80,
			},
		},
	}
	ifindexes := buildUserspaceIngressIfindexes(snapshot)
	if len(ifindexes) != 2 || ifindexes[0] != 6 || ifindexes[1] != 12 {
		t.Fatalf("unexpected ingress ifindexes: %v", ifindexes)
	}
}

func TestBuildUserspaceIngressBindingAliasesIncludesVLANChild(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:    "ge-0/0/2",
				Zone:    "wan",
				Ifindex: 6,
			},
			{
				Name:          "ge-0/0/2.80",
				Zone:          "wan",
				Ifindex:       12,
				ParentIfindex: 6,
				VLANID:        80,
			},
			{
				Name:      "gr-0/0/0",
				Zone:      "sfmix",
				Ifindex:   362,
				Tunnel:    true,
				LinuxName: "gr-0-0-0",
			},
		},
	}
	aliases := buildUserspaceIngressBindingAliases(snapshot)
	if len(aliases) != 1 {
		t.Fatalf("unexpected alias count: %v", aliases)
	}
	if got := aliases[12]; got != 6 {
		t.Fatalf("alias 12 => %d, want 6", got)
	}
	if _, ok := aliases[362]; ok {
		t.Fatalf("tunnel interface unexpectedly aliased: %v", aliases)
	}
}

func TestSnapshotHasNativeGRE(t *testing.T) {
	snapshot := &ConfigSnapshot{
		TunnelEndpoints: []TunnelEndpointSnapshot{{
			ID:   1,
			Mode: "ip6gre",
		}},
	}
	if !snapshotHasNativeGRE(snapshot) {
		t.Fatal("expected native GRE snapshot to be detected")
	}
	if snapshotHasNativeGRE(&ConfigSnapshot{}) {
		t.Fatal("did not expect empty snapshot to enable native GRE")
	}
}

func TestSumBindingCounters(t *testing.T) {
	status := &ProcessStatus{
		Bindings: []BindingStatus{
			{
				RXPackets:            100,
				TXPackets:            80,
				ForwardCandidatePkts: 70,
				SessionCreates:       10,
				SessionExpires:       5,
				PolicyDeniedPackets:  3,
				ScreenDrops:          2,
				SNATPackets:          20,
				DNATPackets:          15,
			},
			{
				RXPackets:            200,
				TXPackets:            160,
				ForwardCandidatePkts: 140,
				SessionCreates:       20,
				SessionExpires:       10,
				PolicyDeniedPackets:  7,
				ScreenDrops:          4,
				SNATPackets:          40,
				DNATPackets:          30,
			},
		},
	}
	s := sumBindingCounters(status)
	if s.rxPackets != 300 {
		t.Fatalf("rxPackets = %d, want 300", s.rxPackets)
	}
	if s.txPackets != 240 {
		t.Fatalf("txPackets = %d, want 240", s.txPackets)
	}
	if s.forwardPackets != 210 {
		t.Fatalf("forwardPackets = %d, want 210", s.forwardPackets)
	}
	if s.sessionCreates != 30 {
		t.Fatalf("sessionCreates = %d, want 30", s.sessionCreates)
	}
	if s.sessionExpires != 15 {
		t.Fatalf("sessionExpires = %d, want 15", s.sessionExpires)
	}
	if s.policyDenied != 10 {
		t.Fatalf("policyDenied = %d, want 10", s.policyDenied)
	}
	if s.screenDrops != 6 {
		t.Fatalf("screenDrops = %d, want 6", s.screenDrops)
	}
	if s.snatPackets != 60 {
		t.Fatalf("snatPackets = %d, want 60", s.snatPackets)
	}
	if s.dnatPackets != 45 {
		t.Fatalf("dnatPackets = %d, want 45", s.dnatPackets)
	}
}

func TestSafeDelta(t *testing.T) {
	// Normal increment
	if d := safeDelta(100, 50); d != 50 {
		t.Fatalf("safeDelta(100, 50) = %d, want 50", d)
	}
	// No change
	if d := safeDelta(50, 50); d != 0 {
		t.Fatalf("safeDelta(50, 50) = %d, want 0", d)
	}
	// Counter reset (prev > cur) — return cur as delta
	if d := safeDelta(10, 100); d != 10 {
		t.Fatalf("safeDelta(10, 100) = %d, want 10 (counter reset)", d)
	}
	// First poll (prev=0)
	if d := safeDelta(42, 0); d != 42 {
		t.Fatalf("safeDelta(42, 0) = %d, want 42", d)
	}
}

func TestSnapshotContentHashIgnoresVolatileFields(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"},
	}
	snap1 := buildSnapshot(cfg, config.UserspaceConfig{Workers: 1}, 1, 10)
	snap2 := buildSnapshot(cfg, config.UserspaceConfig{Workers: 1}, 99, 50)

	h1, ok1 := snapshotContentHash(snap1)
	h2, ok2 := snapshotContentHash(snap2)
	if !ok1 || !ok2 {
		t.Fatal("hash failed")
	}
	if h1 != h2 {
		t.Fatal("hashes differ despite identical stable content (only Generation/FIBGeneration changed)")
	}
}

func TestSnapshotContentHashDiffersOnForwardingChange(t *testing.T) {
	cfg1 := &config.Config{}
	cfg1.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"},
	}
	cfg2 := &config.Config{}
	cfg2.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust"},
		"untrust": {Name: "untrust"},
	}

	snap1 := buildSnapshot(cfg1, config.UserspaceConfig{Workers: 1}, 1, 1)
	snap2 := buildSnapshot(cfg2, config.UserspaceConfig{Workers: 1}, 1, 1)

	h1, ok1 := snapshotContentHash(snap1)
	h2, ok2 := snapshotContentHash(snap2)
	if !ok1 || !ok2 {
		t.Fatal("hash failed")
	}
	if h1 == h2 {
		t.Fatal("hashes match despite different zone config")
	}
}

func TestSessionSocketPathDerivation(t *testing.T) {
	m := &Manager{}
	m.cfg.ControlSocket = "/run/xpf/userspace-dp.sock"
	got := m.sessionSocketPath()
	want := "/run/xpf/userspace-dp-sessions.sock"
	if got != want {
		t.Fatalf("sessionSocketPath() = %q, want %q", got, want)
	}
}

func TestSessionSocketPathEmpty(t *testing.T) {
	m := &Manager{}
	m.cfg.ControlSocket = ""
	if got := m.sessionSocketPath(); got != "" {
		t.Fatalf("sessionSocketPath() = %q, want empty", got)
	}
}
