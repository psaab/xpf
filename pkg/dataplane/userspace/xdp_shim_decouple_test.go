package userspace

import (
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"golang.org/x/sys/unix"
)

func TestProgramBootstrapMapsDoesNotRequireLegacyFallbackProgram(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	injectCtrlAndBindingMaps(t, m)
	injectUserspaceBootstrapMaps(t, m)

	if err := m.programBootstrapMapsLocked(&ConfigSnapshot{}, config.UserspaceConfig{Workers: 1}); err != nil {
		t.Fatalf("programBootstrapMapsLocked without legacy fallback program: %v", err)
	}
}

func TestXSKLivenessFailureRestoresUserspaceShimEntry(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := &Manager{
		bpfShim:        dataplane.New(),
		configuredMode: ModeUserspaceCompat,
		// #9337: an ACTIVE data redundancy group. Since #6429 an expired probe
		// with no RX resolves three ways, and "liveness failed" — the branch
		// this cell is named for and asserts — is only one of them:
		// shouldExtendXSKLivenessIdleLocked EXTENDS the probe instead whenever
		// the node has no active data RG, which an empty haGroups map means.
		// With that map empty the cell measured the extension path while
		// asserting the failure path's outcome. It is memlock-gated, so the
		// drift never surfaced under `make test-go`.
		haGroups: map[int]HAGroupStatus{1: {RGID: 1, Active: true}},
	}
	injectShimProgramName(t, m.bpfShim, userspaceXDPEntryProg)
	injectCtrlAndBindingMaps(t, m)
	// #9337: applyHelperStatusLocked re-syncs the ingress/local/interface-NAT
	// classifier maps (#6994), which this fixture does not load — under CAP_BPF
	// it failed with "userspace_ingress_ifaces map not loaded" before reaching
	// anything this cell asserts. Unprivileged the whole test skips, so the gap
	// was invisible. The seam is the established remedy (#7468).
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.neighborsPrewarmed = true
	m.xskProbeStart = time.Now().Add(-11 * time.Second)

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
		}},
	}

	if err := m.applyHelperStatusLocked(&status); err != nil {
		t.Fatalf("applyHelperStatusLocked: %v", err)
	}
	if !m.xskLivenessFailed {
		t.Fatal("xskLivenessFailed = false, want true after expired liveness probe")
	}
	if got := m.bpfShim.XDPEntryProgram(); got != userspaceXDPEntryProg {
		t.Fatalf("XDPEntryProgram() = %q, want %q", got, userspaceXDPEntryProg)
	}
}

func TestUserspaceXDPDegradedCtrlDisabledDropsTransit(t *testing.T) {
	coll := loadUserspaceXDPTestCollection(t)
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
	})

	ret := runUserspaceXDPTestPacket(t, coll, udpIPv4TestPacket(
		[4]byte{198, 51, 100, 10},
		[4]byte{203, 0, 113, 20},
	))
	if ret != xdpActionDrop {
		t.Fatalf("ctrl-disabled transit action = %d, want XDP_DROP", ret)
	}
	assertUserspaceXDPDegradedPathStat(t, coll, "ctrl_disabled")
	assertUserspaceXDPDegradedPathStat(t, coll, "transit_drop")
}
func TestUserspaceXDPDegradedCtrlDisabledNDPRequiresLocalDestination(t *testing.T) {
	local := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	transit := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20}
	src := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}

	for _, tc := range []struct {
		name       string
		dst        [16]byte
		isLocal    bool
		wantAction uint32
		wantStat   string
	}{
		{
			name:       "global destination drops",
			dst:        transit,
			wantAction: xdpActionDrop,
			wantStat:   "transit_drop",
		},
		{
			name:       "configured local destination passes",
			dst:        local,
			isLocal:    true,
			wantAction: xdpActionPass,
			wantStat:   "pass_to_kernel",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
				Enabled:            0,
				MetadataVersion:    userspaceMetadataVersion,
				Workers:            1,
				QueueCount:         1,
				HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
			})
			if tc.isLocal {
				updateUserspaceXDPTestLocalV6(t, coll, tc.dst)
			}

			ret := runUserspaceXDPTestPacket(t, coll, icmpv6TestPacket(src, tc.dst, 135))
			if ret != tc.wantAction {
				t.Fatalf("ctrl-disabled NDP action = %d, want %d", ret, tc.wantAction)
			}
			assertUserspaceXDPDegradedPathStat(t, coll, "ctrl_disabled")
			assertUserspaceXDPDegradedPathStat(t, coll, tc.wantStat)
			if tc.isLocal {
				assertUserspaceXDPDegradedPathStatAbsent(t, coll, "transit_drop")
			} else {
				assertUserspaceXDPDegradedPathStatAbsent(t, coll, "pass_to_kernel")
			}
		})
	}
}

func TestUserspaceXDPDegradedCtrlDisabledPassesLocalControl(t *testing.T) {
	coll := loadUserspaceXDPTestCollection(t)
	local := [4]byte{192, 0, 2, 1}
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
	})
	updateUserspaceXDPTestLocalV4(t, coll, local)

	ret := runUserspaceXDPTestPacket(t, coll, udpIPv4TestPacket(
		[4]byte{198, 51, 100, 10},
		local,
	))
	if ret != xdpActionPass {
		t.Fatalf("ctrl-disabled local action = %d, want XDP_PASS", ret)
	}
	assertUserspaceXDPDegradedPathStat(t, coll, "ctrl_disabled")
	assertUserspaceXDPDegradedPathStat(t, coll, "pass_to_kernel")
	assertUserspaceXDPDegradedPathStatAbsent(t, coll, "transit_drop")
}

func TestUserspaceXDPBindingNotReadyDropsTransitButPassesLocalControl(t *testing.T) {
	for _, tc := range []struct {
		name     string
		dst      [4]byte
		local    bool
		want     uint32
		statName string
	}{
		{
			name:     "transit",
			dst:      [4]byte{203, 0, 113, 20},
			want:     xdpActionDrop,
			statName: "transit_drop",
		},
		{
			name:     "local",
			dst:      [4]byte{192, 0, 2, 1},
			local:    true,
			want:     xdpActionPass,
			statName: "pass_to_kernel",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
				Enabled:            1,
				MetadataVersion:    userspaceMetadataVersion,
				Workers:            1,
				QueueCount:         1,
				HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
			})
			// #9337: the ingress ifindex and binding index must be the ones
			// BPF_PROG_TEST_RUN actually presents (see
			// userspaceXDPTestRunIfindex). Seeded at 0, the shim never
			// recognised the ingress interface and XDP_PASSed with no
			// degraded reason at all.
			updateUserspaceXDPTestIngress(t, coll, userspaceXDPTestRunIfindex(t))
			updateUserspaceXDPTestBinding(t, coll, userspaceXDPTestRunBindingIndex(t, 0), userspaceBindingValue{
				Slot:  0,
				Flags: 2, // non-zero but not userspaceBindingReady
			})
			if tc.local {
				updateUserspaceXDPTestLocalV4(t, coll, tc.dst)
			}

			ret := runUserspaceXDPTestPacket(t, coll, udpIPv4TestPacket(
				[4]byte{198, 51, 100, 10},
				tc.dst,
			))
			if ret != tc.want {
				t.Fatalf("binding-not-ready %s action = %d, want %d", tc.name, ret, tc.want)
			}
			assertUserspaceXDPDegradedPathStat(t, coll, "binding_not_ready")
			assertUserspaceXDPDegradedPathStat(t, coll, tc.statName)
		})
	}
}

func TestUserspaceXDPIPLocalControlUsesCPUMapWhenAvailable(t *testing.T) {
	coll := loadUserspaceXDPTestCollection(t)
	enableUserspaceXDPTestCPUMap(t, coll)
	local := [4]byte{192, 0, 2, 1}
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		Flags:              userspaceCtrlFlagCPUMap,
		HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
	})
	updateUserspaceXDPTestLocalV4(t, coll, local)

	ret := runUserspaceXDPTestPacket(t, coll, udpIPv4TestPacket(
		[4]byte{198, 51, 100, 10},
		local,
	))
	if ret != xdpActionRedirect {
		t.Fatalf("ctrl-disabled local action with cpumap = %d, want XDP_REDIRECT", ret)
	}
	assertUserspaceXDPDegradedPathStat(t, coll, "ctrl_disabled")
	assertUserspaceXDPDegradedPathStat(t, coll, "pass_to_kernel")
	assertUserspaceXDPDegradedPathStatAbsent(t, coll, "transit_drop")
}

func TestUserspaceXDPNDPUsesCPUMapWhenAvailable(t *testing.T) {
	coll := loadUserspaceXDPTestCollection(t)
	enableUserspaceXDPTestCPUMap(t, coll)
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            1,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		Flags:              userspaceCtrlFlagCPUMap,
		HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
	})
	// #9337: see userspaceXDPTestRunIfindex — seeded at 0 these two lines
	// described an interface the run never arrives on.
	updateUserspaceXDPTestIngress(t, coll, userspaceXDPTestRunIfindex(t))
	updateUserspaceXDPTestBinding(t, coll, userspaceXDPTestRunBindingIndex(t, 0), userspaceBindingValue{
		Slot:  0,
		Flags: userspaceBindingReady,
	})
	updateUserspaceXDPTestHeartbeat(t, coll, 0)

	// #10640: unicast NDP uses the healthy local-destination arm, not a
	// type-only early pass.
	local := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	updateUserspaceXDPTestLocalV6(t, coll, local)

	ret := runUserspaceXDPTestPacket(t, coll, icmpv6TestPacket(
		[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10},
		local,
		136,
	))
	if ret != xdpActionRedirect {
		t.Fatalf("NDP action with cpumap = %d, want XDP_REDIRECT", ret)
	}
	// Healthy local delivery is not counted as a degraded-path fallback.
	assertUserspaceXDPDegradedPathStatAbsent(t, coll, "early_filter")
	assertUserspaceXDPDegradedPathStatAbsent(t, coll, "pass_to_kernel")
}

func TestUserspaceXDPDegradedESPToInterfaceNATPassesLocalControl(t *testing.T) {
	coll := loadUserspaceXDPTestCollection(t)
	natLocal := [4]byte{192, 0, 2, 254}
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
	})
	updateUserspaceXDPTestInterfaceNATV4(t, coll, natLocal)

	ret := runUserspaceXDPTestPacket(t, coll, espIPv4TestPacket(
		[4]byte{198, 51, 100, 10},
		natLocal,
	))
	if ret != xdpActionPass {
		t.Fatalf("ctrl-disabled ESP to interface NAT action = %d, want XDP_PASS", ret)
	}
	assertUserspaceXDPDegradedPathStat(t, coll, "ctrl_disabled")
	assertUserspaceXDPDegradedPathStat(t, coll, "pass_to_kernel")
	assertUserspaceXDPDegradedPathStatAbsent(t, coll, "transit_drop")
}

func TestUserspaceXDPDegradedNonIPL2PassesDirect(t *testing.T) {
	coll := loadUserspaceXDPTestCollection(t)
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		Flags:              userspaceCtrlFlagCPUMap,
		HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
	})

	ret := runUserspaceXDPTestPacket(t, coll, arpTestPacket())
	if ret != xdpActionPass {
		t.Fatalf("ctrl-disabled ARP action = %d, want XDP_PASS", ret)
	}
	assertUserspaceXDPDegradedPathStat(t, coll, "ctrl_disabled")
	assertUserspaceXDPDegradedPathStat(t, coll, "pass_to_kernel")
	assertUserspaceXDPDegradedPathStatAbsent(t, coll, "transit_drop")
}

func injectUserspaceBootstrapMaps(t *testing.T, m *Manager) {
	t.Helper()
	injectShimMapSpec(t, m.bpfShim, "userspace_heartbeat", &ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 4096,
	})
	injectShimMapSpec(t, m.bpfShim, "userspace_ingress_ifaces", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: dataplane.MaxInterfaces,
	})
	injectShimMapSpec(t, m.bpfShim, "userspace_local_v4", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 8192,
	})
	injectShimMapSpec(t, m.bpfShim, "userspace_local_v6", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(userspaceLocalV6Key{})),
		ValueSize:  1,
		MaxEntries: 8192,
	})
	injectShimMapSpec(t, m.bpfShim, "userspace_interface_nat_v4", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 8192,
	})
	injectShimMapSpec(t, m.bpfShim, "userspace_interface_nat_v6", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(userspaceLocalV6Key{})),
		ValueSize:  1,
		MaxEntries: 8192,
	})
}

func injectShimMapSpec(t *testing.T, bpfShim *dataplane.Manager, name string, spec *ebpf.MapSpec) {
	t.Helper()
	m, err := ebpf.NewMap(spec)
	if err != nil {
		skipIfBPFMapUnavailable(t, "new "+name+" map", err)
	}
	t.Cleanup(func() { m.Close() })
	injectShimMap(t, bpfShim, name, m)
}

func injectShimProgramName(t *testing.T, bpfShim *dataplane.Manager, name string) {
	t.Helper()
	managerValue := reflect.ValueOf(bpfShim)
	if managerValue.Kind() != reflect.Ptr || managerValue.IsNil() {
		t.Fatalf("injectShimProgramName: expected non-nil pointer, got %T", bpfShim)
	}
	managerElem := managerValue.Elem()
	rv := managerElem.FieldByName("programs")
	if !rv.IsValid() {
		t.Fatal("injectShimProgramName: dataplane.Manager has no field named \"programs\"")
	}
	rm := reflect.NewAt(rv.Type(), unsafe.Pointer(rv.UnsafeAddr())).Elem()
	if rm.IsNil() {
		rm.Set(reflect.MakeMap(rv.Type()))
	}
	// SwapToUserspaceXDPShimEntryProgram only needs the name to exist when no links are
	// attached, so a nil *ebpf.Program is sufficient for this unit test.
	rm.SetMapIndex(reflect.ValueOf(name), reflect.Zero(rv.Type().Elem()))
}

const (
	xdpActionDrop     = 1
	xdpActionPass     = 2
	xdpActionRedirect = 4
)

func loadUserspaceXDPTestCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpec(filepath.Join("..", "userspace_xdp_bpfel.o"))
	if err != nil {
		t.Fatalf("load userspace_xdp_bpfel.o spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") ||
			strings.Contains(err.Error(), "permission denied") {
			t.Skipf("load userspace XDP collection: %v", err)
		}
		t.Fatalf("load userspace XDP collection: %v", err)
	}
	t.Cleanup(func() { coll.Close() })
	return coll
}

func updateUserspaceXDPTestCtrl(t *testing.T, coll *ebpf.Collection, ctrl userspaceCtrlValue) {
	t.Helper()
	updateUserspaceXDPTestMap(t, coll, "userspace_ctrl", uint32(0), ctrl)
}

func updateUserspaceXDPTestBinding(t *testing.T, coll *ebpf.Collection, idx uint32, binding userspaceBindingValue) {
	t.Helper()
	updateUserspaceXDPTestMap(t, coll, "userspace_bindings", idx, binding)
}

func updateUserspaceXDPTestIngress(t *testing.T, coll *ebpf.Collection, ifindex uint32) {
	t.Helper()
	updateUserspaceXDPTestMap(t, coll, "userspace_ingress_ifaces", ifindex, uint8(1))
}

// userspaceXDPTestRunIfindex is the ingress ifindex BPF_PROG_TEST_RUN presents
// to an XDP program (#9337).
//
// It is NOT zero. bpf_prog_test_run_xdp registers the calling netns's LOOPBACK
// device as the run's RX queue (xdp_rxq_info_reg(..., net->loopback_dev, ...)),
// so ctx->ingress_ifindex is lo's, and the binding coordinate the shim derives
// from it is `ifindex * BINDING_QUEUES_PER_IFACE + rx_queue_index`, not 0.
//
// The two cells that seeded ifindex 0 therefore missed userspace_ingress_ifaces
// entirely: the shim treated the packet as arriving on an interface it does not
// manage and returned XDP_PASS with NO degraded reason recorded — which is why
// "binding-not-ready transit action = 2, want 1" was the symptom rather than a
// wrong reason code. They are memlock-gated, so this never showed under
// `make test-go`; measured only once #9337 ran the guards under CAP_BPF.
//
// Derived rather than hard-coded to 1: lo's index is conventionally 1 but is a
// property of the netns, not a constant.
func userspaceXDPTestRunIfindex(t *testing.T) uint32 {
	t.Helper()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("look up the loopback device BPF_PROG_TEST_RUN attaches the run to: %v", err)
	}
	return uint32(lo.Index)
}

// userspaceXDPTestRunBindingIndex is the binding-array index the shim resolves
// for a BPF_PROG_TEST_RUN packet on the given RX queue. Mirrors binding_slot in
// userspace-xdp/src/binding_index.rs.
func userspaceXDPTestRunBindingIndex(t *testing.T, rxQueue uint32) uint32 {
	t.Helper()
	return userspaceXDPTestRunIfindex(t)*bindingQueuesPerIface + rxQueue
}

// updateUserspaceXDPTestHeartbeat seeds userspace_heartbeat for a binding slot
// with a FRESH timestamp on the clock the shim reads (#9337).
//
// The shim's degraded gates are an ordered chain, and the heartbeat pair
// (missing, then stale) sits immediately after the binding-ready check. A cell
// whose binding IS ready therefore cannot reach anything past it without this:
// the array defaults to 0, `bpf_ktime_get_ns() - 0` exceeds any timeout, and
// the packet leaves as heartbeat_stale. CLOCK_MONOTONIC, not the manager's
// CLOCK_BOOTTIME helper — bpf_ktime_get_ns() is CLOCK_MONOTONIC, and seeding a
// BOOTTIME value on a host that has suspended writes a timestamp in the shim's
// future, which its `now_ns < *last_heartbeat` guard reads as stale.
func updateUserspaceXDPTestHeartbeat(t *testing.T, coll *ebpf.Collection, slot uint32) {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatalf("clock_gettime(CLOCK_MONOTONIC): %v", err)
	}
	now := uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
	updateUserspaceXDPTestMap(t, coll, "userspace_heartbeat", slot, now)
}

func updateUserspaceXDPTestLocalV4(t *testing.T, coll *ebpf.Collection, ip [4]byte) {
	t.Helper()
	updateUserspaceXDPTestMap(t, coll, "userspace_local_v4", binary.BigEndian.Uint32(ip[:]), uint8(1))
}
func updateUserspaceXDPTestLocalV6(t *testing.T, coll *ebpf.Collection, ip [16]byte) {
	t.Helper()
	updateUserspaceXDPTestMap(t, coll, "userspace_local_v6", userspaceLocalV6Key{Addr: ip}, uint8(1))
}

func updateUserspaceXDPTestInterfaceNATV4(t *testing.T, coll *ebpf.Collection, ip [4]byte) {
	t.Helper()
	updateUserspaceXDPTestMap(t, coll, "userspace_interface_nat_v4", binary.BigEndian.Uint32(ip[:]), uint8(1))
}

func enableUserspaceXDPTestCPUMap(t *testing.T, coll *ebpf.Collection) {
	t.Helper()
	m := coll.Maps["userspace_cpumap"]
	if m == nil {
		t.Fatal("userspace_cpumap map not loaded")
	}
	val := make([]byte, 8)
	binary.NativeEndian.PutUint32(val[0:4], 2048)
	cpus := runtime.NumCPU()
	if cpus > 256 {
		cpus = 256
	}
	for cpu := 0; cpu < cpus; cpu++ {
		if err := m.Update(uint32(cpu), val, ebpf.UpdateAny); err != nil {
			t.Skipf("update userspace_cpumap cpu %d: %v", cpu, err)
		}
	}
}

func updateUserspaceXDPTestMap(t *testing.T, coll *ebpf.Collection, name string, key any, value any) {
	t.Helper()
	m := coll.Maps[name]
	if m == nil {
		t.Fatalf("%s map not loaded", name)
	}
	if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
		t.Fatalf("update %s: %v", name, err)
	}
}

func runUserspaceXDPTestPacket(t *testing.T, coll *ebpf.Collection, packet []byte) uint32 {
	t.Helper()
	prog := coll.Programs[userspaceXDPEntryProg]
	if prog == nil {
		t.Fatalf("%s program not loaded", userspaceXDPEntryProg)
	}
	ret, _, err := prog.Test(packet)
	if err != nil {
		t.Fatalf("run %s: %v", userspaceXDPEntryProg, err)
	}
	return ret
}

func assertUserspaceXDPDegradedPathStat(t *testing.T, coll *ebpf.Collection, name string) {
	t.Helper()
	if got := userspaceXDPDegradedPathStat(t, coll, name); got == 0 {
		// #9337: name the reason that DID fire. "stat X = 0" says the expected
		// gate did not run and nothing about which one did, and the shim's
		// degraded gates are an ORDERED chain — the answer is almost always
		// "an earlier gate diverted the packet", which the counter set states
		// directly. Diagnosing this from the bare message cost a full source
		// read of userspace-xdp/src/lib.rs.
		t.Fatalf("degraded path stat %q = 0, want incremented. Reasons that DID "+
			"fire: %s", name, userspaceXDPDegradedPathStatsSummary(t, coll))
	}
}

// userspaceXDPDegradedPathStatsSummary renders every non-zero degraded-path
// reason, in the shim's own gate order.
func userspaceXDPDegradedPathStatsSummary(t *testing.T, coll *ebpf.Collection) string {
	t.Helper()
	var parts []string
	for _, reason := range degradedPathReasonNames {
		if reason == "" {
			continue
		}
		if got := userspaceXDPDegradedPathStat(t, coll, reason); got != 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", reason, got))
		}
	}
	if len(parts) == 0 {
		return "none — the packet never reached a degraded gate"
	}
	return strings.Join(parts, " ")
}

func assertUserspaceXDPDegradedPathStatAbsent(t *testing.T, coll *ebpf.Collection, name string) {
	t.Helper()
	if got := userspaceXDPDegradedPathStat(t, coll, name); got != 0 {
		t.Fatalf("degraded path stat %q = %d, want 0", name, got)
	}
}

func userspaceXDPDegradedPathStat(t *testing.T, coll *ebpf.Collection, name string) uint64 {
	t.Helper()
	stats := coll.Maps["userspace_fallback_stats"]
	if stats == nil {
		t.Fatal("userspace_fallback_stats compatibility map not loaded")
	}
	idx := degradedPathReasonIndex(t, name)
	// #4113 (F13): userspace_fallback_stats is a PER-CPU array; a per-CPU
	// lookup returns one value per possible CPU. Sum across CPUs to get the
	// cumulative count for this reason.
	var perCPU []uint64
	if err := stats.Lookup(idx, &perCPU); err != nil {
		t.Fatalf("lookup userspace_fallback_stats compatibility map[%d] (%s): %v", idx, name, err)
	}
	var got uint64
	for _, v := range perCPU {
		got += v
	}
	return got
}

func degradedPathReasonIndex(t *testing.T, name string) uint32 {
	t.Helper()
	for idx, candidate := range degradedPathReasonNames {
		if candidate == name {
			return uint32(idx)
		}
	}
	t.Fatalf("degraded path reason %q not found", name)
	return 0
}

func udpIPv4TestPacket(src [4]byte, dst [4]byte) []byte {
	return ipv4TestPacket(src, dst, 17, 8)
}

func espIPv4TestPacket(src [4]byte, dst [4]byte) []byte {
	return ipv4TestPacket(src, dst, 50, 8)
}

func ipv4TestPacket(src [4]byte, dst [4]byte, protocol byte, payloadLen int) []byte {
	packet := make([]byte, 14+20+8)
	if payloadLen > 8 {
		packet = make([]byte, 14+20+payloadLen)
	}
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)

	ip := packet[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)+payloadLen))
	ip[8] = 64
	ip[9] = protocol
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])

	if protocol == 17 {
		udp := packet[34:]
		binary.BigEndian.PutUint16(udp[0:2], 12345)
		binary.BigEndian.PutUint16(udp[2:4], 443)
		binary.BigEndian.PutUint16(udp[4:6], uint16(payloadLen))
	}
	return packet
}

func icmpv6TestPacket(src [16]byte, dst [16]byte, icmpType byte) []byte {
	packet := make([]byte, 14+40+8)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x86dd)

	ip := packet[14:54]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 8)
	ip[6] = 58
	ip[7] = 255
	copy(ip[8:24], src[:])
	copy(ip[24:40], dst[:])

	icmp := packet[54:]
	icmp[0] = icmpType
	return packet
}

func arpTestPacket() []byte {
	packet := make([]byte, 14+28)
	copy(packet[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x0806)
	return packet
}
