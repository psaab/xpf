package userspace

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestDegradedPathReasonNamesCoverRetainedShimActions(t *testing.T) {
	found := map[string]bool{}
	for _, name := range degradedPathReasonNames {
		found[name] = true
	}

	for _, name := range []string{
		"ctrl_disabled",
		"pass_to_kernel",
		"transit_drop",
		"strict_drop",
		"redirect_err",
		"binding_missing",
		"binding_not_ready",
		"heartbeat_missing",
		"heartbeat_stale",
		"adjust_meta",
		"meta_bounds",
		"qinq_drop",
		"stag_drop",
	} {
		if !found[name] {
			t.Fatalf("degraded path reason %q missing from %v", name, degradedPathReasonNames)
		}
	}
	if got, want := len(degradedPathReasonNames), 18; got != want {
		t.Fatalf("degradedPathReasonNames length = %d, want %d", got, want)
	}
	if got := mapNameUserspaceShimDegradedStats; got != "userspace_fallback_stats" {
		t.Fatalf("mapNameUserspaceShimDegradedStats = %q, want pinned compatibility map name", got)
	}
	for idx, name := range degradedPathReasonNames {
		if name == "" {
			t.Fatalf("degradedPathReasonNames[%d] is empty", idx)
		}
	}
}

// TestApplyHelperStatusRejectsOverCapIfindex verifies that a binding
// whose ifindex overflows the userspace_bindings Array cap is caught
// at the call site with a legible error rather than bubbling up the
// kernel's generic "argument list too long" from bpf_map_update_elem.
// See issue #814.
func TestApplyHelperStatusRejectsOverCapIfindex(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	m.bpfShim.SelectUserspaceXDPShimEntryProgram()
	ctrlMap, _ := injectCtrlAndBindingMaps(t, m)
	injectUserspaceSessionMap(t, m)
	m.neighborsPrewarmed = true
	m.xskLivenessProven = true
	m.publishedSnapshot = 1

	// Any ifindex >= MaxInterfaces overflows the flat
	// idx = ifindex*BindingQueuesPerIface + queue_id formula.
	overCapIfindex := int(dataplane.MaxInterfaces) + 7

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
			Ifindex:    overCapIfindex,
			Registered: true,
			Armed:      true,
			Bound:      true,
		}},
	}

	err := m.applyHelperStatusLocked(&status)
	if err == nil {
		t.Fatal("applyHelperStatusLocked returned nil for over-cap ifindex, want error")
	}
	// Error must be legible — name the cap and the remediation path.
	if !strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("error missing cap message: %v", err)
	}
	if !strings.Contains(err.Error(), "MAX_INTERFACES") {
		t.Fatalf("error missing remediation pointer: %v", err)
	}
	var ctrl userspaceCtrlValue
	lookupErr := ctrlMap.Lookup(uint32(0), &ctrl)
	if lookupErr == nil && ctrl.Enabled != 0 {
		t.Fatalf("userspace_ctrl.Enabled = %d after binding publication failure, want not enabled", ctrl.Enabled)
	}
	if lookupErr != nil && !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
		t.Fatalf("lookup userspace_ctrl after binding publication failure: %v", lookupErr)
	}
}

func TestApplyHelperStatusDisablesLiveCtrlOnPublicationFailure(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	ctrlMap, _ := injectCtrlAndBindingMaps(t, m)
	m.neighborsPrewarmed = true
	m.xskLivenessProven = true
	m.ctrlWasEnabled = true
	m.publishedSnapshot = 1

	zero := uint32(0)
	if err := ctrlMap.Update(zero, userspaceCtrlValue{
		Enabled:            1,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		HeartbeatTimeoutMS: 30000,
	}, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed userspace_ctrl: %v", err)
	}

	overCapIfindex := int(dataplane.MaxInterfaces) + 7
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
			Ifindex:    overCapIfindex,
			Registered: true,
			Armed:      true,
			Bound:      true,
		}},
	}

	err := m.applyHelperStatusLocked(&status)
	if err == nil {
		t.Fatal("applyHelperStatusLocked returned nil for over-cap ifindex, want error")
	}
	var ctrl userspaceCtrlValue
	if lookupErr := ctrlMap.Lookup(zero, &ctrl); lookupErr != nil {
		t.Fatalf("lookup userspace_ctrl after publication failure: %v", lookupErr)
	}
	if ctrl.Enabled != 0 {
		t.Fatalf("userspace_ctrl.Enabled = %d after live publication failure, want 0", ctrl.Enabled)
	}
	if m.ctrlWasEnabled {
		t.Fatal("ctrlWasEnabled = true after fail-closed publication failure, want false")
	}
}

func TestSyncLocalAddressMapsAddsBeforeRemovingStale(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	localV4Map, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("new userspace_local_v4 map: %v", err)
	}
	t.Cleanup(func() { localV4Map.Close() })
	injectShimMap(t, m.bpfShim, "userspace_local_v4", localV4Map)
	injectShimMapSpec(t, m.bpfShim, "userspace_local_v6", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(userspaceLocalV6Key{})),
		ValueSize:  1,
		MaxEntries: 16,
	})

	oldLocal := binary.BigEndian.Uint32([]byte{192, 0, 2, 1})
	newLocal := binary.BigEndian.Uint32([]byte{198, 51, 100, 1})
	if err := localV4Map.Update(oldLocal, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatalf("seed userspace_local_v4: %v", err)
	}

	err = m.syncLocalAddressMapsLocked(&ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{{
			Name: "reth0.0",
			Addresses: []InterfaceAddressSnapshot{{
				Family:  "inet",
				Address: "198.51.100.1/24",
			}},
		}},
	})
	if err == nil {
		t.Fatal("syncLocalAddressMapsLocked succeeded despite full map, want add-before-remove failure")
	}

	var got uint8
	if err := localV4Map.Lookup(oldLocal, &got); err != nil {
		t.Fatalf("old local address was removed before replacement published: %v", err)
	}
	if err := localV4Map.Lookup(newLocal, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("new local address lookup err = %v, want ErrKeyNotExist after failed add", err)
	}
}

func TestSyncInterfaceNATAddressMapsAddsBeforeRemovingStale(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	natV4Map, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("new userspace_interface_nat_v4 map: %v", err)
	}
	t.Cleanup(func() { natV4Map.Close() })
	injectShimMap(t, m.bpfShim, "userspace_interface_nat_v4", natV4Map)
	injectShimMapSpec(t, m.bpfShim, "userspace_interface_nat_v6", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(userspaceLocalV6Key{})),
		ValueSize:  1,
		MaxEntries: 16,
	})

	oldNAT := binary.BigEndian.Uint32([]byte{203, 0, 113, 1})
	newNAT := binary.BigEndian.Uint32([]byte{198, 51, 100, 1})
	if err := natV4Map.Update(oldNAT, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatalf("seed userspace_interface_nat_v4: %v", err)
	}

	err = m.syncInterfaceNATAddressMapsLocked(&ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{{
			Name: "reth1.0",
			Zone: "untrust",
			Addresses: []InterfaceAddressSnapshot{{
				Family:  "inet",
				Address: "198.51.100.1/24",
			}},
		}},
		SourceNAT: []SourceNATRuleSnapshot{{
			Name:          "snat-out",
			ToZone:        "untrust",
			InterfaceMode: true,
		}},
	})
	if err == nil {
		t.Fatal("syncInterfaceNATAddressMapsLocked succeeded despite full map, want add-before-remove failure")
	}

	var got uint8
	if err := natV4Map.Lookup(oldNAT, &got); err != nil {
		t.Fatalf("old NAT address was removed before replacement published: %v", err)
	}
	if err := natV4Map.Lookup(newNAT, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("new NAT address lookup err = %v, want ErrKeyNotExist after failed add", err)
	}
}

func TestSamePlanClassifierMapRefreshFailsClosedOnNATSyncFailure(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	ctrlMap, _ := injectCtrlAndBindingMaps(t, m)
	injectShimMapSpec(t, m.bpfShim, "userspace_ingress_ifaces", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 16,
	})
	injectShimMapSpec(t, m.bpfShim, "userspace_local_v4", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 1024,
	})
	injectShimMapSpec(t, m.bpfShim, "userspace_local_v6", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(userspaceLocalV6Key{})),
		ValueSize:  1,
		MaxEntries: 1024,
	})
	natV4Map, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("new userspace_interface_nat_v4 map: %v", err)
	}
	t.Cleanup(func() { natV4Map.Close() })
	injectShimMap(t, m.bpfShim, "userspace_interface_nat_v4", natV4Map)
	injectShimMapSpec(t, m.bpfShim, "userspace_interface_nat_v6", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(userspaceLocalV6Key{})),
		ValueSize:  1,
		MaxEntries: 16,
	})

	zero := uint32(0)
	if err := ctrlMap.Update(zero, userspaceCtrlValue{
		Enabled:            1,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		HeartbeatTimeoutMS: 30000,
	}, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed userspace_ctrl: %v", err)
	}
	m.ctrlWasEnabled = true

	oldNAT := binary.BigEndian.Uint32([]byte{203, 0, 113, 1})
	newNAT := binary.BigEndian.Uint32([]byte{198, 51, 100, 1})
	if err := natV4Map.Update(oldNAT, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatalf("seed userspace_interface_nat_v4: %v", err)
	}

	err = m.syncUserspaceClassifierMapsFailClosedLocked(&ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{{
			Name:    "reth1.0",
			Zone:    "untrust",
			Ifindex: 5,
			Addresses: []InterfaceAddressSnapshot{{
				Family:  "inet",
				Address: "198.51.100.1/24",
			}},
		}},
		SourceNAT: []SourceNATRuleSnapshot{{
			Name:          "snat-out",
			ToZone:        "untrust",
			InterfaceMode: true,
		}},
	})
	if err == nil {
		t.Fatal("classifier-map refresh succeeded despite full NAT map, want error")
	}
	if !strings.Contains(err.Error(), "userspace_interface_nat_v4") {
		t.Fatalf("refresh failed before interface-NAT sync: %v", err)
	}

	var ctrl userspaceCtrlValue
	if lookupErr := ctrlMap.Lookup(zero, &ctrl); lookupErr != nil {
		t.Fatalf("lookup userspace_ctrl after refresh failure: %v", lookupErr)
	}
	if ctrl.Enabled != 0 {
		t.Fatalf("userspace_ctrl.Enabled = %d after refresh failure, want 0", ctrl.Enabled)
	}
	if m.ctrlWasEnabled {
		t.Fatal("ctrlWasEnabled = true after refresh failure, want false")
	}

	var got uint8
	if lookupErr := natV4Map.Lookup(oldNAT, &got); lookupErr != nil {
		t.Fatalf("old NAT address missing after failed refresh: %v", lookupErr)
	}
	if lookupErr := natV4Map.Lookup(newNAT, &got); !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
		t.Fatalf("new NAT address lookup err = %v, want ErrKeyNotExist", lookupErr)
	}
}

func TestBlindFailClosedUserspaceCtrlAfterLookupFailure(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	for _, tc := range []struct {
		name       string
		mode       DataplaneMode
		wantStrict bool
	}{
		{name: "strict", mode: ModeUserspaceStrict, wantStrict: true},
		{name: "compat", mode: ModeUserspaceCompat, wantStrict: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			m.configuredMode = tc.mode
			ctrlMap, _ := injectCtrlAndBindingMaps(t, m)
			injectClassifierRefreshMapsWithFullNATV4(t, m)
			m.ctrlWasEnabled = true

			zero := uint32(0)
			if err := ctrlMap.Update(zero, userspaceCtrlValue{
				Enabled:            1,
				MetadataVersion:    userspaceMetadataVersion,
				Workers:            8,
				QueueCount:         8,
				HeartbeatTimeoutMS: 30000,
			}, ebpf.UpdateAny); err != nil {
				t.Fatalf("seed userspace_ctrl: %v", err)
			}

			lookupErr := errors.New("transient ctrl lookup failed")
			m.lookupUserspaceCtrlForFailClosedHook = func(_ ctrlMapUpdater, _ uint32, _ *userspaceCtrlValue) error {
				return lookupErr
			}

			err := m.syncUserspaceClassifierMapsFailClosedLocked(classifierRefreshFailureSnapshot())
			if err == nil {
				t.Fatal("classifier-map refresh succeeded despite full NAT map, want error")
			}
			if !strings.Contains(err.Error(), "userspace_interface_nat_v4") {
				t.Fatalf("refresh failed before interface-NAT sync: %v", err)
			}
			if !errors.Is(err, lookupErr) {
				t.Fatalf("error does not wrap lookup failure: %v", err)
			}

			var ctrl userspaceCtrlValue
			if err := ctrlMap.Lookup(zero, &ctrl); err != nil {
				t.Fatalf("lookup userspace_ctrl after blind fail-closed: %v", err)
			}
			if ctrl.Enabled != 0 {
				t.Fatalf("userspace_ctrl.Enabled = %d after blind fail-closed, want 0", ctrl.Enabled)
			}
			if ctrl.MetadataVersion != userspaceMetadataVersion {
				t.Fatalf("MetadataVersion = %d, want %d", ctrl.MetadataVersion, userspaceMetadataVersion)
			}
			if ctrl.Workers != 3 || ctrl.QueueCount != 3 {
				t.Fatalf("Workers/QueueCount = %d/%d, want 3/3", ctrl.Workers, ctrl.QueueCount)
			}
			if ctrl.ConfigGeneration != 99 || ctrl.FIBGeneration != 7 {
				t.Fatalf("generations = %d/%d, want 99/7", ctrl.ConfigGeneration, ctrl.FIBGeneration)
			}
			gotStrict := ctrl.Flags&userspaceCtrlFlagStrict != 0
			if gotStrict != tc.wantStrict {
				t.Fatalf("strict flag present = %t, want %t (flags=%#x)", gotStrict, tc.wantStrict, ctrl.Flags)
			}
			if m.ctrlWasEnabled {
				t.Fatal("ctrlWasEnabled = true after blind fail-closed, want false")
			}
		})
	}
}

func TestClassifierMapRefreshMissingCtrlRowReturnsClassifierError(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	ctrlMap, _ := injectCtrlAndBindingMaps(t, m)
	injectClassifierRefreshMapsWithFullNATV4(t, m)

	err := m.syncUserspaceClassifierMapsFailClosedLocked(classifierRefreshFailureSnapshot())
	if err == nil {
		t.Fatal("classifier-map refresh succeeded despite full NAT map, want error")
	}
	if !strings.Contains(err.Error(), "userspace_interface_nat_v4") {
		t.Fatalf("refresh failed before interface-NAT sync: %v", err)
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("missing ctrl row leaked ErrKeyNotExist into returned error: %v", err)
	}
	var ctrl userspaceCtrlValue
	if lookupErr := ctrlMap.Lookup(uint32(0), &ctrl); !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
		t.Fatalf("userspace_ctrl lookup err = %v, want ErrKeyNotExist", lookupErr)
	}
}

func injectClassifierRefreshMapsWithFullNATV4(t *testing.T, m *Manager) {
	t.Helper()
	injectShimMapSpec(t, m.bpfShim, "userspace_ingress_ifaces", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 16,
	})
	injectShimMapSpec(t, m.bpfShim, "userspace_local_v4", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 1024,
	})
	injectShimMapSpec(t, m.bpfShim, "userspace_local_v6", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(userspaceLocalV6Key{})),
		ValueSize:  1,
		MaxEntries: 1024,
	})
	natV4Map, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("new userspace_interface_nat_v4 map: %v", err)
	}
	t.Cleanup(func() { natV4Map.Close() })
	injectShimMap(t, m.bpfShim, "userspace_interface_nat_v4", natV4Map)
	injectShimMapSpec(t, m.bpfShim, "userspace_interface_nat_v6", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(userspaceLocalV6Key{})),
		ValueSize:  1,
		MaxEntries: 16,
	})

	oldNAT := binary.BigEndian.Uint32([]byte{203, 0, 113, 1})
	if err := natV4Map.Update(oldNAT, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatalf("seed userspace_interface_nat_v4: %v", err)
	}
}

func classifierRefreshFailureSnapshot() *ConfigSnapshot {
	return &ConfigSnapshot{
		Generation:    99,
		FIBGeneration: 7,
		Userspace: config.UserspaceConfig{
			Workers: 3,
		},
		Interfaces: []InterfaceSnapshot{{
			Name:    "reth1.0",
			Zone:    "untrust",
			Ifindex: 5,
			Addresses: []InterfaceAddressSnapshot{{
				Family:  "inet",
				Address: "198.51.100.1/24",
			}},
		}},
		SourceNAT: []SourceNATRuleSnapshot{{
			Name:          "snat-out",
			ToZone:        "untrust",
			InterfaceMode: true,
		}},
	}
}

func TestSyncInterfaceNATAddressMapsReplacesStaleWhenCapacityAllows(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	natV4Map, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 2,
	})
	if err != nil {
		t.Fatalf("new userspace_interface_nat_v4 map: %v", err)
	}
	t.Cleanup(func() { natV4Map.Close() })
	injectShimMap(t, m.bpfShim, "userspace_interface_nat_v4", natV4Map)
	injectShimMapSpec(t, m.bpfShim, "userspace_interface_nat_v6", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(userspaceLocalV6Key{})),
		ValueSize:  1,
		MaxEntries: 16,
	})

	oldNAT := binary.BigEndian.Uint32([]byte{203, 0, 113, 1})
	newNAT := binary.BigEndian.Uint32([]byte{198, 51, 100, 1})
	if err := natV4Map.Update(oldNAT, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatalf("seed userspace_interface_nat_v4: %v", err)
	}

	if err := m.syncInterfaceNATAddressMapsLocked(&ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{{
			Name: "reth1.0",
			Zone: "untrust",
			Addresses: []InterfaceAddressSnapshot{{
				Family:  "inet",
				Address: "198.51.100.1/24",
			}},
		}},
		SourceNAT: []SourceNATRuleSnapshot{{
			Name:          "snat-out",
			ToZone:        "untrust",
			InterfaceMode: true,
		}},
	}); err != nil {
		t.Fatalf("syncInterfaceNATAddressMapsLocked: %v", err)
	}

	var got uint8
	if err := natV4Map.Lookup(newNAT, &got); err != nil {
		t.Fatalf("new NAT address missing after successful replacement: %v", err)
	}
	if err := natV4Map.Lookup(oldNAT, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("old NAT address lookup err = %v, want ErrKeyNotExist after stale cleanup", err)
	}
}

// TestApplyHelperStatusAcceptsIfindexWithinCap exercises the happy path
// to confirm the new cap guard does not spuriously reject valid
// ifindexes. Any small ifindex (< MaxInterfaces) must still succeed.
func TestApplyHelperStatusAcceptsIfindexWithinCap(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	m.bpfShim.SelectUserspaceXDPShimEntryProgram()
	injectCtrlAndBindingMaps(t, m)
	injectUserspaceSessionMap(t, m)
	// #9337: applyHelperStatusLocked re-syncs the ingress/local/interface-NAT
	// classifier maps (#6994), which this fixture does not load — under CAP_BPF
	// it failed with "userspace_ingress_ifaces map not loaded" before reaching
	// anything this cell asserts. Unprivileged the whole test skips, so the gap
	// was invisible. The seam is the established remedy (#7468).
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
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
	if err := m.applyHelperStatusLocked(&status); err != nil {
		t.Fatalf("applyHelperStatusLocked with in-cap ifindex returned %v, want nil", err)
	}
}

// TestVerifyBindingsWatchdogSkipsOverCapIfindex exercises the
// watchdog's log-and-skip branch when a reported binding has an
// ifindex that would overflow BindingArrayMaxEntries. The watchdog
// must NOT unwind (it's repair-only) — it logs and keeps going.
func TestVerifyBindingsWatchdogSkipsOverCapIfindex(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	m.bpfShim.SelectUserspaceXDPShimEntryProgram()
	injectCtrlAndBindingMaps(t, m)
	m.ctrlWasEnabled = true
	// verifyBindingsMapLocked early-returns on m.proc == nil or
	// m.proc.Process == nil — give it a non-nil *exec.Cmd with a
	// harmless pointer to our own PID so the guard passes.
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}

	overCapIfindex := int(dataplane.MaxInterfaces) + 42
	m.lastStatus.Bindings = []BindingStatus{
		{Slot: 1, QueueID: 0, Ifindex: overCapIfindex, Registered: true, Armed: true, Bound: true},
		{Slot: 2, QueueID: 1, Ifindex: 7, Registered: true, Armed: true, Bound: true},
	}

	// Must not panic, must not return repaired=true for the over-cap
	// entry. The in-cap entry may or may not be "repaired" depending
	// on whether the map has any entries yet — what matters here is
	// the watchdog did not die on the over-cap ifindex.
	_ = m.verifyBindingsMapLocked()
}

// TestBindingArrayMaxEntriesMirrorsRustSide pins the Go-visible
// constant to its derivation. If MaxInterfaces drifts vs
// userspace-xdp/src/lib.rs, or BindingQueuesPerIface vs
// userspace-xdp/src/binding_index.rs, the
// load-time assertion in loader_ebpf.go catches it — but this test
// fails at compile/unit-test time before you get that far.
func TestBindingArrayMaxEntriesMirrorsRustSide(t *testing.T) {
	if dataplane.BindingQueuesPerIface != bindingQueuesPerIface {
		t.Fatalf("bindingQueuesPerIface in maps_sync.go (%d) differs from dataplane.BindingQueuesPerIface (%d); one side of the mirror drifted",
			bindingQueuesPerIface, dataplane.BindingQueuesPerIface)
	}
	if dataplane.BindingArrayMaxEntries != dataplane.MaxInterfaces*dataplane.BindingQueuesPerIface {
		t.Fatalf("BindingArrayMaxEntries (%d) != MaxInterfaces * BindingQueuesPerIface (%d * %d)",
			dataplane.BindingArrayMaxEntries, dataplane.MaxInterfaces, dataplane.BindingQueuesPerIface)
	}
}
