package dataplane

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6893 part 2 — a VLAN sub-interface that FAILS TO BE CREATED now fails the
// apply, instead of being soft-skipped into a clean commit whose filter binding
// silently went missing.
//
// PAIRED, because "the guard reds when deleted" shows only that it is
// load-bearing, not that it was needed. The same input, one axis:
//
//	creation FAILS    -> mapZoneInterface returns an error (the apply fails)
//	creation SUCCEEDS -> mapZoneInterface returns nil      (nothing refused)
//
// Without the second row a guard that refused unconditionally would satisfy the
// first, and it would break every VLAN config on the box.
//
// SCOPE. The guard keys on errVLANCreateFailed, which marks netlink.LinkAdd
// refusing — and nothing else. The absent-parent case keeps its soft skip
// because #6893 itself hedges on it as arguably legitimate; the
// created-but-unusable cases keep theirs because the link EXISTS, so
// compileFirewallFilters resolves it and the filter IS assigned — the harm this
// issue is about does not arise there. The third subtest pins that scope: a
// non-create failure must still be soft-skipped, or this change has quietly
// become "refuse every VLAN problem".
func TestVLANCreateFailureFailsTheApply_6893(t *testing.T) {
	const physName = "ge-0-0-2"

	newState := func() *zoneMapState {
		return &zoneMapState{
			writtenIfaceZone: map[IfaceZoneKey]bool{},
			writtenVlanIface: map[uint32]bool{},
			attached:         map[int]bool{},
			attachedXDP:      map[int]bool{},
			tunnelIfindexes:  map[int]bool{},
		}
	}
	newCfg := func() *config.Config {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			physName: {
				Name:  physName,
				Units: map[int]*config.InterfaceUnit{50: {Number: 50, VlanID: 50}},
			},
		}
		return cfg
	}
	newResult := func() *CompileResult {
		return &CompileResult{
			ifCache: map[string]*net.Interface{physName: {Index: 42, Name: physName}},
			// markHostMutated writes here on the created=true path (#4960);
			// the VLAN child is queued for generic XDP on the success path.
			hostMutations:       map[string]bool{},
			genericXDPIfindexes: map[int]bool{},
		}
	}

	orig := ensureVLANSubInterfaceFn
	t.Cleanup(func() { ensureVLANSubInterfaceFn = orig })

	t.Run("creation failure fails the apply", func(t *testing.T) {
		ensureVLANSubInterfaceFn = func(string, int, bool) (int, bool, error) {
			return 0, false, errors.Join(errVLANCreateFailed, errors.New("operation not permitted"))
		}
		st := newState()
		err := st.mapZoneInterface(&recordingFilterDP{}, newCfg(), newResult(),
			"trust", &config.ZoneConfig{Name: "trust"}, 1, physName+".50", map[string]uint32{})
		if err == nil {
			t.Fatal("a VLAN sub-interface that could not be CREATED must fail the apply — " +
				"the device does not exist, compileFirewallFilters will miss it, and the " +
				"filter bound to it is silently not assigned (#6893)")
		}
		if !strings.Contains(err.Error(), "50") {
			t.Errorf("error %q does not name the surface — an operator needs to know WHICH "+
				"interface refused", err)
		}
	})

	t.Run("the guard's predicate selects ONLY the create failure", func(t *testing.T) {
		// The success PATH is not unit-drivable: past the VLAN branch
		// mapZoneInterface does physical-interface setup that needs netlink and
		// a real DataPlane, and chasing that with stubs would test the stubs.
		// So the "not refused" half is proven at the discriminator instead —
		// which is the thing that could widen — plus the soft-skip row below,
		// which drives the real function.
		for _, tc := range []struct {
			name string
			err  error
			want bool
		}{
			{"success", nil, false},
			{"absent parent", errors.New("parent interface ge-0-0-2: no such device"), false},
			{"created but not findable", errors.New("find created VLAN sub-interface ge-0-0-2.50: x"), false},
			{"created but not up", errors.New("set VLAN sub-interface ge-0-0-2.50 up: x"), false},
			{"LinkAdd refused", errors.Join(errVLANCreateFailed, errors.New("operation not permitted")), true},
		} {
			if got := tc.err != nil && errors.Is(tc.err, errVLANCreateFailed); got != tc.want {
				t.Errorf("%s: guard fires = %v, want %v — the scope of this change is "+
					"netlink.LinkAdd refusing and nothing else", tc.name, got, tc.want)
			}
		}
	})

	t.Run("a NON-create failure keeps its soft skip", func(t *testing.T) {
		ensureVLANSubInterfaceFn = func(string, int, bool) (int, bool, error) {
			// The absent-parent shape: no errVLANCreateFailed marker.
			return 0, false, errors.New("parent interface ge-0-0-2: no such device")
		}
		st := newState()
		result := newResult()
		err := st.mapZoneInterface(&recordingFilterDP{}, newCfg(), result,
			"trust", &config.ZoneConfig{Name: "trust"}, 1, physName+".50", map[string]uint32{})
		if err != nil {
			t.Fatalf("a non-create VLAN failure must keep the soft skip, got %v — this change "+
				"is scoped to netlink.LinkAdd refusing, and widening it silently would "+
				"refuse configs #6893 deliberately does not take a position on", err)
		}
		if len(result.unarmedSurfaces) == 0 {
			t.Error("the soft skip must still RECORD the unarmed surface — dropping the record " +
				"while keeping the skip would lose the trace #5275 added")
		}
	})
}
