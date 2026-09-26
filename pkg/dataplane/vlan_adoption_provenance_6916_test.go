package dataplane

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
)

// #6916 / #6917 — a device is adopted as xpf's VLAN child only if it can be
// PROVEN to be one.
//
// The trap this file is written against: every assertion an existence check can
// make is answered identically by a device xpf created and a foreign device it
// merely found. "There is a link at ge-0-0-2.50" is true in both worlds; so is
// "it has an ifindex", "it is up", and "the compile succeeded". The defect is
// entirely about PROVENANCE, so every cell below asserts which of the two
// happened — refused with a reason, or adopted — and never merely that a
// device is there.
//
// Fixture shapes, all real vishvananda/netlink types rather than fakes, because
// the production code calls Link.Type() and the concrete type IS the thing
// under test:
//
//	*netlink.Veth  at "<phys>.<vid>"   -> the reproduction in #6916: a
//	                                     cross-namespace veth whose
//	                                     ParentIndex is its PEER's ifindex
//	*netlink.Vlan  NetNsID != -1       -> a GENUINE 802.1Q child whose
//	                                     real_dev moved to another namespace
//	*netlink.Vlan  VlanId mismatch     -> right name, wrong tag
//	*netlink.Vlan  ParentIndex mismatch-> right kind and tag, wrong parent
//	*netlink.Vlan  all matching        -> the one that must be ADOPTED

const (
	provPhys6916   = "ge-0-0-2"
	provVID6916    = 50
	provParentIdx  = 4242
	provSubIdx6916 = 4277
)

func provSubName6916() string { return fmt.Sprintf("%s.%d", provPhys6916, provVID6916) }

// provDP6916 is the dataplane for the mapZoneInterface cells. It embeds
// censusDP6903 rather than recordingFilterDP because the SUCCESS path reaches
// SetVlanIfaceInfo, and recordingFilterDP embeds a nil DataPlane interface — so
// the adopted-child cell would not fail, it would PANIC and take the whole
// package binary down with it, turning every other test in the package into a
// result nobody measured.
type provDP6916 struct{ censusDP6903 }

// goodVLAN6916 is the device xpf itself would have created: kind vlan, local
// real_dev, the configured VID, delegating to the configured parent.
func goodVLAN6916() *netlink.Vlan {
	return &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        provSubName6916(),
			Index:       provSubIdx6916,
			ParentIndex: provParentIdx,
			NetNsID:     netnsIDLocal,
			OperState:   netlink.OperUp,
		},
		VlanId: provVID6916,
	}
}

func TestVLANAdoptionRefusesWhatItCannotProve_6916(t *testing.T) {
	mutate := func(f func(*netlink.Vlan)) *netlink.Vlan {
		v := goodVLAN6916()
		f(v)
		return v
	}

	cases := []struct {
		name string
		link netlink.Link
		// wantRefused is the whole point: an existence check cannot tell these
		// apart, so each row states which side of the adoption decision it is.
		wantRefused bool
		wantReason  string
	}{{
		name:        "wrong kind: the #6916 cross-namespace veth squatting the name",
		link:        &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: provSubName6916(), Index: 6, ParentIndex: provParentIdx, NetNsID: netnsIDLocal}},
		wantRefused: true,
		wantReason:  "not an 802.1Q vlan",
	}, {
		name:        "genuine vlan whose real_dev is in another namespace",
		link:        mutate(func(v *netlink.Vlan) { v.NetNsID = 0 }),
		wantRefused: true,
		wantReason:  "ANOTHER namespace",
	}, {
		name:        "vlan carrying a different VID than configured",
		link:        mutate(func(v *netlink.Vlan) { v.VlanId = provVID6916 + 1 }),
		wantRefused: true,
		wantReason:  "not the configured VID",
	}, {
		name:        "vlan delegating to a different parent than configured",
		link:        mutate(func(v *netlink.Vlan) { v.ParentIndex = provParentIdx + 1 }),
		wantRefused: true,
		wantReason:  "not the configured parent",
	}, {
		name:        "the child xpf would itself have created",
		link:        goodVLAN6916(),
		wantRefused: false,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			why := vlanAdoptionRefusal(tc.link, provParentIdx, provVID6916)
			if tc.wantRefused {
				if why == "" {
					t.Fatalf("ADOPTED a device it cannot prove is its VLAN child: %#v.\n"+
						"That ifindex becomes a delegated VLAN child, and the attach loop "+
						"skips delegated children because the parent handles their traffic "+
						"— which for a device that is not that parent's child means NOTHING "+
						"handles it. It forwards with no shim (#6916).", tc.link)
				}
				if !strings.Contains(why, tc.wantReason) {
					t.Errorf("refused for the wrong reason: got %q, want it to name %q.\n"+
						"The reason reaches the operator in the UnarmedSurface record; a "+
						"refusal that does not say WHICH check refused leaves them nothing "+
						"to act on.", why, tc.wantReason)
				}
				return
			}
			if why != "" {
				t.Fatalf("REFUSED the device xpf would itself have created: %q.\n"+
					"Without this row a predicate that refused unconditionally would "+
					"satisfy every other row here and break every VLAN config on the box.", why)
			}
		})
	}
}

// TestEnsureVLANSubInterfaceBindsTheAdoptionGate_6916 binds the WIRING, not the
// predicate. TestVLANAdoptionRefusesWhatItCannotProve_6916 above proves
// vlanAdoptionRefusal answers correctly; deleting the call to it from
// ensureVLANSubInterface leaves that test entirely green, because the function
// it tests still works. This is the cell that reds.
func TestEnsureVLANSubInterfaceBindsTheAdoptionGate_6916(t *testing.T) {
	parent := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: provPhys6916, Index: provParentIdx}}

	withLinks := func(t *testing.T, sub netlink.Link) {
		t.Helper()
		orig := vlanLinkByNameSeam
		t.Cleanup(func() { vlanLinkByNameSeam = orig })
		vlanLinkByNameSeam = func(name string) (netlink.Link, error) {
			switch name {
			case provPhys6916:
				return parent, nil
			case provSubName6916():
				return sub, nil
			}
			return nil, fmt.Errorf("no such link %q", name)
		}
	}

	t.Run("a foreign device at the name is refused, not adopted", func(t *testing.T) {
		withLinks(t, &netlink.Veth{LinkAttrs: netlink.LinkAttrs{
			Name: provSubName6916(), Index: 6, ParentIndex: provParentIdx, NetNsID: netnsIDLocal,
		}})

		idx, created, err := ensureVLANSubInterface(provPhys6916, provVID6916)
		if err == nil {
			t.Fatalf("adopted the squatter: returned ifindex %d, created=%v, no error (#6916)",
				idx, created)
		}
		if !errors.Is(err, errVLANAdoptRefused) {
			t.Errorf("refusal must carry errVLANAdoptRefused so the caller can tell it "+
				"apart from a create failure and report the right thing to the operator; "+
				"got %v", err)
		}
		// The ifindex is the payload. Returning it alongside an error would
		// still let a caller that ignores the error put the squatter into the
		// delegated-child set.
		if idx != 0 {
			t.Errorf("returned ifindex %d with a refusal — a refused adoption must hand "+
				"back NOTHING usable", idx)
		}
		if created {
			t.Error("reported created=true for a device it did not create (#4960 host-mutation signal)")
		}
	})

	t.Run("the child xpf would have created is still adopted", func(t *testing.T) {
		withLinks(t, goodVLAN6916())

		idx, created, err := ensureVLANSubInterface(provPhys6916, provVID6916)
		if err != nil {
			t.Fatalf("refused a legitimate existing VLAN child: %v.\n"+
				"Without this row the gate could refuse everything and every cell above "+
				"would still pass.", err)
		}
		if idx != provSubIdx6916 {
			t.Errorf("adopted ifindex %d, want %d", idx, provSubIdx6916)
		}
		if created {
			t.Error("created=true for a link that was already present — that flag is the " +
				"#4960 signal that the host gained an object the operator must remove")
		}
	})
}

// TestRefusedVLANNeverEntersTheDelegatedChildSet_6916 is the consequence half.
// The refusal above is only worth anything if the ifindex it withholds never
// reaches genericXDPIfindexes — that set is what makes the attach loop skip an
// interface, and being skipped is the whole harm.
func TestRefusedVLANNeverEntersTheDelegatedChildSet_6916(t *testing.T) {
	const physName = provPhys6916

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
				Units: map[int]*config.InterfaceUnit{provVID6916: {Number: provVID6916, VlanID: provVID6916}},
			},
		}
		return cfg
	}
	newResult := func() *CompileResult {
		return &CompileResult{
			ifCache:       map[string]*net.Interface{physName: {Index: provParentIdx, Name: physName}},
			hostMutations: map[string]bool{},
			// Pre-seeded so both #5268 and #10915 tag-strip checks are
			// satisfied: this fixture is about adoption provenance, and a
			// missing ethtool on the test host would otherwise abort it
			// before reaching the delegated-child append.
			rxTagStripOffCache: map[string]bool{physName: true},
			ethtoolApplied:     map[string]bool{},
			// High, otherwise-unused ifindexes so the netlink fallbacks in
			// cachedLinkByIndex MISS on the test host instead of resolving a
			// real local interface into this fixture.
			linkCache:           map[string]netlink.Link{},
			linkIdxMap:          map[int]netlink.Link{},
			genericXDPIfindexes: map[int]bool{},
		}
	}

	orig := ensureVLANSubInterfaceFn
	t.Cleanup(func() { ensureVLANSubInterfaceFn = orig })

	t.Run("refused: not delegated, and recorded as unarmed", func(t *testing.T) {
		ensureVLANSubInterfaceFn = func(string, int) (int, bool, error) {
			return 0, false, fmt.Errorf("%w: %s: ifindex 6 is a %q link, not an 802.1Q vlan",
				errVLANAdoptRefused, provSubName6916(), "veth")
		}
		st, result := newState(), newResult()
		if err := st.mapZoneInterface(provDP6916{}, newCfg(), result,
			"trust", &config.ZoneConfig{Name: "trust"}, 1, provSubName6916(),
			map[string]uint32{}); err != nil {
			t.Fatalf("an adoption refusal must SOFT-skip the surface, not fail the apply: %v.\n"+
				"Refusing a whole commit because an unrelated device squats a name is a far "+
				"larger blast radius than #6893 part 2 took on for a failed create.", err)
		}
		if len(result.genericXDPIfindexes) != 0 {
			t.Fatalf("a refused device reached the delegated-VLAN-child set: %v.\n"+
				"The attach loop SKIPS that set on the theory the parent covers it, so this "+
				"is exactly the silent exclusion #6916 reported.", result.genericXDPIfindexes)
		}
		if len(result.unarmedSurfaces) != 1 {
			t.Fatalf("refused surfaces recorded: %d, want 1 — a surface the config asked "+
				"for and the compile declined to arm must be visible to the operator (#5275)",
				len(result.unarmedSurfaces))
		}
		// The record must not tell the operator a creation failed. Nothing was
		// created; a device is PRESENT and forwarding, which is the opposite
		// state and sends them looking for the wrong thing.
		if got := result.unarmedSurfaces[0].Reason; !strings.Contains(got, "not adopted") {
			t.Errorf("unarmed record reads %q; a refusal must not be reported as a create "+
				"failure — nothing failed to be created, a foreign device is present", got)
		}
	})

	t.Run("adopted: delegated, exactly as before", func(t *testing.T) {
		ensureVLANSubInterfaceFn = func(string, int) (int, bool, error) {
			return provSubIdx6916, false, nil
		}
		st, result := newState(), newResult()
		if err := st.mapZoneInterface(provDP6916{}, newCfg(), result,
			"trust", &config.ZoneConfig{Name: "trust"}, 1, provSubName6916(),
			map[string]uint32{}); err != nil {
			t.Fatalf("a legitimate VLAN child must still compile: %v", err)
		}
		if !result.genericXDPIfindexes[provSubIdx6916] {
			t.Fatalf("a legitimate VLAN child did NOT reach the delegated-child set: %v.\n"+
				"Without this row the change could simply stop delegating every VLAN child "+
				"and the refusal cell above would still pass.", result.genericXDPIfindexes)
		}
		if len(result.unarmedSurfaces) != 0 {
			t.Errorf("recorded %d unarmed surfaces for a healthy child, want 0",
				len(result.unarmedSurfaces))
		}
	})
}
