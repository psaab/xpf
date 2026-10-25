package dataplane

import (
	"errors"
	"io/fs"
	"net"

	"github.com/vishvananda/netlink"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestVLANBringUpFailureIsNotRecordedAsACreateFailure_8122 pins the operator's
// RECORD, not the disposition.
//
// The soft-skip branch labels its UnarmedSurface "create failed" for anything
// that is not errVLANAdoptRefused. A link that WAS created — netlink.LinkAdd
// succeeded — and then failed to come up landed in that branch, so the record
// said a creation failed that had not. That is the #6916 harm one branch over:
// a false statement in the operator's own record, and the one that sends them
// looking for a creation error that never happened.
//
// The disposition is deliberately unchanged and the last subtest pins that: the
// #6893 gate refuses ONLY errVLANCreateFailed, and errVLANBringUpFailed must not
// widen it. A gate that started failing applies on a link that exists would be
// a regression this test would otherwise be the only thing to catch.
func TestVLANBringUpFailureIsNotRecordedAsACreateFailure_8122(t *testing.T) {
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
			ifCache:             map[string]*net.Interface{physName: {Index: 42, Name: physName}},
			hostMutations:       map[string]bool{},
			genericXDPIfindexes: map[int]bool{},
		}
	}

	orig := ensureVLANSubInterfaceFn
	t.Cleanup(func() { ensureVLANSubInterfaceFn = orig })

	rows := []struct {
		name     string
		err      error
		created  bool
		wantWhat string
		wantFail bool
	}{
		{
			name: "a set-up failure after LinkAdd says so",
			err: errors.Join(errVLANBringUpFailed,
				errors.New("set VLAN sub-interface ge-0-0-2.50 up: operation not permitted")),
			created:  true,
			wantWhat: "created but could not be brought up",
		},
		{
			// The other post-LinkAdd failure, which shares the sentinel.
			name: "a find-after-create failure says so too",
			err: errors.Join(errVLANBringUpFailed,
				errors.New("find created VLAN sub-interface ge-0-0-2.50: no such device")),
			created:  true,
			wantWhat: "created but could not be brought up",
		},
		// CONTROLS: the two labels that already existed must not move. Without
		// them a change that labelled everything "created but could not be
		// brought up" would satisfy every row above.
		{
			name:     "an adoption refusal still says not adopted",
			err:      errors.Join(errVLANAdoptRefused, errors.New("ge-0-0-2.50: not an 802.1Q child")),
			wantWhat: "not adopted",
		},
		{
			name:     "an absent parent still says create failed",
			err:      errors.New("parent interface ge-0-0-2: no such device"),
			wantWhat: "create failed",
		},
		{
			// The #6893 gate. Its predicate must not have widened.
			name:     "an actual create failure still FAILS the apply",
			err:      errors.Join(errVLANCreateFailed, errors.New("operation not permitted")),
			wantFail: true,
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			ensureVLANSubInterfaceFn = func(string, int, bool) (int, bool, error) {
				return 0, row.created, row.err
			}
			result := newResult()
			err := newState().mapZoneInterface(&recordingFilterDP{}, newCfg(), result,
				"trust", &config.ZoneConfig{Name: "trust"}, 1, physName+".50",
				map[string]uint32{})

			if row.wantFail {
				if err == nil {
					t.Fatal("the #6893 create gate must still fail the apply — if this " +
						"passes, errVLANBringUpFailed has widened the gate to refuse " +
						"configs for a link that EXISTS")
				}
				return
			}
			if err != nil {
				t.Fatalf("must soft-skip, not fail the apply: %v", err)
			}
			surfaces := result.unarmedSurfaces
			if len(surfaces) != 1 {
				t.Fatalf("want exactly one unarmed-surface record, got %d: %+v",
					len(surfaces), surfaces)
			}
			if !strings.Contains(surfaces[0].Reason, row.wantWhat) {
				t.Fatalf("the operator's record says the wrong thing\n  want it to contain: %q\n  got: %q",
					row.wantWhat, surfaces[0].Reason)
			}
			// The sharp half: a bring-up failure must not be filed as a
			// creation failure. Asserting only the wanted substring would pass
			// on a record that said both.
			if row.wantWhat != "create failed" &&
				strings.Contains(surfaces[0].Reason, "create failed") {
				t.Fatalf("the record still claims a creation failed: %q", surfaces[0].Reason)
			}
		})
	}
}

// TestVLANAcceptRAIsAppliedOnBothPaths_8122 pins the create/adopt symmetry that
// was structural rather than intentional: the accept_ra write sat below
// netlink.LinkAdd, and the adopt branch returned before reaching it, so a VLAN
// child that PRE-EXISTED the daemon with accept_ra=1 kept it.
//
// Driven through the seam because the real write targets /proc, which a unit
// test cannot create. Without the seam this symmetry could only be asserted by
// reading the code — which is exactly what let the two paths diverge.
func TestVLANAcceptRAIsAppliedOnBothPaths_8122(t *testing.T) {
	const parentName = "ge-0-0-2"
	const subName = "ge-0-0-2.50"

	origWrite := acceptRAWriteSeam
	origByName := vlanLinkByNameSeam
	t.Cleanup(func() {
		acceptRAWriteSeam = origWrite
		vlanLinkByNameSeam = origByName
	})

	var wrote []string
	acceptRAWriteSeam = func(path string, data []byte, _ fs.FileMode) error {
		wrote = append(wrote, path+"="+string(data))
		return nil
	}

	// The ADOPT path: the child already exists, is a real 802.1Q child of the
	// parent with the right VID (or vlanAdoptionRefusal would refuse it), and is
	// already UP so no LinkSetUp nudge is attempted.
	parent := &netlink.Device{LinkAttrs: netlink.LinkAttrs{
		Name: parentName, Index: 42, NetNsID: netnsIDLocal,
	}}
	sub := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name: subName, Index: 43, ParentIndex: 42,
			OperState: netlink.OperUp, NetNsID: netnsIDLocal,
		},
		VlanId:       50,
		VlanProtocol: netlink.VLAN_PROTOCOL_8021Q,
	}
	vlanLinkByNameSeam = func(name string) (netlink.Link, error) {
		switch name {
		case parentName:
			return parent, nil
		case subName:
			return sub, nil
		}
		return nil, errors.New("no such device")
	}

	idx, created, err := ensureVLANSubInterface(parentName, 50, false)
	if err != nil {
		t.Fatalf("adopt must succeed: %v", err)
	}
	if created {
		t.Fatal("adopting an existing child must not report created=true (#4960)")
	}
	if idx != 43 {
		t.Fatalf("adopt returned ifindex %d, want 43", idx)
	}

	want := "/proc/sys/net/ipv6/conf/" + subName + "/accept_ra=0"
	if len(wrote) != 1 || wrote[0] != want {
		t.Fatalf("the ADOPT path must disable accept_ra like the create path does; "+
			"a child that pre-existed the daemon with accept_ra=1 otherwise keeps it "+
			"(#8122)\n  want: [%s]\n  got:  %v", want, wrote)
	}
}

// TestVLANBringUpFailureCarriesTheSentinel_8122 binds the WIRING, not the
// switch that reads it.
//
// This cell exists because its absence was demonstrated. The label test above
// drives ensureVLANSubInterfaceFn — the CALLER's seam — and synthesizes the
// wrapped error itself, so deleting both `errVLANBringUpFailed` wraps from
// compiler_iface.go left it green. A claim about what the production code
// returns has to be made against the production code.
func TestVLANBringUpFailureCarriesTheSentinel_8122(t *testing.T) {
	const parentName = "ge-0-0-2"
	const subName = "ge-0-0-2.50"

	origByName, origAdd, origUp, origWrite :=
		vlanLinkByNameSeam, vlanLinkAddSeam, vlanLinkSetUpSeam, acceptRAWriteSeam
	t.Cleanup(func() {
		vlanLinkByNameSeam, vlanLinkAddSeam, vlanLinkSetUpSeam, acceptRAWriteSeam =
			origByName, origAdd, origUp, origWrite
	})
	acceptRAWriteSeam = func(string, []byte, fs.FileMode) error { return nil }

	parent := &netlink.Device{LinkAttrs: netlink.LinkAttrs{
		Name: parentName, Index: 42, NetNsID: netnsIDLocal,
	}}
	created := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name: subName, Index: 43, ParentIndex: 42, NetNsID: netnsIDLocal,
		},
		VlanId:       50,
		VlanProtocol: netlink.VLAN_PROTOCOL_8021Q,
	}

	// The CREATE path: the child does not exist until LinkAdd runs.
	newLookup := func(added *bool) func(string) (netlink.Link, error) {
		return func(name string) (netlink.Link, error) {
			switch {
			case name == parentName:
				return parent, nil
			case name == subName && *added:
				return created, nil
			}
			return nil, errors.New("no such device")
		}
	}

	t.Run("a set-up failure after LinkAdd carries errVLANBringUpFailed", func(t *testing.T) {
		added := false
		vlanLinkByNameSeam = newLookup(&added)
		vlanLinkAddSeam = func(netlink.Link) error { added = true; return nil }
		vlanLinkSetUpSeam = func(netlink.Link) error {
			return errors.New("operation not permitted")
		}

		_, wasCreated, err := ensureVLANSubInterface(parentName, 50, false)
		if err == nil {
			t.Fatal("a failed LinkSetUp must be reported")
		}
		if !errors.Is(err, errVLANBringUpFailed) {
			t.Fatalf("the error must carry errVLANBringUpFailed, or the caller files "+
				"it as a CREATE failure for a link that was created (#6916/#8122); got %v", err)
		}
		if errors.Is(err, errVLANCreateFailed) {
			t.Fatalf("it must NOT carry errVLANCreateFailed — that sentinel fails the "+
				"apply, and LinkAdd succeeded; got %v", err)
		}
		// #4960: LinkAdd succeeded, so the host carries a new link and the
		// caller has to be able to say so even though this call failed.
		if !wasCreated {
			t.Error("created must be true: LinkAdd succeeded and the host was mutated")
		}
	})

	t.Run("a find-after-create failure carries it too", func(t *testing.T) {
		vlanLinkByNameSeam = func(name string) (netlink.Link, error) {
			if name == parentName {
				return parent, nil
			}
			return nil, errors.New("no such device")
		}
		vlanLinkAddSeam = func(netlink.Link) error { return nil }
		vlanLinkSetUpSeam = func(netlink.Link) error { return nil }

		_, _, err := ensureVLANSubInterface(parentName, 50, false)
		if !errors.Is(err, errVLANBringUpFailed) {
			t.Fatalf("want errVLANBringUpFailed, got %v", err)
		}
	})

	t.Run("CONTROL: LinkAdd itself refusing still carries errVLANCreateFailed", func(t *testing.T) {
		added := false
		vlanLinkByNameSeam = newLookup(&added)
		vlanLinkAddSeam = func(netlink.Link) error { return errors.New("operation not permitted") }
		vlanLinkSetUpSeam = func(netlink.Link) error { return nil }

		_, _, err := ensureVLANSubInterface(parentName, 50, false)
		if !errors.Is(err, errVLANCreateFailed) {
			t.Fatalf("the #6893 apply-failing sentinel must survive: got %v", err)
		}
		if errors.Is(err, errVLANBringUpFailed) {
			t.Fatalf("a real create failure must NOT be relabelled as a bring-up "+
				"failure — that would downgrade the one failure that fails the "+
				"apply; got %v", err)
		}
	})

	t.Run("CONTROL: a clean create carries neither and reports created", func(t *testing.T) {
		added := false
		vlanLinkByNameSeam = newLookup(&added)
		vlanLinkAddSeam = func(netlink.Link) error { added = true; return nil }
		vlanLinkSetUpSeam = func(netlink.Link) error { return nil }

		idx, wasCreated, err := ensureVLANSubInterface(parentName, 50, false)
		if err != nil {
			t.Fatalf("a clean create must succeed: %v", err)
		}
		if !wasCreated || idx != 43 {
			t.Fatalf("want created=true ifindex=43, got created=%v ifindex=%d", wasCreated, idx)
		}
	})
}
