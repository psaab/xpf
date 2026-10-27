package routing

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
)

// #17020 (R4-Q42-01): the "release an owned netdev only on a genuine
// not-found" skeleton was hand-written in four live copies in this
// package (bond.deleteLocked, xfrm.deleteLocked, the tunnel Apply
// removed-tunnel loop, and the reconcileVRFs tracked-not-desired
// loop). The transient-lookup defect shipped once per copy (#4901,
// #5495, #7529, #8073) because there was no single branch to fix.
//
// releaseOwnedLink is that skeleton. This table pins every error
// class against one fake:
//
//   - not-found releases (released=true, err=nil, no LinkDel)
//   - transient lookup retains (released=false, wrapped error, no LinkDel)
//   - success retains-until-release (a present, ours link is deleted
//     and reports released=true)
//   - LinkDel failure retains (released=false, wrapped error)
//   - foreign occupant is refused (released=false, errForeignOccupant,
//     no LinkDel)
//
// MUTATION: flipping the helper's not-found branch to "any lookup
// error = absent" turns the not-found/transient distinction here AND
// the pre-existing per-manager cells (#5495
// xfrm_linkbyname_transient_5461_5495_test.go, #7529
// link_lookup_transient_7529_test.go, #4901
// teardown_linkdel_4901_test.go) RED together, because every manager
// now routes through this one branch.
func TestReleaseOwnedLink17020(t *testing.T) {
	transient := errors.New("injected: LinkByName EBUSY (transient)")
	delErr := errors.New("injected: LinkDel EBUSY")

	isBond := func(l netlink.Link) bool {
		_, ok := l.(*netlink.Bond)
		return ok
	}

	tests := []struct {
		name          string
		seed          func(ops *fakeLinkOps)
		isOurs        func(netlink.Link) bool
		wantReleased  bool
		wantErrIs     error // errors.Is target; nil = success expected
		wantErrNonNil bool  // error expected but with no sentinel target
		wantDeleted   bool  // the seeded link was LinkDel'd
	}{
		{
			name:         "not-found releases",
			seed:         func(ops *fakeLinkOps) {}, // un-seeded -> errLinkNotFound
			isOurs:       alwaysOurs,
			wantReleased: true,
		},
		{
			name: "transient lookup retains",
			seed: func(ops *fakeLinkOps) {
				seedDummy(ops, "dev0")
				ops.byNameHardErr["dev0"] = transient
			},
			isOurs:       alwaysOurs,
			wantReleased: false,
			wantErrIs:    transient,
		},
		{
			name: "ours present deletes and releases",
			seed: func(ops *fakeLinkOps) {
				ops.links["dev0"] = &netlink.Bond{LinkAttrs: netlink.LinkAttrs{Name: "dev0"}}
			},
			isOurs:       isBond,
			wantReleased: true,
			wantDeleted:  true,
		},
		{
			name: "alwaysOurs deletes whatever wears the name",
			seed: func(ops *fakeLinkOps) {
				seedDummy(ops, "dev0") // *netlink.Dummy, not a Bond
			},
			isOurs:       alwaysOurs,
			wantReleased: true,
			wantDeleted:  true,
		},
		{
			name: "LinkDel failure retains",
			seed: func(ops *fakeLinkOps) {
				seedDummy(ops, "dev0")
				ops.delFail["dev0"] = delErr
			},
			isOurs:        alwaysOurs,
			wantReleased:  false,
			wantErrIs:     delErr,
			wantErrNonNil: true, // also wraps errLinkDelFailed
		},
		{
			name: "foreign occupant refused, not deleted",
			seed: func(ops *fakeLinkOps) {
				seedDummy(ops, "dev0") // *netlink.Dummy, not a Bond
			},
			isOurs:        isBond,
			wantReleased:  false,
			wantErrIs:     errForeignOccupant,
			wantErrNonNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ops := newFakeLinkOps()
			tc.seed(ops)
			_, seeded := ops.links["dev0"]

			released, err := releaseOwnedLink(ops, "testdev", "dev0", tc.isOurs)

			if released != tc.wantReleased {
				t.Errorf("released = %v, want %v (err=%v)", released, tc.wantReleased, err)
			}
			switch {
			case tc.wantErrIs != nil:
				if !errors.Is(err, tc.wantErrIs) {
					t.Errorf("err = %v, want wrap of %v", err, tc.wantErrIs)
				}
			case tc.wantErrNonNil:
				if err == nil {
					t.Error("err = nil, want non-nil")
				}
			default:
				if err != nil {
					t.Errorf("err = %v, want nil", err)
				}
			}
			_, stillThere := ops.links["dev0"]
			if tc.wantDeleted {
				if !seeded {
					t.Fatal("test bug: wantDeleted but nothing seeded")
				}
				if stillThere {
					t.Error("link still present after release; want LinkDel'd")
				}
				if !sliceHas(ops.delNames, "dev0") {
					t.Errorf("delNames = %v, want dev0 recorded", ops.delNames)
				}
			} else if seeded && !stillThere {
				t.Error("link was deleted but this outcome must not delete it")
			}
		})
	}
}

// TestReleaseOwnedLinkNilIsOurs17020 pins the defensive contract: a
// nil isOurs means "no identity opinion" (same as alwaysOurs), never
// a panic and never a refusal.
func TestReleaseOwnedLinkNilIsOurs17020(t *testing.T) {
	ops := newFakeLinkOps()
	seedDummy(ops, "dev0")
	released, err := releaseOwnedLink(ops, "testdev", "dev0", nil)
	if err != nil || !released {
		t.Fatalf("nil isOurs: released=%v err=%v, want true/nil", released, err)
	}
	if _, ok := ops.links["dev0"]; ok {
		t.Error("nil isOurs: link must be deleted")
	}
}
