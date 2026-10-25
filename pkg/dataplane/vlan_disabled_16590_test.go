package dataplane

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/vishvananda/netlink"
)

// #16590: ensureVLANSubInterface must never bring up a disabled unit's
// child — networkd renders it always-down, and this writer must not fight
// it (the old code brought an existing child UP with no disable test, so
// the primary installed/GARPed a disabled address when the link was up).

func TestEnsureVLANSubInterfaceDisabled16590(t *testing.T) {
	const parentName = "ge-0-0-2"
	const subName = "ge-0-0-2.50"

	origByName, origAdd, origUp, origDown, origWrite :=
		vlanLinkByNameSeam, vlanLinkAddSeam, vlanLinkSetUpSeam, vlanLinkSetDownSeam, acceptRAWriteSeam
	t.Cleanup(func() {
		vlanLinkByNameSeam, vlanLinkAddSeam, vlanLinkSetUpSeam, vlanLinkSetDownSeam, acceptRAWriteSeam =
			origByName, origAdd, origUp, origDown, origWrite
	})
	acceptRAWriteSeam = func(string, []byte, fs.FileMode) error { return nil }

	parent := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: parentName, Index: 42, NetNsID: netnsIDLocal}}

	mkSub := func(state netlink.LinkOperState) *netlink.Vlan {
		return &netlink.Vlan{
			LinkAttrs:    netlink.LinkAttrs{Name: subName, Index: 43, ParentIndex: 42, OperState: state, NetNsID: netnsIDLocal},
			VlanId:       50,
			VlanProtocol: netlink.VLAN_PROTOCOL_8021Q,
		}
	}

	var ups, downs int
	vlanLinkSetUpSeam = func(netlink.Link) error { ups++; return nil }
	vlanLinkSetDownSeam = func(netlink.Link) error { downs++; return nil }

	setupExisting := func(state netlink.LinkOperState) {
		ups, downs = 0, 0
		sub := mkSub(state)
		vlanLinkByNameSeam = func(name string) (netlink.Link, error) {
			switch name {
			case parentName:
				return parent, nil
			case subName:
				return sub, nil
			}
			return nil, errors.New("no such device")
		}
		vlanLinkAddSeam = func(netlink.Link) error { return errors.New("must not create") }
	}

	t.Run("adopt existing UP disabled: brought down, never up", func(t *testing.T) {
		setupExisting(netlink.OperUp)
		idx, created, err := ensureVLANSubInterface(parentName, 50, true)
		if err != nil || created || idx != 43 {
			t.Fatalf("got idx=%d created=%v err=%v", idx, created, err)
		}
		if ups != 0 || downs != 1 {
			t.Fatalf("disabled child must be downed not upped: ups=%d downs=%d", ups, downs)
		}
	})

	t.Run("adopt existing DOWN disabled: no up nudge", func(t *testing.T) {
		setupExisting(netlink.OperDown)
		if _, _, err := ensureVLANSubInterface(parentName, 50, true); err != nil {
			t.Fatalf("err=%v", err)
		}
		if ups != 0 {
			t.Fatalf("disabled child was brought up: ups=%d", ups)
		}
	})

	t.Run("CONTROL adopt existing DOWN enabled: brought up", func(t *testing.T) {
		setupExisting(netlink.OperDown)
		if _, _, err := ensureVLANSubInterface(parentName, 50, false); err != nil {
			t.Fatalf("err=%v", err)
		}
		if ups != 1 || downs != 0 {
			t.Fatalf("enabled control must be brought up: ups=%d downs=%d", ups, downs)
		}
	})

	setupCreate := func() *bool {
		ups, downs = 0, 0
		added := false
		created := mkSub(netlink.OperDown)
		vlanLinkByNameSeam = func(name string) (netlink.Link, error) {
			switch {
			case name == parentName:
				return parent, nil
			case name == subName && added:
				return created, nil
			}
			return nil, errors.New("no such device")
		}
		vlanLinkAddSeam = func(netlink.Link) error { added = true; return nil }
		return &added
	}

	t.Run("create disabled: created but never brought up", func(t *testing.T) {
		setupCreate()
		idx, wasCreated, err := ensureVLANSubInterface(parentName, 50, true)
		if err != nil || !wasCreated || idx != 43 {
			t.Fatalf("got idx=%d created=%v err=%v", idx, wasCreated, err)
		}
		if ups != 0 {
			t.Fatalf("disabled newly-created child was brought up: ups=%d", ups)
		}
	})

	t.Run("CONTROL create enabled: brought up", func(t *testing.T) {
		setupCreate()
		if _, _, err := ensureVLANSubInterface(parentName, 50, false); err != nil {
			t.Fatalf("err=%v", err)
		}
		if ups != 1 {
			t.Fatalf("enabled control must be brought up: ups=%d", ups)
		}
	})
}
