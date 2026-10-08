package daemon

import (
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
)

// fakeRethLink is a minimal netlink.Link for exercising renameRethMember /
// programRethMAC through the rethLinkOps seam.
type fakeRethLink struct {
	attrs netlink.LinkAttrs
}

func (f *fakeRethLink) Attrs() *netlink.LinkAttrs { return &f.attrs }
func (f *fakeRethLink) Type() string              { return "fakeReth" }

// installFakeRethLinkOps wires rethLinkOpsFn to a fake that tracks admin
// link state on link and records the ordered sequence of operations. It
// restores the real ops on test cleanup. adminUp starts true (operational);
// setDown clears it, setUp sets it. macChangeNeedsCycle, when true, makes
// setHardwareAddr fail while the link is UP (modelling a driver without
// IFF_LIVE_ADDR_CHANGE) so programRethMAC takes its DOWN→set→UP fallback.
func installFakeRethLinkOps(t *testing.T, link *fakeRethLink, adminUp *bool, ops *[]string, macChangeNeedsCycle bool) {
	t.Helper()
	orig := rethLinkOpsFn
	t.Cleanup(func() { rethLinkOpsFn = orig })
	rethLinkOpsFn = rethLinkOps{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{
				Index:        link.attrs.Index,
				Name:         link.attrs.Name,
				HardwareAddr: link.attrs.HardwareAddr,
			}}, nil
		},
		byName: func(name string) (netlink.Link, error) {
			if name != link.attrs.Name {
				return nil, errors.New("no such link")
			}
			return link, nil
		},
		byIndex: func(idx int) (netlink.Link, error) {
			if idx != link.attrs.Index {
				return nil, errors.New("no such link")
			}
			return link, nil
		},
		setDown: func(l netlink.Link) error {
			*adminUp = false
			*ops = append(*ops, "down")
			return nil
		},
		setUp: func(l netlink.Link) error {
			*adminUp = true
			*ops = append(*ops, "up")
			return nil
		},
		setName: func(l netlink.Link, name string) error {
			l.Attrs().Name = name
			*ops = append(*ops, "name:"+name)
			return nil
		},
		setHardwareAddr: func(l netlink.Link, mac net.HardwareAddr) error {
			if macChangeNeedsCycle && *adminUp {
				return errors.New("EBUSY: driver lacks IFF_LIVE_ADDR_CHANGE")
			}
			l.Attrs().HardwareAddr = mac
			*ops = append(*ops, "mac")
			return nil
		},
	}
}

// TestRenameRethMemberBringsLinkUpWhenMACMatches is the #3920 RED-on-revert
// guard. It models the post-restart scenario: a RETH member still carrying
// its virtual MAC but under the kernel name enp8s0, needing a rename to
// ge-0-0-1. Because the MAC already equals the virtual MAC, the caller's
// subsequent programRethMAC would early-return with no UP — so renameRethMember
// MUST bring the link back up itself. Reverting the post-rename UP leaves
// adminUp false here → RG demote/blackhole in production.
func TestRenameRethMemberBringsLinkUpWhenMACMatches(t *testing.T) {
	mac, err := net.ParseMAC("02:bf:72:01:01:00")
	if err != nil {
		t.Fatal(err)
	}
	link := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 7, Name: "enp8s0", HardwareAddr: mac}}
	adminUp := true // operational before the rename
	var ops []string
	installFakeRethLinkOps(t, link, &adminUp, &ops, false)

	old, cycled, err := renameRethMember("ge-0-0-1", mac, mac, nil, nil)
	if err != nil || !cycled || old != "enp8s0" {
		t.Fatalf("renameRethMember returned (%q, %v, %v), want (enp8s0, true, nil)",
			old, cycled, err)
	}
	if link.attrs.Name != "ge-0-0-1" {
		t.Fatalf("link not renamed: %q", link.attrs.Name)
	}
	if !adminUp {
		t.Fatal("RETH member left DOWN after rename — RG would demote/blackhole (#3920)")
	}
	// Ordering invariant: the link is downed for the rename, then renamed,
	// then brought back up. No flap beyond the single required cycle.
	want := []string{"down", "name:ge-0-0-1", "up"}
	if !reflect.DeepEqual(ops, want) {
		t.Fatalf("op order = %v, want %v", ops, want)
	}

	// programRethMAC on the just-renamed member no-ops (MAC already matches)
	// and must NOT disturb the UP state that renameRethMember established.
	cycled, err = programRethMAC("ge-0-0-1", mac, nil)
	if err != nil {
		t.Fatalf("programRethMAC: %v", err)
	}
	if cycled {
		t.Fatal("programRethMAC should not report a cycle on a MAC-match no-op")
	}
	if !adminUp {
		t.Fatal("member DOWN after rename+programRethMAC no-op path (#3920)")
	}
}

// TestRenameRethMemberUpOnFailedRename verifies that a rename failure does not
// strand the member DOWN: renameRethMember downed the link, so it must
// best-effort restore UP even when LinkSetName fails.
func TestRenameRethMemberUpOnFailedRename(t *testing.T) {
	mac, err := net.ParseMAC("02:bf:72:01:01:00")
	if err != nil {
		t.Fatal(err)
	}
	link := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 7, Name: "enp8s0", HardwareAddr: mac}}
	adminUp := true
	var ops []string
	orig := rethLinkOpsFn
	t.Cleanup(func() { rethLinkOpsFn = orig })
	rethLinkOpsFn = rethLinkOps{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 7, Name: "enp8s0", HardwareAddr: mac}}, nil
		},
		byIndex: func(idx int) (netlink.Link, error) { return link, nil },
		setDown: func(l netlink.Link) error { adminUp = false; ops = append(ops, "down"); return nil },
		setUp:   func(l netlink.Link) error { adminUp = true; ops = append(ops, "up"); return nil },
		setName: func(l netlink.Link, name string) error {
			ops = append(ops, "name-fail")
			return errors.New("EEXIST: name in use")
		},
	}

	old, cycled, err := renameRethMember("ge-0-0-1", mac, mac, nil, nil)
	if old != "" || !cycled || err == nil {
		t.Fatalf("expected empty old name, completed cycle and error on failed rename; got (%q, %v, %v)",
			old, cycled, err)
	}
	if !adminUp {
		t.Fatal("member left DOWN after a failed rename — must be restored UP (#3920)")
	}
	want := []string{"down", "name-fail", "up"}
	if !reflect.DeepEqual(ops, want) {
		t.Fatalf("op order = %v, want %v", ops, want)
	}
}

// TestProgramRethMACCyclePathEndsUp covers the other production path: a member
// already under its correct name but carrying a stale/physical MAC, on a
// driver that cannot change the MAC live. programRethMAC must down→set→up and
// leave the member UP with linkCycled=true. This is the "a MAC-changing update
// still ends UP" half of #3920.
func TestProgramRethMACCyclePathEndsUp(t *testing.T) {
	virt, err := net.ParseMAC("02:bf:72:01:01:00")
	if err != nil {
		t.Fatal(err)
	}
	phys, err := net.ParseMAC("52:54:00:aa:bb:cc")
	if err != nil {
		t.Fatal(err)
	}
	link := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 9, Name: "ge-0-0-2", HardwareAddr: phys}}
	adminUp := true
	var ops []string
	installFakeRethLinkOps(t, link, &adminUp, &ops, true /* needs cycle */)

	cycled, err := programRethMAC("ge-0-0-2", virt, nil)
	if err != nil {
		t.Fatalf("programRethMAC: %v", err)
	}
	if !cycled {
		t.Fatal("expected linkCycled=true for a driver without live MAC change")
	}
	if !adminUp {
		t.Fatal("member left DOWN after MAC-change cycle (#3920)")
	}
	if !reflect.DeepEqual(link.attrs.HardwareAddr, net.HardwareAddr(virt)) {
		t.Fatalf("MAC not programmed: %v", link.attrs.HardwareAddr)
	}
	// The live-change attempt fails (link UP), then down→set→up.
	want := []string{"down", "mac", "up"}
	if !reflect.DeepEqual(ops, want) {
		t.Fatalf("op order = %v, want %v", ops, want)
	}
}

// TestProgramRethMACLiveChangeNoCycle confirms the fast path: a driver that
// supports IFF_LIVE_ADDR_CHANGE sets the MAC without a link cycle and reports
// linkCycled=false, leaving the member UP.
func TestProgramRethMACLiveChangeNoCycle(t *testing.T) {
	virt, _ := net.ParseMAC("02:bf:72:01:01:00")
	phys, _ := net.ParseMAC("52:54:00:aa:bb:cc")
	link := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 9, Name: "ge-0-0-2", HardwareAddr: phys}}
	adminUp := true
	var ops []string
	installFakeRethLinkOps(t, link, &adminUp, &ops, false /* live change ok */)

	cycled, err := programRethMAC("ge-0-0-2", virt, nil)
	if err != nil {
		t.Fatalf("programRethMAC: %v", err)
	}
	if cycled {
		t.Fatal("expected no cycle on a live-address-change driver")
	}
	if !adminUp {
		t.Fatal("member unexpectedly DOWN")
	}
	if want := []string{"mac"}; !reflect.DeepEqual(ops, want) {
		t.Fatalf("op order = %v, want %v", ops, want)
	}
}
