package daemon

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// formerFixture16860 models two physical ports with permanent MACs. Port 1
// starts as reth1's member (virtual MAC programmed by apply 1); port 3 is the
// operator's replacement / standalone port.
type formerFixture16860 struct {
	links []*fakeRethLink
	ops   []string
}

func (f *formerFixture16860) byName(name string) *fakeRethLink {
	for _, l := range f.links {
		if l.attrs.Name == name {
			return l
		}
	}
	return nil
}

func installFormerFixture16860(t *testing.T) *formerFixture16860 {
	t.Helper()
	perm1 := net.HardwareAddr{0x52, 0x54, 0x00, 0xcc, 0x00, 0x01}
	perm3 := net.HardwareAddr{0x52, 0x54, 0x00, 0xcc, 0x00, 0x03}
	f := &formerFixture16860{links: []*fakeRethLink{
		{attrs: netlink.LinkAttrs{Index: 11, Name: "ge-0-0-1", HardwareAddr: append(net.HardwareAddr(nil), perm1...), PermHWAddr: perm1}},
		{attrs: netlink.LinkAttrs{Index: 13, Name: "ge-0-0-3", HardwareAddr: append(net.HardwareAddr(nil), perm3...), PermHWAddr: perm3}},
	}}
	orig := rethLinkOpsFn
	t.Cleanup(func() { rethLinkOpsFn = orig })
	rethLinkOpsFn = rethLinkOps{
		interfaces: func() ([]net.Interface, error) {
			var out []net.Interface
			for _, l := range f.links {
				out = append(out, net.Interface{Index: l.attrs.Index, Name: l.attrs.Name, HardwareAddr: append(net.HardwareAddr(nil), l.attrs.HardwareAddr...)})
			}
			return out, nil
		},
		byName: func(name string) (netlink.Link, error) {
			if l := f.byName(name); l != nil {
				return l, nil
			}
			return nil, errStep0NoLink
		},
		byIndex: func(idx int) (netlink.Link, error) {
			for _, l := range f.links {
				if l.attrs.Index == idx {
					return l, nil
				}
			}
			return nil, errStep0NoLink
		},
		setDown: func(l netlink.Link) error { f.ops = append(f.ops, "down:"+l.Attrs().Name); return nil },
		setUp:   func(l netlink.Link) error { f.ops = append(f.ops, "up:"+l.Attrs().Name); return nil },
		setName: func(l netlink.Link, name string) error {
			f.ops = append(f.ops, "name:"+l.Attrs().Name+"->"+name)
			l.Attrs().Name = name
			return nil
		},
		setHardwareAddr: func(l netlink.Link, mac net.HardwareAddr) error {
			f.ops = append(f.ops, "mac:"+l.Attrs().Name+":"+mac.String())
			l.Attrs().HardwareAddr = append(net.HardwareAddr(nil), mac...)
			return nil
		},
	}
	// VLAN-child propagation uses the netlink package directly, not this seam;
	// stub its enumeration to no children so it cannot touch the host.
	origByName, origList := rethParentLinkByName, rethLinkLister
	rethParentLinkByName = func(name string) (netlink.Link, error) {
		if l := f.byName(name); l != nil {
			return l, nil
		}
		return nil, errStep0NoLink
	}
	rethLinkLister = func() ([]netlink.Link, error) {
		var out []netlink.Link
		for _, l := range f.links {
			out = append(out, l)
		}
		return out, nil
	}
	t.Cleanup(func() { rethParentLinkByName, rethLinkLister = origByName, origList })
	origRun := runCommandTimeout
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name == "ethtool" && len(args) > 0 && args[0] == "-k" {
			return []byte("rx-vlan-offload: off\nrx-vlan-stag-hw-parse: off\n"), nil
		}
		return nil, nil
	}
	t.Cleanup(func() { runCommandTimeout = origRun })
	return f
}

func formerConfig16860(member string, standalone ...string) *config.Config {
	ifaces := map[string]*config.InterfaceConfig{
		"reth1":    {Name: "reth1", RedundancyGroup: 1},
		"ge-7/0/1": {Name: "ge-7/0/1", RedundantParent: "reth1"},
	}
	if member != "" {
		ifaces[member] = &config.InterfaceConfig{Name: member, RedundantParent: "reth1"}
	}
	for _, s := range standalone {
		ifaces[s] = &config.InterfaceConfig{Name: s}
	}
	return &config.Config{
		Chassis:    config.ChassisConfig{Cluster: &config.ClusterConfig{ClusterID: 1, NodeID: 0}},
		Interfaces: config.InterfacesConfig{Interfaces: ifaces},
	}
}

func carriers16860(f *formerFixture16860, mac net.HardwareAddr) int {
	n := 0
	for _, l := range f.links {
		if bytes.Equal(l.attrs.HardwareAddr, mac) {
			n++
		}
	}
	return n
}

// TestFormerMemberSwapRestoresPermMAC16860 is the swap cell: after reth1 moves
// ge-0/0/1 -> ge-0/0/3, exactly one port may carry the virtual MAC and the
// former member must be back on its permanent MAC.
func TestFormerMemberSwapRestoresPermMAC16860(t *testing.T) {
	withTempLinkDir(t)
	f := installFormerFixture16860(t)
	d := twoMemberRethDaemon(t, &leaseTracingLinkController{})
	virt := cluster.RethMAC(1, 1, 1, 0)

	if err := d.applyConfigLocked(context.Background(), formerConfig16860("ge-0/0/1")); err != nil {
		t.Fatalf("apply1: %v", err)
	}
	if got := f.byName("ge-0-0-1").attrs.HardwareAddr; !bytes.Equal(got, virt) {
		t.Fatalf("apply1 former-to-be MAC = %s, want virtual %s", got, virt)
	}
	f.ops = nil
	if err := d.applyConfigLocked(context.Background(), formerConfig16860("ge-0/0/3", "ge-0/0/1")); err != nil {
		t.Fatalf("apply2: %v", err)
	}
	if n := carriers16860(f, virt); n != 1 {
		t.Fatalf("virtual MAC carriers after swap = %d, want 1; links: %s=%s %s=%s ops=%v",
			n, "ge-0-0-1", f.byName("ge-0-0-1").attrs.HardwareAddr, "ge-0-0-3", f.byName("ge-0-0-3").attrs.HardwareAddr, f.ops)
	}
	perm1 := net.HardwareAddr{0x52, 0x54, 0x00, 0xcc, 0x00, 0x01}
	if got := f.byName("ge-0-0-1").attrs.HardwareAddr; !bytes.Equal(got, perm1) {
		t.Fatalf("former member MAC after swap = %s, want permanent %s", got, perm1)
	}
}

// TestFormerMemberDeleteRestoresPermMAC16860: deleting the RETH restores the
// former member's permanent MAC.
func TestFormerMemberDeleteRestoresPermMAC16860(t *testing.T) {
	withTempLinkDir(t)
	f := installFormerFixture16860(t)
	d := twoMemberRethDaemon(t, &leaseTracingLinkController{})
	virt := cluster.RethMAC(1, 1, 1, 0)

	if err := d.applyConfigLocked(context.Background(), formerConfig16860("ge-0/0/1")); err != nil {
		t.Fatalf("apply1: %v", err)
	}
	if got := f.byName("ge-0-0-1").attrs.HardwareAddr; !bytes.Equal(got, virt) {
		t.Fatalf("apply1 MAC = %s, want %s", got, virt)
	}
	noReth := &config.Config{
		Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{ClusterID: 1, NodeID: 0}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/1": {Name: "ge-0/0/1"},
			"ge-7/0/1": {Name: "ge-7/0/1"},
		}},
	}
	if err := d.applyConfigLocked(context.Background(), noReth); err != nil {
		t.Fatalf("apply2 (delete): %v", err)
	}
	perm1 := net.HardwareAddr{0x52, 0x54, 0x00, 0xcc, 0x00, 0x01}
	if got := f.byName("ge-0-0-1").attrs.HardwareAddr; !bytes.Equal(got, perm1) {
		t.Fatalf("former member MAC after RETH delete = %s, want permanent %s; ops=%v", got, perm1, f.ops)
	}
}

// TestFormerMemberAbsentNewMemberNotRenamed16860: the new member ge-0/0/5 has
// no NIC; the former member (now a configured standalone port) must NOT be
// renamed into the missing member's slot.
func TestFormerMemberAbsentNewMemberNotRenamed16860(t *testing.T) {
	withTempLinkDir(t)
	f := installFormerFixture16860(t)
	d := twoMemberRethDaemon(t, &leaseTracingLinkController{})

	if err := d.applyConfigLocked(context.Background(), formerConfig16860("ge-0/0/1")); err != nil {
		t.Fatalf("apply1: %v", err)
	}
	f.ops = nil
	_ = d.applyConfigLocked(context.Background(), formerConfig16860("ge-0/0/5", "ge-0/0/1"))
	for _, op := range f.ops {
		if len(op) >= 5 && op[:5] == "name:" {
			t.Fatalf("configured standalone former member was renamed: ops=%v", f.ops)
		}
	}
	if f.byName("ge-0-0-1") == nil {
		t.Fatalf("ge-0-0-1 disappeared (renamed away); ops=%v", f.ops)
	}
	if f.byName("ge-0-0-5") != nil {
		t.Fatalf("ge-0-0-5 unexpectedly materialised from the former member; ops=%v", f.ops)
	}
}

// TestRenameRethMemberExcludesConfiguredStandalone16860 binds the recovery
// exclusion directly: a candidate wearing the virtual MAC but configured as a
// standalone interface must not be claimed.
func TestRenameRethMemberExcludesConfiguredStandalone16860(t *testing.T) {
	virt := cluster.RethMAC(1, 1, 1, 0)
	perm := net.HardwareAddr{0x52, 0x54, 0x00, 0xcc, 0x00, 0x01}
	link := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 11, Name: "ge-0-0-1", HardwareAddr: append(net.HardwareAddr(nil), virt...), PermHWAddr: perm}}
	var ops []string
	adminUp := true
	installFakeRethLinkOps(t, link, &adminUp, &ops, false)
	// installFakeRethLinkOps reports the link under its current name; the
	// configured set excludes it, so no rename may happen.
	old, cycled, err := renameRethMember("ge-0-0-5", virt, virt,
		map[string]struct{}{"ge-0-0-1": {}, "ge-0-0-5": {}}, nil)
	if err != nil || old != "" || cycled {
		t.Fatalf("renameRethMember = (%q,%v,%v), want no rename of configured standalone", old, cycled, err)
	}
	if link.attrs.Name != "ge-0-0-1" {
		t.Fatalf("configured standalone renamed to %q", link.attrs.Name)
	}
}

// TestRestoreFormerHookRunsOnTheCallersGoroutine_16860 is the behavioural
// containment proof for the restore site's PrepareLinkCycle acquisition
// (link_cycle_acquisition_site_6871_test.go): the hook must run on the
// caller's goroutine, inside restoreFormerRethMemberMAC's extent, so the
// apply's deferred abandonLinkCycleLease bounds the lease it takes.
func TestRestoreFormerHookRunsOnTheCallersGoroutine_16860(t *testing.T) {
	// The proof is that programRethMAC invokes its hook synchronously; drive
	// it through the restore-shaped hook and compare goroutine identity.
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true))
	caller := goIDFromStack()
	if caller == 0 {
		t.Fatal("fixture: could not read test goroutine id")
	}
	ran := false
	var hookGoID uint64
	cycled, _, err := programRethMAC("ge-0-0-1", virtMAC5103, func() error {
		ran = true
		hookGoID = goIDFromStack()
		return nil
	})
	if err != nil || !cycled || !ran {
		t.Fatalf("programRethMAC = (cycled=%v, err=%v), hook ran=%v; want cycled with hook run", cycled, err, ran)
	}
	if hookGoID != caller {
		t.Fatalf("restore beforeCycle ran on goroutine %d, caller %d", hookGoID, caller)
	}
}
