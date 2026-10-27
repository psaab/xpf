package daemon

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// formerFixture16860 models two physical ports with permanent MACs. Port 1
// starts as reth1's member (virtual MAC programmed by apply 1); port 3 is the
// operator's replacement / standalone port.
type formerFixture16860 struct {
	links               []*fakeRethLink
	ops                 []string
	setHardwareAddrErrs map[string]error
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
	f := &formerFixture16860{
		links: []*fakeRethLink{
			{attrs: netlink.LinkAttrs{Index: 11, Name: "ge-0-0-1", HardwareAddr: append(net.HardwareAddr(nil), perm1...), PermHWAddr: perm1}},
			{attrs: netlink.LinkAttrs{Index: 13, Name: "ge-0-0-3", HardwareAddr: append(net.HardwareAddr(nil), perm3...), PermHWAddr: perm3}},
		},
		setHardwareAddrErrs: make(map[string]error),
	}
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
			if err := f.setHardwareAddrErrs[l.Attrs().Name]; err != nil {
				return err
			}
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

// TestFormerMemberFailedRestoreRetainedAcrossRetry17890 proves that a failed
// permanent-MAC write leaves the former member pending for the next apply.
func TestFormerMemberFailedRestoreRetainedAcrossRetry17890(t *testing.T) {
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

	restoreErr := errors.New("injected permanent-MAC write failure")
	f.setHardwareAddrErrs["ge-0-0-1"] = restoreErr
	swapCfg := formerConfig16860("ge-0/0/3", "ge-0/0/1")
	if err := d.applyConfigLocked(context.Background(), swapCfg); !errors.Is(err, restoreErr) {
		t.Fatalf("apply2 error = %v, want injected restore error %v", err, restoreErr)
	}
	if got := f.byName("ge-0-0-1").attrs.HardwareAddr; !bytes.Equal(got, virt) {
		t.Fatalf("failed restore changed former member MAC = %s, want virtual %s", got, virt)
	}
	if _, pending := d.lastRethMembers["ge-0-0-1"]; !pending {
		t.Fatalf("failed former member absent from retry record: %v", d.lastRethMembers)
	}

	delete(f.setHardwareAddrErrs, "ge-0-0-1")
	if err := d.applyConfigLocked(context.Background(), swapCfg); err != nil {
		t.Fatalf("apply3 retry: %v", err)
	}
	perm1 := net.HardwareAddr{0x52, 0x54, 0x00, 0xcc, 0x00, 0x01}
	if got := f.byName("ge-0-0-1").attrs.HardwareAddr; !bytes.Equal(got, perm1) {
		t.Fatalf("former member MAC after retry = %s, want permanent %s", got, perm1)
	}
	if len(d.lastRethMembers) != 1 {
		t.Fatalf("retry record = %v, want only current RETH member", d.lastRethMembers)
	}
	if _, current := d.lastRethMembers["ge-0-0-3"]; !current {
		t.Fatalf("current member missing from retry record: %v", d.lastRethMembers)
	}
}

// TestRestoreFormerRethRejectsUnrestorableMembers17890 covers paths that must
// not become green no-op restores or swallow a MAC-write error without a join.
func TestRestoreFormerRethRejectsUnrestorableMembers17890(t *testing.T) {
	t.Run("missing link", func(t *testing.T) {
		installFormerFixture16860(t)
		d := &Daemon{}
		if _, _, err := d.restoreFormerRethMemberMAC("absent"); err == nil {
			t.Fatal("restore of absent former member returned success")
		}
	})
	t.Run("missing permanent MAC", func(t *testing.T) {
		f := installFormerFixture16860(t)
		f.byName("ge-0-0-1").attrs.PermHWAddr = nil
		d := &Daemon{}
		if _, _, err := d.restoreFormerRethMemberMAC("ge-0-0-1"); err == nil {
			t.Fatal("restore without a permanent MAC returned success")
		}
	})
	t.Run("MAC write failure without dataplane", func(t *testing.T) {
		f := installFormerFixture16860(t)
		f.byName("ge-0-0-1").attrs.HardwareAddr = cluster.RethMAC(1, 1, 1, 0)
		restoreErr := errors.New("injected MAC write failure")
		f.setHardwareAddrErrs["ge-0-0-1"] = restoreErr
		d := &Daemon{}
		if _, _, err := d.restoreFormerRethMemberMAC("ge-0-0-1"); !errors.Is(err, restoreErr) {
			t.Fatalf("restore error = %v, want injected write error %v", err, restoreErr)
		}
	})
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
func formerOnlyMemberConfig17890(member string) *config.Config {
	interfaces := map[string]*config.InterfaceConfig{
		"reth1": {Name: "reth1", RedundancyGroup: 1},
	}
	if member != "" {
		interfaces[member] = &config.InterfaceConfig{
			Name: member, RedundantParent: "reth1",
		}
	}
	return &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{ClusterID: 1, NodeID: 0},
		},
		Interfaces: config.InterfacesConfig{Interfaces: interfaces},
	}
}

// TestFormerRethRestoreFollowsDeviceMapTeardownRename17890 proves a former
// member's restoration identity follows a successful managed-to-unmapped
// rename even when bringing the renamed link up fails. A further apply verifies
// the completed obligation does not survive under the obsolete logical name.
func TestFormerRethRestoreFollowsDeviceMapTeardownRename17890(t *testing.T) {
	dir := withTempLinkDir(t)
	f := installFormerFixture16860(t)
	d := twoMemberRethDaemon(t, &leaseTracingLinkController{})
	if err := d.applyConfigLocked(context.Background(), formerOnlyMemberConfig17890("ge-0/0/1")); err != nil {
		t.Fatalf("apply1: %v", err)
	}
	if wrote, err := writeLinkFile("ge-0-0-1", "enp8s0"); err != nil || !wrote {
		t.Fatalf("seed former member .link: wrote=%v err=%v", wrote, err)
	}
	netFile := filepath.Join(dir, linkPrefix+"ge-0-0-1.network")
	if err := os.WriteFile(netFile, []byte("[Match]\nName=ge-0-0-1\n"), 0o644); err != nil {
		t.Fatalf("seed former member .network: %v", err)
	}

	oldRestore, oldByName := teardownRestoreTargetFn, nlLinkByName
	oldDown, oldSetName, oldUp := nlLinkSetDown, nlLinkSetName, nlLinkSetUp
	oldRename, oldReload := renameInterfaceFn, networkctlReloadFn
	t.Cleanup(func() {
		teardownRestoreTargetFn, nlLinkByName = oldRestore, oldByName
		nlLinkSetDown, nlLinkSetName, nlLinkSetUp = oldDown, oldSetName, oldUp
		renameInterfaceFn, networkctlReloadFn = oldRename, oldReload
	})
	teardownRestoreTargetFn = func(name string) (string, bool) {
		return "enp8s0", name == "ge-0-0-1" && f.byName(name) != nil
	}
	// Exercise the real renameInterface result path: its rename succeeds, but
	// both the initial and retry LinkSetUp fail after the interface is renamed.
	renameInterfaceFn = renameInterface
	nlLinkByName = func(name string) (netlink.Link, error) {
		if link := f.byName(name); link != nil {
			return link, nil
		}
		return nil, errStep0NoLink
	}
	nlLinkSetDown = func(netlink.Link) error { return nil }
	nlLinkSetName = func(link netlink.Link, name string) error {
		link.Attrs().Name = name
		return nil
	}
	upErr := errors.New("injected post-rename link-up failure")
	upCalls := 0
	nlLinkSetUp = func(netlink.Link) error {
		upCalls++
		if upCalls <= 2 {
			return upErr
		}
		return nil
	}
	networkctlReloadFn = func() error { return nil }

	retired := formerOnlyMemberConfig17890("")
	retired.Chassis.DeviceMap = &config.DeviceMapConfig{
		Entries:        []config.DeviceMapEntry{{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"}},
		UnmappedPolicy: config.DeviceMapPolicyLeaveAlone,
	}
	err := d.applyConfigLocked(context.Background(), retired)
	if !errors.Is(err, upErr) {
		t.Fatalf("apply2 link-up error = %v, want post-rename error %v", err, upErr)
	}
	perm := net.HardwareAddr{0x52, 0x54, 0x00, 0xcc, 0x00, 0x01}
	if got := f.byName("enp8s0"); got == nil || !bytes.Equal(got.attrs.HardwareAddr, perm) {
		t.Fatalf("renamed former member = %v, want enp8s0 restored to %s; ops=%v", got, perm, f.ops)
	}
	for _, marker := range []string{
		filepath.Join(dir, linkPrefix+"ge-0-0-1.link"),
		netFile,
	} {
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("completed teardown rename retained stale managed marker %q: %v", marker, err)
		}
	}
	if len(d.lastRethMembers) != 0 {
		t.Fatalf("completed restoration left stale member record: %v", d.lastRethMembers)
	}
	if err := d.applyConfigLocked(context.Background(), retired); err != nil {
		t.Fatalf("apply3 after completed device-map removal: %v", err)
	}
}

// TestFormerRethMissingLinkRemainsPending17890 is the fail-closed control:
// unlike a successful teardown rename, a genuinely absent former link keeps
// returning an error and stays in the retry record.
func TestFormerRethMissingLinkRemainsPending17890(t *testing.T) {
	withTempLinkDir(t)
	f := installFormerFixture16860(t)
	d := twoMemberRethDaemon(t, &leaseTracingLinkController{})
	if err := d.applyConfigLocked(context.Background(), formerOnlyMemberConfig17890("ge-0/0/1")); err != nil {
		t.Fatalf("apply1: %v", err)
	}
	for i, link := range f.links {
		if link.attrs.Name == "ge-0-0-1" {
			f.links = append(f.links[:i], f.links[i+1:]...)
			break
		}
	}
	if err := d.applyConfigLocked(context.Background(), formerOnlyMemberConfig17890("")); err == nil {
		t.Fatal("apply2 with genuinely absent former member succeeded")
	}
	if _, pending := d.lastRethMembers["ge-0-0-1"]; !pending {
		t.Fatalf("genuinely absent former member lost retry record: %v", d.lastRethMembers)
	}
}

// TestFormerMemberPendingExcludedFromDaemonRecovery17890 keeps an unconfigured
// former member out of a missing replacement's recovery search after its MAC
// restoration fails, then proves the absent replacement itself never becomes
// a permanent restore obligation.
func TestFormerMemberPendingExcludedFromDaemonRecovery17890(t *testing.T) {
	withTempLinkDir(t)
	f := installFormerFixture16860(t)
	d := twoMemberRethDaemon(t, &leaseTracingLinkController{})
	for i, link := range f.links {
		if link.attrs.Name == "ge-0-0-3" {
			f.links = append(f.links[:i], f.links[i+1:]...)
			break
		}
	}
	virt := cluster.RethMAC(1, 1, 1, 0)
	if err := d.applyConfigLocked(context.Background(), formerOnlyMemberConfig17890("ge-0/0/1")); err != nil {
		t.Fatalf("apply1: %v", err)
	}
	restoreErr := errors.New("injected permanent-MAC write failure")
	f.setHardwareAddrErrs["ge-0-0-1"] = restoreErr
	if err := d.applyConfigLocked(context.Background(), formerOnlyMemberConfig17890("ge-0/0/3")); !errors.Is(err, restoreErr) {
		t.Fatalf("apply2 error = %v, want former restore error %v", err, restoreErr)
	}
	if got := f.byName("ge-0-0-1"); got == nil || !bytes.Equal(got.attrs.HardwareAddr, virt) {
		t.Fatalf("pending former member was renamed or lost: link=%v ops=%v", got, f.ops)
	}
	if got := f.byName("ge-0-0-3"); got != nil {
		t.Fatalf("missing replacement was recovered from pending former: %q", got.attrs.Name)
	}
	if _, pending := d.lastRethMembers["ge-0-0-1"]; !pending {
		t.Fatalf("failed former restore absent from retry record: %v", d.lastRethMembers)
	}
	if _, ghost := d.lastRethMembers["ge-0-0-3"]; ghost {
		t.Fatalf("never-present desired replacement became restore debt: %v", d.lastRethMembers)
	}

	delete(f.setHardwareAddrErrs, "ge-0-0-1")
	retired := formerOnlyMemberConfig17890("")
	if err := d.applyConfigLocked(context.Background(), retired); err != nil {
		t.Fatalf("apply3 after removing missing replacement and retrying former: %v", err)
	}
	perm := net.HardwareAddr{0x52, 0x54, 0x00, 0xcc, 0x00, 0x01}
	if got := f.byName("ge-0-0-1"); got == nil || !bytes.Equal(got.attrs.HardwareAddr, perm) {
		t.Fatalf("former member after apply3 = %v, want permanent MAC %s", got, perm)
	}
	if len(d.lastRethMembers) != 0 {
		t.Fatalf("completed former restore left retry debt: %v", d.lastRethMembers)
	}
	if err := d.applyConfigLocked(context.Background(), retired); err != nil {
		t.Fatalf("apply4 repeated rollback apply: %v", err)
	}
}

// TestRethMemberWriteSuccessSurvivesReadbackFailure17890 verifies that a
// successful virtual-MAC write is remembered without relying on a
// post-write lookup, which this seam would fail if attempted.
func TestRethMemberWriteSuccessSurvivesReadbackFailure17890(t *testing.T) {
	withTempLinkDir(t)
	f := installFormerFixture16860(t)
	d := twoMemberRethDaemon(t, &leaseTracingLinkController{})
	virtual := cluster.RethMAC(1, 1, 1, 0)
	originalByName := rethLinkOpsFn.byName
	t.Cleanup(func() { rethLinkOpsFn.byName = originalByName })
	readbackErr := errors.New("transient post-write bookkeeping lookup failure")
	rethLinkOpsFn.byName = func(name string) (netlink.Link, error) {
		link, err := originalByName(name)
		if name == "ge-0-0-1" && err == nil && bytes.Equal(link.Attrs().HardwareAddr, virtual) {
			return nil, readbackErr
		}
		return link, err
	}
	if err := d.applyConfigLocked(context.Background(), formerOnlyMemberConfig17890("ge-0/0/1")); err != nil {
		t.Fatalf("apply1 despite bookkeeping-only lookup failure: %v", err)
	}
	if _, tracked := d.lastRethMembers["ge-0-0-1"]; !tracked {
		t.Fatalf("successful virtual-MAC write lost its restore obligation: %v", d.lastRethMembers)
	}

	rethLinkOpsFn.byName = originalByName
	retired := formerOnlyMemberConfig17890("")
	if err := d.applyConfigLocked(context.Background(), retired); err != nil {
		t.Fatalf("apply2 removing successfully programmed member: %v", err)
	}
	permanent := net.HardwareAddr{0x52, 0x54, 0x00, 0xcc, 0x00, 0x01}
	if got := f.byName("ge-0-0-1"); got == nil || !bytes.Equal(got.attrs.HardwareAddr, permanent) {
		t.Fatalf("removed member after apply2 = %v, want permanent MAC %s", got, permanent)
	}
}

// TestLegacyRethMigrationFailureRetainsVirtualMACOwner17890 covers the
// shared-MAC migration fallback: a candidate renamed to the configured member
// still needs restoration if setting its indexed MAC then fails.
func TestLegacyRethMigrationFailureRetainsVirtualMACOwner17890(t *testing.T) {
	withTempLinkDir(t)
	f := installFormerFixture16860(t)
	d := twoMemberRethDaemon(t, &leaseTracingLinkController{})
	legacy := cluster.RethMAC(1, 1, 0, 0)
	f.byName("ge-0-0-1").attrs.HardwareAddr = append(net.HardwareAddr(nil), legacy...)
	for i, link := range f.links {
		if link.attrs.Name == "ge-0-0-3" {
			f.links = append(f.links[:i], f.links[i+1:]...)
			break
		}
	}
	programErr := errors.New("injected indexed-MAC migration failure")
	f.setHardwareAddrErrs["ge-0-0-3"] = programErr
	if err := d.applyConfigLocked(context.Background(), formerOnlyMemberConfig17890("ge-0/0/3")); err == nil {
		t.Fatal("apply1 with failed legacy-MAC migration succeeded")
	}
	if got := f.byName("ge-0-0-3"); got == nil || !bytes.Equal(got.attrs.HardwareAddr, legacy) {
		t.Fatalf("legacy migration candidate = %v, want renamed member still carrying %s", got, legacy)
	}
	if _, tracked := d.lastRethMembers["ge-0-0-3"]; !tracked {
		t.Fatalf("legacy virtual-MAC owner absent from restore record: %v", d.lastRethMembers)
	}

	delete(f.setHardwareAddrErrs, "ge-0-0-3")
	retired := formerOnlyMemberConfig17890("")
	if err := d.applyConfigLocked(context.Background(), retired); err != nil {
		t.Fatalf("apply2 restoring failed legacy-MAC owner: %v", err)
	}
	permanent := net.HardwareAddr{0x52, 0x54, 0x00, 0xcc, 0x00, 0x01}
	if got := f.byName("ge-0-0-3"); got == nil || !bytes.Equal(got.attrs.HardwareAddr, permanent) {
		t.Fatalf("legacy owner after apply2 = %v, want permanent MAC %s", got, permanent)
	}
}
