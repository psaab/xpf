package daemon

import (
	"fmt"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #12583 real-kernel cells. They SKIP without a private netns (run under
// `unshare -rn`). fxp* links are enslaved to a VRF on table 999, so their
// connected routes are the kernel's own; ge-0-0-0 stays in the main table.
// Every apply runs the production applyMgmtVRFRoutesTo through
// countingMgmtProgrammer12539 and checks its error, its replace and delete
// counts, and the link the kernel lists the backup-router on.

type backupKernelEnv12583 struct {
	t       *testing.T
	vrf     netlink.Link
	nlh     *netlink.Handle
	counter *countingMgmtProgrammer12539
	links   map[string]netlink.Link
	names   map[int]string
}

func newBackupKernelEnv12583(t *testing.T) *backupKernelEnv12583 {
	t.Helper()
	enterPrivateNetns9813(t)
	if err := netlink.LinkAdd(&netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: mgmtVRFDeviceName},
		Table:     uint32(mgmtVRFTableID),
	}); err != nil {
		t.Skipf("cannot create a table-%d VRF in this netns (is the vrf module loaded?): %v", mgmtVRFTableID, err)
	}
	vrf, err := netlink.LinkByName(mgmtVRFDeviceName)
	if err != nil {
		t.Fatalf("lookup %s: %v", mgmtVRFDeviceName, err)
	}
	if err := netlink.LinkSetUp(vrf); err != nil {
		t.Fatalf("bring %s up: %v", mgmtVRFDeviceName, err)
	}
	nlh, err := netlink.NewHandle()
	if err != nil {
		t.Fatalf("netlink.NewHandle: %v", err)
	}
	t.Cleanup(nlh.Close)
	return &backupKernelEnv12583{
		t:       t,
		vrf:     vrf,
		nlh:     nlh,
		counter: &countingMgmtProgrammer12539{Handle: nlh},
		links:   make(map[string]netlink.Link),
		names:   make(map[int]string),
	}
}

// link creates an up dummy link; a management link is enslaved to the VRF.
func (e *backupKernelEnv12583) link(name string, management bool) {
	e.t.Helper()
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		e.t.Fatalf("add %s: %v", name, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		e.t.Fatalf("lookup %s: %v", name, err)
	}
	if management {
		if err := netlink.LinkSetMasterByIndex(link, e.vrf.Attrs().Index); err != nil {
			e.t.Fatalf("enslave %s to %s: %v", name, mgmtVRFDeviceName, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		e.t.Fatalf("bring %s up: %v", name, err)
	}
	e.links[name] = link
	e.names[link.Attrs().Index] = name
}

func (e *backupKernelEnv12583) addr(name, cidr string, add bool) {
	e.t.Helper()
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		e.t.Fatalf("ParseAddr(%q): %v", cidr, err)
	}
	addr.Flags = unix.IFA_F_NODAD
	if add {
		err = netlink.AddrAdd(e.links[name], addr)
	} else {
		err = netlink.AddrDel(e.links[name], addr)
	}
	if err != nil {
		e.t.Fatalf("address %s on %s (add=%v): %v", cidr, name, add, err)
	}
}

// backupLink names the link the kernel lists the metric-250 route via gateway
// on in table 999, or returns "" when it is absent.
func (e *backupKernelEnv12583) backupLink(gateway string) string {
	e.t.Helper()
	gw := net.ParseIP(gateway)
	family := netlink.FAMILY_V4
	if gw.To4() == nil {
		family = netlink.FAMILY_V6
	}
	routes, err := e.nlh.RouteListFiltered(family, &netlink.Route{Table: mgmtVRFTableID}, netlink.RT_FILTER_TABLE)
	if err != nil {
		e.t.Fatalf("list table %d: %v", mgmtVRFTableID, err)
	}
	for _, route := range routes {
		if route.Priority == 250 && route.Gw.Equal(gw) {
			if name, ok := e.names[route.LinkIndex]; ok {
				return name
			}
			return fmt.Sprintf("ifindex %d", route.LinkIndex)
		}
	}
	return ""
}

type backupApply12583 struct {
	step     string
	err      bool
	replaced int
	deleted  int
	link     string // where the kernel lists the backup-router; "" = absent
}

func (e *backupKernelEnv12583) apply(d *Daemon, mgmtSet map[string]bool, gateway string, want backupApply12583) {
	e.t.Helper()
	e.counter.replaced, e.counter.deleted = 0, 0
	err := d.applyMgmtVRFRoutesTo(e.counter, nil, mgmtSet)
	link := e.backupLink(gateway)
	if (err != nil) != want.err || e.counter.replaced != want.replaced ||
		e.counter.deleted != want.deleted || link != want.link {
		e.t.Fatalf("%s: err=%v replaced=%d deleted=%d backup-router link=%q; want error=%v replaced=%d deleted=%d link=%q",
			want.step, err, e.counter.replaced, e.counter.deleted, link,
			want.err, want.replaced, want.deleted, want.link)
	}
}

// P0: an unchanged backup-router in either family is installed on fxp0 once,
// then repeated reconciles neither replace nor delete it. Each family gets a
// fresh netns; the families are not subtests so that a missing netns skips
// the cell itself instead of reporting a pass over two skipped subtests.
func TestBackupRouterSteadyStateOnKernel12583(t *testing.T) {
	for _, gateway := range []string{"192.0.2.1", "2001:db8:10::1"} {
		e := newBackupKernelEnv12583(t)
		e.link("fxp0", true)
		e.addr("fxp0", "192.0.2.2/24", true)
		e.addr("fxp0", "2001:db8:10::2/64", true)
		d := &Daemon{store: testStoreWithSetConfig(t, []string{
			"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
			"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64",
			"set system backup-router " + gateway,
		})}
		mgmtSet := map[string]bool{"fxp0": true}
		for pass, want := range []backupApply12583{
			{replaced: 1, link: "fxp0"},
			{link: "fxp0"},
			{link: "fxp0"},
		} {
			want.step = fmt.Sprintf("%s apply %d", gateway, pass+1)
			e.apply(d, mgmtSet, gateway, want)
		}
	}
}

// P1: the gateway's subnet moves from fxp0 to fxp1. fxp0 keeps another
// address, so the kernel keeps listing the route on fxp0 until the reconcile
// moves it to fxp1 in place.
func TestBackupRouterFollowsGatewayMoveOnKernel12583(t *testing.T) {
	const gateway = "192.0.2.1"
	e := newBackupKernelEnv12583(t)
	e.link("fxp0", true)
	e.link("fxp1", true)
	e.addr("fxp0", "192.0.2.2/24", true)
	e.addr("fxp0", "10.9.9.2/24", true)
	d := &Daemon{store: testStoreWithSetConfig(t, []string{"set system backup-router " + gateway})}
	mgmtSet := map[string]bool{"fxp0": true, "fxp1": true}
	e.apply(d, mgmtSet, gateway, backupApply12583{step: "apply 1", replaced: 1, link: "fxp0"})
	e.addr("fxp1", "192.0.2.3/24", true)
	e.addr("fxp0", "192.0.2.2/24", false)
	if link := e.backupLink(gateway); link != "fxp0" {
		t.Fatalf("precondition: after the subnet moved the kernel lists the backup-router on %q, want fxp0", link)
	}
	e.apply(d, mgmtSet, gateway, backupApply12583{step: "apply 2 (subnet on fxp1)", replaced: 1, link: "fxp1"})
	e.apply(d, mgmtSet, gateway, backupApply12583{step: "apply 3", link: "fxp1"})
}

// P2: the gateway's subnet is removed from fxp0, which keeps another address,
// so the kernel keeps listing the unreachable route. The reconcile's re-check
// fails: the apply returns the error and deletes the stale route, and the next
// apply fails again.
func TestBackupRouterUnreachableGatewayFailsClosedOnKernel12583(t *testing.T) {
	const gateway = "192.0.2.1"
	e := newBackupKernelEnv12583(t)
	e.link("fxp0", true)
	e.addr("fxp0", "192.0.2.2/24", true)
	e.addr("fxp0", "10.9.9.2/24", true)
	d := &Daemon{store: testStoreWithSetConfig(t, []string{"set system backup-router " + gateway})}
	mgmtSet := map[string]bool{"fxp0": true}
	e.apply(d, mgmtSet, gateway, backupApply12583{step: "apply 1", replaced: 1, link: "fxp0"})
	e.addr("fxp0", "192.0.2.2/24", false)
	if link := e.backupLink(gateway); link != "fxp0" {
		t.Fatalf("precondition: after the subnet was removed the kernel lists the backup-router on %q, want fxp0", link)
	}
	e.apply(d, mgmtSet, gateway, backupApply12583{
		step: "apply 2 (gateway unreachable)", err: true, replaced: 1, deleted: 1,
	})
	e.apply(d, mgmtSet, gateway, backupApply12583{step: "apply 3", err: true, replaced: 1})
}

// P3: before fxp0 is connected the gateway resolves to no management link, and
// the kernel installs the route through the non-management ge-0-0-0. Every
// apply re-checks it until fxp0 carries the gateway's subnet; the reconcile
// then moves the route to fxp0 in place.
func TestBackupRouterLeavesNonManagementLinkOnKernel12583(t *testing.T) {
	const gateway = "192.0.2.1"
	e := newBackupKernelEnv12583(t)
	e.link("fxp0", true)
	e.link("ge-0-0-0", false)
	e.addr("ge-0-0-0", "192.0.2.10/24", true)
	d := &Daemon{store: testStoreWithSetConfig(t, []string{"set system backup-router " + gateway})}
	mgmtSet := map[string]bool{"fxp0": true}
	e.apply(d, mgmtSet, gateway, backupApply12583{
		step: "apply 1 (kernel picks ge-0-0-0)", replaced: 1, link: "ge-0-0-0",
	})
	e.apply(d, mgmtSet, gateway, backupApply12583{
		step: "apply 2 (still unresolved)", replaced: 1, link: "ge-0-0-0",
	})
	e.addr("fxp0", "192.0.2.2/24", true)
	e.apply(d, mgmtSet, gateway, backupApply12583{step: "apply 3 (fxp0 connected)", replaced: 1, link: "fxp0"})
	e.apply(d, mgmtSet, gateway, backupApply12583{step: "apply 4", link: "fxp0"})
}
