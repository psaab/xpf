package daemon

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/vipstamp"
)

// #18573 real-kernel cells. They SKIP without a private netns (run under
// `unshare -rn`); test/daemon/selftest-daemon-kernel_15241.sh forces them.
// The fake-table cells in direct_vip_reconcile_18573_test.go cannot see the
// two kernel facts the fix rests on: that the kernel keeps IFA_PROTO on the
// address and reports it in a dump (so the stamp IS the ownership record),
// and that NLM_F_REPLACE rewrites it in place on both families (adoption).

func kernelLink18573(t *testing.T, name string) netlink.Link {
	t.Helper()
	enterPrivateNetns9813(t)
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		if os.Getenv("XPF_REQUIRE_NETNS") != "" {
			t.Fatalf("cannot create dummy %s in this netns: %v (XPF_REQUIRE_NETNS is set)", name, err)
		}
		t.Skipf("cannot create dummy %s in this netns: %v", name, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("lookup %s: %v", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("up %s: %v", name, err)
	}
	return link
}

// kernelRows18573 dumps the kernel through the production decoder and keys
// the rows on ifindex by prefix.
func kernelRows18573(t *testing.T, ifindex int) map[netip.Prefix]vipstamp.Row {
	t.Helper()
	rows, err := vipstamp.Dump()
	if err != nil {
		t.Fatalf("vipstamp.Dump: %v", err)
	}
	out := make(map[netip.Prefix]vipstamp.Row)
	for _, r := range rows {
		if r.LinkIndex == ifindex {
			out[r.Prefix] = r
		}
	}
	return out
}

func addForeign18573(t *testing.T, link netlink.Link, cidr string) {
	t.Helper()
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatal(err)
	}
	if addr.IP.To4() == nil {
		addr.Flags = unix.IFA_F_NODAD
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatalf("foreign AddrAdd %s: %v", cidr, err)
	}
}

func TestDirectVIPStampRoundTripsThroughTheKernel18573(t *testing.T) {
	link := kernelLink18573(t, "ge-0-0-2.50")
	idx := link.Attrs().Index
	v4 := netip.MustParsePrefix("172.16.50.42/24")
	v6 := netip.MustParsePrefix("2001:db8:50::42/64")
	for _, p := range []netip.Prefix{v4, v6} {
		if err := vipstamp.Add(idx, p, false); err != nil {
			t.Fatalf("stamped add %s: %v", p, err)
		}
		if err := vipstamp.Add(idx, p, false); err == nil {
			t.Fatalf("exclusive re-add of %s must fail EEXIST like netlink.AddrAdd", p)
		}
	}
	addForeign18573(t, link, "172.16.50.10/24")
	addForeign18573(t, link, "2001:db8:50::10/64")

	rows := kernelRows18573(t, idx)
	for _, p := range []netip.Prefix{v4, v6} {
		if r, ok := rows[p]; !ok || !r.Stamped() {
			t.Fatalf("%s: kernel row %+v ok=%v, want stamped (all rows %v)", p, r, ok, rows)
		}
	}
	for _, s := range []string{"172.16.50.10/24", "2001:db8:50::10/64"} {
		if r, ok := rows[netip.MustParsePrefix(s)]; !ok || r.Stamped() {
			t.Fatalf("%s (library AddrAdd): row %+v ok=%v, want present and unstamped", s, r, ok)
		}
	}
	// The kernel's own link-local carries IFAPROT_KERNEL_LL, never the stamp.
	for p, r := range rows {
		if p.Addr().IsLinkLocalUnicast() && r.Stamped() {
			t.Fatalf("kernel link-local %s reads as stamped", p)
		}
	}

	// Adoption: REPLACE rewrites the proto in place, both families.
	for _, s := range []string{"172.16.50.10/24", "2001:db8:50::10/64"} {
		if err := vipstamp.Add(idx, netip.MustParsePrefix(s), true); err != nil {
			t.Fatalf("adopt %s: %v", s, err)
		}
	}
	rows = kernelRows18573(t, idx)
	for _, s := range []string{"172.16.50.10/24", "2001:db8:50::10/64"} {
		if r := rows[netip.MustParsePrefix(s)]; !r.Stamped() {
			t.Fatalf("%s after REPLACE: %+v, want stamped", s, r)
		}
	}
	for _, p := range []netip.Prefix{v4, v6} {
		if err := vipstamp.Del(rows[p]); err != nil {
			t.Fatalf("Del %s: %v", p, err)
		}
		if err := vipstamp.Del(rows[p]); err == nil || !vipstamp.GoneErr(err) {
			t.Fatalf("second Del %s: %v, want a GoneErr", p, err)
		}
	}
	rows = kernelRows18573(t, idx)
	if _, ok := rows[v4]; ok {
		t.Fatalf("v4 survived Del: %v", rows)
	}
	if _, ok := rows[v6]; ok {
		t.Fatalf("v6 survived Del: %v", rows)
	}
}

// The issue's reproduction end to end on a real kernel: the owner installs
// .10 / ::10, a commit renumbers to .42 / ::42; the commit's userspace
// snapshot (built while the old address is still on the netdev) must offer
// only .42 as the interface-SNAT source; the owner's reconcile then deletes
// the old pair and leaves the foreign address; demotion removes the new pair.
func TestDirectVIPRenumberOnKernel18573(t *testing.T) {
	link := kernelLink18573(t, "ge-0-0-2.50")
	idx := link.Attrs().Index
	d := &Daemon{store: rethStore18573(t, "172.16.50.10/24", "2001:db8:50::10/64")}
	if added := d.directAddVIPs(1); added != 2 {
		t.Fatalf("first owner pass added %d, want 2", added)
	}
	addForeign18573(t, link, "172.16.50.99/24")

	d.store = rethStore18573(t, "172.16.50.42/24", "2001:db8:50::42/64")

	// The commit's snapshot, built before the reconcile has run: the kernel
	// holds .10, .42 is not even installed yet.
	var unit *dpuserspace.InterfaceSnapshot
	rowsSnap := dpuserspace.BuildInterfaceSnapshots(d.store.ActiveConfig())
	for i := range rowsSnap {
		if rowsSnap[i].Name == "reth0.50" {
			unit = &rowsSnap[i]
		}
	}
	if unit == nil {
		t.Fatalf("no reth0.50 row in %d rows", len(rowsSnap))
	}
	if unit.Ifindex != idx {
		t.Fatalf("reth0.50 row ifindex %d, want the netns link %d", unit.Ifindex, idx)
	}
	var first net.IP
	for _, a := range unit.Addresses {
		if a.Address == "172.16.50.10/24" || a.Address == "2001:db8:50::10/64" {
			t.Fatalf("the commit's snapshot publishes the renumbered-away %s: %v", a.Address, unit.Addresses)
		}
		if ip, _, err := net.ParseCIDR(a.Address); err == nil && first == nil && ip.To4() != nil && !ip.IsLinkLocalUnicast() {
			first = ip
		}
	}
	if !first.Equal(net.ParseIP("172.16.50.42")) {
		t.Fatalf("interface-SNAT source candidate = %v, want 172.16.50.42 (row %v)", first, unit.Addresses)
	}

	if added := d.directAddVIPs(1); added != 2 {
		t.Fatalf("post-commit owner pass added %d, want 2", added)
	}
	rows := kernelRows18573(t, idx)
	for _, s := range []string{"172.16.50.10/24", "2001:db8:50::10/64"} {
		if _, ok := rows[netip.MustParsePrefix(s)]; ok {
			t.Fatalf("renumbered-away %s still on the owner: %v", s, rows)
		}
	}
	for _, s := range []string{"172.16.50.42/24", "2001:db8:50::42/64"} {
		if r, ok := rows[netip.MustParsePrefix(s)]; !ok || !r.Stamped() {
			t.Fatalf("%s: %+v ok=%v, want installed and stamped", s, r, ok)
		}
	}
	if r, ok := rows[netip.MustParsePrefix("172.16.50.99/24")]; !ok || r.Stamped() {
		t.Fatalf("foreign 172.16.50.99/24 touched: %+v ok=%v", r, ok)
	}

	if removed := d.directRemoveVIPs(1); removed != 2 {
		t.Fatalf("demotion removed %d, want 2", removed)
	}
	rows = kernelRows18573(t, idx)
	for p, r := range rows {
		if r.Stamped() {
			t.Fatalf("demoted node keeps stamped %s", p)
		}
	}
	if _, ok := rows[netip.MustParsePrefix("172.16.50.99/24")]; !ok {
		t.Fatal("demotion removed the foreign address")
	}
}
