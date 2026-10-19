package daemon

import (
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func mgmtStaticSetLines12539(rib, destination string, preference int, gateways ...string) []string {
	prefix := "set routing-options static route " + destination
	if rib != "" {
		prefix = "set routing-options rib " + rib + " static route " + destination
	}
	var lines []string
	for _, gateway := range gateways {
		lines = append(lines, prefix+" next-hop "+gateway+" interface fxp0")
	}
	if preference > 0 {
		lines = append(lines, fmt.Sprintf("%s preference %d", prefix, preference))
	}
	return lines
}

// F2/F4 of #12539 on a real kernel (SKIPs without CAP_NET_ADMIN, like the other
// table-999 kernel cells). An ECMP management static with 2+ resolved gateways
// installs in both families, follows every leg, preference and destination
// change without leaving an orphan that keeps forwarding, and is reaped on
// removal. The same-slot steps (single->ECMP, leg removal, ECMP->single) pin
// the replaced-slot rule: the kernel matches a stale delete against the
// replacement (IPv4 single-path requests against the first leg, multipath
// requests leg by leg over the installed legs; IPv6 deletes each matching leg),
// so the reconcile must not issue it. Operator ECMP routes survive every step,
// and re-applying each step's config changes nothing (kernel read-back matches
// the desired key).
func TestMgmtStaticECMPLifecycleInKernel12539(t *testing.T) {
	enterPrivateNetns9813(t)
	fxp0 := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fxp0"}}
	if err := netlink.LinkAdd(fxp0); err != nil {
		t.Skipf("cannot create dummy fxp0 in private netns: %v", err)
	}
	if err := netlink.LinkSetUp(fxp0); err != nil {
		t.Fatalf("bring fxp0 up: %v", err)
	}
	for _, cidr := range []string{"192.0.2.2/24", "2001:db8:ffff::2/64"} {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatalf("ParseAddr(%q): %v", cidr, err)
		}
		addr.Flags = unix.IFA_F_NODAD
		if err := netlink.AddrAdd(fxp0, addr); err != nil {
			t.Fatalf("add fxp0 address %s: %v", cidr, err)
		}
	}
	nlh, err := netlink.NewHandle()
	if err != nil {
		t.Fatalf("netlink.NewHandle: %v", err)
	}
	t.Cleanup(nlh.Close)
	link, err := nlh.LinkByName("fxp0")
	if err != nil {
		t.Fatalf("lookup fxp0: %v", err)
	}

	for _, operator := range []struct {
		family   int
		dst      string
		gateways []string
	}{
		{netlink.FAMILY_V4, "203.0.113.0/24", []string{"192.0.2.1", "192.0.2.3"}},
		{netlink.FAMILY_V6, "2001:db8:99::/48", []string{"2001:db8:ffff::1", "2001:db8:ffff::3"}},
	} {
		route := &netlink.Route{
			Family:   operator.family,
			Dst:      mustRoute11449(t, operator.dst),
			Table:    mgmtVRFTableID,
			Type:     unix.RTN_UNICAST,
			Protocol: unix.RTPROT_STATIC,
			Priority: 5,
		}
		for _, gateway := range operator.gateways {
			route.MultiPath = append(route.MultiPath,
				&netlink.NexthopInfo{LinkIndex: link.Attrs().Index, Gw: net.ParseIP(gateway)})
		}
		if err := nlh.RouteAdd(route); err != nil {
			t.Fatalf("install operator ECMP %s: %v", operator.dst, err)
		}
	}
	operators := []string{
		"203.0.113.0/24 prio=5 proto=4 realm=0x0 via=192.0.2.1,192.0.2.3",
		"2001:db8:99::/48 prio=5 proto=4 realm=0x0 via=2001:db8:ffff::1,2001:db8:ffff::3",
	}

	const (
		v4a, v4b, v4c = "192.0.2.1", "192.0.2.3", "192.0.2.4"
		v6a, v6b, v6c = "2001:db8:ffff::1", "2001:db8:ffff::3", "2001:db8:ffff::4"
	)
	steps := []struct {
		name  string
		lines []string
		want  []string
	}{
		{
			name: "single-path",
			lines: append(mgmtStaticSetLines12539("", "198.51.100.0/24", 0, v4a),
				mgmtStaticSetLines12539("inet6.0", "2001:db8:70::/48", 0, v6a)...),
			want: []string{
				"198.51.100.0/24 prio=5 proto=88 realm=0x585046 via=192.0.2.1",
				"2001:db8:70::/48 prio=5 proto=88 realm=0x0 via=2001:db8:ffff::1",
			},
		},
		{
			name: "single-path to three-leg ECMP in the same slot",
			lines: append(mgmtStaticSetLines12539("", "198.51.100.0/24", 0, v4a, v4b, v4c),
				mgmtStaticSetLines12539("inet6.0", "2001:db8:70::/48", 0, v6a, v6b, v6c)...),
			want: []string{
				"198.51.100.0/24 prio=5 proto=88 realm=0x0 via=192.0.2.1,192.0.2.3,192.0.2.4",
				"2001:db8:70::/48 prio=5 proto=88 realm=0x0 via=2001:db8:ffff::1,2001:db8:ffff::3,2001:db8:ffff::4",
			},
		},
		{
			name: "trailing leg removed in the same slot",
			lines: append(mgmtStaticSetLines12539("", "198.51.100.0/24", 0, v4a, v4b),
				mgmtStaticSetLines12539("inet6.0", "2001:db8:70::/48", 0, v6a, v6b)...),
			want: []string{
				"198.51.100.0/24 prio=5 proto=88 realm=0x0 via=192.0.2.1,192.0.2.3",
				"2001:db8:70::/48 prio=5 proto=88 realm=0x0 via=2001:db8:ffff::1,2001:db8:ffff::3",
			},
		},
		{
			name: "preference change moves the priority",
			lines: append(mgmtStaticSetLines12539("", "198.51.100.0/24", 7, v4a, v4b),
				mgmtStaticSetLines12539("inet6.0", "2001:db8:70::/48", 7, v6a, v6b)...),
			want: []string{
				"198.51.100.0/24 prio=7 proto=88 realm=0x0 via=192.0.2.1,192.0.2.3",
				"2001:db8:70::/48 prio=7 proto=88 realm=0x0 via=2001:db8:ffff::1,2001:db8:ffff::3",
			},
		},
		{
			name: "destination widened",
			lines: append(mgmtStaticSetLines12539("", "198.51.0.0/16", 7, v4a, v4b),
				mgmtStaticSetLines12539("inet6.0", "2001:db8::/40", 7, v6a, v6b)...),
			want: []string{
				"198.51.0.0/16 prio=7 proto=88 realm=0x0 via=192.0.2.1,192.0.2.3",
				"2001:db8::/40 prio=7 proto=88 realm=0x0 via=2001:db8:ffff::1,2001:db8:ffff::3",
			},
		},
		{
			name: "ECMP to single-path in the same slot",
			lines: append(mgmtStaticSetLines12539("", "198.51.0.0/16", 7, v4a),
				mgmtStaticSetLines12539("inet6.0", "2001:db8::/40", 7, v6a)...),
			want: []string{
				"198.51.0.0/16 prio=7 proto=88 realm=0x585046 via=192.0.2.1",
				"2001:db8::/40 prio=7 proto=88 realm=0x0 via=2001:db8:ffff::1",
			},
		},
		{
			name: "single-path back to ECMP in the same slot",
			lines: append(mgmtStaticSetLines12539("", "198.51.0.0/16", 7, v4a, v4b),
				mgmtStaticSetLines12539("inet6.0", "2001:db8::/40", 7, v6a, v6b)...),
			want: []string{
				"198.51.0.0/16 prio=7 proto=88 realm=0x0 via=192.0.2.1,192.0.2.3",
				"2001:db8::/40 prio=7 proto=88 realm=0x0 via=2001:db8:ffff::1,2001:db8:ffff::3",
			},
		},
		{
			name: "single-path statics removed (#14972 IPv6 reap)",
			lines: append(mgmtStaticSetLines12539("", "198.51.0.0/16", 7, v4a),
				mgmtStaticSetLines12539("inet6.0", "2001:db8::/40", 7, v6a)...),
			want: []string{
				"198.51.0.0/16 prio=7 proto=88 realm=0x585046 via=192.0.2.1",
				"2001:db8::/40 prio=7 proto=88 realm=0x0 via=2001:db8:ffff::1",
			},
		},
		{name: "single-path statics removed (empty config)"},
		{name: "ECMP statics removed"},
	}
	base := []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set interfaces fxp0 unit 0 family inet6 address 2001:db8:ffff::2/64",
	}
	mgmtSet := map[string]bool{"fxp0": true}
	counting := &countingMgmtProgrammer12539{Handle: nlh}
	for i, step := range steps {
		cfg := testStoreWithSetConfig(t, append(append([]string(nil), base...), step.lines...)).ActiveConfig()
		if err := (&Daemon{}).applyMgmtVRFStaticRoutesTo(counting, cfg, mgmtSet); err != nil {
			t.Fatalf("step %d (%s): applyMgmtVRFStaticRoutesTo: %v", i+1, step.name, err)
		}
		var routes []netlink.Route
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			got, err := nlh.RouteListFiltered(family, &netlink.Route{Table: mgmtVRFTableID}, netlink.RT_FILTER_TABLE)
			if err != nil {
				t.Fatalf("step %d (%s): list table 999: %v", i+1, step.name, err)
			}
			routes = append(routes, got...)
		}
		want := renderSorted12539(append(append([]string(nil), operators...), step.want...))
		if got := renderMgmtStatics12539(routes); !reflect.DeepEqual(got, want) {
			t.Fatalf("step %d (%s): table 999 =\n  %s\nwant\n  %s", i+1, step.name,
				strings.Join(got, "\n  "), strings.Join(want, "\n  "))
		}
		// The kernel's read-back form must match the desired key, so an
		// unchanged config reconciles without touching the table.
		counting.replaced, counting.deleted = 0, 0
		if err := (&Daemon{}).applyMgmtVRFStaticRoutesTo(counting, cfg, mgmtSet); err != nil {
			t.Fatalf("step %d (%s): steady-state reconcile: %v", i+1, step.name, err)
		}
		if counting.replaced != 0 || counting.deleted != 0 {
			t.Fatalf("step %d (%s): steady-state reconcile churned: %d replaces, %d deletes",
				i+1, step.name, counting.replaced, counting.deleted)
		}
	}
}

// countingMgmtProgrammer12539 is the real netlink handle with mutation counts.
type countingMgmtProgrammer12539 struct {
	*netlink.Handle
	replaced, deleted int
}

func (c *countingMgmtProgrammer12539) RouteReplace(route *netlink.Route) error {
	c.replaced++
	return c.Handle.RouteReplace(route)
}

func (c *countingMgmtProgrammer12539) RouteDel(route *netlink.Route) error {
	c.deleted++
	return c.Handle.RouteDel(route)
}

func renderSorted12539(lines []string) []string {
	out := append([]string(nil), lines...)
	sort.Strings(out)
	return out
}
