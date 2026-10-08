package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

const riMemberSecureTunnelNetnsChild12087 = "XPF_12087_ST0_NETNS_CHILD"

// #12087: create the same xfrmi name the authored bind-interface creates,
// apply an RI list binding once, and inspect the kernel's real MasterIndex.
// The second read uses the same ownership map consumed by stale-member
// cleanup: the correctly-bound xfrmi must not be queued for unbind.
func TestRIMemberSecureTunnelUnitBindsToVRF12087(t *testing.T) {
	if os.Getenv(riMemberSecureTunnelNetnsChild12087) == "1" {
		runRIMemberSecureTunnelUnitNetnsChild12087(t)
		return
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skipf("cannot run the isolated MasterIndex cell: unshare not found: %v", err)
	}
	cmd := exec.Command(unshare, "-rn", os.Args[0], "-test.run", "^TestRIMemberSecureTunnelUnitBindsToVRF12087$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), riMemberSecureTunnelNetnsChild12087+"=1")
	out, err := cmd.CombinedOutput()
	if !strings.Contains(string(out), "NETNS-CHILD-STARTED-12087") {
		if os.Getenv("XPF_REQUIRE_NETNS") == "" {
			t.Skipf("cannot create an isolated network namespace (%v): %s", err, out)
		}
		t.Fatalf("netns child never started (%v): %s", err, out)
	}
	if err != nil || !strings.Contains(string(out), "NETNS-CHILD-PASSED-12087") {
		t.Fatalf("real-kernel #12087 MasterIndex cell failed (%v):\n%s", err, out)
	}
}

func runRIMemberSecureTunnelUnitNetnsChild12087(t *testing.T) {
	fmt.Println("NETNS-CHILD-STARTED-12087")
	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-blue"}, Table: 12087}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Fatalf("create vrf-blue in private netns: %v", err)
	}
	if err := netlink.LinkSetUp(vrf); err != nil {
		t.Fatalf("bring vrf-blue up: %v", err)
	}
	vrfLink, err := netlink.LinkByName("vrf-blue")
	if err != nil {
		t.Fatalf("read vrf-blue: %v", err)
	}

	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn0": {Name: "vpn0", BindInterface: "st0.0"},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "blue", InstanceType: "vrf", TableID: 12087,
		Interfaces: []string{"st0.0"},
	}}
	rt, err := routing.New()
	if err != nil {
		t.Fatalf("routing.New: %v", err)
	}
	defer func() { _ = rt.Close() }()
	if err := rt.ApplyXfrmi(cfg.Security.IPsec.VPNs); err != nil {
		t.Fatalf("create xfrmi from authored bind-interface: %v", err)
	}
	d := &Daemon{routing: rt, linkByNameFn: netlink.LinkByName}
	d.bindRoutingInstanceMembers(cfg)

	xfrmi, err := netlink.LinkByName("st0.0")
	if err != nil {
		t.Fatalf("xfrmi st0.0 absent: %v", err)
	}
	if got, want := xfrmi.Attrs().MasterIndex, vrfLink.Attrs().Index; got != want {
		t.Fatalf("#12087: st0.0 master index = %d, want vrf-blue (%d); the member resolver must bind the netdev created under the authored bind-interface spelling",
			got, want)
	}

	for _, member := range d.riMembersOutsideTheirVRF(cfg) {
		if member.unbind && member.linuxName == "st0.0" {
			t.Fatalf("#12087: stale-member cleanup queued %s for unbind from %s despite current RI ownership",
				member.linuxName, member.instance)
		}
	}
	d.rebindRIMembersOutsideTheirVRF(cfg)
	xfrmi, err = netlink.LinkByName("st0.0")
	if err != nil {
		t.Fatalf("xfrmi st0.0 absent after stale-member cleanup: %v", err)
	}
	if got, want := xfrmi.Attrs().MasterIndex, vrfLink.Attrs().Index; got != want {
		t.Fatalf("#12087: stale-member cleanup changed st0.0 master index to %d, want vrf-blue (%d)",
			got, want)
	}
	fmt.Println("NETNS-CHILD-PASSED-12087")
}
