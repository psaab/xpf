package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #18728 incident (loss gate, 2026-11-01): the lo0 implicit discard on node1
// dropped the cluster control link and the fabric. On the lab nodes em0 and
// the fabric IPVLAN are enslaved to the `vrf-mgmt` l3mdev, and for a VRF
// slave the input hook's iifname is the VRF MASTER (`vrf-mgmt`); the slave is
// only visible as sdifname. An iifname-only exemption therefore never matched
// them. This cell reproduces that shape on a real kernel in a private netns
// (node1 naming: em0 + fab1 over ge-7/0/0), installs the lo0 table through
// the production netlink installer, and pings each address from its own
// peer namespace:
//
//   - em0 and fab1 are VRF slaves and must stay reachable (exempt);
//   - fxp0 is a slave of the SAME VRF and must be dropped (not exempt), so
//     a fix that exempts the VRF master would fail here;
//   - ge-0-0-1 is an ordinary non-VRF port and must be dropped (control
//     that the implicit discard is installed at all).
const lo0VRFSlaveChild18728 = "XPF_LO0_VRF_SLAVE_CHILD_18728"

func TestLo0ImplicitDiscardExemptsVRFSlavesOnRealKernel18728(t *testing.T) {
	if os.Getenv(lo0VRFSlaveChild18728) == "1" {
		lo0VRFSlaveChild18728Body(t)
		return
	}
	if findNft() == "" {
		if os.Getenv("XPF_REQUIRE_NETNS") != "" {
			t.Fatalf("nft not found (XPF_REQUIRE_NETNS is set)")
		}
		t.Skip("nft not found")
	}
	for _, tool := range []string{"unshare", "ip", "nsenter", "ping", "sleep"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("XPF_REQUIRE_NETNS") != "" {
				t.Fatalf("%s not available (XPF_REQUIRE_NETNS is set)", tool)
			}
			t.Skipf("%s not available", tool)
		}
	}
	cmd := exec.Command("unshare", "-rn", os.Args[0], "-test.run",
		"^TestLo0ImplicitDiscardExemptsVRFSlavesOnRealKernel18728$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), lo0VRFSlaveChild18728+"=1")
	out, err := cmd.CombinedOutput()
	if !strings.Contains(string(out), "NETNS-CHILD-STARTED-18728") {
		if os.Getenv("XPF_REQUIRE_NETNS") == "" {
			t.Skipf("netns unavailable (%v): %s", err, out)
		}
		t.Fatalf("netns child never started (%v): %s", err, out)
	}
	if err != nil || !strings.Contains(string(out), "NETNS-CHILD-PASSED-18728") {
		t.Fatalf("real-kernel cell failed inside namespace (%v):\n%s", err, out)
	}
}

func lo0VRFSlaveChild18728Body(t *testing.T) {
	fmt.Println("NETNS-CHILD-STARTED-18728")
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, out)
		}
	}
	selfNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("read own netns: %v", err)
	}
	peer := func() string {
		t.Helper()
		c := exec.Command("unshare", "-n", "sleep", "300")
		if err := c.Start(); err != nil {
			t.Fatalf("start peer namespace: %v", err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
		pid := strconv.Itoa(c.Process.Pid)
		for range 300 {
			if ns, err := os.Readlink("/proc/" + pid + "/ns/net"); err == nil && ns != selfNS {
				return pid
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("peer %s never entered its own network namespace", pid)
		return ""
	}
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "vrf-mgmt", "type", "vrf", "table", "999")
	run("ip", "link", "set", "vrf-mgmt", "up")
	type link struct {
		dev, peerDev, v4, peerV4, v6, peerV6 string
		vrf                                  bool
		pid                                  string
	}
	// One topology carries both nodes' role netdevs, so a node0 or a node1
	// config is checked against the same kernel (#18728 incident: node1
	// naming, em0 and fab1 as vrf-mgmt slaves).
	links := map[string]*link{
		"em0":      {dev: "em0", peerDev: "pem0", v4: "10.99.12.2/30", peerV4: "10.99.12.1/30", v6: "fd00:99:12::2/64", peerV6: "fd00:99:12::1/64", vrf: true},
		"fab0":     {dev: "fab0", peerDev: "pfab0", v4: "10.99.13.6/30", peerV4: "10.99.13.5/30", v6: "fd00:99:13::6/64", peerV6: "fd00:99:13::5/64", vrf: true},
		"fab1":     {dev: "fab1", peerDev: "pfab1", v4: "10.99.13.2/30", peerV4: "10.99.13.1/30", v6: "fd00:99:13:1::2/64", peerV6: "fd00:99:13:1::1/64", vrf: true},
		"fxp0":     {dev: "fxp0", peerDev: "pfxp", v4: "10.136.126.134/24", peerV4: "10.136.126.113/24", v6: "fd00:136::134/64", peerV6: "fd00:136::113/64", vrf: true},
		"ge-0-0-1": {dev: "ge-0-0-1", peerDev: "pdata", v4: "10.0.61.1/24", peerV4: "10.0.61.100/24", v6: "fd00:61::1/64", peerV6: "fd00:61::100/64", vrf: false},
	}
	for _, l := range links {
		l.pid = peer()
		run("ip", "link", "add", l.dev, "type", "veth", "peer", "name", l.peerDev, "netns", l.pid)
		if l.vrf {
			run("ip", "link", "set", l.dev, "master", "vrf-mgmt")
		}
		run("ip", "addr", "add", l.v4, "dev", l.dev)
		run("ip", "-6", "addr", "add", l.v6, "dev", l.dev, "nodad")
		run("ip", "link", "set", l.dev, "up")
		for _, args := range [][]string{
			{"link", "set", "lo", "up"},
			{"addr", "add", l.peerV4, "dev", l.peerDev},
			{"-6", "addr", "add", l.peerV6, "dev", l.peerDev, "nodad"},
			{"link", "set", l.peerDev, "up"},
		} {
			run("nsenter", append([]string{"-t", l.pid, "-n", "ip"}, args...)...)
		}
	}
	addrOf := func(cidr string) string { return strings.Split(cidr, "/")[0] }
	ping := func(l *link, v6 bool) bool {
		args := []string{"-t", l.pid, "-n", "ping", "-c", "2", "-W", "1"}
		addr := addrOf(l.v4)
		if v6 {
			args = append(args, "-6")
			addr = addrOf(l.v6)
		}
		return exec.Command("nsenter", append(args, addr)...).Run() == nil
	}
	nodeCfg := func(fabric, member string) *config.Config {
		cfg := &config.Config{}
		cfg.System.Lo0FilterInputV4 = "protect-re"
		cfg.System.Lo0FilterInputV6 = "protect-re6"
		cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{"protect-re": {Name: "protect-re"}}
		cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{"protect-re6": {Name: "protect-re6"}}
		cfg.Chassis.Cluster = &config.ClusterConfig{ControlInterface: "em0"}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"em0":  {Name: "em0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: []string{"10.99.12.2/30"}}}},
			fabric: {Name: fabric, FabricMembers: []string{member}},
			"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true}}},
		}
		return cfg
	}
	failed := false
	for _, node := range []struct {
		name, fabric, member string
	}{
		{"node0", "fab0", "ge-0/0/0"},
		{"node1", "fab1", "ge-7/0/0"},
	} {
		spec := toNftLo0Spec(nodeCfg(node.fabric, node.member), "protect-re", "protect-re6")
		if !spec.ImplicitDiscardV4 || !spec.ImplicitDiscardV6 {
			t.Fatalf("%s fixture: both empty lo0 filters must carry the implicit discard: %+v", node.name, spec)
		}
		if _, err := xnft.NewNetlinkInstaller().InstallLo0(spec); err != nil {
			t.Fatalf("%s InstallLo0: %v", node.name, err)
		}
		for _, c := range []struct {
			dev  string
			want bool
			why  string
		}{
			{"em0", true, "VRF-slave control link, exempt"},
			{node.fabric, true, "VRF-slave local fabric, exempt"},
			{"fxp0", false, "slave of the same VRF, NOT exempt"},
			{"ge-0-0-1", false, "non-VRF data port, NOT exempt"},
		} {
			for _, v6 := range []bool{false, true} {
				if got := ping(links[c.dev], v6); got != c.want {
					t.Errorf("%s %s v6=%v (%s): reachable=%v want %v", node.name, c.dev, v6, c.why, got, c.want)
					failed = true
				}
			}
		}
	}
	if failed {
		out, _ := exec.Command(findNft(), "list", "table", "inet", xnft.Lo0TableName).CombinedOutput()
		t.Logf("table:\n%s", out)
		return
	}
	fmt.Println("NETNS-CHILD-PASSED-18728")
}
