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
		c := exec.Command("unshare", "-n", "sleep", "120")
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
	wire := func(dev, peerDev, addr, peerAddr string, vrf bool) string {
		t.Helper()
		pid := peer()
		run("ip", "link", "add", dev, "type", "veth", "peer", "name", peerDev, "netns", pid)
		if vrf {
			run("ip", "link", "set", dev, "master", "vrf-mgmt")
		}
		run("ip", "addr", "add", addr, "dev", dev)
		run("ip", "link", "set", dev, "up")
		for _, args := range [][]string{
			{"link", "set", "lo", "up"},
			{"addr", "add", peerAddr, "dev", peerDev},
			{"link", "set", peerDev, "up"},
		} {
			run("nsenter", append([]string{"-t", pid, "-n", "ip"}, args...)...)
		}
		return pid
	}
	em0Peer := wire("em0", "pem0", "10.99.12.2/30", "10.99.12.1/30", true)
	fabPeer := wire("fab1", "pfab", "10.99.13.2/30", "10.99.13.1/30", true)
	fxpPeer := wire("fxp0", "pfxp", "10.136.126.134/24", "10.136.126.113/24", true)
	dataPeer := wire("ge-0-0-1", "pdata", "10.0.61.1/24", "10.0.61.100/24", false)

	cfg := &config.Config{}
	cfg.System.Lo0FilterInputV4 = "protect-re"
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{"protect-re": {Name: "protect-re"}}
	cfg.Chassis.Cluster = &config.ClusterConfig{ControlInterface: "em0"}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"em0":  {Name: "em0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: []string{"10.99.12.2/30"}}}},
		"fab1": {Name: "fab1", FabricMembers: []string{"ge-7/0/0"}},
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true}}},
	}
	spec := toNftLo0Spec(cfg, "protect-re", "")
	if !spec.ImplicitDiscardV4 {
		t.Fatalf("fixture: the empty lo0 filter must carry the implicit discard: %+v", spec)
	}
	if _, err := xnft.NewNetlinkInstaller().InstallLo0(spec); err != nil {
		t.Fatalf("InstallLo0: %v", err)
	}
	ping := func(pid, addr string) bool {
		return exec.Command("nsenter", "-t", pid, "-n", "ping", "-c", "2", "-W", "1", addr).Run() == nil
	}
	failed := false
	for _, c := range []struct {
		name, pid, addr string
		want            bool
	}{
		{"em0 (VRF-slave control link, exempt)", em0Peer, "10.99.12.2", true},
		{"fab1 (VRF-slave fabric, exempt)", fabPeer, "10.99.13.2", true},
		{"fxp0 (VRF slave, NOT exempt)", fxpPeer, "10.136.126.134", false},
		{"ge-0-0-1 (no VRF, NOT exempt)", dataPeer, "10.0.61.1", false},
	} {
		got := ping(c.pid, c.addr)
		if got != c.want {
			t.Errorf("%s: reachable=%v want %v", c.name, got, c.want)
			failed = true
		}
	}
	if failed {
		out, _ := exec.Command(findNft(), "list", "table", "inet", xnft.Lo0TableName).CombinedOutput()
		t.Logf("table:\n%s", out)
		return
	}
	fmt.Println("NETNS-CHILD-PASSED-18728")
}
