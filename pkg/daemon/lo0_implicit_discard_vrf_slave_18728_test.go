package daemon

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
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
// (node1 naming: em0 + fab1, an IPVLAN child of ge-7-0-0 as on the lab
// nodes; node0's fab0 is a plain veth), installs the lo0 table through the
// production netlink installer, and pings each address from its own peer
// namespace, sourced from the peer's own address:
//
//   - em0 and fab1 are VRF slaves and must stay reachable (exempt);
//   - fxp0 is a slave of the SAME VRF and must be dropped (not exempt), so
//     a fix that exempts the VRF master would fail here;
//   - ge-0-0-1 is an ordinary non-VRF port and must be dropped (control
//     that the implicit discard is installed at all).
//
// It also checks locally generated traffic: IPv4 the box sends to its own
// fxp0 address inside vrf-mgmt (iifname = sdifname = vrf-mgmt) and traffic in
// the default table (iifname lo) are exempt. IPv6 VRF-local traffic is NOT
// exempt, because it is indistinguishable from fxp0 ingress; the property
// that forbids exempting it is asserted directly: an IPv6 packet injected on
// fxp0 with the box's OWN address as source must not get past the lo0 table
// (a prerouting counter in the same run proves it arrived).
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
		// ipvlanParent, when set, makes dev an IPVLAN (l2) child of a veth
		// named ipvlanParent whose peer end is peerDev: the lab's fabric
		// shape, where the IPVLAN child is the VRF slave (and so the sdif).
		ipvlanParent string
	}
	// One topology carries both nodes' role netdevs, so a node0 or a node1
	// config is checked against the same kernel (#18728 incident: node1
	// naming, em0 and fab1 as vrf-mgmt slaves).
	links := map[string]*link{
		"em0":      {dev: "em0", peerDev: "pem0", v4: "10.99.12.2/30", peerV4: "10.99.12.1/30", v6: "fd00:99:12::2/64", peerV6: "fd00:99:12::1/64", vrf: true},
		"fab0":     {dev: "fab0", peerDev: "pfab0", v4: "10.99.13.6/30", peerV4: "10.99.13.5/30", v6: "fd00:99:13::6/64", peerV6: "fd00:99:13::5/64", vrf: true},
		"fab1":     {dev: "fab1", peerDev: "pfab1", v4: "10.99.13.2/30", peerV4: "10.99.13.1/30", v6: "fd00:99:13:1::2/64", peerV6: "fd00:99:13:1::1/64", vrf: true, ipvlanParent: "ge-7-0-0"},
		"fxp0":     {dev: "fxp0", peerDev: "pfxp", v4: "10.136.126.134/24", peerV4: "10.136.126.113/24", v6: "fd00:136::134/64", peerV6: "fd00:136::113/64", vrf: true},
		"ge-0-0-1": {dev: "ge-0-0-1", peerDev: "pdata", v4: "10.0.61.1/24", peerV4: "10.0.61.100/24", v6: "fd00:61::1/64", peerV6: "fd00:61::100/64", vrf: false},
	}
	for _, l := range links {
		l.pid = peer()
		if l.ipvlanParent != "" {
			run("ip", "link", "add", l.ipvlanParent, "type", "veth", "peer", "name", l.peerDev, "netns", l.pid)
			run("ip", "link", "set", l.ipvlanParent, "up")
			run("ip", "link", "add", "link", l.ipvlanParent, "name", l.dev, "type", "ipvlan", "mode", "l2")
		} else {
			run("ip", "link", "add", l.dev, "type", "veth", "peer", "name", l.peerDev, "netns", l.pid)
		}
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
	// Pin IPv6 neighbors both ways on the NOT-exempt ports (fxp0 and
	// ge-0-0-1). The implicit drop discards neighbor discovery there (an NA
	// reaches the input hook with the INGRESS device as iifname, sdif 0: the
	// VRF code keeps the ingress device for NDISC), so with dynamic ND those
	// IPv6 rows would measure ND, not the echo verdict. That made the fxp0
	// IPv6 "NOT exempt" row read unreachable even under a mutant that
	// accepts all IPv6 with iifname vrf-mgmt (#18755 review seat AE). The
	// exempt ports (em0, fab0, fab1) keep dynamic ND on purpose: their IPv6
	// rows also prove that ND on a VRF slave, which matches the exemption
	// by iifname rather than sdifname, gets through.
	peerMAC := func(l *link) string {
		t.Helper()
		out, err := exec.Command("nsenter", "-t", l.pid, "-n", "ip", "-o", "link", "show", l.peerDev).CombinedOutput()
		f := strings.Fields(string(out))
		for i := range f {
			if f[i] == "link/ether" && i+1 < len(f) {
				return f[i+1]
			}
		}
		t.Fatalf("peer MAC of %s: %v: %s", l.peerDev, err, out)
		return ""
	}
	for _, name := range []string{"fxp0", "ge-0-0-1"} {
		l := links[name]
		ifc, err := net.InterfaceByName(l.dev)
		if err != nil {
			t.Fatalf("%s: %v", l.dev, err)
		}
		run("ip", "-6", "neigh", "replace", addrOf(l.peerV6), "lladdr", peerMAC(l), "dev", l.dev, "nud", "permanent")
		run("nsenter", "-t", l.pid, "-n", "ip", "-6", "neigh", "replace", addrOf(l.v6),
			"lladdr", ifc.HardwareAddr.String(), "dev", l.peerDev, "nud", "permanent")
	}
	// Spoof fixture: a second own address on fxp0 that the fxp0 peer also
	// holds, so the peer can send a packet whose SOURCE is one of the box's
	// own IPv6 addresses to the box's fxp0 address. The peer resolves the
	// target with a static neighbor (an NA from the box would be addressed
	// to its own address and never leave it).
	fxp := links["fxp0"]
	const spoofSrc6 = "fd00:136::135"
	run("ip", "-6", "addr", "add", spoofSrc6+"/64", "dev", "fxp0", "nodad")
	run("nsenter", "-t", fxp.pid, "-n", "ip", "-6", "addr", "add", spoofSrc6+"/128", "dev", fxp.peerDev, "nodad")
	fxpIf, err := net.InterfaceByName("fxp0")
	if err != nil {
		t.Fatalf("fxp0: %v", err)
	}
	run("nsenter", "-t", fxp.pid, "-n", "ip", "-6", "neigh", "replace", addrOf(fxp.v6),
		"lladdr", fxpIf.HardwareAddr.String(), "dev", fxp.peerDev, "nud", "permanent")
	// The probe table counts the spoofed echo requests at prerouting (they
	// arrived: the positive control) and at input AFTER xpf_lo0 (priority
	// 100 > the lo0 chain's 0): a packet the lo0 table drops is never seen
	// there.
	probe := func(fresh bool) (pre, in int) {
		t.Helper()
		match := "ip6 saddr " + spoofSrc6 + " ip6 daddr " + addrOf(fxp.v6) + " icmpv6 type echo-request"
		if fresh {
			c := exec.Command(findNft(), "-f", "-")
			c.Stdin = strings.NewReader("add table inet xpfprobe18728\ndelete table inet xpfprobe18728\n" +
				"table inet xpfprobe18728 {\n" +
				"  chain pre { type filter hook prerouting priority -300; policy accept; " + match + " counter comment \"pre\"; }\n" +
				"  chain in { type filter hook input priority 100; policy accept; " + match + " counter comment \"in\"; }\n}\n")
			if out, err := c.CombinedOutput(); err != nil {
				t.Fatalf("install probe table: %v: %s", err, out)
			}
			return 0, 0
		}
		out, err := exec.Command(findNft(), "list", "table", "inet", "xpfprobe18728").CombinedOutput()
		if err != nil {
			t.Fatalf("list probe table: %v: %s", err, out)
		}
		pre, in = -1, -1
		for _, m := range regexp.MustCompile(`counter packets (\d+) bytes \d+ comment "(pre|in)"`).FindAllStringSubmatch(string(out), -1) {
			n, _ := strconv.Atoi(m[1])
			if m[2] == "pre" {
				pre = n
			} else {
				in = n
			}
		}
		if pre < 0 || in < 0 {
			t.Fatalf("probe counters not found:\n%s", out)
		}
		return pre, in
	}
	// ping reaches one of this namespace's addresses from the link's peer,
	// SOURCED from the peer's own address. Without -I the fxp0 peer would
	// pick the spoof fixture's /128 below (longest matching prefix), the
	// reply would be addressed to one of the box's own addresses, and the
	// IPv6 fxp0 row would read unreachable whatever the lo0 table did.
	ping := func(l *link, v6 bool) bool {
		args := []string{"-t", l.pid, "-n", "ping", "-c", "2", "-W", "1", "-I", addrOf(l.peerV4)}
		addr := addrOf(l.v4)
		if v6 {
			args = []string{"-t", l.pid, "-n", "ping", "-6", "-c", "2", "-W", "1", "-I", addrOf(l.peerV6)}
			addr = addrOf(l.v6)
		}
		return exec.Command("nsenter", append(args, addr)...).Run() == nil
	}
	// localPing pings one of this namespace's own addresses from inside the
	// namespace: bound to the VRF device (`ping -I vrf-mgmt`; `ip vrf exec`
	// needs cgroup BPF that a user namespace lacks) or in the default table.
	localPing := func(addr string, v6, inVRF bool) bool {
		args := []string{"-c", "2", "-W", "1"}
		if v6 {
			args = append(args, "-6")
		}
		if inVRF {
			args = append(args, "-I", "vrf-mgmt")
		}
		return exec.Command("ping", append(args, addr)...).Run() == nil
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
		// Locally generated traffic: IPv4 inside vrf-mgmt to the box's own
		// fxp0 address (iifname = sdifname = vrf-mgmt) is exempt, the VRF
		// analogue of `lo`; in the default table to the data port's address
		// (iifname lo) both families are exempt. The fxp0-RECEIVED rows above
		// stay dropped (sdifname fxp0), so the IPv4 exemption is keyed on
		// sdifname.
		for _, c := range []struct {
			name, addr string
			v6, inVRF  bool
		}{
			{"local in vrf-mgmt to own fxp0", addrOf(links["fxp0"].v4), false, true},
			{"local in default table to own ge-0-0-1", addrOf(links["ge-0-0-1"].v4), false, false},
			{"local in default table to own ge-0-0-1", addrOf(links["ge-0-0-1"].v6), true, false},
		} {
			if !localPing(c.addr, c.v6, c.inVRF) {
				t.Errorf("%s %s v6=%v: locally generated traffic was dropped (must be exempt)", node.name, c.name, c.v6)
				failed = true
			}
		}
		// IPv6 inside vrf-mgmt to the box's own fxp0 address is not exempt
		// (its sdifname is fxp0, the same as fxp0 ingress). Observed, not
		// asserted: a future discriminator that exempts it safely must not
		// fail this cell. The property that matters is the spoof row below.
		t.Logf("%s local in vrf-mgmt to own fxp0 v6: reachable=%v (not exempt by design; see config.Lo0ImplicitDiscardVRFMasters)",
			node.name, localPing(addrOf(fxp.v6), true, true))
		probe(true)
		_ = exec.Command("nsenter", "-t", fxp.pid, "-n", "ping", "-6", "-c", "3", "-i", "0.2", "-W", "1",
			"-I", spoofSrc6, addrOf(fxp.v6)).Run()
		pre, in := probe(false)
		t.Logf("%s own-source IPv6 injected on fxp0: prerouting=%d input-after-lo0=%d", node.name, pre, in)
		if pre < 3 || in != 0 {
			t.Errorf("%s own-source IPv6 injected on fxp0: prerouting=%d (want >= 3: it arrived) input-after-lo0=%d (want 0: the implicit discard must drop it)",
				node.name, pre, in)
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
