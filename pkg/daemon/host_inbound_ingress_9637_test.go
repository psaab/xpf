package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// ingressViews9637 is two zones shaped like the loss cluster's lan and wan: lan
// admits ssh and ping, wan admits ping. withIngress selects the #9637 shape,
// where each view is scoped to its own netdev, or the destination-only shape
// that came before it.
func ingressViews9637(withIngress bool) []dpuserspace.ZoneHostInboundView {
	lan := dpuserspace.ZoneHostInboundView{Zone: "lan", SystemServices: []string{"ssh", "ping"}, V4Addrs: []string{"10.0.61.1"}}
	wan := dpuserspace.ZoneHostInboundView{Zone: "wan", SystemServices: []string{"ping"}, V4Addrs: []string{"172.16.80.8"}}
	if withIngress {
		lan.IngressNetdevs = []string{"fwlan"}
		wan.IngressNetdevs = []string{"fwwan"}
	}
	return []dpuserspace.ZoneHostInboundView{lan, wan}
}

// TestHostInboundIngressRulesShape9637 pins the payload shape:
//   - every ingress-zone rule is scoped to its view's netdevs AND to every judged
//     address, the unzoned ones included;
//   - all of them come before the first destination-only rule;
//   - the counter pre-pass declares the counter a family's ingress drop
//     references, even where the view has no address of its own.
func TestHostInboundIngressRulesShape9637(t *testing.T) {
	views := ingressViews9637(true)
	views[1].V6Addrs = []string{"2001:db8:80::8"} // lan has no v6 address of its own
	payload := buildHostInboundFilterPayload(views, []string{"10.0.99.1"}, nil, nil, nil)

	allV4 := nftAddrSet([]string{"10.0.61.1", "172.16.80.8", "10.0.99.1"})
	allV6 := nftAddrSet([]string{"2001:db8:80::8"})
	scope := func(netdev, family, set string) string {
		return "    iifname " + nftIifnameSet([]string{netdev}) + " " + family + " daddr " + set
	}
	var want []string
	for _, m := range hostInboundMatchSet(views[0], "ip") {
		want = append(want, scope("fwlan", "ip", allV4)+" "+m.match+" "+m.action)
	}
	want = append(want,
		scope("fwlan", "ip", allV4)+` counter name "`+xnft.HostInboundDenyCounterName("lan", "ip")+`" drop`,
		scope("fwwan", "ip", allV4)+` counter name "`+xnft.HostInboundDenyCounterName("wan", "ip")+`" drop`,
		scope("fwlan", "ip6", allV6)+` counter name "`+xnft.HostInboundDenyCounterName("lan", "ip6")+`" drop`,
	)
	lines := strings.Split(payload, "\n")
	index := map[string]int{}
	for i, l := range lines {
		if _, dup := index[l]; !dup {
			index[l] = i
		}
	}
	for _, w := range want {
		if _, ok := index[w]; !ok {
			t.Errorf("missing ingress-zone rule:\n%s\npayload:\n%s", w, payload)
		}
	}
	if strings.Contains(payload, scope("fwwan", "ip", allV4)+" tcp dport 22") {
		t.Error("wan's ingress rules must not admit ssh: wan does not list it")
	}
	lastIngress, firstDest := -1, -1
	for i, l := range lines {
		s := strings.TrimSpace(l)
		if strings.HasPrefix(s, "iifname ") {
			lastIngress = i
		}
		if firstDest < 0 && (strings.HasPrefix(s, "ip daddr ") || strings.HasPrefix(s, "ip6 daddr ")) {
			firstDest = i
		}
	}
	if lastIngress < 0 || firstDest < 0 || lastIngress > firstDest {
		t.Errorf("every ingress-zone rule must precede the first destination-only rule (last ingress line %d, first destination line %d)", lastIngress, firstDest)
	}
	if !strings.Contains(payload, "  counter "+xnft.HostInboundDenyCounterName("lan", "ip6")+" {") {
		t.Error("lan's ip6 ingress drop references a counter the table must declare, though lan has no v6 address")
	}
}

// netnsChild9637 marks the re-executed test binary running inside the private
// network namespace.
const netnsChild9637 = "XPF_9637_NETNS_CHILD"

// TestHostInboundIngressZoneVerdictsOnRealKernel9637 is the kernel half. It
// re-executes this test binary in a private user and network namespace, where
// three client namespaces reach a port-22 listener through the ruleset
// buildHostInboundFilterPayload renders:
//   - lan, on netdev fwlan, whose zone admits ssh;
//   - wan, on netdev fwwan, whose zone does not;
//   - x, on netdev fwx, which no view claims.
//
// The destination-only ruleset reproduces both directions of #9637 first. wan
// reaches ssh on lan's address, and lan is refused ssh on wan's address. The
// ingress-scoped ruleset must invert both, and must leave x judged by
// destination address exactly as before. That last property is what makes a
// netdev the scope leaves out safe.
func TestHostInboundIngressZoneVerdictsOnRealKernel9637(t *testing.T) {
	if os.Getenv(netnsChild9637) == "1" {
		hostInboundIngressNetnsChild9637(t)
		return
	}
	if findNft() == "" {
		t.Skip("nft not found")
	}
	for _, tool := range []string{"unshare", "ip", "nsenter", "timeout", "bash", "sleep"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	cmd := exec.Command("unshare", "-rn", os.Args[0],
		"-test.run", "^TestHostInboundIngressZoneVerdictsOnRealKernel9637$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), netnsChild9637+"=1")
	out, err := cmd.CombinedOutput()
	if !strings.Contains(string(out), "NETNS-CHILD-STARTED-9637") {
		if os.Getenv("XPF_REQUIRE_NETNS") == "" {
			t.Skipf("netns unavailable (%v): %s", err, out)
		}
		t.Fatalf("netns child never started (%v): %s", err, out)
	}
	if err != nil || !strings.Contains(string(out), "NETNS-CHILD-PASSED-9637") {
		t.Fatalf("real-kernel cell failed inside the namespace (%v):\n%s", err, out)
	}
}

func hostInboundIngressNetnsChild9637(t *testing.T) {
	fmt.Println("NETNS-CHILD-STARTED-9637")
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
	// A client namespace is held open by a sleeper. The veth peer must not be
	// moved until the sleeper has actually left this namespace, or it would
	// land here.
	client := func() string {
		t.Helper()
		c := exec.Command("unshare", "-n", "sleep", "120")
		if err := c.Start(); err != nil {
			t.Fatalf("start client namespace: %v", err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
		pid := strconv.Itoa(c.Process.Pid)
		for i := 0; i < 300; i++ {
			if ns, err := os.Readlink("/proc/" + pid + "/ns/net"); err == nil && ns != selfNS {
				return pid
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("client %s never entered its own network namespace", pid)
		return ""
	}
	wire := func(fwDev, clDev, fwAddr, clAddr, gw string) string {
		pid := client()
		run("ip", "link", "add", fwDev, "type", "veth", "peer", "name", clDev, "netns", pid)
		run("ip", "addr", "add", fwAddr, "dev", fwDev)
		run("ip", "link", "set", fwDev, "up")
		for _, args := range [][]string{
			{"link", "set", "lo", "up"},
			{"addr", "add", clAddr, "dev", clDev},
			{"link", "set", clDev, "up"},
			{"route", "add", "default", "via", gw},
		} {
			run("nsenter", append([]string{"-t", pid, "-n", "ip"}, args...)...)
		}
		return pid
	}
	run("ip", "link", "set", "lo", "up")
	lan := wire("fwlan", "cllan", "10.0.61.1/24", "10.0.61.100/24", "10.0.61.1")
	wan := wire("fwwan", "clwan", "172.16.80.8/24", "172.16.80.100/24", "172.16.80.8")
	x := wire("fwx", "clx", "192.0.2.1/24", "192.0.2.100/24", "192.0.2.1")

	ln, err := net.Listen("tcp4", "0.0.0.0:22")
	if err != nil {
		t.Fatalf("listen on :22: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	// connect reports what a TCP connect to dst:22 from a client sees. A dropped
	// SYN is a timeout; an admitted one completes against the listener.
	connect := func(pid, dst string) string {
		err := exec.Command("nsenter", "-t", pid, "-n", "timeout", "1", "bash", "-c", "exec 3<>/dev/tcp/"+dst+"/22").Run()
		var ee *exec.ExitError
		switch {
		case err == nil:
			return "connected"
		case errors.As(err, &ee) && ee.ExitCode() == 124:
			return "timeout"
		}
		return "error: " + err.Error()
	}
	load := func(views []dpuserspace.ZoneHostInboundView) {
		t.Helper()
		cmd := exec.Command(findNft(), "-f", "-")
		cmd.Stdin = strings.NewReader(buildHostInboundFilterPayload(views, nil, nil, nil, nil))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft -f: %v: %s", err, out)
		}
	}
	type row struct {
		label, pid, dst, want string
	}
	check := func(phase string, rows []row) {
		t.Helper()
		for _, r := range rows {
			if got := connect(r.pid, r.dst); got != r.want {
				t.Errorf("%s: %s: ssh to %s = %s, want %s", phase, r.label, r.dst, got, r.want)
			}
		}
	}

	load(ingressViews9637(false))
	check("destination-only (before #9637)", []row{
		{"lan client to lan's own address (control)", lan, "10.0.61.1", "connected"},
		{"wan client to wan's own address (control)", wan, "172.16.80.8", "timeout"},
		{"wan client to lan's address: the exposure", wan, "10.0.61.1", "connected"},
		{"lan client to wan's address: the over-refusal", lan, "172.16.80.8", "timeout"},
	})
	if t.Failed() {
		t.Fatal("the destination-only ruleset did not reproduce #9637, so the rows below would not measure the fix")
	}

	load(ingressViews9637(true))
	check("ingress-scoped (#9637)", []row{
		{"lan client to lan's own address", lan, "10.0.61.1", "connected"},
		{"wan client to wan's own address", wan, "172.16.80.8", "timeout"},
		{"wan client to lan's address is judged by wan", wan, "10.0.61.1", "timeout"},
		{"lan client to wan's address is judged by lan", lan, "172.16.80.8", "connected"},
		{"a netdev no view claims is still judged by destination (lan admits)", x, "10.0.61.1", "connected"},
		{"a netdev no view claims is still judged by destination (wan drops)", x, "172.16.80.8", "timeout"},
	})
	if !t.Failed() {
		fmt.Println("NETNS-CHILD-PASSED-9637")
	}
}
