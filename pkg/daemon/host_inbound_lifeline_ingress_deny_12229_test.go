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

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

const lifelineSharedAddr12229 = "192.0.2.1"

func lifelineDenyAllConfig12229() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{lifelineSharedAddr12229 + "/32", "203.0.113.1/24"}},
		}},
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{lifelineSharedAddr12229 + "/32", "198.51.100.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/0.0"}}, // no host-inbound stanza
	}
	return cfg
}

func lifelineDenyAllSnapshot12229() []dpuserspace.InterfaceSnapshot {
	return []dpuserspace.InterfaceSnapshot{
		{
			Name: "fxp0.0", LinuxName: "fxp0", IsUnit: true,
			Addresses: []dpuserspace.InterfaceAddressSnapshot{{Family: "inet", Address: lifelineSharedAddr12229 + "/32"}},
		},
		{
			Name: "ge-0/0/0.0", Zone: "untrust", LinuxName: "ge-0-0-0", IsUnit: true,
			Addresses: []dpuserspace.InterfaceAddressSnapshot{{Family: "inet", Address: lifelineSharedAddr12229 + "/32"}},
		},
	}
}

func TestLifelineSharedDenyAllHasIngressOnlyDrop12229(t *testing.T) {
	views := dpuserspace.BuildZoneHostInboundViewsFromSnapshots(lifelineDenyAllConfig12229(), lifelineDenyAllSnapshot12229())
	var untrust *dpuserspace.ZoneHostInboundView
	for i := range views {
		if views[i].Zone == "untrust" {
			untrust = &views[i]
			break
		}
	}
	if untrust == nil {
		t.Fatalf("no untrust view in builder output: %+v", views)
	}
	if len(untrust.SystemServices) != 0 || len(untrust.Protocols) != 0 {
		t.Fatalf("fixture must be a deny-all view: %+v", untrust)
	}
	if got := strings.Join(untrust.IngressNetdevs, " "); got != "ge-0-0-0" {
		t.Fatalf("untrust ingress = %q, want ge-0-0-0", got)
	}
	if len(untrust.V4Addrs) != 0 {
		t.Fatalf("#7284 must keep lifeline-shared address out of destination-only drop; got %v", untrust.V4Addrs)
	}

	fence := dpuserspace.BuildFenceAddrSetsFromSnapshots(
		lifelineDenyAllConfig12229(), lifelineDenyAllSnapshot12229(), views)
	if !strings.Contains("\n"+strings.Join(fence.WithheldV4, "\n")+"\n", "\n"+lifelineSharedAddr12229+"\n") {
		t.Fatalf("cold-boot fence no longer withholds the shared management value: %v", fence.WithheldV4)
	}

	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	counter := xnft.HostInboundDenyCounterName("untrust", "ip")
	want := `    iifname "ge-0-0-0" ip daddr ` + lifelineSharedAddr12229 + ` counter name "` + counter + `" drop`
	if !strings.Contains(payload, want) {
		t.Fatalf("missing ingress-only deny for lifeline-shared address; expected %q\npayload:\n%s", want, payload)
	}
	if strings.Contains(payload, `    ip daddr `+lifelineSharedAddr12229+` counter name "`+counter+`" drop`) {
		t.Fatalf("shared address must not get a destination-only drop that strands fxp0 management:\n%s", payload)
	}
	if strings.Contains(payload, `iifname "fxp0" ip daddr `+lifelineSharedAddr12229) {
		t.Fatalf("lifeline management interface must not be covered by data-zone ingress deny:\n%s", payload)
	}
}

func TestLifelineSharedAdmittingViewKeepsDestinationPolicy12229(t *testing.T) {
	cfg := lifelineDenyAllConfig12229()
	cfg.Security.Zones["untrust"].HostInboundTraffic = &config.HostInboundTraffic{
		SystemServices: []string{"ssh"},
	}
	views := dpuserspace.BuildZoneHostInboundViewsFromSnapshots(cfg, lifelineDenyAllSnapshot12229())
	var untrust *dpuserspace.ZoneHostInboundView
	for i := range views {
		if views[i].Zone == "untrust" {
			untrust = &views[i]
			break
		}
	}
	if untrust == nil {
		t.Fatalf("no untrust view in builder output: %+v", views)
	}
	if !strings.Contains("\n"+strings.Join(untrust.V4Addrs, "\n")+"\n", "\n"+lifelineSharedAddr12229+"\n") {
		t.Fatalf("admitting view must keep shared address in its destination policy: %+v", untrust)
	}
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	counter := xnft.HostInboundDenyCounterName("untrust", "ip")
	wantService := `iifname "ge-0-0-0" ip daddr ` + lifelineSharedAddr12229 + " tcp dport 22 accept"
	wantDrop := `iifname "ge-0-0-0" ip daddr ` + lifelineSharedAddr12229 + ` counter name "` + counter + `" drop`
	if !strings.Contains(payload, wantService) || strings.Count(payload, wantDrop) != 1 {
		t.Fatalf("admitting view must keep the shared destination policy without a duplicate ingress-only drop:\n%s", payload)
	}
}

const lifelineDenyAllNetnsChild12229 = "XPF_12229_NETNS_CHILD"

// TestLifelineSharedDenyAllVerdictsOnRealKernel12229 is the acceptance cell:
// SSH-port traffic to the shared address is dropped on untrust, while the same
// destination remains reachable through fxp0. It is isolated in a private
// user/network namespace and never mutates the host's live firewall.
func TestLifelineSharedDenyAllVerdictsOnRealKernel12229(t *testing.T) {
	if os.Getenv(lifelineDenyAllNetnsChild12229) == "1" {
		lifelineSharedDenyAllNetnsChild12229(t)
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
	cmd := exec.Command("unshare", "-rn", os.Args[0], "-test.run", "^TestLifelineSharedDenyAllVerdictsOnRealKernel12229$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), lifelineDenyAllNetnsChild12229+"=1")
	out, err := cmd.CombinedOutput()
	if !strings.Contains(string(out), "NETNS-CHILD-STARTED-12229") {
		if os.Getenv("XPF_REQUIRE_NETNS") == "" {
			t.Skipf("netns unavailable (%v): %s", err, out)
		}
		t.Fatalf("netns child never started (%v): %s", err, out)
	}
	if err != nil || !strings.Contains(string(out), "NETNS-CHILD-PASSED-12229") {
		t.Fatalf("real-kernel cell failed inside namespace (%v):\n%s", err, out)
	}
}

func lifelineSharedDenyAllNetnsChild12229(t *testing.T) {
	fmt.Println("NETNS-CHILD-STARTED-12229")
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
	client := func() string {
		t.Helper()
		c := exec.Command("unshare", "-n", "sleep", "120")
		if err := c.Start(); err != nil {
			t.Fatalf("start client namespace: %v", err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
		pid := strconv.Itoa(c.Process.Pid)
		for range 300 {
			if ns, err := os.Readlink("/proc/" + pid + "/ns/net"); err == nil && ns != selfNS {
				return pid
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("client %s never entered its own network namespace", pid)
		return ""
	}
	wire := func(fwDev, clDev, fwAddr, clAddr, gateway string) string {
		t.Helper()
		pid := client()
		run("ip", "link", "add", fwDev, "type", "veth", "peer", "name", clDev, "netns", pid)
		run("ip", "addr", "add", fwAddr, "dev", fwDev)
		run("ip", "link", "set", fwDev, "up")
		for _, args := range [][]string{
			{"link", "set", "lo", "up"},
			{"addr", "add", clAddr, "dev", clDev},
			{"link", "set", clDev, "up"},
			{"route", "add", "default", "via", gateway},
		} {
			run("nsenter", append([]string{"-t", pid, "-n", "ip"}, args...)...)
		}
		return pid
	}
	run("ip", "link", "set", "lo", "up")
	fxpClient := wire("fxp0", "clfxp", "203.0.113.1/24", "203.0.113.100/24", "203.0.113.1")
	untrustClient := wire("ge-0-0-0", "cluntrust", "198.51.100.1/24", "198.51.100.100/24", "198.51.100.1")
	for _, dev := range []string{"fxp0", "ge-0-0-0"} {
		run("ip", "addr", "add", lifelineSharedAddr12229+"/32", "dev", dev)
	}

	ln, err := net.Listen("tcp4", "0.0.0.0:22")
	if err != nil {
		t.Fatalf("listen on :22: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	views := dpuserspace.BuildZoneHostInboundViews(lifelineDenyAllConfig12229())
	if len(views) == 0 {
		t.Fatal("real builder returned no zone views")
	}
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	cmd := exec.Command(findNft(), "-f", "-")
	cmd.Stdin = strings.NewReader(payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f: %v: %s\npayload:\n%s", err, out, payload)
	}
	connect := func(pid string) string {
		t.Helper()
		err := exec.Command("nsenter", "-t", pid, "-n", "timeout", "1", "bash", "-c", "exec 3<>/dev/tcp/"+lifelineSharedAddr12229+"/22").Run()
		var exit *exec.ExitError
		switch {
		case err == nil:
			return "connected"
		case errors.As(err, &exit) && exit.ExitCode() == 124:
			return "timeout"
		default:
			return fmt.Sprintf("error: %v", err)
		}
	}
	check := func(backend string) {
		t.Helper()
		if got := connect(untrustClient); got != "timeout" {
			t.Errorf("%s: untrust SSH to shared address = %s, want timeout/drop", backend, got)
		}
		if got := connect(fxpClient); got != "connected" {
			t.Errorf("%s: fxp0 management SSH to shared address = %s, want connected", backend, got)
		}
	}
	check("text oracle")
	if err := xnft.NewNetlinkInstaller().InstallHostInbound(
		toNftHostInboundSpec(views, nil, nil, nil, nil, nil, true),
	); err != nil {
		t.Fatalf("install production netlink rules: %v", err)
	}
	check("production netlink")
	if !t.Failed() {
		fmt.Println("NETNS-CHILD-PASSED-12229")
	}
}
