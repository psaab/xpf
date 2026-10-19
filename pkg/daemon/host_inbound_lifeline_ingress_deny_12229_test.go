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
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.1.1.1/24"}},
		}},
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.2.2.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/0.0"}}, // no host-inbound stanza
		"dmz":     {Name: "dmz", Interfaces: []string{"ge-0/0/1.0"}},
		"trust": {Name: "trust", Interfaces: []string{"ge-0/0/2.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
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
			Addresses: []dpuserspace.InterfaceAddressSnapshot{
				{Family: "inet", Address: lifelineSharedAddr12229 + "/32"},
				{Family: "inet", Address: "198.51.100.1/24"},
			},
		},
		{
			Name: "ge-0/0/1.0", Zone: "dmz", LinuxName: "ge-0-0-1", IsUnit: true,
			Addresses: []dpuserspace.InterfaceAddressSnapshot{{Family: "inet", Address: "10.1.1.1/24"}},
		},
		{
			Name: "ge-0/0/2.0", Zone: "trust", LinuxName: "ge-0-0-2", IsUnit: true,
			Addresses: []dpuserspace.InterfaceAddressSnapshot{{Family: "inet", Address: "10.2.2.1/24"}},
		},
	}
}

func lifelineIngressRule12229(payload, ifname, family, address, action string) string {
	for _, line := range strings.Split(payload, "\n") {
		if !strings.Contains(line, "ct state") &&
			strings.Contains(line, `iifname "`+ifname+`"`) &&
			strings.Contains(line, family+" daddr") &&
			strings.Contains(line, address) &&
			strings.Contains(line, action) {
			return line
		}
	}
	return ""
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
	ownerAddrs := strings.Join(untrust.V4Addrs, " ")
	if strings.Contains(ownerAddrs, lifelineSharedAddr12229) || !strings.Contains(ownerAddrs, "198.51.100.1") {
		t.Fatalf("#7284 must withhold only the lifeline-shared value from owner destination policy; got %v", untrust.V4Addrs)
	}

	fence := dpuserspace.BuildFenceAddrSetsFromSnapshots(
		lifelineDenyAllConfig12229(), lifelineDenyAllSnapshot12229(), views)
	if !strings.Contains("\n"+strings.Join(fence.WithheldV4, "\n")+"\n", "\n"+lifelineSharedAddr12229+"\n") {
		t.Fatalf("cold-boot fence no longer withholds the shared management value: %v", fence.WithheldV4)
	}

	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	untrustDrop := lifelineIngressRule12229(payload, "ge-0-0-0", "ip", lifelineSharedAddr12229, "drop")
	dmzDrop := lifelineIngressRule12229(payload, "ge-0-0-1", "ip", lifelineSharedAddr12229, "drop")
	dmzUntrustAddressDrop := lifelineIngressRule12229(payload, "ge-0-0-1", "ip", "198.51.100.1", "drop")
	trustSSH := lifelineIngressRule12229(payload, "ge-0-0-2", "ip", lifelineSharedAddr12229, "tcp dport 22 accept")
	trustDrop := lifelineIngressRule12229(payload, "ge-0-0-2", "ip", lifelineSharedAddr12229, "drop")
	if untrustDrop == "" || dmzDrop == "" || dmzUntrustAddressDrop == "" || trustSSH == "" || trustDrop == "" {
		t.Fatalf("all ingress views must judge shared and ordinary addresses with their own policy; untrust=%q dmz=%q dmz-own=%q trust-ssh=%q trust-drop=%q\npayload:\n%s", untrustDrop, dmzDrop, dmzUntrustAddressDrop, trustSSH, trustDrop, payload)
	}
	if strings.Contains(payload, `    ip daddr `+lifelineSharedAddr12229+` counter name`) {
		t.Fatalf("shared address must not get a destination-only drop that strands fxp0 management:\n%s", payload)
	}
	if strings.Contains(payload, `iifname "fxp0" ip daddr `+lifelineSharedAddr12229) {
		t.Fatalf("lifeline management interface must not be covered by data-zone ingress deny:\n%s", payload)
	}
	established := strings.Index(payload, "ct state established,related accept")
	if established < 0 || strings.Index(payload, untrustDrop) >= established {
		t.Fatalf("shared-address ingress drop must precede the residual established accept:\n%s", payload)
	}
}

func TestLifelineSharedAdmittingViewUsesIngressPolicy12229(t *testing.T) {
	cfg := lifelineDenyAllConfig12229()
	cfg.Security.Zones["untrust"].HostInboundTraffic = &config.HostInboundTraffic{
		SystemServices: []string{"ping"},
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
	if strings.Contains(strings.Join(untrust.V4Addrs, " "), lifelineSharedAddr12229) ||
		!strings.Contains(strings.Join(untrust.IngressDenyV4, " "), lifelineSharedAddr12229) {
		t.Fatalf("admitting view must withhold shared lifeline address from destination-only policy: %+v", untrust)
	}
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	service := lifelineIngressRule12229(payload, "ge-0-0-0", "ip", lifelineSharedAddr12229, "icmp type echo-request accept")
	drop := lifelineIngressRule12229(payload, "ge-0-0-0", "ip", lifelineSharedAddr12229, "drop")
	if service == "" || drop == "" {
		t.Fatalf("admitting view must preserve service policy on data ingress:\n%s", payload)
	}
	if strings.Contains(payload, `    ip daddr `+lifelineSharedAddr12229+` counter name`) {
		t.Fatalf("shared address must not receive destination-only service/drop rules that affect fxp0:\n%s", payload)
	}
	if strings.Contains(payload, `iifname "fxp0" ip daddr `+lifelineSharedAddr12229) {
		t.Fatalf("lifeline interface must remain outside data-zone ingress policy:\n%s", payload)
	}
}

func TestLifelineSharedFamiliesAndVRFText12229(t *testing.T) {
	const sharedV6 = "2001:db8::1"
	cfg := lifelineDenyAllConfig12229()
	cfg.Interfaces.Interfaces["fxp0"].Units[0].Addresses = append(
		cfg.Interfaces.Interfaces["fxp0"].Units[0].Addresses, sharedV6+"/128", "2001:db8:f::1/64")
	cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].Addresses = append(
		cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].Addresses, sharedV6+"/128", "2001:db8:a::1/64")
	snaps := lifelineDenyAllSnapshot12229()
	snaps[0].Addresses = append(snaps[0].Addresses, dpuserspace.InterfaceAddressSnapshot{Family: "inet6", Address: sharedV6 + "/128"})
	snaps[1].Addresses = append(snaps[1].Addresses, dpuserspace.InterfaceAddressSnapshot{Family: "inet6", Address: sharedV6 + "/128"})
	views := dpuserspace.BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	var untrust *dpuserspace.ZoneHostInboundView
	for i := range views {
		if views[i].Zone == "untrust" {
			untrust = &views[i]
			break
		}
	}
	if untrust == nil || len(untrust.IngressDenyV6) != 1 || untrust.IngressDenyV6[0] != sharedV6 {
		t.Fatalf("builder did not preserve the withheld IPv6 address: %+v", untrust)
	}
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	v6Drop := lifelineIngressRule12229(payload, "ge-0-0-0", "ip6", sharedV6, "drop")
	if v6Drop == "" {
		t.Fatalf("text renderer omitted the shared IPv6 ingress deny:\n%s", payload)
	}
	established := strings.Index(payload, "ct state established,related accept")
	if established < 0 || strings.Index(payload, v6Drop) >= established {
		t.Fatalf("shared IPv6 ingress drop must precede the residual established accept:\n%s", payload)
	}

	vrfView := []dpuserspace.ZoneHostInboundView{{
		Zone: "vrf-deny", IngressNetdevs: []string{"vrf-shared"},
		IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-shared", Slaves: []string{"ge-vrf0"}}},
		IngressDenyV4:    []string{"198.18.1.1"},
		IngressDenyV6:    []string{"2001:db8:18::1"},
	}}
	vrfPayload := buildHostInboundFilterPayload(vrfView, nil, nil, nil, nil, true)
	for _, tc := range []struct {
		family string
		addr   string
	}{
		{"ip", "198.18.1.1"},
		{"ip6", "2001:db8:18::1"},
	} {
		rule := `iifname "vrf-shared" meta sdifname "ge-vrf0" ` + tc.family + " daddr " + tc.addr
		if !strings.Contains(vrfPayload, rule+" counter name ") {
			t.Fatalf("text renderer omitted %s VRF-scoped shared deny %s:\n%s", tc.family, tc.addr, vrfPayload)
		}
	}
}
func TestLifelineSharedUnzonedAmbiguousIngressDeny12229(t *testing.T) {
	const sharedV6 = "2001:db8::1"
	views := []dpuserspace.ZoneHostInboundView{{
		Zone: "untrust", IngressNetdevs: []string{"ge-0-0-0"},
		V4Addrs: []string{"198.51.100.1"}, V6Addrs: []string{"2001:db8:a::1"},
		IngressDenyV4: []string{lifelineSharedAddr12229}, IngressDenyV6: []string{sharedV6},
		IngressDenyNetdevs: []string{"amb0"},
	}}
	payload := buildHostInboundFilterPayloadWithUnzonedIngress(
		views, []string{"10.3.3.1"}, nil, []string{"uz0"}, nil,
		nil, nil, true, nil, nil, nil, dhcpBackstopLists{})
	// Both catch-alls share the reserved junos-host counter (neither has a
	// unique zone attribution), but each is its own rule with its own
	// ingress scope: collect them by (iifname, family) so the ambiguous
	// and unzoned paths are pinned independently.
	type scope struct {
		ifname, family string
	}
	got := map[scope][]string{}
	for _, line := range strings.Split(payload, "\n") {
		if !strings.Contains(line, "counter name") || !strings.Contains(line, "drop") ||
			strings.Contains(line, "tcp dport") || strings.Contains(line, "ct state") {
			continue
		}
		for _, ifname := range []string{"amb0", "uz0"} {
			if !strings.Contains(line, `iifname "`+ifname+`"`) {
				continue
			}
			for _, family := range []string{"ip", "ip6"} {
				if !strings.Contains(line, " "+family+" daddr ") {
					continue
				}
				got[scope{ifname, family}] = append(got[scope{ifname, family}], line)
			}
		}
	}
	for _, ifname := range []string{"amb0", "uz0"} {
		for _, tc := range []struct {
			family, shared string
		}{
			{"ip", lifelineSharedAddr12229},
			{"ip6", sharedV6},
		} {
			lines := got[scope{ifname, tc.family}]
			if len(lines) != 1 {
				t.Errorf("%s %s catch-all: got %d rules %q, want exactly 1", ifname, tc.family, len(lines), lines)
				continue
			}
			if !strings.Contains(lines[0], tc.shared) || !strings.Contains(lines[0], dpuserspace.UnzonedHostInboundZoneLabel) {
				t.Errorf("%s %s catch-all omits shared %s or junos-host counter: %q", ifname, tc.family, tc.shared, lines[0])
			}
		}
	}
	if t.Failed() {
		t.Fatalf("payload:\n%s", payload)
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
		if os.Getenv("XPF_REQUIRE_NETNS") != "" {
			t.Fatalf("nft not found (XPF_REQUIRE_NETNS is set)")
		}
		t.Skip("nft not found")
	}
	for _, tool := range []string{"unshare", "ip", "nsenter", "timeout", "bash", "sleep"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("XPF_REQUIRE_NETNS") != "" {
				t.Fatalf("%s not available (XPF_REQUIRE_NETNS is set)", tool)
			}
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
	fxpClient := wire("fxp0", "clfxp", "203.0.113.1/24", "203.0.113.100/24", "203.0.113.1")
	untrustClient := wire("ge-0-0-0", "cluntrust", "198.51.100.1/24", "198.51.100.100/24", "198.51.100.1")
	dmzClient := wire("ge-0-0-1", "cldmz", "10.1.1.1/24", "10.1.1.100/24", "10.1.1.1")
	trustClient := wire("ge-0-0-2", "cltrust", "10.2.2.1/24", "10.2.2.100/24", "10.2.2.1")
	unzonedClient := wire("ge-0-0-3", "clunzoned", "10.3.3.1/24", "10.3.3.100/24", "10.3.3.1")
	for _, dev := range []string{"fxp0", "ge-0-0-0"} {
		run("ip", "addr", "add", lifelineSharedAddr12229+"/32", "dev", dev)
	}

	for _, port := range []string{"22", "80"} {
		ln, err := net.Listen("tcp4", "0.0.0.0:"+port)
		if err != nil {
			t.Fatalf("listen on :%s: %v", port, err)
		}
		defer ln.Close()
		go func(listener net.Listener) {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}(ln)
	}

	cfg := lifelineDenyAllConfig12229()
	cfg.Interfaces.Interfaces["ge-0/0/3"] = &config.InterfaceConfig{
		Name: "ge-0/0/3",
		Units: map[int]*config.InterfaceUnit{0: {
			Number: 0, Addresses: []string{"10.3.3.1/24"},
		}},
	}
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	unzonedIngress := []string{"ge-0-0-3"}
	if len(views) == 0 {
		t.Fatal("real builder returned no zone views")
	}
	payload := buildHostInboundFilterPayloadWithUnzonedIngress(
		views, unzonedV4, unzonedV6, unzonedIngress, nil, nil, nil, true, nil, nil, nil, dhcpBackstopLists{})
	cmd := exec.Command(findNft(), "-f", "-")
	cmd.Stdin = strings.NewReader(payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f: %v: %s\npayload:\n%s", err, out, payload)
	}
	connect := func(pid, address, port string) string {
		t.Helper()
		err := exec.Command("nsenter", "-t", pid, "-n", "timeout", "1", "bash", "-c", "exec 3<>/dev/tcp/"+address+"/"+port).Run()
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
		for _, tc := range []struct {
			name, client, address, port, want string
		}{
			{"fxp0->shared:22", fxpClient, lifelineSharedAddr12229, "22", "connected"},
			{"untrust->shared:22", untrustClient, lifelineSharedAddr12229, "22", "timeout"},
			{"dmz->shared:22", dmzClient, lifelineSharedAddr12229, "22", "timeout"},
			{"dmz->untrust-address:22", dmzClient, "198.51.100.1", "22", "timeout"},
			{"trust->shared:22", trustClient, lifelineSharedAddr12229, "22", "connected"},
			{"trust->shared:80", trustClient, lifelineSharedAddr12229, "80", "timeout"},
			{"trust->untrust-address:80", trustClient, "198.51.100.1", "80", "timeout"},
			{"unzoned->shared:22", unzonedClient, lifelineSharedAddr12229, "22", "timeout"},
		} {
			if got := connect(tc.client, tc.address, tc.port); got != tc.want {
				t.Errorf("%s: %s = %s, want %s", backend, tc.name, got, tc.want)
			}
		}
	}
	check("text oracle")
	if err := xnft.NewNetlinkInstaller().InstallHostInbound(
		toNftHostInboundSpecWithUnzonedIngress(
			views, unzonedV4, unzonedV6, unzonedIngress, nil, nil, nil, nil, true, nil,
		),
	); err != nil {
		t.Fatalf("install production netlink rules: %v", err)
	}
	check("production netlink")
	t.Run("shared-only-kernel-load", func(t *testing.T) {
		onlyShared := []dpuserspace.ZoneHostInboundView{{
			Zone: "shared-only", IngressNetdevs: []string{"ge-only"},
			IngressDenyV4: []string{"192.0.2.88"}, IngressDenyV6: []string{"2001:db8:88::1"},
		}}
		payload := buildHostInboundFilterPayload(onlyShared, nil, nil, nil, nil, true)
		run(findNft(), "delete", "table", "inet", "xpf_hostinbound")
		cmd := exec.Command(findNft(), "-f", "-")
		cmd.Stdin = strings.NewReader(payload)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft -f shared-only rules: %v: %s\n%s", err, out, payload)
		}
		if err := xnft.NewNetlinkInstaller().InstallHostInbound(
			toNftHostInboundSpec(onlyShared, nil, nil, nil, nil, nil, true),
		); err != nil {
			t.Fatalf("install shared-only netlink rules: %v", err)
		}
	})
	if !t.Failed() {
		fmt.Println("NETNS-CHILD-PASSED-12229")
	}
}
