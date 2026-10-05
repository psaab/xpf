package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"golang.org/x/sys/unix"
)

const netnsChild12034 = "XPF_12034_NETNS_CHILD"

func sharedVRFHostInboundConfig12034() *config.Config {
	cfg := junosHostDenyTestConfig()
	cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0].Addresses = []string{
		"192.0.2.1/24", "2001:db8:1::1/64",
	}
	cfg.Interfaces.Interfaces["ge-0/0/2"] = &config.InterfaceConfig{
		Name: "ge-0/0/2",
		Units: map[int]*config.InterfaceUnit{0: {
			Number: 0, Addresses: []string{"198.51.100.1/24", "2001:db8:2::1/64"},
		}},
	}
	cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = []string{"dns", "ping"}
	cfg.Security.Zones["trust"] = &config.ZoneConfig{
		Name: "trust", Interfaces: []string{"ge-0/0/2.0"},
		HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"dns", "ssh"}},
	}
	cfg.Interfaces.Interfaces["wg0"] = &config.InterfaceConfig{
		Name: "wg0",
		Tunnel: &config.TunnelConfig{
			Name: "wg0", Mode: "wireguard", Source: "192.0.2.1", WgListenPort: 51820,
		},
	}
	cfg.Security.Zones["trust"].Interfaces = append(cfg.Security.Zones["trust"].Interfaces, "wg0")
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "shared", InstanceType: "virtual-router",
		Interfaces: []string{"ge-0/0/1.0", "ge-0/0/2.0"},
	}}
	cfg.Security.AddressBook.Addresses["bad-net"] = &config.Address{Name: "bad-net", Value: "203.0.113.0/24"}
	cfg.Security.AddressBook.Addresses["bad-net6"] = &config.Address{Name: "bad-net6", Value: "2001:db8:bad::/64"}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "untrust", ToZone: "junos-host",
		Policies: append(
			zonePairDeny("untrust", "block-bad-source", "src:bad-net", "app:any"),
			zonePairDeny("untrust", "block-bad-source6", "src:bad-net6", "app:any")...,
		),
	}}
	return cfg
}

// TestHostInboundSharedVRFMasterIngressAndFineDeny12034 exercises two distinct
// zone slaves of one VRF master against the rendered text rules in a real kernel.
// It covers the destination-owner leak/refusal, a service neither zone admits,
// and a source-scoped junos-host deny that must not spill onto the sibling zone.
func TestHostInboundSharedVRFMasterIngressAndFineDeny12034(t *testing.T) {
	if os.Getenv(netnsChild12034) == "1" {
		hostInboundSharedVRFNetnsChild12034(t)
		return
	}
	if findNft() == "" {
		t.Skip("nft not found")
	}
	for _, tool := range []string{"unshare", "ip", "nsenter"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	cmd := exec.Command("unshare", "-rn", os.Args[0], "-test.run", "^TestHostInboundSharedVRFMasterIngressAndFineDeny12034$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), netnsChild12034+"=1")
	out, err := cmd.CombinedOutput()
	if !strings.Contains(string(out), "NETNS-CHILD-STARTED-12034") {
		if os.Getenv("XPF_REQUIRE_NETNS") == "" {
			t.Skipf("netns unavailable (%v): %s", err, out)
		}
		t.Fatalf("netns child never started (%v): %s", err, out)
	}
	if err != nil || !strings.Contains(string(out), "NETNS-CHILD-PASSED-12034") {
		t.Fatalf("shared-VRF real-kernel cell failed (%v):\n%s", err, out)
	}
}

func hostInboundSharedVRFNetnsChild12034(t *testing.T) {
	fmt.Println("NETNS-CHILD-STARTED-12034")
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, out)
		}
		return string(out)
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
		for i := 0; i < 300; i++ {
			if ns, err := os.Readlink("/proc/" + pid + "/ns/net"); err == nil && ns != selfNS {
				return pid
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("client %s never entered its network namespace", pid)
		return ""
	}
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "vrf-shared", "type", "vrf", "table", "12034")
	run("ip", "link", "set", "vrf-shared", "up")
	for _, iface := range []string{"all", "default", "vrf-shared"} {
		path := "/proc/sys/net/ipv4/conf/" + iface + "/rp_filter"
		if err := os.WriteFile(path, []byte("0"), 0644); err != nil {
			t.Fatalf("disable reverse-path filtering on %s: %v", iface, err)
		}
	}
	untrust, trust := client(), client()
	wire := func(fwDev, peerDev, pid, fwV4, peerV4, gwV4, fwV6, peerV6, gwV6 string) {
		t.Helper()
		run("ip", "link", "add", fwDev, "type", "veth", "peer", "name", peerDev, "netns", pid)
		run("ip", "link", "set", fwDev, "master", "vrf-shared")
		run("ip", "addr", "add", fwV4, "dev", fwDev)
		run("ip", "-6", "addr", "add", fwV6, "dev", fwDev, "nodad")
		run("ip", "link", "set", fwDev, "up")
		for _, args := range [][]string{
			{"link", "set", "lo", "up"},
			{"addr", "add", peerV4, "dev", peerDev},
			{"addr", "add", "203.0.113.100/32", "dev", peerDev},
			{"-6", "addr", "add", peerV6, "dev", peerDev, "nodad"},
			{"-6", "addr", "add", "2001:db8:bad::100/128", "dev", peerDev, "nodad"},
			{"link", "set", peerDev, "up"},
			{"route", "add", "default", "via", gwV4, "dev", peerDev},
			{"-6", "route", "add", "default", "via", gwV6, "dev", peerDev},
		} {
			run("nsenter", append([]string{"-t", pid, "-n", "ip"}, args...)...)
		}
	}
	wire("ge-0-0-1", "cl-untrust", untrust,
		"192.0.2.1/24", "192.0.2.100/24", "192.0.2.1",
		"2001:db8:1::1/64", "2001:db8:1::100/64", "2001:db8:1::1")
	wire("ge-0-0-2", "cl-trust", trust,
		"198.51.100.1/24", "198.51.100.100/24", "198.51.100.1",
		"2001:db8:2::1/64", "2001:db8:2::100/64", "2001:db8:2::1")

	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "vrf-shared")
		}); err != nil {
			return err
		}
		return sockErr
	}}
	var listeners []net.Listener
	for _, network := range []string{"tcp4", "tcp6"} {
		ln, err := lc.Listen(context.Background(), network, ":22")
		if err != nil {
			t.Fatalf("listen %s :22 on vrf-shared: %v", network, err)
		}
		listeners = append(listeners, ln)
		go func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}(ln)
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		ln, err := lc.Listen(context.Background(), network, ":18080")
		if err != nil {
			t.Fatalf("listen %s :18080 on vrf-shared: %v", network, err)
		}
		listeners = append(listeners, ln)
		go func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}(ln)
	}
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()

	udp4, err := lc.ListenPacket(context.Background(), "udp4", ":53")
	if err != nil {
		t.Fatalf("listen udp4 :53 on vrf-shared: %v", err)
	}
	defer udp4.Close()
	udp6, err := lc.ListenPacket(context.Background(), "udp6", ":53")
	if err != nil {
		t.Fatalf("listen udp6 :53 on vrf-shared: %v", err)
	}
	defer udp6.Close()
	wg4, err := lc.ListenPacket(context.Background(), "udp4", ":51820")
	if err != nil {
		t.Fatalf("listen udp4 :51820 on vrf-shared: %v", err)
	}
	defer wg4.Close()
	received := make(chan string, 16)
	for _, pc := range []net.PacketConn{udp4, udp6} {
		go func(pc net.PacketConn) {
			buf := make([]byte, 128)
			for {
				n, _, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				received <- string(buf[:n])
			}
		}(pc)
	}
	wgReceived := make(chan string, 4)
	go func() {
		buf := make([]byte, 128)
		for {
			n, _, err := wg4.ReadFrom(buf)
			if err != nil {
				return
			}
			wgReceived <- string(buf[:n])
		}
	}()

	cfg := sharedVRFHostInboundConfig12034()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	programs := dpuserspace.BuildJunosHostPrograms(cfg)
	wgZones := hostInboundWireGuardZonePorts(cfg, views)
	payload := buildHostInboundFilterPayload(views, nil, nil, programs, wgZones, true)
	cmd := exec.Command(findNft(), "-f", "-")
	cmd.Stdin = strings.NewReader(payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("load rendered host-inbound rules: %v: %s\npayload:\n%s", err, out, payload)
	}

	dial := func(pid, network, source, dst string) bool {
		t.Helper()
		var conn net.Conn
		err := inNetns12034(pid, func() error {
			d := net.Dialer{Timeout: 700 * time.Millisecond}
			switch network {
			case "tcp4":
				d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source).To4()}
			case "tcp6":
				d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
			}
			var err error
			conn, err = d.Dial(network, net.JoinHostPort(dst, "22"))
			return err
		})
		if conn != nil {
			_ = conn.Close()
		}
		return err == nil
	}
	sendDNS := func(pid, network, source, dst, label string) error {
		return inNetns12034(pid, func() error {
			d := net.Dialer{Timeout: time.Second}
			if network == "udp4" {
				d.LocalAddr = &net.UDPAddr{IP: net.ParseIP(source).To4()}
			} else {
				d.LocalAddr = &net.UDPAddr{IP: net.ParseIP(source)}
			}
			conn, err := d.Dial(network, net.JoinHostPort(dst, "53"))
			if err != nil {
				return err
			}
			defer conn.Close()
			_, err = conn.Write([]byte(label))
			return err
		})
	}
	gotDNS := func(label string, want bool) {
		t.Helper()
		timer := time.NewTimer(250 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case got := <-received:
				if got == label {
					if !want {
						t.Errorf("denied DNS datagram %q reached the host", label)
					}
					return
				}
			case <-timer.C:
				if want {
					t.Errorf("permitted DNS datagram %q did not reach the host", label)
				}
				return
			}
		}
	}

	sendWG := func(pid, source, label string) error {
		return inNetns12034(pid, func() error {
			d := net.Dialer{Timeout: time.Second, LocalAddr: &net.UDPAddr{IP: net.ParseIP(source).To4()}}
			conn, err := d.Dial("udp4", net.JoinHostPort("192.0.2.1", "51820"))
			if err != nil {
				return err
			}
			defer conn.Close()
			_, err = conn.Write([]byte(label))
			return err
		})
	}
	expectWG := func(label string, want bool) {
		t.Helper()
		timer := time.NewTimer(250 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case got := <-wgReceived:
				if got == label {
					if !want {
						t.Errorf("denied WireGuard datagram %q reached the host", label)
					}
					return
				}
			case <-timer.C:
				if want {
					t.Errorf("permitted WireGuard datagram %q did not reach the host", label)
				}
				return
			}
		}
	}

	for _, tc := range []struct {
		label, network, source, dst string
		pid                         string
		connected                   bool
	}{
		{label: "untrust to trusted v4 ssh", pid: untrust, network: "tcp4", source: "192.0.2.100", dst: "198.51.100.1"},
		{label: "trust to untrust v4 ssh", pid: trust, network: "tcp4", source: "198.51.100.100", dst: "192.0.2.1", connected: true},
		{label: "trust to trust v4 ssh", pid: trust, network: "tcp4", source: "198.51.100.100", dst: "198.51.100.1", connected: true},
		{label: "untrust to trusted v6 ssh", pid: untrust, network: "tcp6", source: "2001:db8:1::100", dst: "2001:db8:2::1"},
		{label: "trust to untrust v6 ssh", pid: trust, network: "tcp6", source: "2001:db8:2::100", dst: "2001:db8:1::1", connected: true},
		{label: "trust to trust v6 ssh", pid: trust, network: "tcp6", source: "2001:db8:2::100", dst: "2001:db8:2::1", connected: true},
	} {
		got := dial(tc.pid, tc.network, tc.source, tc.dst)
		if got != tc.connected {
			t.Errorf("%s: connected = %v, want %v", tc.label, got, tc.connected)
		}
	}
	for _, tc := range []struct {
		label, network, source, dst string
		pid                         string
	}{
		{"untrust to untrust v4 forbidden port", "tcp4", "192.0.2.100", "192.0.2.1", untrust},
		{"trust to trust v4 forbidden port", "tcp4", "198.51.100.100", "198.51.100.1", trust},
		{"untrust to untrust v6 forbidden port", "tcp6", "2001:db8:1::100", "2001:db8:1::1", untrust},
		{"trust to trust v6 forbidden port", "tcp6", "2001:db8:2::100", "2001:db8:2::1", trust},
	} {
		var conn net.Conn
		err := inNetns12034(tc.pid, func() error {
			d := net.Dialer{Timeout: 700 * time.Millisecond}
			if tc.network == "tcp4" {
				d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(tc.source).To4()}
			} else {
				d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(tc.source)}
			}
			var err error
			conn, err = d.Dial(tc.network, net.JoinHostPort(tc.dst, "18080"))
			return err
		})
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil {
			t.Errorf("%s: non-admitted port connected", tc.label)
		}
	}

	for _, tc := range []struct {
		label, network, src, dst string
		pid                      string
		want                     bool
	}{
		{"bad source denied by untrust v4 fine program", "udp4", "203.0.113.100", "192.0.2.1", untrust, false},
		{"same bad source on trust v4 unaffected", "udp4", "203.0.113.100", "198.51.100.1", trust, true},
		{"non-denied source on untrust v4 admitted", "udp4", "192.0.2.100", "192.0.2.1", untrust, true},
		{"bad source denied by untrust v6 fine program", "udp6", "2001:db8:bad::100", "2001:db8:1::1", untrust, false},
		{"same bad source on trust v6 unaffected", "udp6", "2001:db8:bad::100", "2001:db8:2::1", trust, true},
		{"non-denied source on untrust v6 admitted", "udp6", "2001:db8:1::100", "2001:db8:1::1", untrust, true},
	} {
		if err := sendDNS(tc.pid, tc.network, tc.src, tc.dst, tc.label); err != nil {
			t.Fatalf("send %s: %v", tc.label, err)
		}
		gotDNS(tc.label, tc.want)
	}

	for _, tc := range []struct {
		label, source string
		pid           string
		want          bool
	}{
		{"owner member admits its listener", "192.0.2.100", untrust, true},
		{"sibling member cannot reach owner's listener", "198.51.100.100", trust, false},
	} {
		if err := sendWG(tc.pid, tc.source, tc.label); err != nil {
			t.Fatalf("send %s: %v", tc.label, err)
		}
		expectWG(tc.label, tc.want)
	}

	for _, family := range []string{"ip", "ip6"} {
		name := xnft.HostInboundDenyCounterName("untrust", family)
		out := run(findNft(), "list", "counter", "inet", xnft.HostInboundTableName, name)
		if !regexp.MustCompile(`packets [1-9][0-9]*`).MatchString(out) {
			t.Errorf("untrust %s ingress deny counter %s did not increment: %s", family, name, out)
		}
		fineName := xnft.HostInboundJunosHostDenyCounterName("untrust", family)
		out = run(findNft(), "list", "counter", "inet", xnft.HostInboundTableName, fineName)
		if !regexp.MustCompile(`packets [1-9][0-9]*`).MatchString(out) {
			t.Errorf("untrust %s fine junos-host deny counter %s did not increment: %s", family, fineName, out)
		}
	}
	if !t.Failed() {
		fmt.Println("NETNS-CHILD-PASSED-12034")
	}
}

func inNetns12034(pid string, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	current, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return err
	}
	defer current.Close()
	target, err := os.Open("/proc/" + pid + "/ns/net")
	if err != nil {
		return err
	}
	defer target.Close()
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		return err
	}
	defer func() { _ = unix.Setns(int(current.Fd()), unix.CLONE_NEWNET) }()
	return fn()
}
