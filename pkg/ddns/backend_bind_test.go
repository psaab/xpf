package ddns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
)

// #2691 P1b / #2665 source-binding tests: the resolved bindConfig + the custom
// net.Dialer the rfc2136 backend uses. The socket bind itself is a kernel
// operation exercised on the cluster; here we assert the DIAL CONFIGURATION
// (the unit the issue's fix-direction names) — LocalAddr/Control are wired iff
// a binding is configured, an invalid source-address is rejected, and the
// rfc2136 backend installs the custom dialer.

func TestResolveBindConfigEmptyIsNoBinding(t *testing.T) {
	b, err := resolveBindConfig(config.RFC2136Endpoint{}, nil)
	if err != nil {
		t.Fatalf("empty config: %v", err)
	}
	if b.isSet() {
		t.Fatal("empty source-binding config must request NO binding")
	}
	if d := b.dialer(time.Second); d != nil {
		t.Fatal("no-binding config must yield a nil dialer (default transport)")
	}
}

func TestResolveBindConfigSourceAddress(t *testing.T) {
	b, err := resolveBindConfig(config.RFC2136Endpoint{SourceAddress: "10.0.0.9"}, nil)
	if err != nil {
		t.Fatalf("source-address: %v", err)
	}
	if !b.sourceAddr.IsValid() || b.sourceAddr.String() != "10.0.0.9" {
		t.Fatalf("source-address not resolved: %v", b.sourceAddr)
	}
	if !b.isSet() {
		t.Fatal("a source-address must request a binding")
	}
	if d := b.dialer(time.Second); d == nil || d.Control == nil {
		t.Fatal("a source-address must produce a dialer with a Control hook (source bind)")
	}
}

func TestResolveBindConfigInvalidSourceAddressRejected(t *testing.T) {
	if _, err := resolveBindConfig(config.RFC2136Endpoint{SourceAddress: "not-an-ip"}, nil); err == nil {
		t.Fatal("an invalid source-address must be rejected (the manager then falls back to no-op + counts it)")
	}
}

// bindTestConfig builds a committed *config.Config that exercises the SSOT
// interface-name resolver (config.ResolveKernelIfName) for the #5070 cases the
// leaf slash-substitution gets WRONG:
//
//   - ge-0/0/2 has unit 0 (unit-0 collapse) and unit 50 with vlan-id 80
//     (unit#≠vlan-id: the kernel subif is named by the VLAN ID, not the unit).
//   - reth1's local physical member is ge-0/0/1 (there is no bonded "reth1"
//     kernel device — SO_BINDTODEVICE must target the member).
//   - reth0's local physical member is ge-0/0/3, and reth0 unit 100 carries
//     vlan-id 100, so reth0.100 → the member's VLAN subif ge-0-0-3.100.
//
// NodeID 0 makes the slot-0 members the LOCAL-node members (RethToPhysical).
func bindTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0},
			50: {Number: 50, VlanID: 80},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"},
		"ge-0/0/3": {Name: "ge-0/0/3", RedundantParent: "reth0"},
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			100: {Number: 100, VlanID: 100},
		}},
	}
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 0}
	return cfg
}

func TestResolveBindConfigDestInterfaceWinsOverVRF(t *testing.T) {
	// destination-interface is the more specific SO_BINDTODEVICE pin; when both
	// it and a routing-instance are set, the destination-interface wins — and it
	// resolves from Junos form ("ge-0/0/2") to the real kernel device ("ge-0-0-2")
	// via the committed config's SSOT resolver so SO_BINDTODEVICE targets a real
	// device (#5070).
	resolve := bindTestConfig().ResolveKernelIfName
	b, err := resolveBindConfig(config.RFC2136Endpoint{
		DestinationInterface: "ge-0/0/2",
		RoutingInstance: "WAN",
	}, resolve)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if b.bindDevice != "ge-0-0-2" {
		t.Fatalf("destination-interface must resolve to the kernel device for SO_BINDTODEVICE, got %q", b.bindDevice)
	}
	// routingInst keeps the RAW routing-instance name (informational only).
	if b.routingInst != "WAN" {
		t.Fatalf("routing-instance must be recorded (raw, informational), got %q", b.routingInst)
	}
}

func TestResolveBindConfigVRFOnlyBindsVRFDevice(t *testing.T) {
	b, err := resolveBindConfig(config.RFC2136Endpoint{RoutingInstance: "WAN"}, bindTestConfig().ResolveKernelIfName)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// A routing-instance binds to its kernel VRF master device "vrf-<name>"
	// (pkg/routing), NOT the raw routing-instance name (#5070).
	if b.bindDevice != "vrf-WAN" {
		t.Fatalf("a VRF-only config must bind to the vrf-<name> device, got %q", b.bindDevice)
	}
}

// TestResolveBindConfigResolvesKernelDevices is the #5070 fix-direction table:
// a committed Junos interface / routing-instance reference MUST resolve to the
// EXACT current kernel device name SO_BINDTODEVICE needs, via the committed
// config's SSOT resolver — NOT the leaf slash-substitution, which produces
// nonexistent devices for reth / VLAN-unit / unit-0 cases (the HA-cluster WAN
// binding is exactly reth-with-VLAN). Before the fix bindDevice held the raw
// Junos token and the dial hard-failed on a nonexistent device.
func TestResolveBindConfigResolvesKernelDevices(t *testing.T) {
	resolve := bindTestConfig().ResolveKernelIfName
	cases := []struct {
		name string
		cfg  config.DHCPDynamicDNSConfig
		want string
	}{
		// bare physical → slash-substituted.
		{"physical", config.DHCPDynamicDNSConfig{RFC2136Endpoint: config.RFC2136Endpoint{DestinationInterface: "ge-0/0/2"}}, "ge-0-0-2"},
		// unit-0 collapse: ".0" is stripped (kernel has no ".0" subif).
		{"unit-0-collapse", config.DHCPDynamicDNSConfig{RFC2136Endpoint: config.RFC2136Endpoint{DestinationInterface: "ge-0/0/2.0"}}, "ge-0-0-2"},
		// unit# ≠ vlan-id: unit 50 carries vlan-id 80, kernel subif is ".80".
		{"unit-neq-vlanid", config.DHCPDynamicDNSConfig{RFC2136Endpoint: config.RFC2136Endpoint{DestinationInterface: "ge-0/0/2.50"}}, "ge-0-0-2.80"},
		// reth → its LOCAL physical member (no bonded "reth1" kernel device).
		{"reth", config.DHCPDynamicDNSConfig{RFC2136Endpoint: config.RFC2136Endpoint{DestinationInterface: "reth1"}}, "ge-0-0-1"},
		// reth VLAN unit → member's VLAN subif (reth0 member ge-0/0/3, vlan-id 100).
		{"reth-vlan-unit", config.DHCPDynamicDNSConfig{RFC2136Endpoint: config.RFC2136Endpoint{DestinationInterface: "reth0.100"}}, "ge-0-0-3.100"},
		// RI-only → vrf-<name> master (no resolver needed for this half).
		{"ri-only", config.DHCPDynamicDNSConfig{RFC2136Endpoint: config.RFC2136Endpoint{RoutingInstance: "WAN"}}, "vrf-WAN"},
		// #16664: instance "vrf-red" → vrf-vrf-red (prefix unconditional);
		// "vrf-red" alone is sibling instance "red".
		{"ri-vrf-prefixed-instance", config.DHCPDynamicDNSConfig{RFC2136Endpoint: config.RFC2136Endpoint{RoutingInstance: "vrf-red"}}, "vrf-vrf-red"},
		// control: sibling "red" still binds its own device.
		{"ri-bare-sibling-control", config.DHCPDynamicDNSConfig{RFC2136Endpoint: config.RFC2136Endpoint{RoutingInstance: "red"}}, "vrf-red"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			b, err := resolveBindConfig(cfg.RFC2136Endpoint, resolve)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if b.bindDevice != tc.want {
				t.Fatalf("bindDevice = %q, want %q", b.bindDevice, tc.want)
			}
		})
	}
}

// TestNewRFC2136UpdaterValidatesBindDeviceExists proves the #5070
// construction-time existence check: a resolved bind device that netlink cannot
// find fails backend construction with a CLEAR error (naming the resolved
// kernel device) instead of a cryptic SO_BINDTODEVICE dial failure later. It
// threads the SSOT resolver so a reth binding resolves to its physical member,
// and uses the injectable netlink seam so the test needs no real interface.
func TestNewRFC2136UpdaterValidatesBindDeviceExists(t *testing.T) {
	pol := policyFromConfig(&config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com",
		RFC2136Endpoint: config.RFC2136Endpoint{
			UpdateServer: "192.0.2.53:53",
		},
	})
	resolve := bindTestConfig().ResolveKernelIfName

	// Seam: pretend only the reth1 physical member "ge-0-0-1" exists.
	orig := bindDeviceLinkByName
	t.Cleanup(func() { bindDeviceLinkByName = orig })
	bindDeviceLinkByName = func(name string) error {
		if name == "ge-0-0-1" {
			return nil
		}
		return fmt.Errorf("Link not found")
	}

	// Present device: reth1 → member "ge-0-0-1" (resolved) → constructs.
	ok := &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com",
		RFC2136Endpoint: config.RFC2136Endpoint{
			UpdateServer: "192.0.2.53:53",
			DestinationInterface: "reth1",
		},
	}
	if _, err := newRFC2136Updater(pol, ok.RFC2136Endpoint, nil, nil, nil, resolve); err != nil {
		t.Fatalf("a present bind device must construct, got %v", err)
	}

	// Absent device: ge-0/0/2 → "ge-0-0-2" (not in the seam) → clear error
	// naming the resolved kernel device.
	bad := &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com",
		RFC2136Endpoint: config.RFC2136Endpoint{
			UpdateServer: "192.0.2.53:53",
			DestinationInterface: "ge-0/0/2",
		},
	}
	_, err := newRFC2136Updater(pol, bad.RFC2136Endpoint, nil, nil, nil, resolve)
	if err == nil {
		t.Fatal("an absent bind device must fail newRFC2136Updater")
	}
	if !strings.Contains(err.Error(), "ge-0-0-2") {
		t.Fatalf("construction error must name the resolved kernel device, got %v", err)
	}
}

// TestNewRFC2136UpdaterInstallsCustomDialer proves the rfc2136 backend installs
// the source-binding dialer on its production *dns.Client when a binding is
// configured (and leaves the default dialer when none is). The client seam is
// nil here so newRFC2136Updater builds the real *dns.Client.
func TestNewRFC2136UpdaterInstallsCustomDialer(t *testing.T) {
	pol := policyFromConfig(&config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com",
		RFC2136Endpoint: config.RFC2136Endpoint{
			UpdateServer: "192.0.2.53:53",
		},
	})
	// With a binding configured → custom dialer installed.
	withBind := &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com",
		RFC2136Endpoint: config.RFC2136Endpoint{
			UpdateServer: "192.0.2.53:53",
			SourceAddress: "10.0.0.9",
		},
	}
	u, err := newRFC2136Updater(pol, withBind.RFC2136Endpoint, nil, nil, nil)
	if err != nil {
		t.Fatalf("newRFC2136Updater (with bind): %v", err)
	}
	cl, ok := u.client.(*dns.Client)
	if !ok {
		t.Fatalf("expected production *dns.Client, got %T", u.client)
	}
	if cl.Dialer == nil || cl.Dialer.Control == nil {
		t.Fatal("a configured source-address must install a custom dialer on the *dns.Client")
	}

	// With NO binding → default dialer (today's behaviour).
	noBind := &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com",
		RFC2136Endpoint: config.RFC2136Endpoint{
			UpdateServer: "192.0.2.53:53",
		},
	}
	u2, err := newRFC2136Updater(pol, noBind.RFC2136Endpoint, nil, nil, nil)
	if err != nil {
		t.Fatalf("newRFC2136Updater (no bind): %v", err)
	}
	cl2 := u2.client.(*dns.Client)
	if cl2.Dialer != nil {
		t.Fatal("no source-binding must leave the *dns.Client's default dialer (nil)")
	}
}

// TestNewRFC2136UpdaterInvalidSourceAddressErrors proves an invalid
// source-address is surfaced from the constructor so the manager falls back to
// no-op for that family rather than emitting UPDATEs from the wrong source.
func TestNewRFC2136UpdaterInvalidSourceAddressErrors(t *testing.T) {
	pol := policyFromConfig(&config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com",
		RFC2136Endpoint: config.RFC2136Endpoint{
			UpdateServer: "192.0.2.53:53",
		},
	})
	bad := &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com",
		RFC2136Endpoint: config.RFC2136Endpoint{
			UpdateServer: "192.0.2.53:53",
			SourceAddress: "garbage",
		},
	}
	if _, err := newRFC2136Updater(pol, bad.RFC2136Endpoint, nil, nil, nil); err == nil {
		t.Fatal("an invalid source-address must fail newRFC2136Updater")
	}
}

// TestSourceMatchesDialFamily proves the family gate keying off the
// Dialer.Control "network" argument: a v4 source matches a "4"-suffixed network
// and not a "6"-suffixed one (and vice-versa); an unsuffixed network permits the
// bind (no family hint, pre-#2901 behaviour).
func TestSourceMatchesDialFamily(t *testing.T) {
	v4 := netip.MustParseAddr("10.0.0.9")
	v6 := netip.MustParseAddr("2001:db8::9")
	cases := []struct {
		src     netip.Addr
		network string
		want    bool
	}{
		{v4, "tcp4", true}, {v4, "udp4", true},
		{v4, "tcp6", false}, {v4, "udp6", false},
		{v6, "tcp6", true}, {v6, "udp6", true},
		{v6, "tcp4", false}, {v6, "udp4", false},
		{v4, "tcp", true}, {v6, "udp", true}, // no family hint ⇒ permit
	}
	for _, c := range cases {
		if got := sourceMatchesDialFamily(c.src, c.network); got != c.want {
			t.Errorf("sourceMatchesDialFamily(%s, %q)=%v want %v", c.src, c.network, got, c.want)
		}
	}
}

// runDialerControl opens a real socket of the requested family, invokes the
// dialer's Control hook with the matching "network" string, and returns any
// error the hook surfaced. This exercises the exact unix.Bind path the issue
// describes, so the family gate is proven against the kernel (EAFNOSUPPORT is a
// kernel verdict, not a Go-level check).
func runDialerControl(t *testing.T, d *net.Dialer, family int, network string) error {
	t.Helper()
	fd, err := unix.Socket(family, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket(%d): %v", family, err)
	}
	defer unix.Close(fd)
	rc := rawConnFD(fd)
	return d.Control(network, "", rc)
}

// rawConnFD adapts a raw fd to the syscall.RawConn the Control hook expects. We
// only need Control(); Read/Write are unused by backend_bind's hook.
type rawConnFD int

func (r rawConnFD) Control(f func(fd uintptr)) error {
	f(uintptr(r))
	return nil
}
func (r rawConnFD) Read(func(fd uintptr) (done bool)) error  { return nil }
func (r rawConnFD) Write(func(fd uintptr) (done bool)) error { return nil }

var _ syscall.RawConn = rawConnFD(0)

// TestDialerSourceBindFamilyGate is the #2901 FAIL-ON-REVERT test. A
// source-address whose family MATCHES the dial network binds successfully (the
// source IP is applied — proven by reading it back with getsockname). A MISMATCH
// (v4 source on a v6 socket, and v6 source on a v4 socket) must NOT attempt the
// bind: it returns nil and the socket is left unbound. If the family gate is
// removed, the mismatch case attempts unix.Bind with the wrong-family Sockaddr
// and the kernel returns EAFNOSUPPORT (EINVAL on some kernels) — turning this
// test RED.
func TestDialerSourceBindFamilyGate(t *testing.T) {
	// A loopback source binds without needing the address assigned to an iface.
	b4, err := resolveBindConfig(config.RFC2136Endpoint{SourceAddress: "127.0.0.1"}, nil)
	if err != nil {
		t.Fatalf("resolve v4: %v", err)
	}
	d4 := b4.dialer(time.Second)
	if d4 == nil || d4.Control == nil {
		t.Fatal("v4 source must produce a Control dialer")
	}

	// MATCH: v4 source on an AF_INET / "tcp4" dial → bind applied, no error.
	if err := runDialerControl(t, d4, unix.AF_INET, "tcp4"); err != nil {
		t.Fatalf("v4 source on tcp4 must bind cleanly, got %v", err)
	}
	// MISMATCH: v4 source on an AF_INET6 / "tcp6" dial → bind SKIPPED, no error.
	// Without the family gate this attempts unix.Bind(SockaddrInet4) on an
	// AF_INET6 socket → EAFNOSUPPORT/EINVAL.
	if err := runDialerControl(t, d4, unix.AF_INET6, "tcp6"); err != nil {
		if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EINVAL) {
			t.Fatalf("v4 source on tcp6 must SKIP the bind (family gate), got family error %v", err)
		}
		t.Fatalf("v4 source on tcp6 must not error, got %v", err)
	}

	b6, err := resolveBindConfig(config.RFC2136Endpoint{SourceAddress: "::1"}, nil)
	if err != nil {
		t.Fatalf("resolve v6: %v", err)
	}
	d6 := b6.dialer(time.Second)
	if d6 == nil || d6.Control == nil {
		t.Fatal("v6 source must produce a Control dialer")
	}
	// MATCH: v6 source on an AF_INET6 / "tcp6" dial → bind applied, no error.
	if err := runDialerControl(t, d6, unix.AF_INET6, "tcp6"); err != nil {
		t.Fatalf("v6 source on tcp6 must bind cleanly, got %v", err)
	}
	// MISMATCH: v6 source on an AF_INET / "tcp4" dial → bind SKIPPED, no error.
	if err := runDialerControl(t, d6, unix.AF_INET, "tcp4"); err != nil {
		if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EINVAL) {
			t.Fatalf("v6 source on tcp4 must SKIP the bind (family gate), got family error %v", err)
		}
		t.Fatalf("v6 source on tcp4 must not error, got %v", err)
	}
}
