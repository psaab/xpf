package dhcprelay

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #9406. `forwarding-options dhcp-relay group <g> interface <ref>` is the
// relay's bind key, and the compiler stores the AUTHORED reference. Under the
// canonical Junos spelling that is a LOGICAL interface — `ge-0/0/0.0`,
// `reth0.0` — which net.InterfaceByName and SO_BINDTODEVICE cannot find: no
// listener binds, no giaddr resolves, nothing is relayed, on a commit that all
// four config channels ACCEPT with no warning.
//
// This is the #4049 CLASS (LLDP, same silent-name-mismatch shape) but NOT the
// #4049 REMEDY. LLDP references are physical interfaces, so
// `config.LinuxIfName` sufficed there. Measured here:
//
//	LinuxIfName("ge-0/0/0.0")          = "ge-0-0-0.0"   <- still not a device
//	ResolveKernelIfName("ge-0/0/0.0")  = "ge-0-0-0"     <- unit-0 collapse
//	ResolveKernelIfName("ge-0/0/0.80") = "ge-0-0-0.180" <- .<vlan-id>, not .80
//
// A relay member needs the unit-0 collapse and the vlan-id arm, so the fix is
// the canonical resolver, not the slash rewrite.

// cfg9406 declares the interfaces the resolution arms need: a unit-0 ref, a
// tagged unit whose NUMBER differs from its vlan-id (#5107), and a RETH.
func cfg9406(t *testing.T) *config.Config {
	t.Helper()
	text := `
interfaces {
    ge-0/0/0 {
        vlan-tagging;
        unit 0 { family inet { address 10.0.1.1/24; } }
        unit 80 { vlan-id 180; family inet { address 10.0.80.1/24; } }
    }
    ge-0/0/2 { gigether-options { redundant-parent reth0; } }
    reth0 {
        unit 0 { family inet { address 10.0.2.1/24; } }
    }
}
`
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("fixture must compile: %v", err)
	}
	return cfg
}

func relayCfg9406(ifaces ...string) *config.DHCPRelayConfig {
	return &config.DHCPRelayConfig{
		ServerGroups: map[string]*config.DHCPRelayServerGroup{
			"sg": {Name: "sg", Servers: []string{"192.0.2.1"}},
		},
		Groups: map[string]*config.DHCPRelayGroup{
			"g": {Name: "g", Interfaces: ifaces, ActiveServerGroup: "sg"},
		},
	}
}

// TestDesiredSetResolvesBindNameKeepsIdentity9406 pins BOTH halves. Resolving
// the bind target is the fix; resolving the KEY would be a regression, because
// the desired-set key is the relay's identity everywhere downstream — the
// #2348 Apply diff, the Stats row, and pkg/daemon's relayInterfaceRG, which
// parses it as a Junos unit ref to find the owning redundancy group. A kernel
// name is not a key in cfg.Interfaces.Interfaces, so keying on it would return
// RG 0 for every RETH-owned segment and silently open the #2456 HA gate on the
// backup node — duplicate upstream relays with two different giaddrs.
func TestDesiredSetResolvesBindNameKeepsIdentity9406(t *testing.T) {
	cfg := cfg9406(t)
	for _, tc := range []struct{ ref, wantKernel string }{
		{"ge-0/0/0.0", "ge-0-0-0"},
		{"ge-0/0/0.80", "ge-0-0-0.180"},
		{"reth0.0", "ge-0-0-2"},
		{"ge-0-0-0", "ge-0-0-0"}, // already kernel-form: idempotent
	} {
		desired := computeDesired(relayCfg9406(tc.ref), cfg.ResolveKernelIfName)
		d, ok := desired[tc.ref]
		if !ok {
			t.Fatalf("desired set is keyed on %v, not the authored reference %q — "+
				"that identity is what relayInterfaceRG and the #2456 HA gate read",
				keysOf9406(desired), tc.ref)
		}
		if d.ifaceName != tc.ref {
			t.Errorf("ifaceName = %q, want the authored reference %q", d.ifaceName, tc.ref)
		}
		if d.kernelName != tc.wantKernel {
			t.Errorf("kernelName for %q = %q, want %q", tc.ref, d.kernelName, tc.wantKernel)
		}
		if d.spec.kernelName != tc.wantKernel {
			t.Errorf("spec.kernelName for %q = %q, want %q — the bind target must be "+
				"part of the spec or a retag never restarts the relay",
				tc.ref, d.spec.kernelName, tc.wantKernel)
		}
	}
}

func keysOf9406(m map[string]desiredRelay) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestNilResolverIsIdentity9406 pins the compatibility default: a Manager
// driven without a resolver behaves exactly as it did before #9406, so the ~50
// direct Apply call sites in this package's tests stay meaningful.
func TestNilResolverIsIdentity9406(t *testing.T) {
	desired := computeDesired(relayCfg9406("ge-0/0/0.0"), nil)
	d, ok := desired["ge-0/0/0.0"]
	if !ok {
		t.Fatalf("desired = %v", keysOf9406(desired))
	}
	if d.kernelName != "ge-0/0/0.0" {
		t.Fatalf("kernelName = %q, want the identity fallback %q", d.kernelName, "ge-0/0/0.0")
	}
}

// TestRetagRestartsTheRelay9406: a vlan-id edit changes the bind DEVICE without
// changing any other spec field. If kernelName is not part of relaySpec.equal,
// the #2348 reconcile sees "unchanged" and leaves the relay bound to the OLD
// VLAN device — serving the wrong segment, with healthy-looking counters.
func TestRetagRestartsTheRelay9406(t *testing.T) {
	a := relaySpec{servers: []string{"192.0.2.1"}, kernelName: "ge-0-0-0.180"}
	b := relaySpec{servers: []string{"192.0.2.1"}, kernelName: "ge-0-0-0.181"}
	if a.equal(b) {
		t.Fatal("two specs binding DIFFERENT kernel devices compared equal: the " +
			"reconcile would leave the relay on the old VLAN device after a retag")
	}
	if !a.equal(relaySpec{servers: []string{"192.0.2.1"}, kernelName: "ge-0-0-0.180"}) {
		t.Fatal("identical specs compared unequal: every commit would churn every relay")
	}
}

// TestRelayBindsTheKernelDevice9406 is the cell that matters: it asserts what
// the RUNTIME hands the kernel, not what the desired set computed. A correct
// desired set whose kernelName nothing reads is exactly the pre-#9406 defect.
func TestRelayBindsTheKernelDevice9406(t *testing.T) {
	cfg := cfg9406(t)

	var mu sync.Mutex
	var bindNames, giaddrNames, ifindexNames, l2Names []string
	rec := func(dst *[]string) func(string) {
		return func(s string) {
			mu.Lock()
			*dst = append(*dst, s)
			mu.Unlock()
		}
	}
	recBind, recGiaddr, recIfindex, recL2 :=
		rec(&bindNames), rec(&giaddrNames), rec(&ifindexNames), rec(&l2Names)

	m := NewManager()
	m.retryInterval = time.Millisecond
	m.ifindexCheck = time.Hour
	m.newConn = func(ctx context.Context, ifaceName string, reusePort, broadcast bool,
		bindAddr *net.UDPAddr) (net.PacketConn, error) {
		if ifaceName != "" { // the server-facing conn binds no device
			recBind(ifaceName)
		}
		return newFakeConn(), nil
	}
	m.resolveGIAddr = func(ifaceName string) (net.IP, error) {
		recGiaddr(ifaceName)
		return net.IPv4(10, 0, 0, 254), nil
	}
	m.resolveIfindex = func(ifaceName string) (int, error) {
		recIfindex(ifaceName)
		return 100, nil
	}
	m.newL2 = func(ifaceName string) (l2Replier, error) {
		recL2(ifaceName)
		return &fakeL2{}, nil
	}
	m.SetIfNameResolver(cfg.ResolveKernelIfName)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Apply(ctx, relayCfg9406("ge-0/0/0.80"))
	defer m.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := len(bindNames) > 0 && len(giaddrNames) > 0 && len(ifindexNames) > 0
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	const want = "ge-0-0-0.180"
	for _, c := range []struct {
		what string
		got  []string
	}{
		{"SO_BINDTODEVICE", bindNames},
		{"giaddr address lookup", giaddrNames},
		{"#2347 ifindex drift check", ifindexNames},
	} {
		if len(c.got) == 0 {
			t.Fatalf("%s was never called — this cell measured nothing", c.what)
		}
		for _, got := range c.got {
			if got != want {
				t.Errorf("%s was handed %q, want the kernel device %q. The authored "+
					"reference `ge-0/0/0.80` is not a device: unit 80 carries "+
					"`vlan-id 180`, so the netdev is %q (#9406/#5107).",
					c.what, got, want, want)
			}
		}
	}

	// The identity surfaced to the operator stays the authored reference, with
	// the bound device reported beside it.
	stats := m.Stats()
	if len(stats) != 1 {
		t.Fatalf("Stats() = %+v, want one row", stats)
	}
	if stats[0].Interface != "ge-0/0/0.80" {
		t.Errorf("Stats().Interface = %q, want the authored reference", stats[0].Interface)
	}
	if stats[0].KernelInterface != want {
		t.Errorf("Stats().KernelInterface = %q, want %q — an all-zero counter row "+
			"with no bound device shown is indistinguishable from an idle segment",
			stats[0].KernelInterface, want)
	}
}
