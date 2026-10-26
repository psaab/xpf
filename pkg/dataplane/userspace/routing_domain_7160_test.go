package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7160 (#2387) — the ROUTING DOMAIN a session key is discriminated by.
//
// The number is decided HERE, in Go, and shipped per interface on the config
// snapshot; the Rust dataplane folds it into `SessionKey.routing_domain` and
// never re-derives it. These cells guard the three properties that decision
// rests on, each of which is invisible to every pre-existing test because
// every one of them runs with no routing-instance interface membership.

func routingDomainCfg7160(t *testing.T, cmds ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// The default instance MUST be domain 0, and a named instance MUST NOT be.
//
// This is the whole reason 0 can double as "the default routing instance"
// rather than needing a separate "unknown" sentinel: a snapshot from an older
// Go binary omits the field, an interface in no instance never sets it, and a
// peer whose ingress identity could not be resolved imports at 0 — all three
// have to mean the same, correct thing. If a named instance could ever hash to
// 0 that conflation would silently place a tenant's flow in the default
// instance's session space, which is the collision this field exists to close.
func TestRoutingInstanceDomainReservesZeroForTheDefaultInstance7160(t *testing.T) {
	if got := routingInstanceDomain(""); got != 0 {
		t.Fatalf("routingInstanceDomain(\"\") = %d, want 0 (the default instance)", got)
	}
	// The band is the guarantee, not a spot check: EVERY named instance lands
	// in [Base, Base+Span), which starts well above 0.
	if config.RoutingInstanceTableIDBase <= 0 {
		t.Fatalf("RoutingInstanceTableIDBase = %d; a band including 0 would let a "+
			"named instance collide with the default instance",
			config.RoutingInstanceTableIDBase)
	}
	for _, name := range []string{
		"tenant-a", "tenant-b", "ISP-B", "vr1", "0", "default", "x",
		"a-very-long-routing-instance-name-that-hashes-somewhere-else",
	} {
		got := routingInstanceDomain(name)
		if got == 0 {
			t.Fatalf("routingInstanceDomain(%q) = 0, which is the default "+
				"instance's domain — a tenant would share the default "+
				"instance's session space", name)
		}
		if got < uint32(config.RoutingInstanceTableIDBase) ||
			got >= uint32(config.RoutingInstanceTableIDBase+config.RoutingInstanceTableIDSpan) {
			t.Fatalf("routingInstanceDomain(%q) = %d, outside the reserved band [%d,%d)",
				name, got, config.RoutingInstanceTableIDBase,
				config.RoutingInstanceTableIDBase+config.RoutingInstanceTableIDSpan)
		}
	}
}

// The domain must BE `StableRoutingInstanceTableID`, not merely resemble it.
//
// Asserted as an AGREEMENT rather than against pinned literals on purpose: a
// literal would encode which of the two spellings is trusted, and the point of
// reusing the stable table id is that there is only ONE spelling — already
// gated at commit against name collisions
// (validateRoutingInstanceTableIDCollisionAST). Fork the two and this cell
// goes red without anyone having to guess the new numbers.
func TestRoutingInstanceDomainIsTheStableTableID7160(t *testing.T) {
	for _, name := range []string{"tenant-a", "tenant-b", "ISP-B", "vr1"} {
		want := uint32(config.StableRoutingInstanceTableID(name))
		if got := routingInstanceDomain(name); got != want {
			t.Fatalf("routingInstanceDomain(%q) = %d, want StableRoutingInstanceTableID = %d. "+
				"The domain must be the SAME number the routing-instance table id is, so the "+
				"commit-time collision gate covers it and both HA nodes compute it identically.",
				name, got, want)
		}
	}
	// Distinct names must give distinct domains for the discriminator to
	// discriminate at all. (The commit gate is what makes this an invariant
	// rather than a hope; this is the shape of what it enforces.)
	if routingInstanceDomain("tenant-a") == routingInstanceDomain("tenant-b") {
		t.Fatal("tenant-a and tenant-b hash to the same routing domain — two tenants " +
			"would share one conntrack identity, which is #2387 verbatim")
	}
}

// End to end: the per-interface snapshot the Rust dataplane consumes carries
// the domain, on BOTH the physical row and the logical unit row, and carries 0
// for an interface in no routing instance.
//
// The unit row is the one that matters at runtime — `ifindex_to_routing_domain`
// is keyed by the LOGICAL ifindex, exactly like the zone / filter / pre-routing
// NAT ingress identity — so a fix that stamped only the physical row would
// leave every VLAN unit in domain 0 and this cell would not see it if it only
// checked one row.
func TestInterfaceSnapshotCarriesTheRoutingDomain7160(t *testing.T) {
	cfg := routingDomainCfg7160(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/24",
		"set routing-instances tenant-a instance-type virtual-router",
		"set routing-instances tenant-a interface ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
	)
	wantA := uint32(config.StableRoutingInstanceTableID("tenant-a"))

	var sawMember, sawUnmapped bool
	for _, snap := range buildInterfaceSnapshots(cfg) {
		switch snap.RoutingInstance {
		case "tenant-a":
			sawMember = true
			if snap.RoutingDomain != wantA {
				t.Fatalf("snapshot %q (instance tenant-a) RoutingDomain = %d, want %d",
					snap.Name, snap.RoutingDomain, wantA)
			}
		case "":
			sawUnmapped = true
			if snap.RoutingDomain != 0 {
				t.Fatalf("snapshot %q is in NO routing instance but carries domain %d; "+
					"it must be 0, the default instance", snap.Name, snap.RoutingDomain)
			}
		default:
			t.Fatalf("unexpected routing instance %q on %q", snap.RoutingInstance, snap.Name)
		}
	}
	if !sawMember {
		t.Fatal("no interface snapshot carried routing instance tenant-a — the fixture " +
			"does not exercise the member-interface path this cell is about")
	}
	if !sawUnmapped {
		t.Fatal("no interface snapshot was outside a routing instance — the fixture " +
			"cannot show that the default instance still reads 0")
	}
}

// A config with NO routing-instance interface membership must produce domain 0
// everywhere, which is what makes #7160 bit-identical to pre-#7160 for the
// overwhelming majority of deployments (and for the HA smoke cluster).
func TestNoRoutingInstanceMembershipLeavesEveryDomainZero7160(t *testing.T) {
	cfg := routingDomainCfg7160(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 50 vlan-id 50",
		"set interfaces ge-0/0/1 unit 50 family inet address 172.16.50.8/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.50",
	)
	snaps := buildInterfaceSnapshots(cfg)
	if len(snaps) == 0 {
		t.Fatal("fixture produced no interface snapshots")
	}
	for _, snap := range snaps {
		if snap.RoutingDomain != 0 {
			t.Fatalf("snapshot %q carries routing domain %d in a config with no "+
				"routing-instance interface membership; every such deployment must "+
				"keep byte-identical session identity", snap.Name, snap.RoutingDomain)
		}
	}
}
