package routing

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sys/unix"
)

// TestNextTableRulesIngressScope_9420 pins the #9420 contract at the applier:
// every next-table leak rule carries an FRA_IIFNAME naming an ingress interface
// of the instance that authored the leak, and NO rule is ever emitted without
// one.
//
// The shape of the defect, not just an outcome: the assertion below is TOTAL
// over the emitted rules ("no rule may have an empty IifName"), because a
// count- or presence-based check cannot tell a correctly-scoped set from a set
// where one unscoped rule slipped through — and one unscoped rule at priority
// 100 is the whole finding.
func TestNextTableRulesIngressScope_9420(t *testing.T) {
	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}

	routes := []*config.StaticRoute{
		{Destination: "10.20.0.0/16", NextTable: "dmz-vr"},
		{Destination: "2001:db8::/32", NextTable: "dmz-vr"},
	}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}
	iifs := []string{"ge-0-0-0", "ge-0-0-1.50"}

	if err := nt.Apply(routes, instances, iifs); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		got := ops.rules[family]
		if len(got) != len(iifs) {
			t.Fatalf("family %d: expected one rule per ingress interface (%d), got %d: %v",
				family, len(iifs), len(got), got)
		}
		seen := map[string]bool{}
		for _, r := range got {
			// TOTAL: no success path may emit an unscoped rule.
			if r.IifName == "" {
				t.Errorf("family %d: rule %v carries NO ingress scope; a pref-%d "+
					"iif-less rule steers traffic from every other routing instance "+
					"into table %d (#9420)", family, r, r.Priority, r.Table)
			}
			if r.Table != 101 {
				t.Errorf("family %d: rule %v targets table %d, want 101", family, r, r.Table)
			}
			seen[r.IifName] = true
		}
		for _, want := range iifs {
			if !seen[want] {
				t.Errorf("family %d: no rule scoped to ingress interface %q; rules=%v",
					family, want, got)
			}
		}
	}
}

// TestNextTableRulesFailClosedWithoutIngress_9420 pins the #5117 posture the
// fix copies: with no resolvable ingress interface, install NOTHING rather than
// a global iif-less rule. The fail-safe direction is an under-steer.
//
// The second sub-case is the control that stops the gate from being a blanket
// "next-table is broken now": a config with NO eligible leak must apply
// silently, so an operator with zero next-table statics never sees a degraded
// commit for a leak that does not exist.
func TestNextTableRulesFailClosedWithoutIngress_9420(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	t.Run("eligible leak with no ingress interface refuses to install", func(t *testing.T) {
		ops := newFakeRuleOps()
		nt := &nextTableManager{ops: ops}
		routes := []*config.StaticRoute{{Destination: "10.20.0.0/16", NextTable: "dmz-vr"}}

		err := nt.Apply(routes, instances, nil)
		if err == nil {
			t.Fatal("Apply must report a degraded result when the leak cannot be ingress-scoped")
		}
		if !strings.Contains(err.Error(), "iif-less") {
			t.Errorf("degraded error should name the refused shape, got %q", err)
		}
		if n := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); n != 0 {
			t.Fatalf("expected NO rules installed, got %d: %v", n, ops.rules)
		}
	})

	t.Run("no eligible leak applies silently", func(t *testing.T) {
		ops := newFakeRuleOps()
		nt := &nextTableManager{ops: ops}
		routes := []*config.StaticRoute{
			{Destination: "10.0.0.0/8"},                            // no next-table
			{Destination: "10.99.0.0/16", NextTable: "unknown-vr"}, // unknown instance
		}
		if err := nt.Apply(routes, instances, nil); err != nil {
			t.Fatalf("a config with no eligible next-table leak must apply cleanly, got %v", err)
		}
	})
}

// TestNextTableWindowIsLeakAtomic_9420 pins that a leak whose full ingress
// expansion does not fit the priority window is dropped WHOLE, never installed
// on a subset of its interfaces. A partially-scoped leak works on some ingress
// interfaces and silently not on others.
func TestNextTableWindowIsLeakAtomic_9420(t *testing.T) {
	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}

	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}
	// 3 interfaces × 34 leaks = 102 > the 100-slot window, so the 34th leak
	// must not install at all (33 × 3 = 99 rules).
	iifs := []string{"ge-0-0-0", "ge-0-0-1", "ge-0-0-2"}
	var routes []*config.StaticRoute
	for i := 0; i < 34; i++ {
		routes = append(routes, &config.StaticRoute{
			Destination: mk9420Prefix(i), NextTable: "dmz-vr",
		})
	}

	err := nt.Apply(routes, instances, iifs)
	if err == nil {
		t.Fatal("expected a degraded overflow error")
	}
	if !strings.Contains(err.Error(), "ingress interface") {
		t.Errorf("the overflow error must name the per-interface multiplier so the "+
			"operator can see why the effective leak capacity dropped, got %q", err)
	}
	got := ops.count(unix.AF_INET)
	if got%len(iifs) != 0 {
		t.Fatalf("truncation split a leak across interfaces: %d rules is not a "+
			"multiple of %d", got, len(iifs))
	}
	if got != 99 {
		t.Fatalf("expected 33 whole leaks (99 rules), got %d", got)
	}
}

func mk9420Prefix(i int) string {
	return "10." + itoa9420(i) + ".0.0/16"
}

func itoa9420(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestDefaultInstanceIngressIfaces_9420 pins the scoping SET: units claimed by
// a routing instance are excluded (they are that instance's ingress, not the
// default instance's), everything else is included, and the result is sorted
// and de-duplicated so ip-rule priorities are stable across applies.
func TestDefaultInstanceIngressIfaces_9420(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}, 50: {Number: 50, VlanID: 50}}},
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101, Interfaces: []string{"ge-0/0/2"}},
	}

	got := DefaultInstanceIngressIfaces(cfg)
	want := []string{"ge-0-0-0", "ge-0-0-1", "ge-0-0-1.50"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}

	// Control: with EVERY interface claimed by an instance, the default
	// instance has no ingress and the applier's fail-closed gate arms.
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101, Interfaces: []string{"ge-0/0/0", "ge-0/0/1", "ge-0/0/2"}},
	}
	if got := DefaultInstanceIngressIfaces(cfg); len(got) != 0 {
		t.Fatalf("expected no default-instance ingress, got %v", got)
	}
}

// TestNextTableIngressScopeOnRealKernel_9420 is the kernel half: the B1/B2/B3
// cells from the issue, executed in a private netns, plus the fix.
//
// It is skipped when the environment cannot create a user+net namespace. Every
// DIVERSION verdict is scored against a control in the SAME run — "the packet
// resolved in the target table" and "my probe was malformed" otherwise read the
// same, and so do "the leak is scoped" and "the topology has no route anyway".
func TestNextTableIngressScopeOnRealKernel_9420(t *testing.T) {
	if _, err := exec.LookPath("unshare"); err != nil {
		if os.Getenv("XPF_REQUIRE_NETNS") != "" {
			t.Fatalf("unshare not available (XPF_REQUIRE_NETNS is set)")
		}
		t.Skip("unshare not available")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		if os.Getenv("XPF_REQUIRE_NETNS") != "" {
			t.Fatalf("iproute2 not available (XPF_REQUIRE_NETNS is set)")
		}
		t.Skip("iproute2 not available")
	}
	script := `set -e
ip link add duma type dummy; ip link add dumb type dummy; ip link add dumc type dummy
ip link add vrf-b type vrf table 200; ip link add vrf-c type vrf table 300
ip link set vrf-b up; ip link set vrf-c up
ip link set dumb master vrf-b; ip link set dumc master vrf-c
ip link set duma up; ip link set dumb up; ip link set dumc up; ip link set lo up
ip addr add 10.10.0.2/24 dev duma; ip addr add 10.20.0.2/24 dev dumb; ip addr add 10.30.0.2/24 dev dumc
ip route add 10.9.0.0/16 via 10.20.0.1 dev dumb table 200
g() { ip route get "$@" 2>&1 | head -1; }
echo "A_BASELINE_VRFC=$(g 10.9.0.1 from 10.30.0.77 iif dumc)"
ip rule add to 10.9.0.0/16 table 200 pref 100
echo "B1_UNSCOPED_VRFC=$(g 10.9.0.1 from 10.30.0.77 iif dumc)"
ip route add 10.9.0.0/16 dev dumc table 300
echo "B2_UNSCOPED_VRFC_OWNROUTE=$(g 10.9.0.1 from 10.30.0.77 iif dumc)"
ip route del 10.9.0.0/16 dev dumc table 300
echo "B1B_UNSCOPED_DEFAULT=$(g 10.9.0.1 from 10.10.0.77 iif duma)"
ip rule del to 10.9.0.0/16 table 200 pref 100
echo "B3_CONTROL_NORULE_VRFC=$(g 10.9.0.1 from 10.30.0.77 iif dumc)"
ip rule add to 10.9.0.0/16 iif duma table 200 pref 100
echo "F1A_SCOPED_DEFAULT=$(g 10.9.0.1 from 10.10.0.77 iif duma)"
echo "F1B_SCOPED_VRFC=$(g 10.9.0.1 from 10.30.0.77 iif dumc)"
ip route add 10.9.0.0/16 dev dumc table 300
echo "F1C_SCOPED_VRFC_OWNROUTE=$(g 10.9.0.1 from 10.30.0.77 iif dumc)"
`
	out, err := exec.Command("unshare", "-rn", "bash", "-c", script).CombinedOutput()
	if err != nil {
		if os.Getenv("XPF_REQUIRE_NETNS") == "" {
			t.Skipf("netns unavailable (%v): %s", err, out)
		}
		t.Fatalf("netns setup failed: %v\n%s", err, out)
	}
	got := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			got[k] = v
		}
	}
	leaked := func(k string) bool { return strings.Contains(got[k], "table 200") }

	// Controls first: the probe reaches the FIB at all, and the diversion is
	// not an artifact of the topology.
	if leaked("A_BASELINE_VRFC") {
		t.Fatalf("A: VRF-C must not reach table 200 with no rule installed: %q", got["A_BASELINE_VRFC"])
	}
	if leaked("B3_CONTROL_NORULE_VRFC") {
		t.Fatalf("B3 control: removing the rule must remove the diversion: %q", got["B3_CONTROL_NORULE_VRFC"])
	}
	// The defect, reproduced.
	if !leaked("B1_UNSCOPED_VRFC") {
		t.Fatalf("B1: an UNSCOPED pref-100 rule must divert VRF-C ingress into "+
			"table 200 — if this does not reproduce, the probe is not measuring "+
			"the finding: %q", got["B1_UNSCOPED_VRFC"])
	}
	if !leaked("B2_UNSCOPED_VRFC_OWNROUTE") {
		t.Fatalf("B2: the unscoped rule must win even when VRF-C has its OWN "+
			"route for the prefix: %q", got["B2_UNSCOPED_VRFC_OWNROUTE"])
	}
	// The fix.
	if !leaked("F1A_SCOPED_DEFAULT") {
		t.Fatalf("F1a POSITIVE CONTROL: the leak must still work for ingress on "+
			"the authoring instance's interface — without this, F1b below is "+
			"satisfied by a rule that simply does nothing: %q", got["F1A_SCOPED_DEFAULT"])
	}
	if leaked("F1B_SCOPED_VRFC") {
		t.Fatalf("F1b: an iif-scoped rule must NOT divert VRF-C ingress: %q", got["F1B_SCOPED_VRFC"])
	}
	if leaked("F1C_SCOPED_VRFC_OWNROUTE") {
		t.Fatalf("F1c: VRF-C with its own route must use it: %q", got["F1C_SCOPED_VRFC_OWNROUTE"])
	}
	if !strings.Contains(got["F1C_SCOPED_VRFC_OWNROUTE"], "table 300") {
		t.Errorf("F1c: VRF-C should resolve in its own table 300, got %q", got["F1C_SCOPED_VRFC_OWNROUTE"])
	}
}
