package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #15653 regression: TestDualStackPrimaryAddressAndNetlinkPromotion.
//
// RED on pre-fix: dual-stack inet6 primary was dropped into the shared
// PrimaryAddress slot (first-wins guard), non-first primaries installed
// as IFA_F_SECONDARY (authored add order), and a primary flip was a no-op
// (present[] short-circuit).

func compileDualStack15653(t *testing.T) *config.InterfaceUnit {
	t.Helper()
	input := "interfaces {\n" +
		"  ge-0/0/0 {\n" +
		"    unit 0 {\n" +
		"      family inet {\n" +
		"        address 10.0.0.1/24;\n" +
		"        address 10.0.0.2/24 { primary; }\n" +
		"        address 10.0.0.3/24 { preferred; }\n" +
		"      }\n" +
		"      family inet6 {\n" +
		"        address 2001:db8::1/64;\n" +
		"        address 2001:db8::2/64 { primary; }\n" +
		"        address 2001:db8::3/64 { preferred; }\n" +
		"      }\n" +
		"    }\n" +
		"  }\n" +
		"}\n" +
		"security { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }\n"
	p := config.NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	unit := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
	if unit == nil {
		t.Fatal("unit 0 missing")
	}
	dualStackCfg15653 = cfg
	return unit
}

var dualStackCfg15653 *config.Config

func TestDualStackPrimaryAddressAndNetlinkPromotion(t *testing.T) {
	unit := compileDualStack15653(t)

	// (a) per-family primaries compiled.
	if unit.PrimaryAddress != "10.0.0.2/24" {
		t.Errorf("PrimaryAddress=%q want 10.0.0.2/24", unit.PrimaryAddress)
	}
	if unit.PrimaryAddressV6 != "2001:db8::2/64" {
		t.Errorf("PrimaryAddressV6=%q want 2001:db8::2/64 (inet6 primary dropped on dual-stack)", unit.PrimaryAddressV6)
	}
	if unit.PreferredAddress != "10.0.0.3/24" {
		t.Errorf("PreferredAddress=%q want 10.0.0.3/24", unit.PreferredAddress)
	}
	if unit.PreferredAddressV6 != "2001:db8::3/64" {
		t.Errorf("PreferredAddressV6=%q want 2001:db8::3/64", unit.PreferredAddressV6)
	}
	if got := unit.PrimaryAddressForFamily(true); got != "2001:db8::2/64" {
		t.Errorf("PrimaryAddressForFamily(true)=%q", got)
	}
	if got := unit.PrimaryAddressForFamily(false); got != "10.0.0.2/24" {
		t.Errorf("PrimaryAddressForFamily(false)=%q", got)
	}
	// physDesired carries per-family primaries.
	pd := planPhysDesired(dualStackCfg15653)["ge-0-0-0"]
	if pd == nil {
		t.Fatal("no physDesired for ge-0-0-0")
	}
	if pd.primaryV4 != "10.0.0.2/24" || pd.primaryV6 != "2001:db8::2/64" {
		t.Errorf("physDesired primaries v4=%q v6=%q", pd.primaryV4, pd.primaryV6)
	}
	// networkd model carries both. Seed the interface cache so
	// buildInterfaceNetworkdModels does not skip the nonexistent device.
	result := newValidationResult()
	result.ifCache["ge-0-0-0"] = &net.Interface{Name: "ge-0-0-0", Index: 99, HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	seen := map[string]bool{}
	buildInterfaceNetworkdModels(dualStackCfg15653, result, seen)
	var model *networkd.InterfaceConfig
	for i := range result.ManagedInterfaces {
		if result.ManagedInterfaces[i].Name == "ge-0-0-0" {
			model = &result.ManagedInterfaces[i]
		}
	}
	if model == nil {
		t.Fatal("no networkd model for ge-0-0-0")
	}
	if model.PrimaryAddress != "10.0.0.2/24" || model.PrimaryAddressV6 != "2001:db8::2/64" {
		t.Errorf("model primaries v4=%q v6=%q", model.PrimaryAddress, model.PrimaryAddressV6)
	}
	if model.PreferredAddressV6 != "2001:db8::3/64" {
		t.Errorf("model PreferredAddressV6=%q", model.PreferredAddressV6)
	}

	// (b) fresh install: adds ordered primary-first per subnet.
	desired := []string{"10.0.0.1/24", "10.0.0.2/24", "2001:db8::1/64", "2001:db8::2/64"}
	_, add, _ := planAddressReconcile(nil, desired, "ge-0-0-0", "10.0.0.2/24", "2001:db8::2/64")
	if len(add) != 4 {
		t.Fatalf("fresh add count=%d want 4", len(add))
	}
	if add[0].IPNet.String() != "10.0.0.2/24" {
		t.Errorf("first add=%s want primary 10.0.0.2/24 first (else IFA_F_SECONDARY)", add[0].IPNet.String())
	}
	// v6 primary must precede its subnet peer.
	v6First, v6Peer := -1, -1
	for i, a := range add {
		switch a.IPNet.String() {
		case "2001:db8::2/64":
			v6First = i
		case "2001:db8::1/64":
			v6Peer = i
		}
	}
	if v6First < 0 || v6Peer < 0 || v6First > v6Peer {
		t.Errorf("v6 primary order idx=%d peer=%d in %v", v6First, v6Peer, add)
	}

	// (c) primary flip: existing .1 primary (no flag), .2 secondary;
	// desired primary is .2 -> delete+re-add, not no-op.
	mk := func(cidr string, flags int) netlink.Addr {
		a, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatal(err)
		}
		a.Flags = flags
		return *a
	}
	existing := []netlink.Addr{
		mk("10.0.0.1/24", 0),
		mk("10.0.0.2/24", unix.IFA_F_SECONDARY),
	}
	del, add2, _ := planAddressReconcile(existing, []string{"10.0.0.1/24", "10.0.0.2/24"}, "ge-0-0-0", "10.0.0.2/24", "")
	if len(del) == 0 || len(add2) == 0 {
		t.Fatalf("primary flip must delete+re-add, got del=%d add=%d (no-op flip)", len(del), len(add2))
	}
	foundDel2, foundAdd2 := false, false
	for _, d := range del {
		if d.IPNet.String() == "10.0.0.2/24" {
			foundDel2 = true
		}
	}
	for _, a := range add2 {
		if a.IPNet.String() == "10.0.0.2/24" {
			foundAdd2 = true
		}
	}
	if !foundDel2 || !foundAdd2 {
		t.Errorf("flip must delete and re-add 10.0.0.2/24: del2=%v add2=%v del=%v add=%v", foundDel2, foundAdd2, del, add2)
	}
	if len(add2) == 0 || add2[0].IPNet.String() != "10.0.0.2/24" {
		t.Errorf("promoted primary must be added first, add=%v", add2)
	}

	// Control: already-primary (no SECONDARY) is converged (empty plan).
	existingOK := []netlink.Addr{mk("10.0.0.2/24", 0), mk("10.0.0.1/24", unix.IFA_F_SECONDARY)}
	del3, add3, _ := planAddressReconcile(existingOK, []string{"10.0.0.1/24", "10.0.0.2/24"}, "ge-0-0-0", "10.0.0.2/24", "")
	if len(del3) != 0 || len(add3) != 0 {
		t.Errorf("converged primary must be empty plan, got del=%d add=%d", len(del3), len(add3))
	}
	// Control: no primaries -> legacy converged empty.
	del4, add4, _ := planAddressReconcile(existing, []string{"10.0.0.1/24", "10.0.0.2/24"}, "ge-0-0-0")
	if len(del4) != 0 || len(add4) != 0 {
		t.Errorf("no-primary converged must be empty, got del=%d add=%d", len(del4), len(add4))
	}
}
