package daemon

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// foldFixture9821 builds the both-declared receiver topology: `p.0` with a
// vlan-100 child, separately-declared `p.0.2`, and (for the truncation shape)
// `p` — plus the fake host devices for each.
func foldFixture9821(withTruncation bool) (*config.Config, []net.Interface) {
	ifaces := map[string]*config.InterfaceConfig{
		"p.0": {Name: "p.0", Units: map[int]*config.InterfaceUnit{
			0:   {Number: 0},
			100: {Number: 100, VlanID: 100},
		}},
		"p.0.2": {Name: "p.0.2", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	devs := []net.Interface{
		{Index: 90, Name: "p.0"},
		{Index: 91, Name: "p.0.2"},
	}
	if withTruncation {
		ifaces["p"] = &config.InterfaceConfig{Name: "p", Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0},
			50: {Number: 50, VlanID: 50},
		}}
		devs = append(devs, net.Interface{Index: 89, Name: "p"})
	}
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: ifaces}}
	return cfg, devs
}

// TestIngressFoldDottedTuples9821 drives the REAL install path (extracted
// builder + fake devices): a dotted bare installs its OWN device with vlan 0
// (no split); the enum's vlan-child candidate installs parent+vlan; and with
// a separately-declared truncation present the dotted name still installs its
// own device — never the truncation's.
func TestIngressFoldDottedTuples9821(t *testing.T) {
	for _, trunc := range []bool{false, true} {
		cfg, devs := foldFixture9821(trunc)
		resolve := buildIngressFoldResolverWithIfaces(cfg, devs)
		cases := []struct {
			stable      string
			wantIfindex uint32
			wantVlan    uint16
		}{
			{"p.0", 90, 0},
			{"p.0.2", 91, 0},
			{"p.0.100", 90, 100},
		}
		for _, tc := range cases {
			fold := config.StableIfaceID(tc.stable)
			ifindex, vlan, ok := resolve(fold)
			if !ok {
				t.Errorf("trunc=%v: fold(%q) unresolved — want (%d,%d)",
					trunc, tc.stable, tc.wantIfindex, tc.wantVlan)
				continue
			}
			if ifindex != tc.wantIfindex || vlan != tc.wantVlan {
				t.Errorf("trunc=%v: fold(%q) = (%d,%d), want (%d,%d)",
					trunc, tc.stable, ifindex, vlan, tc.wantIfindex, tc.wantVlan)
			}
		}
	}
}

// TestIngressFoldD13ChildSession9821 pins the D13-population dependency: a
// session on a D13-attached dotted vlan-child device folds (sender, pure)
// and installs (receiver) as parent+vlan — sans wrong-interface.
func TestIngressFoldD13ChildSession9821(t *testing.T) {
	cfg, devs := foldFixture9821(false)
	// The D13-attached child device also exists on the host (vlan netdev).
	devs = append(devs, net.Interface{Index: 93, Name: "p.0.100"})
	sent := cfg.ClusterStableIfaceName("p.0.100", 0)
	if sent != "p.0.100" {
		t.Fatalf("sender folds the D13 child device to %q, want p.0.100", sent)
	}
	resolve := buildIngressFoldResolverWithIfaces(cfg, devs)
	ifindex, vlan, ok := resolve(config.StableIfaceID(sent))
	if !ok {
		t.Fatal("fold(p.0.100) unresolved — want the parent+vlan tuple")
	}
	if ifindex != 90 || vlan != 100 {
		t.Errorf("fold(p.0.100) = (%d,%d), want (90,100) (parent device + vlan)", ifindex, vlan)
	}
}

// TestIngressFoldUnconfiguredVlanLegacy9821 pins the legacy preservation: an
// unconfigured numeric suffix folds first-cut (sender) and installs the
// truncation's device (receiver) — exactly as before, honest approx where
// the sender cannot know better.
func TestIngressFoldUnconfiguredVlanLegacy9821(t *testing.T) {
	cfg, devs := foldFixture9821(true)
	sent := cfg.ClusterStableIfaceName("p.0.200", 0)
	if sent != "p" {
		t.Fatalf("unconfigured-vlan sender = %q, want legacy first-cut p", sent)
	}
	resolve := buildIngressFoldResolverWithIfaces(cfg, devs)
	ifindex, vlan, ok := resolve(config.StableIfaceID(sent))
	if !ok {
		t.Fatal("fold(p) unresolved — want the truncation device (legacy)")
	}
	if ifindex != 89 || vlan != 0 {
		t.Errorf("fold(p) = (%d,%d), want (89,0)", ifindex, vlan)
	}
}

// legacyFoldInstall9821 mirrors the OLD install split (last-dot-numeric,
// unconditionally) over a fake device set — the F-MIXED old→new oracle.
// Returns "approx" or "dev:<ifindex>:<vlan>".
func legacyFoldInstall9821(localName string, devices map[string]uint32) string {
	base, vlan := localName, uint16(0)
	if i := strings.LastIndexByte(localName, '.'); i >= 0 {
		if v, err := strconv.ParseUint(localName[i+1:], 10, 16); err == nil {
			base, vlan = localName[:i], uint16(v)
		}
	}
	idx := devices[config.LinuxIfName(base)]
	if idx == 0 {
		return "approx"
	}
	return "dev:" + strconv.FormatUint(uint64(idx), 10) + ":" + strconv.FormatUint(uint64(vlan), 10)
}

// TestIngressFoldMixedOldToNew9821 (F-MIXED) pins old→new ≡ old→old: old
// folds (truncated/legacy forms) install identically through the new
// receiver and the legacy split — the declared short-circuit fires only on
// exact declared matches, which old folds reach exactly as no-dot names did
// before. Fixtures are non-reth (reth is covered by identical-strings +
// the 7095 contract).
func TestIngressFoldMixedOldToNew9821(t *testing.T) {
	cfg, devs := foldFixture9821(true)
	devices := map[string]uint32{}
	for _, d := range devs {
		devices[d.Name] = uint32(d.Index)
	}
	resolve := buildIngressFoldResolverWithIfaces(cfg, devs)
	// Old-fold corpus: ONLY forms an old peer emits — truncated first-cuts,
	// legacy dot-free names, and legacy vlan-suffixed names. (New-only folds
	// like `p.0` are intentionally absent: old senders truncate dotted
	// inputs, so comparing split outcomes on them would test nothing about
	// mixed flight — and the new receiver deliberately answers them
	// differently, which IS the fix, pinned by the tuple test above.)
	for _, foldName := range []string{"p", "p.50", "eth9"} {
		fold := config.StableIfaceID(foldName)
		ifindex, vlan, ok := resolve(fold)
		gotNew := "approx"
		if ok {
			gotNew = "dev:" + strconv.FormatUint(uint64(ifindex), 10) + ":" + strconv.FormatUint(uint64(vlan), 10)
		}
		// The old peer resolves only enum-held folds; anything else is
		// approx on both sides by construction (lookup miss).
		held := false
		for _, e := range cfg.ClusterStableIfaceNames() {
			if config.StableIfaceID(e) == fold {
				held = true
			}
		}
		gotOld := "approx"
		if held {
			gotOld = legacyFoldInstall9821(foldName, devices)
		}
		if gotNew != gotOld {
			t.Errorf("old fold %q: new receiver %q vs old %q — must be identical", foldName, gotNew, gotOld)
		}
	}
}
