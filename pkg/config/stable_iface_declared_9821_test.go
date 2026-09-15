package config

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// dottedStableCfg9821 builds the sender-fixture topology: a dotted interface
// with a vlan child, a both-declared sibling pair, and an undotted control.
func dottedStableCfg9821() *Config {
	return &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{
			0:   {Number: 0},
			100: {Number: 100, VlanID: 100},
		}},
		"p.0.2": {Name: "p.0.2", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"p.100": {Name: "p.100", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"p":     {Name: "p", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"eth0":  {Name: "eth0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}}}
}

// TestClusterStableIfaceNameDotted9821 pins the D25/F-R71 sender: declared
// names fold untruncated with kind-tracked VLAN append (declaration text is
// never confused with encoded VLAN).
func TestClusterStableIfaceNameDotted9821(t *testing.T) {
	cfg := dottedStableCfg9821()
	cases := []struct {
		name  string
		local string
		vlan  uint16
		want  string
	}{
		{"dotted bare untruncated", "p.0", 0, "p.0"},
		{"declared-exact always appends param", "p.0", 100, "p.0.100"},
		{"R7-1 declaration text not encoding", "p.100", 100, "p.100.100"},
		{"child keep on param zero", "p.0.100", 0, "p.0.100"},
		{"child no-double on param match", "p.0.100", 100, "p.0.100"},
		{"child param-wins on conflict", "p.0.100", 50, "p.0.50"},
		{"truncation immunity", "p.0", 0, "p.0"},
		{"unknown shape legacy", "nope.5", 0, "nope"},
		{"unknown bare legacy append", "nope", 7, "nope.7"},
		{"undotted control", "eth0", 0, "eth0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cfg.ClusterStableIfaceName(tc.local, tc.vlan); got != tc.want {
				t.Errorf("ClusterStableIfaceName(%q,%d) = %q, want %q",
					tc.local, tc.vlan, got, tc.want)
			}
		})
	}
	// Convergence theorem: (D,V)+(V) ≡ (D.V,0) for configured V.
	if a, b := cfg.ClusterStableIfaceName("p.0", 100), cfg.ClusterStableIfaceName("p.0.100", 0); a != b {
		t.Errorf("convergence violated: (p.0,100)=%q vs (p.0.100,0)=%q", a, b)
	}
}

// TestClusterStableIfaceNameUnconfiguredVlanLegacy9821 pins the legacy
// preservation: a numeric suffix that is NEITHER a configured vlan-id NOR a
// unit number falls to first-cut, exactly as before.
func TestClusterStableIfaceNameUnconfiguredVlanLegacy9821(t *testing.T) {
	cfg := dottedStableCfg9821()
	if got := cfg.ClusterStableIfaceName("p.0.200", 0); got != "p" {
		t.Errorf("unconfigured-vlan input folds %q, want legacy first-cut p", got)
	}
}

// TestClusterStableIfaceNameUntaggedNonzeroUnit9821 pins the D25 follow-up
// pointer (intended fail-closed direction change): an untagged nonzero unit
// device folds untruncated (ChildDevice) and hash-misses the enumeration
// (which holds only vlan children), degrading honestly — where legacy
// parent-folded onto the parent's device with false confidence.
func TestClusterStableIfaceNameUntaggedNonzeroUnit9821(t *testing.T) {
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"p": {Name: "p", Units: map[int]*InterfaceUnit{
			0: {Number: 0},
			5: {Number: 5},
		}},
	}}}
	got := cfg.ClusterStableIfaceName("p.5", 0)
	if got != "p.5" {
		t.Fatalf("untagged unit-5 device folds %q, want untruncated p.5", got)
	}
	for _, e := range cfg.ClusterStableIfaceNames() {
		if StableIfaceID(e) == StableIfaceID(got) && e != got {
			t.Fatalf("fold of %q collides with enum candidate %q — the honest miss needs a miss", got, e)
		}
	}
	found := false
	for _, e := range cfg.ClusterStableIfaceNames() {
		if e == got {
			found = true
		}
	}
	if found {
		t.Fatalf("enum unexpectedly holds %q — untagged nonzero units are not enumerated", got)
	}
}

// TestClusterStableIfaceNameSuffixedFixturePreserved9821 (F-EVIDENCE) pins the
// member vlan-child input on the 7095 fixture: param 0 preserves legacy
// `reth0`, param 50 preserves `reth0.50`. The fixture's members carry no
// units, so (b)'s owner-scoped predicate misses and (c) cuts to the member
// exactly as before — preservation by predicate, not by pin coincidence.
func TestClusterStableIfaceNameSuffixedFixturePreserved9821(t *testing.T) {
	n1 := clusterCfg7095(1, 7)
	if got := n1.ClusterStableIfaceName("ge-7-0-2.50", 0); got != "reth0" {
		t.Errorf("suffixed member input param-0 folds %q, want legacy reth0", got)
	}
	if got := n1.ClusterStableIfaceName("ge-7-0-2.50", 50); got != "reth0.50" {
		t.Errorf("suffixed member input param-50 folds %q, want legacy reth0.50", got)
	}
}

// TestClusterStableIfaceNameSlashApproxDashResolve9821 pins the spelling
// asymmetry: dash-declared dotted RESOLVES (sender untruncated, fold hits the
// dash-spelled enum); slash-declared honestly APPROXIMATES (sender
// untruncated — the fix — but the dash-spelled fold misses the slash-spelled
// enum, the same zone-approx as today's entire slash-declared non-reth class).
func TestClusterStableIfaceNameSlashApproxDashResolve9821(t *testing.T) {
	dash := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"ge-0-0-5.0": {Name: "ge-0-0-5.0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}}}
	if got := dash.ClusterStableIfaceName("ge-0-0-5.0", 0); got != "ge-0-0-5.0" {
		t.Fatalf("dash-declared sender = %q, want untruncated", got)
	}
	if _, ok := dash.LocalIfaceForStableID(StableIfaceID("ge-0-0-5.0")); !ok {
		t.Error("dash-declared fold does not resolve — want resolution")
	}
	slash := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}}}
	// Kernel-spelling input against a slash declaration.
	if got := slash.ClusterStableIfaceName("ge-0-0-5.0", 0); got != "ge-0-0-5.0" {
		t.Fatalf("slash-declared sender = %q, want untruncated (the fix)", got)
	}
	if _, ok := slash.LocalIfaceForStableID(StableIfaceID("ge-0-0-5.0")); ok {
		t.Error("slash-declared dash fold unexpectedly resolves — want honest hash-miss (zone approx)")
	}
}

// TestClusterStableIfaceNameSlashConvergence9821 pins the review fix: both
// arms fold the INPUT spelling, so one dash-spelled identity converges
// ((D,V) ≡ (D.V,0)) instead of splitting into a dash fold and a slash fold
// that straddle the enum. Slash-approximation is preserved: both dash folds
// hash-miss the slash-spelled enum, exactly as legacy first-cut did.
func TestClusterStableIfaceNameSlashConvergence9821(t *testing.T) {
	slash := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*InterfaceUnit{
			0:   {Number: 0},
			100: {Number: 100, VlanID: 100},
		}},
	}}}
	a := slash.ClusterStableIfaceName("ge-0-0-5.0", 100)
	b := slash.ClusterStableIfaceName("ge-0-0-5.0.100", 0)
	if a != b {
		t.Errorf("slash convergence violated: (D,V)=%q vs (D.V,0)=%q — one identity must fold one name", a, b)
	}
	if a != "ge-0-0-5.0.100" || b != "ge-0-0-5.0.100" {
		t.Errorf("child folds = (%q,%q) — want the input spelling on both arms", a, b)
	}
	for _, s := range []string{a, b} {
		if _, ok := slash.LocalIfaceForStableID(StableIfaceID(s)); ok {
			t.Errorf("fold(%q) unexpectedly resolves — want honest hash-miss (zone approx)", s)
		}
	}
}

// legacyStableIfaceName9821 is the pre-D25 sender (first-cut + reth +
// append), copied for the F-MIXED equivalence table — NOT a second
// implementation to maintain; it pins what old peers emit.
func legacyStableIfaceName9821(c *Config, local string, vlan uint16) string {
	if c == nil || local == "" {
		return ""
	}
	base := local
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	baseLinux := LinuxIfName(base)
	stable := base
	for reth, member := range c.RethToPhysical() {
		if LinuxIfName(member) == baseLinux {
			stable = reth
			break
		}
	}
	if vlan > 0 {
		return stable + "." + strconv.FormatUint(uint64(vlan), 10)
	}
	return stable
}

// oldFoldOutcome9821 resolves a SENDER OUTPUT STRING the way an old peer
// would: enum-hit, then last-dot-numeric split, then device-hit. Fixtures are
// non-reth (reth is covered by identical-strings + the 7095 contract), so no
// ResolveReth mirror is needed. Returns "approx" or "dev:<base>:<vlan>".
func oldFoldOutcome9821(c *Config, senderOut string, devices map[string]bool) string {
	fold := StableIfaceID(senderOut)
	found := ""
	for _, e := range c.ClusterStableIfaceNames() {
		if StableIfaceID(e) == fold {
			if found != "" {
				return "approx" // collision → approx (both impls agree)
			}
			found = e
		}
	}
	if found == "" {
		return "approx"
	}
	base, vlan := found, 0
	if i := strings.LastIndexByte(found, '.'); i >= 0 {
		if v, err := strconv.ParseUint(found[i+1:], 10, 16); err == nil {
			base, vlan = found[:i], int(v)
		}
	}
	if !devices[LinuxIfName(base)] {
		return "approx"
	}
	return fmt.Sprintf("dev:%s:%d", base, vlan)
}

// TestStableIfaceMixedNewToOld9821 (F-MIXED) pins new→old ≡ old→old
// case-by-case through the legacy oracles. Equal outcomes are the requirement
// ("never newly wrong"); the triple-declared row locks an equally-wrong
// resolution — a CHARACTERIZATION of old-behavior equivalence, NOT approval.
func TestStableIfaceMixedNewToOld9821(t *testing.T) {
	// Identical-strings cases (undotted/reth/vlan rules preserve legacy
	// forms): new and old emitters agree byte-for-byte.
	n0 := clusterCfg7095(0, 0)
	for _, tc := range []struct {
		local string
		vlan  uint16
	}{
		{"ge-0-0-2", 50},
		{"ge-0-0-2", 0},
		{"ge-0-0-1", 0},
		{"ge-0-0-2.50", 0},
	} {
		n, o := n0.ClusterStableIfaceName(tc.local, tc.vlan), legacyStableIfaceName9821(n0, tc.local, tc.vlan)
		if n != o {
			t.Errorf("identical-strings violated for (%q,%d): new=%q old=%q", tc.local, tc.vlan, n, o)
		}
	}
	// Outcome-equivalence cases (dotted shapes diverge as strings; the old
	// peer's RESOLUTION must be no worse for the new string).
	single := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}}}
	triple := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"p":     {Name: "p", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"p.0":   {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"p.0.2": {Name: "p.0.2", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}}}
	child := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{
			0:   {Number: 0},
			100: {Number: 100, VlanID: 100},
		}},
	}}}
	devSingle := map[string]bool{"p.0": true}
	devTriple := map[string]bool{"p": true, "p.0": true, "p.0.2": true}
	devChild := map[string]bool{"p.0": true}
	cases := []struct {
		name    string
		cfg     *Config
		devices map[string]bool
		local   string
		vlan    uint16
		// wantNew/wantOld are the required old-peer outcome CLASSES.
		wantNew, wantOld string
	}{
		{"single-declared both approx", single, devSingle, "p.0", 0, "approx", "approx"},
		{"triple equally wrong together", triple, devTriple, "p.0", 0, "dev:p:0", "dev:p:0"},
		{"D13 child new correct old approx", child, devChild, "p.0.100", 0, "dev:p.0:100", "approx"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, o := tc.cfg.ClusterStableIfaceName(tc.local, tc.vlan), legacyStableIfaceName9821(tc.cfg, tc.local, tc.vlan)
			gotNew, gotOld := oldFoldOutcome9821(tc.cfg, n, tc.devices), oldFoldOutcome9821(tc.cfg, o, tc.devices)
			if gotNew != tc.wantNew || gotOld != tc.wantOld {
				t.Errorf("(%q,%d): new=%q→%q (want %q), old=%q→%q (want %q)",
					tc.local, tc.vlan, n, gotNew, tc.wantNew, o, gotOld, tc.wantOld)
			}
		})
	}
}
