package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15260 (A92-02): the symmetric CoS fixture bound its reverse
// shaper/filter to the dash-form `ge-0-0-1`. On the documented lab
// base (docs/ha-cluster-userspace.conf) node0 already authors
// `ge-0/0/1` as the reth1 member, and LinuxIfName folds both
// spellings onto the same kernel device, so the #5832 strict
// ifname-collision gate rejects every --symmetric commit-check.
// The pre-existing Go guard
// (TestCoSIperfSymmetricFixtureCompilesReverseSourcePortOutputFilter)
// compiled the fixture on an EMPTY tree, so it stayed green while
// every real --symmetric cell was dead.
//
// The fix binds the reverse filter/shaper to reth1 unit 0 (the LAN
// RETH whose member is ge-0/0/1 on node0 / ge-7/0/1 on node1 — the
// actual egress for reverse traffic, per docs/fairness-regimes.md).
// This guard therefore compiles base+overlay through the REAL
// strict commit pipeline (compileTreeStrict: schema gate + strict
// compile, peer views included) for BOTH nodes, and pins the
// reverse binding on reth1.0.

// cosOverlayTree15260 builds base+fixture exactly as
// apply-cos-config.sh does: parse the hierarchical lab base, then
// replay the fixture's `set` lines onto it (the script strips the
// fixture's delete lines and injects its own delete preamble, which
// only removes prior CoS state and cannot create the collision).
func cosOverlayTree15260(t *testing.T, fixture string) *config.ConfigTree {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(haClusterConfPath))
	if err != nil {
		t.Fatalf("read lab base: %v", err)
	}
	tree, perrs := config.NewParser(string(raw)).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse lab base: %v", perrs)
	}
	data, err := os.ReadFile(filepath.Clean(fixture))
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixture, err)
	}
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "set ") {
			continue
		}
		if err := applyEditLine(tree, line); err != nil {
			t.Fatalf("overlay %q: %v", line, err)
		}
	}
	return tree
}

func TestA92OverlaySymmetricFixtureOnLabBase15260(t *testing.T) {
	for _, node := range []int{0, 1} {
		cfg, err := compileTreeStrict(cosOverlayTree15260(t, "../../test/incus/cos-iperf-symmetric.set"), node)
		if err != nil {
			t.Fatalf("node %d: symmetric fixture does not commit on lab base: %v", node, err)
		}
		// Reverse binding must land on reth1 unit 0, not the member name.
		revUnit := cfg.Interfaces.Interfaces["reth1"].Units[0]
		if revUnit == nil {
			t.Fatalf("node %d: expected reth1 unit 0 interface config", node)
		}
		if got := revUnit.FilterOutputV4; got != "bandwidth-output-reverse" {
			t.Errorf("node %d: reth1.0 inet output filter = %q, want bandwidth-output-reverse", node, got)
		}
		if got := revUnit.FilterOutputV6; got != "bandwidth-output-reverse" {
			t.Errorf("node %d: reth1.0 inet6 output filter = %q, want bandwidth-output-reverse", node, got)
		}
		revCos := cfg.ClassOfService.Interfaces["reth1"].Units[0]
		if revCos == nil {
			t.Fatalf("node %d: expected reverse CoS shaper on reth1 unit 0", node)
		}
		if got := revCos.SchedulerMap; got != "bandwidth-limit" {
			t.Errorf("node %d: reth1.0 scheduler-map = %q, want bandwidth-limit", node, got)
		}
		if revCos.ShapingRateBytes == 0 {
			t.Errorf("node %d: reth1.0 shaping-rate is zero, want 25g shaper", node)
		}
		// Forward binding unchanged (control: no behaviour change
		// outside the cited mechanism).
		fwdUnit := cfg.Interfaces.Interfaces["reth0"].Units[80]
		if fwdUnit == nil || fwdUnit.FilterOutputV4 != "bandwidth-output" || fwdUnit.FilterOutputV6 != "bandwidth-output" {
			t.Errorf("node %d: forward reth0.80 output filters changed: %+v", node, fwdUnit)
		}
		// The dash-form member name must not carry the reverse binding.
		if bad := cfg.Interfaces.Interfaces["ge-0-0-1"]; bad != nil && bad.Units[0] != nil &&
			(bad.Units[0].FilterOutputV4 == "bandwidth-output-reverse" || bad.Units[0].FilterOutputV6 == "bandwidth-output-reverse") {
			t.Errorf("node %d: reverse filter still bound to ge-0-0-1.0", node)
		}
	}
}

// The neighbouring fixtures share the same apply path; they must
// also commit on the lab base for both nodes (named control cases).
func TestA92OverlayNeighbourFixturesOnLabBase15260(t *testing.T) {
	for _, fixture := range []string{
		"../../test/incus/cos-iperf-config.set",
		"../../test/incus/cos-iperf-same-class.set",
	} {
		for _, node := range []int{0, 1} {
			if _, err := compileTreeStrict(cosOverlayTree15260(t, fixture), node); err != nil {
				t.Errorf("%s node %d: does not commit on lab base: %v", filepath.Base(fixture), node, err)
			}
		}
	}
}
