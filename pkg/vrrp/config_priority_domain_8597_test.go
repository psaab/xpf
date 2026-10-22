package vrrp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 (muse-004 K17) / gemini-review-048 finding 17 — the VRRP half of the
// same defect: a wide config int reaching a narrow wire field, with the LOCAL
// decision made on the wide value.
//
// `instance_send.go` writes `Priority: uint8(priority)` while the local state
// machine reads `vi.cfg.Priority` as an int (instance_preempt.go, three sites)
// — so a configured 256 advertised as 0. 0 is not a low priority in VRRP; it is
// the RFC 5798 RESIGNATION beacon this package uses to hand mastership over
// (manager.go ResignRG). The node would tell the LAN "take over now" on every
// advert while believing itself the most preferred candidate.
//
// #8321 dispositioned this finding as mechanism-real, reachability NOT
// established: "I have not found such a path and I am not asserting there is
// none." The path is the tolerant ingress, the same one K17 travels, and
// TestLenientLoadKeepsAnOutOfRangeVRRPPriority_8597 below drives it rather than
// asserting it.

// TestLenientLoadKeepsAnOutOfRangeVRRPPriority_8597 answers the #8321 open
// question by execution: the strict gate rejects, the tolerant compile keeps
// the raw value, and the value is one that truncates to the resignation beacon.
func TestLenientLoadKeepsAnOutOfRangeVRRPPriority_8597(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24 vrrp-group 1 virtual-address 10.0.0.254",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24 vrrp-group 1 priority 256",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	if err := config.SchemaValidate(tree); err == nil {
		t.Error("the strict typed-leaf gate accepted vrrp-group priority 256; the " +
			"lenient/strict split this finding rests on no longer exists")
	}

	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must not fail (#1960 no-brick), got: %v", err)
	}
	var got int
	for _, ifc := range cfg.Interfaces.Interfaces {
		for _, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			for _, vg := range unit.VRRPGroups {
				if vg != nil && vg.ID == 1 {
					got = vg.Priority
				}
			}
		}
	}
	if got != 256 {
		t.Fatalf("lenient compile stored vrrp-group priority %d, want the raw 256 — if "+
			"the tolerant ingress now bounds it, the runtime clamp is unreachable and "+
			"should be re-argued rather than silently kept", got)
	}
	// And that raw value is the dangerous one specifically because of what it
	// becomes on the wire.
	if uint8(got) != 0 {
		t.Fatalf("uint8(%d) = %d, want 0 — the fixture is chosen because it truncates "+
			"onto the resignation beacon, not merely because it is out of range",
			got, uint8(got))
	}
}

// TestConstructorStillExpressesTheResignState_8597 pins the boundary the first
// draft of this fix got wrong.
//
// Clamping inside newInstance broke TestGetPriority_TrackMatrix's
// priority-0-resign-passthrough case, and that test was RIGHT to fail:
// newInstance is a plain constructor, and 0 is the correct representation of a
// resigning master (ResignRG sets it under the instance lock). The clamp
// belongs at the CONFIG boundary — the manager's install and updateConfig —
// not on every construction. This cell states that boundary so a future
// "tighten it further" move has to argue with it.
func TestConstructorStillExpressesTheResignState_8597(t *testing.T) {
	vi := newInstance(Instance{Interface: "ge-0-0-0", GroupID: 1, Priority: 0}, nil, nil, nil)
	if got := vi.cfg.Priority; got != 0 {
		t.Errorf("newInstance rewrote a priority of 0 to %d; 0 is the resignation "+
			"state the run loop installs, and the constructor must be able to "+
			"express it", got)
	}
}

// TestUpdateConfigClampsAnOutOfRangePriority_8597 is the day-2 path. A commit
// that changes only the priority reaches updateConfig, not newInstance, so a
// clamp on the constructor alone would leave a running instance able to acquire
// the out-of-range value it was protected from at startup.
func TestUpdateConfigClampsAnOutOfRangePriority_8597(t *testing.T) {
	vi := newInstance(Instance{Interface: "ge-0-0-0", GroupID: 1, Priority: 100}, nil, nil, nil)
	vi.updateConfig(Instance{Interface: "ge-0-0-0", GroupID: 1, Priority: 256})
	if got := vi.cfg.Priority; got != 254 {
		t.Errorf("updateConfig stored priority %d for a configured 256, want 254 — the "+
			"clamp must cover BOTH config entry points", got)
	}
}

// TestClampConfigPriorityKeepsTheTwoReservedValuesApart_8597 is the OVER-BROAD
// control and the semantic one.
//
// The two clamp targets are deliberately different, and a fix that used one
// value for both ends would be wrong in two distinct ways:
//
//   - clamping LOW to 0 would install the resignation sentinel from config;
//   - clamping HIGH to 255 would silently grant IP-ADDRESS-OWNER semantics —
//     preemptEnabled() treats an owner as always-preempting and track.go exempts
//     it from track-down demotion — to a config that only asked for a big number.
//
// An explicit 255 must still pass through: that is how an operator legitimately
// declares the address owner.
func TestClampConfigPriorityKeepsTheTwoReservedValuesApart_8597(t *testing.T) {
	for _, c := range []struct {
		in   int
		want int
		why  string
	}{
		{256, 254, "above range clamps to the highest ORDINARY priority, never to the owner value"},
		{65700, 254, "far above range, same target"},
		{0, 1, "below range clamps to the lowest ordinary priority, never to the resignation beacon"},
		{-1, 1, "negative, same target"},
		{255, 255, "an explicit owner declaration is in range and passes through"},
		{254, 254, "max ordinary boundary"},
		{1, 1, "min boundary"},
		{100, 100, "ordinary"},
		{200, 200, "ordinary"},
	} {
		if got := clampConfigPriority(c.in); got != c.want {
			t.Errorf("clampConfigPriority(%d) = %d, want %d — %s", c.in, got, c.want, c.why)
		}
	}
}

// TestClampedPriorityStaysMonotonic_8597: the property the election depends on.
// Two priorities that order one way as configured ints must order the same way
// after clamping, or the clamp has done what the truncation did.
func TestClampedPriorityStaysMonotonic_8597(t *testing.T) {
	for _, pair := range [][2]int{{256, 200}, {65700, 254}, {300, 100}, {200, 100}} {
		hi, lo := pair[0], pair[1]
		if clampConfigPriority(hi) < clampConfigPriority(lo) {
			t.Errorf("clampConfigPriority inverted %d > %d into %d < %d",
				hi, lo, clampConfigPriority(hi), clampConfigPriority(lo))
		}
	}
}
