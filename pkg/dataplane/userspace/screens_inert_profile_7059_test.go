package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileScreenCfg7059(t *testing.T, lines []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func compileScreenCfgLenient7059(t *testing.T, lines []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	// The UNDEFINED state is strict-REJECTED, so the only way to build it is the
	// tolerant path this whole #5806 surface exists to cover.
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	return cfg
}

// TestScreenReferenceHasThreeStates_7059 is the table the whole issue is about,
// and the MIDDLE ROW is the one that carries it.
//
// Before #7059 rows "inert" and "enforcing" were indistinguishable on every
// #5806 surface: both had zero unresolved refs, zero status lines, and no
// metric. A two-row table (undefined vs enforcing) passes on the broken code —
// it is only the row where the reference RESOLVES and yet nothing is enforced
// that can tell the two implementations apart.
func TestScreenReferenceHasThreeStates_7059(t *testing.T) {
	for _, tc := range []struct {
		name          string
		lines         []string
		lenient       bool
		wantSnapshots int
		wantMissing   int
		wantInert     int
	}{
		{
			// The state the SHIPPED surfaces already cover. It is here so the
			// table separates "unresolved" from "inert" rather than assuming
			// they cannot be confused: a predicate that reported undefined
			// profiles as inert too would blur two states with different
			// operator remedies (define the profile vs. add a check to it).
			// Strict commit REJECTS this, so it must be built leniently — which
			// is also the only way production reaches it.
			name: "referenced_profile_undefined",
			lines: []string{
				"set security zones security-zone trust screen ghost",
			},
			lenient:       true,
			wantSnapshots: 0, wantMissing: 1, wantInert: 0,
		},
		{
			// THE MIDDLE ROW. Passes strict commit with zero warnings.
			name: "defined_but_enables_no_checks",
			lines: []string{
				"set security screen ids-option p alarm-without-drop",
				"set security zones security-zone trust screen p",
			},
			wantSnapshots: 0, wantMissing: 0, wantInert: 1,
		},
		{
			name: "defined_and_enforcing",
			lines: []string{
				"set security screen ids-option p tcp land",
				"set security zones security-zone trust screen p",
			},
			wantSnapshots: 1, wantMissing: 0, wantInert: 0,
		},
		{
			// A zone with NO screen at all also publishes no snapshot. It must
			// NOT be reported: "nothing enforced because nothing was asked for"
			// is not a finding. Without this row the inert predicate could be
			// "snapshots == 0" and still pass.
			name: "no_screen_configured",
			lines: []string{
				"set security zones security-zone trust description plain",
			},
			wantSnapshots: 0, wantMissing: 0, wantInert: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compile := compileScreenCfg7059
			if tc.lenient {
				compile = compileScreenCfgLenient7059
			}
			cfg := compile(t, tc.lines)
			if got := len(buildScreenSnapshots(cfg)); got != tc.wantSnapshots {
				t.Errorf("published snapshots = %d, want %d", got, tc.wantSnapshots)
			}
			if got := len(ScreenMissingProfileRefs(cfg)); got != tc.wantMissing {
				t.Errorf("unresolved refs = %d, want %d", got, tc.wantMissing)
			}
			if got := len(ScreenInertProfileRefs(cfg)); got != tc.wantInert {
				t.Errorf("inert refs = %d, want %d — this is the state that used to "+
					"render identically to a healthy, enforcing zone on every #5806 "+
					"surface (#7059)", got, tc.wantInert)
			}
		})
	}
}

// TestInertAndEnforcingRenderDifferently_7059 states the property in the form an
// operator experiences: the two configs must not produce the same output. A
// per-field assertion can drift from this; a direct inequality cannot.
func TestInertAndEnforcingRenderDifferently_7059(t *testing.T) {
	inert := compileScreenCfg7059(t, []string{
		"set security screen ids-option p alarm-without-drop",
		"set security zones security-zone trust screen p",
	})
	enforcing := compileScreenCfg7059(t, []string{
		"set security screen ids-option p tcp land",
		"set security zones security-zone trust screen p",
	})
	inertOut := strings.Join(ScreenInertProfileLines(inert), "\n")
	enforcingOut := strings.Join(ScreenInertProfileLines(enforcing), "\n")
	if inertOut == enforcingOut {
		t.Fatalf("a zone enforcing NOTHING and a zone enforcing a real check rendered "+
			"identically (%q). That is the defect: a check failing to a value "+
			"indistinguishable from healthy (#7059)", inertOut)
	}
	if enforcingOut != "" {
		t.Fatalf("an enforcing zone must produce NO inert block — a false alarm here "+
			"trains operators to ignore the real one; got %q", enforcingOut)
	}
	if !strings.Contains(inertOut, "'p'") {
		t.Fatalf("the profile name must be QUOTED in the block: a bare \"enables no "+
			"checks\" reads as \"you forgot to configure it\" to an operator who did "+
			"configure it; got %q", inertOut)
	}
	if !strings.Contains(inertOut, "trust") {
		t.Fatalf("the block must name the affected ZONE; got %q", inertOut)
	}
}

// TestInertPredicateTracksThePublisher_7059 is the single-source proof. The
// inert surface asks buildScreenSnapshots what it published rather than
// re-deriving the emit gate, so the two cannot disagree about which zones the
// dataplane enforces for. This asserts the invariant directly over the whole
// enabled-check inventory rather than trusting the shared call.
func TestInertPredicateTracksThePublisher_7059(t *testing.T) {
	// Every single-check config must publish AND be absent from the inert set.
	for _, line := range []string{
		"set security screen ids-option p tcp land",
		"set security screen ids-option p tcp syn-fin",
		"set security screen ids-option p tcp no-flag",
		"set security screen ids-option p tcp fin-no-ack",
		"set security screen ids-option p tcp winnuke",
		"set security screen ids-option p tcp syn-frag",
		"set security screen ids-option p icmp ping-death",
		"set security screen ids-option p icmp fragment",
		"set security screen ids-option p ip tear-drop",
		"set security screen ids-option p ip source-route-option",
		"set security screen ids-option p icmp flood threshold 100",
		"set security screen ids-option p udp flood threshold 100",
		"set security screen ids-option p tcp syn-flood attack-threshold 200",
		"set security screen ids-option p tcp port-scan threshold 100",
		"set security screen ids-option p ip ip-sweep threshold 100",
		"set security screen ids-option p limit-session source-ip-based 10",
		"set security screen ids-option p limit-session destination-ip-based 10",
	} {
		t.Run(line, func(t *testing.T) {
			cfg := compileScreenCfg7059(t, []string{
				line,
				"set security zones security-zone trust screen p",
			})
			published := len(buildScreenSnapshots(cfg)) > 0
			inert := len(ScreenInertProfileRefs(cfg)) > 0
			if published == inert {
				t.Fatalf("published=%v and inert=%v must always be OPPOSITE for a zone "+
					"whose profile is defined — they are two readings of one question, "+
					"and a divergence is always a bug (#7059)", published, inert)
			}
			if !published {
				t.Fatalf("this config enables a real check, so the dataplane must " +
					"receive a snapshot for the zone; if this leaf is genuinely not " +
					"enforced the emit gate and this list must change together")
			}
		})
	}
}

// TestInertBlockRendersBeforeTheAnchor_7059 pins the ordering through the
// single-sourced contract rather than a hand-written index compare, for both
// anchors — the wide renderers' empty-inventory line and the per-profile
// renderers' not-found line (#7060).
func TestInertBlockRendersBeforeTheAnchor_7059(t *testing.T) {
	cfg := compileScreenCfg7059(t, []string{
		"set security screen ids-option p alarm-without-drop",
		"set security zones security-zone trust screen p",
	})
	block := strings.Join(ScreenInertProfileLines(cfg), "\n") + "\n"

	t.Run("before_empty_inventory", func(t *testing.T) {
		if err := CheckScreenInertRenderOrder(block + ScreenEmptyInventoryLine + "\n"); err != nil {
			t.Fatal(err)
		}
		// The inverse must be REJECTED, or the check proves nothing.
		if err := CheckScreenInertRenderOrder(ScreenEmptyInventoryLine + "\n" + block); err == nil {
			t.Fatal("the ordering check accepted the block rendered AFTER the " +
				"empty-inventory line, so it cannot detect the defect it exists for")
		}
	})

	t.Run("before_not_found", func(t *testing.T) {
		anchor := "Screen profile 'p' not found\n"
		if err := CheckScreenDiagnosticRenderOrderBefore(block+anchor, anchor); err != nil {
			t.Fatal(err)
		}
		if err := CheckScreenDiagnosticRenderOrderBefore(anchor+block, anchor); err == nil {
			t.Fatal("the ordering check accepted the block rendered AFTER the " +
				"not-found line (#7060)")
		}
	})

	t.Run("absent_anchor_is_not_a_silent_pass", func(t *testing.T) {
		if err := CheckScreenDiagnosticRenderOrderBefore(block, "Screen profile 'p' not found"); err == nil {
			t.Fatal("with the anchor absent the ordering check must FAIL rather than " +
				"pass vacuously — a test that forgets to drive the anchor path would " +
				"otherwise report a green it never earned")
		}
	})
}

// TestUnresolvedAndInertAreDisjoint_7059 pins that the two surfaces never both
// claim the same zone. They carry DIFFERENT operator remedies — define the
// missing profile, versus add a check to the profile you did define — so a zone
// appearing in both would tell an operator to do two contradictory things, and a
// zone appearing in neither while unenforced is the original #7059 defect.
//
// Added because mutation cell M3 (deleting the undefined-skip from the inert
// predicate) was caught only by a PRE-EXISTING renderer test and by none of the
// cells written for this change — the table above had no undefined row at all.
func TestUnresolvedAndInertAreDisjoint_7059(t *testing.T) {
	// One zone of each kind, in ONE config, so the disjointness is observed on
	// the same input rather than inferred across two runs.
	cfg := compileScreenCfgLenient7059(t, []string{
		"set security zones security-zone ghosted screen ghost",
		"set security screen ids-option inert alarm-without-drop",
		"set security zones security-zone stranded screen inert",
		"set security screen ids-option live tcp land",
		"set security zones security-zone healthy screen live",
	})
	missing := map[string]bool{}
	for _, r := range ScreenMissingProfileRefs(cfg) {
		missing[r.Zone] = true
	}
	inert := map[string]bool{}
	for _, r := range ScreenInertProfileRefs(cfg) {
		inert[r.Zone] = true
	}
	if !missing["ghosted"] {
		t.Errorf("the zone whose profile is UNDEFINED must be in the unresolved set; got %v", missing)
	}
	if !inert["stranded"] {
		t.Errorf("the zone whose profile is DEFINED-but-empty must be in the inert set; got %v", inert)
	}
	if missing["healthy"] || inert["healthy"] {
		t.Errorf("the ENFORCING zone must be in neither set; missing=%v inert=%v", missing, inert)
	}
	for z := range missing {
		if inert[z] {
			t.Fatalf("zone %q is reported BOTH unresolved and inert. The two carry "+
				"different remedies — define the profile, versus add a check to it — "+
				"so an operator is told to do two contradictory things (#7059)", z)
		}
	}
}
