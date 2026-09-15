package api

// #5806 metric guards. Which of these BIND the fix and which are coverage, so a
// later reader does not over-trust the count:
//
//   - TestScreenUnresolvedProfileZonesEmittedOnTolerantLoad is the binding one.
//     Its "want exactly one" positive control is what a collector that always
//     emits nothing fails on, and its label-set + HELP-anchor assertions are what
//     the label/wording regressions fail on.
//   - TestScreenUnresolvedProfileZonesSilentWhenResolved and
//     ...NilStoreNoPanic are NEGATIVE controls. They are necessary — without
//     them the binding test could pass with a collector that emits a row for
//     every zone — but neither fails if the collector goes silent, so on their
//     own they are coverage, not guards.
//
// The SSOT/source-identity, snapshot-publication, local-CLI and gRPC renderer
// guards live in their own packages; see
// pkg/dataplane/userspace/screens_ssot_source_5806_test.go,
// pkg/cli/cli_show_screen_unresolved_5806_test.go and
// pkg/grpcapi/server_show_screen_unresolved_5806_test.go. The runtime claim that
// policy evaluation still runs is bound in Rust, where the decision actually
// lives: userspace-dp/src/afxdp/poll_stages_tests.rs
// (unresolved_screen_profile_zone_continues_to_policy_5806).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// danglingScreenRefStore builds a store whose ACTIVE config contains a zone
// referencing an undefined screen profile — through the genuine TOLERANT LOAD
// path, because that is the only way this state is reachable.
//
// Strict commit rejects the dangling reference outright (verified: "security
// zone \"trust\" references undefined screen profile ..."), so the config
// cannot simply be committed. Instead a VALID config is committed, the
// persisted active.json is then externally modified so the profile DEFINITION
// no longer parses as one (the `ids-option` path token is renamed; it occurs
// exactly once) while the zone's `screen alpha` REFERENCE survives, and a fresh
// store re-Loads it. That is reachability path 1 from the issue — "loading an
// older or externally modified active.json through tolerant startup/recovery" —
// and is the same shape an HA config-sync from a schema-skewed peer produces.
func danglingScreenRefStore(t *testing.T) *configstore.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "xpf.conf")
	store := newConfigStore(t, path)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	// trust references screen profile alpha; wan deliberately has NO screen at
	// all, so the low-noise contract ("no screen configured" is not a dangling
	// reference) is exercised by the same fixture.
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.1.10/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.2.10/24; } } }
}
security {
    screen { ids-option alpha { icmp { ping-death; } } }
    zones {
        security-zone trust { screen alpha; interfaces { ge-0/0/0.0; } }
        security-zone wan { interfaces { ge-0/0/1.0; } }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	dbPath := filepath.Join(dir, ".configdb", "active.json")
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read persisted db: %v", err)
	}
	if n := strings.Count(string(raw), "ids-option"); n != 1 {
		t.Fatalf("fixture assumption broken: %q occurs %d times in the persisted "+
			"db, want exactly 1 (the profile definition)", "ids-option", n)
	}
	// Strand the reference: the definition stops being a screen profile, the
	// zone keeps pointing at it.
	mutated := strings.Replace(string(raw), "ids-option", "ids-optionz", 1)
	// #9898 F-035: the mutation above is deliberate test surgery on a
	// digest-stamped envelope; strip the tamper-evidence field so the
	// reload exercises the legacy-accept path (a missing field means
	// "pre-fix bytes", which these hand-mutated bytes now are). Without
	// the strip the reload correctly fails closed on the digest mismatch —
	// which would test the gate, not the tolerant dangling-ref load this
	// fixture exists for. The gate itself is pinned in pkg/configstore.
	if i := strings.Index(mutated, " body-sha256="); i >= 0 {
		nl := strings.IndexByte(mutated[i:], '\n')
		if nl < 0 {
			t.Fatalf("fixture broken: stamped header has no newline")
		}
		mutated = mutated[:i] + mutated[i+nl:]
	}
	if err := os.WriteFile(dbPath, []byte(mutated), 0o644); err != nil {
		t.Fatalf("write mutated db: %v", err)
	}

	reloaded := newConfigStore(t, path)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("tolerant Load() error = %v (the whole point is that this path "+
			"does NOT reject a dangling screen reference)", err)
	}
	if reloaded.ActiveConfig() == nil {
		t.Fatal("tolerant Load() produced a nil active config; the fixture must " +
			"reach a LOADED state with the dangling reference, not a failed compile")
	}
	return reloaded
}

// TestScreenUnresolvedProfileZonesEmittedOnTolerantLoad is the #5806
// fail-on-revert proof for acceptance criterion 4 — "runtime status and
// Prometheus expose the unresolved reference and enforcement disposition; one
// warning is not the sole signal".
//
// Before this, a rate-limited runtime WARN in the Rust screen runtime was the
// ONLY signal that a zone's configured screens are entirely unenforced; nothing
// in pkg/api, pkg/grpcapi or pkg/cli referenced the missing-profile set at all.
//
// The dataplane is deliberately nil: this is a config-derived control-plane
// signal that must survive a config-only / degraded boot, so Collect must run
// collectScreenUnresolvedProfileZones BEFORE the `dp == nil || !dp.IsLoaded()`
// gate. Moving the call below that gate makes this RED (the series vanishes).
//
// RED on revert: drop the collector call, the descriptor, or the exported
// dpuserspace.ScreenMissingProfileRefs seam, and the series is absent.
func TestScreenUnresolvedProfileZonesEmittedOnTolerantLoad(t *testing.T) {
	s := &Server{store: danglingScreenRefStore(t)} // dp intentionally nil.
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	type series struct{ zone, profile string }
	got := map[series]float64{}
	var help string
	var labelNames []string
	for _, mf := range mfs {
		if mf.GetName() != "xpf_screen_unresolved_profile_zones" {
			continue
		}
		help = mf.GetHelp()
		for _, m := range mf.GetMetric() {
			var k series
			labelNames = labelNames[:0]
			for _, l := range m.GetLabel() {
				labelNames = append(labelNames, l.GetName())
				switch l.GetName() {
				case "zone":
					k.zone = l.GetValue()
				case "profile":
					k.profile = l.GetValue()
				}
			}
			got[k] = m.GetGauge().GetValue()
		}
	}

	if len(got) != 1 {
		t.Fatalf("xpf_screen_unresolved_profile_zones series = %v, want exactly one "+
			"{trust, alpha} entry (config-only boot; the collector must run BEFORE "+
			"the dataplane gate)", got)
	}
	want := series{zone: "trust", profile: "alpha"}
	if v, ok := got[want]; !ok || v != 1 {
		t.Fatalf("series %+v = %v (present=%v), want 1; got map %v", want, v, ok, got)
	}

	// The label set is exactly {zone, profile}. The enforcement disposition is a
	// GLOBAL statement about the implementation — identical for every series — so
	// it belongs in HELP, not in a label: a label would carry no information and
	// would hand us unbounded cardinality the day the prose starts to vary.
	if len(labelNames) != 2 {
		t.Errorf("label set = %v, want exactly [zone profile]", labelNames)
	}
	for _, l := range labelNames {
		if l != "zone" && l != "profile" {
			t.Errorf("unexpected label %q; the disposition must live in HELP, not a label", l)
		}
	}
	// HELP must carry the disposition, and it must be the SHARED string so the
	// metric and the `show security screen` block cannot drift apart.
	if !strings.Contains(help, dpuserspace.ScreenUnresolvedDisposition) {
		t.Errorf("HELP must carry the shared disposition string; got %q", help)
	}
	// The #5806 anchor is load-bearing: this describes a decision made in the Rust
	// runtime that Go cannot derive, so when the posture is settled a grep for the
	// issue number has to land here.
	if !strings.Contains(help, "5806") {
		t.Errorf("HELP disposition must carry the #5806 anchor so a posture change "+
			"greps to this claim; got %q", help)
	}
	// The posture change #5806 anticipated arrived in #7168, so its anchor is
	// load-bearing too. Both are required: #5806 is the lineage a reader may
	// grep from, #7168 is what the runtime does today.
	if !strings.Contains(help, "7168") {
		t.Errorf("HELP disposition must carry the #7168 anchor (the settled posture); "+
			"got %q", help)
	}

	for k := range got {
		if k.zone == "wan" {
			t.Error("wan configures NO screen at all — it is not a dangling reference " +
				"and must not appear (low-noise contract)")
		}
	}
}

// TestScreenUnresolvedProfileZonesSilentWhenResolved is the negative control.
// A config whose screen reference RESOLVES must emit no series at all —
// otherwise the guard above would pass even if the collector emitted a row for
// every screened zone, which would make the metric useless as an alert.
func TestScreenUnresolvedProfileZonesSilentWhenResolved(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.10/24; } } } }
security {
    screen { ids-option alpha { icmp { ping-death; } } }
    zones { security-zone trust { screen alpha; interfaces { ge-0/0/0.0; } } }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	s := &Server{store: store}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "xpf_screen_unresolved_profile_zones" {
			t.Fatalf("a RESOLVED screen reference must emit no series; got %d",
				len(mf.GetMetric()))
		}
	}
}

// TestScreenUnresolvedProfileZonesNilStoreNoPanic guards the degraded path: a
// Server with no store (early boot) must not panic when the collector runs
// ahead of the dataplane gate.
func TestScreenUnresolvedProfileZonesNilStoreNoPanic(t *testing.T) {
	s := &Server{}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("Gather with nil store: %v", err)
	}
}
