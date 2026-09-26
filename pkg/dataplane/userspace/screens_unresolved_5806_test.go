package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// unresolvedRefConfig builds a config with all three shapes the predicate must
// tell apart: a zone with a DANGLING screen reference, a zone whose reference
// RESOLVES, and a zone with NO screen at all.
func unresolvedRefConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"defined": {},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":     {Name: "trust", ScreenProfile: "missing"},
		"dmz":       {Name: "dmz", ScreenProfile: "defined"},
		"unscanned": {Name: "unscanned"},
	}
	return cfg
}

// TestScreenMissingProfileRefsExportedSSOT pins the exported seam (#5806): the
// Prometheus collector and both `show security screen` renderers read this, and
// it must return ONLY genuinely dangling references. A predicate that also
// returned resolved zones would make the metric fire on every screened firewall
// and be useless as an alert; one that returned unscreened zones would fire on
// every firewall, period.
//
// RED on revert: delete the ScreenMissingProfileRefs wrapper (the observability
// surfaces lose their SSOT and must re-derive the predicate, which is exactly
// the drift this seam exists to prevent).
func TestScreenMissingProfileRefsExportedSSOT(t *testing.T) {
	got := ScreenMissingProfileRefs(unresolvedRefConfig())
	if len(got) != 1 {
		t.Fatalf("ScreenMissingProfileRefs = %+v, want exactly one entry (trust->missing)", got)
	}
	if got[0].Zone != "trust" || got[0].Profile != "missing" {
		t.Fatalf("got %+v, want {Zone:trust Profile:missing}", got[0])
	}
	// The exported seam must be the SAME computation the dataplane snapshot
	// carries, not a parallel re-derivation.
	internal := buildScreenMissingProfileRefs(unresolvedRefConfig())
	if len(internal) != len(got) || internal[0] != got[0] {
		t.Fatalf("exported seam diverged from the snapshot builder: %+v vs %+v", got, internal)
	}
	if ScreenMissingProfileRefs(nil) != nil {
		t.Error("nil config must yield no refs")
	}
}

// TestScreenUnresolvedProfileLinesNamesZoneProfileAndDisposition is the
// fail-on-revert guard for the operator-facing status block. It must name the
// zone, the referenced profile, AND the enforcement disposition — the #5806
// acceptance criterion is that the operator can see the reference is unresolved
// *and* what the dataplane currently does about it, not merely that something
// is wrong.
//
// RED on revert: drop any of the three from the rendering and the matching
// assertion fails.
func TestScreenUnresolvedProfileLinesNamesZoneProfileAndDisposition(t *testing.T) {
	lines := ScreenUnresolvedProfileLines(unresolvedRefConfig())
	if len(lines) == 0 {
		t.Fatal("a dangling reference must render a status block")
	}
	joined := strings.Join(lines, "\n")
	// The disposition is ONE trailing line, not a per-zone annotation: it is a
	// global statement about the implementation, so repeating it per row is noise.
	if n := strings.Count(joined, ScreenUnresolvedDisposition); n != 1 {
		t.Errorf("disposition must appear exactly once (a global statement, not a "+
			"per-zone annotation); got %d occurrences in:\n%s", n, joined)
	}
	// The #5806 anchor must survive into the rendered text: this asserts runtime
	// behaviour that lives in Rust and Go cannot derive, so a posture change has
	// to grep to it.
	if !strings.Contains(joined, "5806") {
		t.Errorf("rendered disposition must carry the #5806 anchor; got:\n%s", joined)
	}
	// #7168 SETTLED the posture #5806 deferred, so the anchor for what the
	// dataplane does NOW must also be greppable. #5806 is kept alongside it
	// rather than replaced: it is the lineage, and someone working from the old
	// issue must still land here.
	if !strings.Contains(joined, "7168") {
		t.Errorf("rendered disposition must carry the #7168 anchor — that is the issue "+
			"that decided what the dataplane actually does with an unresolved "+
			"reference; got:\n%s", joined)
	}
	for _, want := range []string{"trust", "missing", ScreenUnresolvedDisposition} {
		if !strings.Contains(joined, want) {
			t.Errorf("status block must mention %q; got:\n%s", want, joined)
		}
	}
	// The resolved and unscreened zones must not be reported as problems.
	for _, unwanted := range []string{"dmz", "unscanned"} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("zone %q is not a dangling reference and must not appear; got:\n%s",
				unwanted, joined)
		}
	}
}

// TestScreenUnresolvedProfileLinesSilentWhenResolved is the negative control:
// a healthy config must render nothing, so callers can append unconditionally
// and operators never see a spurious warning block.
func TestScreenUnresolvedProfileLinesSilentWhenResolved(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Screen = map[string]*config.ScreenProfile{"defined": {}}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"dmz": {Name: "dmz", ScreenProfile: "defined"},
	}
	if lines := ScreenUnresolvedProfileLines(cfg); lines != nil {
		t.Fatalf("a fully resolved config must render nothing; got %v", lines)
	}
	if lines := ScreenUnresolvedProfileLines(nil); lines != nil {
		t.Fatalf("nil config must render nothing; got %v", lines)
	}
}

// TestQuotedEmptyScreenProfileIsUnresolved10973 ensures tolerant compilation
// retains an explicitly empty binding as a missing reference, not an
// unconfigured zone. That entry feeds both operator diagnostics and the
// dataplane's conservative-default warning path.
func TestQuotedEmptyScreenProfileIsUnresolved10973(t *testing.T) {
	path, quoted, grouped, err := config.ParseSetCommandGrouped(`set security zones security-zone trust screen ""`)
	if err != nil {
		t.Fatalf("parse set command: %v", err)
	}
	tree := &config.ConfigTree{}
	if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
		t.Fatalf("SetPathQuotedGrouped: %v", err)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), `security zone "trust" has an empty screen profile reference`) {
		t.Fatalf("lenient compile did not warn about the empty zone binding: %v", cfg.Warnings)
	}
	refs := ScreenMissingProfileRefs(cfg)
	if len(refs) != 1 || refs[0].Zone != "trust" || refs[0].Profile != "" {
		t.Fatalf("quoted-empty binding refs = %+v, want [{Zone:trust Profile:}]", refs)
	}
	lines := ScreenUnresolvedProfileLines(cfg)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, `Zone trust references undefined screen profile ''`) ||
		!strings.Contains(joined, ScreenUnresolvedDisposition) {
		t.Fatalf("operator status did not identify the empty profile and its disposition: %v", lines)
	}
}
