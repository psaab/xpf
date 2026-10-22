package config

import (
	"reflect"
	"strings"
	"testing"
)

// #16166 PR-0: completeness of the tolerant-path opt set.
//
// compileOpts carries ~300 lenient*/sanitize* severity-downgrade bools.
// Adding a gate requires the field (link 1) AND `field: true` in
// lenientCompileOpts() (link 2). Forgetting link 2 silently makes the
// tolerant load / peer-sync path strict for that gate — the #1960
// brick-the-boot class — and no compiler error catches it, because the
// zero value is a perfectly valid bool. Until now the invariant was
// enforced by reviewer vigilance only.
//
// This test enforces links 1-2 by construction: it reflects recursively
// over compileOpts (including the embedded protocolScopeOpts, whose two
// lenient bools a shallow NumField walk over compileOpts would miss)
// and asserts every lenient*/sanitize* bool is true in
// lenientCompileOpts(). It does NOT enforce links 3-4 (gate call-site
// reads the right flag; warning/show surface) — that is the separately
// gated registry work, not PR-0.
//
// Scope is deliberately the name prefix, not "every bool": compileOpts
// also carries non-downgrade bools whose lenient value is not uniformly
// true (skipCompactNormalize is a test seam that must stay false so the
// normalizer runs on the tolerant path; nodeAware is stamped per call
// by the node-aware entry, overwriting whatever the literal held).
// A future non-downgrade bool must not be named lenient*/sanitize*, and
// a future downgrade bool must — the prefix is the contract this test
// polices. The suppress* advisory bools are the one deliberate
// exception already in the tree: they silence commit-time advisories
// (never a hard error) on the tolerant paths, are set true in
// lenientCompileOpts(), and are allowlisted explicitly below so the
// exception is reviewed rather than silent.

// lenientCompletenessAllowlist16166 names every bool field reachable
// from compileOpts that is NOT required to be true in
// lenientCompileOpts(), with the reason. Any bool not prefixed
// lenient*/sanitize* and not listed here fails the census arm of the
// test, so a new bool forces an explicit decision here.
var lenientCompletenessAllowlist16166 = map[string]string{
	// #8690 test seam: production and the tolerant path must run the
	// compact normalizer; only measurement tests set this.
	"skipCompactNormalize": "test seam (#8690); tolerant path must normalize",
	// #4329 runtime identity: compileConfigForNodeWithOpts stamps
	// nodeAware/stampNodeID per call after lenientCompileOpts() returns,
	// so the literal's value is never operative.
	"nodeAware": "stamped per call by the node-aware entry (#4329)",
	// Advisory suppressors: not severity downgrades (the checks warn on
	// every path), but they ARE set true in lenientCompileOpts() today.
	// Listed so the prefix census classifies them deliberately; the
	// truth arm also covers them via the extra check below.
	"suppressClusterNTPAdvisory":         "advisory suppressor (#8357), true in lenientCompileOpts",
	"suppressContestedTrunkZoneAdvisory": "advisory suppressor (#7509), true in lenientCompileOpts",
	"suppressDPDThresholdIKEv2Advisory":  "advisory suppressor (#15025), true in lenientCompileOpts",
	"suppressFabricStampAdvisory":        "advisory suppressor (#10105), true in lenientCompileOpts",
}

// walkBoolFields16166 visits every bool field reachable from v,
// recursing into embedded and nested struct fields. path is the dotted
// field path from the root (e.g. "protocolScopeOpts.lenientOSPFAreaInterface11400").
func walkBoolFields16166(v reflect.Value, path string, visit func(path string, fv reflect.Value)) {
	t := v.Type()
	for i := range v.NumField() {
		sf := t.Field(i)
		fv := v.Field(i)
		p := sf.Name
		if path != "" {
			p = path + "." + sf.Name
		}
		if fv.Kind() == reflect.Struct {
			walkBoolFields16166(fv, p, visit)
			continue
		}
		if fv.Kind() == reflect.Bool {
			visit(p, fv)
		}
	}
}

func TestLenientCompileOptsCompleteness16166(t *testing.T) {
	opts := lenientCompileOpts()
	v := reflect.ValueOf(opts)

	var downgrades, others int
	walkBoolFields16166(v, "", func(path string, fv reflect.Value) {
		name := path[strings.LastIndex(path, ".")+1:]
		switch {
		case strings.HasPrefix(name, "lenient"), strings.HasPrefix(name, "sanitize"):
			downgrades++
			if !fv.Bool() {
				t.Errorf("%s is false in lenientCompileOpts(): the field exists but its "+
					"lenientCompileOpts() entry is missing, so the tolerant load / peer-sync "+
					"path stays STRICT for this gate and a persisted or peer-synced config an "+
					"older binary accepted would fail to boot (#1960). Add `%s: true` to "+
					"lenientCompileOpts() in compiler_opts.go", path, name)
			}
		case lenientCompletenessAllowlist16166[name] != "":
			others++
		default:
			t.Errorf("%s is a bool in compileOpts that is neither a lenient*/sanitize* "+
				"downgrade nor allowlisted in lenientCompletenessAllowlist16166: classify it. "+
				"If it downgrades a gate on the tolerant path, name it lenient*/sanitize* so "+
				"this test requires it true in lenientCompileOpts(); otherwise add it to the "+
				"allowlist with the reason its lenient value is not required to be true", path)
		}
	})

	// Census guards: the walk must actually reach the population it
	// claims to police. A walk that silently visits nothing (or stops
	// recursing into the embedded protocolScopeOpts) would green while
	// missing exactly the class this test exists to catch, so pin the
	// embedded fields by name and require a plausible census. The floor
	// is deliberately below the current count (re-measured at
	// implementation: 298 lenient*/sanitize* bools, 296 direct in
	// compileOpts plus 2 in the embedded protocolScopeOpts) so removing
	// a retired gate does not flake this test, while a collapsed walk
	// (0, or 296-without-the-embedded-pair shape) still trips it via
	// the named pins below.
	if downgrades < 250 {
		t.Errorf("census: only %d lenient*/sanitize* bools reached by the recursive walk; "+
			"the walk is not reaching the compileOpts population (want ~298)", downgrades)
	}
	if others == 0 {
		t.Error("census: no allowlisted non-downgrade bools reached; the walk is not " +
			"reaching compileOpts fields such as skipCompactNormalize")
	}
	embedded := opts.protocolScopeOpts
	if !embedded.lenientProtocolInterfaceMembership11310 {
		t.Error("protocolScopeOpts.lenientProtocolInterfaceMembership11310 is false in " +
			"lenientCompileOpts(): embedded-struct downgrade not registered (recursion pin)")
	}
	if !embedded.lenientOSPFAreaInterface11400 {
		t.Error("protocolScopeOpts.lenientOSPFAreaInterface11400 is false in " +
			"lenientCompileOpts(): embedded-struct downgrade not registered (recursion pin)")
	}
	// The allowlisted suppress* bools are in fact set true today; pin
	// that so the allowlist entry cannot quietly become the place a
	// forgotten registration hides. Removing one from
	// lenientCompileOpts() must fail here, not pass via the allowlist.
	if !opts.suppressClusterNTPAdvisory || !opts.suppressContestedTrunkZoneAdvisory ||
		!opts.suppressDPDThresholdIKEv2Advisory || !opts.suppressFabricStampAdvisory {
		t.Error("a suppress* advisory bool is false in lenientCompileOpts(): the tolerant " +
			"paths would re-fire commit-time advisories on every boot / peer sync; " +
			"restore its `true` entry in lenientCompileOpts()")
	}
	if opts.skipCompactNormalize {
		t.Error("skipCompactNormalize is true in lenientCompileOpts(): the tolerant path " +
			"must run the compact normalizer (#8690 seam is test-only)")
	}
	if opts.nodeAware {
		t.Error("nodeAware is true in lenientCompileOpts(): node identity must come only " +
			"from the node-aware entry's per-call stamp (#4329)")
	}
}

// TestLenientCompletenessWalkRecurses16166 proves the walk itself
// recurses into embedded structs, independent of the current field
// population: a planted lenient bool inside a protocolScopeOpts-shaped
// embedded struct that is left false must be reported. Without this
// arm, a future refactor that flattened the walk to direct fields
// would keep the completeness test green while missing the embedded
// pair — the exact failure the Codex dissent on #16166 called out.
func TestLenientCompletenessWalkRecurses16166(t *testing.T) {
	type plantedEmbedded struct {
		lenientPlantedEmbedded16166 bool
		lenientPlantedSet16166      bool
	}
	type plantedRoot struct {
		lenientPlantedDirect16166 bool
		plantedEmbedded
	}
	root := plantedRoot{plantedEmbedded: plantedEmbedded{lenientPlantedSet16166: true}}

	var seen []string
	var falseDowngrades []string
	walkBoolFields16166(reflect.ValueOf(root), "", func(path string, fv reflect.Value) {
		seen = append(seen, path)
		name := path[strings.LastIndex(path, ".")+1:]
		if (strings.HasPrefix(name, "lenient") || strings.HasPrefix(name, "sanitize")) && !fv.Bool() {
			falseDowngrades = append(falseDowngrades, path)
		}
	})

	wantSeen := map[string]bool{
		"lenientPlantedDirect16166":                   false,
		"plantedEmbedded.lenientPlantedEmbedded16166": false,
		"plantedEmbedded.lenientPlantedSet16166":      false,
	}
	for _, p := range seen {
		if _, ok := wantSeen[p]; ok {
			wantSeen[p] = true
		} else {
			t.Errorf("walk visited unexpected field %s", p)
		}
	}
	for p, found := range wantSeen {
		if !found {
			t.Errorf("walk did not visit %s; visited %v (recursion into embedded structs is broken)", p, seen)
		}
	}
	if len(falseDowngrades) != 2 {
		t.Errorf("false-downgrade detection = %v, want the unset direct and embedded planted fields", falseDowngrades)
	}
}
