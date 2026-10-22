package config

import (
	"fmt"
	"sort"
	"strings"
)

// ISIS level (`is-type`) canonicalization — #8446.
//
// `protocols isis level` and `protocols isis is-type` spell the SAME concept
// and both compile into ISISConfig.Level. Two independent defects met there:
//
//   - the leaves were untyped in setSchema, so ANY string committed; and
//   - the FRR renderer switched on the stored string with no `default` arm,
//     so an unrecognized value emitted NO `is-type` line at all and FRR fell
//     back to its own default, `level-1-2`.
//
// The composition silently WIDENED the router's adjacency scope. The sharpest
// case was self-inflicted: `is-type level-2-only` is the exact string xpf
// itself writes into frr.conf, and feeding it back in turned a Level-2-only
// router into a Level-1-2 one. Leaving the leaf unset produced level-2-only,
// so configuring it explicitly was LESS restrictive than not configuring it.
//
// This file is the one canonicalizer both sides share, so the commit gate and
// the renderer cannot drift (the pattern #6686 established for as-path
// regexes: same predicate, one definition).

// isisLevelSpellings maps every accepted operator spelling to its canonical
// form. `level-2-only` is FRR's spelling and the one this product emits, so it
// is accepted as a synonym rather than rejected — rejecting the output of our
// own renderer would be a surprising failure mode.
var isisLevelSpellings = map[string]string{
	"level-1":      "level-1",
	"level-2":      "level-2",
	"level-1-2":    "level-1-2",
	"level-2-only": "level-2",
}

// DefaultISISLevel is the level a `protocols isis` stanza with no `level` /
// `is-type` runs at. It is level-2 (rendered `is-type level-2-only`), matching
// the renderer's long-standing behaviour for an empty value.
const DefaultISISLevel = "level-2"

// CanonicalISISLevel maps an authored `level` / `is-type` value to its
// canonical spelling. An empty value canonicalizes to DefaultISISLevel so the
// unset case and the explicitly-default case travel the same path. ok is false
// for a value no accepted spelling matches.
func CanonicalISISLevel(raw string) (canonical string, ok bool) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return DefaultISISLevel, true
	}
	c, ok := isisLevelSpellings[v]
	return c, ok
}

// ISISLevelSpellings returns the accepted spellings in sorted order, for
// operator-facing error text, schema value examples, and completion.
func ISISLevelSpellings() []string {
	out := make([]string, 0, len(isisLevelSpellings))
	for k := range isisLevelSpellings {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ValidateISISLevel is the setSchema typed-leaf validator for `level` and
// `is-type`. It is shared by both schema copies (the top-level `protocols` one
// and the `routing-instances` one) so a spelling cannot be accepted in one
// context and rejected in the other.
func ValidateISISLevel(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected one of %s)",
			strings.Join(ISISLevelSpellings(), ", "))
	}
	if _, ok := CanonicalISISLevel(raw); !ok {
		return fmt.Errorf("not a valid IS-IS level: %q (expected one of %s)",
			raw, strings.Join(ISISLevelSpellings(), ", "))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Per-INTERFACE circuit type — #8450, a different leaf and a different defect.
//
// `protocols isis interface <if> level <n>` restricts one interface's adjacency
// to a level. It compiled into ISISInterface.Level and was then NEVER RENDERED:
// pkg/frr emitted no `isis circuit-type` line anywhere, so the interface formed
// adjacencies at the ROUTER-WIDE is-type regardless of what the operator wrote.
// Dead config that fails OPEN — the interface is wider than authored, which is
// the same direction as the router-wide #8446 defect one level down.
//
// The spelling domain is WIDER here than for the router-wide leaf. Junos writes
// the per-interface level as a bare digit (`level 1`), while FRR's circuit-type
// takes the `level-N` forms, so both must be accepted. That is why this is a
// separate canonicalizer rather than a reuse of CanonicalISISLevel: sharing it
// would have to widen the router-wide leaf's domain too, and `is-type 2` is a
// value #8446 deliberately rejects.
// ---------------------------------------------------------------------------

// isisCircuitTypeSpellings maps every accepted per-interface `level` spelling to
// the FRR `isis circuit-type` argument it renders as.
var isisCircuitTypeSpellings = map[string]string{
	"1":            "level-1",
	"2":            "level-2-only",
	"1-2":          "level-1-2",
	"level-1":      "level-1",
	"level-2":      "level-2-only",
	"level-1-2":    "level-1-2",
	"level-2-only": "level-2-only",
}

// CanonicalISISCircuitType maps an authored per-interface `level` value to the
// FRR circuit-type argument. An EMPTY value returns ("", true): no
// `isis circuit-type` line is rendered and the interface inherits the
// router-wide is-type, which is both FRR's behaviour and Junos's.
func CanonicalISISCircuitType(raw string) (circuitType string, ok bool) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", true
	}
	c, ok := isisCircuitTypeSpellings[v]
	return c, ok
}

// ISISCircuitTypeSpellings returns the accepted per-interface spellings in
// sorted order, for error text, schema value examples, and completion.
func ISISCircuitTypeSpellings() []string {
	out := make([]string, 0, len(isisCircuitTypeSpellings))
	for k := range isisCircuitTypeSpellings {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ValidateISISCircuitType is the setSchema typed-leaf validator for
// `protocols isis interface <if> level`. Shared by both schema copies.
func ValidateISISCircuitType(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected one of %s)",
			strings.Join(ISISCircuitTypeSpellings(), ", "))
	}
	if _, ok := CanonicalISISCircuitType(raw); !ok {
		return fmt.Errorf("not a valid IS-IS interface level: %q (expected one of %s)",
			raw, strings.Join(ISISCircuitTypeSpellings(), ", "))
	}
	return nil
}
