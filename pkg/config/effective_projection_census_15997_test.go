package config

import (
	"reflect"
	"sort"
	"testing"
)

// #15997: the effective-term projection is hand-maintained, so a future
// semantic field on FirewallFilterTerm would silently escape the
// identical-duplicate comparator (the #8258 asymmetry). This census fails
// the build until the new field is projected (or explicitly excluded
// below with a reason).
func TestEffectiveProjectionCensus15997(t *testing.T) {
	termType := reflect.TypeOf(FirewallFilterTerm{})
	projType := reflect.TypeOf(effectiveTermProjection15997{})

	// Fields of FirewallFilterTerm that are NOT term-match semantics and
	// therefore legitimately absent from the projection. None today: every
	// field affects matching, actions, or strict/tolerant disposition.
	excluded := map[string]string{}

	termFields := map[string]bool{}
	for i := range termType.NumField() {
		termFields[termType.Field(i).Name] = true
	}
	projFields := map[string]bool{}
	for i := range projType.NumField() {
		projFields[projType.Field(i).Name] = true
	}

	// Projection-only synthetic fields (not term fields).
	synthetic := map[string]bool{"HasFlexMatch": true}

	var missing, extra []string
	// Term fields are unexported in part (unknownChildren etc.); projection
	// uses exported names for them. Compare case-insensitively by mapping
	// projection names lower-first-letter to term names.
	lowerFirst := func(s string) string {
		if s == "" {
			return s
		}
		return string(s[0]+'a'-'A') + s[1:]
	}
	// Build term field set with both spellings.
	termByLower := map[string]string{}
	for name := range termFields {
		termByLower[name] = name
		termByLower[lowerFirst(name)] = name
	}
	matchedTerm := map[string]bool{}
	for name := range projFields {
		if synthetic[name] {
			continue
		}
		if termName, ok := termByLower[name]; ok {
			matchedTerm[termName] = true
			// Also accept exact or lowerFirst match in either direction.
			matchedTerm[name] = true
			continue
		}
		if _, ok := termByLower[lowerFirst(name)]; ok {
			matchedTerm[termByLower[lowerFirst(name)]] = true
			continue
		}
		extra = append(extra, name)
	}
	for name := range termFields {
		if _, ex := excluded[name]; ex {
			continue
		}
		if !matchedTerm[name] && !projFields[name] && !projFields[upperFirst(name)] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Fatalf("FirewallFilterTerm fields missing from effectiveTermProjection15997: %v — add them to the projection (or exclude with reason)", missing)
	}
	if len(extra) > 0 {
		t.Fatalf("projection fields with no FirewallFilterTerm counterpart: %v", extra)
	}
	if termType.NumField() != projType.NumField()-len(synthetic)+len(excluded) {
		t.Fatalf("field counts: FirewallFilterTerm=%d projection=%d (synthetic %d, excluded %d) — census drift", termType.NumField(), projType.NumField(), len(synthetic), len(excluded))
	}
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	if s[0] >= 'a' && s[0] <= 'z' {
		return string(s[0]-'a'+'A') + s[1:]
	}
	return s
}
