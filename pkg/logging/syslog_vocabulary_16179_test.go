package logging

import (
	"strings"
	"testing"
)

// TestSyslogVocabularyDifferential16179 is the decisive old-vs-new check for
// #16179: the four hand-written vocabulary switches were replaced by lookup
// tables (categoryVocabulary shared by the two category parsers,
// severityVocabulary lenient, severityVocabularyStrict separate). The
// oracles below are literal transcriptions of the PRE-REFACTOR switches, so
// mutating any production table row — dropping a spelling, widening the
// strict set with a lenient-only name, or losing a sentinel row — turns
// this test red. It is not derived from the production maps.
//
// Pre-refactor semantics transcribed:
//   - ParseCategory: "all"/"" -> 0, the four categories -> their bits,
//     anything else -> 0 (case-sensitive).
//   - ParseCategoryStrict: same spellings/values, anything else errors.
//   - ParseSeverityStrict: "" -> 0, error/warning/notice/info only,
//     anything else errors (case-sensitive; "any"/"none"/"emergency"/
//     "alert"/"critical"/"debug" were all REJECTED).
//   - ParseSeverity: case-insensitive; any/"" -> 0, none -> SeverityNone,
//     emergency -> SeverityEmergency, alert..debug -> RFC 1..7,
//     anything else -> 0.
func TestSyslogVocabularyDifferential16179(t *testing.T) {
	oldCategory := map[string]uint8{
		"": 0, "all": 0,
		"session": CategorySession, "policy": CategoryPolicy,
		"screen": CategoryScreen, "firewall": CategoryFirewall,
	}
	oldSeverityLenient := map[string]int{ // keyed by lower-cased input
		"": 0, "any": 0, "none": SeverityNone, "emergency": SeverityEmergency,
		"alert": SyslogAlert, "critical": SyslogCritical, "error": SyslogError,
		"warning": SyslogWarning, "notice": SyslogNotice, "info": SyslogInfo,
		"debug": SyslogDebug,
	}
	oldSeverityStrict := map[string]int{
		"": 0, "error": SyslogError, "warning": SyslogWarning,
		"notice": SyslogNotice, "info": SyslogInfo,
	}

	// Candidate spellings: every oracle key, case variants of every key,
	// whitespace-padded variants, near-miss typos, numeric strings, and
	// names owned by other vocabularies (facility spellings must not leak
	// into category/severity).
	inputs := map[string]bool{"": true}
	for k := range oldCategory {
		inputs[k] = true
	}
	for k := range oldSeverityLenient {
		inputs[k] = true
	}
	for _, bad := range []string{
		"sessoin", "polic", "scree", "firewal", "warn", "err", "information",
		"emerg", "crit", "al", "alll", "anyy", "nonee", "debg", "notic",
		"0", "1", "7", "-1", "local0", "kern", "auth", "daemon", "user",
		"any ", " error", "error ", "\tinfo", "all categories", "session,policy",
	} {
		inputs[bad] = true
	}
	capitalize := func(s string) string {
		if s == "" {
			return s
		}
		return strings.ToUpper(s[:1]) + s[1:]
	}
	for k := range inputs { // ranging a map we extend is safe: variants are checked too, if visited
		inputs[strings.ToUpper(k)] = true
		inputs[capitalize(k)] = true
	}

	for name := range inputs {
		// Categories: lenient falls back to 0, strict errors, on any
		// spelling outside the (identical) oracle set.
		wantCat, catKnown := oldCategory[name]
		if got := ParseCategory(name); got != wantCat {
			t.Errorf("ParseCategory(%q) = %d, want %d (pre-refactor)", name, got, wantCat)
		}
		gotCat, err := ParseCategoryStrict(name)
		if catKnown {
			if err != nil || gotCat != wantCat {
				t.Errorf("ParseCategoryStrict(%q) = (%d, %v), want (%d, nil)", name, gotCat, err, wantCat)
			}
		} else if err == nil {
			t.Errorf("ParseCategoryStrict(%q) = (%d, nil), want error — strict parser must keep rejecting formerly rejected categories (fail-open)", name, gotCat)
		}

		// Severities: lenient is case-insensitive with a 0 fallback; the
		// separate strict set is case-sensitive and must keep rejecting
		// every formerly rejected spelling, including the lenient-only
		// names any/none/emergency/alert/critical/debug in any case.
		wantSev := oldSeverityLenient[strings.ToLower(name)] // absent -> 0, the old default
		if got := ParseSeverity(name); got != wantSev {
			t.Errorf("ParseSeverity(%q) = %d, want %d (pre-refactor)", name, got, wantSev)
		}
		wantStrict, strictKnown := oldSeverityStrict[name]
		gotSev, err := ParseSeverityStrict(name)
		if strictKnown {
			if err != nil || gotSev != wantStrict {
				t.Errorf("ParseSeverityStrict(%q) = (%d, %v), want (%d, nil)", name, gotSev, err, wantStrict)
			}
			// Where both parsers accept a spelling they must agree.
			if gotSev != ParseSeverity(name) {
				t.Errorf("severity %q: strict %d != lenient %d", name, gotSev, ParseSeverity(name))
			}
		} else if err == nil {
			t.Errorf("ParseSeverityStrict(%q) = (%d, nil), want error — strict parser must keep rejecting formerly rejected severities (fail-open)", name, gotSev)
		}
	}
}

// TestSyslogVocabularySentinelsAndSeparation16179 pins the explicit table
// encoding #16179 requires: sentinel rows present as rows (not implicit
// fallbacks), and the strict severity set kept separate from and narrower
// than the lenient one — merging them into a single shared allowlist is
// the rejected form of this issue.
func TestSyslogVocabularySentinelsAndSeparation16179(t *testing.T) {
	// Category sentinels: "all"/"" are explicit 0 rows; the strict parser
	// accepts them by membership while rejecting typos that also yield 0.
	for _, sentinel := range []string{"", "all"} {
		if v, ok := categoryVocabulary[sentinel]; !ok || v != 0 {
			t.Errorf("categoryVocabulary[%q] = (%d, %v), want explicit (0, true) sentinel row", sentinel, v, ok)
		}
	}
	// Severity sentinels: "any"->0 class collision with SyslogEmergency(0)
	// and the unknown fallback, "none"->SeverityNone, "emergency"->
	// SeverityEmergency must all be explicit rows.
	for name, want := range map[string]int{
		"": 0, "any": 0, "none": SeverityNone, "emergency": SeverityEmergency,
	} {
		if v, ok := severityVocabulary[name]; !ok || v != want {
			t.Errorf("severityVocabulary[%q] = (%d, %v), want explicit (%d, true) sentinel row", name, v, ok, want)
		}
	}
	// Separation: every lenient-only severity stays out of the strict
	// table, and every strict row exists in the lenient table with the
	// same value.
	for _, lenientOnly := range []string{"any", "none", "emergency", "alert", "critical", "debug"} {
		if _, ok := severityVocabularyStrict[lenientOnly]; ok {
			t.Errorf("severityVocabularyStrict must not admit lenient-only %q (merged allowlist would fail open)", lenientOnly)
		}
	}
	for name, want := range severityVocabularyStrict {
		if v, ok := severityVocabulary[name]; !ok || v != want {
			t.Errorf("strict severity %q=%d not mirrored in lenient table (%d, %v)", name, want, v, ok)
		}
	}
	if len(severityVocabularyStrict) >= len(severityVocabulary) {
		t.Errorf("strict severity table (%d rows) must stay narrower than lenient (%d rows)",
			len(severityVocabularyStrict), len(severityVocabulary))
	}
}
