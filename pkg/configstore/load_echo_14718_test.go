package configstore

import (
	"strings"
	"testing"
)

// #14718: flat load errors echoed the raw offending line verbatim
// (`line %d: %q ...`), so any caller who can submit load content —
// including a non-superuser PermConfig class whose `show configuration`
// is redacted under #4099 — could read denied file lines one error at a
// time by placing a valid flat verb line before the secret line.
// The rescue loader in this package already scrubs exactly this
// (rescueParseError, coordinates only). These cells pin the same
// discipline for merge / override / set, including the inner
// applyEditLine error which can itself carry path tokens from the line.
//
// FAIL-ON-REVERT: restoring any `%q` of the trimmed line (or the raw
// inner error) in parseOverrideContent / LoadMergeAsPlantClass /
// LoadSetAsPlantClass makes the marker appear in the error and fails.

const secretMarker14718 = "SECRET-MARKER-14718-do-not-echo"

func TestFlatLoadErrorsDoNotEchoLine14718(t *testing.T) {
	// Line 1 selects the flat branch; line 2 is the secret that must
	// never appear in the returned error. Two failure shapes:
	// (a) line 2 has no flat verb -> "not a ... command" arm
	// (b) line 2 has a flat verb but fails applyEditLine -> wrapped arm
	bodies := map[string]string{
		"no-verb secret line":          "set system host-name ok14718\n" + secretMarker14718 + "\n",
		"verb secret line fails apply": "set system host-name ok14718\ndelete " + secretMarker14718 + " nonexistent-path-14718\n",
	}
	for name, body := range bodies {
		t.Run(name+"/merge", func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			err := s.LoadMergeAsPlantClass("", "", body)
			if err == nil {
				t.Fatal("load merge of a body with a bad line 2 must fail")
			}
			if strings.Contains(err.Error(), secretMarker14718) {
				t.Errorf("merge error echoed the secret line: %v (#14718)", err)
			}
			if !strings.Contains(err.Error(), "line 2") {
				t.Errorf("merge error must retain the line coordinate: %v", err)
			}
		})
		t.Run(name+"/override", func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			err := s.LoadOverrideAsPlantClass("", "", body)
			if err == nil {
				t.Fatal("load override of a body with a bad line 2 must fail")
			}
			if strings.Contains(err.Error(), secretMarker14718) {
				t.Errorf("override error echoed the secret line: %v (#14718)", err)
			}
			if !strings.Contains(err.Error(), "line 2") {
				t.Errorf("override error must retain the line coordinate: %v", err)
			}
		})
		t.Run(name+"/set", func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			_, err := s.LoadSetAsPlantClass("", "", body)
			if err == nil {
				t.Fatal("load set of a body with a bad line 2 must fail")
			}
			if strings.Contains(err.Error(), secretMarker14718) {
				t.Errorf("set error echoed the secret line: %v (#14718)", err)
			}
			if !strings.Contains(err.Error(), "line 2") {
				t.Errorf("set error must retain the line coordinate: %v", err)
			}
		})
	}
}

// Positive control: a well-formed flat load still applies, so the scrub
// cannot pass by refusing everything.
func TestFlatLoadValidStillApplies14718(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadMergeAsPlantClass("", "", "set system host-name ok14718\n"); err != nil {
		t.Fatalf("valid flat merge refused: %v", err)
	}
	if got := s.ShowCandidate(); !strings.Contains(got, "ok14718") {
		t.Errorf("valid flat merge did not reach candidate:\n%s", got)
	}
}

// Hierarchical-branch control (bounds the claim): a hierarchical body
// whose parse fails must also not echo its secret leaf value.
func TestHierarchicalLoadErrorDoesNotEcho14718(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	body := "system {\n    root-authentication {\n        plain-text-password " + secretMarker14718 + "\n    }\n"
	err := s.LoadMergeAsPlantClass("", "", body)
	if err == nil {
		t.Fatal("unterminated hierarchical body must fail")
	}
	if strings.Contains(err.Error(), secretMarker14718) {
		t.Errorf("hierarchical error echoed the secret: %v (#14718)", err)
	}
}
