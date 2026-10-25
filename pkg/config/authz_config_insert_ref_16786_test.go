package config

import "testing"

// #16786 (R3-A53-03): `insert` adjudicated only the moved element, never
// the reference. Security policies are first-match within a zone pair,
// so moving a permitted policy ahead of a protected deny policy changes
// that deny's effective position even though its statement is untouched.
// The old gate discarded the ref (`resolve(elem)` only) on the rationale
// that "a deny covering the element covers it" — true only for a deny on
// the common parent, false for a deny (anchored or plain) on the
// reference policy itself.
//
// These cells run through AuthorizeConfigMutation, the shared decision
// every surface (on-box CLI, gRPC, REST) calls, so one fix prices all
// of them. Both deny spellings are cells, mirroring #9938: an unanchored
// deny and an anchored deny must each refuse an insert whose REFERENCE
// is the denied path while its element is allowed.
//
// RED pre-fix: every "refused" cell below is ALLOWED (the gate never
// builds the ref path), while the positive controls already pass.

func TestInsertAdjudicatesReferencePath16786(t *testing.T) {
	// Plain (unanchored) deny on the denied policy p1, anchored deny
	// fixture is mutCfgFor9938's anchoredDeny (^security policies p1$).
	cfg := mutCfgFor9938(t)

	for name, tc := range map[string]struct {
		class string
		line  string
	}{
		// Defect cells: element allowed, reference denied.
		"plain deny, insert allowed before denied": {
			"plainDeny", "insert security policies ok before security policies p1",
		},
		"plain deny, insert allowed after denied": {
			"plainDeny", "insert security policies ok after security policies p1",
		},
		"anchored deny, insert allowed before denied": {
			"anchoredDeny", "insert security policies ok before security policies p1",
		},
		"anchored deny, insert allowed after denied": {
			"anchoredDeny", "insert security policies ok after security policies p1",
		},
		// Short ref spelling: the ref tokens replace the element's
		// trailing identifier under the same parent, so `before p1`
		// under element `security policies ok` IS `security policies p1`.
		// A fix that joined the raw ref tokens without InsertRefPath
		// resolution would miss this spelling.
		"plain deny, short ref": {
			"plainDeny", "insert security policies ok before p1",
		},
		"anchored deny, short ref": {
			"anchoredDeny", "insert security policies ok before p1",
		},
		// Edit-path resolved: under [edit security] the typed element
		// `policies ok` + ref `p1` resolves to the denied reference.
		"anchored deny, short ref via edit path": {
			"anchoredDeny", "insert policies ok before p1",
		},
	} {
		t.Run(name+" refused", func(t *testing.T) {
			editPath := []string(nil)
			if name == "anchored deny, short ref via edit path" {
				editPath = []string{"security"}
			}
			if err := AuthorizeConfigMutation(cfg, tc.class, editPath, tc.line); err == nil {
				t.Fatalf("%q was ALLOWED; the insert reference is the denied "+
					"path and moving the element relative to it reorders a "+
					"protected first-match policy (#16786)", tc.line)
			}
		})
	}

	// Element-denied cells must stay refused (pre-existing #9938
	// behaviour; a ref fix must not trade one endpoint for the other).
	for name, line := range map[string]string{
		"plain deny, denied element before allowed ref":    "insert security policies p1 before security policies ok",
		"anchored deny, denied element before allowed ref": "insert security policies p1 before security policies ok",
	} {
		class := "plainDeny"
		if name[:8] == "anchored" {
			class = "anchoredDeny"
		}
		t.Run(name+" refused", func(t *testing.T) {
			if err := AuthorizeConfigMutation(cfg, class, nil, line); err == nil {
				t.Fatalf("%q was ALLOWED; the insert element is denied (#16786/#9938)", line)
			}
		})
	}
}

// Positive controls: an insert with BOTH endpoints allowed still runs,
// under both deny spellings and under an allow-list. Without these, a
// "refuse every insert" non-fix would pass the defect cells above.
func TestInsertWithBothEndpointsAllowedStillRuns16786(t *testing.T) {
	cfg := mutCfgFor9938(t)
	for _, class := range []string{"plainDeny", "anchoredDeny"} {
		for _, line := range []string{
			"insert security policies ok before security policies alsook",
			"insert security policies ok after security policies alsook",
			"insert security policies ok before alsook",
			"insert security zones trust before security zones dmz",
		} {
			if err := AuthorizeConfigMutation(cfg, class, nil, line); err != nil {
				t.Errorf("class %s: %q refused though neither endpoint is denied: %v (#16786)", class, line, err)
			}
		}
	}
	// Allow-list class: both endpoints under the allow pass; an insert
	// whose REFERENCE falls outside the allow is refused even though
	// the element is inside it (the allow-configuration mirror of the
	// defect — longest-match adjudication sees the ref path at all).
	allowCfg := classWithConfigRegex9154(t, "^security policies", "")
	if err := AuthorizeConfigMutation(allowCfg, "limited", nil,
		"insert security policies ok before security policies alsook"); err != nil {
		t.Errorf("allow-list: both-endpoints-allowed insert refused: %v (#16786)", err)
	}
	if err := AuthorizeConfigMutation(allowCfg, "limited", nil,
		"insert security policies ok before security zones trust"); err == nil {
		t.Error("allow-list: insert with reference outside the allow was ALLOWED (#16786)")
	}
	// A class with no configuration regexes is unaffected.
	if err := AuthorizeConfigMutation(cfg, "wideopen", nil,
		"insert security policies ok before security policies p1"); err != nil {
		t.Errorf("wideopen class refused an insert: %v (#16786)", err)
	}
}
