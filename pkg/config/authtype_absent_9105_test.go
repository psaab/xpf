package config

import (
	"strings"
	"testing"
)

// #9105: an `authentication-key` with NO `authentication-type` rendered the key
// in PLAINTEXT on the wire, silently.
//
// At the pkg/frr render sites an ABSENT type and a CHOSEN plaintext type are the
// same state. `simple` rendering `clear` is CORRECT — the operator asked for
// plaintext — and the empty string took the identical path, so no care at the
// render site could separate them: the information was destroyed before the
// renderer ran.
//
// The downgrade is quiet in the worst way. Authentication stays ON, adjacencies
// come up and authenticate, and `show configuration` echoes back whatever was
// written. A dropped-authentication defect is noisy; this one succeeds.
func TestAuthKeyWithoutTypeIsRefused9105(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lines      []string
		wantStrict bool // true = accepted
	}{
		// THE DEFECT, at all three sites the renderers cover.
		{"isis key, no type", []string{
			"set protocols isis authentication-key secret1"}, false},
		{"rip key, no type", []string{
			"set protocols rip authentication-key secret1"}, false},
		{"isis interface key, no type", []string{
			"set protocols isis interface ge-0/0/0 authentication-key secret1"}, false},

		// ACCEPTED: the operator stated their intent, either way.
		{"isis key + md5", []string{
			"set protocols isis authentication-key secret1",
			"set protocols isis authentication-type md5"}, true},
		// THE ROW THAT BOUNDS THE GATE. `simple` is a deliberate plaintext
		// choice and must stay legal — this gate asks for a decision, it does
		// not forbid plaintext. Without this row, "reject when it renders
		// clear" would satisfy every case above and take a supported
		// configuration away.
		{"isis key + simple (deliberate plaintext)", []string{
			"set protocols isis authentication-key secret1",
			"set protocols isis authentication-type simple"}, true},
		// No key means nothing to expose — in #9105's own terms. #14399
		// rejects this same cell from the other direction (a stated type
		// with no key renders UNAUTHENTICATED); the two gates compose, so
		// type-only no longer commits. Keyed `simple` above is the way to
		// state plaintext deliberately.
		{"isis type only, no key (#14399 rejects)", []string{
			"set protocols isis authentication-type md5"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &ConfigTree{}
			for _, l := range tc.lines {
				p, err := ParseSetCommand(l)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", l, err)
				}
				if err := tr.SetPath(p); err != nil {
					t.Fatalf("SetPath: %v", err)
				}
			}
			_, err := CompileConfig(tr)
			if (err == nil) != tc.wantStrict {
				t.Fatalf("strict accepted=%v, want %v (err=%v)", err == nil, tc.wantStrict, err)
			}
			if !tc.wantStrict {
				// The message must name what to DO. "rejected" without the
				// remedy sends the operator to the schema.
				if !strings.Contains(err.Error(), "authentication-type md5") {
					t.Errorf("the refusal does not name the remedy: %v", err)
				}
			}

			// #1960: the TOLERANT path must WARN, never refuse. A config an
			// older binary accepted has to boot; refusing here would turn a
			// silent downgrade into a failure to load.
			lc, lerr := CompileConfigLenient(tr)
			if lerr != nil {
				t.Fatalf("the lenient path REJECTED — a persisted or peer-synced config would "+
					"fail to load (#1960): %v", lerr)
			}
			if !tc.wantStrict {
				var warned bool
				for _, w := range lc.Warnings {
					if strings.Contains(w, "authentication-type") {
						warned = true
					}
				}
				if !warned {
					t.Error("the lenient path accepted a key with no type and said NOTHING — " +
						"silent is the state #9105 is about")
				}
			}
		})
	}
}

// TestAuthTypeAbsentDistinguishesFromChosen9105 pins the predicate the whole
// fix rests on. Before it, `AuthTypeUnrecognized("")` was FALSE and
// `AuthTypeIsMD5("")` was FALSE, so an absent type fell into the plaintext arm
// with no warning — the same cell as a chosen `simple`.
func TestAuthTypeAbsentDistinguishesFromChosen9105(t *testing.T) {
	for _, tc := range []struct {
		raw          string
		absent       bool
		unrecognized bool
		isMD5        bool
	}{
		{"", true, false, false},        // the defect's cell
		{"   ", true, false, false},     // whitespace is still absent
		{"simple", false, false, false}, // chosen plaintext — renders clear, correctly
		{"md5", false, false, true},
		{"bogus", false, true, false},
	} {
		t.Run("type="+tc.raw, func(t *testing.T) {
			if got := AuthTypeAbsent(tc.raw); got != tc.absent {
				t.Errorf("AuthTypeAbsent(%q) = %v, want %v", tc.raw, got, tc.absent)
			}
			// These two are asserted UNCHANGED. AuthTypeIsMD5 must not start
			// promoting an absent type to md5: a box running plaintext against
			// a peer expecting plaintext would flip on upgrade and the
			// adjacency would drop — a silent downgrade turned into a silent
			// outage, on the path whose purpose is that a persisted config
			// boots.
			if got := AuthTypeUnrecognized(tc.raw); got != tc.unrecognized {
				t.Errorf("AuthTypeUnrecognized(%q) = %v, want %v", tc.raw, got, tc.unrecognized)
			}
			if got := AuthTypeIsMD5(tc.raw); got != tc.isMD5 {
				t.Errorf("AuthTypeIsMD5(%q) = %v, want %v", tc.raw, got, tc.isMD5)
			}
		})
	}
}
