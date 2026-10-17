package config

import (
	"strings"
	"testing"
)

// #14400 (DR10-H1): the #9105 gate — an `authentication-key` with no
// `authentication-type` renders the key in PLAINTEXT — checked only the
// GLOBAL `protocols` instance. The identical key under
// `routing-instances <n> protocols rip|isis` compiled clean on strict
// commit and rendered plaintext per-VRF (pkg/frr renders per-instance
// RIP/IS-IS through the same plaintext arm), with no refusal and, on the
// lenient path, no warning naming the scope.
//
// The three VRF spellings below mirror the three global sites in
// TestAuthKeyWithoutTypeIsRefused9105 (RIP key, IS-IS key, IS-IS
// per-interface key). Each must be refused on strict commit, warned (not
// refused, #1960) on lenient load, and a VRF key WITH
// `authentication-type md5` or `simple` must still commit — the gate asks
// for a stated intent, it does not forbid plaintext.
func TestAuthKeyWithoutTypeInRoutingInstanceIsRefused14400(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lines      []string
		wantStrict bool
	}{
		// THE DEFECT, at all three per-instance sites the renderers cover.
		{"vrf rip key, no type", []string{
			"set routing-instances V protocols rip authentication-key secret1"}, false},
		{"vrf isis key, no type", []string{
			"set routing-instances V protocols isis authentication-key secret1"}, false},
		{"vrf isis interface key, no type", []string{
			"set routing-instances V protocols isis interface ge-0/0/0 authentication-key secret1"}, false},

		// ACCEPTED: the operator stated their intent, either way.
		{"vrf rip key + md5", []string{
			"set routing-instances V protocols rip authentication-key secret1",
			"set routing-instances V protocols rip authentication-type md5"}, true},
		{"vrf isis key + md5", []string{
			"set routing-instances V protocols isis authentication-key secret1",
			"set routing-instances V protocols isis authentication-type md5"}, true},
		{"vrf isis interface key + md5", []string{
			"set routing-instances V protocols isis interface ge-0/0/0 authentication-key secret1",
			"set routing-instances V protocols isis interface ge-0/0/0 authentication-type md5"}, true},
		// THE ROWS THAT BOUND THE GATE. `simple` is a deliberate plaintext
		// choice and must stay legal in a VRF exactly as globally.
		{"vrf rip key + simple (deliberate plaintext)", []string{
			"set routing-instances V protocols rip authentication-key secret1",
			"set routing-instances V protocols rip authentication-type simple"}, true},
		{"vrf isis key + simple (deliberate plaintext)", []string{
			"set routing-instances V protocols isis authentication-key secret1",
			"set routing-instances V protocols isis authentication-type simple"}, true},
		// No key means nothing to expose.
		{"vrf isis type only, no key", []string{
			"set routing-instances V protocols isis authentication-type md5"}, true},
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
				if !strings.Contains(err.Error(), "authentication-type md5") {
					t.Errorf("the refusal does not name the remedy: %v", err)
				}
				if !strings.Contains(err.Error(), "routing-instances V") {
					t.Errorf("the refusal does not name the routing-instance scope: %v", err)
				}
			}

			// #1960: the TOLERANT path must WARN, never refuse.
			lc, lerr := CompileConfigLenient(tr)
			if lerr != nil {
				t.Fatalf("the lenient path REJECTED — a persisted or peer-synced config would "+
					"fail to load (#1960): %v", lerr)
			}
			if !tc.wantStrict {
				var warned bool
				for _, w := range lc.Warnings {
					if strings.Contains(w, "authentication-type") && strings.Contains(w, "routing-instances V") {
						warned = true
					}
				}
				if !warned {
					t.Error("the lenient path accepted a VRF key with no type and said NOTHING " +
						"naming the instance — silent is the state #9105/#14400 is about")
				}
			}
		})
	}
}

// TestAuthKeyWithoutTypeGlobalControl14400 is the positive control in the
// same run: the global spelling must still be refused, so a green VRF arm
// cannot be read as "the gate stopped firing entirely".
func TestAuthKeyWithoutTypeGlobalControl14400(t *testing.T) {
	tr := &ConfigTree{}
	p, err := ParseSetCommand("set protocols rip authentication-key secret1")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tr.SetPath(p); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	if _, err := CompileConfig(tr); err == nil {
		t.Fatal("CONTROL: global rip key with no type was accepted — the #9105 gate is not firing at all")
	}
}
