package config

import (
	"strings"
	"testing"
)

// #14398 (DR9-H2): RIP `authentication-type` without `authentication-key`
// rendered unauthenticated. The compiler reads type and key as independent
// leaves; #9105 rejects only the reverse (key without type). With a type
// but no key the renderer block (gated on AuthKey != "") emits nothing and
// warns nothing, so the interface forms an unauthenticated RIP adjacency
// despite `authentication-type md5`.

func TestRIPAuthTypeWithoutKeyIsRefused14398(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lines      []string
		wantStrict bool
		scope      string
	}{
		// THE DEFECT. Mirrors issue fixture.
		{"global md5 no key", []string{
			"set protocols rip authentication-type md5",
			"set protocols rip neighbor ge-0/0/1"}, false, "protocols rip"},
		{"global simple no key", []string{
			"set protocols rip authentication-type simple",
			"set protocols rip neighbor ge-0/0/1"}, false, "protocols rip"},
		{"global text no key", []string{
			"set protocols rip authentication-type text",
			"set protocols rip neighbor ge-0/0/1"}, false, "protocols rip"},
		// Routing-instance parity (DR10-H1 notes same loop idiom; #9105 RI
		// coverage is out of scope here except RIP must not escape via RI).
		{"routing-instance md5 no key", []string{
			"set routing-instances VRF-A instance-type vrf",
			"set routing-instances VRF-A protocols rip authentication-type md5",
			"set routing-instances VRF-A protocols rip neighbor ge-0/0/1"}, false, "routing-instance"},

		// CONTROLS: keyed (md5/plaintext) must still commit.
		{"global keyed md5", []string{
			"set protocols rip authentication-type md5",
			"set protocols rip authentication-key s3cret",
			"set protocols rip neighbor ge-0/0/1"}, true, ""},
		{"global keyed simple", []string{
			"set protocols rip authentication-type simple",
			"set protocols rip authentication-key s3cret",
			"set protocols rip neighbor ge-0/0/1"}, true, ""},
		{"routing-instance keyed md5", []string{
			"set routing-instances VRF-A instance-type vrf",
			"set routing-instances VRF-A protocols rip authentication-type md5",
			"set routing-instances VRF-A protocols rip authentication-key s3cret",
			"set routing-instances VRF-A protocols rip neighbor ge-0/0/1"}, true, ""},
		// Neither leaf: no auth chosen, still compiles.
		{"neither leaf", []string{
			"set protocols rip neighbor ge-0/0/1"}, true, ""},
		{"routing-instance neither leaf", []string{
			"set routing-instances VRF-A instance-type vrf",
			"set routing-instances VRF-A protocols rip neighbor ge-0/0/1"}, true, ""},
		// Key without type remains #9105's cell — must still reject (regression guard).
		{"key without type still 9105", []string{
			"set protocols rip authentication-key s3cret",
			"set protocols rip neighbor ge-0/0/1"}, false, "protocols rip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, strictErr := CompileConfig(flatTreeFromSets(t, tc.lines...))
			if (strictErr == nil) != tc.wantStrict {
				t.Fatalf("strict accepted=%v, want %v (err=%v)", strictErr == nil, tc.wantStrict, strictErr)
			}
			if !tc.wantStrict {
				if !strings.Contains(strictErr.Error(), "authentication-key") {
					t.Errorf("refusal does not name the missing key: %v", strictErr)
				}
				if tc.scope != "" && !strings.Contains(strictErr.Error(), tc.scope) {
					t.Errorf("refusal %q does not name scope %q", strictErr, tc.scope)
				}
			}
			lenientCfg, lenientErr := CompileConfigLenient(flatTreeFromSets(t, tc.lines...))
			if lenientErr != nil {
				t.Fatalf("lenient REJECTED — persisted/peer-synced config would fail to load (#1960): %v", lenientErr)
			}
			if !tc.wantStrict {
				var warned bool
				for _, w := range lenientCfg.Warnings {
					if strings.Contains(w, "authentication-key") {
						warned = true
					}
				}
				if !warned {
					t.Errorf("lenient accepted type-without-key silently; warnings=%v", lenientCfg.Warnings)
				}
			}
		})
	}
}
