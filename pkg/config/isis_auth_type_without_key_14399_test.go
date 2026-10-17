package config

import (
	"strings"
	"testing"
)

// #14399 (DR9-H3): IS-IS `authentication-type` without `authentication-key`
// rendered unauthenticated. The compiler reads type and key as independent
// leaves at the area/domain level and per interface; #9105 rejects only the
// reverse (key without type). With a type but no key both renderer blocks
// (gated on AuthKey != "") emit nothing and warn nothing, so the adjacency
// forms with no authentication despite `authentication-type md5`.

func compileLines14399(t *testing.T, lines []string) (*Config, error, *Config, error) {
	t.Helper()
	tr := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tr.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	strictCfg, strictErr := CompileConfig(tr)
	tr2 := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tr2.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	lenientCfg, lenientErr := CompileConfigLenient(tr2)
	return strictCfg, strictErr, lenientCfg, lenientErr
}

func TestISISAuthTypeWithoutKeyIsRefused14399(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lines      []string
		wantStrict bool
		scope      string
	}{
		// THE DEFECT at both independent sites.
		{"global md5 no key", []string{
			"set protocols isis authentication-type md5"}, false, "protocols isis"},
		{"global simple no key", []string{
			"set protocols isis authentication-type simple"}, false, "protocols isis"},
		{"interface md5 no key", []string{
			"set protocols isis interface ge-0/0/0 authentication-type md5"}, false, "protocols isis interface"},
		{"interface simple no key", []string{
			"set protocols isis interface ge-0/0/0 authentication-type simple"}, false, "protocols isis interface"},
		{"routing-instance md5 no key", []string{
			"set routing-instances V protocols isis authentication-type md5"}, false, "routing-instance"},
		{"routing-instance interface md5 no key", []string{
			"set routing-instances V protocols isis interface ge-0/0/0 authentication-type md5"}, false, "routing-instance"},

		// CONTROLS: keyed (md5/plaintext) at each level must still commit.
		{"global keyed md5", []string{
			"set protocols isis authentication-type md5",
			"set protocols isis authentication-key s3cret"}, true, ""},
		{"global keyed simple", []string{
			"set protocols isis authentication-type simple",
			"set protocols isis authentication-key s3cret"}, true, ""},
		{"interface keyed md5", []string{
			"set protocols isis interface ge-0/0/0 authentication-type md5",
			"set protocols isis interface ge-0/0/0 authentication-key s3cret"}, true, ""},
		{"interface keyed simple", []string{
			"set protocols isis interface ge-0/0/0 authentication-type simple",
			"set protocols isis interface ge-0/0/0 authentication-key s3cret"}, true, ""},
		{"ri keyed md5", []string{
			"set routing-instances V protocols isis authentication-type md5",
			"set routing-instances V protocols isis authentication-key s3cret"}, true, ""},
		// Neither leaf: no auth chosen, still compiles.
		{"neither leaf", []string{
			"set protocols isis net 49.0001.0100.0000.0001.00"}, true, ""},
		{"interface neither leaf", []string{
			"set protocols isis interface ge-0/0/0 passive"}, true, ""},
		// Key at one level does NOT satisfy the other level's type.
		{"global keyed but interface type-only", []string{
			"set protocols isis authentication-type md5",
			"set protocols isis authentication-key s3cret",
			"set protocols isis interface ge-0/0/0 authentication-type md5"}, false, "protocols isis interface"},
		{"interface keyed but global type-only", []string{
			"set protocols isis authentication-type md5",
			"set protocols isis interface ge-0/0/0 authentication-type md5",
			"set protocols isis interface ge-0/0/0 authentication-key s3cret"}, false, "protocols isis"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, strictErr, lenientCfg, lenientErr := compileLines14399(t, tc.lines)
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
			if lenientErr != nil {
				t.Fatalf("lenient REJECTED — persisted/peer-synced config would fail to load (#1960): %v", lenientErr)
			}
			if !tc.wantStrict {
				var warned bool
				for _, w := range lenientCfg.Warnings {
					if strings.Contains(w, "authentication-key") && strings.Contains(w, "14399") {
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
