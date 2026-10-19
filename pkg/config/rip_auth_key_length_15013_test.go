package config

import (
	"strings"
	"testing"
)

// #15013 (A12-01): a RIP `authentication-key` of 17+ characters bricks
// the FRR reload forever. FRR ripd accepts at most 16 characters for
// `ip rip authentication string <key>`; the schema leaf had no
// validator and no compiled gate bounded length, so a key17 config
// committed clean, rendered verbatim, and ripd rejected the line on
// every frr-reload (degraded retry that can never succeed).
//
// Strict (CompileConfig / CheckText via SchemaValidate) must reject
// key17 and accept key16, globally and per routing instance; lenient
// must warn-not-reject (#1960) so a persisted config still boots.

const (
	ripKey16_15013 = "1234567890123456"  // exactly 16
	ripKey17_15013 = "12345678901234567" // 17 — one over
)

func TestRIPAuthKeyLengthStrict15013(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lines      []string
		wantStrict bool
	}{
		{"global key17 rejected", []string{
			"set protocols rip authentication-type md5",
			"set protocols rip authentication-key " + ripKey17_15013,
			"set protocols rip neighbor ge-0/0/1"}, false},
		{"global key16 accepted", []string{
			"set protocols rip authentication-type md5",
			"set protocols rip authentication-key " + ripKey16_15013,
			"set protocols rip neighbor ge-0/0/1"}, true},
		{"global key16 simple accepted", []string{
			"set protocols rip authentication-type simple",
			"set protocols rip authentication-key " + ripKey16_15013,
			"set protocols rip neighbor ge-0/0/1"}, true},
		{"global key1 accepted", []string{
			"set protocols rip authentication-type md5",
			"set protocols rip authentication-key x",
			"set protocols rip neighbor ge-0/0/1"}, true},
		{"routing-instance key17 rejected", []string{
			"set routing-instances VRF-A instance-type vrf",
			"set routing-instances VRF-A protocols rip authentication-type md5",
			"set routing-instances VRF-A protocols rip authentication-key " + ripKey17_15013,
			"set routing-instances VRF-A protocols rip neighbor ge-0/0/1"}, false},
		{"routing-instance key16 accepted", []string{
			"set routing-instances VRF-A instance-type vrf",
			"set routing-instances VRF-A protocols rip authentication-type md5",
			"set routing-instances VRF-A protocols rip authentication-key " + ripKey16_15013,
			"set routing-instances VRF-A protocols rip neighbor ge-0/0/1"}, true},
		// Control: neighbouring auth keys are NOT length-capped by this gate.
		{"isis key17 not capped here", []string{
			"set protocols isis authentication-type md5",
			"set protocols isis authentication-key " + ripKey17_15013}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, strictErr := CompileConfig(flatTreeFromSets(t, tc.lines...))
			if (strictErr == nil) != tc.wantStrict {
				t.Fatalf("strict accepted=%v, want %v (err=%v)", strictErr == nil, tc.wantStrict, strictErr)
			}
			if !tc.wantStrict {
				if !strings.Contains(strictErr.Error(), "authentication-key") {
					t.Errorf("refusal does not name authentication-key: %v", strictErr)
				}
				if !strings.Contains(strictErr.Error(), "16") {
					t.Errorf("refusal does not name the 16-character maximum: %v", strictErr)
				}
				// The error must not leak the key value.
				if strings.Contains(strictErr.Error(), ripKey17_15013) {
					t.Errorf("refusal leaks the key value: %v", strictErr)
				}
			}
			// Lenient always boots (#1960); over-long warns.
			lenientCfg, lenientErr := CompileConfigLenient(flatTreeFromSets(t, tc.lines...))
			if lenientErr != nil {
				t.Fatalf("lenient REJECTED — persisted config would fail to load (#1960): %v", lenientErr)
			}
			if !tc.wantStrict {
				var warned bool
				for _, w := range lenientCfg.Warnings {
					if strings.Contains(w, "authentication-key") && strings.Contains(w, "16") {
						warned = true
					}
					if strings.Contains(w, ripKey17_15013) {
						t.Errorf("lenient warning leaks the key value: %q", w)
					}
				}
				if !warned {
					t.Errorf("lenient accepted over-long key silently; warnings=%v", lenientCfg.Warnings)
				}
			}
		})
	}
}

// SchemaValidate is the CheckText/commit-check surface: it must reject
// key17 directly (the typed-leaf validator), not only via compilation.
func TestRIPAuthKeyLengthSchemaValidate15013(t *testing.T) {
	for _, tc := range []struct {
		name    string
		lines   []string
		wantErr bool
	}{
		{"global key17", []string{
			"set protocols rip authentication-type md5",
			"set protocols rip authentication-key " + ripKey17_15013}, true},
		{"global key16", []string{
			"set protocols rip authentication-type md5",
			"set protocols rip authentication-key " + ripKey16_15013}, false},
		{"routing-instance key17", []string{
			"set routing-instances VRF-A instance-type vrf",
			"set routing-instances VRF-A protocols rip authentication-type md5",
			"set routing-instances VRF-A protocols rip authentication-key " + ripKey17_15013}, true},
		{"routing-instance key16", []string{
			"set routing-instances VRF-A instance-type vrf",
			"set routing-instances VRF-A protocols rip authentication-type md5",
			"set routing-instances VRF-A protocols rip authentication-key " + ripKey16_15013}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, tc.lines...)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			err = SchemaValidate(tree, cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("SchemaValidate err=%v, wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "16") {
				t.Errorf("SchemaValidate refusal does not name the 16 maximum: %v", err)
			}
		})
	}
}

// The validator unit: boundary and empty.
func TestValidateRIPAuthKeyLength15013(t *testing.T) {
	if err := ValidateRIPAuthKeyLength(ripKey16_15013, nil); err != nil {
		t.Errorf("key16 rejected: %v", err)
	}
	if err := ValidateRIPAuthKeyLength(ripKey17_15013, nil); err == nil {
		t.Error("key17 accepted by validator")
	}
	if err := ValidateRIPAuthKeyLength("", nil); err == nil {
		t.Error("empty key accepted by validator")
	}
	// Rune count, not bytes: 16 multi-byte runes (32 bytes) is legal.
	if err := ValidateRIPAuthKeyLength(strings.Repeat("é", 16), nil); err != nil {
		t.Errorf("16-rune key rejected: %v", err)
	}
	if err := ValidateRIPAuthKeyLength(strings.Repeat("é", 17), nil); err == nil {
		t.Error("17-rune key accepted by validator")
	}
}
