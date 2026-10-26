package config

import (
	"strings"
	"testing"
)

// #16628 (R3-A12-04): OSPF MD5 keys longer than 16 bytes and
// simple-passwords longer than 8 committed strict-clean; ospfd silently
// truncates them (RFC 2328 D.2: simple password is a 64-bit field;
// D.4.3: the MD5 key is 16 bytes), so every frr-reload deleted
// and re-added the key — a perpetual diff that also defeats the
// #15203 reload certification — and the effective key diverged from
// `show configuration`.
//
// Strict (CompileConfig / CheckText via SchemaValidate) must reject
// MD5 key17 / simple9 and accept MD5 key16 / simple8, globally and
// per routing instance; lenient must warn-not-reject (#1960) so a
// persisted config still boots. This mirrors #15013 for RIP.

const (
	ospfMD5Key16_16628 = "1234567890123456"  // exactly 16
	ospfMD5Key17_16628 = "12345678901234567" // 17 — one over
	ospfSimple8_16628  = "12345678"          // exactly 8
	ospfSimple9_16628  = "123456789"         // 9 — one over
)

func TestOSPFKeyLengthStrict16628(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lines      []string
		wantStrict bool
		wantSub    string // substring the refusal must name ("" = accept)
	}{
		{"global md5 key17 rejected", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key " + ospfMD5Key17_16628}, false, "16"},
		{"global md5 key16 accepted", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key " + ospfMD5Key16_16628}, true, ""},
		{"global md5 key1 accepted", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key x"}, true, ""},
		{"global md5 valid encoded 10-byte key accepted", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key \"" + junos9Blob15051 + "\""}, true, ""},
		{"global simple9 rejected", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password " + ospfSimple9_16628}, false, "8"},
		{"global simple8 accepted", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password " + ospfSimple8_16628}, true, ""},
		{"global simple1 accepted", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password x"}, true, ""},
		{"global simple encoded 10-byte password rejected", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password \"" + junos9Blob15051 + "\""}, false, "8"},
		{"routing-instance md5 key17 rejected", []string{
			"set routing-instances VRF-A instance-type vrf",
			"set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key " + ospfMD5Key17_16628}, false, "16"},
		{"routing-instance md5 key16 accepted", []string{
			"set routing-instances VRF-A instance-type vrf",
			"set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key " + ospfMD5Key16_16628}, true, ""},
		{"routing-instance simple9 rejected", []string{
			"set routing-instances VRF-A instance-type vrf",
			"set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password " + ospfSimple9_16628}, false, "8"},
		{"routing-instance simple8 accepted", []string{
			"set routing-instances VRF-A instance-type vrf",
			"set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password " + ospfSimple8_16628}, true, ""},
		// The #17680 regression: rune counts stay at or under the limit
		// while the encoded key bytes exceed ospfd's fixed-width fields.
		{"global md5 16-rune 32-byte key rejected", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key \"" + strings.Repeat("é", 16) + "\""}, false, "16"},
		{"global md5 multibyte key exactly at byte limit accepted", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key \"" + strings.Repeat("é", 8) + "\""}, true, ""},
		{"global simple 8-rune 16-byte password rejected", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password \"" + strings.Repeat("é", 8) + "\""}, false, "8"},
		{"global simple multibyte password exactly at byte limit accepted", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password \"" + strings.Repeat("é", 4) + "\""}, true, ""},
		// Rollover: one valid + one over-long entry must reject —
		// the over-long entry would be truncated by ospfd while the
		// valid one renders, a silent partial-truth.
		{"rollover one valid one over-long rejected", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key " + ospfMD5Key16_16628,
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 2 key " + ospfMD5Key17_16628}, false, "16"},
		{"rollover both at bound accepted", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key " + ospfMD5Key16_16628,
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 2 key " + ospfMD5Key16_16628}, true, ""},
		{"rip key17 still only RIP-gated", []string{
			"set protocols rip authentication-type md5",
			"set protocols rip authentication-key " + ospfMD5Key16_16628,
			"set protocols rip neighbor ge-0/0/1"}, true, ""},
		{"isis key17 not capped here", []string{
			"set protocols isis authentication-type md5",
			"set protocols isis authentication-key " + ospfMD5Key17_16628}, true, ""},
		{"no auth at all accepted", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0"}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, strictErr := CompileConfig(flatTreeFromSets(t, tc.lines...))
			if (strictErr == nil) != tc.wantStrict {
				t.Fatalf("strict accepted=%v, want %v (err=%v)", strictErr == nil, tc.wantStrict, strictErr)
			}
			if !tc.wantStrict {
				if !strings.Contains(strictErr.Error(), tc.wantSub) {
					t.Errorf("refusal does not name the %s-byte maximum: %v", tc.wantSub, strictErr)
				}
				if !strings.Contains(strictErr.Error(), "16628") {
					t.Errorf("refusal does not cite #16628: %v", strictErr)
				}
				// The error must not leak the key value.
				if strings.Contains(strictErr.Error(), ospfMD5Key17_16628) || strings.Contains(strictErr.Error(), ospfSimple9_16628) || strings.Contains(strictErr.Error(), junos9Blob15051) {
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
					if strings.Contains(w, "16628") {
						warned = true
					}
					if strings.Contains(w, ospfMD5Key17_16628) || strings.Contains(w, ospfSimple9_16628) || strings.Contains(w, junos9Blob15051) {
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
// the over-long keys directly (the typed-leaf validators), not only
// via compilation.
func TestOSPFKeyLengthSchemaValidate16628(t *testing.T) {
	for _, tc := range []struct {
		name    string
		lines   []string
		wantErr bool
		wantSub string
	}{
		{"global md5 key17", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key " + ospfMD5Key17_16628}, true, "16"},
		{"global md5 key16", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key " + ospfMD5Key16_16628}, false, ""},
		{"global md5 valid encoded 10-byte key", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key \"" + junos9Blob15051 + "\""}, false, ""},
		{"global md5 16-rune 32-byte key", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key \"" + strings.Repeat("é", 16) + "\""}, true, "16"},
		{"global md5 multibyte byte-exact key", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key \"" + strings.Repeat("é", 8) + "\""}, false, ""},
		{"global simple9", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password " + ospfSimple9_16628}, true, "8"},
		{"global simple8", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password " + ospfSimple8_16628}, false, ""},
		{"global simple encoded 10-byte password", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password \"" + junos9Blob15051 + "\""}, true, "8"},
		{"global simple 8-rune 16-byte password", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password \"" + strings.Repeat("é", 8) + "\""}, true, "8"},
		{"global simple multibyte byte-exact password", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password \"" + strings.Repeat("é", 4) + "\""}, false, ""},
		{"routing-instance md5 key17", []string{
			"set routing-instances VRF-A instance-type vrf",
			"set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key " + ospfMD5Key17_16628}, true, "16"},
		{"routing-instance md5 key16", []string{
			"set routing-instances VRF-A instance-type vrf",
			"set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key " + ospfMD5Key16_16628}, false, ""},
		{"routing-instance simple9", []string{
			"set routing-instances VRF-A instance-type vrf",
			"set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password " + ospfSimple9_16628}, true, "8"},
		{"routing-instance simple8", []string{
			"set routing-instances VRF-A instance-type vrf",
			"set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password " + ospfSimple8_16628}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, tc.lines...)
			if _, err := CompileConfigLenient(tree); err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			err := SchemaValidate(tree)
			if (err != nil) != tc.wantErr {
				t.Fatalf("SchemaValidate err=%v, wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("SchemaValidate refusal does not name the %s maximum: %v", tc.wantSub, err)
			}
		})
	}
}

// The validator units: byte boundaries, empty values, and multi-byte
// values whose rune count differs from their byte count.
func TestValidateOSPFKeyLength16628(t *testing.T) {
	if err := ValidateOSPFMD5KeyLength(ospfMD5Key16_16628); err != nil {
		t.Errorf("md5 key16 rejected: %v", err)
	}
	if err := ValidateOSPFMD5KeyLength(ospfMD5Key17_16628); err == nil {
		t.Error("md5 key17 accepted by validator")
	} else if !strings.Contains(err.Error(), "17 bytes") {
		t.Errorf("md5 key17 error does not report bytes: %v", err)
	}
	if err := ValidateOSPFMD5KeyLength(""); err == nil {
		t.Error("empty md5 key accepted by validator")
	}
	if err := ValidateOSPFSimplePasswordLength(ospfSimple8_16628); err != nil {
		t.Errorf("simple8 rejected: %v", err)
	}
	if err := ValidateOSPFSimplePasswordLength(ospfSimple9_16628); err == nil {
		t.Error("simple9 accepted by validator")
	} else if !strings.Contains(err.Error(), "9 bytes") {
		t.Errorf("simple9 error does not report bytes: %v", err)
	}
	if err := ValidateOSPFSimplePasswordLength(""); err == nil {
		t.Error("empty simple-password accepted by validator")
	}
	if err := ValidateOSPFMD5KeyLength(junos9Blob15051); err != nil {
		t.Errorf("valid encoded 10-byte MD5 key rejected before decoding: %v", err)
	}
	if err := ValidateOSPFSimplePasswordLength(junos9Blob15051); err == nil || !strings.Contains(err.Error(), "10 bytes") {
		t.Errorf("encoded 10-byte simple password error=%v, want the decoded byte length", err)
	}

	md5Over := strings.Repeat("é", 16) // 16 runes, 32 bytes; old validator accepted it
	if err := ValidateOSPFMD5KeyLength(md5Over); err == nil {
		t.Error("16-rune/32-byte md5 key accepted by validator")
	} else {
		if !strings.Contains(err.Error(), "32 bytes") || strings.Contains(err.Error(), md5Over) {
			t.Errorf("md5 error lacks byte count or leaks the key: %v", err)
		}
	}
	if err := ValidateOSPFMD5KeyLength(strings.Repeat("é", 8)); err != nil {
		t.Errorf("8-rune/16-byte md5 key rejected at byte limit: %v", err)
	}
	simpleOver := strings.Repeat("é", 8) // 8 runes, 16 bytes; old validator accepted it
	if err := ValidateOSPFSimplePasswordLength(simpleOver); err == nil {
		t.Error("8-rune/16-byte simple-password accepted by validator")
	} else {
		if !strings.Contains(err.Error(), "16 bytes") || strings.Contains(err.Error(), simpleOver) {
			t.Errorf("simple-password error lacks byte count or leaks the key: %v", err)
		}
	}
	if err := ValidateOSPFSimplePasswordLength(strings.Repeat("é", 4)); err != nil {
		t.Errorf("4-rune/8-byte simple-password rejected at byte limit: %v", err)
	}
}

// This gate is also reached for compiled Config values that bypass the
// schema walker. Pin byte counting in both strict diagnostics and the
// tolerant warning path, including the legacy single-key MD5 view.
func TestValidateOSPFKeyLengthStrictBytes17680(t *testing.T) {
	for _, tc := range []struct {
		name      string
		authType  string
		key       string
		md5Keys   []OSPFMD5Key12186
		wantCount string
	}{
		{
			name:      "md5 rollover entry over byte limit",
			authType:  "md5",
			key:       strings.Repeat("é", 16),
			md5Keys:   []OSPFMD5Key12186{{ID: 1, Key: NewSecret(strings.Repeat("é", 16))}},
			wantCount: "32 bytes",
		},
		{
			name:      "md5 legacy key over byte limit",
			authType:  "md5",
			key:       strings.Repeat("é", 16),
			wantCount: "32 bytes",
		},
		{
			name:      "simple key over byte limit",
			authType:  "simple",
			key:       strings.Repeat("é", 8),
			wantCount: "16 bytes",
		},
		{
			name:     "md5 rollover entry at byte limit",
			authType: "md5",
			key:      strings.Repeat("é", 8),
			md5Keys:  []OSPFMD5Key12186{{ID: 1, Key: NewSecret(strings.Repeat("é", 8))}},
		},
		{
			name:     "simple key at byte limit",
			authType: "simple",
			key:      strings.Repeat("é", 4),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iface := &OSPFInterface{
				Name:        "ge-0/0/1.0",
				AuthType:    tc.authType,
				AuthKey:     NewSecret(tc.key),
				AuthKeyID:   1,
				AuthMD5Keys: tc.md5Keys,
			}
			cfg := &Config{}
			cfg.Protocols.OSPF = &OSPFConfig{Areas: []*OSPFArea{{
				ID:         "0.0.0.0",
				Interfaces: []*OSPFInterface{iface},
			}}}

			warnings, err := validateOSPFKeyLengthStrict(cfg, false)
			if tc.wantCount == "" {
				if err != nil || len(warnings) != 0 {
					t.Fatalf("byte-exact compiled key rejected: warnings=%v err=%v", warnings, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantCount) {
				t.Fatalf("strict compiled gate error=%v, want byte count %q", err, tc.wantCount)
			}
			if strings.Contains(err.Error(), tc.key) {
				t.Fatalf("strict compiled gate error leaked the key: %v", err)
			}

			warnings, err = validateOSPFKeyLengthStrict(cfg, true)
			if err != nil {
				t.Fatalf("lenient compiled gate rejected overlong key: %v", err)
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0], tc.wantCount) {
				t.Fatalf("lenient warning=%v, want one warning reporting %q", warnings, tc.wantCount)
			}
			if strings.Contains(warnings[0], tc.key) {
				t.Fatalf("lenient warning leaked the key: %q", warnings[0])
			}
		})
	}
}
