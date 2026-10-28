package config

import (
	"strings"
	"testing"
)

// #9008: `lifetime-seconds` on an IKE (Phase-1) or IPsec (Phase-2) proposal
// carries validator: ValidateIntegerMin(1) in setSchema, but SchemaValidate
// runs ONLY from compileTreeStrict. Name the channel in any claim about this
// leaf -- the three differ:
//
//	SchemaValidate          the schema gate; Store.Commit runs it FIRST
//	CompileConfig           STRICT compiler gates (strictCompileOpts(),
//	                        #17148), reached only via compileTreeStrict -- no schema gate
//	CompileConfigLenient    tolerant compiler gates; backs Store.Load and HA
//	                        SyncApply (via compileTreeLenient, which schema-
//	                        validates and DOWNGRADES to slog.Warn)
//
// Before the fix the tolerant channel accepted a negative or non-numeric
// lifetime with ZERO warnings, and a negative parsed cleanly through
// strconv.Atoi and was STORED -- carried on into the swanctl renderer.
func ipsecLifetimeTree9008(t *testing.T, stanza, propKind, value string) *ConfigTree {
	t.Helper()
	txt := "security {\n " + stanza + " {\n  proposal p1 {\n" +
		propKind +
		"   lifetime-seconds " + value + ";\n  }\n }\n}\n"
	tr, perrs := NewParser(txt).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse %q: %v", value, perrs)
	}
	return tr
}

func TestIPsecProposalLifetimeChannels9008(t *testing.T) {
	const ikeBody = "   authentication-method pre-shared-keys;\n   dh-group group14;\n" +
		"   authentication-algorithm sha-256;\n   encryption-algorithm aes-256-cbc;\n"
	const espBody = "   protocol esp;\n   authentication-algorithm hmac-sha-256-128;\n" +
		"   encryption-algorithm aes-256-cbc;\n"

	phases := []struct {
		name, stanza, body string
		// lifetime reads the compiled proposal p1's LifetimeSeconds.
		lifetime func(*Config) (int, bool)
	}{
		{"ike", "ike", ikeBody, func(c *Config) (int, bool) {
			p, ok := c.Security.IPsec.IKEProposals["p1"]
			if !ok || p == nil {
				return 0, false
			}
			return p.LifetimeSeconds, true
		}},
		{"ipsec", "ipsec", espBody, func(c *Config) (int, bool) {
			p, ok := c.Security.IPsec.Proposals["p1"]
			if !ok || p == nil {
				return 0, false
			}
			return p.LifetimeSeconds, true
		}},
	}

	cases := []struct {
		value string
		valid bool
	}{
		{"3600", true}, // control: a good value must stay accepted on every channel
		{"-5", false},  // the reported case: Atoi SUCCEEDS, so it was stored
		{"0", false},   // below the schema floor of 1
		{"abc", false}, // Atoi fails: was dropped, leaving 0 == "unset"
	}

	for _, ph := range phases {
		for _, tc := range cases {
			name := ph.name + "/" + tc.value
			t.Run(name, func(t *testing.T) {
				// --- CHANNEL: SchemaValidate (Store.Commit runs this first) ---
				schemaErr := SchemaValidate(ipsecLifetimeTree9008(t, ph.stanza, ph.body, tc.value))
				if tc.valid && schemaErr != nil {
					t.Fatalf("SchemaValidate rejected the valid value %q: %v", tc.value, schemaErr)
				}
				if !tc.valid && schemaErr == nil {
					t.Fatalf("SchemaValidate accepted invalid lifetime-seconds %q", tc.value)
				}

				// --- CHANNEL: CompileConfig (strict compiler gates) ---
				// Reached only from compileTreeStrict, which schema-rejects
				// first, so this is defence in depth on the commit path -- but
				// it must agree, not merely not-crash.
				_, strictErr := CompileConfig(ipsecLifetimeTree9008(t, ph.stanza, ph.body, tc.value))
				if tc.valid && strictErr != nil {
					t.Fatalf("CompileConfig rejected the valid value %q: %v", tc.value, strictErr)
				}
				if !tc.valid {
					if strictErr == nil {
						t.Fatalf("CompileConfig accepted invalid lifetime-seconds %q", tc.value)
					}
					if !strings.Contains(strictErr.Error(), "lifetime-seconds") {
						t.Fatalf("CompileConfig error for %q does not name the leaf: %v", tc.value, strictErr)
					}
				}

				// --- CHANNEL: CompileConfigLenient (Store.Load / SyncApply) ---
				// #1960 doctrine: the tolerant path must NOT gain a new
				// rejection -- a config an older binary persisted has to keep
				// booting. It must gain a WARNING.
				cfg, lenErr := CompileConfigLenient(ipsecLifetimeTree9008(t, ph.stanza, ph.body, tc.value))
				if lenErr != nil {
					t.Fatalf("tolerant path gained a NEW REJECTION for %q (#1960 violation): %v",
						tc.value, lenErr)
				}
				got, ok := ph.lifetime(cfg)
				if !ok {
					t.Fatalf("tolerant compile dropped proposal p1 entirely for %q", tc.value)
				}

				var warned bool
				for _, w := range cfg.Warnings {
					if strings.Contains(w, "lifetime") && strings.Contains(w, "p1") {
						warned = true
					}
				}
				if tc.valid {
					if warned {
						t.Fatalf("tolerant path warned about the VALID value %q: %v", tc.value, cfg.Warnings)
					}
					if got != 3600 {
						t.Fatalf("valid lifetime %q compiled to %d, want 3600", tc.value, got)
					}
					return
				}
				if !warned {
					t.Fatalf("tolerant path accepted invalid lifetime-seconds %q in SILENCE "+
						"(%d warning(s): %v) -- this is the #9008 defect",
						tc.value, len(cfg.Warnings), cfg.Warnings)
				}
				// The bad token must never reach the renderer as a value.
				if got != 0 {
					t.Fatalf("invalid lifetime %q was STORED as %d; it must not be carried "+
						"into the swanctl renderer", tc.value, got)
				}
			})
		}
	}
}
