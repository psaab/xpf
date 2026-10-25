package config

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// #16732: PKICAProfile.EnrollmentURL and CRLURL marshalled verbatim
// through json.Marshal, which is what GET /api/v1/config (PermView)
// returns, while the raw-AST surface already redacted the same `url`
// leaves. These tests pin the typed-route behaviour directly so the
// fix cannot silently regress behind the census: the census would
// also fail, but with twenty fields of context instead of a named
// field.
//
// RED evidence: on origin/master (7bc0c4ad23) the existing census
// TestURLShapedFieldsAreRedactedOnMarshal6733 fails with exactly
// these two fields. If the RedactURL calls in
// PKICAProfile.MarshalJSON are removed, the credential-bearing cases
// below fail with the secret in the output.

const pkiURLSecret16732 = "PKI16732SECRET"

func TestPKICAProfileMarshalRedactsURLCredentials16732(t *testing.T) {
	credentialed := "https://user:" + pkiURLSecret16732 + "@ca.example.test/scep?token=" + pkiURLSecret16732

	for _, tc := range []struct {
		name        string
		profile     *PKICAProfile
		mustAbsent  []string
		mustPresent []string
	}{
		{
			name: "enrollment userinfo and query redacted",
			profile: &PKICAProfile{
				Name: "c1", EnrollmentURL: credentialed,
			},
			mustAbsent:  []string{pkiURLSecret16732, "user:"},
			mustPresent: []string{"ca.example.test", "/scep"},
		},
		{
			name: "crl userinfo and query redacted",
			profile: &PKICAProfile{
				Name: "c1", CRLURL: credentialed,
			},
			mustAbsent:  []string{pkiURLSecret16732, "user:"},
			mustPresent: []string{"ca.example.test", "/scep"},
		},
		{
			name: "credential-free URLs unchanged",
			profile: &PKICAProfile{
				Name:          "c1",
				EnrollmentURL: "http://ca.example.com:8080/scep",
				CRLURL:        "http://ca.example.com/crl.pem",
			},
			mustAbsent:  []string{"<redacted>"},
			mustPresent: []string{"http://ca.example.com:8080/scep", "http://ca.example.com/crl.pem"},
		},
		{
			name:        "empty URLs stay empty",
			profile:     &PKICAProfile{Name: "c1"},
			mustAbsent:  []string{"<redacted>"},
			mustPresent: []string{`"EnrollmentURL":""`, `"CRLURL":""`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.profile)
			if err != nil {
				t.Fatalf("marshal profile: %v", err)
			}
			for _, s := range tc.mustAbsent {
				if strings.Contains(string(b), s) {
					t.Errorf("marshalled PKICAProfile contains %q verbatim:\n%s", s, b)
				}
			}
			for _, s := range tc.mustPresent {
				if !strings.Contains(string(b), s) {
					t.Errorf("marshalled PKICAProfile lost %q:\n%s", s, b)
				}
			}
			// yaml.Marshal honours MarshalYAML; the two surfaces agree.
			yb, err := yaml.Marshal(tc.profile)
			if err != nil {
				t.Fatalf("yaml marshal profile: %v", err)
			}
			for _, s := range tc.mustAbsent {
				if strings.Contains(string(yb), s) {
					t.Errorf("YAML-marshalled PKICAProfile contains %q verbatim:\n%s", s, yb)
				}
			}
		})
	}
}

// TestPKICAProfileMarshalRedactsThroughConfig16732 pins the reachable
// route: a compiled *Config marshalled by pointer AND by value (the
// census's value-form doctrine — PKI is reached through
// map[string]*PKICAProfile, so both forms must redact), the live
// config must not be mutated by the read, and a second marshal must
// still redact.
func TestPKICAProfileMarshalRedactsThroughConfig16732(t *testing.T) {
	enroll := "https://user:" + pkiURLSecret16732 + "@ca.example.test/scep?token=" + pkiURLSecret16732
	crl := "https://user:" + pkiURLSecret16732 + "@ca.example.test/crl?token=" + pkiURLSecret16732

	newCfg := func() *Config {
		cfg := &Config{}
		cfg.Security.PKI = &PKIConfig{CAProfiles: map[string]*PKICAProfile{
			"c1": {Name: "c1", EnrollmentURL: enroll, CRLURL: crl},
		}}
		return cfg
	}

	for _, tc := range []struct {
		name string
		v    func() any
	}{
		{"pointer: json.Marshal(cfg)", func() any { return newCfg() }},
		{"VALUE: json.Marshal(*cfg)", func() any { return *newCfg() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.v())
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if strings.Contains(string(b), pkiURLSecret16732) {
				t.Errorf("%s leaked the PKI URL credential:\n%s", tc.name, b)
			}
		})
	}

	cfg := newCfg()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), pkiURLSecret16732) {
		t.Fatalf("premise broken: the credential was not redacted in the JSON at all:\n%s", b)
	}
	p := cfg.Security.PKI.CAProfiles["c1"]
	if p.EnrollmentURL != enroll || p.CRLURL != crl {
		t.Errorf("marshalling MUTATED the live config: EnrollmentURL=%q CRLURL=%q", p.EnrollmentURL, p.CRLURL)
	}
	b2, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("second marshal: %v", err)
	}
	if string(b) != string(b2) {
		t.Errorf("marshal is not idempotent: the first call changed what the second sees")
	}
}
