package config

import (
	"errors"
	"strings"
	"testing"
)

// buildRedactTree replays flat `set` commands into a fresh AST the way the config
// store does (ParseSetCommand + SetPath) — NOT NewParser, which merges lines.
func buildRedactTree(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		toks, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(toks); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

// redactionSecretSet mirrors the #2053 secret-bearing leaves (the same set the
// pkg/api typed-struct redaction test stages), one distinctive sentinel per
// secret leaf so a single leak is identifiable in the raw-AST render.
var redactionSecretSet = []string{
	"set security ike policy pol1 pre-shared-key ascii-text LEAK-IKE-PSK",
	"set security ipsec vpn site-a pre-shared-key LEAK-IPSEC-VPN-PSK",
	"set protocols ospf area 0.0.0.0 interface ge-0-0-1 authentication md5 1 key LEAK-OSPF-MD5KEY",
	"set protocols ospf area 0.0.0.0 interface ge-0-0-9 authentication simple-password LEAK-OSPF-SIMPLE",
	"set protocols rip authentication-key LEAK-RIP-AUTHKEY",
	"set protocols isis authentication-key LEAK-ISIS-AREA-AUTHKEY",
	"set protocols isis interface ge-0-0-2 authentication-key LEAK-ISIS-IFACE-AUTHKEY",
	"set protocols bgp group external authentication-key LEAK-BGP-AUTHPW",
	"set interfaces ge-0-0-3 unit 0 family inet address 10.0.3.1/24 vrrp-group 1 authentication-key LEAK-VRRP-AUTHKEY",
	"set system services web-management api-auth user admin password LEAK-API-USER-PW",
	"set system services web-management api-auth api-key LEAK-API-KEY-TOKEN",
	"set snmp v3 usm local-engine user admin authentication-sha256 authentication-password LEAK-SNMPV3-AUTHPW",
	"set snmp v3 usm local-engine user admin privacy-des privacy-password LEAK-SNMPV3-PRIVPW",
	"set snmp community LEAK-SNMP-COMMUNITY authorization read-only",
	"set system services dhcp-local-server dynamic-dns tsig-secret LEAK-TSIG-SECRET",
	"set system services dynamic-dns provider cf backend cloudflare",
	"set system services dynamic-dns provider cf api-token LEAK-DDNS-APITOKEN",
	"set system services dynamic-dns provider r53 backend route53",
	"set system services dynamic-dns provider r53 aws-secret-key LEAK-DDNS-AWSSECRET",
	"set system services dynamic-dns provider dy backend dyndns2",
	"set system services dynamic-dns provider dy password LEAK-DDNS-HTTP-PW",
	"set interfaces wg0 tunnel wireguard private-key LEAK-WG-PRIVKEY",
	"set interfaces wg0 tunnel wireguard peer p1 preshared-key LEAK-WG-PSK",
	`set system root-authentication encrypted-password "$6$LEAKr008$rootHASHrootHASH` + strings.Repeat("a", 70) + `"`,
	`set system login user op authentication encrypted-password "$6$LEAKl008$loginHASHloginHASH` + strings.Repeat("a", 68) + `"`,
}

var redactionSentinels = []string{
	"LEAK-IKE-PSK", "LEAK-IPSEC-VPN-PSK", "LEAK-OSPF-MD5KEY", "LEAK-OSPF-SIMPLE",
	"LEAK-RIP-AUTHKEY", "LEAK-ISIS-AREA-AUTHKEY", "LEAK-ISIS-IFACE-AUTHKEY",
	"LEAK-BGP-AUTHPW", "LEAK-VRRP-AUTHKEY", "LEAK-API-USER-PW", "LEAK-API-KEY-TOKEN",
	"LEAK-SNMPV3-AUTHPW", "LEAK-SNMPV3-PRIVPW", "LEAK-SNMP-COMMUNITY",
	"LEAK-TSIG-SECRET", "LEAK-DDNS-APITOKEN", "LEAK-DDNS-AWSSECRET", "LEAK-DDNS-HTTP-PW",
	"LEAK-WG-PRIVKEY", "LEAK-WG-PSK", "rootHASHrootHASH", "loginHASHloginHASH",
}

// TestRedactedCloneMasksEverySecretAcrossFormats is the #4051 RED-on-revert
// net: it renders a secret-bearing tree through every raw-AST format after
// RedactedClone and asserts no cleartext secret survives while the placeholder
// does. It goes RED (cleartext secrets present) if RedactedClone is a no-op.
func TestRedactedCloneMasksEverySecretAcrossFormats(t *testing.T) {
	tree := buildRedactTree(t, redactionSecretSet)
	red := tree.RedactedClone()

	renders := map[string]string{
		"Format":      red.Format(),
		"FormatSet":   red.FormatSet(),
		"FormatJSON":  red.FormatJSON(),
		"FormatXML":   red.FormatXML(),
		"Inheritance": red.FormatInheritance(),
	}
	for name, out := range renders {
		for _, leak := range redactionSentinels {
			if strings.Contains(out, leak) {
				t.Errorf("%s leaked cleartext secret %q:\n%s", name, leak, out)
			}
		}
		if !strings.Contains(out, SecretDataPlaceholder) {
			t.Errorf("%s did not emit the %s placeholder; redaction not applied?\n%s",
				name, SecretDataPlaceholder, out)
		}
	}
}

// TestRedactedCloneDoesNotMutateSource proves masking is display-only: the
// live tree still carries cleartext for HA sync / the DR archive / persistence.
func TestRedactedCloneDoesNotMutateSource(t *testing.T) {
	tree := buildRedactTree(t, redactionSecretSet)
	_ = tree.RedactedClone()

	out := tree.Format() + tree.FormatSet()
	for _, want := range redactionSentinels {
		if !strings.Contains(out, want) {
			t.Errorf("source tree lost cleartext secret %q after RedactedClone (mutation!)\n%s", want, out)
		}
	}
}

// TestRedactedCloneKeepsNonSecrets guards against over-masking: generic
// keyword look-alikes that are NOT secrets must render verbatim.
func TestRedactedCloneKeepsNonSecrets(t *testing.T) {
	lines := []string{
		"set system host-name fw-edge-1",                                             // plain
		"set snmp community LEAK-SNMP-COMMUNITY clients 10.0.0.0/8",                  // community NAME is secret, CIDR is not
		"set interfaces gr-0-0-0 unit 0 tunnel key 4242",                             // GRE tunnel key — not a secret
		"set system services dynamic-dns provider r53 aws-access-key AKIA-PUBLIC-ID", // access-key ID is public
		"set system services dynamic-dns provider dy username joeuser",               // username is not a secret
		"set policy-options community CUST members 65000:100",                        // routing community — not a secret
	}
	tree := buildRedactTree(t, lines)
	out := tree.RedactedClone().FormatSet()

	keep := []string{"fw-edge-1", "10.0.0.0/8", "4242", "AKIA-PUBLIC-ID", "joeuser", "65000:100", "CUST"}
	for _, w := range keep {
		if !strings.Contains(out, w) {
			t.Errorf("non-secret value %q was masked (over-redaction):\n%s", w, out)
		}
	}
	// The SNMP community NAME must still be masked even though its sibling
	// CIDR is not.
	if strings.Contains(out, "LEAK-SNMP-COMMUNITY") {
		t.Errorf("SNMP community string leaked:\n%s", out)
	}
	if !strings.Contains(out, SecretDataPlaceholder) {
		t.Errorf("community NAME not masked; expected placeholder:\n%s", out)
	}
}

// TestRedactionPlaceholderIngestRejected is the #4060 RED-on-revert net for
// the symmetric commit-ingest guard: re-applying a secret-redacted REST export
// (every secret leaf carries the "##SECRET-DATA##" placeholder) must be
// REJECTED, not silently committed with the placeholder as a literal secret.
//
// It re-ingests the redacted render of the full secret set the way the config
// store does (ParseSetCommand + SetPath), then asserts checkRedactionPlaceholder
// AND the commit-ingest schema gate (SchemaValidate) reject it. It goes RED (a
// redacted export commits with placeholder secrets) if the guard is a no-op.
func TestRedactionPlaceholderIngestRejected(t *testing.T) {
	// Build the cleartext tree, redact it (as REST export does), render it to
	// `set` lines, and replay those lines back into a fresh tree — exactly the
	// operator foot-gun the guard closes.
	cleartext := buildRedactTree(t, redactionSecretSet)
	redactedSet := cleartext.RedactedClone().FormatSet()
	if !strings.Contains(redactedSet, SecretDataPlaceholder) {
		t.Fatalf("redacted export did not contain the placeholder; test precondition broken:\n%s", redactedSet)
	}

	reingested := &ConfigTree{}
	for _, line := range strings.Split(redactedSet, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		toks, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := reingested.SetPath(toks); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}

	if err := checkRedactionPlaceholder(reingested); err == nil {
		t.Fatal("checkRedactionPlaceholder accepted a redacted export; want rejection")
	} else if !errors.Is(err, errRedactionPlaceholderIngest) {
		t.Fatalf("checkRedactionPlaceholder err = %v, want errRedactionPlaceholderIngest", err)
	}

	// The commit-ingest schema gate (the production strict-commit hook) must
	// also reject it.
	if err := SchemaValidate(reingested, nil); err == nil {
		t.Fatal("SchemaValidate accepted a redacted export; want rejection")
	} else if !errors.Is(err, errRedactionPlaceholderIngest) {
		t.Fatalf("SchemaValidate err = %v, want errRedactionPlaceholderIngest", err)
	}
}

// TestRedactionPlaceholderIngest_PerSecretLeaf confirms the guard fires for
// EVERY secret-leaf signature individually (mirroring RedactedClone's set), so
// a redacted export of ANY single secret is rejected — not just the first in
// the full-set render.
func TestRedactionPlaceholderIngest_PerSecretLeaf(t *testing.T) {
	for _, line := range redactionSecretSet {
		line := line
		// Skip the pure-selector lines that carry no secret value (they set a
		// DDNS provider backend, not a secret).
		if strings.Contains(line, "backend") {
			continue
		}
		t.Run(line, func(t *testing.T) {
			redacted := buildRedactTree(t, []string{line}).RedactedClone()
			err := checkRedactionPlaceholder(redacted)
			if err == nil {
				t.Fatalf("guard missed a redacted secret leaf:\n%s", redacted.FormatSet())
			}
			if !errors.Is(err, errRedactionPlaceholderIngest) {
				t.Fatalf("err = %v, want errRedactionPlaceholderIngest", err)
			}
		})
	}
}

// TestRedactionPlaceholderIngest_NormalSecretPasses proves the guard rejects
// ONLY the exact placeholder: a real cleartext secret (the un-redacted set)
// still commits cleanly through the same gate.
func TestRedactionPlaceholderIngest_NormalSecretPasses(t *testing.T) {
	cleartext := buildRedactTree(t, redactionSecretSet)
	if err := checkRedactionPlaceholder(cleartext); err != nil {
		t.Fatalf("checkRedactionPlaceholder rejected a normal cleartext config: %v", err)
	}
	if err := SchemaValidate(cleartext, nil); err != nil {
		t.Fatalf("SchemaValidate rejected a normal cleartext config: %v", err)
	}
}

// TestRedactionPlaceholderIngest_NonSecretScoped confirms the guard is
// secret-leaf-scoped (matching RedactedClone): a NON-secret leaf that happens to
// carry the literal "##SECRET-DATA##" string is NOT rejected — RedactedClone
// never masks such a leaf, so ingesting it is harmless.
func TestRedactionPlaceholderIngest_NonSecretScoped(t *testing.T) {
	tree := buildRedactTree(t, []string{
		// host-name is not a secret leaf; even the literal placeholder value is
		// fine here (it would never have been produced by RedactedClone).
		`set system host-name "` + SecretDataPlaceholder + `"`,
		// A GRE tunnel `key` is a non-secret generic keyword (secretIndices
		// gates `key` to the OSPF md5 context only).
		`set interfaces gr-0-0-0 unit 0 tunnel key "` + SecretDataPlaceholder + `"`,
	})
	if err := checkRedactionPlaceholder(tree); err != nil {
		t.Fatalf("guard over-reached onto a non-secret leaf: %v", err)
	}
}

// TestRedactedClonePreservesFormatQualifier confirms an IKE pre-shared-key
// keeps its ascii-text/hexadecimal format qualifier (structural validity)
// while only the key material is masked.
func TestRedactedClonePreservesFormatQualifier(t *testing.T) {
	tree := buildRedactTree(t, []string{
		"set security ike policy pol1 pre-shared-key ascii-text SUPERSECRET",
	})
	out := tree.RedactedClone().FormatSet()
	// The placeholder contains '#', a non-identifier char, so FormatSet quotes
	// it: `pre-shared-key ascii-text "##SECRET-DATA##"`. The qualifier is
	// retained and the key material is masked.
	if !strings.Contains(out, "pre-shared-key ascii-text") ||
		!strings.Contains(out, SecretDataPlaceholder) {
		t.Errorf("expected qualifier retained + key masked; got:\n%s", out)
	}
	if strings.Contains(out, "SUPERSECRET") {
		t.Errorf("pre-shared-key material leaked:\n%s", out)
	}
}
