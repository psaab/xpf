package config

import (
	"strings"
	"testing"
)

// #16731 (R3-A20-04): unmodelled Junos credential leaves committed clean on
// open-world/inert paths and rendered in cleartext on every RedactedClone
// surface (CLI show configuration, gRPC ShowConfig, REST config/show) to
// PermView readers. The closed enumeration in secretIndices had no case
// for them. The fix fails closed on credential-SHAPED keywords
// (isCredentialShapedKeyword16731) plus the outbound-ssh `secret` gate.

var credentialRows16731 = []struct {
	name   string
	line   string
	secret string
}{
	{"chap default-chap-secret", "set interfaces pp0 unit 0 ppp-options chap default-chap-secret LEAK16731-CHAP", "LEAK16731-CHAP"},
	{"pap local-password", "set interfaces pp0 unit 0 ppp-options pap local-password LEAK16731-PAP", "LEAK16731-PAP"},
	{"outbound-ssh secret", "set system services outbound-ssh client c1 secret LEAK16731-OSSH", "LEAK16731-OSSH"},
	{"secintel auth-token", "set services security-intelligence authentication auth-token LEAK16731-SECINTEL", "LEAK16731-SECINTEL"},
	{"snmp-community community-name", "set snmp v3 snmp-community idx1 community-name LEAK16731-COMMNAME", "LEAK16731-COMMNAME"},
	{"dhcp-local group password", "set system services dhcp-local-server group g1 authentication password LEAK16731-DHCPGRP", "LEAK16731-DHCPGRP"},
	{"dhcp-local global password", "set system services dhcp-local-server authentication password LEAK16731-DHCPGLOB", "LEAK16731-DHCPGLOB"},
	{"dhcpv6 group password", "set system services dhcpv6-local-server group g6 authentication password LEAK16731-DHCP6", "LEAK16731-DHCP6"},
	{"dhcp-relay group password", "set forwarding-options dhcp-relay group rg authentication password LEAK16731-RELAY", "LEAK16731-RELAY"},
}

// TestCredentialShapedLeavesMasked16731 is the RED-on-revert net: every
// leaking row must be masked on Format/FormatSet/FormatJSON/FormatXML,
// with the placeholder present, and the source tree must stay cleartext
// (display-only transform).
func TestCredentialShapedLeavesMasked16731(t *testing.T) {
	for _, row := range credentialRows16731 {
		t.Run(row.name, func(t *testing.T) {
			tree := buildRedactTree(t, []string{row.line})
			red := tree.RedactedClone()
			renders := map[string]string{
				"Format":     red.Format(),
				"FormatSet":  red.FormatSet(),
				"FormatJSON": red.FormatJSON(),
				"FormatXML":  red.FormatXML(),
			}
			for name, out := range renders {
				if strings.Contains(out, row.secret) {
					t.Errorf("%s leaked %q:\n%s", name, row.secret, out)
				}
				if !strings.Contains(out, SecretDataPlaceholder) {
					t.Errorf("%s did not emit placeholder:\n%s", name, out)
				}
			}
			if !strings.Contains(tree.FormatSet(), row.secret) {
				t.Errorf("source tree mutated; cleartext lost:\n%s", tree.FormatSet())
			}
		})
	}
}

// TestCredentialShapedHierarchical16731: braced spelling flattens to the
// same path and must mask identically (dual AST shape).
func TestCredentialShapedHierarchical16731(t *testing.T) {
	tree := parseHierText(t, "snmp {\n v3 {\n  snmp-community idx1 {\n   community-name LEAK16731-HIER;\n  }\n }\n}\n")
	red := tree.RedactedClone()
	out := red.Format() + red.FormatSet()
	if strings.Contains(out, "LEAK16731-HIER") {
		t.Errorf("hierarchical community-name leaked:\n%s", out)
	}
	if !strings.Contains(out, SecretDataPlaceholder) {
		t.Errorf("hierarchical community-name not masked:\n%s", out)
	}
}

// TestCredentialShapedControlsUnchanged16731: already-masked controls stay
// masked; the NTP over-mask is pinned as a known cost (authentication-key's
// trailing `value <key>` is masked wholesale, pre-existing).
func TestCredentialShapedControlsUnchanged16731(t *testing.T) {
	lines := []string{
		"set snmp v3 usm local-engine user admin authentication-sha256 authentication-password LEAK16731-CTRL-USM",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0 authentication simple-password LEAK16731-CTRL-OSPF",
		"set system ntp authentication-key 1 type md5 value LEAK16731-CTRL-NTP",
		"set snmp community LEAK16731-CTRL-COMM authorization read-only",
	}
	out := buildRedactTree(t, lines).RedactedClone().FormatSet()
	for _, s := range []string{"LEAK16731-CTRL-USM", "LEAK16731-CTRL-OSPF", "LEAK16731-CTRL-NTP", "LEAK16731-CTRL-COMM"} {
		if strings.Contains(out, s) {
			t.Errorf("control %q leaked:\n%s", s, out)
		}
	}
}

// TestCredentialShapedNonSecretsRender16731: non-secret neighbours of the
// leaking rows, plus the public `*-key` identifiers and flag spellings,
// must render verbatim (no over-masking).
func TestCredentialShapedNonSecretsRender16731(t *testing.T) {
	lines := []string{
		"set snmp v3 snmp-community idx1 security-name secname16731",
		"set system services dhcp-local-server group g1 authentication access-profile prof16731",
		"set services security-intelligence authentication tls-profile tls16731",
		"set system services dynamic-dns provider r53 aws-access-key AKIA16731PUBLIC",
		"set system services dhcp-local-server dynamic-dns tsig-key xpf-key-16731",
		"set system ntp trusted-key 42",
		"set interfaces gr-0/0/0 unit 0 tunnel key 4242",
		"set policy-options community CUST16731 members 65000:100",
		"set system services ssh no-password-authentication",
		"set system master-password pseudorandom-function hmac-sha2-256",
	}
	out := buildRedactTree(t, lines).RedactedClone().FormatSet()
	for _, keep := range []string{"secname16731", "prof16731", "tls16731", "AKIA16731PUBLIC", "xpf-key-16731", "42", "4242", "CUST16731", "65000:100", "hmac-sha2-256"} {
		if !strings.Contains(out, keep) {
			t.Errorf("non-secret %q was masked (over-redaction):\n%s", keep, out)
		}
	}
	if strings.Contains(out, SecretDataPlaceholder) {
		t.Errorf("placeholder emitted for a tree with no secrets:\n%s", out)
	}
}

// TestCredentialShapeRegistry16731 enumerates the accepted-unmodelled
// credential keywords: each must be classified credential-shaped (or, for
// bare `secret`, gated under outbound-ssh), and the known public/flag
// keywords must NOT be.
func TestCredentialShapeRegistry16731(t *testing.T) {
	for _, kw := range []string{
		"default-chap-secret", "local-password", "auth-token", "community-name",
		"password", "client-secret", "shared-secret",
		"tsig-secret", "aws-secret-key", "encrypted-password", "simple-password",
		"authentication-password", "privacy-password", "plain-text-password",
	} {
		if !isCredentialShapedKeyword16731(kw) {
			t.Errorf("keyword %q not credential-shaped; unmodelled leaves with this name would leak", kw)
		}
	}
	for _, kw := range []string{
		"trusted-key", "tsig-key", "aws-access-key", "api-key", "pre-shared-key",
		"authentication-key", "private-key", "preshared-key", "key", "community",
		"security-name", "access-profile", "tls-profile", "host-name",
		"secret", "master-password", "no-password-authentication", "no-passwords", "user-password",
	} {
		if isCredentialShapedKeyword16731(kw) {
			t.Errorf("keyword %q wrongly credential-shaped (public identifier / gated key would be over-masked)", kw)
		}
	}
	// Bare `secret` is gated, not shaped: outbound-ssh arms it, other
	// contexts do not (mirrors TestSecretRedactionStaysScoped15019).
	if got := secretIndices([]string{"system", "services", "outbound-ssh", "client", "c1", "secret", "V16731"}); len(got) != 1 || got[0] != 6 {
		t.Errorf("outbound-ssh secret not masked: secretIndices=%v", got)
	}
	if got := secretIndices([]string{"system", "services", "ssh", "secret", "V16731"}); len(got) != 0 {
		t.Errorf("bare secret outside gated contexts masked: secretIndices=%v", got)
	}
}

// TestCredentialPlaceholderIngestRejected16731: the symmetric ingest guard
// (checkRedactionPlaceholder, same secretIndices set) must reject a
// redacted export carrying the placeholder at any new row, so a PermView
// export cannot be re-applied with ##SECRET-DATA## as the literal value.
func TestCredentialPlaceholderIngestRejected16731(t *testing.T) {
	for _, row := range credentialRows16731 {
		t.Run(row.name, func(t *testing.T) {
			tree := buildRedactTree(t, []string{row.line})
			redacted := tree.RedactedClone().FormatSet()
			reingested := buildRedactTree(t, []string{strings.TrimSpace(redacted)})
			if err := checkRedactionPlaceholder(reingested); err == nil {
				t.Errorf("placeholder at %s not rejected on ingest; redacted:\n%s", row.name, redacted)
			}
		})
	}
}
