package config

import (
	"strconv"
	"strings"
	"testing"
)

// #6625 — the #1798 control-character gate rendered a credential leaf's VALUE
// into its error.
//
// For a leaf whose value is a secret (a cluster PSK, an IKE pre-shared-key, a
// WireGuard private key, an encrypted password, a TSIG secret, an SNMP
// community) that put the secret into everything that consumes the error:
// commit output on the CLI, the daemon log, the audit journal.
//
// It fired twice per rejection — once in the rendered PATH (joinNodePath
// renders every key, and the value IS a key) and once in the quoted value.
//
// The trigger is narrow but routine: a PSK pasted from a password manager, a
// terminal or a file commonly carries a leading or trailing tab or CR. The
// operator does the ordinary thing, the commit is refused, and the refusal
// publishes the key they were trying to set privately.
//
// The project already treats secret rendering as a hard rule — Secret redacts
// on String()/marshal, the #4406 golden redacts ControlLinkAuthKey, and
// pkg/grpcapi carries an AST gate (#6532/#6602) against unwrapping a Secret
// into a rendered string. This validator bypassed all of it by formatting the
// raw value.

// controlCharErr runs the strict commit-path control-character gate and returns
// its error.
func controlCharErr6625(t *testing.T, keys ...string) error {
	t.Helper()
	return controlCharErrUnder6625(t, "", keys...)
}

// controlCharErrUnder6625 runs the gate with an explicit path prefix, so a
// DUAL-USE keyword can be exercised under each stanza it appears in.
func controlCharErrUnder6625(t *testing.T, prefix string, keys ...string) error {
	t.Helper()
	return validateNodesControlChars([]*Node{{Keys: keys, IsLeaf: true}}, prefix)
}

// TestSecretValueNotRenderedInControlCharError6625 is the fail-on-revert case.
//
// FAIL-ON-REVERT: drop the secretLeaf branch from validateNodesControlChars, or
// stop redacting the keys handed to joinNodePath — either alone re-publishes
// the credential.
func TestSecretValueNotRenderedInControlCharError6625(t *testing.T) {
	for _, leaf := range []string{
		"authentication-key",
		"pre-shared-key",
		"preshared-key",
		"private-key",
		"encrypted-password",
		"password",
		"tsig-secret",
		"api-key",
	} {
		t.Run(leaf, func(t *testing.T) {
			const secret = "SUPER-SECRET-PSK-VALUE"
			err := controlCharErr6625(t, leaf, "\t"+secret+"\t")
			if err == nil {
				t.Fatalf("setup: a control character in %s must still be REJECTED", leaf)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("#6625: the %s error PUBLISHES the credential — it reaches commit "+
					"output, the daemon log and the audit journal, which is precisely what the "+
					"operator was setting privately.\ngot: %s", leaf, err.Error())
			}
			// It must still be actionable: name the statement, and say where
			// and what the offending byte is.
			if !strings.Contains(err.Error(), leaf) {
				t.Fatalf("the error must still name the statement %q; got: %s", leaf, err.Error())
			}
			if !strings.Contains(err.Error(), "byte offset") {
				t.Fatalf("the error must locate the offending byte so the operator can fix the "+
					"input without seeing it echoed; got: %s", err.Error())
			}
			if !strings.Contains(err.Error(), "0x09") {
				t.Fatalf("the error must name the offending byte class; got: %s", err.Error())
			}
		})
	}
}

// TestNonSecretValueStillRenderedInControlCharError6625 is the negative
// control: the fix must not blanket-suppress a genuinely useful diagnostic.
//
// For an ordinary leaf the value is exactly what the operator needs to see —
// which invisible character got pasted into their host-name or description.
//
// FAIL-ON-REVERT: make the redaction unconditional (drop the secretLeafKeywords
// lookup) and this reds.
func TestNonSecretValueStillRenderedInControlCharError6625(t *testing.T) {
	for _, leaf := range []string{"host-name", "description", "domain-name"} {
		t.Run(leaf, func(t *testing.T) {
			const val = "my\thost"
			err := controlCharErr6625(t, leaf, val)
			if err == nil {
				t.Fatalf("setup: a control character in %s must be REJECTED", leaf)
			}
			// %q ESCAPES the tab, so the rendered form is the quoted literal
			// `"my\thost"`, not a raw tab. Asserting the raw byte would fail
			// against a correct implementation.
			if !strings.Contains(err.Error(), strconv.Quote(val)) {
				t.Fatalf("#6625 over-correction: a NON-secret leaf must still render its value — "+
					"that diagnostic is the whole point for an ordinary statement; got: %s",
					err.Error())
			}
		})
	}
}

// TestSecretLeafKeywordsExistInSchema pins the set against the grammar: every
// keyword must be a real schema leaf, so the set cannot accumulate entries for
// statements that no longer exist and quietly look bigger than it is.
//
// FAIL-ON-REVERT: add a keyword to secretLeafKeywords that appears nowhere in
// the schema.
func TestSecretLeafKeywordsExistInSchema(t *testing.T) {
	if len(secretLeafKeywords) == 0 {
		t.Fatal("secretLeafKeywords is EMPTY — every credential value would be rendered, and " +
			"the redaction tests would pass vacuously against an empty set")
	}
	for kw := range secretLeafKeywords {
		if !schemaHasLeafKeyword(t, kw) {
			t.Errorf("#6625: secretLeafKeywords contains %q, which is not a leaf keyword anywhere "+
				"in setSchema — a dead entry makes the set look broader than it is", kw)
		}
	}
}

// TestSecretLeafKeywordsCoverKnownCredentials is the coverage direction, and it
// is the one that matters: a credential leaf MISSING from the set leaks, while
// a spurious one merely costs a diagnostic.
//
// The list here is deliberately independent of the production set — it is
// derived from the leaves the compiler wraps in Secret() — so the two must
// agree rather than one being read off the other.
//
// FAIL-ON-REVERT: remove any of these from secretLeafKeywords.
func TestSecretLeafKeywordsCoverKnownCredentials(t *testing.T) {
	// Every one of these is wrapped in config.Secret by the compiler:
	// authentication-key (chassis cluster / VRRP / OSPF / RIP / IS-IS),
	// pre-shared-key (IKE), preshared-key + private-key (WireGuard),
	// encrypted-password (system login / root-authentication),
	// password (web-management auth), tsig-secret (DDNS), api-key (REST auth).
	for _, kw := range []string{
		"authentication-key",
		"pre-shared-key",
		"preshared-key",
		"private-key",
		"encrypted-password",
		"password",
		"tsig-secret",
		"api-key",
	} {
		if !secretLeafKeywords[kw] {
			t.Errorf("#6625: %q is a credential leaf (the compiler wraps it in Secret) but is "+
				"NOT in secretLeafKeywords, so a control character in it publishes the "+
				"credential to commit output, the daemon log and the audit journal", kw)
		}
	}
}

// schemaHasLeafKeyword reports whether keyword appears as a leaf name anywhere
// in setSchema.
func schemaHasLeafKeyword(t *testing.T, keyword string) bool {
	t.Helper()
	seen := map[*schemaNode]bool{}
	var walk func(n *schemaNode) bool
	walk = func(n *schemaNode) bool {
		if n == nil || seen[n] {
			return false
		}
		seen[n] = true
		for name, child := range n.children {
			if name == keyword {
				return true
			}
			if walk(child) {
				return true
			}
		}
		return walk(n.wildcard)
	}
	return walk(setSchema)
}

// TestDualUseCommunityRedactedOnlyUnderSNMP6625 pins BOTH sides of the one
// keyword whose secrecy depends on where it appears.
//
// Under `snmp` the community string IS the credential. Under `policy-options`
// it is a BGP route-target name, and #4097's gate exists specifically to show
// the operator WHICH community member carried a newline.
//
// An earlier revision of this fix keyed secrecy on the KEYWORD alone and
// redacted both — which broke that diagnostic and was caught by
// TestFRRPolicyValueControlCharsBlocked_4097, not by inspection. This test
// exists so the distinction cannot regress silently in either direction.
//
// FAIL-ON-REVERT: move "community" into secretLeafKeywords (the BGP leg reds),
// or delete secretLeafKeywordsByRoot (the SNMP leg reds).
func TestDualUseCommunityRedactedOnlyUnderSNMP6625(t *testing.T) {
	const val = "\tSECRET-COMMUNITY-STRING\t"

	snmpErr := controlCharErrUnder6625(t, "snmp", "community", val)
	if snmpErr == nil {
		t.Fatal("setup: a control character in an snmp community must be REJECTED")
	}
	if strings.Contains(snmpErr.Error(), "SECRET-COMMUNITY-STRING") {
		t.Fatalf("#6625: an SNMP community string IS a credential and must not be rendered; "+
			"got: %s", snmpErr.Error())
	}

	bgpErr := controlCharErrUnder6625(t, "policy-options", "community", val)
	if bgpErr == nil {
		t.Fatal("setup: a control character in a policy-options community must be REJECTED")
	}
	if !strings.Contains(bgpErr.Error(), strconv.Quote(val)) {
		t.Fatalf("#6625 over-correction: a BGP policy-options community is a route-target NAME, "+
			"not a credential — #4097's gate exists to show WHICH member carried the control "+
			"character, and redacting it destroys that diagnostic; got: %s", bgpErr.Error())
	}
}

func TestSchemaErrorsRedactCredentialPathElements10771(t *testing.T) {
	tests := []struct {
		name        string
		set         string
		secret      string
		want        string
		wantVisible string
	}{
		{
			name:        "SNMP community identity",
			set:         "set snmp community LEAK-SNMP-COMMUNITY-10771 authorization read-wrote",
			secret:      "LEAK-SNMP-COMMUNITY-10771",
			want:        "<redacted>",
			wantVisible: `invalid value "read-wrote"`,
		},
		{
			name:        "IKE PSK swallowed as missing qualifier",
			set:         "set security ike policy ike-pol pre-shared-key LEAK-PSK-10771",
			secret:      "LEAK-PSK-10771",
			want:        "<redacted>",
			wantVisible: "pre-shared-key",
		},
		{
			name:        "BGP community remains an identifier",
			set:         "set policy-options community LEAK-BGP-COMMUNITY-10771 members",
			secret:      "LEAK-BGP-COMMUNITY-10771",
			wantVisible: "LEAK-BGP-COMMUNITY-10771",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := SchemaValidate(buildTree(t, []string{tc.set}), nil)
			if err == nil {
				t.Fatal("malformed secret-path config passed schema validation")
			}
			got := err.Error()
			if strings.Contains(got, tc.secret) && tc.want != "" {
				t.Fatalf("schema diagnostic leaked credential %q: %s", tc.secret, got)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("schema diagnostic lacks redaction marker %q: %s", tc.want, got)
			}
			if !strings.Contains(got, tc.wantVisible) {
				t.Fatalf("schema diagnostic lost actionable detail %q: %s", tc.wantVisible, got)
			}
			if tc.want == "" && strings.Contains(got, "<redacted>") {
				t.Fatalf("non-secret BGP community name was over-redacted: %s", got)
			}
		})
	}
}
