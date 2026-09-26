package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// errRedactedSecretIngest is returned by Secret.UnmarshalJSON when the
// redaction sentinel is decoded — see UnmarshalJSON.
var errRedactedSecretIngest = errors.New(
	"config: refusing to ingest redacted secret sentinel \"" + SecretRedacted + "\"")

// Secret is a config string whose cleartext value is preserved in memory
// for the reconciler/render paths but is REDACTED on any JSON/YAML marshal
// so a compiled-config serializer can never leak it (#2053).
//
// Why this exists: the compiled *config.Config carries every operator
// secret verbatim (IKE/IPsec pre-shared keys, OSPF/IS-IS/RIP/VRRP/interface
// auth keys, the TSIG HMAC key, SNMPv3 auth/priv passwords, root/login
// crypt(3) hashes, the BGP TCP-MD5 password, REST basic-auth passwords +
// API keys, the WireGuard private key). A registered production REST route,
// GET /api/v1/config (pkg/api/config.go), JSON-encodes that whole struct.
// Before #2053 it returned every secret in plaintext to any authorized
// client (loopback by default, but bindable non-loopback over HTTPS via
// `web-management https interface`). The pre-existing String() redaction on
// a couple of structs only covers %v/%s/slog — encoding/json ignores
// Stringer, so it did NOT close the marshal leak. Making the field type
// itself enforce redaction means the guarantee is type-enforced, not
// per-comment: any present or future marshal of a struct that contains a
// Secret field redacts automatically, and adding a new secret field is a
// single type annotation.
//
// Round-trip is safe: nothing in the tree unmarshals a compiled
// *config.Config back from JSON/YAML (the persistence/sync SSOT is the
// *ConfigTree AST, db.go / sync_conn.go). A redacting marshaller therefore
// cannot starve any consumer of a secret. Render/reconcile sites read the
// cleartext via Reveal(). UnmarshalJSON and UnmarshalYAML below additionally
// refuse the redaction sentinel so that if a compiled-config JSON or YAML
// ingest is ever added it fails loudly instead of silently loading
// "<redacted>" as a key.
//
// Secret keeps the underlying string kind (it is a named string type, not a
// struct) so it stays comparable — usable as a map key and directly
// comparable to "" for present/absent checks at call sites.
type Secret string

// SecretRedacted is the sentinel emitted in place of a non-empty Secret on
// JSON/YAML marshal.
const SecretRedacted = "<redacted>"

// String redacts a non-empty Secret for %v/%s/slog formatting (logging
// hygiene). An empty Secret renders as "" so absence stays distinguishable.
func (s Secret) String() string {
	if s == "" {
		return ""
	}
	return SecretRedacted
}

// RedactURL strips credential-bearing components from a URL or URL template
// for %v/%s/slog formatting (logging hygiene, #2781). It is deliberately
// string-based rather than net/url-based because the value may be an inadyn
// URL TEMPLATE carrying %h/%i/%u/%p specifiers (e.g. the generic DDNS backend,
// pkg/ddns/backend_generic.go) which are not valid percent-encoding and would
// make url.Parse fail or mangle the string.
//
// FOUR credential-carrying components are redacted while the scheme/host/path
// prefix is preserved so the log line stays diagnostically useful:
//
//   - userinfo: a "user:pass@" (or "user@") segment inside the authority
//     becomes "<redacted>@" — operators embed creds there (e.g.
//     https://user:token@api.example/update). The authority is the network
//     location up to the first '/', '?' or '#'; for a scheme'd URL it begins
//     after "://", for a SCHEME-RELATIVE URL ("//user:pass@host/") after the
//     leading "//", and for a SCHEMELESS URL (e.g. a generic DDNS provider
//     template like "user:pass@host/upd?token=SECRET", which has NO commit-time
//     scheme validator) at index 0. Userinfo is redacted in ALL THREE cases
//     (#5458, #6609).
//   - query string: everything after the first '?' becomes "<redacted>" — the
//     #2781 case is a token in the query (e.g. ...?token=SECRET&host=%h).
//   - fragment: everything after '#' becomes "<redacted>" (#6609). A fragment
//     carries an auth token exactly as routinely as a query
//     ("https://host/cb#access_token=SECRET"), and preserving one while
//     dropping the other was an inconsistency, not a decision. Note the
//     fragment was ALREADY dropped whenever a query was present, because the
//     query rule truncates the whole tail — so only the no-query case leaked,
//     which is exactly the case a sentinel in the query would not reveal.
//   - a HOST:PORT slot that cannot be a host:port (#6609). This is the one rule
//     that is not about a well-formed URL, and it is the reason this function
//     cannot be replaced by "parse, then redact the parsed parts".
//
// WHY THE HOST:PORT RULE EXISTS. The commonest credentialed operator typo is
// omitting the '@':
//
//	RedactURL("http://user:s3cr3t.example/")
//
// There is no '@' in the authority, so a purely userinfo-based redactor returns
// that UNCHANGED and the password is rendered in full. The same input is also
// what url.Parse rejects with an unbounded raw substring ("invalid port
// \":s3cr3t.example\" after host"), so one realistic mistake hits two surfaces
// at once — and any caller that reports "this URL is malformed" while rendering
// RedactURL(input) leaked the credential twice over. Since callers reach this
// function precisely BECAUSE a value is malformed, being sound only on
// well-formed input is the wrong contract.
//
// So when the host part carries a colon whose suffix is not a valid port, the
// WHOLE authority is replaced rather than a sub-span: in that state there is no
// way to tell the host from the credential, and a redactor that guesses would
// be guessing about a secret. This deliberately costs diagnostic detail on
// malformed input — the same trade #6594 made by printing no part of the input
// on a parse-failure branch. A bracketed IPv6 literal ("[::1]", "[::1]:8080")
// is recognised so it is NOT swallowed by this rule.
//
// The redaction is bounded to the authority: an '@' in the PATH ("host/p@th")
// or QUERY ("host?x=a@b") is past the authority boundary and does NOT trigger
// userinfo redaction (the query is dropped wholesale regardless).
//
// An empty input returns "" so absence stays distinguishable. A value with no
// credential-bearing component is returned with the query (if any) still
// redacted; query strings are treated as sensitive because generic templates
// routinely carry the auth token there.
//
// NOT CONSOLIDATED WITH pkg/ddns's scrubber, deliberately. That one takes an
// *error* and works on an ALREADY-PARSED *url.URL, where it can enumerate
// fields; this one takes a string that may not parse at all. They cannot share
// an implementation. What they must share is the DEFINITION of which parts may
// carry a credential — userinfo, query and fragment — and that agreement is
// pinned by a cross-package sentinel corpus (pkg/ddns's scrubber-parity test),
// so a third scrubber cannot re-derive a partial list.
func RedactURL(s string) string {
	if s == "" {
		return ""
	}
	const redacted = "<redacted>"

	// Locate the authority. It starts after "://" for a scheme'd URL, after the
	// leading "//" for a scheme-relative one, and at index 0 for a schemeless
	// template (#5458); it ends at the first '/', '?' or '#'. Bounding to the
	// authority keeps an '@' in the path or query untouched.
	authStart := urlAuthorityStart(s)
	authEnd := len(s)
	for j := authStart; j < len(s); j++ {
		if c := s[j]; c == '/' || c == '?' || c == '#' {
			authEnd = j
			break
		}
	}
	authority := s[authStart:authEnd]

	// Split userinfo from the host part. The host part is what follows the LAST
	// '@'; with no '@' the whole authority is the host part.
	host := authority
	hasUserinfo := false
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		host = authority[at+1:]
		hasUserinfo = true
	}

	switch {
	case !urlHostPortPlausible(host):
		// The host part cannot be a host[:port], so a credential is sitting in
		// the host:port slot (the missing-'@' typo) — or in BOTH slots. There is
		// no way to tell host from secret here, so replace the whole authority.
		s = s[:authStart] + redacted + s[authEnd:]
	case hasUserinfo:
		s = s[:authStart] + redacted + "@" + host + s[authEnd:]
	}

	// Redact the query string: everything after the first '?'. This already
	// swallows any fragment, since the whole tail goes.
	if q := strings.IndexByte(s, '?'); q >= 0 {
		return s[:q+1] + redacted
	}
	// No query: the fragment still has to go on its own (#6609).
	if f := strings.IndexByte(s, '#'); f >= 0 {
		return s[:f+1] + redacted
	}
	return s
}

// urlAuthorityStart returns the index at which a URL-ish string's authority
// begins.
//
// The scheme separator counts only when what precedes it could actually be a
// scheme — RFC 3986 forbids '/', '?' and '#' in a scheme, so a "://" appearing
// inside a path or query (".../p?u=http://a@b") is not one. Before #6609 the
// plain strings.Index would take that later "://" as the separator and point
// the authority window into the query.
//
// A leading "//" with no scheme is a SCHEME-RELATIVE URL, whose authority
// begins at index 2. Before #6609 this was missed entirely: authStart stayed 0,
// the very first character was the '/' that terminates the authority scan, and
// the authority came out EMPTY — so "//user:SECRET@host/" was returned
// verbatim, userinfo and all.
func urlAuthorityStart(s string) int {
	if i := strings.Index(s, "://"); i >= 0 && !strings.ContainsAny(s[:i], "/?#") {
		return i + len("://")
	}
	if strings.HasPrefix(s, "//") {
		return 2
	}
	return 0
}

// urlHostPortPlausible reports whether a URL authority's host part could be a
// host[:port]. It is false exactly when a colon is present whose suffix is not
// a port, which is what a credential in the host:port slot looks like.
//
// An empty host is plausible (an empty authority is not a leak; a hostless URL
// is rejected elsewhere, by the callers that care). An empty port is plausible
// too — url.Parse accepts "http://host:".
//
// A bracketed IPv6 literal is recognised so it is not mistaken for a
// credential: "[::1]" and "[::1]:8080" are both plausible, while an
// unterminated "[::1" is not (it cannot be a host, so whatever it is should not
// be printed). Without the bracket case every IPv6 URL would be redacted, which
// would be a silent loss of diagnostics on entirely well-formed input.
func urlHostPortPlausible(host string) bool {
	if host == "" {
		return true
	}
	rest := host
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end < 0 {
			return false // unterminated IPv6 literal
		}
		rest = host[end+1:]
		if rest == "" {
			return true
		}
		if rest[0] != ':' {
			return false // junk after the literal
		}
		return isAllDigits(rest[1:])
	}
	i := strings.LastIndexByte(rest, ':')
	if i < 0 {
		return true // no port separator at all
	}
	return isAllDigits(rest[i+1:])
}

// isAllDigits reports whether s consists solely of ASCII digits. An empty
// string is all-digits by this definition, which is what makes "http://host:"
// (an empty but syntactically valid port) plausible.
func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Reveal returns the real cleartext value. It is the canonical, audited way
// to read the secret; render/reconcile paths must call it explicitly. (A raw
// string(s) conversion also yields the cleartext — Secret is a string newtype
// — but Reveal is deliberately greppable so an audit can find every cleartext
// access; prefer it, and never feed the result into a log line.)
func (s Secret) Reveal() string { return string(s) }

// MarshalJSON redacts the secret. An empty Secret marshals to "" so that
// unset/empty stays distinguishable from a present-but-redacted value; a
// non-empty Secret marshals to the redaction sentinel. A value receiver is
// required so redaction fires for a Secret used as a struct field, inside a
// []Secret slice, and as a map value.
func (s Secret) MarshalJSON() ([]byte, error) {
	if s == "" {
		return []byte(`""`), nil
	}
	return json.Marshal(SecretRedacted)
}

// UnmarshalJSON accepts a plain string so the type is a drop-in if a tree
// value is ever decoded into it, but REFUSES the redaction sentinel: a
// round-trip through the redacting marshaller must never silently reload
// "<redacted>" as a real secret. The compiled-config SSOT is the AST tree,
// not JSON, so this path should not be reached today; it fails closed if
// that ever changes.
func (s *Secret) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	if v == SecretRedacted {
		return errRedactedSecretIngest
	}
	*s = Secret(v)
	return nil
}

// MarshalYAML mirrors MarshalJSON for the gopkg.in/yaml.v3 marshaller. No
// config YAML marshaller exists today, but the issue title names YAML and
// the method is detected by interface so this future-proofs the YAML
// surface at no cost. A value receiver keeps redaction firing in slices and
// map values.
func (s Secret) MarshalYAML() (any, error) {
	if s == "" {
		return "", nil
	}
	return SecretRedacted, nil
}

// UnmarshalYAML mirrors UnmarshalJSON for the gopkg.in/yaml.v3 decoder: it
// accepts a plain scalar so the type is a drop-in if a tree value is ever
// decoded from YAML, but REFUSES the redaction sentinel. Without this method
// yaml.v3 would decode the literal "<redacted>" straight into the Secret,
// bypassing the fail-closed guard the JSON path enforces (a marshalled-then-
// reloaded compiled config could silently reload "<redacted>" as a live
// secret). No config YAML ingest path exists today (the compiled-config SSOT
// is the AST tree, not YAML); this keeps the YAML surface symmetric with JSON
// and fails closed if one is ever added. A pointer receiver is required for
// any yaml.Unmarshaler.
func (s *Secret) UnmarshalYAML(value *yaml.Node) error {
	var v string
	if err := value.Decode(&v); err != nil {
		return err
	}
	if v == SecretRedacted {
		return errRedactedSecretIngest
	}
	*s = Secret(v)
	return nil
}

// secretLeafKeywords is the set of config-grammar leaf keywords whose VALUE is
// a credential (#6625).
//
// It exists because the control-character gate (validateNodesControlChars)
// runs on the AST, BEFORE compilation, so the compiled `Secret` type is not
// available to it — and that gate formats the offending value into its error,
// which for a credential publishes the credential to commit output, the daemon
// log and the audit journal.
//
// Keyed on the leaf KEYWORD (Keys[0]) rather than a full path, because a
// credential leaf is spelled the same wherever it appears: `authentication-key`
// is a secret under chassis cluster, VRRP, OSPF, RIP and IS-IS alike, and a
// path-keyed set would have to enumerate all of them and would silently miss
// the next one.
//
// ERR TOWARD INCLUSION for an UNAMBIGUOUS keyword. A false positive costs one
// diagnostic detail — the operator is told the byte offset and class instead of
// the value. A false negative publishes a credential.
//
// Membership is pinned against the schema by
// TestSecretLeafKeywordsExistInSchema (no dead entries) and against the known
// credential leaves by TestSecretLeafKeywordsCoverKnownCredentials.
var secretLeafKeywords = map[string]bool{
	"authentication-key": true,
	"pre-shared-key":     true,
	"preshared-key":      true,
	"private-key":        true,
	"encrypted-password": true,
	"password":           true,
	"tsig-secret":        true,
	"api-key":            true,
}

// secretLeafKeywordsByRoot qualifies a DUAL-USE keyword by the top-level
// stanza it appears under: secret in one place, an ordinary identifier in
// another.
//
// `community` is the worked example and the reason this map exists. Under
// `snmp` the community string IS the credential; under `policy-options` a
// community is a BGP route-target name, and #4097's gate exists specifically to
// show the operator WHICH community member carried a newline. Blanket-keying on
// the keyword redacted the BGP one and broke that diagnostic — caught by
// TestFRRPolicyValueControlCharsBlocked_4097, not by inspection.
//
// The lesson generalises: keyword-keying is right for a leaf spelled the same
// wherever it appears, and wrong the moment a spelling is reused for something
// that is not a credential. Add to THIS map, not the set above, whenever that
// is true.
var secretLeafKeywordsByRoot = map[string]map[string]bool{
	"community": {"snmp": true},
}

// IsSecretLeafKeyword reports whether an UNAMBIGUOUS config leaf keyword
// carries a credential as its value. Dual-use keywords are resolved by
// isSecretLeaf, which also considers the stanza the leaf appears under.
func IsSecretLeafKeyword(keyword string) bool {
	return secretLeafKeywords[keyword]
}

// isSecretLeaf reports whether the leaf named by keys carries a credential,
// given the path prefix it was found under.
func isSecretLeaf(prefix string, keys []string) bool {
	if len(keys) == 0 {
		return false
	}
	kw := keys[0]
	if secretLeafKeywords[kw] {
		return true
	}
	roots, dualUse := secretLeafKeywordsByRoot[kw]
	if !dualUse {
		return false
	}
	root := prefix
	if i := strings.IndexByte(root, ' '); i >= 0 {
		root = root[:i]
	}
	return roots[root]
}

// describeControlChar names the first control character in s by offset and
// byte value, WITHOUT reproducing the surrounding value (#6625). That is
// enough to locate and fix the input — a leading tab from a password manager
// is offset 0, a trailing CR is the last offset — while disclosing nothing.
func describeControlChar(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return fmt.Sprintf("a control character (0x%02x) at byte offset %d", s[i], i)
		}
	}
	return "a control character"
}

// redactSecretKeys returns keys with every VALUE token replaced by the
// redaction sentinel when the leaf keyword is a credential (#6625). Keys[0] is
// the leaf name and is kept — the operator needs to know WHICH statement was
// rejected.
func redactSecretKeys(prefix string, keys []string) []string {
	if !isSecretLeaf(prefix, keys) {
		return keys
	}
	out := make([]string, len(keys))
	out[0] = keys[0]
	for i := 1; i < len(keys); i++ {
		out[i] = SecretRedacted
	}
	return out
}

// redactSecretPath masks credential operands in a schema-walker path before
// it is included in a diagnostic. It shares the path classification used by
// AST rendering so identity-bearing credentials (such as SNMP community names)
// and value-bearing credentials cannot diverge across output surfaces.
func redactSecretPath(path []string) []string {
	indices := secretIndices(path)
	if len(indices) == 0 {
		return path
	}
	redacted := append([]string(nil), path...)
	for _, index := range indices {
		if index >= 0 && index < len(redacted) {
			redacted[index] = SecretRedacted
		}
	}
	return redacted
}
