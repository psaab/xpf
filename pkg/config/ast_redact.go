package config

import (
	"errors"
	"fmt"
	"strings"
)

// ast_redact.go masks secret leaf VALUES in the raw-AST render paths.
//
// #2053 made the TYPED compiled-config render safe: the config.Secret newtype
// redacts every operator secret on JSON/YAML marshal, so GET /api/v1/config
// (which json-encodes the compiled *config.Config) no longer leaks cleartext.
// But the AST-render surface — Format / FormatSet / FormatJSON / FormatXML /
// FormatInheritance / FormatCompare in ast_format.go — walks the *ConfigTree
// AST and prints leaf key tokens VERBATIM. That surface backs the REST config
// show / export / search / rollback endpoints and the gRPC ShowConfig RPC, so
// those returned the same secrets (#2053 protects) in CLEARTEXT (#4051, fable
// F-020). Junos redacts secrets in `show configuration` (SECRET-DATA); xpf's
// raw-AST paths did not.
//
// RedactedClone masks the secret leaf values so the AST-render display paths
// mirror the #2053 guarantee. It is a DISPLAY-only transform applied at the
// REST + gRPC boundary: the cleartext Format() on the real tree still backs HA
// config sync (daemon_ha_sync.go), the DR/compliance archive (daemon_flow.go),
// on-disk persistence + rollback (configstore) and the on-box CLI, none of
// which may lose the real secret.
//
// #2053's Secret-typed field set is the baseline, resolved to its AST leaf
// signatures (verified against compiler Secret(...) sites), plus the unmodeled
// identity/access bind-password paths from #10948:
//
//	pre-shared-key            IKE policy / IPsec VPN PSK   (keeps ascii-text|hexadecimal qualifier)
//	authentication-key        OSPF/IS-IS/RIP/BGP/VRRP auth key + BGP TCP-MD5
//	simple-password           OSPF simple-password auth (same AuthKey field)
//	key (under authentication md5 <id>)   OSPF hello md5 key
//	authentication-password   SNMPv3 USM auth password
//	privacy-password          SNMPv3 USM privacy password
//	encrypted-password        root / login crypt(3) hash
//	api-key                   REST API bearer/X-API-Key token(s)
//	password (under api-auth | dynamic-dns | archive-sites | identity | access)
//	                          REST basic-auth / DDNS HTTP / archival / AD-LDAP bind password
//	tsig-secret               RFC 2136 / DDNS TSIG HMAC key
//	api-token                 Cloudflare / DuckDNS DDNS API token
//	aws-secret-key            Route 53 DDNS AWS secret access key
//	private-key               WireGuard local static private key
//	preshared-key             WireGuard per-peer PSK
//	community (under snmp)     SNMP v1/v2c community string (the identity token)

// SecretDataPlaceholder is the mask emitted in place of a secret leaf value on
// the raw-AST render/display paths. It mirrors the Junos SECRET-DATA idiom and
// is deliberately distinct from the typed-struct redaction sentinel
// (SecretRedacted, "<redacted>") so the two surfaces stay independently
// greppable. It contains non-identifier characters, so a text/set/XML render
// quotes it — the output stays structurally valid.
const SecretDataPlaceholder = "##SECRET-DATA##"

// RedactedClone returns a deep copy of the tree with every secret leaf value
// masked by SecretDataPlaceholder, for the raw-AST DISPLAY paths (REST config
// show / export / search / rollback + gRPC ShowConfig / ShowCompare /
// ShowRollback). Structure, ordering, inactive markers and all non-secret
// values are preserved, so the redacted render is byte-identical to the
// cleartext render except at the masked value tokens. Returns nil for a nil
// receiver (callers mirror the nil handling of their cleartext siblings).
//
// It operates on a clone so the live tree — the SSOT for HA sync, the DR
// archive and persistence — is never mutated.
func (t *ConfigTree) RedactedClone() *ConfigTree {
	if t == nil {
		return nil
	}
	c := t.Clone()
	redactNodes(c.Children, nil)
	return c
}

// redactNodes walks nodes maintaining the flattened key path of all ancestors
// (base). A secret token is identified on the FULL flattened path so it is
// matched identically whether the parser produced a hierarchical tree (secret
// split across nested block nodes) or a flat SetPath collapsed the whole
// branch onto one leaf's Keys (the dual AST shape, CLAUDE.md). Each secret
// index is masked in whichever node's own Keys slice owns it (idx >= len(base))
// — so a container-identity secret (an SNMP community name) is masked once, on
// the node that introduces it, and its descendants skip it.
func redactNodes(nodes []*Node, base []string) {
	for _, n := range nodes {
		full := append(append([]string(nil), base...), n.Keys...)
		for _, idx := range secretIndices(full) {
			if idx >= len(base) && idx < len(full) {
				n.Keys[idx-len(base)] = SecretDataPlaceholder
			}
		}
		// #6703: URL-bearing leaves are TRANSFORMED, not masked — see
		// urlLeafIndices. RedactURL strips userinfo/query/fragment (and an
		// implausible authority, #6609) while keeping scheme/host/path, so a
		// credential-free URL renders unchanged.
		for _, idx := range urlLeafIndices(full) {
			if idx >= len(base) && idx < len(full) {
				n.Keys[idx-len(base)] = RedactURL(n.Keys[idx-len(base)])
			}
		}
		if !n.IsLeaf {
			redactNodes(n.Children, full)
		}
	}
}

// secretIndices returns the indices into the flattened key path fp that carry
// a secret value and must be masked. It reuses #2053's secret-leaf signatures
// (see the file header) and adds the unmodeled AD/LDAP bind-password contexts
// from #10948. Generic keywords (key, password, community) are disambiguated by
// required ancestor context so a GRE tunnel `key`, a chassis identity `key` or
// a routing-policy `community` (all non-secret) are never masked.
func secretIndices(fp []string) []int {
	var out []int
	for i, k := range fp {
		switch k {
		case "pre-shared-key":
			// Value token(s) follow; keep a leading ascii-text|hexadecimal
			// format qualifier so the render stays structurally valid.
			j := i + 1
			if j < len(fp) && (fp[j] == "ascii-text" || fp[j] == "hexadecimal") {
				j++
			}
			for ; j < len(fp); j++ {
				out = append(out, j)
			}
		case "authentication-key", "additional-authentication-key",
			"authentication-password", "privacy-password",
			"encrypted-password", "simple-password", "api-key", "tsig-secret",
			"api-token", "aws-secret-key", "private-key", "preshared-key":
			// Distinctive secret keywords: every token after the keyword is
			// secret value (covers multi-token / bracketed list values too).
			for j := i + 1; j < len(fp); j++ {
				out = append(out, j)
			}
		case "password":
			// Generic keyword — secret under REST api-auth, a DDNS
			// provider, an archive-site transfer credential (#7511), or an
			// AD/LDAP identity stanza (#10948); other `password` uses do
			// not exist today but the context gate keeps a future non-secret
			// `password` unmasked.
			//
			// #7511: `system archival configuration archive-sites <url>
			// password <secret>` rendered the secret IN FULL. `archive-sites`
			// is named for what it is, and a `password` nested under it matched
			// neither of the two scopes this pass knew about — the name-keyed
			// design's limitation, seen on the raw-AST surface after #7510
			// fixed the typed one.
			//
			// #10948: same shape, new unenclosed context. `services
			// user-identification ...` (and the same identity stanzas spelled
			// directly under `services`) is unmodeled — absent from
			// schemaServices, accepted-only per #10947, AST the sole carrier —
			// so an AD/LDAP bind `password` under it matched no scope and
			// rendered in cleartext to PermView on every AST-display surface.
			// `user-identification` covers the wrapped spelling at any depth;
			// the three stanza names cover the direct-under-services spelling
			// the compiler also accepts.
			if containsAnyOf(fp[:i], "api-auth", "dynamic-dns", "archive-sites", "user-identification", "access",
				"active-directory-access", "identity-management", "local-authentication-table") {
				for j := i + 1; j < len(fp); j++ {
					out = append(out, j)
				}
			}
		case "secret":
			// `secret` is generic; redact it only for named API-key identities.
			if isAPIAuthNamedKeySecretPath(fp[:i]) {
				for j := i + 1; j < len(fp); j++ {
					out = append(out, j)
				}
			}
		case "key":
			// `authentication md5 <key-id> key <secret>`. A GRE tunnel `key`
			// or a chassis device-map identity `key` has no such context.
			if i >= 3 && fp[i-2] == "md5" && fp[i-3] == "authentication" && i+1 < len(fp) {
				out = append(out, i+1)
			}
		case "community":
			// SNMP v1/v2c community string is the container-identity token
			// directly under `snmp` (the whole point of the community is a
			// shared secret). A policy-options `community` is a routing object
			// under policy-options, not snmp — left unmasked.
			if i >= 1 && fp[i-1] == "snmp" && i+1 < len(fp) {
				out = append(out, i+1)
			}
		}
	}
	return out
}

// urlLeafIndices returns the indices into the flattened key path fp that hold a
// URL-BEARING leaf value. These are redacted by TRANSFORM (RedactURL) rather
// than by replacement with SecretDataPlaceholder, because a URL is
// secret-BEARING without being a secret (#6703): the credential lives in the
// userinfo, query or fragment, while the scheme/host/path are the diagnostic
// payload an operator needs to keep seeing. Masking the whole token would make
// a credential-free URL — the overwhelmingly common case — unreadable.
//
// KEYED ON THE LEAF NAME, not on a list of config locations. `url` is matched
// in EVERY context, so a future url-bearing leaf inherits redaction with no
// extra step; that is deliberate, and it is why this does not repeat the
// hand-scoped mistake that produced #6703 in the first place. Applying
// RedactURL universally is safe precisely because it is a no-op on a URL with
// no credential-bearing component.
//
// The two DDNS leaves that are URLs without being named `url`
// (`url-template`, `checkip-url`) are distinctive enough to match unqualified.
// `server` and `update-server` are NOT — `server` is also an NTP leaf
// (schema_system.go) — so both are gated on a `dynamic-dns` ancestor, the same
// context-gate doctrine secretIndices uses for the generic `password` keyword.
func urlLeafIndices(fp []string) []int {
	var out []int
	for i, k := range fp {
		switch k {
		case "url", "url-template", "checkip-url":
			for j := i + 1; j < len(fp); j++ {
				out = append(out, j)
			}
		case "server", "update-server":
			// Generic keywords — a URL only under a DDNS provider.
			if containsAnyOf(fp[:i], "dynamic-dns") {
				for j := i + 1; j < len(fp); j++ {
					out = append(out, j)
				}
			}
		case "path":
			// #7406: the per-feed path under `security dynamic-address
			// feed-server <s> feed-name <f> path <p>`. resolveBaseURL joins
			// this onto the feed-server's url/hostname, so the leaf accepts a
			// full URL tail and a `?token=SECRET` query is the common feed
			// provider shape. FeedEntry.MarshalJSON (types_security.go) has
			// run it through RedactURL on the JSON config-read route since
			// #6703; without this case `show configuration` rendered the SAME
			// token verbatim. The two surfaces have to agree, and the
			// AST one was the leak.
			//
			// Gated like `server`: `path` is a generic keyword, so it is a URL
			// only under a feed-server. Note this closes the QUERY/userinfo
			// class only — a key that IS a path segment or a host label
			// (`.../SECRET/list.txt`, `https://SECRET.feed.example/`) is
			// unredactable by any string rule and is documented as such in
			// pkg/feeds/README.md rather than papered over here.
			if containsAnyOf(fp[:i], "feed-server") {
				for j := i + 1; j < len(fp); j++ {
					out = append(out, j)
				}
			}
		case "hostname":
			// #8104: `security dynamic-address feed-server <s> hostname`.
			// resolveBaseURL joins this with a feed's path to build the fetch
			// URL, so it accepts a FULL URL including userinfo -- the typed
			// route has redacted it since #6733, whose own comment names the
			// leak shape ("an operator who writes user:token@feeds.example
			// here leaks it through the authenticated REST GET"). That fix
			// covered the JSON surface only; the AST route rendered the same
			// credential verbatim on `show configuration`, the gRPC config
			// RPCs and the on-box CLI until #8104.
			//
			// Gated on `feed-server` exactly like `path`: `hostname` is a
			// generic keyword and is a bare host under `security ike gateway
			// dynamic`, `security ipsec gateway dynamic` and the per-unit
			// `dynamic-dns` blocks, none of which the typed route redacts.
			// RedactURL is a no-op on a bare host anyway (#6609), so the gate
			// is about not making a claim the typed side does not make.
			if containsAnyOf(fp[:i], "feed-server") {
				for j := i + 1; j < len(fp); j++ {
					out = append(out, j)
				}
			}
		case "endpoint":
			// #8104: `interfaces <if> [unit <u>] tunnel wireguard peer <p>
			// endpoint`. WgPeerConfig.MarshalJSON has run this through
			// RedactURL since the peer type gained a marshaller; the AST route
			// did not, so a `user:token@host` endpoint rendered verbatim.
			//
			// Gated on `wireguard` for the same reason as `hostname`: the
			// keyword is generic enough that an unqualified case would claim
			// leaves the typed route says nothing about.
			if containsAnyOf(fp[:i], "wireguard") {
				for j := i + 1; j < len(fp); j++ {
					out = append(out, j)
				}
			}
		case "archive-sites":
			// #7511: an archive TRANSFER url — `scp://user:pw@host/dir` — which
			// lives only in the raw AST and is never promoted to a typed field,
			// so no MarshalJSON sees it and #7510's typed pass could not reach
			// it. Both spellings are covered: `system syslog file <n> archive
			// archive-sites <url>` and `system archival configuration
			// archive-sites <url>`.
			//
			// STOPS AT `password`, which follows the url as a sibling token in
			// the flat path (`archive-sites <url> password <secret>`). Marking
			// every trailing token would hand the SECRET to RedactURL, and
			// RedactURL is a no-op on input that is not a URL — so the password
			// would render verbatim while looking like it had been processed.
			// The secret is masked outright by secretIndices' `password` case,
			// which #7511 extends to this scope; these two must not overlap.
			//
			// If another sub-keyword is ever added under archive-sites, it
			// needs adding here too, or its value is fed to RedactURL. That is
			// a no-op rather than a corruption, but it would also mean the new
			// leaf is unredacted — so the stop list is the thing to extend.
			for j := i + 1; j < len(fp); j++ {
				if fp[j] == "password" {
					break
				}
				out = append(out, j)
			}
		}
	}
	return out
}

// containsAnyOf reports whether seq contains any of names.
func containsAnyOf(seq []string, names ...string) bool {
	for _, s := range seq {
		for _, n := range names {
			if s == n {
				return true
			}
		}
	}
	return false
}

// errRedactionPlaceholderIngest is returned by checkRedactionPlaceholder when a
// SECRET leaf carries the raw-AST redaction placeholder (SecretDataPlaceholder,
// "##SECRET-DATA##"). It is the symmetric commit-ingest guard for the raw-AST
// display redaction, mirroring errRedactedSecretIngest (secret.go), which
// refuses the typed-struct sentinel ("<redacted>") on a JSON round-trip.
//
// Why this exists (#4060): RedactedClone masks every secret leaf with the
// placeholder for the REST config show / export + gRPC ShowConfig surfaces
// (#4051). Those renders are DISPLAY-only and deliberately NOT restorable — the
// cleartext SSOT still backs HA sync, the DR/compliance archive and persistence.
// But an operator who does a REST `export` (now secret-redacted) and then
// re-applies that text (a `load`/commit) would otherwise silently commit
// "##SECRET-DATA##" as the LITERAL secret for every secret leaf — the IKE PSK,
// key or community becomes the nonsense string and the tunnel/auth breaks. The
// guard rejects that on commit-ingest so the redacted export cannot masquerade
// as a restorable backup.
var errRedactionPlaceholderIngest = errors.New(
	"config contains the redaction placeholder " + SecretDataPlaceholder +
		" — this is a redacted export (REST show/export / gRPC ShowConfig), not a " +
		"restorable config; restore from the DR archive (request system " +
		"configuration rescue) or re-enter the secret in cleartext")

// errRedactedURLIngest is the URL-leaf sibling of errRedactionPlaceholderIngest
// (#6703). RedactURL rewrites a credential-bearing URL leaf to contain the
// typed sentinel ("<redacted>") on the display paths, and unlike the secret
// placeholder the result still LOOKS like a valid URL — so re-committing a
// redacted export would silently install a broken endpoint (a DDNS provider
// publishing to "https://host/upd?<redacted>", a feed fetched from a mangled
// URL) instead of failing loudly. That is a worse failure than the secret case,
// which is why the ingest guard is symmetric rather than optional.
var errRedactedURLIngest = errors.New(
	"config contains a redacted URL value (" + SecretRedacted + ") — this is a " +
		"redacted export (REST show/export / gRPC ShowConfig), not a restorable " +
		"config; restore from the DR archive (request system configuration " +
		"rescue) or re-enter the URL in cleartext")

// checkRedactionPlaceholder rejects a tree whose SECRET leaf value is exactly
// SecretDataPlaceholder ("##SECRET-DATA##"). It is invoked by the commit-ingest
// schema gate (SchemaValidateWithDefinitions), so on the strict operator commit
// / commit-check path it FAILS the commit, while the tolerant Load / SyncApply
// path downgrades it to a warning (compileTreeLenient) — the same strict/lenient
// doctrine the #1319 typed-leaf gate uses.
//
// Scope is exactly RedactedClone's: the SAME secret-leaf set (secretIndices) is
// used to detect the placeholder that RedactedClone used to PRODUCE it. A
// non-secret leaf that happens to carry the literal "##SECRET-DATA##" string is
// NOT rejected — RedactedClone never masks it, so ingesting it is harmless and
// rejecting it would be an over-reach. The returned error names the offending
// config path for the operator.
func checkRedactionPlaceholder(t *ConfigTree) error {
	if t == nil {
		return nil
	}
	if path := findRedactionPlaceholder(t.Children, nil); path != "" {
		return fmt.Errorf("%w (at %q)", errRedactionPlaceholderIngest, path)
	}
	if path := findRedactedURL(t.Children, nil); path != "" {
		return fmt.Errorf("%w (at %q)", errRedactedURLIngest, path)
	}
	return nil
}

// findRedactedURL is the URL-leaf mirror of findRedactionPlaceholder (#6703).
// Its scope is exactly what redactNodes TRANSFORMS — the same urlLeafIndices
// set is used to detect the sentinel that produced it — so detection stays
// symmetric with masking under either AST shape.
//
// It tests CONTAINS rather than equals: RedactURL embeds the sentinel inside an
// otherwise-intact URL ("https://host/upd?<redacted>"), so an equality test
// would miss every real case. A non-URL leaf carrying that literal is not
// inspected at all, mirroring the placeholder guard's deliberate narrowness.
func findRedactedURL(nodes []*Node, base []string) string {
	for _, n := range nodes {
		full := append(append([]string(nil), base...), n.Keys...)
		for _, idx := range urlLeafIndices(full) {
			if idx >= len(base) && idx < len(full) && strings.Contains(n.Keys[idx-len(base)], SecretRedacted) {
				return strings.Join(full[:idx+1], " ")
			}
		}
		if !n.IsLeaf {
			if hit := findRedactedURL(n.Children, full); hit != "" {
				return hit
			}
		}
	}
	return ""
}

// findRedactionPlaceholder walks nodes maintaining the flattened key path of all
// ancestors (base), mirroring redactNodes. It returns the flattened path (up to
// and including the offending value token) of the FIRST secret leaf whose value
// equals SecretDataPlaceholder, or "" if none. A secret index is only inspected
// in whichever node's own Keys slice owns it (idx >= len(base)) — matching how
// redactNodes masks the token — so the detection is exactly symmetric with the
// masking regardless of the dual (hierarchical vs flat-set) AST shape.
func findRedactionPlaceholder(nodes []*Node, base []string) string {
	for _, n := range nodes {
		full := append(append([]string(nil), base...), n.Keys...)
		for _, idx := range secretIndices(full) {
			if idx >= len(base) && idx < len(full) && n.Keys[idx-len(base)] == SecretDataPlaceholder {
				return strings.Join(full[:idx+1], " ")
			}
		}
		if !n.IsLeaf {
			if hit := findRedactionPlaceholder(n.Children, full); hit != "" {
				return hit
			}
		}
	}
	return ""
}
