package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
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
// signatures (verified against compiler NewSecret(...) sites), plus the unmodeled
// identity/access bind-password paths from #10948:
//
//	pre-shared-key            IKE policy / IPsec VPN PSK   (keeps ascii-text|hexadecimal qualifier)
//	authentication-key        OSPF/IS-IS/RIP/BGP/VRRP auth key + BGP TCP-MD5
//	simple-password           OSPF simple-password auth (same AuthKey field)
//	key (under an authentication/md5 ancestor pair, any distance)   OSPF hello md5 key (#14389)
//	authentication-password   SNMPv3 USM auth password
//	privacy-password          SNMPv3 USM privacy password
//	encrypted-password        root / login crypt(3) hash
//	plain-text-password(-value)  Junos plaintext password (rejected at strict commit, #15053; masked for tolerant trees)
//	api-key                   REST API bearer/X-API-Key token(s)
//	password (under api-auth | dynamic-dns | archive-sites | identity | access)
//	                          REST basic-auth / DDNS HTTP / archival / AD-LDAP bind password
//	tsig-secret               RFC 2136 / DDNS TSIG HMAC key
//	api-token                 Cloudflare / DuckDNS DDNS API token
//	aws-secret-key            Route 53 DDNS AWS secret access key
//	private-key               WireGuard local static private key
//	preshared-key             WireGuard per-peer PSK
//	community (under snmp)     SNMP v1/v2c community string (the identity token)
//	trap-group (under snmp)    trap-group name = v1/v2c trap community (#16728)
//	secret (under radius-server | tacplus-server | accounting | outbound-ssh)
//	                          RADIUS/TACACS+ shared secret (#15019); outbound-ssh
//	                          client secret (#16731, unmodelled Junos leaf)
//	user-password              AD bind credential under active-directory-access
//	                          (#15996; unmodelled stanza, AST-side only)
//	credential-shaped keywords (#16731 fail-closed): any keyword containing
//	                          `secret` or `password`, equal to `auth-token`, or
//	                          equal to `community-name` masks every trailing
//	                          token in ANY context. This covers the unmodelled
//	                          Junos leaves default-chap-secret, local-password,
//	                          auth-token, community-name and dhcp/dhcp-relay
//	                          `authentication password` without enumerating
//	                          their ancestors. Valued `*-key` is deliberately
//	                          NOT shape-masked: trusted-key/tsig-key/aws-access-key
//	                          are public identifiers and GRE/chassis `key`
//	                          stays gated on the OSPF md5 pair below.

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

// FormatCompareRedacted returns a hierarchical diff with secret values
// constant-masked on both arms. A changed secret also emits an adjacent
// 8-hex SHA-256 fingerprint metadata line, so equality is preserved without
// placing the fingerprint in the rendered value arm. URL credentials receive
// the same treatment while their already-redacted URL context is preserved.
func FormatCompareRedacted(oldTree, newTree *ConfigTree) string {
	diff := FormatCompare(fingerprintRedactedClone(oldTree), fingerprintRedactedClone(newTree))
	return maskCompareFingerprints(diff)
}

// FormatCompareRedactedAtPath is FormatCompareRedacted filtered to path
// (#15272 B24-03).
//
// #15942 H2-03: the path is navigated on the UNREDACTED trees first and
// only the matched subtrees are fingerprint-redacted. Redacting the
// whole tree first rewrites identity tokens the path itself names
// (`snmp community <name>`, a credential-bearing `archive-sites <url>`),
// so navigation by the caller's original path matched nothing and a
// valid secret-identity path rendered "" / "[no changes]" even when
// the subtree changed.
func FormatCompareRedactedAtPath(oldTree, newTree *ConfigTree, path []string) string {
	if len(path) == 0 {
		return FormatCompareRedacted(oldTree, newTree)
	}
	oldMatches, oldWidth := scopedMatches15942(oldTree, path)
	newMatches, newWidth := scopedMatches15942(newTree, path)
	if len(oldMatches) == 0 && len(newMatches) == 0 {
		return ""
	}
	width := oldWidth
	if len(oldMatches) == 0 {
		width = newWidth
	}
	parentPrefix := append([]string(nil), path[:len(path)-width]...)
	// #15942 (fold): a DESCENDANT scope's parent prefix is rendered as
	// output context ([edit …] header, set-line prefixes), so it must
	// not reprint secret identity tokens the scope passed THROUGH
	// (`snmp community public authorization` must not print `public`).
	parentPrefix = maskSecretPathComponents15942(parentPrefix)
	var b strings.Builder
	diffNodes(&b, fingerprintMatches15942(oldMatches, parentPrefix), fingerprintMatches15942(newMatches, parentPrefix), parentPrefix)
	return maskCompareFingerprints(b.String())
}

// scopedMatches15942 navigates path on tree (unredacted) and reports the
// matches plus the consumed width, mirroring FormatCompareAtPath.
func scopedMatches15942(t *ConfigTree, path []string) ([]*Node, int) {
	if t == nil {
		return nil, 0
	}
	return navigatePathWidth(t.Children, path)
}

// fingerprintMatches15942 fingerprint-redacts clones of matched nodes.
// base is the parent prefix the matches sit under, so secretIndices /
// urlLeafIndices see the same flattened path the whole-tree walk saw.
func fingerprintMatches15942(matches []*Node, base []string) []*Node {
	if len(matches) == 0 {
		return nil
	}
	out := make([]*Node, len(matches))
	for i, m := range matches {
		out[i] = cloneNodes([]*Node{m})[0]
	}
	fingerprintCompareNodes(out, append([]string(nil), base...))
	return out
}

// FormatPathRedacted renders the subtree at path with secrets masked
// (#15942 H2-03) — the navigate-then-redact order: the path is navigated
// on the UNREDACTED tree and cloned matches are masked before rendering,
// so a path naming a masked identity token (`snmp community <name>`)
// finds its subtree where redact-then-navigate matched nothing.
func (t *ConfigTree) FormatPathRedacted(path []string) string {
	matches, _ := t.redactedScopedMatches(path)
	if matches == nil {
		return ""
	}
	var b strings.Builder
	for _, n := range matches {
		renderScopedHierarchical15942(&b, n)
	}
	return b.String()
}

// FormatPathSetRedacted is FormatPathRedacted in `display set` form.
func (t *ConfigTree) FormatPathSetRedacted(path []string) string {
	matches, width := t.redactedScopedMatches(path)
	if matches == nil {
		return ""
	}
	if len(path) == 0 {
		return (&ConfigTree{Children: matches}).FormatSet()
	}
	// FormatPathSet renders from path prefixes reconstructed from the
	// caller's tokens. Feed it an ephemeral parent chain whose matched
	// terminal nodes are the already-masked clones; joining the set lines
	// with the original prefix restores the exact requested spelling.
	// The set-line prefix is output, not navigation: mask any secret
	// identity component it names (see FormatCompareRedactedAtPath).
	parentPrefix := maskSecretPathComponents15942(append([]string(nil), path[:len(path)-width]...))
	var b strings.Builder
	for _, n := range matches {
		prefix, prefixQuote, prefixGroup := appendNodeKeysGrouped(parentPrefix, nil, nil, n)
		if n.IsLeaf {
			fmt.Fprintf(&b, "set %s\n", joinKeysProvGrouped(prefix, prefixQuote, prefixGroup))
		} else {
			if len(n.Children) == 0 {
				fmt.Fprintf(&b, "set %s\n", joinKeysProvGrouped(prefix, prefixQuote, prefixGroup))
			}
			formatSetNodes(&b, n.Children, prefix, prefixQuote, prefixGroup)
		}
		if n.Annotation != "" {
			fmt.Fprintf(&b, "annotate %s %s\n", joinKeysProvGrouped(prefix, prefixQuote, prefixGroup), EscapedAnnotation(n.Annotation))
		}
		if n.Inactive {
			fmt.Fprintf(&b, "deactivate %s\n", joinKeysProvGrouped(prefix, prefixQuote, prefixGroup))
		}
	}
	return b.String()
}

// FormatPathJSONRedacted is FormatPathRedacted in JSON form.
func (t *ConfigTree) FormatPathJSONRedacted(path []string) string {
	matches, width := t.redactedScopedMatches(path)
	if matches == nil {
		return ""
	}
	parentPath := ""
	if len(path) > 0 {
		parentPath = strings.Join(maskSecretPathComponents15942(append([]string(nil), path[:len(path)-width]...)), " ")
	}
	data, err := marshalScopedJSON15942(matches, parentPath)
	if err != nil {
		return "{}"
	}
	return data
}

// FormatPathXMLRedacted is FormatPathRedacted in XML form.
func (t *ConfigTree) FormatPathXMLRedacted(path []string) string {
	matches, _ := t.redactedScopedMatches(path)
	if matches == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString("<configuration>\n")
	formatXMLNodes(&b, matches, 1)
	b.WriteString("</configuration>\n")
	return b.String()
}

// FormatPathInheritanceRedactedForNode is FormatPathRedacted with
// apply-groups inheritance annotations for nodeID. Inheritance expansion
// returns a fresh expanded tree, so it can use the same order: navigate
// the expanded tree by the original path, clone the matches, and mask
// only those matches before rendering with inheritance annotations.
func (t *ConfigTree) FormatPathInheritanceRedactedForNode(path []string, nodeID int) (string, error) {
	if t == nil {
		return "", nil
	}
	if len(path) == 0 {
		return t.RedactedClone().FormatPathInheritanceForNode(path, nodeID)
	}
	expanded, err := t.expandForInheritance(nodeID)
	if err != nil {
		return "", err
	}
	matches, width := navigatePathWidth(expanded.Children, path)
	if len(matches) == 0 {
		return "", nil
	}
	clones := cloneNodes(matches)
	// Mask with the true ancestor prefix the matches sit under, exactly
	// as redactedScopedMatches does: context-gated predicates
	// (snmp>community, authentication/md5>key, archive-sites>password,
	// gated URL leaves) test ancestors at/above the matched node, so a
	// nil base silently unmasked them (#15979). Tokens beyond the
	// consumed width live in the clones' Keys, not in base, and
	// redactMatches15942 only masks idx >= len(base), so the caller's
	// navigation spelling is preserved.
	parentPrefix := append([]string(nil), path[:len(path)-width]...)
	redactMatches15942(clones, parentPrefix)
	var b strings.Builder
	for _, n := range clones {
		if n.Annotation != "" {
			fmt.Fprintf(&b, "/* %s */\n", n.Annotation)
		}
		if n.IsLeaf {
			fmt.Fprintf(&b, "%s%s;\n", inactivePrefix(n), n.QuotedKeyPath())
		} else {
			fmt.Fprintf(&b, "%s%s {\n", inactivePrefix(n), n.QuotedKeyPath())
			formatNodesInheritance(&b, n.Children, 1)
			fmt.Fprintf(&b, "}\n")
		}
	}
	return b.String(), nil
}

func renderScopedHierarchical15942(b *strings.Builder, n *Node) {
	if n.Annotation != "" {
		fmt.Fprintf(b, "/* %s */\n", n.Annotation)
	}
	if n.IsLeaf {
		fmt.Fprintf(b, "%s%s;\n", inactivePrefix(n), n.QuotedKeyPath())
		return
	}
	fmt.Fprintf(b, "%s%s {\n", inactivePrefix(n), n.QuotedKeyPath())
	formatNodes(b, n.Children, 1)
	fmt.Fprintf(b, "}\n")
}

func marshalScopedJSON15942(matches []*Node, parentPath string) (string, error) {
	obj := nodesToJSONAt(matches, parentPath)
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

func (t *ConfigTree) redactedScopedMatches(path []string) ([]*Node, int) {
	if t == nil {
		return nil, 0
	}
	if len(path) == 0 {
		c := t.RedactedClone()
		if c == nil {
			return nil, 0
		}
		return c.Children, 0
	}
	matches, width := navigatePathWidth(t.Children, path)
	if len(matches) == 0 {
		return nil, width
	}
	clones := cloneNodes(matches)
	parentPrefix := append([]string(nil), path[:len(path)-width]...)
	redactMatches15942(clones, parentPrefix)
	return clones, width
}

// redactMatches15942 masks secret/URL tokens inside matched nodes with
// SecretDataPlaceholder, mirroring redactNodes but rooted at base (the
// parent prefix the matches sit under) instead of the tree root.
// Tokens at or above base (idx < len(base)) belong to ancestor nodes
// outside the match and keep their authored spelling — that is what
// leaves the caller's navigation path intact on the clone.
// maskSecretPathComponents15942 returns path with every token that is
// a secret identity at its position replaced by SecretDataPlaceholder.
// The judgement reuses secretIndices/urlLeafIndices on the path itself,
// so this masks exactly the tokens the tree redactor would mask at
// that flattened position (`public` in `snmp community public …`, a
// credential-bearing archive-sites URL) and nothing else.
func maskSecretPathComponents15942(path []string) []string {
	if len(path) == 0 {
		return path
	}
	out := append([]string(nil), path...)
	for _, idx := range secretIndices(out) {
		if idx >= 0 && idx < len(out) {
			out[idx] = SecretDataPlaceholder
		}
	}
	for _, idx := range urlLeafIndices(out) {
		if idx >= 0 && idx < len(out) {
			out[idx] = RedactURL(out[idx])
		}
	}
	return out
}

func redactMatches15942(matches []*Node, base []string) {
	for _, n := range matches {
		full := append(append([]string(nil), base...), n.Keys...)
		for _, idx := range secretIndices(full) {
			if idx >= len(base) && idx < len(full) {
				n.Keys[idx-len(base)] = SecretDataPlaceholder
			}
		}
		for _, idx := range urlLeafIndices(full) {
			if idx >= len(base) && idx < len(full) {
				n.Keys[idx-len(base)] = RedactURL(n.Keys[idx-len(base)])
			}
		}
		redactEmbeddedCommands14413(n, full, base)
		if !n.IsLeaf {
			redactMatches15942(n.Children, full)
		}
	}
}

func fingerprintRedactedClone(t *ConfigTree) *ConfigTree {
	if t == nil {
		return nil
	}
	c := t.Clone()
	fingerprintCompareNodes(c.Children, nil)
	return c
}

func fingerprintCompareNodes(nodes []*Node, base []string) {
	for _, n := range nodes {
		full := append(append([]string(nil), base...), n.Keys...)
		// Dedupe by path index, never value bytes: quoted strings may contain NUL.
		secretIdxs := secretIndices(full)
		urlIdxs := urlLeafIndices(full)
		var seen map[int]struct{}
		if len(secretIdxs)+len(urlIdxs) > 0 {
			seen = make(map[int]struct{}, len(secretIdxs)+len(urlIdxs))
		}
		for _, idx := range secretIdxs {
			if idx < len(base) || idx >= len(full) {
				continue
			}
			if _, ok := seen[idx]; ok {
				continue
			}
			seen[idx] = struct{}{}
			valueIndex := idx - len(base)
			n.Keys[valueIndex] = SecretDataPlaceholder + compareFingerprintSuffix(n.Keys[valueIndex])
		}
		for _, idx := range urlIdxs {
			if idx < len(base) || idx >= len(full) {
				continue
			}
			if _, ok := seen[idx]; ok {
				continue
			}
			seen[idx] = struct{}{}
			valueIndex := idx - len(base)
			value := n.Keys[valueIndex]
			redacted := RedactURL(value)
			if redacted != value {
				n.Keys[valueIndex] = redacted + compareURLFingerprintSuffix(value)
			}
		}
		fingerprintEmbeddedCommands14413(n, full, base)
		if !n.IsLeaf {
			fingerprintCompareNodes(n.Children, full)
		}
	}
}

// RedactEmbeddedChangeConfigCommand masks credential values inside one
// `event-options … then change-configuration commands` payload for DISPLAY
// (#14413, fail-closed #16726). The stored command is never mutated by
// callers: the event engine executes the raw text, so this is a render-time
// transform shared by RedactedClone, `show event-options` (gRPC and CLI),
// FormatCompareRedacted, and the event-engine journal warnings.
//
// Fail closed (#16726): the redactor must cover what the store holds, not
// only what classifyPlan would run. Any verb (any case), or no verb at all,
// is judged by the SAME secretIndices/urlLeafIndices sets the AST redactor
// uses — no second list — so `pre-shared-key`, gated
// `password`/`key`/`community`, URL userinfo and every other existing leaf
// keep their exact semantics inside a command, and the value token(s) after
// a secret keyword are masked regardless of the leading verb. When the
// command does not lex cleanly end-to-end, the lenient lexer's prefix is
// judged; if it marks nothing, the credential may sit in the dropped tail,
// so the whole payload is replaced by SecretDataPlaceholder. A nonempty
// payload that lexes to zero tokens (for example, a comment-only command) is
// also replaced whole. Only an actually empty or whitespace-only command is
// returned unchanged.
// Masked tokens are replaced by SecretDataPlaceholder; tokens are re-joined
// with quoteKey so a multi-word value stays one re-parseable token.
func RedactEmbeddedChangeConfigCommand(cmd string) string {
	redacted, _ := redactEmbeddedCommand(cmd, false)
	return redacted
}

// redactEmbeddedCommand is RedactEmbeddedChangeConfigCommand plus the
// compare-fingerprint variant: a masked secret token gets the same
// \x00xpf-sha256= suffix fingerprintCompareNodes appends, so FormatCompare
// preserves secret-equality without leaking the value.
//
// Lexing: the lenient lexer's PREFIX tokens are judged even when the line
// does not lex cleanly end-to-end. If the prefix already marks a secret/URL
// token (an unbalanced quote AFTER the credential, a `@` truncating a
// credential URL — `@` is not an identifier char, so every bare URL lexes
// as a prefix), that token is masked and the command renders from the
// masked prefix: the raw credential tail is never re-joined. Only when the
// prefix marks NOTHING and the payload is nonempty — either because the line
// does not lex cleanly and the credential may sit in the dropped tail
// (`… ascii-text "<secret>`), or because the lexer discarded a comment-only
// command — is the whole payload replaced (fingerprinted as one unit in
// compare mode, so two different unjudgeable credentials still diff as
// changed). Empty and whitespace-only commands alone stay unchanged.
func redactEmbeddedCommand(cmd string, fingerprint bool) (string, bool) {
	tokens, quoted, lexOK, comments := lexConfigMutationLineStrict15167WithComments(cmd)
	if len(tokens) == 0 {
		if strings.TrimSpace(cmd) == "" {
			return cmd, false
		}
		return wholePayloadMask16726(cmd, fingerprint)
	}
	// The outer config lexer unwraps a quoted commands value as one opaque
	// token. If its contents start with a comment, lex those contents as an
	// embedded command too; otherwise a quoted `"# set ..."` looks like one
	// harmless token and its credential survives.
	if len(tokens) == 1 && quoted[0] {
		inner := strings.TrimSpace(tokens[0])
		if strings.HasPrefix(inner, "#") || strings.HasPrefix(inner, "/*") ||
			strings.HasPrefix(inner, "//") {
			return redactEmbeddedCommand(tokens[0], fingerprint)
		}
	}
	changed := redactEmbeddedTokens(tokens, fingerprint)
	if !lexOK && !changed {
		return wholePayloadMask16726(cmd, fingerprint)
	}
	parts := make([]string, len(tokens))
	for i, tok := range tokens {
		parts[i] = quoteKey(tok)
	}
	rendered := strings.Join(parts, " ")
	return rendered, changed || (comments && rendered != cmd)
}

func wholePayloadMask16726(cmd string, fingerprint bool) (string, bool) {
	if fingerprint {
		return SecretDataPlaceholder + compareFingerprintSuffix(cmd), true
	}
	return SecretDataPlaceholder, true
}

// redactEmbeddedTokens masks secret/URL token indices in one lexed embedded
// command in place (#16726). There is no verb gate: a `delete`, a mis-cased
// `Set`/`SET`, or any other verb can carry a credential value token in the
// stored text (the store holds it whether or not classifyPlan would run
// it), so every token is judged. The leading verb token itself (index 0) is
// never masked — secretIndices/urlLeafIndices never mark it for a real
// command, and a bare secret keyword with no following value masks nothing.
// Returns whether any token changed.
func redactEmbeddedTokens(tokens []string, fingerprint bool) bool {
	if len(tokens) == 0 {
		return false
	}
	judged := embeddedJudgedTokens16726(tokens)
	idxs := make(map[int]bool)
	for _, idx := range secretIndices(judged) {
		idxs[idx] = true
	}
	urls := make(map[int]bool)
	for _, idx := range urlLeafIndices(judged) {
		if !idxs[idx] {
			urls[idx] = true
		}
	}
	// A secret keyword in the FINAL position has no following value token
	// (its credential is a child in the hierarchical shape); secretIndices
	// only reports following indices, so nothing is masked — matching the
	// AST walk, which masks nothing there either.
	changed := false
	for idx := range idxs {
		if idx < 0 || idx >= len(tokens) {
			continue
		}
		if fingerprint {
			tokens[idx] = SecretDataPlaceholder + compareFingerprintSuffix(tokens[idx])
		} else {
			tokens[idx] = SecretDataPlaceholder
		}
		changed = true
	}
	for idx := range urls {
		if idx < 0 || idx >= len(tokens) {
			continue
		}
		redacted := RedactURL(tokens[idx])
		if redacted == tokens[idx] {
			continue
		}
		if fingerprint {
			tokens[idx] = redacted + compareURLFingerprintSuffix(tokens[idx])
		} else {
			tokens[idx] = redacted
		}
		changed = true
	}
	return changed
}

// embeddedJudgedTokens16726 returns the token slice secretIndices /
// urlLeafIndices must judge for an embedded command (#16726):
//
//   - A command whose first token IS a secret keyword (`pre-shared-key
//     ascii-text <v>`, no verb at all) is judged as-is: prepending a verb
//     would shift the keyword off its value.
//   - Otherwise the first token is a verb slot: an exact `set` is judged
//     as-is (isADUserPasswordLeaf15996 skips it), and any other verb is
//     rewritten to `set` in a COPY so that gate aligns for delete/Set/any
//     verb. The rendered tokens keep the authored verb.
//   - A single-token command has no verb+path structure; judged as-is.
func embeddedJudgedTokens16726(tokens []string) []string {
	if len(tokens) < 2 || tokens[0] == "set" || isSecretKeywordToken16726(tokens[0]) {
		return tokens
	}
	judged := append([]string(nil), tokens...)
	judged[0] = "set"
	return judged
}

// isSecretKeywordToken16726 reports whether k is a token secretIndices /
// urlLeafIndices can mark values after (distinctive or gated), so a command
// STARTING with it carries its credential without any verb.
func isSecretKeywordToken16726(k string) bool {
	switch k {
	case "pre-shared-key", "authentication-key", "additional-authentication-key",
		"authentication-password", "privacy-password", "encrypted-password",
		"simple-password", "api-key", "tsig-secret", "plain-text-password",
		"plain-text-password-value", "api-token", "aws-secret-key",
		"private-key", "preshared-key", "client-secret", "shared-secret",
		"radius-shared-secret", "user-password", "password", "secret",
		"key", "community", "url", "url-template", "checkip-url",
		"server", "update-server", "target", "path", "hostname",
		"endpoint", "archive-sites":
		return true
	}
	return false
}

// redactEmbeddedCommands14413 applies embedded-command redaction to the
// `commands` payload carried by node n (full = base + n.Keys) on a redaction
// CLONE. Shapes (compiler_services.go eventChangeConfigCommands):
//   - `commands "<one command>"` / `commands [ "a" "b" ]`: every Keys token
//     after `commands` is one command (quoted) — rewrite each in place.
//   - `commands set … <bare words>`: one unquoted command — judged as the
//     joined tail, then re-split only if a secret was masked (a no-secret
//     tail is left byte-identical so ordinary commands never churn).
//   - `commands { "a"; set …; }`: each child carries one command in its Keys
//     (eventMultiWordLeafValues grouping) — recurse with full as base.
//
// KeysQuoted provenance, when present, decides quoted-vs-joined exactly as
// the compiler reader does; without it the token text decides (a token
// containing a space must have been quoted).
func redactEmbeddedCommands14413(n *Node, full, base []string) {
	ci := -1
	for i := 0; i+1 < len(full); i++ {
		if full[i] == "change-configuration" && full[i+1] == "commands" {
			ci = i
			break
		}
	}
	if ci < 0 {
		return
	}
	// The `commands` keyword must belong to THIS node, not an ancestor: an
	// ancestor-owned payload is handled when that ancestor is visited.
	if ci+1 < len(base) {
		return
	}
	local := ci + 1 - len(base) // index of "commands" within n.Keys
	if local < 0 || local >= len(n.Keys) {
		return
	}
	tailStart := local + 1
	if len(n.Children) > 0 {
		for _, child := range n.Children {
			redactEmbeddedChild14413(child)
		}
		return
	}
	if tailStart >= len(n.Keys) {
		return
	}
	tail := n.Keys[tailStart:]
	hasProv := n.KeysHaveQuoteProvenance()
	quoted := func(j int) bool {
		if hasProv {
			return n.KeyQuoted(tailStart + j)
		}
		return tail[j] == "" || strings.Contains(tail[j], " ")
	}
	if quoted(0) {
		for j := range tail {
			if redacted, changed := redactEmbeddedCommand(tail[j], false); changed {
				n.Keys[tailStart+j] = redacted
			}
		}
		return
	}
	redactJoinedTail14413(n, tailStart)
}

// redactEmbeddedChild14413 handles one child of a `commands { … }` block (or
// a flat-set bracket child): quoted first token means each Keys token is a
// separate command; otherwise the Keys join into one command.
func redactEmbeddedChild14413(child *Node) {
	if len(child.Keys) == 0 {
		return
	}
	hasProv := child.KeysHaveQuoteProvenance()
	quotedFirst := (hasProv && child.KeyQuoted(0)) || (!hasProv &&
		(child.Keys[0] == "" || strings.Contains(child.Keys[0], " ")))
	if quotedFirst {
		for j := range child.Keys {
			if redacted, changed := redactEmbeddedCommand(child.Keys[j], false); changed {
				child.Keys[j] = redacted
			}
		}
		return
	}
	joined := strings.Join(child.Keys, " ")
	if redacted, changed := redactEmbeddedCommand(joined, false); changed {
		applyRedactedJoin14413(child, redacted)
	}
}

// redactJoinedTail14413 judges the joined unquoted tail of `commands set …`
// and, only when a secret is masked, rewrites the node's tail to the
// redacted tokenization. A clean tail is untouched.
func redactJoinedTail14413(n *Node, tailStart int) {
	joined := strings.Join(n.Keys[tailStart:], " ")
	redacted, changed := redactEmbeddedCommand(joined, false)
	if !changed {
		return
	}
	tokens, _ := lexConfigMutationLine9938(redacted)
	if len(tokens) == 0 {
		// Whole-payload masks begin with `#`, so the config lexer treats the
		// placeholder itself as a comment. Preserve it as one AST key rather
		// than dropping the replacement with the empty token list.
		n.Keys = append(n.Keys[:tailStart], redacted)
		n.KeysQuoted = nil
		n.KeysBracketed = nil
		return
	}
	keys := make([]string, 0, tailStart+len(tokens))
	keys = append(keys, n.Keys[:tailStart]...)
	keys = append(keys, tokens...)
	n.Keys = keys
	if len(n.KeysQuoted) == len(n.Keys) {
		// Stale provenance no longer describes the rewritten keys; drop it
		// rather than claim quotes that were never authored.
		n.KeysQuoted = nil
	}
	if len(n.KeysBracketed) == len(n.Keys) {
		n.KeysBracketed = nil
	}
}

// applyRedactedJoin14413 rewrites a block child's Keys to the redacted
// tokenization of its joined command.
func applyRedactedJoin14413(child *Node, redacted string) {
	tokens, _ := lexConfigMutationLine9938(redacted)
	if len(tokens) == 0 {
		child.Keys = []string{redacted}
		child.KeysQuoted = nil
		child.KeysBracketed = nil
		return
	}
	child.Keys = tokens
	child.KeysQuoted = nil
	child.KeysBracketed = nil
}

// fingerprintEmbeddedCommands14413 is redactEmbeddedCommands14413 with
// compare fingerprints: masked secret/URL tokens carry the \x00xpf-sha256=
// suffix maskCompareFingerprints already strips into a metadata line, so a
// changed embedded credential still diffs as changed (and an unchanged one
// as unchanged) without the value ever rendering.
func fingerprintEmbeddedCommands14413(n *Node, full, base []string) {
	ci := -1
	for i := 0; i+1 < len(full); i++ {
		if full[i] == "change-configuration" && full[i+1] == "commands" {
			ci = i
			break
		}
	}
	if ci < 0 || ci+1 < len(base) {
		return
	}
	local := ci + 1 - len(base)
	if local < 0 || local >= len(n.Keys) {
		return
	}
	tailStart := local + 1
	if len(n.Children) > 0 {
		for _, child := range n.Children {
			fingerprintEmbeddedChild14413(child)
		}
		return
	}
	if tailStart >= len(n.Keys) {
		return
	}
	tail := n.Keys[tailStart:]
	hasProv := n.KeysHaveQuoteProvenance()
	quotedFirst := (hasProv && n.KeyQuoted(tailStart)) || (!hasProv &&
		(tail[0] == "" || strings.Contains(tail[0], " ")))
	if quotedFirst {
		for j := range tail {
			if redacted, changed := redactEmbeddedCommand(tail[j], true); changed {
				n.Keys[tailStart+j] = redacted
			}
		}
		return
	}
	joined := strings.Join(tail, " ")
	if redacted, changed := redactEmbeddedCommand(joined, true); changed {
		tokens, _ := lexConfigMutationLine9938(redacted)
		if len(tokens) == 0 {
			// See redactJoinedTail14413: whole-payload masks lex as comments,
			// but still need to replace the stored joined tail.
			n.Keys = append(n.Keys[:tailStart], redacted)
			n.KeysQuoted = nil
			n.KeysBracketed = nil
			return
		}
		keys := make([]string, 0, tailStart+len(tokens))
		keys = append(keys, n.Keys[:tailStart]...)
		keys = append(keys, tokens...)
		n.Keys = keys
		n.KeysQuoted = nil
		n.KeysBracketed = nil
	}
}

func fingerprintEmbeddedChild14413(child *Node) {
	if len(child.Keys) == 0 {
		return
	}
	hasProv := child.KeysHaveQuoteProvenance()
	quotedFirst := (hasProv && child.KeyQuoted(0)) || (!hasProv &&
		(child.Keys[0] == "" || strings.Contains(child.Keys[0], " ")))
	if quotedFirst {
		for j := range child.Keys {
			if redacted, changed := redactEmbeddedCommand(child.Keys[j], true); changed {
				child.Keys[j] = redacted
			}
		}
		return
	}
	joined := strings.Join(child.Keys, " ")
	if redacted, changed := redactEmbeddedCommand(joined, true); changed {
		applyRedactedJoin14413(child, redacted)
	}
}

const compareFingerprintMarker = "\x00xpf-sha256="

func compareFingerprintSuffix(value string) string {
	fingerprint := sha256.Sum256([]byte(value))
	return compareFingerprintMarker + hex.EncodeToString(fingerprint[:4]) + "\x00"
}

func compareURLFingerprintSuffix(value string) string {
	authStart := urlAuthorityStart(value)
	authEnd := len(value)
	for i := authStart; i < len(value); i++ {
		if value[i] == '/' || value[i] == '?' || value[i] == '#' {
			authEnd = i
			break
		}
	}
	authority := value[authStart:authEnd]
	var material strings.Builder
	at := strings.LastIndex(authority, "@")
	host := authority
	if at >= 0 {
		host = authority[at+1:]
	}
	if !urlHostPortPlausible(host) {
		material.WriteString(authority)
	} else if at >= 0 {
		material.WriteString(authority[:at])
	}
	if query := strings.IndexByte(value, '?'); query >= 0 {
		if material.Len() > 0 {
			material.WriteByte('\x00')
		}
		material.WriteString(value[query:])
	} else if fragment := strings.IndexByte(value, '#'); fragment >= 0 {
		if material.Len() > 0 {
			material.WriteByte('\x00')
		}
		material.WriteString(value[fragment:])
	}
	fingerprint := sha256.Sum256([]byte(material.String()))
	return compareFingerprintMarker + hex.EncodeToString(fingerprint[:4]) + "\x00"
}

func maskCompareFingerprints(diff string) string {
	var out strings.Builder
	for _, line := range strings.SplitAfter(diff, "\n") {
		maskedLine := line
		var fingerprints []string
		for {
			start := strings.Index(maskedLine, compareFingerprintMarker)
			if start < 0 {
				break
			}
			hashStart := start + len(compareFingerprintMarker)
			hashEnd := hashStart + 8
			if hashEnd >= len(maskedLine) || maskedLine[hashEnd] != '\x00' {
				break
			}
			fingerprints = append(fingerprints, maskedLine[hashStart:hashEnd])
			maskedLine = maskedLine[:start] + maskedLine[hashEnd+1:]
		}
		out.WriteString(maskedLine)
		if len(fingerprints) == 0 {
			continue
		}
		action := ""
		if strings.HasPrefix(line, "-") {
			action = "removed"
		} else if strings.HasPrefix(line, "+") {
			action = "added"
		}
		if action == "" {
			continue
		}
		for _, fingerprint := range fingerprints {
			fmt.Fprintf(&out, "    [secret fingerprint %s: %s]\n", action, fingerprint)
		}
	}
	return out.String()
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
		redactEmbeddedCommands14413(n, full, base)
		if !n.IsLeaf {
			redactNodes(n.Children, full)
		}
	}
}

// secretIndices returns the indices into the flattened key path fp that carry
// a secret value and must be masked. It reuses #2053's secret-leaf signatures
// (see the file header) and adds the unmodeled AD/LDAP bind-password contexts
// from #10948. Generic keywords (key, community) are disambiguated by
// required ancestor context so a GRE tunnel `key`, a chassis identity `key` or
// a routing-policy `community` (all non-secret) are never masked.
//
// #16731 fail-closed arm: credential-SHAPED keywords mask in any context.
// The closed enumeration kept missing unmodelled Junos credential leaves
// (default-chap-secret, local-password, auth-token, community-name,
// dhcp/dhcp-relay `authentication password`, outbound-ssh `secret`) that
// commit clean on open-world/inert paths and are live credentials on
// external systems. Shape, not ancestor enumeration, is the fix: a keyword
// containing `secret`/`password`, or exactly `auth-token`/`community-name`,
// has no non-secret valued use in the Junos grammar xpf accepts. Three
// exact-name exemptions keep non-credentials legible: bare `secret` (a
// generic token, gated below to api-auth/AAA/outbound-ssh), and the
// value-less spellings `master-password` (closed container),
// `no-password-authentication` / `no-passwords` (flags) — masking their
// trailing tokens would hide the PRF name / sibling statements packed on
// the same flattened path. Valued `*-key` is NOT shape-masked:
// `trusted-key`/`tsig-key`/`aws-access-key` are public identifiers.
func isCredentialShapedKeyword16731(k string) bool {
	switch k {
	case "auth-token", "community-name":
		return true
	case "secret", "master-password", "no-password-authentication", "no-passwords", "user-password":
		// user-password (#15996) is structurally gated below: it is also a
		// legal login user NAME, so shape-masking would hide the account
		// identity in `system login user user-password class …`.
		return false
	}
	return strings.Contains(k, "secret") || strings.Contains(k, "password")
}

func secretIndices(fp []string) []int {
	var out []int
	for i, k := range fp {
		// #16731: fail closed on credential-shaped keywords in any context.
		// Checked before the switch so gated keywords (password, secret via
		// outbound-ssh, user-password) cannot fall through unmasked when
		// their ancestor gate misses an unmodelled subtree.
		if isCredentialShapedKeyword16731(k) {
			for j := i + 1; j < len(fp); j++ {
				out = append(out, j)
			}
			continue
		}
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
			"plain-text-password", "plain-text-password-value",
			"api-token", "aws-secret-key", "private-key", "preshared-key",
			"client-secret", "shared-secret", "radius-shared-secret":
			// Distinctive secret keywords: every token after the keyword is
			// secret value (covers multi-token / bracketed list values too).
			// client-secret/shared-secret are the JIMS (Juniper Identity
			// Management Service) credentials under user-identification
			// (#15655 V15-04); they are credential-shaped names with no
			// non-secret Junos use.
			for j := i + 1; j < len(fp); j++ {
				out = append(out, j)
			}
		case "user-password":
			// AD bind credential (#15996, #16850) — STRUCTURALLY GATED, not
			// distinctive: `user-password` is also a legal login USER NAME
			// (`system login user user-password class …`), where every token
			// after it is the account's class/full-name, not a credential.
			// An ancestor scan is not enough either: a config GROUP named
			// `active-directory-access`/`user-identification` (apply-groups
			// bodies flatten to `groups <name> system login user
			// user-password …`) would put those tokens earlier in the path
			// and mask the login identity. The leaf is secret only beneath
			// the structural root chain rooted at services/security
			// (optionally under one groups <name> prefix) through
			// active-directory-access; beneath that stanza it may sit at
			// any depth (#16850: `domain <D>`, packed `domain-name <D>`,
			// hierarchical `domain D { … }`, the optional `user-name <name>`
			// pair, and any other sibling/instance layers Junos AD
			// profiles carry). The stanza is unmodelled (no schema leaf by
			// that name), so the schema-pinned secretLeafKeywords set
			// cannot name it and the fix must live AST-side only —
			// control-char/schema diagnostics resolve through
			// secretIndices and pick it up from here.
			if isADUserPasswordLeaf15996(fp, i) {
				for j := i + 1; j < len(fp); j++ {
					out = append(out, j)
				}
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
			// the compiler also accepts. #15943 (H15-01): the Junos
			// sub-stanzas `authentication-source` and `device-information`
			// are likewise identity contexts in their own right — a bind
			// `password` directly under `services authentication-source` /
			// `device-information` (or the `security` spellings below)
			// matched no scope and rendered in cleartext.
			if containsAnyOf(fp[:i], "api-auth", "dynamic-dns", "archive-sites", "user-identification", "access",
				"active-directory-access", "identity-management", "local-authentication-table",
				"authentication-source", "device-information") {
				for j := i + 1; j < len(fp); j++ {
					out = append(out, j)
				}
			}
		case "secret":
			// `secret` alone is NOT credential-shaped by substring alone in
			// the fail-closed sense — it is a bare generic token that could
			// be an identifier — so it stays gated: named API-key identities,
			// the AAA server stanzas (#15019), and outbound-ssh clients
			// (#16731: `system services outbound-ssh client <c> secret <s>`
			// is an unmodelled Junos leaf whose value is live on the
			// management server).
			if isAPIAuthNamedKeySecretPath(fp[:i]) || isAAASecretPath(fp[:i]) || containsAnyOf(fp[:i], "outbound-ssh") {
				for j := i + 1; j < len(fp); j++ {
					out = append(out, j)
				}
			}
		case "key":
			// `authentication md5 <key-id> key <secret>`. A GRE tunnel `key`
			// or a chassis device-map identity `key` has no such context.
			//
			// #14389: an exact-position window (md5 at i-2, authentication
			// at i-3) misses the hierarchical spelling
			// `md5 1 2 { key SECRET; }`, which flattens to
			// [..., authentication, md5, 1, 2, key, SECRET] — the compiler
			// still installs that key (id 1), so it leaked live on every
			// redacted display surface. Mask every token after `key` when
			// a consecutive ("authentication", "md5") pair appears strictly
			// before it: that pair is the context every other gated keyword
			// in this function uses (ancestry, not position), and none of
			// the non-secret `key` paths (GRE tunnel, NTP, api-auth named
			// key, chassis device-map) contains it. Masking all trailing
			// tokens, as the distinctive-secret cases above do, also covers
			// `md5 1 key { key SECRET; }`, whose outer `key` was previously
			// masked while its nested secret value leaked.
			if keyHasOSPFMD5Ancestor(fp, i) {
				for j := i + 1; j < len(fp); j++ {
					out = append(out, j)
				}
			}
		case "community":
			// SNMP v1/v2c community string is the container-identity token
			// directly under `snmp` (the whole point of the community is a
			// shared secret). A policy-options `community` is a routing object
			// under policy-options, not snmp — left unmasked.
			if i >= 1 && fp[i-1] == "snmp" && i+1 < len(fp) {
				out = append(out, i+1)
			}
		case "trap-group":
			// #16728: since #15052 the trap-group name IS the v1/v2c trap
			// community sent on the wire (pkg/snmp trapCommunityForGroup
			// returns tg.Name), so the identity token directly under
			// `snmp trap-group` is a credential exactly like the query
			// community above. Gate on the exact `snmp trap-group`
			// adjacency (allowing a `groups <name>` config-group prefix,
			// whose raw render is itself a PermView surface) so no other
			// `trap-group` spelling can arm it.
			if isSNMPTrapGroupIdentity(fp, i) && i+1 < len(fp) {
				out = append(out, i+1)
			}
		}
	}
	return out
}

// isSNMPTrapGroupIdentity reports whether fp[i] (a `trap-group` token) is
// the SNMP trap-group container whose next token is the trap community
// (#16728). Structural position — the exact `snmp trap-group` adjacency,
// optionally behind one `groups <name>` config-group prefix (with an
// optional leading `set` verb from embedded commands) — so a subtree
// merely NAMED trap-group cannot arm it.
func isSNMPTrapGroupIdentity(fp []string, i int) bool {
	if i < 1 || fp[i] != "trap-group" || fp[i-1] != "snmp" {
		return false
	}
	off := 0
	if len(fp) > 0 && fp[0] == "set" {
		off = 1
	}
	if off+1 < len(fp) && fp[off] == "groups" {
		off += 2
	}
	return i-1 == off
}

// isADUserPasswordLeaf15996 reports whether fp[i] (a `user-password` token)
// is the value leaf of the AD identity stanza (#15996, #16850). The
// structural ROOT chain is exact — never a bare ancestor scan — so any
// other subtree merely NAMED active-directory-access / user-identification
// cannot arm it, and a login user named user-password (system login
// user …) never matches. Beneath that root chain the leaf may sit at ANY
// depth: Junos AD access profiles carry `domain <D>`,
// `domain-name <D>`, the `user-name <name>` pair and other sibling or
// instance layers between active-directory-access and user-password
// (#16850 — the #15996 gate required ADA immediately before the leaf or
// the pair, so every domain-scoped spelling leaked).
//
// Accepted flattened shape (prefix = "" | "groups <name>", root =
// services|security, ADA = active-directory-access, UP = user-password
// at i):
//
//	prefix root [user-identification] ADA <any tokens> UP
//
// The groups spelling is the same stanza DEFINED inside a config group
// (`groups g1 services user-identification …`, applied via apply-groups);
// the raw groups render is itself a PermView surface, so it must mask
// too. Nothing may intervene between the prefix and root, between root
// and the optional user-identification wrapper, or between the wrapper
// and ADA — that root anchoring is what keeps a group NAMED
// active-directory-access wrapping `system login user user-password`
// (and any non-services/security root) unmasked. Everything strictly
// between ADA and UP is unconstrained.
func isADUserPasswordLeaf15996(fp []string, i int) bool {
	if i < 2 || i >= len(fp) || fp[i] != "user-password" {
		return false
	}
	// Embedded change-configuration commands are judged as lexed `set …`
	// token slices; skip the verb so the structural chain aligns.
	off := 0
	if fp[0] == "set" {
		off = 1
	}
	// Optional config-group definition prefix: groups <name>.
	if off+1 < len(fp) && fp[off] == "groups" {
		off += 2
	}
	// Root chain: (services|security) [user-identification]
	// active-directory-access, anchored at off.
	if off >= len(fp) || (fp[off] != "services" && fp[off] != "security") {
		return false
	}
	p := off + 1
	if p < len(fp) && fp[p] == "user-identification" {
		p++
	}
	if p >= len(fp) || fp[p] != "active-directory-access" {
		return false
	}
	// ADA must be strictly before the leaf; any tokens between them
	// (domain/domain-name instance, user-name pair, nested blocks
	// flattened onto the path) are the stanza's own interior.
	return p < i
}

// keyHasOSPFMD5Ancestor reports whether the flattened path fp contains a
// consecutive ("authentication", "md5") pair strictly before index i — the
// OSPF MD5 context that makes a generic `key` leaf secret (#14389). The scan
// is over fp[:i] only, never at or after the `key` token itself.
func keyHasOSPFMD5Ancestor(fp []string, i int) bool {
	for j := 0; j+1 < i; j++ {
		if fp[j] == "authentication" && fp[j+1] == "md5" {
			return true
		}
	}
	return false
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
		case "target":
			// #14379 (DR4-H7 + DR4-H7-ext): the RPM probe target carries a
			// credential-bearing URL in every spelling the compiler
			// installs (compiler_services.go `target` case): bare
			// `target <url>`, `target address <url>` (flat, block and
			// grandchild — all flatten to [..., "target", "address",
			// <url>]) and `target url <url>`. Only the last contains a
			// `url` token, so only it was redacted via the `url` case
			// above; the bare and `address` spellings rendered the
			// userinfo/query credential verbatim on every AST display
			// surface while the typed route redacted RPMTest.Target.
			//
			// Gated on an `rpm` ancestor exactly like `server` is gated
			// on `dynamic-dns`: `target` is generic (the schema declares
			// this leaf only under services rpm, but the AST can carry
			// unmodelled stanzas, and an unqualified claim would feed
			// non-URL targets elsewhere to RedactURL). Marking every
			// token after `target` is safe: the `address`/`url` keyword
			// tokens are not URLs, so RedactURL returns them unchanged,
			// and it is idempotent on the value the `url` case already
			// claimed, so `target url <url>` keeps its existing
			// redaction with no double-transform. A credential-free
			// value (`target address 10.0.0.1`, a bare IP/hostname) is a
			// RedactURL no-op and renders byte-unchanged.
			if containsAnyOf(fp[:i], "rpm") {
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
// guard rejects it on strict commits and tolerant Load / SyncApply ingress so
// the redacted export cannot masquerade as a restorable backup.
var errRedactionPlaceholderIngest = errors.New(
	"config contains the redaction placeholder " + SecretDataPlaceholder +
		" — this is a redacted export (REST show/export / gRPC ShowConfig), not a " +
		"restorable config; restore from the DR archive (request system " +
		"configuration rescue) or re-enter the secret in cleartext")

// IsRedactionPlaceholderIngestError reports whether err is the raw-AST secret
// redaction-placeholder rejection, including when wrapped by an ingress path.
func IsRedactionPlaceholderIngestError(err error) bool {
	return errors.Is(err, errRedactionPlaceholderIngest)
}

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
// schema gate (SchemaValidateWithDefinitions), so it fails strict operator
// commits and remains a hard error on tolerant Load / SyncApply ingress: the
// display-only placeholder is never a valid persisted secret.
//
// Scope is exactly RedactedClone's: the SAME secret-leaf set (secretIndices) is
// used to detect the placeholder that RedactedClone used to PRODUCE it. A
// non-secret leaf that happens to carry the literal "##SECRET-DATA##" string is
// NOT rejected — RedactedClone never masks it, so ingesting it is harmless and
// rejecting it would be an over-reach. The returned error names the offending
// config path for the operator.
//
// #15209 (A20-03): the scope includes credentials embedded in an
// `event-options … then change-configuration commands` payload. #14413 taught
// RedactedClone to mask those (via lexConfigMutationLine9938 +
// secretIndices/urlLeafIndices on the inner command), so a redacted export
// carries the placeholder / a "<redacted>" URL inside the quoted command
// string — invisible to the direct leaf checks below, which only see the
// whole command as one token. findRedactionPlaceholder/findRedactedURL
// therefore also lex each embedded command (see
// embeddedRedactionHit15209) and judge its inner tokens with the same sets.
func checkRedactionPlaceholder(t *ConfigTree) error {
	if t == nil {
		return nil
	}
	// Fold 5 (#16090): the "(at %q)" location names the stanza/leaf
	// NAME path only — never the rendered flattened path. The old form
	// embedded candidate VALUES (a preceding secret operand on the
	// same leaf, or the whole quoted change-configuration payload),
	// and every string-scrub layer kept losing to deeper escaping.
	// Names are schema vocabulary, not operator data.
	if loc := findRedactionPlaceholder(t.Children, nil); loc != "" {
		return fmt.Errorf("%w (at %s)", errRedactionPlaceholderIngest, loc)
	}
	if loc := findRedactedURL(t.Children, nil); loc != "" {
		return fmt.Errorf("%w (at %s)", errRedactedURLIngest, loc)
	}
	return nil
}

// redactedLocName renders the name-only location for a guard hit:
// the flattened path up to and including the offending leaf KEYWORD
// (plus instance names, which are identifiers, not values). For an
// embedded change-configuration hit the location is the event-policy
// stanza path without the payload token. Callers pass the flattened
// path and the index of the last token to keep.
func redactedLocName(full []string, keep int) string {
	if keep >= len(full) {
		keep = len(full) - 1
	}
	if keep < 0 {
		return ""
	}
	return strings.Join(redactSecretPath(full[:keep+1]), " ")
}

// secretLeafKeywordIndex returns the index in full of the keyword that
// opened the secret span containing value index idx: walk back from
// idx-1 while the token is itself secret-indexed as a value.
func secretLeafKeywordIndex(full []string, idx int) int {
	keep := idx - 1
	for keep > 0 {
		isVal := false
		for _, si := range secretIndices(full[:keep+1]) {
			if si == keep {
				isVal = true
				break
			}
		}
		if !isVal {
			break
		}
		keep--
	}
	if keep < 0 {
		keep = idx
	}
	return keep
}

// urlLeafKeywordIndex is the urlLeafIndices twin: the keyword is the
// token immediately before the first URL value token; walk back over
// any additional URL-indexed tokens.
func urlLeafKeywordIndex(full []string, idx int) int {
	keep := idx - 1
	for keep > 0 {
		isVal := false
		for _, ui := range urlLeafIndices(full[:keep+1]) {
			if ui == keep {
				isVal = true
				break
			}
		}
		if !isVal {
			break
		}
		keep--
	}
	if keep < 0 {
		keep = idx
	}
	return keep
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
				return redactedLocName(full, urlLeafKeywordIndex(full, idx))
			}
		}
		if hit, _ := embeddedRedactionHit15209(n, full, base); hit != "" {
			return hit
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
//
// #15209: embedded `change-configuration commands` payloads are inspected via
// embeddedRedactionHit15209, mirroring redactEmbeddedCommands14413.
func findRedactionPlaceholder(nodes []*Node, base []string) string {
	for _, n := range nodes {
		full := append(append([]string(nil), base...), n.Keys...)
		for _, idx := range secretIndices(full) {
			if idx >= len(base) && idx < len(full) && n.Keys[idx-len(base)] == SecretDataPlaceholder {
				return redactedLocName(full, secretLeafKeywordIndex(full, idx))
			}
		}
		if _, hit := embeddedRedactionHit15209(n, full, base); hit != "" {
			return hit
		}
		if !n.IsLeaf {
			if hit := findRedactionPlaceholder(n.Children, full); hit != "" {
				return hit
			}
		}
	}
	return ""
}

// embeddedRedactionHit15209 is the ingest-guard mirror of
// redactEmbeddedCommands14413 (#15209). It locates the
// `change-configuration commands` payload carried by node n (full = base +
// n.Keys), extracts every embedded command with the SAME shapes the display
// redactor handles (quoted tokens, unquoted joined tail, `commands { … }`
// block/bracket children), lexes each with lexConfigMutationLine9938, and
// judges the inner tokens with the SAME secretIndices/urlLeafIndices sets.
// It returns (urlHit, secretHit): urlHit is the flattened outer path when an
// inner URL token contains SecretRedacted, secretHit when an inner secret
// token equals SecretDataPlaceholder. There is no verb gate (#16726),
// mirroring redactEmbeddedTokens: any verb's credential placeholder is a
// hit. A non-secret inner leaf carrying the placeholder, or the placeholder
// glued inside a larger token, is NOT a hit — RedactedClone replaces whole
// tokens (or, for an unlexable command, the whole payload), so neither
// glued spelling is one it produces. The reported path is the outer
// flattened path up to and including the payload token (quoted command) or
// the whole node (unquoted joined tail / block child), naming the offending
// config path.
func embeddedRedactionHit15209(n *Node, full, base []string) (string, string) {
	ci := -1
	for i := 0; i+1 < len(full); i++ {
		if full[i] == "change-configuration" && full[i+1] == "commands" {
			ci = i
			break
		}
	}
	if ci < 0 {
		return "", ""
	}
	// The `commands` keyword must belong to THIS node, not an ancestor: an
	// ancestor-owned payload is judged when that ancestor is visited.
	if ci+1 < len(base) {
		return "", ""
	}
	local := ci + 1 - len(base) // index of "commands" within n.Keys
	if local < 0 || local >= len(n.Keys) {
		return "", ""
	}
	tailStart := local + 1
	if len(n.Children) > 0 {
		for _, child := range n.Children {
			if urlHit, secretHit := embeddedChildRedactionHit15209(child, full); urlHit != "" || secretHit != "" {
				return urlHit, secretHit
			}
		}
		return "", ""
	}
	if tailStart >= len(n.Keys) {
		return "", ""
	}
	tail := n.Keys[tailStart:]
	hasProv := n.KeysHaveQuoteProvenance()
	quoted := func(j int) bool {
		if hasProv {
			return n.KeyQuoted(tailStart + j)
		}
		return tail[j] == "" || strings.Contains(tail[j], " ")
	}
	if quoted(0) {
		for j := range tail {
			cmdPath := redactedLocName(full, len(base)+tailStart-1)
			if hit := embeddedCommandURLHit15209(tail[j], cmdPath); hit != "" {
				return hit, ""
			}
			if hit := embeddedCommandSecretHit15209(tail[j], cmdPath); hit != "" {
				return "", hit
			}
		}
		return "", ""
	}
	joined := strings.Join(tail, " ")
	nodePath := redactedLocName(full, len(base)+tailStart-1)
	if hit := embeddedCommandURLHit15209(joined, nodePath); hit != "" {
		return hit, ""
	}
	if hit := embeddedCommandSecretHit15209(joined, nodePath); hit != "" {
		return "", hit
	}
	return "", ""
}

// embeddedChildRedactionHit15209 handles one child of a `commands { … }`
// block (or a flat-set bracket child), mirroring redactEmbeddedChild14413:
// quoted first token means each Keys token is a separate command; otherwise
// the Keys join into one command. parentFull is the flattened path of the
// owning `commands` node, used to name the offending path.
func embeddedChildRedactionHit15209(child *Node, parentFull []string) (string, string) {
	if len(child.Keys) == 0 {
		return "", ""
	}
	childFull := append(append([]string(nil), parentFull...), child.Keys...)
	hasProv := child.KeysHaveQuoteProvenance()
	quotedFirst := (hasProv && child.KeyQuoted(0)) || (!hasProv &&
		(child.Keys[0] == "" || strings.Contains(child.Keys[0], " ")))
	if quotedFirst {
		for j := range child.Keys {
			cmdPath := redactedLocName(childFull, len(parentFull)-1)
			if hit := embeddedCommandURLHit15209(child.Keys[j], cmdPath); hit != "" {
				return hit, ""
			}
			if hit := embeddedCommandSecretHit15209(child.Keys[j], cmdPath); hit != "" {
				return "", hit
			}
		}
		return "", ""
	}
	joined := strings.Join(child.Keys, " ")
	nodePath := redactedLocName(childFull, len(parentFull)-1)
	if hit := embeddedCommandURLHit15209(joined, nodePath); hit != "" {
		return hit, ""
	}
	if hit := embeddedCommandSecretHit15209(joined, nodePath); hit != "" {
		return "", hit
	}
	return "", ""
}

// embeddedCommandSecretHit15209 reports path when an embedded command
// ALREADY carries SecretDataPlaceholder in a secret VALUE position
// (#15209, #16726) — i.e. it is a redacted export being re-ingested, not a
// cleartext command (whose secret value renders to the placeholder only
// AFTER redaction, so judging the render would false-positive on every
// cleartext credential). No verb gate: judged on the same verb-normalised
// copy as redactEmbeddedTokens. The bare whole-payload placeholder is a
// hit. Because the placeholder starts with `#`, an authored (unquoted-tail
// / re-lexed) occurrence truncates the command as a lexer comment: that
// truncation is a hit iff the surviving prefix ends at a secret keyword
// (plus optional qualifier). The placeholder glued inside a larger token,
// or standing as a non-secret value (host-name, GRE key, value-less
// delete), is NOT a hit — the redactor replaces whole secret tokens only.
func embeddedCommandSecretHit15209(cmd, path string) string {
	if cmd == SecretDataPlaceholder {
		return path
	}
	tokens, _, lexOK := lexConfigMutationLineStrict15167(cmd)
	if !lexOK {
		return ""
	}
	for _, idx := range secretIndices(embeddedJudgedTokens16726(tokens)) {
		if idx >= 0 && idx < len(tokens) && tokens[idx] == SecretDataPlaceholder {
			return path
		}
	}
	// The placeholder starts with `#`: inside an authored command the
	// lexer treats it (and everything after it) as a comment, so a
	// re-ingested redacted command truncates exactly at the placeholder.
	// The truncation is a hit iff the surviving prefix ends at a secret
	// keyword (optionally past its ascii-text/hexadecimal qualifier) —
	// i.e. the placeholder occupied the secret VALUE position. A
	// non-secret truncation (`… host-name ##…`) ends elsewhere and is
	// not a hit.
	if i := strings.Index(cmd, SecretDataPlaceholder); i >= 0 {
		prefix := strings.TrimSpace(cmd[:i])
		ptoks, _, _ := lexConfigMutationLineStrict15167(prefix)
		if len(ptoks) == 0 {
			return ""
		}
		judged := embeddedJudgedTokens16726(ptoks)
		probe := append(append([]string(nil), judged...), "x")
		for _, idx := range secretIndices(probe) {
			if idx == len(judged) {
				return path
			}
		}
	}
	return ""
}

// embeddedCommandURLHit15209 reports path when a urlLeafIndices token
// contains SecretRedacted (#15209, #16726): no verb gate, judged on the
// same verb-normalised copy and the lenient lexer's prefix tokens (a bare
// URL truncates at `@`, and the sentinel sits before it in every RedactURL
// output). A cleartext credential URL contains no sentinel, so it is not
// a hit — only an already-redacted export is refused.
func embeddedCommandURLHit15209(cmd, path string) string {
	tokens, _ := lexConfigMutationLine9938(cmd)
	for _, idx := range urlLeafIndices(embeddedJudgedTokens16726(tokens)) {
		if idx >= 0 && idx < len(tokens) && strings.Contains(tokens[idx], SecretRedacted) {
			return path
		}
	}
	return ""
}
