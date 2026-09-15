package configstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

const encryptedTreeFormat = "xpf-master-password-v1"

type encryptedTreeEnvelope struct {
	Format string `json:"format"`
	PRF    string `json:"prf"`
	Salt   string `json:"salt"`
	Nonce  string `json:"nonce"`
	Data   string `json:"data"`
}

func (db *DB) masterKeyPath() string {
	return filepath.Join(db.dir, "master.key")
}

// defaultMasterPasswordPRF is the supported PRF used to key at-rest encryption
// when encryption is required (a master-password is configured somewhere) but
// no SUPPORTED effective PRF can be resolved from the applied config — e.g. the
// encryption belt is triggered only by a dormant (inactive / unapplied-group)
// master-password, or the effective declaration carries an unsupported selector
// that slipped past the #4578 commit gate on a tolerant HA/upgrade path. It
// MUST be a value prfHash accepts so the persistence write never fails
// deterministically. See masterPasswordPRF (#5638 / codex-review-181 M30).
const defaultMasterPasswordPRF = "sha256"

// masterPasswordPRF resolves the master-password pseudorandom-function that
// keys at-rest encryption (maybeEncryptTreeJSON) and gates the #4579 A4-06
// plaintext-downgrade warning (db.go readTreeMeta). It answers TWO separable
// questions — conflating them caused #5638 (codex-review-181 M30):
//
//  1. IS ENCRYPTION REQUIRED?  Conservative, fail-closed. ANY master-password
//     anywhere — an active top-level `system` stanza (#4705), or any
//     `master-password` under any `groups { ... }` block including an
//     UNAPPLIED or `<*>`-wildcard group (#5231) — means "encrypt, never leak
//     plaintext." Over-encrypting a dormant/unapplied master-password is a
//     harmless false-positive; under-encrypting leaks secrets to disk. This is
//     masterPasswordConfigured.
//
//  2. WHICH PRF ALGORITHM?  Must be a SUPPORTED, DETERMINISTIC selector so the
//     write path never fails and an active↔standby pair reproduces the same
//     key. Resolve it from the EFFECTIVE/APPLIED scope only — the same
//     inactive-strip + apply-groups expansion the compiler applies
//     (effectiveMasterPasswordPRF) — and accept only a selector prfHash
//     understands. A dormant or unsupported PRF must NOT reach prfHash.
//
// Why the split matters (M30): the #4578 commit gate (ValidateMasterPasswordPRF)
// validates the EFFECTIVE tree (inactive stripped, groups expanded), so an
// UNSUPPORTED PRF hidden in an inactive node or an unapplied group is never
// rejected at commit. The old resolver's fail-closed SUPERSET, however, scanned
// every group regardless of application state and returned that unsupported
// value. On HA config-sync the standby promotes the peer tree in memory
// (Option B) and then persists it: masterPasswordPRF returned the dormant
// `bogus`, prfHash rejected it, writeActive failed, and the singleton retry
// re-selected `bogus` forever — a DETERMINISTIC, non-transient persistence
// failure that keeps the node /health-503 and its authoritative generation off
// disk (non-durable across restart). The fix keeps the encryption belt broad
// (question 1) but constrains the ALGORITHM to a supported effective value,
// falling back to defaultMasterPasswordPRF rather than poisoning the write with
// an unsupported selector. Encryption still happens; only a value prfHash
// accepts ever reaches it.
//
// The effective resolution is error-tolerant (any apply-groups expansion error
// falls through to the supported default), so the "this write path must not
// fail" contract that originally motivated NOT calling ExpandGroups here still
// holds — it runs on a clone and never propagates an error.
func masterPasswordPRF(tree *config.ConfigTree) string {
	if tree == nil {
		return ""
	}

	// Question 1: is at-rest encryption required at all? Fail-closed broad
	// scan (dormant/unapplied/wildcard included). Empty means plaintext.
	if !masterPasswordConfigured(tree) {
		return ""
	}

	// Question 2: choose a SUPPORTED, DETERMINISTIC algorithm from the
	// effective/applied scope. A dormant or unsupported effective value must
	// not reach prfHash on the persistence write path.
	if prf := effectiveMasterPasswordPRF(tree); prf != "" && prfSupported(prf) {
		return prf
	}

	// Encryption is required but the applied config resolves no supported PRF
	// (belt triggered by dormant content, or an unsupported effective value):
	// fall back to a fixed supported selector so the DB is still encrypted and
	// the write stays durable and deterministic across active↔standby.
	return defaultMasterPasswordPRF
}

// masterPasswordConfigured reports whether ANY master-password is present in
// the tree — the fail-closed "must we encrypt?" decision (#4705 split stanzas +
// #5231 groups/wildcard). It intentionally does NOT strip inactive nodes or
// require apply-groups: a master-password that exists anywhere (even dormant)
// means secrets have been or may be configured, and erring toward encryption is
// always safe. Read-only and total (nil-safe, never errors) — it runs on the
// config write path, which must not fail.
func masterPasswordConfigured(tree *config.ConfigTree) bool {
	if tree == nil {
		return false
	}
	// #9152: FOLD ADMITTED COMPACT STANZAS FIRST, exactly as
	// effectiveMasterPasswordPRF does. Without this the two questions
	// DISAGREED ABOUT THE SAME TREE:
	//
	//	                  Q1 configured   Q2 effective PRF   result
	//	braced            true            juniper-prf1       encrypted
	//	stanza elided     FALSE           juniper-prf1       PLAINTEXT
	//	fully elided      FALSE           juniper-prf1       PLAINTEXT
	//
	// masterPasswordPRFOfNode reads `pseudorandom-function` as a CHILD of
	// `master-password`, and in a packed spelling the token sits on the
	// parent's Keys instead. #8898 fixed Q2 and its comment says exactly why
	// the fold is needed; Q1 was left raw-scanning, so `masterPasswordPRF`
	// returned "" and active.json and confirm.json were written in CLEARTEXT
	// -- including IKE pre-shared keys -- on a clean commit with no warning at
	// any level, while `show configuration` rendered the stanza back.
	//
	// This is not "the wrong KDF was chosen". It is no encryption at all, and
	// the only observable is reading the raw DB file.
	//
	// The broad fail-closed scope is UNCHANGED: this folds spellings, it does
	// not strip inactive nodes or restrict to applied groups, so a dormant or
	// wildcard master-password still forces encryption. NormalizeCompactForScan
	// returns the original tree when nothing folds and never mutates its
	// argument, which callers persist.
	tree = config.NormalizeCompactForScan(tree)
	// Surface 1: every top-level `system { ... }` stanza (#4705).
	if masterPasswordPRFInSystems(systemBlocksOf(tree)) != "" {
		return true
	}
	// Surface 2: any `master-password` anywhere under any `groups { ... }`
	// block (#5231) — recursive so it catches a master-password nested under a
	// `<*>` wildcard (or any other intervening node), not only a literal
	// `system` child.
	for _, groupsRoot := range groupsBlocksOf(tree) {
		if masterPasswordPRFInSubtree(groupsRoot) != "" {
			return true
		}
	}
	return false
}

// effectiveMasterPasswordPRF resolves the master-password PRF from the
// EFFECTIVE/APPLIED config only — the value the compiler would activate — so
// the algorithm chosen for at-rest encryption matches the running config and
// never comes from a dormant (inactive / unapplied-group) subtree. It mirrors
// the compile/schema path (schemaValidateExpandedTreeForNode): strip inactive
// THEN expand applied groups, on a CLONE, then scan the resulting top-level
// `system` stanzas. Returns "" when no active master-password resolves (the
// caller then uses the supported default).
//
// This runs on the config write path, which MUST NOT fail: it operates on a
// clone (never the persisted tree) and swallows every apply-groups expansion
// error (returning ""), so a ${node}/undefined-group condition degrades to the
// default rather than failing the write.
func effectiveMasterPasswordPRF(tree *config.ConfigTree) string {
	if tree == nil {
		return ""
	}
	// issue 8898: fold admitted compact stanzas before scanning. This reader
	// walks the RAW tree, so it never sees the normalizer that runs inside the
	// compiler -- `system master-password pseudorandom-function <p>;` resolved
	// to nothing here even after the pair was admitted to the scope, and the
	// selector fell back to defaultMasterPasswordPRF while `show
	// configuration` rendered the one the operator wrote.
	//
	// Clone-safe: returns the original tree when nothing folds, and never
	// mutates the argument, which callers persist.
	tree = config.NormalizeCompactForScan(tree)
	// Fast path: with no groups to expand and no inactive nodes to strip, the
	// effective scope is exactly the raw top-level `system` stanzas. Scan
	// directly with zero extra allocation — this covers every normal active
	// config, keeping it bit-identical to the pre-#5638 resolver.
	if len(groupsBlocksOf(tree)) == 0 && !tree.HasInactiveNodes() {
		return masterPasswordPRFInSystems(systemBlocksOf(tree))
	}
	stripped := tree.WithoutInactive()
	expanded := stripped.Clone()
	if err := expanded.ExpandGroups(); err != nil {
		// A cluster ${node} group can only be expanded with the node var; the
		// write path is node-agnostic and the envelope is self-describing
		// (decrypt reads env.PRF), so a deterministic node0 substitution is
		// enough to resolve a supported selector. Any residual error degrades
		// to "" → the caller's supported default (the write must not fail).
		if strings.Contains(err.Error(), `undefined group "${node}"`) {
			vars := map[string]string{"node": "node0"}
			if err2 := expanded.ExpandGroupsWithVars(vars); err2 != nil {
				return ""
			}
		} else {
			return ""
		}
	}
	return masterPasswordPRFInSystems(systemBlocksOf(expanded))
}

// prfSupported reports whether prf is a selector prfHash can key encryption
// with. It is the single gate that keeps an unsupported PRF — one that slipped
// past the #4578 commit gate through a tolerant HA/upgrade load — off the
// deterministic persistence-retry path (#5638).
func prfSupported(prf string) bool {
	_, err := prfHash(prf)
	return err == nil
}

// masterPasswordPRFInSystems returns the first non-empty master-password
// pseudorandom-function value across the given system-shaped nodes. Used by
// the top-level (#4705) scan in masterPasswordPRF.
func masterPasswordPRFInSystems(systems []*config.Node) string {
	for _, sys := range systems {
		if prf := masterPasswordPRFOfNode(sys); prf != "" {
			return prf
		}
	}
	return ""
}

// masterPasswordPRFOfNode returns the first non-empty pseudorandom-function
// value carried by a `master-password` child of node.
func masterPasswordPRFOfNode(node *config.Node) string {
	if node == nil {
		return ""
	}
	for _, mp := range node.FindChildren("master-password") {
		prf := mp.FindChild("pseudorandom-function")
		if prf == nil {
			continue
		}
		if v := nodeValue(prf); v != "" {
			return v
		}
	}
	return ""
}

// masterPasswordPRFInSubtree recursively searches node and all its descendants
// for any `master-password { pseudorandom-function <X> }` and returns the first
// non-empty PRF value found. It is read-only and total — nil-safe and never
// errors or panics on a malformed tree — because it runs on the config write
// path, which must not fail. See masterPasswordPRF for why the groups/
// apply-groups scan (#5231) recurses instead of keying on a literal `system`
// node name.
func masterPasswordPRFInSubtree(node *config.Node) string {
	if node == nil {
		return ""
	}
	if len(node.Keys) > 0 && node.Keys[0] == "master-password" {
		if prf := node.FindChild("pseudorandom-function"); prf != nil {
			if v := nodeValue(prf); v != "" {
				return v
			}
		}
	}
	for _, child := range node.Children {
		if v := masterPasswordPRFInSubtree(child); v != "" {
			return v
		}
	}
	return ""
}

func nodeValue(n *config.Node) string {
	if n == nil {
		return ""
	}
	if len(n.Keys) >= 2 {
		return n.Keys[1]
	}
	if len(n.Children) > 0 {
		return n.Children[0].Name()
	}
	return ""
}

// aad is the AES-GCM additional authenticated data. The envelope write path
// passes the header line so the plaintext header — including the #1922
// committed= marker — is bound to the ciphertext and cannot be edited in place
// (#7176 C179-053). Callers with no header to bind (WriteConfirm) pass nil,
// which is the pre-#7176 behaviour and is correct for them: there is no
// plaintext preamble to authenticate.
func (db *DB) maybeEncryptTreeJSON(data []byte, tree *config.ConfigTree, aad []byte) ([]byte, error) {
	prf := masterPasswordPRF(tree)
	if prf == "" {
		return data, nil
	}

	keyMaterial, err := db.readOrCreateMasterKey()
	if err != nil {
		return nil, err
	}
	key, salt, err := deriveEncryptionKey(keyMaterial, prf)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	env := encryptedTreeEnvelope{
		Format: encryptedTreeFormat,
		PRF:    prf,
		Salt:   base64.StdEncoding.EncodeToString(salt),
		Nonce:  base64.StdEncoding.EncodeToString(nonce),
		Data:   base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, data, aad)),
	}
	return marshalEnvelope(env)
}

// maybeDecryptTreeJSON returns the plaintext body of a stored config.
// The second return value reports whether the input was an AES-GCM
// envelope that was actually decrypted (true) or was passed through as
// plaintext because it carried no envelope (false). Callers that know
// the config declares a master-password use the flag to detect an
// unexpected plaintext downgrade (#4579 A4-06).
// aad must be byte-identical to what the writer sealed with, or the tag check
// fails. The envelope read path supplies the stored header line ONLY when the
// stored v= is at or above envelopeAADFormatVersion; below that it passes nil,
// which is how pre-v2 envelopes stay readable. A tampered v2 header — including
// one rewritten to claim v=1 — therefore fails to decrypt rather than being
// read under the weaker rule (#7176 C179-053).
func (db *DB) maybeDecryptTreeJSON(data []byte, aad []byte) ([]byte, bool, error) {
	env, ok, err := unmarshalEnvelope(data)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return data, false, nil
	}

	keyMaterial, err := db.readMasterKey()
	if err != nil {
		return nil, false, fmt.Errorf("encrypted config but master key unavailable: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return nil, false, fmt.Errorf("decode salt: %w", err)
	}
	key, err := deriveEncryptionKeyFromSalt(keyMaterial, env.PRF, salt)
	if err != nil {
		return nil, false, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, false, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, false, fmt.Errorf("decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false, fmt.Errorf("create GCM: %w", err)
	}
	// #4793: cipher.AEAD.Open panics if len(nonce) != gcm.NonceSize()
	// instead of returning an error. A corrupt or tampered on-disk
	// envelope (bad base64 length, truncated write, hand-edited JSON)
	// would otherwise crash the daemon here on every boot — a
	// config-DB-triggered boot loop. Fail closed with a plain error so
	// the caller can report it instead of the process dying.
	if len(nonce) != gcm.NonceSize() {
		return nil, false, fmt.Errorf("invalid nonce length %d (want %d)", len(nonce), gcm.NonceSize())
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, false, fmt.Errorf("decrypt config tree: %w", err)
	}
	return plaintext, true, nil
}

func marshalEnvelope(env encryptedTreeEnvelope) ([]byte, error) {
	type alias encryptedTreeEnvelope
	return json.Marshal(alias(env))
}

func unmarshalEnvelope(data []byte) (encryptedTreeEnvelope, bool, error) {
	// #7454: decide envelope-ness by KEY PRESENCE, before the typed decode.
	//
	// The guard below fails closed on an envelope-shaped body whose
	// discriminator we do not support (#4888) — but it sits AFTER this
	// unmarshal, and this unmarshal used to swallow every error as "not the
	// envelope shape at all". That comment is true for a SYNTAX error. It is
	// not true for a *json.UnmarshalTypeError: a perfectly good JSON object,
	// with the right keys, one of them carrying the wrong JSON TYPE
	// (`"salt": 5`, `"data": null`, `"format": []`) landed in the same branch
	// and passed through as PLAINTEXT — never reaching the fail-closed test.
	//
	// Downstream, json.Unmarshal then drops the unknown fields and decodes an
	// EMPTY ConfigTree, Store.Load compiles it, and the daemon boots with NO
	// POLICY reporting success. The #4579 plaintext-downgrade warning does not
	// fire either: it keys on masterPasswordPRF(tree) != "" and the tree is
	// empty. Completely silent — and the exact outcome #4888's comment names as
	// the thing it exists to prevent, reached by the branch in front of it.
	//
	// KEY PRESENCE is used rather than discriminating the error type, because it
	// is strictly stronger and carries no over-rejection risk here: the
	// plaintext body written by writeTreeMarked is `json.MarshalIndent(tree)` of
	// a config.ConfigTree, whose ONLY top-level key is "Children". None of the
	// five envelope keys can appear in a genuine plaintext body. So any body
	// carrying one was MEANT to be an envelope, and a decode failure on it is
	// corruption, whatever its shape — a wrong type, a null, an array.
	envKeys := envelopeKeysPresent(data)

	type alias encryptedTreeEnvelope
	var env alias
	if err := json.Unmarshal(data, &env); err != nil {
		if len(envKeys) > 0 {
			return encryptedTreeEnvelope{}, false, fmt.Errorf(
				"corrupted encrypted config envelope: %w (envelope fields present: %s)",
				err, strings.Join(envKeys, ", "))
		}
		// Not JSON, or not the envelope object shape at all — a genuine
		// plaintext (pre-encryption / legacy) config body. Pass through.
		return encryptedTreeEnvelope{}, false, nil
	}
	if env.Format != encryptedTreeFormat {
		// Fail CLOSED on an envelope-shaped body whose discriminator we do not
		// support (#4888). An unknown/future `format`
		// (e.g. xpf-master-password-v2), or the AES-GCM fields
		// (salt/nonce/data) present without our current `format`, is a too-new
		// or corrupted ENCRYPTED DB — it MUST be rejected, never treated as
		// plaintext. Treating it as plaintext lets json.Unmarshal drop the
		// unknown fields and decode an EMPTY ConfigTree, so Store.Load would
		// boot a committed-empty config (loss of policy) instead of failing
		// closed with ErrConfigDBUnreadable. Only a body with NO format AND no
		// AES-GCM fields is a genuine plaintext body and passes through.
		// #8288: the discriminator is KEY PRESENCE, not a hand-listed subset of
		// the decoded fields. It used to read
		// `env.Format != "" || env.Salt != "" || env.Nonce != "" || env.Data != ""`
		// — four of the envelope's FIVE fields, omitting PRF — so a body whose
		// only envelope key was `prf` satisfied "no format AND no AES-GCM
		// fields" and took the plaintext passthrough the comment above
		// describes. `{"prf":"sha256"}` is well-formed JSON, so it also never
		// reached the #7454 key-presence guard, which is consulted only inside
		// the decode-FAILURE branch. The two guards had a gap between them and
		// this body fell through it: json.Unmarshal drops the unknown field,
		// an EMPTY ConfigTree decodes, and Store.Load boots an active firewall
		// with no security policy, reporting success. Silently — the #4579
		// plaintext-downgrade warning keys on masterPasswordPRF(tree) != "" and
		// the tree is empty.
		//
		// Deliberately NOT fixed by appending `|| env.PRF != ""`. That works,
		// but the DEFECT IS a five-field struct guarded by a hand-maintained
		// four-field list, and adding a fifth item reproduces the shape that
		// caused it. `envKeys` answers the same question #7454 already answers
		// — "was this MEANT to be an envelope" — and is derived from the body,
		// so it cannot drift out of sync with the struct.
		//
		// It is also strictly STRONGER than the field test, and safe to be:
		// `{"format":""}` carries the key with an empty value, which the field
		// test passed through and this refuses. A body that names an envelope
		// key at all was meant to be an envelope.
		//
		// Over-rejection is not a risk here, and that is a property of the
		// data rather than a hope: `config.ConfigTree` has exactly ONE field
		// (`Children []*Node`, pkg/config/ast.go) with no omitempty, so a
		// genuine plaintext body's top-level key set is always exactly
		// {"Children"} whatever it contains — verified by marshalling one, not
		// by reading. The non-object shapes envelopeKeysPresent tolerates
		// (`null`, an array, a scalar, garbage) return no keys and keep the
		// plaintext passthrough #7454's acceptance requires.
		if len(envKeys) > 0 {
			return encryptedTreeEnvelope{}, false, fmt.Errorf(
				"unsupported encrypted config envelope format %q (too-new or corrupted config DB) "+
					"(envelope fields present: %s)", env.Format, strings.Join(envKeys, ", "))
		}
		return encryptedTreeEnvelope{}, false, nil
	}
	if env.PRF == "" || env.Salt == "" || env.Nonce == "" || env.Data == "" {
		return encryptedTreeEnvelope{}, false, fmt.Errorf("invalid encrypted config envelope")
	}
	return encryptedTreeEnvelope(env), true, nil
}

// envelopeKeysPresent returns the encrypted-envelope field names present at the
// top level of a JSON object body, sorted; nil when the body is not a JSON
// object at all (#7454).
//
// It answers "was this MEANT to be an envelope", which is a different question
// from "does it decode as one" — and it is the question that matters, because a
// body that was meant to be an envelope and does not decode is corrupt, not
// plaintext. Deliberately tolerant of a body that is not an object: `null`, an
// array, a scalar or garbage keeps the existing plaintext-passthrough
// behaviour, which the acceptance criteria require unchanged.
//
// #8597 (muse-004 K69): the membership test is CASE-INSENSITIVE, because the
// decoder it guards is.
//
// encoding/json matches an incoming object key to a struct field by preferring
// an exact match but ACCEPTING a case-insensitive one. This probe used an exact
// lowercase lookup, so the guard and the decoder disagreed about what counts as
// an envelope key — and every body whose key differed only in case fell into
// the gap. Measured before the fix:
//
//	{"format": 123}      -> rejected (fail-closed)
//	{"Format": 123}      -> PASSED THROUGH AS PLAINTEXT
//	{"Format":"garbage"} -> PASSED THROUGH AS PLAINTEXT
//	{"Salt": 5}          -> PASSED THROUGH AS PLAINTEXT
//
// Downstream, json.Unmarshal drops the unknown fields, an EMPTY ConfigTree
// decodes, and Store.Load boots an active firewall with NO SECURITY POLICY
// reporting success. Silently: the #4579 plaintext-downgrade warning keys on
// masterPasswordPRF(tree) != "" and the tree is empty.
//
// This is the FOURTH member of that family. #4888 fixed the unknown-format
// passthrough, #7454 the wrong-JSON-type passthrough, #8288 the `prf`-only
// passthrough — each strengthening the discriminator, and all three reading the
// body's keys with a rule the decoder does not use. The lesson the first three
// did not reach: a guard in front of a decoder has to answer the decoder's
// question, in the decoder's terms.
//
// Over-rejection stays safe for the reason #8288 records: `config.ConfigTree`
// has exactly one field (`Children`), so a genuine plaintext body's top-level
// key set is always exactly {"Children"}, whose folded form is "children" — not
// an envelope name under any casing.
//
// The returned names are the CANONICAL lowercase spellings, so the diagnostics
// that embed them stay stable whatever case the corrupt body used.
func envelopeKeysPresent(data []byte) []string {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil
	}
	folded := make(map[string]struct{}, len(probe))
	for k := range probe {
		folded[strings.ToLower(k)] = struct{}{}
	}
	var present []string
	for _, k := range []string{"data", "format", "nonce", "prf", "salt"} {
		if _, ok := folded[k]; ok {
			present = append(present, k)
		}
	}
	return present
}

func deriveEncryptionKey(keyMaterial []byte, prf string) ([]byte, []byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("generate salt: %w", err)
	}
	key, err := deriveEncryptionKeyFromSalt(keyMaterial, prf, salt)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}

func deriveEncryptionKeyFromSalt(keyMaterial []byte, prf string, salt []byte) ([]byte, error) {
	hashFn, err := prfHash(prf)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(hashFn, keyMaterial, salt, "xpf-configstore-master-password", 32)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return key, nil
}

// prfHash maps a master-password pseudorandom-function selector name to its
// hash constructor. It is the SSOT for the name->hash.Hash mapping; the
// accepted NAMES are mirrored in config.masterPasswordPRFNames, which the
// commit-time gate (config.ValidateMasterPasswordPRF, #4578) uses to reject a
// typo'd selector BEFORE it reaches this path. Adding a case here means adding
// the name there too. Matching is case-insensitive (the commit gate mirrors
// this ToLower).
func prfHash(prf string) (func() hash.Hash, error) {
	switch strings.ToLower(prf) {
	case "juniper-prf1", "hmac-sha2-256", "sha256":
		return sha256.New, nil
	case "hmac-sha2-384", "sha384":
		return sha512.New384, nil
	case "hmac-sha2-512", "sha512":
		return sha512.New, nil
	case "hmac-sha1", "sha1":
		return sha1.New, nil
	default:
		return nil, fmt.Errorf("unsupported master-password pseudorandom-function %q", prf)
	}
}

// maxMasterKeyFileSize bounds a master-key file read (#8597). The key is
// exactly 32 bytes; the ceiling is generous enough that a legitimate file with
// a trailing newline or a future longer key still reads, and small enough that
// a corrupt or hostile file is refused before it is materialised rather than
// after.
const maxMasterKeyFileSize = 4096

// readMasterKey reads an existing master key — never creates one.
// Used by the decrypt path to avoid overwriting a lost key.
func (db *DB) readMasterKey() ([]byte, error) {
	path := db.masterKeyPath()
	// #8597 (muse-004 K70): bounded. The contract is EXACTLY 32 bytes and the
	// length is checked three lines down — but only after the whole file is
	// resident, so a huge file was fully read and then rejected. Bounding at
	// maxMasterKeyFileSize refuses it before the allocation.
	data, err := ReadBoundedFile(path, maxMasterKeyFileSize)
	if err != nil {
		return nil, fmt.Errorf("read master key: %w", err)
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("invalid master key length in %s", path)
	}
	return data, nil
}

// masterKeyLink publishes a complete temp key file at the final master-key
// path. A seam so tests can inject EEXIST/ENOENT races deterministically
// (#9898 F-111). Production code must never mutate it.
var masterKeyLink = os.Link

// syncMasterKeyFile fsyncs an adopted key file's content. A seam so tests
// can observe (and fail) the durability assist deterministically (#9898
// F-111). Production code must never mutate it.
var syncMasterKeyFile = func(f *os.File) error { return f.Sync() }

// masterKeyPublishAttempts bounds recreate retries when a concurrent NewDB
// temp sweep deletes a live key temp between CreateTemp and Link (the sweep
// matches `.*.tmp-*` unconditionally). The sweep is one-shot per NewDB, so
// recreating converges; the bound keeps a vanishing directory fail-closed
// and loud instead of looping.
const masterKeyPublishAttempts = 3

func (db *DB) readOrCreateMasterKey() ([]byte, error) {
	path := db.masterKeyPath()
	// #8597 (muse-004 K70): bounded — see readMasterKey.
	//
	// #9898 F-111: EVERY return from this function carries a DURABLE key.
	// A racing read sees absent or complete, never partial (Link publishes
	// only a fully-written, synced, closed temp), so an invalid length is
	// genuinely corrupt — but "complete" is not "durable": the entry may
	// predate its creator's dir sync (a racing winner parked between Link
	// and sync, or a previous EIO-leave). The existing file therefore goes
	// through the same durability adoption as a Link loser: without a
	// barrier here, an adopter seals ciphertext that WriteFileDurable
	// rename-publishes BEFORE any dir sync covers the key entry (the
	// rename lands at fsatomic writeFile's rename, the dir sync after it),
	// and a power cut with selective entry loss strands the ciphertext
	// with its key gone. The two syncs below cost an adopter one file
	// fsync (no-op I/O on an unchanged file) plus one dir sync (this
	// directory is synced repeatedly on the commit path anyway).
	if _, err := ReadBoundedFile(path, maxMasterKeyFileSize); err == nil {
		return adoptPublishedMasterKey(path)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read master key: %w", err)
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}

	// Atomic publish (#9898 F-111): the base check-then-act (read miss ->
	// generate -> temp+rename) let racing creators seal with divergent
	// keys, the loser's ciphertext permanently undecryptable. link(2)
	// publishes exactly one winner; losers see EEXIST and adopt the
	// winner's complete file. Durability matches WriteFileDurable (temp
	// sync + close check + dir sync, key before any tree encrypted with
	// it — this runs inside the encrypt step of writeTree, so the ordering
	// is structural), and a crash-leaked temp matches the NewDB `.*.tmp-*`
	// sweep. Owner-only 0600 is enforced explicitly like the old
	// WriteFileDurable call (CreateTemp starts 0600 but umask could
	// tighten it into unreadability).
	//
	// On dir-sync failure the file is LEFT in place and a PLAIN error is
	// returned: "first key wins forever" stays unconditional (no remove
	// race against a concurrent adopter), and the error never takes the
	// *PostRenameSyncError shape — Commit reads that type as "the NEW
	// ACTIVE config is visible, converge" (#5185), which is wrong for a
	// key file (the active write never ran; a plain reject leaves the old
	// active plus an intact candidate to retry, and the base misclassified
	// exactly this case). The left file is undurable-known, not broken:
	// the next acquisition adopt-syncs it before use (see below), so the
	// EIO heals instead of stranding.
	//
	// Mixed-version residual: a pre-fix binary racing this path still
	// overwrites via rename; convergence needs cooperating (post-fix)
	// writers — the upgrade window only.
	dir := filepath.Dir(path)
	for attempt := 0; ; attempt++ {
		tmp, err := os.CreateTemp(dir, ".master.key.tmp-")
		if err != nil {
			return nil, fmt.Errorf("create master key temp in %s: %w", dir, err)
		}
		tmpName := tmp.Name()
		removeTmp := func() { _ = os.Remove(tmpName) }
		failTemp := func(format string, args ...any) ([]byte, error) {
			_ = tmp.Close()
			removeTmp()
			return nil, fmt.Errorf(format, args...)
		}
		if n, werr := tmp.Write(key); werr != nil || n != len(key) {
			if werr == nil {
				werr = fmt.Errorf("short write (%d of %d bytes)", n, len(key))
			}
			return failTemp("write master key temp: %w", werr)
		}
		if err := tmp.Chmod(0600); err != nil {
			return failTemp("chmod master key temp: %w", err)
		}
		if err := tmp.Sync(); err != nil {
			return failTemp("sync master key temp: %w", err)
		}
		if err := tmp.Close(); err != nil {
			removeTmp()
			return nil, fmt.Errorf("close master key temp: %w", err)
		}
		err = masterKeyLink(tmpName, path)
		removeTmp() // drop the temp name (winner) or sweep the orphan (loser)
		if err == nil {
			// Winner. The entry is visible; one dir sync makes both the
			// publish and the temp-name removal durable.
			if serr := rbSyncDir(dir); serr != nil {
				return nil, fmt.Errorf("persist master key: dir sync: %w", serr)
			}
			return key, nil
		}
		if os.IsExist(err) {
			// Loser: discard our key and adopt the winner's complete file.
			return adoptPublishedMasterKey(path)
		}
		if os.IsNotExist(err) && attempt+1 < masterKeyPublishAttempts {
			continue // swept by a concurrent NewDB; recreate and converge
		}
		return nil, fmt.Errorf("publish master key: %w", err)
	}
}

// adoptPublishedMasterKey adopts another creator's published key file with
// full durability (#9898 F-111): the file's content is fsynced and its
// directory entry synced before the key is returned, so EVERY
// readOrCreateMasterKey return — winner, loser, or fast-path reader — is
// durable BEFORE any ciphertext sealed with it can be rename-published. A
// post-fix winner's content is already durable (temp synced pre-Link), so
// the file sync is belt (it also covers hand-placed keys); the dir sync is
// the load-bearing barrier for a racing winner parked between Link and its
// own sync, or a previous EIO-leave. Any sync failure fails closed with a
// plain error — the file stays put, so a retry re-syncs and converges to
// the same key (an EIO-leave heals on the next acquisition; there is no
// double-EIO strand: durability is re-established, not assumed).
func adoptPublishedMasterKey(path string) ([]byte, error) {
	data, err := ReadBoundedFile(path, maxMasterKeyFileSize)
	if err != nil {
		return nil, fmt.Errorf("read published master key: %w", err)
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("invalid published master key length in %s", path)
	}
	// Sync the content through a second descriptor: ReadBoundedFile above
	// already closed its own. A concurrent replace between the read and
	// this open (a mixed-version renamer — the accepted upgrade-window
	// residual) could sync a successor inode while these bytes are used;
	// post-fix publishers never replace, so the window is empty for them.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("adopt published master key: open: %w", err)
	}
	serr := syncMasterKeyFile(f)
	cerr := f.Close()
	if serr != nil {
		return nil, fmt.Errorf("adopt published master key: file sync: %w", serr)
	}
	if cerr != nil {
		return nil, fmt.Errorf("adopt published master key: close: %w", cerr)
	}
	if err := rbSyncDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("adopt published master key: dir sync: %w", err)
	}
	return data, nil
}
