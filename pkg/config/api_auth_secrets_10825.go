package config

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

const (
	apiAuthBcryptPrefix        = "$xpf-bcrypt$"
	apiAuthInvalidBcryptPrefix = "$xpf-invalid$"
	// Cost 12 raises API-auth offline-guessing work fourfold over the
	// previous cost 10 while keeping admission throttling ahead of compares.
	apiAuthBcryptCost = 12
)

// APIAuthBasicPasswordMinRunes is the strict-commit minimum for an api-auth
// Basic password (#10825). Requiring twelve characters prevents the shortest
// human-password guesses from being valid online-guessing targets.
const APIAuthBasicPasswordMinRunes = 12

// APIAuthKeyMinRunes is the strict-commit minimum for an api-auth API key
// (#10825). API keys are machine-generated; sixteen characters is the floor.
const APIAuthKeyMinRunes = 16

// ValidateAPIAuthBasicPassword rejects too-short operator passwords and
// invalid verifiers produced while tolerantly loading those old values.
func ValidateAPIAuthBasicPassword(raw string, _ *Config) error {
	if strings.HasPrefix(raw, apiAuthInvalidBcryptPrefix) {
		return fmt.Errorf("api-auth Basic password is an invalid stored verifier")
	}
	if strings.HasPrefix(raw, apiAuthBcryptPrefix) {
		if !IsAPIAuthSecretHash(raw) {
			return fmt.Errorf("api-auth Basic password is a malformed stored verifier")
		}
		return nil
	}
	if utf8.RuneCountInString(raw) < APIAuthBasicPasswordMinRunes {
		return fmt.Errorf("api-auth Basic password must be at least %d characters (#10825)", APIAuthBasicPasswordMinRunes)
	}
	return nil
}

// ValidateAPIAuthKey rejects too-short operator keys and invalid verifiers
// produced while tolerantly loading those old values.
func ValidateAPIAuthKey(raw string, _ *Config) error {
	if strings.HasPrefix(raw, apiAuthInvalidBcryptPrefix) {
		return fmt.Errorf("api-auth API key is an invalid stored verifier")
	}
	if strings.HasPrefix(raw, apiAuthBcryptPrefix) {
		if !IsAPIAuthSecretHash(raw) {
			return fmt.Errorf("api-auth API key is a malformed stored verifier")
		}
		return nil
	}
	if utf8.RuneCountInString(raw) < APIAuthKeyMinRunes {
		return fmt.Errorf("api-auth API key must be at least %d characters (#10825)", APIAuthKeyMinRunes)
	}
	return nil
}

// ValidateAPIAuthExpiry validates the UTC calendar-date form used by api-auth.
func ValidateAPIAuthExpiry(raw string, _ *Config) error {
	if _, err := time.Parse("2006-01-02", raw); err != nil {
		return fmt.Errorf("api-auth expiry must be a UTC date in YYYY-MM-DD form")
	}
	return nil
}

// ParseAPIAuthExpiry turns a validated UTC date into an exclusive expiry
// instant: a credential remains usable throughout the named UTC calendar day.
func ParseAPIAuthExpiry(raw string) (time.Time, error) {
	date, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("api-auth expiry must be a UTC date in YYYY-MM-DD form")
	}
	return date.AddDate(0, 0, 1), nil
}

// IsAPIAuthSecretHash reports whether raw contains a valid xpf-tagged bcrypt
// verifier. The tag prevents a compiled tree from hashing the verifier again.
func IsAPIAuthSecretHash(raw string) bool {
	return taggedAPIAuthHash(raw, apiAuthBcryptPrefix)
}

func isStoredAPIAuthSecret(raw string) bool {
	return strings.HasPrefix(raw, apiAuthBcryptPrefix) ||
		strings.HasPrefix(raw, apiAuthInvalidBcryptPrefix)
}

func taggedAPIAuthHash(raw, prefix string) bool {
	if !strings.HasPrefix(raw, prefix) {
		return false
	}
	encoded := strings.TrimPrefix(raw, prefix)
	if len(encoded) != 60 {
		return false
	}
	for i := 7; i < len(encoded); i++ {
		c := encoded[i]
		if !(c == '.' || c == '/' || c >= 'A' && c <= 'Z' ||
			c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	_, err := bcrypt.Cost([]byte(encoded))
	return err == nil
}

// HashAPIAuthSecret produces the persisted bcrypt verifier for an api-auth
// secret. A SHA-256 prehash keeps bcrypt's input fixed-size without truncating
// long operator secrets. Already-compiled verifiers are returned unchanged.
func HashAPIAuthSecret(raw string) (string, error) {
	return hashAPIAuthSecretAtMinimum(raw, 0)
}

func hashAPIAuthSecretAtMinimum(raw string, minimum int) (string, error) {
	if raw == "" || isStoredAPIAuthSecret(raw) {
		return raw, nil
	}
	prefix := apiAuthBcryptPrefix
	if minimum > 0 && utf8.RuneCountInString(raw) < minimum {
		prefix = apiAuthInvalidBcryptPrefix
	}
	prehash := sha256.Sum256([]byte(raw))
	hash, err := bcrypt.GenerateFromPassword(prehash[:], apiAuthBcryptCost)
	if err != nil {
		return "", fmt.Errorf("hashing api-auth secret failed")
	}
	return prefix + string(hash), nil
}

// VerifyAPIAuthSecret checks a presented cleartext secret against a compiled
// xpf bcrypt verifier.
func VerifyAPIAuthSecret(encoded, presented string) bool {
	if !IsAPIAuthSecretHash(encoded) {
		return false
	}
	prehash := sha256.Sum256([]byte(presented))
	return bcrypt.CompareHashAndPassword([]byte(strings.TrimPrefix(encoded, apiAuthBcryptPrefix)), prehash[:]) == nil
}

// HashAPIAuthSecrets rewrites only credential leaves in the
// system/services/web-management/api-auth schema subtree to salted bcrypt
// verifiers. Short legacy values use a well-formed, non-authenticating
// `$xpf-invalid$` marker so the migration remains idempotent after restart.
// It intentionally mutates only the tree supplied by its caller; compile and
// commit boundaries pass a private clone.
func HashAPIAuthSecrets(tree *ConfigTree) (bool, error) {
	changed, err := hashAPIAuthSecrets(tree, nil)
	return changed, err
}

// HashAPIAuthSecretsWithInvalidPaths also reports distinct leaf paths whose
// cleartext values were replaced by non-authenticating short-secret markers.
// The paths never contain credential values; already-stored verifiers are not
// reported.
func HashAPIAuthSecretsWithInvalidPaths(tree *ConfigTree) (bool, []string, error) {
	report := &apiAuthSecretHashReport{}
	changed, err := hashAPIAuthSecrets(tree, report)
	if err != nil {
		return false, nil, err
	}
	return changed, report.invalidPaths, nil
}

func hashAPIAuthSecrets(tree *ConfigTree, report *apiAuthSecretHashReport) (bool, error) {
	if tree == nil {
		return false, nil
	}
	changed := false
	var walk func(nodes []*Node, parent []string) error
	walk = func(nodes []*Node, parent []string) error {
		for _, node := range nodes {
			if node == nil {
				continue
			}
			parentLen := len(parent)
			parent = append(parent, node.Keys...)
			nodeParent := parent[:parentLen]

			// Flat-set and parsed trees can place the keyword and value in the
			// same Keys slice. Recognize only the actual schema credential slots,
			// not any later keyword below an object whose name happens to be
			// "api-auth".
			for i, keyword := range node.Keys {
				if !apiAuthSecretKeywordAt(nodeParent, node.Keys, i, keyword) {
					continue
				}
				start := i + 1
				end := start + 1
				if keyword == "api-key" {
					end = len(node.Keys)
				}
				if end > len(node.Keys) {
					end = len(node.Keys)
				}
				for j := start; j < end; j++ {
					if isMalformedAPIAuthSecretTag(node.Keys[j]) {
						return fmt.Errorf("api-auth secret has a malformed reserved verifier tag")
					}
					raw := node.Keys[j]
					hash, err := hashAPIAuthSecretAtMinimum(raw, apiAuthSecretMinRunes(keyword))
					if err != nil {
						return err
					}
					if report != nil && !isStoredAPIAuthSecret(raw) &&
						strings.HasPrefix(hash, apiAuthInvalidBcryptPrefix) {
						report.addPath(apiAuthSecretLeafPath(nodeParent, node.Keys, i))
					}
					if hash != raw {
						node.Keys[j] = hash
						changed = true
					}
				}
			}

			// Leaf values represented as children are used by repeated
			// `api-key` list members and parser-normalized singleton leaves.
			if keyword, ok := apiAuthSecretSlotAtPath(parent); ok {
				for _, child := range node.Children {
					if child == nil || len(child.Keys) == 0 {
						continue
					}
					count := 1
					if keyword == "api-key" {
						count = len(child.Keys)
					}
					for j := 0; j < count; j++ {
						if isMalformedAPIAuthSecretTag(child.Keys[j]) {
							return fmt.Errorf("api-auth secret has a malformed reserved verifier tag")
						}
						raw := child.Keys[j]
						hash, err := hashAPIAuthSecretAtMinimum(raw, apiAuthSecretMinRunes(keyword))
						if err != nil {
							return err
						}
						if report != nil && !isStoredAPIAuthSecret(raw) &&
							strings.HasPrefix(hash, apiAuthInvalidBcryptPrefix) {
							report.addPath(apiAuthSecretLeafPath(parent, nil, -1))
						}
						if hash != raw {
							child.Keys[j] = hash
							changed = true
						}
					}
				}
			}
			if err := walk(node.Children, parent); err != nil {
				return err
			}
			parent = parent[:parentLen]
		}
		return nil
	}
	if err := walk(tree.Children, nil); err != nil {
		return false, err
	}
	return changed, nil
}

type apiAuthSecretHashReport struct {
	invalidPaths []string
	seenPaths    map[string]struct{}
}

func (report *apiAuthSecretHashReport) addPath(path string) {
	if report.seenPaths == nil {
		report.seenPaths = make(map[string]struct{})
	}
	if _, exists := report.seenPaths[path]; exists {
		return
	}
	report.seenPaths[path] = struct{}{}
	report.invalidPaths = append(report.invalidPaths, path)
}

func apiAuthSecretLeafPath(parent, keys []string, keywordIndex int) string {
	parts := make([]string, 0, len(parent)+keywordIndex+1)
	parts = append(parts, parent...)
	if keywordIndex >= 0 {
		parts = append(parts, keys[:keywordIndex+1]...)
	}
	return formatAPIAuthSecretLeafPath(parts)
}

func formatAPIAuthSecretLeafPath(path []string) string {
	if len(path) == 0 {
		return ""
	}
	parts := append([]string(nil), path...)
	scopeEnd, ok := apiAuthScopeEnd(parts[:len(parts)-1])
	if ok {
		if parts[0] == "groups" {
			parts[1] = fmt.Sprintf("%q", parts[1])
		}
		if scopeEnd < len(parts)-1 {
			switch parts[scopeEnd] {
			case "user", "key":
				parts[scopeEnd+1] = fmt.Sprintf("%q", parts[scopeEnd+1])
			}
		}
	}
	return strings.Join(parts, " ")
}

func isMalformedAPIAuthSecretTag(raw string) bool {
	if strings.HasPrefix(raw, apiAuthInvalidBcryptPrefix) {
		// This well-formed deny marker is persisted for short legacy values.
		// It must survive later loads, but never passes IsAPIAuthSecretHash or
		// the strict credential validators.
		return !taggedAPIAuthHash(raw, apiAuthInvalidBcryptPrefix)
	}
	return strings.HasPrefix(raw, apiAuthBcryptPrefix) && !IsAPIAuthSecretHash(raw)
}

// HasMalformedAPIAuthSecretTag reports whether an API-auth credential slot
// contains a reserved verifier tag with an invalid encoding. A well-formed
// `$xpf-invalid$` is the durable deny marker for short legacy secrets; it is
// structurally stable but remains unusable and is rejected by schema validation.
// It checks the schema-defined root and group paths without mutating the tree.
func HasMalformedAPIAuthSecretTag(tree *ConfigTree) bool {
	if tree == nil {
		return false
	}
	var walk func(nodes []*Node, parent []string) bool
	walk = func(nodes []*Node, parent []string) bool {
		for _, node := range nodes {
			if node == nil {
				continue
			}
			for i, keyword := range node.Keys {
				if !apiAuthSecretKeywordAt(parent, node.Keys, i, keyword) {
					continue
				}
				start := i + 1
				end := start + 1
				if keyword == "api-key" {
					end = len(node.Keys)
				}
				if end > len(node.Keys) {
					end = len(node.Keys)
				}
				for j := start; j < end; j++ {
					if isMalformedAPIAuthSecretTag(node.Keys[j]) {
						return true
					}
				}
			}

			parentLen := len(parent)
			parent = append(parent, node.Keys...)
			if keyword, ok := apiAuthSecretSlotAtPath(parent); ok {
				for _, child := range node.Children {
					if child == nil || len(child.Keys) == 0 {
						continue
					}
					count := 1
					if keyword == "api-key" {
						count = len(child.Keys)
					}
					for j := 0; j < count; j++ {
						if isMalformedAPIAuthSecretTag(child.Keys[j]) {
							return true
						}
					}
				}
			}
			if walk(node.Children, parent) {
				return true
			}
			parent = parent[:parentLen]
		}
		return false
	}
	return walk(tree.Children, nil)
}

// apiAuthSecretKeywordAt reports whether keys[index] names a credential leaf
// at the corresponding schema location. parent and keys are the AST path split
// at the current node; keeping that split avoids allocating a flattened path
// for each token inspected.
func apiAuthSecretKeywordAt(parent, keys []string, index int, keyword string) bool {
	if index < 0 || index >= len(keys) || keyword != keys[index] {
		return false
	}
	absolute := len(parent) + index
	scopeEnd, ok := apiAuthScopeEndAt(parent, keys, index)
	if !ok {
		return false
	}
	remaining := absolute - scopeEnd
	switch keyword {
	case "api-key":
		return remaining == 0
	case "password":
		return remaining == 2 && apiAuthPathPart(parent, keys, scopeEnd) == "user"
	case "secret":
		return remaining == 2 && apiAuthPathPart(parent, keys, scopeEnd) == "key"
	default:
		return false
	}
}

func apiAuthSecretSlotAtPath(path []string) (string, bool) {
	if len(path) == 0 {
		return "", false
	}
	keyword := path[len(path)-1]
	scopeEnd, ok := apiAuthScopeEnd(path[:len(path)-1])
	if !ok {
		return "", false
	}
	remaining := len(path) - 1 - scopeEnd
	switch keyword {
	case "api-key":
		ok = remaining == 0
	case "password":
		ok = remaining == 2 && path[scopeEnd] == "user"
	case "secret":
		ok = remaining == 2 && path[scopeEnd] == "key"
	default:
		ok = false
	}
	if !ok {
		return "", false
	}
	return keyword, true
}

func apiAuthScopeEnd(path []string) (int, bool) {
	if len(path) >= 4 && path[0] == "system" && path[1] == "services" &&
		path[2] == "web-management" && path[3] == "api-auth" {
		return 4, true
	}
	if len(path) >= 6 && path[0] == "groups" && path[2] == "system" &&
		path[3] == "services" && path[4] == "web-management" &&
		path[5] == "api-auth" {
		return 6, true
	}
	return 0, false
}

func apiAuthScopeEndAt(parent, keys []string, keyCount int) (int, bool) {
	length := len(parent) + keyCount
	part := func(index int) string { return apiAuthPathPart(parent, keys, index) }
	if length >= 4 && part(0) == "system" && part(1) == "services" &&
		part(2) == "web-management" && part(3) == "api-auth" {
		return 4, true
	}
	if length >= 6 && part(0) == "groups" && part(2) == "system" &&
		part(3) == "services" && part(4) == "web-management" &&
		part(5) == "api-auth" {
		return 6, true
	}
	return 0, false
}

func apiAuthPathPart(parent, keys []string, index int) string {
	if index < len(parent) {
		return parent[index]
	}
	index -= len(parent)
	if index < 0 || index >= len(keys) {
		return ""
	}
	return keys[index]
}

// ConfigTreesEquivalentForSync compares two parsed source trees without
// mutating either. The only non-identical values it accepts are incoming
// cleartext API-auth credentials that verify against the corresponding valid
// tagged bcrypt verifier already stored in active.
func ConfigTreesEquivalentForSync(active, incoming *ConfigTree) bool {
	if active == nil || incoming == nil {
		return active == incoming
	}
	return equivalentSyncNodes(active.Children, incoming.Children, nil, nil, "", "")
}

func equivalentSyncNodes(active, incoming []*Node, activePath, incomingPath []string, activeValueSlot, incomingValueSlot string) bool {
	if len(active) != len(incoming) {
		return false
	}
	for i := range active {
		a, b := active[i], incoming[i]
		if a == nil || b == nil {
			if a != b {
				return false
			}
			continue
		}
		if a.IsLeaf != b.IsLeaf || a.Annotation != b.Annotation ||
			a.Inactive != b.Inactive || a.InheritedFrom != b.InheritedFrom ||
			!equalStrings(a.fromGroups, b.fromGroups) ||
			!equalLeafMemberGroups(a.leafMemberGroups9862, b.leafMemberGroups9862) ||
			!equalBools(a.KeysQuoted, b.KeysQuoted) ||
			!equalBools(a.KeysBracketed, b.KeysBracketed) ||
			len(a.Keys) != len(b.Keys) || len(a.Children) != len(b.Children) {
			return false
		}
		for k := range a.Keys {
			aCredential := activeValueSlot != "" && (activeValueSlot == "api-key" || k == 0)
			bCredential := incomingValueSlot != "" && (incomingValueSlot == "api-key" || k == 0)
			if !aCredential {
				aCredential = apiAuthNodeKeyValueAt(activePath, a.Keys, k)
			}
			if !bCredential {
				bCredential = apiAuthNodeKeyValueAt(incomingPath, b.Keys, k)
			}
			if aCredential != bCredential {
				return false
			}
			if a.Keys[k] != b.Keys[k] && (!aCredential || !syncCredentialValueEquivalent(a.Keys[k], b.Keys[k])) {
				return false
			}
		}

		activePathLen, incomingPathLen := len(activePath), len(incomingPath)
		activePath = append(activePath, a.Keys...)
		incomingPath = append(incomingPath, b.Keys...)
		aChildSlot, _ := apiAuthSecretSlotAtPath(activePath)
		bChildSlot, _ := apiAuthSecretSlotAtPath(incomingPath)
		if aChildSlot != bChildSlot {
			return false
		}
		if !equivalentSyncNodes(a.Children, b.Children, activePath, incomingPath, aChildSlot, bChildSlot) {
			return false
		}
		activePath = activePath[:activePathLen]
		incomingPath = incomingPath[:incomingPathLen]
	}
	return true
}

func apiAuthNodeKeyValueAt(parent, keys []string, index int) bool {
	if index <= 0 || index >= len(keys) {
		return false
	}
	if apiAuthSecretKeywordAt(parent, keys, index-1, keys[index-1]) {
		return true
	}
	scopeEnd, ok := apiAuthScopeEndAt(parent, keys, len(keys))
	if !ok {
		return false
	}
	apiKeyIndex := scopeEnd - len(parent)
	return index > apiKeyIndex && apiAuthSecretKeywordAt(parent, keys, apiKeyIndex, "api-key")
}

func syncCredentialValueEquivalent(active, incoming string) bool {
	return active == incoming || (IsAPIAuthSecretHash(active) && VerifyAPIAuthSecret(active, incoming))
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalBools(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalLeafMemberGroups(a, b []leafListMemberGroups9862) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].value != b[i].value || a[i].quoted != b[i].quoted ||
			!equalStrings(a[i].groups, b[i].groups) {
			return false
		}
	}
	return true
}

func apiAuthSecretMinRunes(keyword string) int {
	if keyword == "password" {
		return APIAuthBasicPasswordMinRunes
	}
	return APIAuthKeyMinRunes
}
