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
	if taggedAPIAuthHash(raw, apiAuthInvalidBcryptPrefix) {
		return fmt.Errorf("api-auth Basic password is an invalid stored verifier")
	}
	if IsAPIAuthSecretHash(raw) {
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
	if taggedAPIAuthHash(raw, apiAuthInvalidBcryptPrefix) {
		return fmt.Errorf("api-auth API key is an invalid stored verifier")
	}
	if IsAPIAuthSecretHash(raw) {
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
	return IsAPIAuthSecretHash(raw) || taggedAPIAuthHash(raw, apiAuthInvalidBcryptPrefix)
}

func taggedAPIAuthHash(raw, prefix string) bool {
	if !strings.HasPrefix(raw, prefix) {
		return false
	}
	_, err := bcrypt.Cost([]byte(strings.TrimPrefix(raw, prefix)))
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
	hash, err := bcrypt.GenerateFromPassword(prehash[:], bcrypt.DefaultCost)
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

// HashAPIAuthSecrets rewrites api-auth credential leaves in tree to salted
// bcrypt verifiers. It intentionally mutates only the tree supplied by its
// caller; compile and commit boundaries pass a private clone.
func HashAPIAuthSecrets(tree *ConfigTree) (bool, error) {
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
			path := append(append([]string(nil), parent...), node.Keys...)
			authAt := -1
			for i, part := range path {
				if part == "api-auth" {
					authAt = i
				}
			}
			keywordIndex := len(parent)
			for i, keyword := range node.Keys {
				at := keywordIndex + i
				if authAt >= 0 && at > authAt && isAPIAuthSecretKeyword(keyword) {
					start := i + 1
					end := start + 1
					if keyword == "api-key" {
						end = len(node.Keys)
					}
					if end > len(node.Keys) {
						end = len(node.Keys)
					}
					for j := start; j < end; j++ {
						hash, err := hashAPIAuthSecretAtMinimum(node.Keys[j], apiAuthSecretMinRunes(keyword))
						if err != nil {
							return err
						}
						if hash != node.Keys[j] {
							node.Keys[j] = hash
							changed = true
						}
					}
				}
			}
			// Leaf values represented as children are used by repeated
			// `api-key` list members and by parser-normalized singleton leaves.
			if authAt >= 0 && len(path) > 0 && isAPIAuthSecretKeyword(path[len(path)-1]) {
				for _, child := range node.Children {
					if child == nil || len(child.Keys) == 0 {
						continue
					}
					count := 1
					if path[len(path)-1] == "api-key" {
						count = len(child.Keys)
					}
					for j := 0; j < count; j++ {
						hash, err := hashAPIAuthSecretAtMinimum(child.Keys[j], apiAuthSecretMinRunes(path[len(path)-1]))
						if err != nil {
							return err
						}
						if hash != child.Keys[j] {
							child.Keys[j] = hash
							changed = true
						}
					}
				}
			}
			if err := walk(node.Children, path); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(tree.Children, nil); err != nil {
		return false, err
	}
	return changed, nil
}

func apiAuthSecretMinRunes(keyword string) int {
	if keyword == "password" {
		return APIAuthBasicPasswordMinRunes
	}
	return APIAuthKeyMinRunes
}

func isAPIAuthSecretKeyword(keyword string) bool {
	return keyword == "password" || keyword == "secret" || keyword == "api-key"
}
