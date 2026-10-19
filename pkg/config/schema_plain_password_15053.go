package config

import "fmt"

// #15053 (A20-05): Junos plain-text-password(-value) under root-authentication
// and login user authentication was unmodeled, so it committed clean, was
// silently ignored by the compiler, and rendered in cleartext on every
// redacted surface. Modeled ONLY so strict SchemaValidate REFUSES it with a
// hint to encrypted-password. Strict commit rejects; the tolerant Load /
// SyncApply path downgrades schema violations to warnings (#1960), so a
// persisted or peer-synced config carrying it does not brick the daemon.
// The values are also in secretIndices (ast_redact.go) so any tolerant tree
// that does carry the leaf never discloses it via RedactedClone.
func plainTextPasswordLeaf15053(leaf string) *schemaNode {
	return &schemaNode{
		desc:        "Plain-text password (NOT supported by xpf — rejected at commit; use encrypted-password)",
		args:        1,
		placeholder: "<password>",
		valueType:   ValueEnumOf,
		valueDesc:   "not supported by xpf; use encrypted-password with a $6$ crypt hash",
		validator:   rejectPlainTextPassword15053(leaf),
		children:    nil,
	}
}

func rejectPlainTextPassword15053(leaf string) LeafValidator {
	return func(_ string, _ *Config) error {
		return fmt.Errorf("%s: plain-text passwords are not supported by xpf and are refused rather than silently ignored (#15053); use encrypted-password with a $6$ crypt hash (for example from `openssl passwd -6`)", leaf)
	}
}
