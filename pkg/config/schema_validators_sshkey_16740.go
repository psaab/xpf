package config

import (
	"fmt"
	"strings"
)

// #16740 (R3-A45-04): the authorized_keys key-type vocabulary and
// single-key predicate live in pkg/config so the commit-time schema
// validator (ValidateAuthorizedSSHKey, wired onto the ssh-ed25519 /
// ssh-rsa / ssh-dsa leaves in schema_system.go) and the daemon
// apply-boundary belt (pkg/daemon validateAuthorizedSSHKeys, which
// delegates here) share ONE accepted set. pkg/daemon imports
// pkg/config, so the rule cannot live in the daemon for the commit
// gate to reach it; two copies would drift, and drift on this leaf is
// the #16740 defect itself — a value that commits clean and durable,
// then fails at apply while the previously installed key stays live.
//
// The accepted set is the OpenSSH authorized_keys key-type vocabulary
// (#14111): OpenSSH accepts many key types besides the ssh-* family
// (ecdsa-sha2-nistp256/384/521 and the FIDO sk-* variants). Junos
// operators habitually store the full "<type> <base64> <comment>"
// string as the leaf value, so an ecdsa key filed under any ssh-*
// leaf is valid; requiring an ssh- prefix rejected such a key and
// skipped ALL provisioning for that user. The set stays a fail-closed
// allowlist: an option-prefixed line (`command="..." ssh-ed25519
// ...`), a bare blob, or any unknown type is refused. A
// whitespace-separated base64 blob must follow the type; the comment
// is optional.

// SSHAuthorizedKeyTypes is the OpenSSH authorized_keys key-type
// vocabulary accepted for an authorized_keys value (#14111, #16740).
var SSHAuthorizedKeyTypes = map[string]bool{
	"ssh-ed25519":                                 true,
	"ssh-rsa":                                     true,
	"ssh-dss":                                     true,
	"ecdsa-sha2-nistp256":                         true,
	"ecdsa-sha2-nistp384":                         true,
	"ecdsa-sha2-nistp521":                         true,
	"sk-ssh-ed25519@openssh.com":                  true,
	"sk-ecdsa-sha2-nistp256@openssh.com":          true,
	"ssh-ed25519-cert-v01@openssh.com":            true,
	"ssh-rsa-cert-v01@openssh.com":                true,
	"ssh-dss-cert-v01@openssh.com":                true,
	"ecdsa-sha2-nistp256-cert-v01@openssh.com":    true,
	"ecdsa-sha2-nistp384-cert-v01@openssh.com":    true,
	"ecdsa-sha2-nistp521-cert-v01@openssh.com":    true,
	"sk-ssh-ed25519-cert-v01@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com": true,
}

// ValidAuthorizedSSHKey reports whether key is a single-line OpenSSH
// public key: "<key-type> <base64-blob> [comment]" with the type in
// SSHAuthorizedKeyTypes, no CR/LF, and a base64-shaped blob. It is the
// predicate the daemon apply belt has enforced since #14111/#10725,
// moved here unchanged (#16740) so commit and apply judge identically.
func ValidAuthorizedSSHKey(key string) bool {
	if strings.ContainsAny(key, "\r\n") {
		return false
	}
	typ, blob, ok := strings.Cut(key, " ")
	if !ok || !SSHAuthorizedKeyTypes[typ] {
		return false
	}
	blob = strings.TrimLeft(blob, " ")
	if blob == "" {
		return false
	}
	if i := strings.IndexByte(blob, ' '); i >= 0 {
		blob = blob[:i]
	}
	for _, r := range blob {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '+' || r == '/' || r == '=' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// ValidateAuthorizedSSHKey is the commit-time (SchemaValidate) leaf
// validator for `system root-authentication ssh-ed25519|ssh-rsa|ssh-dsa`
// and `system login user <name> authentication ssh-ed25519|ssh-rsa|
// ssh-dsa` (#16740). Before this gate those leaves were untyped, so a
// trailing token (e.g. a value of `from 10.1.1.1`, an authorized_keys
// option, not a key), a bare blob, or any malformed key committed
// clean and durable; apply then refused ALL of that principal's keys
// (daemon validateAuthorizedSSHKeys) and skipped both install and
// revoke, leaving the previously installed — possibly compromised —
// key live on every later apply until the config was corrected.
//
// #16740, after #16066: the error names only the defect class, never
// any fragment of the submitted value. A pasted key (or what the
// operator believed was one) is credential material; commit errors
// are logged/returned verbatim by tolerant ingress and reach
// journal/syslog. The walker (typedLeafInvalidErrorf) additionally
// renders the offending token beside this message, so the message
// itself must not repeat it.
func ValidateAuthorizedSSHKey(raw string) error {
	if !ValidAuthorizedSSHKey(raw) {
		return fmt.Errorf("must be a single-line OpenSSH public key " +
			"(\"<key-type> <base64> [comment]\", e.g. \"ssh-ed25519 AAAA... user@host\")")
	}
	return nil
}
