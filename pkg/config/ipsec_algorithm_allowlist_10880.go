package config

import (
	"strings"
)

// IPsec proposal algorithms are written as unquoted swanctl proposal tokens.
// Keep the accepted Junos algorithm domain here so strict config validation
// and the renderer's tolerant-load belt agree on the same vocabulary.
//
// The Juniper spellings are included alongside the canonical swanctl aliases
// already emitted/accepted by the renderer. Deliberately weak but real Junos
// choices (DES, 3DES, SHA-1, MD5) remain accepted for interoperability; null
// encryption and arbitrary SectionSafe strings do not.
var ipsecEncryptionAlgorithms = map[string]struct{}{
	"des-cbc": {}, "3des-cbc": {},
	"aes-128-cbc": {}, "aes-192-cbc": {}, "aes-256-cbc": {},
	"aes128-cbc": {}, "aes192-cbc": {}, "aes256-cbc": {},
	"aes": {}, "aes128": {}, "aes192": {}, "aes256": {},
	"aes-128-gcm": {}, "aes-192-gcm": {}, "aes-256-gcm": {},
	"aes128gcm": {}, "aes192gcm": {}, "aes256gcm": {},
	"aes128gcm16": {}, "aes192gcm16": {}, "aes256gcm16": {},
	"aes128gcm128": {}, "aes192gcm128": {}, "aes256gcm128": {},
}

var ipsecAuthenticationAlgorithms = map[string]struct{}{
	"md5": {}, "sha1": {}, "sha-1": {},
	"sha-256": {}, "sha256": {},
	"sha-384": {}, "sha384": {},
	"sha-512": {}, "sha512": {},
	"hmac-md5": {}, "hmac-md5-96": {},
	"hmac-sha1": {}, "hmac-sha1-96": {}, "hmac-sha-1-96": {},
	"hmac-sha256": {}, "hmac-sha256-128": {},
	"hmac-sha-256": {}, "hmac-sha-256-128": {},
	"hmac-sha384": {}, "hmac-sha384-192": {},
	"hmac-sha-384": {}, "hmac-sha-384-192": {},
	"hmac-sha512": {}, "hmac-sha512-256": {},
	"hmac-sha-512": {}, "hmac-sha-512-256": {},
}

// IsSupportedIPsecEncryptionAlgorithm reports whether value belongs to the
// algorithm vocabulary that the Junos compiler and swanctl renderer support.
// An empty value is allowed here because the renderer supplies its established
// aes256 default; callers enforce required integrity separately.
func IsSupportedIPsecEncryptionAlgorithm(value string) bool {
	if value == "" {
		return true
	}
	_, ok := ipsecEncryptionAlgorithms[strings.ToLower(value)]
	return ok
}

// IsSupportedIPsecAuthenticationAlgorithm reports whether value belongs to
// the supported Junos/swanctl integrity vocabulary. Empty means omitted and is
// validated according to the proposal's encryption mode by the caller.
func IsSupportedIPsecAuthenticationAlgorithm(value string) bool {
	if value == "" {
		return true
	}
	_, ok := ipsecAuthenticationAlgorithms[strings.ToLower(value)]
	return ok
}

// IsIPsecAEADEncryptionAlgorithm classifies supported AEAD ciphers without
// depending on the spelling's case. Domain validation remains a separate check.
func IsIPsecAEADEncryptionAlgorithm(value string) bool {
	return strings.Contains(strings.ToLower(value), "gcm")
}
