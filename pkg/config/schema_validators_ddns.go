package config

import (
	"fmt"
	"strings"
)

// ValidateDDNSHostname rejects a Surface A DDNS hostname that the publish
// path (pkg/ddns surfaceAName -> sanitizeFQDN) would SILENTLY rewrite to a
// different DNS name (#2779). For router-owned Surface A records the hostname
// is operator intent — the operator types the exact public name to publish —
// so a name that sanitization would structurally change (drop a non-LDH
// character, collapse/drop an empty label, trim a leading/trailing dash off a
// label) must be a commit error, not a silent transform. The operator fixes
// the name rather than discovering wan_1.example.net was published as
// wan1.example.net.
//
// What is ACCEPTED (sanitization is a no-op or a benign canonicalization the
// operator clearly intended):
//   - lower-case [a-z0-9-] labels separated by single dots (the canonical LDH
//     form sanitizeFQDN produces),
//   - upper-case letters (sanitizeFQDN lower-cases; DNS is case-insensitive so
//     this is a benign canonicalization, not a structural change),
//   - a single trailing dot (absolute-name canonicalization; stripped before
//     publish).
//
// What is REJECTED (sanitization would change the published structure):
//   - any rune outside [A-Za-z0-9-] inside a label (underscore, space, '@',
//     IDN/punycode source chars, etc.) — sanitizeLabel drops it,
//   - an empty label (leading dot, double dot, or a label made only of dropped
//     characters) — sanitizeFQDN drops the whole label,
//   - a label that begins or ends with '-' — sanitizeLabel trims it,
//   - a label over 63 octets or a total name over 253 octets — capped.
func ValidateDDNSHostname(raw string) error {
	name := strings.TrimSpace(raw)
	if name == "" {
		// An unset/blank hostname is handled by the binding-completeness
		// warning (validateSurfaceADDNSWarnings), not a hard reject — a
		// half-built candidate must still commit.
		return nil
	}
	// A single trailing dot is the only dot-position canonicalization the
	// publish path performs (TrimSuffix "."); strip it before the per-label
	// structural check so an absolute name is accepted.
	stripped := strings.TrimSuffix(name, ".")
	if stripped == "" {
		return fmt.Errorf("dynamic-dns hostname %q has no labels", raw)
	}
	if len(stripped) > maxDNSNameLen {
		return fmt.Errorf("dynamic-dns hostname %q exceeds %d octets and would be "+
			"truncated before publishing", raw, maxDNSNameLen)
	}
	labels := strings.Split(stripped, ".")
	for _, lbl := range labels {
		if lbl == "" {
			return fmt.Errorf("dynamic-dns hostname %q has an empty label "+
				"(leading/trailing/doubled dot); it would be dropped before "+
				"publishing — fix the name", raw)
		}
		if len(lbl) > maxDNSLabelLen {
			return fmt.Errorf("dynamic-dns hostname label %q exceeds %d octets and "+
				"would be truncated before publishing", lbl, maxDNSLabelLen)
		}
		if lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
			return fmt.Errorf("dynamic-dns hostname label %q begins or ends with '-'; "+
				"the dash would be trimmed before publishing — fix the name", lbl)
		}
		for _, r := range lbl {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
				r >= '0' && r <= '9', r == '-':
				// LDH (letter-digit-hyphen); upper-case is lower-cased
				// at publish but that is benign (DNS is case-insensitive).
			default:
				return fmt.Errorf("dynamic-dns hostname %q contains the non-LDH "+
					"character %q; it would be silently stripped before publishing "+
					"(publishing a different name than configured) — use only "+
					"letters, digits, and hyphens", raw, r)
			}
		}
	}
	return nil
}

// maxDNSLabelLen / maxDNSNameLen mirror pkg/ddns hostname.go (maxDNSLabel /
// maxDNSName) so the commit-time hostname check rejects exactly the names the
// publish path would truncate. Kept as local constants to avoid a
// config->ddns import dependency.
const (
	maxDNSLabelLen = 63
	maxDNSNameLen  = 253
)
