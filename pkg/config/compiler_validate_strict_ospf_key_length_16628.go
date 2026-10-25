package config

import (
	"fmt"
	"log/slog"
)

// #16628 (R3-A12-04): OSPF MD5 keys longer than 16 characters and
// simple-passwords longer than 8 commit strict-clean; ospfd silently
// truncates them, and every reload deletes and re-adds the key
// (perpetual diff).
//
// RFC 2328 Appendix D.2: the simple password is "a 64-bit field"
// (8 characters). D.4.3 step (6)(a): "The 16 byte MD5 key is appended
// to the OSPF packet" (16 characters). FRR ospfd truncates a longer
// key to that width in running-config, so the rendered managed frr.conf
// line never matches what ospfd holds: every frr-reload sees a
// delete-and-add pair for the key, and the #15203 reload-diff
// certification can never pass for that box. The effective key also
// diverges silently from `show configuration`.
//
// This is the OSPF sibling of #15013 (RIP, MaxRIPAuthKeyLen). The fix
// mirrors it exactly:
//
//   - Strict (commit / commit-check): the schema leaves carry
//     ValidateOSPFMD5KeyLength / ValidateOSPFSimplePasswordLength
//     (1..16 / 1..8 characters), and validateOSPFKeyLengthStrict below
//     enforces the same bounds on the compiled *Config — globally and
//     per routing instance (the routing-instance schema shares the
//     global ospf subtree via schemaProtocols).
//   - Lenient (Store.Load, Store.SyncApply, #1960): the compiled gate
//     downgrades to a warning naming only the length, never the key,
//     so a persisted config still boots.
//   - pkg/frr render belt: an over-long key arriving on the tolerant
//     path is withheld fail-closed — the interface is omitted (no
//     `interface` block, no `ip ospf area`) rather than rendering a
//     truncated-truth line that churns forever or activating the
//     interface unauthenticated. A valid rollover key on the same
//     interface still renders; only the over-long entries are dropped,
//     and if no MD5 key survives the whole interface is omitted
//     (the #14388 rule).
//
// The bound counts characters (runes), matching the operator-visible
// length FRR counts — same as #15013.
//
// The Junos `$9$` case: decodeJunos9AtCompile (#15051) runs FIRST in
// runUniformGatesLogFeedRouting and replaces a `$9$` blob with its
// plaintext before this gate reads the compiled Config, so the bound
// applies to the decoded plaintext the daemon would actually hold —
// never to the authored blob. A `$9$` blob whose plaintext exceeds the
// bound is therefore rejected on strict commit for the same reason a
// plain over-long key is: ospfd would truncate the plaintext.
const (
	// MaxOSPFMD5KeyLen is the maximum OSPF MD5 key length in
	// characters (RFC 2328 D.4.3: the 16 byte MD5 key).
	MaxOSPFMD5KeyLen = 16
	// MaxOSPFSimplePasswordLen is the maximum OSPF simple-password
	// length in characters (RFC 2328 D.2: a 64-bit field).
	MaxOSPFSimplePasswordLen = 8
)

// ValidateOSPFMD5KeyLength is the setSchema typed-leaf validator for
// `protocols ospf area <a> interface <i> authentication md5 <id> key`
// (shared by the global and routing-instance copies via
// schemaProtocols). It rejects an empty value and any key longer than
// MaxOSPFMD5KeyLen characters. The compiled gate
// validateOSPFKeyLengthStrict below is the backstop for values that
// bypass SchemaValidate (programmatic trees, tolerant loads downgraded
// to warnings, group-expanded values).
func ValidateOSPFMD5KeyLength(raw string) error {
	if raw == "" {
		return fmt.Errorf("missing OSPF MD5 key (expected 1..%d characters)", MaxOSPFMD5KeyLen)
	}
	if n := len([]rune(raw)); n > MaxOSPFMD5KeyLen {
		return fmt.Errorf("OSPF MD5 key is %d characters, exceeding the %d-character maximum "+
			"accepted by FRR ospfd (ip ospf message-digest-key); ospfd truncates a longer key, "+
			"so the effective key differs from the configuration and every frr-reload deletes "+
			"and re-adds it — shorten the key to at most %d characters (#16628)",
			n, MaxOSPFMD5KeyLen, MaxOSPFMD5KeyLen)
	}
	return nil
}

// ValidateOSPFSimplePasswordLength is the setSchema typed-leaf
// validator for `protocols ospf area <a> interface <i> authentication
// simple-password` (shared by the global and routing-instance copies
// via schemaProtocols). It rejects an empty value and any password
// longer than MaxOSPFSimplePasswordLen characters. The compiled gate
// validateOSPFKeyLengthStrict below is the backstop for values that
// bypass SchemaValidate.
func ValidateOSPFSimplePasswordLength(raw string) error {
	if raw == "" {
		return fmt.Errorf("missing OSPF simple-password (expected 1..%d characters)", MaxOSPFSimplePasswordLen)
	}
	if n := len([]rune(raw)); n > MaxOSPFSimplePasswordLen {
		return fmt.Errorf("OSPF simple-password is %d characters, exceeding the %d-character maximum "+
			"accepted by FRR ospfd (ip ospf authentication-key); ospfd truncates a longer password, "+
			"so the effective password differs from the configuration and every frr-reload deletes "+
			"and re-adds it — shorten the password to at most %d characters (#16628)",
			n, MaxOSPFSimplePasswordLen, MaxOSPFSimplePasswordLen)
	}
	return nil
}

// validateOSPFKeyLengthStrict rejects a compiled OSPF key longer than
// its bound: every AuthMD5Keys entry (and the legacy AuthKey view when
// AuthType is md5) over MaxOSPFMD5KeyLen, and a simple AuthKey over
// MaxOSPFSimplePasswordLen — globally and per routing instance. Strict
// returns an error; lenient appends a warning and logs (never the key
// itself — only its length) so a persisted config still boots while
// pkg/frr withholds the over-long key fail-closed.
func validateOSPFKeyLengthStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	report := func(scope, areaID string, iface *OSPFInterface, kind string, keyID, n, max int) error {
		var msg string
		if kind == "md5" {
			msg = fmt.Sprintf("%sprotocols ospf area %s interface %s authentication md5 %d key is %d characters, "+
				"exceeding the %d-character maximum accepted by FRR ospfd (ip ospf message-digest-key); "+
				"ospfd truncates the key, so the effective key differs from the configuration and every "+
				"frr-reload deletes and re-adds it. Shorten the key to at most %d characters (#16628)",
				scope, areaID, iface.Name, keyID, n, max, max)
		} else {
			msg = fmt.Sprintf("%sprotocols ospf area %s interface %s authentication simple-password is %d characters, "+
				"exceeding the %d-character maximum accepted by FRR ospfd (ip ospf authentication-key); "+
				"ospfd truncates the password, so the effective password differs from the configuration and every "+
				"frr-reload deletes and re-adds it. Shorten the password to at most %d characters (#16628)",
				scope, areaID, iface.Name, n, max, max)
		}
		if lenient {
			slog.Warn("config: OSPF authentication key exceeds the FRR maximum; the interface will not be activated with this key",
				"scope", scope, "area", areaID, "interface", iface.Name,
				"authentication_type", iface.AuthType, "key_id", keyID,
				"key_len", n, "max", max, "issue", "#16628")
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	check := func(scope string, ospf *OSPFConfig) error {
		if ospf == nil {
			return nil
		}
		for _, area := range ospf.Areas {
			if area == nil {
				continue
			}
			for _, iface := range area.Interfaces {
				if iface == nil {
					continue
				}
				switch iface.AuthType {
				case "md5":
					if len(iface.AuthMD5Keys) > 0 {
						for _, key := range iface.AuthMD5Keys {
							if n := len([]rune(key.Key.Reveal())); n > MaxOSPFMD5KeyLen {
								if err := report(scope, area.ID, iface, "md5", key.ID, n, MaxOSPFMD5KeyLen); err != nil {
									return err
								}
							}
						}
					} else if n := len([]rune(iface.AuthKey.Reveal())); n > MaxOSPFMD5KeyLen {
						// Legacy single-key view (directly
						// constructed configs with no
						// AuthMD5Keys): AuthKeyID is the
						// configured key-id, 0 when unset.
						if err := report(scope, area.ID, iface, "md5", iface.AuthKeyID, n, MaxOSPFMD5KeyLen); err != nil {
							return err
						}
					}
				case "simple":
					if n := len([]rune(iface.AuthKey.Reveal())); n > MaxOSPFSimplePasswordLen {
						if err := report(scope, area.ID, iface, "simple", 0, n, MaxOSPFSimplePasswordLen); err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	}
	if err := check("", cfg.Protocols.OSPF); err != nil {
		return warnings, err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		if err := check(fmt.Sprintf("routing-instance %q ", ri.Name), ri.OSPF); err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}
