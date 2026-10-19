package config

import (
	"fmt"
	"log/slog"
)

// #14398 (DR9-H2): A RIP `authentication-type` WITH NO `authentication-key`
// IS NOT AN UNAUTHENTICATED PREFERENCE, and until this gate it was treated
// as one — the reverse direction of #9105 (key with no type).
//
// The compiler reads the two leaves independently
// (compiler_protocols.go), so either may be set without the other. The FRR
// renderer's whole per-interface auth block sits behind an
// `AuthKey != ""` guard, so with a type but no key nothing is emitted and
// no warning fires: the interface runs RIP with no authentication at all,
// while `show configuration` echoes the operator's `authentication-type
// md5` as if it were in force. Any LAN-adjacent peer can then form an
// unauthenticated adjacency and inject routes.
//
// SO THE FIX IS SPLIT, mirroring #9105's doctrine:
//
//   - HERE, strict: refuse a non-absent type with an empty key, so the
//     operator supplies the key. A config with neither leaf (no auth
//     chosen) remains legal; a keyed md5/simple/text config is unchanged.
//   - pkg/frr, always: fail closed for keyless-auth RIP interfaces on the
//     tolerant path — do not enroll the interface in RIP unauthenticated,
//     and warn loudly (#1960: the box still boots, the adjacency does not
//     silently run open).
//
// LENIENT WARNS RATHER THAN REJECTS (#1960). A config an older binary
// accepted must still boot; refusing it here would turn a silent
// unauthenticated adjacency into a failure to load.
//
// #15013 (A12-01): the same file also bounds the KEY length. FRR's
// `ip rip authentication string <key>` (ripd) accepts at most 16
// characters; Junos likewise caps a RIP `authentication-key` at 16.
// A 17+ character key committed clean (the schema leaf had no
// validator and no compiled gate bounded length), rendered verbatim,
// and ripd rejected the line on every frr-reload — a degraded retry
// that can never succeed, so every later commit reported
// non-convergence and RIP stayed down on enrolled interfaces.
// Strict rejects >16; lenient warns (#1960) and the renderer omits
// RIP enrollment for an over-long key rather than emitting a line
// ripd will reject forever. The bound is in characters (runes),
// matching the operator-visible length FRR counts.
const MaxRIPAuthKeyLen = 16

// ValidateRIPAuthKeyLength is the setSchema typed-leaf validator for
// `protocols rip authentication-key` (shared by the global and
// routing-instance copies via schemaProtocols). It rejects an empty
// value and any key longer than MaxRIPAuthKeyLen characters. The
// compiled gate validateRIPAuthKeyLengthStrict below is the backstop
// for values that bypass SchemaValidate (programmatic trees,
// tolerant loads downgraded to warnings).
func ValidateRIPAuthKeyLength(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("missing RIP authentication key (expected 1..%d characters)", MaxRIPAuthKeyLen)
	}
	if n := len([]rune(raw)); n > MaxRIPAuthKeyLen {
		return fmt.Errorf("RIP authentication key is %d characters, exceeding the %d-character maximum "+
			"accepted by FRR ripd (ip rip authentication string); a longer key is rejected on every "+
			"frr-reload and RIP never comes up — shorten the key to at most %d characters (#15013)",
			n, MaxRIPAuthKeyLen, MaxRIPAuthKeyLen)
	}
	return nil
}

// validateRIPAuthKeyLengthStrict rejects a compiled RIP key longer
// than MaxRIPAuthKeyLen, globally and per routing instance. Strict
// returns an error; lenient appends a warning and logs (never the
// key itself — only its length) so a persisted config still boots
// while pkg/frr withholds RIP enrollment for the over-long key.
func validateRIPAuthKeyLengthStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	report := func(scope string, rip *RIPConfig) error {
		n := len([]rune(rip.AuthKey.Reveal()))
		msg := fmt.Sprintf("%s: `authentication-key` is %d characters, exceeding the %d-character maximum "+
			"accepted by FRR ripd (ip rip authentication string); ripd rejects the rendered line on every "+
			"frr-reload, so the reload never converges and RIP stays down. Shorten the key to at most %d "+
			"characters (#15013)", scope, n, MaxRIPAuthKeyLen, MaxRIPAuthKeyLen)
		if lenient {
			slog.Warn("config: rip authentication-key exceeds the FRR 16-character maximum; RIP will not be enrolled for this key",
				"scope", scope, "key_len", n, "max", MaxRIPAuthKeyLen, "issue", "#15013")
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	check := func(scope string, rip *RIPConfig) error {
		if rip == nil || rip.AuthKey.Reveal() == "" {
			return nil
		}
		if len([]rune(rip.AuthKey.Reveal())) <= MaxRIPAuthKeyLen {
			return nil
		}
		return report(scope, rip)
	}
	if err := check("protocols rip", cfg.Protocols.RIP); err != nil {
		return warnings, err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		if err := check(fmt.Sprintf("routing-instance %s protocols rip", ri.Name), ri.RIP); err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}

func validateRIPAuthTypeRequiresKeyStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	report := func(scope string, rip *RIPConfig) error {
		msg := fmt.Sprintf("%s: `authentication-type %s` is configured with no "+
			"`authentication-key`, which renders RIP with NO authentication on the "+
			"wire — an unauthenticated peer can form an adjacency and inject routes. "+
			"Set `authentication-key` to provide the key, or remove "+
			"`authentication-type` to run RIP with no authentication deliberately (#14398)",
			scope, rip.AuthType)
		if lenient {
			slog.Warn("config: rip authentication-type with no authentication-key renders UNAUTHENTICATED",
				"scope", scope, "authentication_type", rip.AuthType, "issue", "#14398")
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	check := func(scope string, rip *RIPConfig) error {
		if rip == nil || AuthTypeAbsent(rip.AuthType) || rip.AuthKey.Reveal() != "" {
			return nil
		}
		return report(scope, rip)
	}
	if err := check("protocols rip", cfg.Protocols.RIP); err != nil {
		return warnings, err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		if err := check(fmt.Sprintf("routing-instance %s protocols rip", ri.Name), ri.RIP); err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}
