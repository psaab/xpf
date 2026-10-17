package config

import (
	"fmt"
	"log/slog"
)

// #14399 (DR9-H3): IS-IS `authentication-type` WITHOUT `authentication-key`
// renders unauthenticated — the reverse of #9105 (key without type).
//
// The compiler reads type and key as independent leaves at the area/domain
// level and per interface (compiler_protocols.go). Both FRR render blocks
// are gated on a non-empty key, and the absent/unrecognized-type warnings
// live INSIDE that guard, so a type with no key emits nothing and warns
// nothing: the operator affirmatively selected md5 (or simple), yet the
// adjacency forms with no authentication at all. #9105 cannot see this
// direction — it fires only when a key is present.
//
// Strict rejects so the operator supplies the key; lenient warns (#1960)
// so a persisted/peer-synced config still boots, and the FRR renderer
// warns at both IS-IS sites on that path. Keyed md5/simple and
// neither-leaf configs are untouched. Routing-instance IS-IS is compiled
// through the same compileProtocols and rendered through the same
// generateProtocols, so it is gated here too; #14400 owns the distinct
// RI key-without-type (#9105) gap and is not folded in.
func validateISISAuthTypeRequiresKeyStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	report := func(scope, authType string) error {
		msg := fmt.Sprintf("%s: `authentication-type %s` is configured with no "+
			"`authentication-key`, which renders IS-IS UNAUTHENTICATED — no "+
			"area/domain or interface password is emitted, so any adjacent peer "+
			"can form an adjacency. Set `authentication-key` at the same level, "+
			"or remove `authentication-type` to state no authentication "+
			"deliberately (#14399)", scope, authType)
		if lenient {
			slog.Warn("config: isis authentication-type with no authentication-key renders UNAUTHENTICATED",
				"scope", scope, "authentication_type", authType, "issue", "#14399")
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	check := func(scope string, isis *ISISConfig) error {
		if isis == nil {
			return nil
		}
		if !AuthTypeAbsent(isis.AuthType) && isis.AuthKey.Reveal() == "" {
			if err := report(scope+"protocols isis", isis.AuthType); err != nil {
				return err
			}
		}
		for _, iface := range isis.Interfaces {
			if iface == nil || AuthTypeAbsent(iface.AuthType) || iface.AuthKey.Reveal() != "" {
				continue
			}
			if err := report(scope+"protocols isis interface "+iface.Name, iface.AuthType); err != nil {
				return err
			}
		}
		return nil
	}
	if err := check("", cfg.Protocols.ISIS); err != nil {
		return warnings, err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		if err := check(fmt.Sprintf("routing-instance %q ", ri.Name), ri.ISIS); err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}
