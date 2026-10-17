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
