package config

import "fmt"

// validateLLDPAllDisableWarning makes `protocols lldp interface all
// disable` loud at commit time (#14617).
//
// Junos `interface all` means "every managed interface, with
// per-interface disable overriding". xpf now expands `all` at LLDP
// apply time to every kernel-enumerated interface minus the disabled
// ones. But `interface all { disable; }` has no such meaning: expanding
// it would silently silence LLDP everywhere — exactly the inversion
// that made the plain `all` lookup defect dangerous. The daemon
// refuses the combination (stops LLDP, warns); this advisory names it
// at commit so the operator learns before commit, not from a missing
// neighbor table.
//
// Advisory, not a hard gate, for the #1960 reason shared with #9405:
// the tolerant load / HA config-sync paths must still accept a
// persisted config an older binary committed. Only the exact
// lower-case `all` is the wildcard; interface names are
// case-sensitive, so `All` is an ordinary (unresolved) name, not
// this finding.
func validateLLDPAllDisableWarning(cfg *Config) []string {
	if cfg == nil || cfg.Protocols.LLDP == nil {
		return nil
	}
	for _, iface := range cfg.Protocols.LLDP.Interfaces {
		if iface.Name == "all" && iface.Disable {
			return []string{fmt.Sprintf(
				"protocols lldp interface all disable: `interface all disable` is not supported — " +
					"it would expand to disabling LLDP on every interface. Use `protocols lldp disable` " +
					"for a global disable, or `interface all` with per-interface `disable` entries (#14617).")}
		}
	}
	return nil
}
