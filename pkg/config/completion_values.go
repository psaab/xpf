package config

import "fmt"

// #16160 (schema R1): the live-value completion switch and the hint-roots
// table were duplicated in pkg/cli (valueProvider + hintRoots14988) and
// pkg/grpcapi (valueProvider + hintRoots) — ~200 lines each with the same
// 12 ValueHint arms, the same four catalogueSuppressed arms, and the same
// nil-slot guards. Drift had already started (stacked duplicate nil
// guards and divergent comments on the CLI copy), and every nil-shape
// panic fix (#3493/#3476/#5068/#5886) had to be applied twice. This file
// is the single shared implementation: ProvideValues is a pure function
// of the typed config, and HintRoots is the config-path data both authz
// wrappers consult. Snapshot acquisition (which config completes, and
// whether the predefined catalogue is suppressed) stays at the callers —
// completionConfig() is per-frontend store/candidate logic, so callers
// pass cfg and catalogueSuppressed in. No schema, wire, or
// authz-semantics change: a hint absent from HintRoots still fails
// closed in each frontend's providerHintAllowed.

// HintRoots maps a ValueHint to the config subtree(s) its live values
// are read from, in the space-joined spelling *-configuration regexes
// match (#14708). It is config-path data, not an authz decision: each
// frontend's authz wrapper consults it and still applies its own
// cursor-path and class checks. A hint absent from the map draws only on
// the cursor path itself (or on no configured data), so the cursor check
// suffices for it; unknown hints fail closed in providerHintAllowed.
var HintRoots = map[ValueHint][]string{
	ValueHintZoneName:      {"security zones"},
	ValueHintAddressName:   {"security address-book"},
	ValueHintAppName:       {"applications"},
	ValueHintAppSetName:    {"applications"},
	ValueHintPoolName:      {"security nat"},
	ValueHintInterfaceName: {"interfaces"},
	ValueHintScreenProfile: {"security screen"},
	ValueHintStreamName:    {"security log"},
	ValueHintPolicyAddress: {"security address-book"},
	ValueHintPolicyApp:     {"applications"},
	ValueHintPolicyName:    {"security policies"},
	ValueHintUnitNumber:    {"interfaces"},
}

// appendPredefinedApplicationSetCompletions appends the predefined
// application-set names not already present in out.
func appendPredefinedApplicationSetCompletions(out []SchemaCompletion) []SchemaCompletion {
	emitted := make(map[string]struct{}, len(out)+len(PredefinedApplicationSets))
	for _, candidate := range out {
		emitted[candidate.Name] = struct{}{}
	}
	for name := range PredefinedApplicationSets {
		if _, exists := emitted[name]; exists {
			continue
		}
		out = append(out, SchemaCompletion{
			Name: name,
			Desc: "predefined application-set",
		})
		emitted[name] = struct{}{}
	}
	return out
}

// ProvideValues returns the live completion values for hint drawn from
// cfg. It is a pure function of the typed config: cfg == nil returns nil
// (the callers' nil-store guards make that unreachable in production,
// but the seam test drives it directly), and present-but-nil map/slice
// slots admitted by the tolerant / HA-sync path (#3494) are skipped
// rather than dereferenced. catalogueSuppressed suppresses the
// predefined catalogue (predefined applications, predefined
// application-sets, and the PolicyApp "any" literal) until the first
// commit (#5763); callers compute it in completionConfig(). Unknown
// hints return nil.
func ProvideValues(cfg *Config, hint ValueHint, path []string, catalogueSuppressed bool) []SchemaCompletion {
	if cfg == nil {
		return nil
	}
	switch hint {
	case ValueHintZoneName:
		var out []SchemaCompletion
		for name, zone := range cfg.Security.Zones {
			if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
			desc := zone.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, SchemaCompletion{Name: name, Desc: desc})
		}
		return out
	case ValueHintAddressName:
		var out []SchemaCompletion
		if cfg.Security.AddressBook != nil {
			for _, addr := range cfg.Security.AddressBook.Addresses {
				out = append(out, SchemaCompletion{Name: addr.Name, Desc: addr.Value})
			}
			for _, as := range cfg.Security.AddressBook.AddressSets {
				out = append(out, SchemaCompletion{Name: as.Name, Desc: "address-set"})
			}
		}
		return out
	case ValueHintAppName:
		var out []SchemaCompletion
		for _, app := range cfg.Applications.Applications {
			out = append(out, SchemaCompletion{Name: app.Name, Desc: app.Description})
		}
		for _, as := range cfg.Applications.ApplicationSets {
			out = append(out, SchemaCompletion{Name: as.Name, Desc: "application-set"})
		}
		if catalogueSuppressed {
			return out
		}
		for name := range PredefinedApplications {
			out = append(out, SchemaCompletion{Name: name, Desc: "predefined"})
		}
		return appendPredefinedApplicationSetCompletions(out)
	case ValueHintAppSetName:
		var out []SchemaCompletion
		for _, as := range cfg.Applications.ApplicationSets {
			out = append(out, SchemaCompletion{Name: as.Name, Desc: "application-set"})
		}
		if catalogueSuppressed {
			return out
		}
		return appendPredefinedApplicationSetCompletions(out)
	case ValueHintPoolName:
		var out []SchemaCompletion
		for name := range cfg.Security.NAT.SourcePools {
			out = append(out, SchemaCompletion{Name: name, Desc: "source pool"})
		}
		if cfg.Security.NAT.Destination != nil {
			for name := range cfg.Security.NAT.Destination.Pools {
				out = append(out, SchemaCompletion{Name: name, Desc: "destination pool"})
			}
		}
		return out
	case ValueHintScreenProfile:
		var out []SchemaCompletion
		for name := range cfg.Security.Screen {
			out = append(out, SchemaCompletion{Name: name, Desc: "screen profile"})
		}
		return out
	case ValueHintStreamName:
		var out []SchemaCompletion
		for name := range cfg.Security.Log.Streams {
			out = append(out, SchemaCompletion{Name: name, Desc: "log stream"})
		}
		return out
	case ValueHintInterfaceName:
		var out []SchemaCompletion
		for name, iface := range cfg.Interfaces.Interfaces {
			// #5886/#5068: skip a present-but-nil interface value
			// (tolerant / HA-sync path admits it, #3494) rather than
			// dereferencing iface.Description and panicking.
			if iface == nil {
				continue
			}
			desc := iface.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, SchemaCompletion{Name: name, Desc: desc})
		}
		return out
	case ValueHintPolicyAddress:
		out := []SchemaCompletion{
			{Name: "any", Desc: "Any IPv4 or IPv6 address"},
			{Name: "any-ipv4", Desc: "Any IPv4 address"},
			{Name: "any-ipv6", Desc: "Any IPv6 address"},
		}
		if cfg.Security.AddressBook != nil {
			for _, addr := range cfg.Security.AddressBook.Addresses {
				out = append(out, SchemaCompletion{Name: addr.Name, Desc: addr.Value})
			}
			for _, as := range cfg.Security.AddressBook.AddressSets {
				out = append(out, SchemaCompletion{Name: as.Name, Desc: "address-set"})
			}
		}
		return out
	case ValueHintPolicyApp:
		var out []SchemaCompletion
		if !catalogueSuppressed {
			out = append(out, SchemaCompletion{Name: "any", Desc: "Any application"})
		}
		for _, app := range cfg.Applications.Applications {
			out = append(out, SchemaCompletion{Name: app.Name, Desc: app.Description})
		}
		for _, as := range cfg.Applications.ApplicationSets {
			out = append(out, SchemaCompletion{Name: as.Name, Desc: "application-set"})
		}
		if catalogueSuppressed {
			return out
		}
		for name := range PredefinedApplications {
			out = append(out, SchemaCompletion{Name: name, Desc: "predefined"})
		}
		return appendPredefinedApplicationSetCompletions(out)
	case ValueHintPolicyName:
		// Extract zone pair from path: ["security","policies","from-zone","X","to-zone","Y","policy"]
		// or global: ["security","policies","global","policy"]
		var policies []*Policy
		for i, tok := range path {
			if tok == "from-zone" && i+3 < len(path) && path[i+2] == "to-zone" {
				fromZone := path[i+1]
				toZone := path[i+3]
				for _, zpp := range cfg.Security.Policies {
					// #3476: skip a nil zone-pair set (tolerant / HA-sync
					// path) rather than dereferencing zpp.FromZone.
					if zpp == nil {
						continue
					}
					if zpp.FromZone == fromZone && zpp.ToZone == toZone {
						policies = zpp.Policies
						break
					}
				}
				break
			}
			if tok == "global" {
				policies = cfg.Security.GlobalPolicies
				break
			}
		}
		var out []SchemaCompletion
		for _, pol := range policies {
			// #3476: skip a nil policy (Policies / GlobalPolicies are
			// []*Policy) rather than dereferencing pol.Description.
			if pol == nil {
				continue
			}
			desc := pol.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, SchemaCompletion{Name: pol.Name, Desc: desc})
		}
		return out
	case ValueHintUnitNumber:
		// Find the interface name from the path context.
		var ifaceName string
		for i, tok := range path {
			if tok == "interfaces" && i+1 < len(path) {
				ifaceName = path[i+1]
				break
			}
		}
		if ifaceName == "" {
			return nil
		}
		iface := cfg.Interfaces.Interfaces[ifaceName]
		if iface == nil {
			return nil
		}
		var out []SchemaCompletion
		for num, unit := range iface.Units {
			// #5886/#5068: skip a present-but-nil unit value (tolerant
			// / HA-sync path admits it, #3494) rather than dereferencing
			// unit.Description and panicking.
			if unit == nil {
				continue
			}
			desc := unit.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, SchemaCompletion{Name: fmt.Sprintf("%d", num), Desc: desc})
		}
		return out
	}
	return nil
}
