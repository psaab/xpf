package config

import (
	"fmt"
	"log/slog"
)

// #14397 (DR9-H1): an OSPF authentication TYPE with no KEY is not
// authentication at all.
//
// The compiler sets AuthType="md5" unconditionally on seeing the `md5`
// child and appends the key entry even when the `key` child is absent
// (Key == ""); `simple-password ""` likewise sets AuthType="simple" with
// an empty AuthKey. Before this gate no validator rejected the keyless
// selection — validateOSPFMD5KeyIDs11794 checks key-IDs only, and
// validateFRRAuthValuesStrict explicitly skips empty secrets — and the
// FRR renderer silently dropped the empty keys, so ospfd ran the
// interface with NO authentication while the commit succeeded with no
// warning. Any LAN-adjacent peer could then form an adjacency and inject
// LSAs area-wide.
//
// Strict rejects the keyless selection, naming area and interface, so the
// operator supplies a key or removes the authentication stanza. A
// rollover mix carrying at least one non-empty MD5 key stays valid
// (at-least-one-non-empty-key rule); the renderer skips the empty
// entries. Lenient (#1960) warns instead of rejecting so an
// already-persisted or peer-synced config still boots; the renderer
// belt in pkg/frr then omits the keyless-auth interface rather than
// activating it unauthenticated.
func validateOSPFAuthKeyPresenceStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	report := func(scope, areaID string, iface *OSPFInterface) error {
		var msg string
		if iface.AuthType == "md5" {
			msg = fmt.Sprintf("%sprotocols ospf area %s interface %s authentication md5 is configured "+
				"with no key: every md5 key is empty, so the interface would run with NO "+
				"authentication — set `authentication md5 <key-id> key <secret>` with a "+
				"non-empty key, or remove the authentication stanza (#14397)",
				scope, areaID, iface.Name)
		} else {
			msg = fmt.Sprintf("%sprotocols ospf area %s interface %s authentication simple-password "+
				"is configured with no key (empty password), so the interface would run with NO "+
				"authentication — set a non-empty simple-password, or remove the "+
				"authentication stanza (#14397)",
				scope, areaID, iface.Name)
		}
		if lenient {
			slog.Warn("config: OSPF authentication configured with no key renders NO authentication",
				"scope", scope, "area", areaID, "interface", iface.Name,
				"authentication_type", iface.AuthType, "issue", "#14397")
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
					hasKey := iface.AuthKey != ""
					for _, key := range iface.AuthMD5Keys {
						if key.Key != "" {
							hasKey = true
							break
						}
					}
					if !hasKey {
						if err := report(scope, area.ID, iface); err != nil {
							return err
						}
					}
				case "simple":
					if iface.AuthKey == "" {
						if err := report(scope, area.ID, iface); err != nil {
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
