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
// operator supplies a key or removes the authentication stanza.
// #15715 narrows the rollover rule: when AuthMD5Keys is populated, EVERY
// configured entry must be non-empty — an empty/keyless entry beside a
// valid one is an incomplete rollover stanza Junos rejects per-entry,
// and the renderer would silently drop it. The legacy single-key view
// (AuthMD5Keys empty, e.g. directly constructed configs) still passes
// on a non-empty AuthKey. Lenient (#1960) warns instead of rejecting so
// an already-persisted or peer-synced config still boots; the renderer
// belt in pkg/frr then omits the keyless-auth interface rather than
// activating it unauthenticated.
func validateOSPFAuthKeyPresenceStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	report := func(scope, areaID string, iface *OSPFInterface, emptyKeyID int, hasEmpty bool) error {
		var msg string
		if iface.AuthType == "md5" && hasEmpty {
			msg = fmt.Sprintf("%sprotocols ospf area %s interface %s authentication md5 %d key is empty: "+
				"every configured md5 key must carry a non-empty key, so the incomplete rollover "+
				"entry would be silently dropped — set `authentication md5 %d key <secret>` with a "+
				"non-empty key, or remove that md5 entry (#15715)",
				scope, areaID, iface.Name, emptyKeyID, emptyKeyID)
		} else if iface.AuthType == "md5" {
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
					if len(iface.AuthMD5Keys) > 0 {
						// #15715: every configured entry must carry a
						// key. An empty entry beside a valid one is not
						// a valid rollover — Junos requires the key
						// statement per md5 entry, and the renderer
						// would silently drop the empty entry.
						for _, key := range iface.AuthMD5Keys {
							if key.Key.Reveal() == "" {
								if err := report(scope, area.ID, iface, key.ID, true); err != nil {
									return err
								}
								break
							}
						}
					} else if iface.AuthKey == "" {
						if err := report(scope, area.ID, iface, 0, false); err != nil {
							return err
						}
					}
				case "simple":
					if iface.AuthKey == "" {
						if err := report(scope, area.ID, iface, 0, false); err != nil {
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
