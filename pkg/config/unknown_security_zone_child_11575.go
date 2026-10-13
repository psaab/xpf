package config

import (
	"errors"
	"fmt"
)

type unknownSecurityZoneChildSchemaError struct {
	path    string
	keyword string
}

func (e *unknownSecurityZoneChildSchemaError) Error() string {
	return fmt.Sprintf("%s: unknown configuration keyword %q under closed-world subtree", e.path, e.keyword)
}

// IsUnknownSecurityZoneChildSchemaError reports whether err is the strict
// closed-world rejection for a direct child of security-zone. Store.Load and
// Store.SyncApply use it to preserve the zone-specific warning on tolerant
// ingestion rather than leaving the schema violation only in slog.
func IsUnknownSecurityZoneChildSchemaError(err error) bool {
	var target *unknownSecurityZoneChildSchemaError
	return errors.As(err, &target)
}

func recordUnknownSecurityZoneChild11575(zone *ZoneConfig, keys []string) {
	if zone == nil || len(keys) == 0 || keys[0] == "" || zoneInterfaceApplyMetaKeyword(keys[0]) {
		return
	}
	keyword := keys[0]
	for _, existing := range zone.UnknownZoneChildren {
		if existing == keyword {
			zone.DroppedEnforcementChild = true
			return
		}
	}
	zone.UnknownZoneChildren = append(zone.UnknownZoneChildren, keyword)
	// The tolerant grammar cannot know whether an unknown keyword carries
	// enforcement. Keep loading for #1960, but quarantine the entire zone.
	zone.DroppedEnforcementChild = true
}

func toleratedUnknownSecurityZoneChildWarnings11575(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var warnings []string
	for _, name := range sortedZoneNames(cfg) {
		zone := cfg.Security.Zones[name]
		if zone == nil {
			continue
		}
		for _, keyword := range zone.UnknownZoneChildren {
			if zone.DroppedEnforcementChild {
				warnings = append(warnings, fmt.Sprintf(
					"security zone %q: unknown child keyword %q was dropped; the zone is unbound because the keyword may configure enforcement (tolerant path)",
					name, keyword))
			} else {
				warnings = append(warnings, fmt.Sprintf(
					"security zone %q: unknown child keyword %q was dropped (tolerant path; strict commit rejects this)",
					name, keyword))
			}
		}
	}
	return warnings
}

// ToleratedUnknownSecurityZoneChildWarnings returns deterministic diagnostics
// for unknown security-zone children recorded by compileZones. Both the
// compiler gate and Store.Load/Store.SyncApply use this source so HA-tolerant
// compilation cannot silently discard the warning.
func ToleratedUnknownSecurityZoneChildWarnings(cfg *Config) []string {
	return toleratedUnknownSecurityZoneChildWarnings11575(cfg)
}

func validateUnknownSecurityZoneChild11575(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for _, name := range sortedZoneNames(cfg) {
		zone := cfg.Security.Zones[name]
		if zone == nil || len(zone.UnknownZoneChildren) == 0 {
			continue
		}
		return fmt.Errorf("security zone %q: unknown child keyword %q is not supported and would be silently dropped", name, zone.UnknownZoneChildren[0])
	}
	return nil
}
