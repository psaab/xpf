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

func recordUnknownSecurityZoneChild11575(zone *ZoneConfig, keyword string) {
	if zone == nil || keyword == "" || zoneInterfaceApplyMetaKeyword(keyword) {
		return
	}
	for _, existing := range zone.UnknownZoneChildren {
		if existing == keyword {
			return
		}
	}
	zone.UnknownZoneChildren = append(zone.UnknownZoneChildren, keyword)
	if enforcementBearingUnknownZoneChild11575(keyword) {
		zone.DroppedEnforcementChild = true
	}
}

// The zone child grammar's enforcement-bearing names are screen (IDS),
// interface membership, host-inbound policy, TCP-RST, and address-book. A
// two-edit bound catches short operator typos; matching case-insensitively and
// recognizing three-or-more-character prefixes also catches common Junos
// keyword truncations without treating arbitrary metadata as enforcement.
func enforcementBearingUnknownZoneChild11575(keyword string) bool {
	if containsZoneKeyword11575(keyword, "screen") || containsZoneKeyword11575(keyword, "ids") {
		return true
	}
	for _, supported := range [...]string{"screen", "interfaces", "host-inbound-traffic", "tcp-rst", "address-book"} {
		if zoneKeywordDistanceAtMostTwo11575(keyword, supported) ||
			zoneKeywordPrefixAtLeastThree11575(keyword, supported) {
			return true
		}
	}
	return false
}

// zoneKeywordPrefixAtLeastThree11575 recognizes a plausible truncated
// enforcement keyword, including "scr" for "screen" and "host-inbound" for
// "host-inbound-traffic". Requiring a three-byte prefix avoids poisoning a
// zone for generic one- or two-character unknown metadata.
func zoneKeywordPrefixAtLeastThree11575(prefix, supported string) bool {
	if len(prefix) < 3 || len(prefix) >= len(supported) {
		return false
	}
	for i := range len(prefix) {
		if zoneKeywordByteFold11575(prefix[i]) != zoneKeywordByteFold11575(supported[i]) {
			return false
		}
	}
	return true
}

func containsZoneKeyword11575(value, part string) bool {
	if len(part) > len(value) {
		return false
	}
	for i := range len(value) - len(part) + 1 {
		matches := true
		for j := range len(part) {
			if zoneKeywordByteFold11575(value[i+j]) != zoneKeywordByteFold11575(part[j]) {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func zoneKeywordByteFold11575(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}

func zoneKeywordDistanceAtMostTwo11575(a, b string) bool {
	if len(a) > 31 || len(b) > 31 || len(a)-len(b) > 2 || len(b)-len(a) > 2 {
		return false
	}
	var row [32]uint8
	for j := range len(b) + 1 {
		row[j] = uint8(j)
	}
	for i := range len(a) {
		diagonal := row[0]
		row[0] = uint8(i + 1)
		rowMin := row[0]
		for j := range len(b) {
			above := row[j+1]
			cost := uint8(1)
			if zoneKeywordByteFold11575(a[i]) == zoneKeywordByteFold11575(b[j]) {
				cost = 0
			}
			deletion := row[j+1] + 1
			insertion := row[j] + 1
			substitution := diagonal + cost
			best := deletion
			if insertion < best {
				best = insertion
			}
			if substitution < best {
				best = substitution
			}
			row[j+1] = best
			diagonal = above
			if best < rowMin {
				rowMin = best
			}
		}
		if rowMin > 2 {
			return false
		}
	}
	return row[len(b)] <= 2
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
