package config

import "fmt"

// #15269 helpers shared by show surfaces so they cannot drift.

// SyslogZoneNames returns the zone-id -> name map for syslog/EventReader
// use: SurvivorZoneNames over buildZoneIDs-equivalent StableZoneID ids.
// Quarantine-aware (collision loser / reserved names never claim an id),
// matching cli.syslogZoneNameMap semantics via the shared survivor helper.
func SyslogZoneNames(cfg *Config) map[uint16]string {
	if cfg == nil {
		return map[uint16]string{}
	}
	ids := make(map[string]uint16, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		ids[name] = StableZoneID(name)
	}
	return SurvivorZoneNames(ids, cfg)
}

// TerseUnitDisabled reports whether logical unit physName.unitNum is
// administratively disabled for `show interfaces terse`: interface-level
// Disable disables every unit, otherwise the unit's own Disable (#14575).
// Nil-safe via LookupInterface/LookupUnit.
func TerseUnitDisabled(cfg *Config, physName string, unitNum int) bool {
	if cfg == nil {
		return false
	}
	ifc, ok := LookupInterface(cfg, physName)
	if !ok || ifc == nil {
		return false
	}
	if ifc.Disable {
		return true
	}
	unit, ok := LookupUnit(ifc, unitNum)
	return ok && unit != nil && unit.Disable
}

// ApplicationTermSuffix renders the optional application qualifiers the
// gRPC text renderer carries after dst-port (#12903/#15269 C09-03):
// src-port, icmp-type, icmp-code, timeout (never / Ns), in that order,
// each prefixed with a space. Empty when none apply. Shared so REST,
// gRPC and any text twin cannot drift.
func ApplicationTermSuffix(app *Application) string {
	if app == nil {
		return ""
	}
	s := ""
	if app.SourcePort != "" {
		s += fmt.Sprintf(" src-port=%s", app.SourcePort)
	}
	if app.ICMPType != nil {
		s += fmt.Sprintf(" icmp-type=%d", *app.ICMPType)
	}
	if app.ICMPCode != nil {
		s += fmt.Sprintf(" icmp-code=%d", *app.ICMPCode)
	}
	if app.InactivityTimeoutNever {
		s += " timeout=never"
	} else if app.InactivityTimeout > 0 {
		s += fmt.Sprintf(" timeout=%ds", app.InactivityTimeout)
	}
	return s
}
