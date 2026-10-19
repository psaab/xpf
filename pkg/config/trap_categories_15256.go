package config

// #15256 A85-02: Junos `snmp trap-group <g> categories` vocabulary.
// SSOT shared by the schema enum (schema_system.go mirrors this list)
// and the compiler gate in compileSNMP (direct CompileConfig callers).
// xpf emits only the `link` category today (pkg/snmp/traps.go
// snmpCategoryLink); the rest are valid Junos tokens that currently
// scope a group to zero emitted traps — warned, not rejected.
var junosTrapCategories15256 = []string{
	"authentication", "chassis", "chassis-cluster", "configuration",
	"link", "otn-alarms", "remote-operations", "rmon-alarm", "routing",
	"services", "sonet-alarms", "startup", "timing-events", "vrrp-events",
}

func validTrapCategory15256(lowerTrimmed string) bool {
	for _, c := range junosTrapCategories15256 {
		if c == lowerTrimmed {
			return true
		}
	}
	return false
}
