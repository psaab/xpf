package config

import (
	"fmt"
	"sort"
)

// snmpPrivacyDESWarnings9917 warns for every USM user configured with
// single-DES privacy (#9917 F-136). DES (56-bit effective strength) stays
// offered for Junos compatibility but is deprecated; the warning steers to
// AES-128. Advisory only — DES keeps working — because the cipher is
// operator-selected.
//
// Keyed on the COMPILED user table so every spelling (flat set, braced block,
// packed run) warns uniformly. Runs inside ValidateConfig, so the operator sees
// it at commit (runTailGates folds ValidateConfig into cfg.Warnings) and it
// persists on show system alarms like the hmac-md5 precedent.
func snmpPrivacyDESWarnings9917(cfg *Config) []string {
	if cfg == nil || cfg.System.SNMP == nil {
		return nil
	}
	var names []string
	for name, u := range cfg.System.SNMP.V3Users {
		if u == nil {
			continue
		}
		if u.PrivProtocol == "des" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	warnings := make([]string, 0, len(names))
	for _, name := range names {
		warnings = append(warnings, fmt.Sprintf("snmp v3 usm local-engine user %q uses privacy-des (single DES, 56-bit effective strength, deprecated); prefer privacy-aes128 (#9917)", name))
	}
	return warnings
}
