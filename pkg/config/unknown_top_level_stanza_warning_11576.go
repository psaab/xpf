package config

import (
	"fmt"
	"strings"
)

// ToleratedUnknownTopLevelStanzaWarningPrefix identifies an unknown root
// stanza ignored by tolerant compilation. It is stable for active-config
// warning and status surfaces.
const ToleratedUnknownTopLevelStanzaWarningPrefix = "[unknown-stanza-tolerated]"

// ToleratedUnknownTopLevelStanzaWarning formats a schema rejection for a
// lenient load/peer-sync warning.
func ToleratedUnknownTopLevelStanzaWarning(err error) string {
	return fmt.Sprintf("%s %s (strict commit would reject this; issue #11576)",
		ToleratedUnknownTopLevelStanzaWarningPrefix, err.Error())
}

// ToleratedUnknownTopLevelStanzaWarnings returns only persisted unknown-root
// schema warnings, excluding unrelated compiler advisories.
func ToleratedUnknownTopLevelStanzaWarnings(cfg *Config) []string {
	if cfg == nil || len(cfg.Warnings) == 0 {
		return nil
	}
	prefix := ToleratedUnknownTopLevelStanzaWarningPrefix + " "
	var warnings []string
	for _, warning := range cfg.Warnings {
		if strings.HasPrefix(warning, prefix) {
			warnings = append(warnings, warning)
		}
	}
	return warnings
}
