package config_test

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestJunosHHMMEqualSchedulerBoundsStillWarn11305(t *testing.T) {
	cfg := compileHierStrict11305(t, "schedulers { scheduler equal { daily { start-time 09:00; stop-time 09:00; } } }")
	for _, warning := range config.ValidateConfig(cfg) {
		if strings.Contains(warning, "start-time == stop-time") && strings.Contains(warning, "\"equal\"") {
			return
		}
	}
	t.Fatal("equal HH:MM scheduler bounds did not warn that the window matches nothing")
}
