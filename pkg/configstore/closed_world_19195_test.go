package configstore

import (
	"strings"
	"testing"
)

// #19195: instance-name container bodies that accepted an unknown keyword at
// commit and are now closedWorld (generate route, global and routing-instance;
// syslog time-format). The third blind member, ntp authentication-key, stays
// open by design: the knob is inert, and closing it refuses the one-line Junos
// form (see schema_system.go). Each row is measured end to end: the valid
// body commits (the TRUE twin), and the same body with `xpfbogus 5` placed
// EXPLICITLY inside the member's own braces is refused. (An earlier probe
// inserted the marker at the fixture's first brace and so measured a parent
// body instead; the explicit placement is the point.)
func TestNewlyClosedInstanceBodiesRejectUnknownKeywords19195(t *testing.T) {
	for _, c := range []struct{ name, valid, bogus string }{
		{"routing-options generate route",
			"routing-options { generate { route 10.0.0.0/8 { discard; } } }",
			"routing-options { generate { route 10.0.0.0/8 { discard; xpfbogus 5; } } }"},
		{"routing-instances generate route",
			"routing-instances { ri1 { routing-options { generate { route 10.0.0.0/8 { discard; } } } } }",
			"routing-instances { ri1 { routing-options { generate { route 10.0.0.0/8 { discard; xpfbogus 5; } } } } }"},
		{"system syslog time-format",
			"system { syslog { time-format fmt { year; } } }",
			"system { syslog { time-format fmt { year; xpfbogus 5; } } }"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := CheckText(c.valid, -1); err != nil {
				t.Fatalf("valid body refused: %v", err)
			}
			_, err := CheckText(c.bogus, -1)
			if err == nil || !strings.Contains(err.Error(), "xpfbogus") {
				t.Fatalf("an unknown keyword in the %s body committed clean (err=%v)", c.name, err)
			}
		})
	}
}
