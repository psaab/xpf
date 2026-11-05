package cli

import (
	"strings"
	"testing"
)

// TestCheckPermission_DestructiveMaintenanceRequiresMaint pins #4108 F21 and
// #16016: the destructive `request system {reboot,halt,power-off,zeroize}`,
// `request chassis cluster failover` (including force-primary), and local
// `request chassis cluster unkeyed-grace restart` verbs require PermMaint.
// `operator` (which holds PermControl) is DENIED, matching Junos where the
// predefined operator class lacks `maintenance`; only `super-user` is allowed.
// Reverting the gate to plain PermControl would allow the operator subtests.
func TestCheckPermission_DestructiveMaintenanceRequiresMaint(t *testing.T) {
	destructive := [][]string{
		{"request", "system", "reboot"},
		{"request", "system", "halt"},
		{"request", "system", "power-off"},
		{"request", "system", "zeroize"},
		{"request", "chassis", "cluster", "failover", "redundancy-group", "1", "node", "0"},
		{"request", "chassis", "cluster", "failover", "data", "node", "0"},
		{"request", "chassis", "cluster", "failover", "force-primary", "redundancy-group", "1", "override", "unkeyed-recovery"},
		{"request", "chassis", "cluster", "unkeyed-grace", "restart"},
	}

	tests := []struct {
		class string
		allow bool // destructive maintenance allowed?
	}{
		{"super-user", true},
		{"operator", false},
		{"read-only", false},
		{"config-viewer", false},
		{"unauthorized", false},
	}

	for _, tc := range tests {
		t.Run(tc.class, func(t *testing.T) {
			c := &CLI{userClass: tc.class}
			for _, parts := range destructive {
				err := c.checkPermission(parts)
				cmd := strings.Join(parts, " ")
				if tc.allow && err != nil {
					t.Errorf("%q denied for %q: %v (want allowed)", cmd, tc.class, err)
				}
				if !tc.allow && err == nil {
					t.Errorf("%q ALLOWED for %q (want denied — destructive maintenance)", cmd, tc.class)
				}
			}
		})
	}
}

// TestCheckPermission_DestructiveMaintenanceAbbreviationCannotBypass asserts
// the gate resolves prefixes the same way the dispatcher does, so an
// abbreviated destructive verb (`request system zero`, `request sys reboot`)
// is gated identically to the fully-spelled form and cannot slip past as plain
// control. operator must stay DENIED on every abbreviation.
func TestCheckPermission_DestructiveMaintenanceAbbreviationCannotBypass(t *testing.T) {
	op := &CLI{userClass: "operator"}
	abbrev := [][]string{
		{"request", "system", "zero"}, // zeroize
		{"request", "system", "reb"},  // reboot
		{"request", "sys", "halt"},    // system halt
		{"request", "sys", "power"},   // system power-off
		{"request", "chassis", "cluster", "fail", "data", "node", "1"},
		{"request", "chassis", "cluster", "unkeyed-g", "restart"},
	}
	for _, parts := range abbrev {
		if err := op.checkPermission(parts); err == nil {
			t.Errorf("operator ALLOWED %q (abbreviation bypassed the maintenance gate)", strings.Join(parts, " "))
		}
	}
	// super-user is allowed via the same abbreviations.
	su := &CLI{userClass: "super-user"}
	for _, parts := range abbrev {
		if err := su.checkPermission(parts); err != nil {
			t.Errorf("super-user denied %q: %v (want allowed)", strings.Join(parts, " "), err)
		}
	}
}

// TestCheckPermission_BenignRequestStaysControlForOperator asserts the gate is
// surgical: operator keeps the BENIGN request verbs at PermControl — the
// destructive `request system` verbs, cluster failover, ISSU drain, and the
// destructive userspace-dataplane disarm/unregister verbs elevate (see the
// #4859 test), but the restorative dataplane verbs and the rest of the request
// family do NOT. This guards against over-gating operator out of its legitimate
// control commands.
func TestCheckPermission_BenignRequestStaysControlForOperator(t *testing.T) {
	op := &CLI{userClass: "operator"}
	benign := [][]string{
		{"request", "system", "configuration", "rescue", "save"},
		{"request", "system", "dynamic-dns", "update"},
		{"request", "security", "ipsec", "sa", "clear"},
		// Restorative dataplane verbs stay at PermControl.
		{"request", "chassis", "cluster", "data-plane", "userspace", "forwarding", "arm"},
		{"request", "chassis", "cluster", "data-plane", "userspace", "queue", "3", "register"},
		{"request", "chassis", "cluster", "data-plane", "userspace", "queue", "3", "arm"},
		{"request", "chassis", "cluster", "data-plane", "userspace", "binding", "slot", "2", "register"},
		{"request", "protocols", "bgp", "clear"},
	}
	for _, parts := range benign {
		if err := op.checkPermission(parts); err != nil {
			t.Errorf("operator DENIED benign request %q: %v (want allowed — control-level)", strings.Join(parts, " "), err)
		}
	}
}
