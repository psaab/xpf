package sysservices

import "testing"

func TestParseSSHDUnitState17770(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		want SSHDState
	}{
		{"active", "loaded\nactive\n", SSHDRunning},
		{"inactive", "loaded\ninactive\n", SSHDStopped},
		{"failed", "loaded\nfailed\n", SSHDStopped},
		{"masked and inactive", "masked\ninactive\n", SSHDStopped},
		{"unit missing", "not-found\ninactive\n", SSHDUnknown},
		{"activating", "loaded\nactivating\n", SSHDUnknown},
		{"unexpected load state", "error\nactive\n", SSHDUnknown},
		{"malformed output", "loaded\n", SSHDUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseSSHDUnitState(tc.out); got != tc.want {
				t.Fatalf("parseSSHDUnitState(%q) = %v, want %v", tc.out, got, tc.want)
			}
		})
	}
}

func TestUnmanagedSSHLine17770(t *testing.T) {
	for _, tc := range []struct {
		state SSHDState
		want  string
	}{
		{SSHDRunning, "  SSH:            running (not managed — no system services ssh; sshd serves under base-image defaults)"},
		{SSHDStopped, "  SSH:            stopped (not managed — no system services ssh)"},
		{SSHDUnknown, "  SSH:            unknown (not managed — no system services ssh)"},
		{SSHDState(255), "  SSH:            unknown (not managed — no system services ssh)"},
	} {
		if got := UnmanagedSSHLine(tc.state); got != tc.want {
			t.Errorf("UnmanagedSSHLine(%v) = %q, want %q", tc.state, got, tc.want)
		}
	}
}
