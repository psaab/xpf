package sysservices

import "testing"

func TestParseSSHDUnitStates17770(t *testing.T) {
	for _, tc := range []struct {
		name       string
		serviceOut string
		socketOut  string
		want       SSHDState
	}{
		{"service active", "loaded\nactive\nrunning\n", "", SSHDRunning},
		{"socket activated", "loaded\ninactive\ndead\n", "loaded\nactive\nlistening\n", SSHDRunningSocketActivated},
		{"inactive service and socket", "loaded\ninactive\ndead\n", "loaded\ninactive\ndead\n", SSHDStopped},
		{"inactive service and absent socket", "loaded\ninactive\ndead\n", "not-found\ninactive\ndead\n", SSHDStopped},
		{"failed service and inactive socket", "loaded\nfailed\nfailed\n", "loaded\ninactive\ndead\n", SSHDStopped},
		{"failed service and listening socket", "loaded\nfailed\nfailed\n", "loaded\nactive\nlistening\n", SSHDUnknown},
		{"inactive service and unexpected active socket", "loaded\ninactive\ndead\n", "loaded\nactive\nrunning\n", SSHDUnknown},
		{"inactive service and unknown socket", "loaded\ninactive\ndead\n", "error\nactive\nlistening\n", SSHDUnknown},
		{"missing service and listening socket", "not-found\ninactive\ndead\n", "loaded\nactive\nlistening\n", SSHDUnknown},
		{"missing service", "not-found\ninactive\ndead\n", "loaded\ninactive\ndead\n", SSHDUnknown},
		{"activating service", "loaded\nactivating\nstart\n", "loaded\ninactive\ndead\n", SSHDUnknown},
		{"malformed socket output", "loaded\ninactive\ndead\n", "loaded\n", SSHDUnknown},
		{"malformed service output", "loaded\n", "loaded\nactive\nlistening\n", SSHDUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseSSHDUnitStates(tc.serviceOut, tc.socketOut); got != tc.want {
				t.Fatalf("parseSSHDUnitStates(%q, %q) = %v, want %v",
					tc.serviceOut, tc.socketOut, got, tc.want)
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
		{SSHDRunningSocketActivated, "  SSH:            running (socket-activated) (not managed — no system services ssh; ssh.socket listens under base-image defaults)"},
		{SSHDStopped, "  SSH:            stopped (not managed — no system services ssh)"},
		{SSHDUnknown, "  SSH:            unknown (not managed — no system services ssh)"},
		{SSHDState(255), "  SSH:            unknown (not managed — no system services ssh)"},
	} {
		if got := UnmanagedSSHLine(tc.state); got != tc.want {
			t.Errorf("UnmanagedSSHLine(%v) = %q, want %q", tc.state, got, tc.want)
		}
	}
}
