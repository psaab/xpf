package api

import "testing"

// indexOf returns the index of want in argv, or -1 if absent.
func indexOf(argv []string, want string) int {
	for i, a := range argv {
		if a == want {
			return i
		}
	}
	return -1
}

// assertSeparatorBeforeTarget checks the option-confusion hardening
// invariant (#2084): a "--" end-of-options separator must appear in the
// argv and the user-supplied target must be the element immediately
// after it, and the last element.
func assertSeparatorBeforeTarget(t *testing.T, argv []string, target string) {
	t.Helper()
	sep := indexOf(argv, "--")
	if sep < 0 {
		t.Fatalf("argv %v: missing \"--\" end-of-options separator", argv)
	}
	if sep+1 >= len(argv) {
		t.Fatalf("argv %v: \"--\" has no following operand", argv)
	}
	if argv[sep+1] != target {
		t.Fatalf("argv %v: target %q is not immediately after \"--\" (got %q)", argv, target, argv[sep+1])
	}
	if sep+1 != len(argv)-1 {
		t.Fatalf("argv %v: target is not the final argv element", argv)
	}
}

func TestBuildPingArgvSeparator(t *testing.T) {
	tests := []struct {
		name string
		req  PingRequest
		want string
	}{
		{"plain target", PingRequest{Target: "192.0.2.1"}, "192.0.2.1"},
		{"dash-prefixed target", PingRequest{Target: "-I"}, "-I"},
		{"with source and size", PingRequest{Target: "-f", Source: "10.0.0.1", Size: 1400}, "-f"},
		{"with routing instance", PingRequest{Target: "-c", RoutingInstance: "blue"}, "-c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argv := buildPingArgv(tt.req, 5)
			assertSeparatorBeforeTarget(t, argv, tt.want)
			ping := indexOf(argv, "ping")
			if ping < 0 || ping > indexOf(argv, "--") {
				t.Fatalf("argv %v: ping must be present and precede the separator", argv)
			}
		})
	}
}

func TestBuildPingArgvVRFInnerSeparator(t *testing.T) {
	argv := buildPingArgv(PingRequest{Target: "-bad", RoutingInstance: "red"}, 5)
	if indexOf(argv, "ip") != 0 {
		t.Fatalf("argv %v: VRF wrapper must lead the argv", argv)
	}
	if indexOf(argv, "vrf-red") < 0 {
		t.Fatalf("argv %v: missing vrf-red device", argv)
	}
	ping := indexOf(argv, "ping")
	sep := indexOf(argv, "--")
	if ping < 0 || sep < 0 || sep < ping {
		t.Fatalf("argv %v: separator must follow ping in the inner command", argv)
	}
	assertSeparatorBeforeTarget(t, argv, "-bad")
}

// TestBuildPingArgvVRFNoDoublePrefix locks the #16664 mapping on the
// REST surface: instance N maps to "vrf-"+N unconditionally, so a bare
// "red" gets "vrf-red" and instance "vrf-red" gets "vrf-vrf-red" (the
// #2143 exactly-once guard probed sibling instance "red").
func TestBuildPingArgvVRFNoDoublePrefix(t *testing.T) {
	tests := []struct {
		name    string
		vrf     string
		wantDev string
	}{
		{"bare name gets one prefix", "red", "vrf-red"},
		{"vrf-prefixed instance gets prefix again", "vrf-red", "vrf-vrf-red"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argv := buildPingArgv(PingRequest{Target: "192.0.2.1", RoutingInstance: tt.vrf}, 5)
			exec := indexOf(argv, "exec")
			if exec < 0 || exec+1 >= len(argv) || argv[exec+1] != tt.wantDev {
				t.Fatalf("argv %v: VRF device != %q (wrong-instance regression?)", argv, tt.wantDev)
			}
		})
	}
}

func TestBuildTracerouteArgvSeparator(t *testing.T) {
	tests := []struct {
		name string
		req  TracerouteRequest
		want string
	}{
		{"plain target", TracerouteRequest{Target: "2001:db8::1"}, "2001:db8::1"},
		{"dash-prefixed target", TracerouteRequest{Target: "-s"}, "-s"},
		{"with source", TracerouteRequest{Target: "-m", Source: "10.0.0.1"}, "-m"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argv := buildTracerouteArgv(tt.req)
			assertSeparatorBeforeTarget(t, argv, tt.want)
			tr := indexOf(argv, "traceroute")
			if tr < 0 || tr > indexOf(argv, "--") {
				t.Fatalf("argv %v: traceroute must be present and precede the separator", argv)
			}
		})
	}
}

func TestBuildTracerouteArgvVRFInnerSeparator(t *testing.T) {
	argv := buildTracerouteArgv(TracerouteRequest{Target: "-bad", RoutingInstance: "green"})
	if indexOf(argv, "ip") != 0 {
		t.Fatalf("argv %v: VRF wrapper must lead the argv", argv)
	}
	tr := indexOf(argv, "traceroute")
	sep := indexOf(argv, "--")
	if tr < 0 || sep < 0 || sep < tr {
		t.Fatalf("argv %v: separator must follow traceroute in the inner command", argv)
	}
	assertSeparatorBeforeTarget(t, argv, "-bad")
}
