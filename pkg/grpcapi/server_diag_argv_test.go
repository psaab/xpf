package grpcapi

import (
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

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
// after it, with no option appearing after the separator.
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
	// The target must be the last element: nothing is appended after it.
	if sep+1 != len(argv)-1 {
		t.Fatalf("argv %v: target is not the final argv element", argv)
	}
}

func TestBuildPingArgvSeparator(t *testing.T) {
	tests := []struct {
		name string
		req  *pb.PingRequest
		want string // expected target operand
	}{
		{
			name: "plain target",
			req:  &pb.PingRequest{Target: "192.0.2.1"},
			want: "192.0.2.1",
		},
		{
			name: "dash-prefixed target is treated as operand",
			req:  &pb.PingRequest{Target: "-I"},
			want: "-I",
		},
		{
			name: "with source and size",
			req:  &pb.PingRequest{Target: "-f", Source: "10.0.0.1", Size: 1400},
			want: "-f",
		},
		{
			name: "with routing instance",
			req:  &pb.PingRequest{Target: "-c", RoutingInstance: "blue"},
			want: "-c",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argv := buildPingArgv(tt.req, 5)
			assertSeparatorBeforeTarget(t, argv, tt.want)
			// ping binary must still be present before the separator.
			ping := indexOf(argv, "ping")
			if ping < 0 {
				t.Fatalf("argv %v: missing ping binary", argv)
			}
			if ping > indexOf(argv, "--") {
				t.Fatalf("argv %v: ping must precede the separator", argv)
			}
		})
	}
}

func TestBuildPingArgvVRFInnerSeparator(t *testing.T) {
	argv := buildPingArgv(&pb.PingRequest{Target: "-bad", RoutingInstance: "red"}, 5)
	// "ip vrf exec vrf-red" wrapper must precede ping, and "--" must be
	// in the inner command (after ping), so it reaches the inner binary.
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
// gRPC surface: instance N maps to "vrf-"+N unconditionally (instance
// "vrf-red" -> "vrf-vrf-red", not sibling "red").
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
			argv := buildPingArgv(&pb.PingRequest{Target: "192.0.2.1", RoutingInstance: tt.vrf}, 5)
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
		req  *pb.TracerouteRequest
		want string
	}{
		{
			name: "plain target",
			req:  &pb.TracerouteRequest{Target: "2001:db8::1"},
			want: "2001:db8::1",
		},
		{
			name: "dash-prefixed target is treated as operand",
			req:  &pb.TracerouteRequest{Target: "-s"},
			want: "-s",
		},
		{
			name: "with source",
			req:  &pb.TracerouteRequest{Target: "-m", Source: "10.0.0.1"},
			want: "-m",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argv := buildTracerouteArgv(tt.req)
			assertSeparatorBeforeTarget(t, argv, tt.want)
			tr := indexOf(argv, "traceroute")
			if tr < 0 {
				t.Fatalf("argv %v: missing traceroute binary", argv)
			}
			if tr > indexOf(argv, "--") {
				t.Fatalf("argv %v: traceroute must precede the separator", argv)
			}
		})
	}
}

func TestBuildTracerouteArgvVRFInnerSeparator(t *testing.T) {
	argv := buildTracerouteArgv(&pb.TracerouteRequest{Target: "-bad", RoutingInstance: "green"})
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
