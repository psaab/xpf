package diagcmd

import (
	"reflect"
	"testing"
)

// TestVRFDeviceName locks the unconditional mapping at the root
// (#16664): the argument is a routing-instance name and the daemon
// always realises instance N as "vrf-"+N, so a vrf- prefixed instance
// name gets the prefix again. The #2143 exactly-once guard resolved
// instance "vrf-cust" onto sibling instance "cust".
func TestVRFDeviceName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty stays empty", "", ""},
		{"bare name gets prefix", "red", "vrf-red"},
		{"control: sibling cust still maps to its own device", "cust", "vrf-cust"},
		{"vrf-prefixed instance gets prefix again", "vrf-cust", "vrf-vrf-cust"},
		{"vrf-mgmt instance does not map onto management VRF", "vrf-mgmt", "vrf-vrf-mgmt"},
		{"only a hyphen-bare name like vrf gets prefixed", "vrf", "vrf-vrf"},
		{"name containing vrf- mid-string is bare", "myvrf-x", "vrf-myvrf-x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VRFDeviceName(tt.in); got != tt.want {
				t.Fatalf("VRFDeviceName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestPingArgvExact asserts the full argv produced for ping across the
// with/without-VRF and bare/vrf-prefixed routing-instance axes. It
// is intentionally exact (reflect.DeepEqual on the whole argv) so any
// reintroduction of the #16664 exactly-once guard, a missing "--"
// separator, or argv-ordering drift FAILS.
func TestPingArgvExact(t *testing.T) {
	tests := []struct {
		name string
		opts PingOptions
		want []string
	}{
		{
			name: "no vrf, v4 target",
			opts: PingOptions{Target: "192.0.2.1", Count: "5"},
			want: []string{"ping", "-c", "5", "--", "192.0.2.1"},
		},
		{
			name: "no vrf, v6 target with source and size",
			opts: PingOptions{Target: "2001:db8::1", Count: "3", Source: "2001:db8::2", Size: "1400"},
			want: []string{"ping", "-c", "3", "-I", "2001:db8::2", "-s", "1400", "--", "2001:db8::1"},
		},
		{
			name: "bare vrf name gets one prefix",
			opts: PingOptions{Target: "192.0.2.1", Count: "5", RoutingInstance: "red"},
			want: []string{"ip", "vrf", "exec", "vrf-red", "ping", "-c", "5", "--", "192.0.2.1"},
		},
		{
			// #16664: instance "vrf-red" is realised as vrf-vrf-red;
			// vrf-red is sibling instance "red".
			name: "vrf-prefixed instance name gets prefix again",
			opts: PingOptions{Target: "192.0.2.1", Count: "5", RoutingInstance: "vrf-red"},
			want: []string{"ip", "vrf", "exec", "vrf-vrf-red", "ping", "-c", "5", "--", "192.0.2.1"},
		},
		{
			name: "vrf with v6 source and dash-prefixed target",
			opts: PingOptions{Target: "-evil", Count: "2", Source: "2001:db8::9", RoutingInstance: "blue"},
			want: []string{"ip", "vrf", "exec", "vrf-blue", "ping", "-c", "2", "-I", "2001:db8::9", "--", "-evil"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PingArgv(tt.opts)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("PingArgv(%+v) =\n  %v\nwant\n  %v", tt.opts, got, tt.want)
			}
		})
	}
}

// TestTracerouteArgvExact mirrors TestPingArgvExact for traceroute.
func TestTracerouteArgvExact(t *testing.T) {
	tests := []struct {
		name string
		opts TracerouteOptions
		want []string
	}{
		{
			name: "no vrf, v4 target",
			opts: TracerouteOptions{Target: "192.0.2.1"},
			want: []string{"traceroute", "--", "192.0.2.1"},
		},
		{
			name: "no vrf, v6 target with source",
			opts: TracerouteOptions{Target: "2001:db8::1", Source: "2001:db8::2"},
			want: []string{"traceroute", "-s", "2001:db8::2", "--", "2001:db8::1"},
		},
		{
			name: "bare vrf name gets one prefix",
			opts: TracerouteOptions{Target: "192.0.2.1", RoutingInstance: "red"},
			want: []string{"ip", "vrf", "exec", "vrf-red", "traceroute", "--", "192.0.2.1"},
		},
		{
			// #16664: as for ping, instance "vrf-green" -> vrf-vrf-green.
			name: "vrf-prefixed instance name gets prefix again",
			opts: TracerouteOptions{Target: "2001:db8::1", RoutingInstance: "vrf-green"},
			want: []string{"ip", "vrf", "exec", "vrf-vrf-green", "traceroute", "--", "2001:db8::1"},
		},
		{
			name: "vrf with source and dash-prefixed target",
			opts: TracerouteOptions{Target: "-evil", Source: "10.0.0.1", RoutingInstance: "blue"},
			want: []string{"ip", "vrf", "exec", "vrf-blue", "traceroute", "-s", "10.0.0.1", "--", "-evil"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TracerouteArgv(tt.opts)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("TracerouteArgv(%+v) =\n  %v\nwant\n  %v", tt.opts, got, tt.want)
			}
		})
	}
}
