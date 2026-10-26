package dhcp

import (
	"net"
	"net/netip"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// #6756: RFC 3442 conditions its rule on the option being RETURNED — "If the
// DHCP server returns both a Classless Static Routes option and a Router
// option, the DHCP client MUST ignore the Router option."
//
// classlessStaticRoutes derived `present` from len(parsedRoutes) != 0, which
// collapsed THREE distinct cases into one false:
//
//	absent                  -> option 3 honoured   (correct)
//	present but zero-length -> option 3 honoured   (RFC says ignore it)
//	present but malformed   -> option 3 honoured   (RFC says ignore it)
//
// So a server that emits a broken option 121/249 alongside a Router option got
// the router installed anyway — the exact fall-through the RFC forbids. Option
// 249's parse error was additionally discarded in silence.
//
// The four cases below are the ones the old code could not tell apart. The
// ABSENT case is the control: without it, "presence is the option slot" and
// "never honour option 3" are indistinguishable, and the second silently breaks
// every ordinary lease that relies on the Router option.

const presence6756Router = "198.51.100.99"

func presenceACK6756(t *testing.T, opts ...dhcpv4.Option) *dhcpv4.DHCPv4 {
	t.Helper()
	all := append([]dhcpv4.Option{dhcpv4.OptRouter(net.ParseIP(presence6756Router))}, opts...)
	return classlessACK(t, all...)
}

func TestClasslessOptionPresenceSuppressesRouter6756(t *testing.T) {
	for _, tc := range []struct {
		name    string
		opts    []dhcpv4.Option
		wantGW  string // "" means no gateway at all
		wantWhy string
	}{
		{
			name:    "ABSENT: option 3 is honoured (the control)",
			opts:    nil,
			wantGW:  presence6756Router,
			wantWhy: "with no classless option the Router option is the ONLY source of a default route; suppressing it here would break every ordinary lease",
		},
		{
			name:    "option 121 present but ZERO-LENGTH",
			opts:    []dhcpv4.Option{{Code: dhcpv4.OptionClasslessStaticRoute, Value: dhcpv4.OptionGeneric{Data: []byte{}}}},
			wantGW:  "",
			wantWhy: "the option was RETURNED, so RFC 3442 requires the Router option to be ignored even though the option yielded nothing",
		},
		{
			name:    "option 121 present but MALFORMED",
			opts:    []dhcpv4.Option{{Code: dhcpv4.OptionClasslessStaticRoute, Value: dhcpv4.OptionGeneric{Data: []byte{0xff, 0x01}}}},
			wantGW:  "",
			wantWhy: "a prefix length of 255 cannot be parsed; the option is still RETURNED",
		},
		{
			name:    "option 249 present but MALFORMED",
			opts:    []dhcpv4.Option{{Code: dhcpv4.GenericOptionCode(249), Value: dhcpv4.OptionGeneric{Data: []byte{0xff, 0x01}}}},
			wantGW:  "",
			wantWhy: "the legacy Microsoft option is the same encoding and the same rule; its parse error used to be discarded in silence",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lease, err := leaseFromACKv4WithProtected("wan0", presenceACK6756(t, tc.opts...), nil)
			if err != nil {
				t.Fatalf("leaseFromACKv4: %v", err)
			}
			if tc.wantGW == "" {
				if lease.Gateway.IsValid() {
					t.Errorf("lease.Gateway = %v, want NO gateway — %s. Installing the "+
						"option-3 router here routes traffic via a gateway the server's "+
						"classless option was meant to override",
						lease.Gateway, tc.wantWhy)
				}
				return
			}
			want := netip.MustParseAddr(tc.wantGW)
			if lease.Gateway != want {
				t.Errorf("lease.Gateway = %v, want %v — %s", lease.Gateway, want, tc.wantWhy)
			}
		})
	}
}

// TestWellFormedClasslessStillSupersedes6756 pins that the presence change did
// not disturb the working path: a VALID option 121 must still supply the
// gateway and the more-specific routes, and still suppress option 3.
//
// Without this, a "fix" that made presence always true would pass every case
// above while breaking the feature #4118 added.
func TestWellFormedClasslessStillSupersedes6756(t *testing.T) {
	classless := dhcpv4.OptClasslessStaticRoute(
		&dhcpv4.Route{Dest: mustCIDR(t, "0.0.0.0/0"), Router: net.ParseIP("192.0.2.1")},
		&dhcpv4.Route{Dest: mustCIDR(t, "10.20.0.0/16"), Router: net.ParseIP("192.0.2.9")},
	)
	lease, err := leaseFromACKv4WithProtected("wan0", presenceACK6756(t, classless), nil)
	if err != nil {
		t.Fatalf("leaseFromACKv4: %v", err)
	}
	if want := netip.MustParseAddr("192.0.2.1"); lease.Gateway != want {
		t.Errorf("lease.Gateway = %v, want %v (the option-121 default, not the option-3 router)",
			lease.Gateway, want)
	}
	if len(lease.ClasslessRoutes) != 1 {
		t.Fatalf("lease.ClasslessRoutes = %+v, want exactly the one more-specific route",
			lease.ClasslessRoutes)
	}
}
