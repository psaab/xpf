package frr

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// 1..254, the installable range (255 is FRR's distance-infinity sentinel).
func TestStaticRoutePreferenceRenderRange12060(t *testing.T) {
	m := New()
	cases := []struct {
		name string
		sr   *config.StaticRoute
		want string
	}{
		{
			name: "route preference 256",
			sr: &config.StaticRoute{
				Destination: "10.0.0.0/8",
				Preference:  256,
				NextHops:    []config.NextHopEntry{{Address: "192.0.2.1"}},
			},
			want: "ip route 10.0.0.0/8 192.0.2.1 254\n",
		},
		{
			name: "route preference maximum i32",
			sr: &config.StaticRoute{
				Destination: "10.1.0.0/16",
				Preference:  2147483647,
				NextHops:    []config.NextHopEntry{{Address: "192.0.2.2"}},
			},
			want: "ip route 10.1.0.0/16 192.0.2.2 254\n",
		},
		{
			name: "qualified-next-hop preference 256",
			sr: &config.StaticRoute{
				Destination: "10.2.0.0/16",
				Preference:  5,
				NextHops: []config.NextHopEntry{{
					Address: "192.0.2.3", Preference: 256, HasPreference: true,
				}},
			},
			want: "ip route 10.2.0.0/16 192.0.2.3 254\n",
		},
		{
			name: "discard preference 256",
			sr: &config.StaticRoute{
				Destination: "10.3.0.0/16", Discard: true, Preference: 256,
			},
			want: "ip route 10.3.0.0/16 Null0 254\n",
		},
		{
			name: "reject preference 256",
			sr: &config.StaticRoute{
				Destination: "10.4.0.0/16", Reject: true, Preference: 256,
			},
			want: "ip route 10.4.0.0/16 reject 254\n",
		},
		{
			name: "maximum installable preference",
			sr: &config.StaticRoute{
				Destination: "10.5.0.0/16",
				Preference:  254,
				NextHops:    []config.NextHopEntry{{Address: "192.0.2.5"}},
			},
			want: "ip route 10.5.0.0/16 192.0.2.5 254\n",
		},
		{
			name: "FRR distance infinity clamps to maximum installable",
			sr: &config.StaticRoute{
				Destination: "10.7.0.0/16",
				Preference:  255,
				NextHops:    []config.NextHopEntry{{Address: "192.0.2.7"}},
			},
			want: "ip route 10.7.0.0/16 192.0.2.7 254\n",
		},
		{
			name: "omitted preference keeps FRR default",
			sr: &config.StaticRoute{
				Destination: "10.6.0.0/16",
				NextHops:    []config.NextHopEntry{{Address: "192.0.2.6"}},
			},
			want: "ip route 10.6.0.0/16 192.0.2.6\n",
		},
	}

	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.generateStaticRoute(tc.sr, "", nil, nil, nil); got != tc.want {
				t.Fatalf("rendered route = %q, want %q", got, tc.want)
			}
		})
	}
	if !strings.Contains(logs.String(), "static route preference exceeds FRR's installable distance; clamping (#12060)") ||
		!strings.Contains(logs.String(), "preference=256") ||
		!strings.Contains(logs.String(), "preference=255") ||
		!strings.Contains(logs.String(), "maximum=254") {
		t.Fatalf("clamping an out-of-range preference must warn with its value and limit; logs: %s", logs.String())
	}
}
