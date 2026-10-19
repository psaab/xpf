package frr

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestGenerateProtocols_BGPAllowASInRange11795(t *testing.T) {
	for _, family := range []struct {
		name  string
		inet  bool
		inet6 bool
	}{
		{name: "inet", inet: true},
		{name: "inet6", inet6: true},
	} {
		for _, tc := range []struct {
			value int
			want  string // rendered allowas-in argument; "" = no line (#15009: loops N -> N-1)
			warn  bool
		}{{0, "", false}, {1, "", false}, {10, "9", false}, {-1, "", true}, {11, "", true}, {999999, "", true}} {
			t.Run(fmt.Sprintf("%s/%d", family.name, tc.value), func(t *testing.T) {
				var logs bytes.Buffer
				previous := slog.Default()
				slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
				defer slog.SetDefault(previous)

				neighbor := &config.BGPNeighbor{
					Address:     "192.0.2.1",
					PeerAS:      65002,
					AllowASIn:   tc.value,
					FamilyInet:  family.inet,
					FamilyInet6: family.inet6,
				}
				got := New().generateProtocols(nil, nil, &config.BGPConfig{
					LocalAS: 65001, Neighbors: []*config.BGPNeighbor{neighbor},
				}, nil, nil, "", 0, nil, nil)
				if tc.want == "" {
					if strings.Contains(got, "allowas-in") {
						t.Fatalf("loops %d: want no allowas-in line:\n%s", tc.value, got)
					}
				} else if line := "neighbor 192.0.2.1 allowas-in " + tc.want + "\n"; !strings.Contains(got, line) {
					t.Fatalf("loops %d: want %q:\n%s", tc.value, line, got)
				}
				if tc.warn {
					for _, field := range []string{"allowas-in", "192.0.2.1", fmt.Sprint(tc.value)} {
						if !strings.Contains(logs.String(), field) {
							t.Errorf("invalid value warning missing %q: %s", field, logs.String())
						}
					}
				} else if logs.Len() != 0 {
					t.Errorf("valid/unset value unexpectedly warned: %s", logs.String())
				}
			})
		}
	}
}

// #15009: Junos `loops N` and FRR `allowas-in N` count differently.
// Junos (loops (Autonomous System), default/threshold semantics):
//
//	loops 1 hides the route if the local AS is detected >=1 time
//	loops 2 hides the route if the local AS is detected >=2 times
//
// i.e. Junos allows N-1 occurrences. FRR counts accepted occurrences:
//
//	no allowas-in       -> count > 0 filtered (0 allowed)
//	allowas-in K        -> count > K filtered (K allowed)
//	allowas-in (bare)   -> 3 allowed (FRR default, never emitted here)
//
// and, with a per-neighbor local-as, FRR separately permits 1
// occurrence of the local-as AS when no allowas-in is set. So the
// Junos-equivalent FRR rendering is: loops 1 -> no line,
// loops N>=2 -> allowas-in N-1, loops 10 -> allowas-in 9.
// The pre-fix renderer copied N verbatim, accepting one extra
// occurrence on every peer with loops configured.
func TestGenerateProtocols_BGPAllowASInLoopsOffByOne15009(t *testing.T) {
	cases := []struct {
		loops int
		want  string // rendered allowas-in argument; "" = no line
	}{
		{0, ""},  // unset: no line (control)
		{1, ""},  // Junos default-equivalent: 0 allowed
		{2, "1"}, // 1 allowed
		{3, "2"},
		{10, "9"}, // max Junos loops -> 9 allowed, still in FRR 1..10
	}
	for _, family := range []struct {
		name  string
		inet  bool
		inet6 bool
	}{
		{name: "inet", inet: true},
		{name: "inet6", inet6: true},
	} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%s/loops-%d", family.name, tc.loops), func(t *testing.T) {
				neighbor := &config.BGPNeighbor{
					Address:     "192.0.2.1",
					PeerAS:      65002,
					AllowASIn:   tc.loops,
					FamilyInet:  family.inet,
					FamilyInet6: family.inet6,
				}
				got := New().generateProtocols(nil, nil, &config.BGPConfig{
					LocalAS: 65001, Neighbors: []*config.BGPNeighbor{neighbor},
				}, nil, nil, "", 0, nil, nil)
				if tc.want == "" {
					if strings.Contains(got, "allowas-in") {
						t.Fatalf("loops %d: want no allowas-in line, got:\n%s", tc.loops, got)
					}
					return
				}
				wantLine := "neighbor 192.0.2.1 allowas-in " + tc.want + "\n"
				if !strings.Contains(got, wantLine) {
					t.Fatalf("loops %d: want %q, got:\n%s", tc.loops, wantLine, got)
				}
				// The verbatim (pre-fix) spelling must not appear.
				verbatim := fmt.Sprintf("neighbor 192.0.2.1 allowas-in %d\n", tc.loops)
				if verbatim != wantLine && strings.Contains(got, verbatim) {
					t.Fatalf("loops %d: verbatim off-by-one line %q present:\n%s", tc.loops, verbatim, got)
				}
			})
		}
	}
	// Out-of-range tolerant-load values still fail closed: no line, one
	// warning naming the neighbor and the authored loops value (#11795
	// behaviour preserved alongside the #15009 mapping).
	for _, value := range []int{-1, 11, 999999} {
		var logs bytes.Buffer
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
		got := New().generateProtocols(nil, nil, &config.BGPConfig{
			LocalAS: 65001,
			Neighbors: []*config.BGPNeighbor{{
				Address: "192.0.2.1", PeerAS: 65002, AllowASIn: value, FamilyInet: true,
			}},
		}, nil, nil, "", 0, nil, nil)
		slog.SetDefault(previous)
		if strings.Contains(got, "allowas-in") {
			t.Fatalf("loops %d: out-of-range value rendered a line:\n%s", value, got)
		}
		for _, field := range []string{"allowas-in", "192.0.2.1", fmt.Sprint(value)} {
			if !strings.Contains(logs.String(), field) {
				t.Errorf("loops %d: warning missing %q: %s", value, field, logs.String())
			}
		}
	}
}
