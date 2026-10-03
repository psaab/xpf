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
			want  bool
			warn  bool
		}{{0, false, false}, {1, true, false}, {10, true, false}, {-1, false, true}, {11, false, true}, {999999, false, true}} {
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
				line := fmt.Sprintf("neighbor 192.0.2.1 allowas-in %d\n", tc.value)
				if emitted := strings.Contains(got, line); emitted != tc.want {
					t.Fatalf("allowas-in emission = %t, want %t for value %d:\n%s", emitted, tc.want, tc.value, got)
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
