package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15658: after the config-layer merge, one valid generate prefix renders
// exactly one blackhole line — the same single route the userspace
// snapshot installs. Duplicate same-prefix entries (the pre-merge shape)
// must not double-render.
func TestGenerateRoutesMergedSingleBlackhole15658(t *testing.T) {
	var b strings.Builder
	renderGenerateRoutes(&b, &FullConfig{
		GenerateRoutes: []*config.GenerateRoute{
			{Prefix: "10.0.0.0/8", Discard: true},
			{Prefix: "2001:db8::/32", Discard: true},
		},
	})
	got := b.String()
	if strings.Count(got, "ip route 10.0.0.0/8 blackhole") != 1 {
		t.Errorf("want exactly one v4 blackhole, got:\n%s", got)
	}
	if strings.Count(got, "ipv6 route 2001:db8::/32 blackhole") != 1 {
		t.Errorf("want exactly one v6 blackhole, got:\n%s", got)
	}
}
