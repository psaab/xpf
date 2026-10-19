package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14399: renderer belt. A type-without-key IS-IS config arriving on the
// tolerant path must warn (not silently render an unauthenticated stanza).
// generateProtocols returns only a string, so the belt is slog.Warn — the
// compile gate is the enforcement; these tests pin that keyed rendering is
// unchanged and type-only rendering emits no password lines.
// #14977: the renderer now also omits the stanza entirely (fail closed).

func TestISISKeyedRenderUnchanged14399(t *testing.T) {
	m := New()
	for _, tc := range []struct {
		name string
		isis *config.ISISConfig
		want []string
	}{
		{"global md5", &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Level: "level-2", AuthType: "md5", AuthKey: config.Secret("s3cret")},
			[]string{" area-password md5 s3cret\n", " domain-password md5 s3cret\n"}},
		{"global simple", &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Level: "level-2", AuthType: "simple", AuthKey: config.Secret("s3cret")},
			[]string{" area-password clear s3cret\n", " domain-password clear s3cret\n"}},
		{"iface md5", &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Level: "level-2", Interfaces: []*config.ISISInterface{{Name: "trust0", AuthType: "md5", AuthKey: config.Secret("s3cret")}}},
			[]string{" isis password md5 s3cret\n"}},
		{"iface simple", &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Level: "level-2", Interfaces: []*config.ISISInterface{{Name: "trust0", AuthType: "simple", AuthKey: config.Secret("s3cret")}}},
			[]string{" isis password clear s3cret\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := m.generateProtocols(nil, nil, nil, nil, tc.isis, "", 0, nil, nil)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("missing %q in:\n%s", w, got)
				}
			}
		})
	}
}

func TestISISTypeWithoutKeyRendersNoPassword14399(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Level: "level-2", AuthType: "md5",
		Interfaces: []*config.ISISInterface{{Name: "trust0", AuthType: "md5"}}}
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil)
	for _, bad := range []string{"area-password", "domain-password", "isis password"} {
		if strings.Contains(got, bad) {
			t.Errorf("type-without-key rendered %q (must be password-free; enforcement is the #14399 compile gate):\n%s", bad, got)
		}
	}
	// #14977 supersedes the stanza-present half of this contract: a
	// type-without-key config now fails closed — the whole IS-IS
	// stanza is omitted rather than activated unauthenticated. The
	// #14399 compile gate remains the strict-path enforcement.
	if strings.Contains(got, "router isis xpf\n") {
		t.Errorf("type-without-key still emitted the IS-IS stanza (unauthenticated activation):\n%s", got)
	}
}
