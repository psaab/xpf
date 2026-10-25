package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16543: a `<*>` group never bound to a bare named OSPF interface or
// BGP neighbor leaf, so the FRR render emitted no auth lines. These
// cells drive the production parse + strict CompileConfig + render
// path: def-bare-wild must render exactly the auth lines ctl-attr-wild
// renders.

func compileHier16543(t *testing.T, text string) *config.Config {
	t.Helper()
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	return cfg
}

func TestBareOSPFWildcardAuthRenders16543(t *testing.T) {
	group := `groups { AUTH { protocols { ospf { area 0.0.0.0 { interface <*> { authentication { md5 1 { key K; } } } } } } } } apply-groups AUTH; `
	for _, c := range []struct{ name, text string }{
		{"def-bare-wild", group + `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0; } } }`},
		{"ctl-attr-wild", group + `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { cost 10; } } } }`},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := compileHier16543(t, c.text)
			got := New().generateProtocols(cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.BGP, cfg.Protocols.RIP, cfg.Protocols.ISIS, "", 0, nil, nil)
			for _, want := range []string{" ip ospf authentication message-digest\n", " ip ospf message-digest-key 1 md5 K\n"} {
				if !strings.Contains(got, want) {
					t.Errorf("FRR render missing %q (#16543):\n%s", want, got)
				}
			}
		})
	}
	// No-group control renders no auth (unchanged).
	cfg := compileHier16543(t, `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0; } } }`)
	got := New().generateProtocols(cfg.Protocols.OSPF, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "message-digest") {
		t.Errorf("no-group bare OSPF rendered auth it never had:\n%s", got)
	}
}

func TestBareBGPWildcardAuthRenders16543(t *testing.T) {
	group := `groups { AUTH { protocols { bgp { group G { neighbor <*> { authentication-key K; } } } } } } apply-groups AUTH; `
	for _, c := range []struct{ name, text string }{
		{"def-bare-wild", group + `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 192.0.2.2; } } }`},
		{"ctl-attr-wild", group + `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 192.0.2.2 { description x; } } } }`},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := compileHier16543(t, c.text)
			got := New().generateProtocols(nil, nil, cfg.Protocols.BGP, nil, nil, "", 0, nil, nil)
			if !strings.Contains(got, " neighbor 192.0.2.2 password K\n") {
				t.Errorf("FRR render missing neighbor password (#16543):\n%s", got)
			}
		})
	}
	cfg := compileHier16543(t, `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 192.0.2.2; } } }`)
	got := New().generateProtocols(nil, nil, cfg.Protocols.BGP, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "password") {
		t.Errorf("no-group bare BGP rendered a password it never had:\n%s", got)
	}
}
