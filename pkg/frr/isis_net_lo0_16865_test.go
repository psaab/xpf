package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16865: a Junos IS-IS config (NET on lo0 `family iso address`, no
// `protocols isis net`) must render ` net ...`; a NET-less IS-IS with
// interfaces must render nothing on the tolerant path.

func compileISIS16865(t *testing.T, src string, lenient bool) *config.Config {
	t.Helper()
	tree, perrs := config.NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	var cfg *config.Config
	var err error
	if lenient {
		cfg, err = config.CompileConfigLenient(tree)
	} else {
		cfg, err = config.CompileConfig(tree)
	}
	if err != nil {
		t.Fatalf("compile lenient=%v: %v", lenient, err)
	}
	return cfg
}

func renderISIS16865(cfg *config.Config) string {
	m := New()
	po := cfg.PolicyOptions
	return m.generateProtocols(cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.BGP, cfg.Protocols.RIP, cfg.Protocols.ISIS, "", 0, &po, nil)
}

func TestISISLo0ISONETRenders16865(t *testing.T) {
	cfg := compileISIS16865(t, `interfaces { lo0 { unit 0 { family iso { address 49.0001.0100.0000.0001.00; } } } }
interfaces { ge-0/0/1 { unit 0 { family inet { address 198.51.100.1/24; } } } }
protocols { isis { interface ge-0/0/1.0; } }`, false)
	if cfg.Protocols.ISIS.NET != "49.0001.0100.0000.0001.00" {
		t.Fatalf("derived NET = %q", cfg.Protocols.ISIS.NET)
	}
	got := renderISIS16865(cfg)
	for _, want := range []string{"router isis xpf\n", " net 49.0001.0100.0000.0001.00\n", " ip router isis xpf\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("render missing %q:\n%s", want, got)
		}
	}
	// Control: explicit NET renders identically.
	control := compileISIS16865(t, `protocols { isis { net 49.0001.0100.0000.0001.00; interface ge-0/0/1.0; } }`, false)
	if gotControl := renderISIS16865(control); gotControl != got {
		t.Errorf("derived render differs from explicit control:\nderived:\n%s\ncontrol:\n%s", got, gotControl)
	}
}

func TestISISNETLessWithheldOnTolerant16865(t *testing.T) {
	cfg := compileISIS16865(t, `protocols { isis { interface ge-0/0/1.0; } }`, true)
	got := renderISIS16865(cfg)
	if strings.Contains(got, "router isis") || strings.Contains(got, "ip router isis") {
		t.Fatalf("NET-less IS-IS rendered an active stanza on tolerant path:\n%s", got)
	}
	// Hand-built NET-less shapes are withheld too.
	m := New()
	got = m.generateProtocols(nil, nil, nil, nil, &config.ISISConfig{
		Level:      "level-2",
		Interfaces: []*config.ISISInterface{{Name: "trust0"}},
	}, "", 0, nil, nil)
	if strings.Contains(got, "router isis") {
		t.Fatalf("hand-built NET-less IS-IS rendered:\n%s", got)
	}
	// Malformed NET with an interface is withheld.
	got = m.generateProtocols(nil, nil, nil, nil, &config.ISISConfig{
		NET:        "49.0001",
		Level:      "level-2",
		Interfaces: []*config.ISISInterface{{Name: "trust0"}},
	}, "", 0, nil, nil)
	if strings.Contains(got, "router isis") {
		t.Fatalf("malformed-NET IS-IS rendered:\n%s", got)
	}
	// Controls: valid NET renders; NET-less without interfaces stays inert.
	got = m.generateProtocols(nil, nil, nil, nil, &config.ISISConfig{
		NET:        "49.0001.0100.0000.0001.00",
		Level:      "level-2",
		Interfaces: []*config.ISISInterface{{Name: "trust0"}},
	}, "", 0, nil, nil)
	if !strings.Contains(got, "router isis xpf\n") || !strings.Contains(got, " net 49.0001.0100.0000.0001.00\n") {
		t.Fatalf("valid-NET control did not render:\n%s", got)
	}
	got = m.generateProtocols(nil, nil, nil, nil, &config.ISISConfig{
		Level:  "level-2",
		Export: []string{"static"},
	}, "", 0, nil, nil)
	if !strings.Contains(got, "router isis xpf\n") {
		t.Fatalf("interface-less NET-less control should stay inert-rendered:\n%s", got)
	}
}
