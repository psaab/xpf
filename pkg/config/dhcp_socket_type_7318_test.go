package config_test

// #7318: opt-in `system services dhcp-local-server dhcp-socket-type`.
//
// FAIL-ON-REVERT: drop the compiler's isV4 read and every compile assertion
// below loses its value; drop the advisory registration and the warning cells
// go silent; widen the validator and the reject cell accepts garbage.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func setTree7318(t *testing.T, cmds ...string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func mustCompile7318(t *testing.T, cmds ...string) *config.Config {
	t.Helper()
	tree := setTree7318(t, cmds...)
	if err := config.SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

const baseDHCP7318 = "set system services dhcp-local-server group g0 interface ge-0-0-1"

func TestSocketTypeCompilesFromSetSyntax7318(t *testing.T) {
	for _, want := range []string{config.DHCPSocketTypeRaw, config.DHCPSocketTypeUDP} {
		t.Run(want, func(t *testing.T) {
			cfg := mustCompile7318(t, baseDHCP7318,
				"set system services dhcp-local-server dhcp-socket-type "+want)
			srv := cfg.System.DHCPServer.DHCPLocalServer
			if srv == nil {
				t.Fatal("dhcp-local-server did not compile")
			}
			if srv.SocketType != want {
				t.Errorf("SocketType = %q, want %q", srv.SocketType, want)
			}
		})
	}
}

// Absent must compile to the empty string, which is what makes the renderer
// omit the key. Pinning this separately keeps "unset" a real third state
// rather than something that happens to equal "raw".
func TestSocketTypeAbsentCompilesEmpty7318(t *testing.T) {
	cfg := mustCompile7318(t, baseDHCP7318)
	srv := cfg.System.DHCPServer.DHCPLocalServer
	if srv == nil {
		t.Fatal("dhcp-local-server did not compile")
	}
	if srv.SocketType != "" {
		t.Errorf("SocketType with no leaf set = %q, want \"\"", srv.SocketType)
	}
}

// #2419 dual-shape: the compact block spelling carries the value in Children,
// not Keys[1]. A reader that takes Keys[1] alone compiles this to "" and the
// operator's setting silently vanishes — the exact class the 2419 inventory
// guards.
//
// This asserts the AGREEMENT between the two spellings rather than pinning
// either one to a literal. Pinning a literal would encode which side I trust,
// and the whole point is that both must land on the same compiled value.
func TestSocketTypeCompactBlockSpellingCompiles7318(t *testing.T) {
	flat := mustCompile7318(t, baseDHCP7318,
		"set system services dhcp-local-server dhcp-socket-type udp")
	flatSrv := flat.System.DHCPServer.DHCPLocalServer
	if flatSrv == nil {
		t.Fatal("flat dhcp-local-server did not compile")
	}

	hier := `system {
    services {
        dhcp-local-server {
            group g0 { interface ge-0-0-1; }
            dhcp-socket-type { udp; }
        }
    }
}`
	pt, perrs := config.NewParser(hier).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse hierarchical: %v", perrs)
	}
	hcfg, err := config.CompileConfig(pt)
	if err != nil {
		t.Fatalf("CompileConfig(hierarchical): %v", err)
	}
	hsrv := hcfg.System.DHCPServer.DHCPLocalServer
	if hsrv == nil {
		t.Fatal("hierarchical dhcp-local-server did not compile")
	}

	if hsrv.SocketType != flatSrv.SocketType {
		t.Errorf("compact spelling compiled to %q but flat compiled to %q — the two spellings must agree",
			hsrv.SocketType, flatSrv.SocketType)
	}
	// Guard against the agreement being vacuous: both landing on "" would
	// satisfy the comparison above while meaning the leaf was dropped twice.
	if hsrv.SocketType == "" {
		t.Error("both spellings compiled to \"\" — the agreement is vacuous, the value was dropped")
	}
}

func TestSocketTypeRejectsUnknownValue7318(t *testing.T) {
	// "packet" is a plausible-looking wrong answer: it is close to AF_PACKET,
	// which is exactly what an operator reading the advisory might type. It is
	// deliberately NOT a value the leaf falls back to.
	tree := setTree7318(t, baseDHCP7318,
		"set system services dhcp-local-server dhcp-socket-type packet")
	err := config.SchemaValidate(tree)
	if err == nil {
		t.Fatal("SchemaValidate accepted dhcp-socket-type packet; the enum must reject it")
	}
	if !strings.Contains(err.Error(), "packet") {
		t.Errorf("error should name the offending value, got: %v", err)
	}
}

// The leaf is IPv4-only. Kea's Dhcp6 has no raw mode, so a v6 stanza must not
// populate the v6 family's SocketType even if someone hand-writes it.
func TestSocketTypeIsV4Only7318(t *testing.T) {
	tree := setTree7318(t,
		"set system services dhcpv6-local-server group g6 interface ge-0-0-1",
		"set system services dhcpv6-local-server dhcp-socket-type udp")
	// The v6 subtree does not model the leaf; whether SchemaValidate rejects
	// it depends on closed-world state for that subtree, so this test pins the
	// COMPILER contract, which is the part that decides behaviour.
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if v6 := cfg.System.DHCPServer.DHCPv6LocalServer; v6 != nil && v6.SocketType != "" {
		t.Errorf("v6 SocketType = %q, want \"\" — the leaf must not take effect on the v6 path", v6.SocketType)
	}
}

func socketTypeWarnings7318(cfg *config.Config) []string {
	var out []string
	for _, w := range config.ValidateConfig(cfg) {
		if strings.Contains(w, "dhcp-socket-type udp") {
			out = append(out, w)
		}
	}
	return out
}

// The advisory is the load-bearing half of the feature: selecting udp silently
// stops directly-attached clients being served, and that must be stated in the
// terms the operator will observe it in.
func TestSocketTypeUDPWarnsWithTheTrade7318(t *testing.T) {
	cfg := mustCompile7318(t, baseDHCP7318,
		"set system services dhcp-local-server dhcp-socket-type udp")
	ws := socketTypeWarnings7318(cfg)
	if len(ws) != 1 {
		t.Fatalf("want exactly 1 socket-type advisory, got %d: %v", len(ws), ws)
	}
	msg := ws[0]

	// Each of these is a distinct fact the operator needs. A message that
	// merely restates the leaf name ("sets dhcp-socket-type to udp") passes
	// none of them, which is the degradation this test exists to prevent.
	for _, want := range []struct{ needle, why string }{
		{"ge-0-0-1", "must name the affected interface"},
		{"RELAYED", "must say relayed clients keep working"},
		{"RENEWING", "must say renewing clients keep working"},
		{"STOP being served", "must state the consequence, not just the setting"},
		{"host-inbound-traffic system-services dhcp", "must say what gateability is bought"},
	} {
		if !strings.Contains(msg, want.needle) {
			t.Errorf("advisory %s (missing %q):\n%s", want.why, want.needle, msg)
		}
	}
}

func TestSocketTypeIsSilentUnlessUDP7318(t *testing.T) {
	for _, tc := range []struct{ name, cmd string }{
		{"absent", ""},
		{"raw", "set system services dhcp-local-server dhcp-socket-type raw"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmds := []string{baseDHCP7318}
			if tc.cmd != "" {
				cmds = append(cmds, tc.cmd)
			}
			cfg := mustCompile7318(t, cmds...)
			if ws := socketTypeWarnings7318(cfg); len(ws) != 0 {
				t.Errorf("no advisory expected for %s, got: %v", tc.name, ws)
			}
		})
	}
}
