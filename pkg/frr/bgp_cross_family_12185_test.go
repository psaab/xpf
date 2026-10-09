package frr

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// An IPv6-literal neighbor with an explicit per-neighbor family inet must not
// be left out of every AF: FRR's default ipv4-unicast activation would then
// carry no rendered import/export policies. The tolerant path warns, keeps
// the unsupported AF inert, and explicitly disables the peer under IPv4
// unicast so the default cannot activate it (#12185). FRR validation uses the
// integrated vtysh grammar parser plus an invalid-command control; it does not
// exercise live bgpd config loading.
func TestBGPPerNeighborCrossFamily12185FailsClosedInFRR(t *testing.T) {
	const peer = "2001:db8::9"
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set policy-options policy-statement EXP term t1 then accept",
		"set policy-options policy-statement IMP term t1 then accept",
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65001",
		"set protocols bgp group external neighbor " + peer + " family inet unicast prefix-limit maximum 100",
		"set protocols bgp group external neighbor " + peer + " export EXP",
		"set protocols bgp group external neighbor " + peer + " import IMP",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if !has12185Warning(cfg.Warnings, peer) {
		t.Fatalf("lenient compile did not diagnose cross-family inet for %s: %v", peer, cfg.Warnings)
	}

	m := New()
	rendered := m.buildManagedSection(&FullConfig{BGP: cfg.Protocols.BGP, PolicyOptions: &cfg.PolicyOptions})
	v4 := bgpAFBlock11374(rendered, bgpInet4AF11374)
	v6 := bgpAFBlock11374(rendered, bgpInet6AF11374)
	if !strings.Contains(v4, "no neighbor "+peer+" activate\n") {
		t.Fatalf("IPv6 cross-family peer must be explicitly disabled in FRR's default IPv4 AF:\n%s", rendered)
	}
	if strings.Contains(v4, "  neighbor "+peer+" activate\n") || strings.Contains(v6, "neighbor "+peer+" activate\n") {
		t.Fatalf("unsupported inet must not activate the IPv6 peer in either AF:\n%s", rendered)
	}
	for _, line := range []string{"route-map EXP out", "route-map IMP in", "maximum-prefix 100"} {
		if strings.Contains(v4+v6, "neighbor "+peer+" "+line) {
			t.Fatalf("inert unsupported inet emitted %q:\n%s", line, rendered)
		}
	}

	vtysh := frrVtyshBinary12185(t)
	if output, err := validateRenderedRouting11417(t, vtysh, rendered); err != nil {
		t.Fatalf("FRR vtysh grammar rejected the fail-closed cross-family config: %v\n%s\nconfig:\n%s", err, output, rendered)
	}
	// Prove the validator actually reads and parses the file, rather than
	// accepting a missing/unreadable config as bgpd -C can do on some builds.
	const invalidCommand = "xpf-invalid-12185-command"
	mutated := rendered + invalidCommand + "\n"
	output, err := validateRenderedRouting11417(t, vtysh, mutated)
	if err == nil || !strings.Contains(string(output), invalidCommand) {
		t.Fatalf("FRR vtysh did not reject the invalid config control: %v\n%s", err, output)
	}
	t.Log("vtysh -C accepted the rendered grammar and rejected its invalid-keyword control")
}

// Group-inherited family flags for mapped IPv6 peers must match FRR's IPv6
// classification: disable IPv4 explicitly and keep the IPv6 policies active.
func TestBGPGroupInheritedMappedFamily12185RendersIPv6(t *testing.T) {
	for _, peer := range []string{"::ffff:192.0.2.9", "::ffff:c000:209"} {
		t.Run(peer, func(t *testing.T) {
			tree := &config.ConfigTree{}
			for _, cmd := range []string{
				"set policy-options policy-statement EXP term t1 then accept",
				"set policy-options policy-statement IMP term t1 then accept",
				"set protocols bgp local-as 65001",
				"set protocols bgp group dual peer-as 65002",
				"set protocols bgp group dual family inet unicast",
				"set protocols bgp group dual family inet6 unicast",
				"set protocols bgp group dual import IMP",
				"set protocols bgp group dual export EXP",
				"set protocols bgp group dual neighbor " + peer,
			} {
				path, err := config.ParseSetCommand(cmd)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("SetPath(%q): %v", cmd, err)
				}
			}
			cfg, err := config.CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict compile: %v", err)
			}
			if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
				t.Fatalf("compiled BGP neighbor missing: %+v", cfg.Protocols.BGP)
			}
			n := cfg.Protocols.BGP.Neighbors[0]
			if n.FamilyInet || !n.FamilyInet6 || n.CrossFamilyInet {
				t.Fatalf("mapped peer did not inherit only inet6: %+v", n)
			}

			rendered := New().buildManagedSection(&FullConfig{
				BGP: cfg.Protocols.BGP, PolicyOptions: &cfg.PolicyOptions,
			})
			v4 := bgpAFBlock11374(rendered, bgpInet4AF11374)
			v6 := bgpAFBlock11374(rendered, bgpInet6AF11374)
			if !strings.Contains(v4, "no neighbor "+peer+" activate\n") {
				t.Fatalf("mapped IPv6 peer lacks explicit IPv4 deactivation:\n%s", rendered)
			}
			if !strings.Contains(v6, "neighbor "+peer+" activate\n") ||
				!strings.Contains(v6, "neighbor "+peer+" route-map EXP out\n") ||
				!strings.Contains(v6, "neighbor "+peer+" route-map IMP in\n") {
				t.Fatalf("mapped IPv6 peer lost IPv6 activation or policies:\n%s", rendered)
			}
			if strings.Contains(v4, "neighbor "+peer+" route-map ") {
				t.Fatalf("mapped IPv6 policy leaked into IPv4 unicast:\n%s", rendered)
			}
		})
	}
}

// Lenient cross-family inet must explicitly disable a mapped peer even when
// group-level inet would otherwise have been inherited.
func TestBGPGroupInheritedMappedFamily12185LenientRendersDisabled(t *testing.T) {
	for _, peer := range []string{"::ffff:192.0.2.9", "::ffff:c000:209"} {
		t.Run(peer, func(t *testing.T) {
			tree := &config.ConfigTree{}
			for _, cmd := range []string{
				"set policy-options policy-statement EXP term t1 then accept",
				"set policy-options policy-statement IMP term t1 then accept",
				"set protocols bgp local-as 65001",
				"set protocols bgp group dual peer-as 65002",
				"set protocols bgp group dual family inet unicast",
				"set protocols bgp group dual import IMP",
				"set protocols bgp group dual export EXP",
				"set protocols bgp group dual neighbor " + peer + " family inet unicast",
			} {
				path, err := config.ParseSetCommand(cmd)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("SetPath(%q): %v", cmd, err)
				}
			}
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if !has12185Warning(cfg.Warnings, peer) {
				t.Fatalf("lenient compile did not diagnose %s: %v", peer, cfg.Warnings)
			}
			if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
				t.Fatalf("compiled BGP neighbor missing: %+v", cfg.Protocols.BGP)
			}
			n := cfg.Protocols.BGP.Neighbors[0]
			if n.FamilyInet || !n.CrossFamilyInet {
				t.Fatalf("inherited inet was not made inert: %+v", n)
			}
			rendered := New().buildManagedSection(&FullConfig{
				BGP: cfg.Protocols.BGP, PolicyOptions: &cfg.PolicyOptions,
			})
			v4 := bgpAFBlock11374(rendered, bgpInet4AF11374)
			v6 := bgpAFBlock11374(rendered, bgpInet6AF11374)
			if !strings.Contains(v4, "no neighbor "+peer+" activate\n") {
				t.Fatalf("lenient mapped peer lacks IPv4 deactivation:\n%s", rendered)
			}
			if strings.Contains(v4, "  neighbor "+peer+" activate\n") ||
				strings.Contains(v6, "  neighbor "+peer+" activate\n") ||
				strings.Contains(rendered, "neighbor "+peer+" route-map ") {
				t.Fatalf("inert cross-family mapped peer was activated or received policy:\n%s", rendered)
			}
		})
	}
}

func has12185Warning(warnings []string, peer string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, "#12185") && strings.Contains(warning, peer) {
			return true
		}
	}
	return false
}

func frrVtyshBinary12185(t *testing.T) string {
	t.Helper()
	if vtysh := os.Getenv("FRR_VTYSH_BINARY"); vtysh != "" {
		return vtysh
	}
	vtysh, err := exec.LookPath("vtysh")
	if err == nil {
		return vtysh
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("resolve FRR vtysh: %v", err)
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		candidate := filepath.Join(dir, "vtysh")
		_, statErr := os.Lstat(candidate)
		if statErr == nil {
			t.Fatalf("FRR vtysh exists on PATH but is unusable: %s", candidate)
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("inspect FRR vtysh candidate %s: %v", candidate, statErr)
		}
	}
	t.Skip("FRR vtysh is absent from PATH; grammar validation unavailable")
	return ""
}
