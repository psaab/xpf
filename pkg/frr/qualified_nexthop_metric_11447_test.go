package frr

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func compileQNHMetricConfig11447(t *testing.T, commands ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, command := range commands {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	compiled, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return compiled
}

func qnhMetricRender11447(t *testing.T, commands ...string) string {
	t.Helper()
	compiled := compileQNHMetricConfig11447(t, commands...)
	return New().buildManagedSection(&FullConfig{
		OSPF:          compiled.Protocols.OSPF,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	})
}

func routeMapBlock11447(rendered, name string) string {
	var block strings.Builder
	inMap := false
	for _, line := range strings.Split(rendered, "\n") {
		if strings.HasPrefix(line, "route-map ") {
			isTarget := strings.HasPrefix(line, "route-map "+name+" ")
			if inMap && !isTarget {
				break
			}
			if isTarget {
				inMap = true
			}
		}
		if inMap {
			block.WriteString(line)
			block.WriteByte('\n')
		}
		if inMap && line == "!" {
			break
		}
	}
	return block.String()
}

func TestQualifiedNextHopMetricReachesStaticRedistribution11447(t *testing.T) {
	rendered := qnhMetricRender11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf export static",
	)
	if !strings.Contains(rendered, "redistribute static route-map ") {
		t.Fatalf("static OSPF export has no synthesized route-map for QNH metric:\n%s", rendered)
	}
	if !strings.Contains(rendered, "set metric 10\n") {
		t.Fatalf("qualified-next-hop metric 10 did not reach the OSPF static redistribution route-map:\n%s", rendered)
	}
	if !strings.Contains(rendered, "match ip next-hop prefix-list ") {
		t.Fatalf("QNH metric route-map must distinguish the qualified gateway, not only the destination:\n%s", rendered)
	}
}

func TestQualifiedNextHopMetricDoesNotSetBGPMetric11447(t *testing.T) {
	compiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols bgp local-as 65001",
		"set protocols bgp export static",
	)
	rendered := New().buildManagedSection(&FullConfig{
		BGP:           compiled.Protocols.BGP,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	})
	if !strings.Contains(rendered, "redistribute static\n") {
		t.Fatalf("BGP static redistribution was lost:\n%s", rendered)
	}
	if strings.Contains(rendered, "redistribute static route-map ") {
		t.Fatalf("qualified-next-hop IGP metric must not become BGP MED:\n%s", rendered)
	}
}

func TestQualifiedNextHopMetricDoesNotOverrideAuthoredPolicyMetric11447(t *testing.T) {
	rendered := qnhMetricRender11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf export EXPORT-STATIC",
		"set policy-options policy-statement EXPORT-STATIC term SET-METRIC from protocol static",
		"set policy-options policy-statement EXPORT-STATIC term SET-METRIC then metric 100",
		"set policy-options policy-statement EXPORT-STATIC term SET-METRIC then accept",
	)
	var mapName string
	for _, line := range strings.Split(rendered, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "redistribute static route-map ") {
			mapName = strings.TrimPrefix(line, "redistribute static route-map ")
			break
		}
	}
	if mapName == "" {
		t.Fatalf("static policy export lacks a route-map:\n%s", rendered)
	}
	block := routeMapBlock11447(rendered, mapName)
	qnhMetric := strings.Index(block, "set metric 10\n")
	authoredMetric := strings.Index(block, "set metric 100\n")
	if qnhMetric < 0 || authoredMetric < 0 {
		t.Fatalf("redistribution map %q must carry QNH metric 10 and authored override 100:\n%s", mapName, rendered)
	}
	if qnhMetric >= authoredMetric {
		t.Fatalf("authored metric must follow and override the QNH fallback metric in map %q:\n%s", mapName, block)
	}
}

func TestQualifiedNextHopMetricMatchesGatewayNotOnlyPrefix11447(t *testing.T) {
	rendered := qnhMetricRender11447(t,
		"set routing-options static route 203.0.113.0/24 next-hop 192.0.2.1",
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.2 metric 10",
		"set protocols ospf export static",
	)
	if !strings.Contains(rendered, "ip prefix-list ") || !strings.Contains(rendered, "192.0.2.2/32") {
		t.Fatalf("route-map must define an exact gateway match for the metric-bearing qualified next-hop:\n%s", rendered)
	}
	if strings.Contains(rendered, "permit 192.0.2.1/32") {
		t.Fatalf("plain primary next-hop must not be assigned the qualified next-hop metric:\n%s", rendered)
	}
}

func TestQualifiedNextHopMetricSupportsHostAndIPv6Routes11447(t *testing.T) {
	t.Run("IPv4 host route", func(t *testing.T) {
		rendered := qnhMetricRender11447(t,
			"set routing-options static route 203.0.113.7 qualified-next-hop 192.0.2.10 metric 10",
			"set protocols ospf export static",
		)
		if !strings.Contains(rendered, "203.0.113.7/32") || !strings.Contains(rendered, "192.0.2.10/32") {
			t.Fatalf("host route QNH metric must match normalized destination and gateway prefixes:\n%s", rendered)
		}
	})

	t.Run("IPv6 route", func(t *testing.T) {
		compiled := compileQNHMetricConfig11447(t,
			"set routing-options static route 2001:db8:10::/64 qualified-next-hop 2001:db8::10 metric 10",
			"set protocols ospf3 area 0.0.0.0 interface ge-0/0/0.0",
			"set protocols ospf3 export static",
		)
		rendered := New().buildManagedSection(&FullConfig{
			OSPFv3:        compiled.Protocols.OSPFv3,
			StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
			PolicyOptions: &compiled.PolicyOptions,
		})
		if !strings.Contains(rendered, "redistribute static route-map ") ||
			!strings.Contains(rendered, "match ipv6 address prefix-list ") ||
			!strings.Contains(rendered, "match ipv6 next-hop prefix-list ") ||
			!strings.Contains(rendered, "set metric 10\n") {
			t.Fatalf("IPv6 QNH metric was not rendered in the OSPFv3 redistribution route-map:\n%s", rendered)
		}
	})
}

func TestFRRLoadQualifiedNextHopMetric11447(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("FRR config check runs as root")
	}
	bgpd := os.Getenv("FRR_BGPD_BINARY")
	if bgpd == "" {
		var err error
		bgpd, err = exec.LookPath("bgpd")
		if err != nil {
			for _, candidate := range []string{"/usr/lib/frr/bgpd", "/usr/libexec/frr/bgpd"} {
				if _, statErr := os.Stat(candidate); statErr == nil {
					bgpd = candidate
					break
				}
			}
		}
	}
	if bgpd == "" {
		t.Skip("FRR bgpd is not installed; config-load validation unavailable")
	}
	compiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols bgp local-as 65001",
		"set protocols bgp export static",
	)
	rendered := New().buildManagedSection(&FullConfig{
		BGP:           compiled.Protocols.BGP,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	})
	if !strings.Contains(rendered, "redistribute static\n") ||
		strings.Contains(rendered, "redistribute static route-map ") ||
		!strings.Contains(rendered, "set metric 10\n") {
		t.Fatalf("FRR check config must contain the generated metric route-map without applying IGP metric as BGP MED:\n%s", rendered)
	}
	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, bgpd, "-C", "-f", confPath).CombinedOutput()
	if err != nil {
		t.Fatalf("FRR bgpd rejected the QNH metric redistribution config: %v\n%s\nconfig:\n%s", err, output, rendered)
	}
}

func TestFRRLoadOSPFQualifiedNextHopMetric11447(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("FRR config check runs as root")
	}
	ospfd := os.Getenv("FRR_OSPFD_BINARY")
	if ospfd == "" {
		var err error
		ospfd, err = exec.LookPath("ospfd")
		if err != nil {
			for _, candidate := range []string{"/usr/lib/frr/ospfd", "/usr/libexec/frr/ospfd"} {
				if _, statErr := os.Stat(candidate); statErr == nil {
					ospfd = candidate
					break
				}
			}
		}
	}
	if ospfd == "" {
		t.Skip("FRR ospfd is not installed; config-load validation unavailable")
	}
	compiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf router-id 10.255.0.1",
		"set protocols ospf export static",
	)
	rendered := New().buildManagedSection(&FullConfig{
		OSPF:          compiled.Protocols.OSPF,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	})
	if !strings.Contains(rendered, "redistribute static route-map ") ||
		!strings.Contains(rendered, "match ip next-hop prefix-list ") ||
		!strings.Contains(rendered, "set metric 10\n") {
		t.Fatalf("compiled OSPF static export omitted the QNH metric route-map:\n%s", rendered)
	}
	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, ospfd, "-C", "-f", confPath).CombinedOutput()
	if err != nil {
		t.Fatalf("FRR ospfd rejected the QNH metric redistribution config: %v\n%s\nconfig:\n%s", err, output, rendered)
	}
}
