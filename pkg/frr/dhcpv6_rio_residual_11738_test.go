package frr

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func renderRIOResidual11738(fc *FullConfig) string {
	var b strings.Builder
	renderDHCPDefaults(&b, fc)
	return b.String()
}

func TestIPv6RIODefaultUsesClasslessInventoryGate11738(t *testing.T) {
	t.Setenv(dhcpClasslessTrustOverrideEnv, "")
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	rio := DHCPRoute{Destination: "::/0", Gateway: "fe80::1", Interface: "wan0", IsIPv6: true}
	got := renderRIOResidual11738(&FullConfig{
		RIBRouteInventoryFailed: true,
		DHCPRoutes:              []DHCPRoute{rio},
	})
	if strings.Contains(got, "ipv6 route ::/0") {
		t.Fatalf("explicit RIO default bypassed fail-closed RIB inventory gate:\n%s", got)
	}
	if !strings.Contains(logs.String(), "without a complete same-table RIB inventory (#11426)") {
		t.Fatalf("explicit RIO default did not traverse classless inventory gate: %s", logs.String())
	}

	logs.Reset()
	got = renderRIOResidual11738(&FullConfig{
		RIBRouteInventoryFailed: true,
		DHCPRoutes:              []DHCPRoute{{Gateway: "fe80::1", Interface: "wan0", IsIPv6: true}},
	})
	if !strings.Contains(got, "ipv6 route ::/0 fe80::1 wan0 200\n") {
		t.Fatalf("ordinary RA default-router gateway should remain independent of classless RIB inventory:\n%s", got)
	}
	if strings.Contains(logs.String(), "incomplete same-table RIB inventory") {
		t.Fatalf("ordinary default gateway incorrectly traversed classless RIB gate: %s", logs.String())
	}
}

func TestIPv6RIODefaultTrustOverrideUsesClasslessPath11738(t *testing.T) {
	t.Setenv(dhcpClasslessTrustOverrideEnv, "1")
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	got := renderRIOResidual11738(&FullConfig{
		RIBRouteInventoryFailed: true,
		DHCPRoutes: []DHCPRoute{{
			Destination: "::/0", Gateway: "fe80::1", Interface: "wan0", IsIPv6: true,
		}},
	})
	if !strings.Contains(got, "ipv6 route ::/0 fe80::1 wan0 200\n") {
		t.Fatalf("explicit trust override should permit broad RIO default:\n%s", got)
	}
	for _, want := range []string{
		"trust override allows a route despite incomplete RIB inventory (#11426)",
		"trust override allows an unsafe route (#9943)",
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("RIO default did not traverse classless trust gate %q; logs: %s", want, logs.String())
		}
	}
}

func TestIPv6RIODefaultTrustOverrideReportsLiveRIBCoverage11738(t *testing.T) {
	t.Setenv(dhcpClasslessTrustOverrideEnv, "1")
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	got := renderRIOResidual11738(&FullConfig{
		RIBRoutes: []RIBRoute{{Destination: "::/0"}},
		DHCPRoutes: []DHCPRoute{{
			Destination: "::/0", Gateway: "fe80::1", Interface: "wan0", IsIPv6: true,
		}},
	})
	if !strings.Contains(got, "ipv6 route ::/0 fe80::1 wan0 200\n") {
		t.Fatalf("explicit trust override should permit the covered RIO route:\n%s", got)
	}
	if !strings.Contains(logs.String(), "trust override allows a route covered by a live same-table RIB route (#11426)") {
		t.Fatalf("RIO default did not report live-RIB coverage through the classless trust gate: %s", logs.String())
	}
}

func TestIPv6RIODefaultTrustOverrideReportsStaticCoverage11738(t *testing.T) {
	t.Setenv(dhcpClasslessTrustOverrideEnv, "1")
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	got := renderRIOResidual11738(&FullConfig{
		Inet6StaticRoutes: []*config.StaticRoute{{
			Destination: "::/0",
			NextHops:    []config.NextHopEntry{{Address: "2001:db8::1"}},
		}},
		DHCPRoutes: []DHCPRoute{{
			Destination: "::/0", Gateway: "fe80::1", Interface: "wan0", IsIPv6: true,
		}},
	})
	if !strings.Contains(got, "ipv6 route ::/0 fe80::1 wan0 200\n") {
		t.Fatalf("explicit trust override should permit the static-covered RIO route:\n%s", got)
	}
	if !strings.Contains(logs.String(), "trust override allows a route covered by a configured static route (#9943)") {
		t.Fatalf("RIO default did not report static coverage through the classless trust gate: %s", logs.String())
	}
}
