package dataplane

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16143: compiler_nat.go DNAT diagnostics must see EVERY plural value, not
// only the scalar first element. A bracket-list rule whose SECOND
// destination is invalid, whose SECOND source/destination address-name is
// unknown, or whose SECOND application is unknown must warn for that value.
// Before the fix only DestinationAddress/Application/SourceAddressName
// scalars were read, so all three warnings were invisible.
//
// Fail-on-revert: restore any scalar read in the DNAT diagnostic block and
// the corresponding subtest goes RED (warning absent).

func captureSlog16143(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func dnatDiagConfig16143(match config.NATMatch) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {Name: "untrust"},
	}
	cfg.Applications.Applications = map[string]*config.Application{
		"app-good": {Name: "app-good", Protocol: "tcp", DestinationPort: "80"},
	}
	cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"dp": {Name: "dp", Address: "10.0.0.5", Port: 8080},
		},
		RuleSets: []*config.NATRuleSet{
			{
				Name: "rs-dnat", FromZone: "untrust",
				Rules: []*config.NATRule{
					{Name: "r1", Match: match, Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"}},
				},
			},
		},
	}
	return cfg
}

func runDNATDiag16143(t *testing.T, match config.NATMatch) string {
	t.Helper()
	buf := captureSlog16143(t)
	cfg := dnatDiagConfig16143(match)
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	// notAValidationDP reports the real pass, so compileWarn/compileInfo emit.
	if err := compileNAT(&notAValidationDP{}, cfg, result); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	return buf.String()
}

func TestDNATDiagnosticsSeePluralValues16143(t *testing.T) {
	t.Run("second destination invalid warns", func(t *testing.T) {
		out := runDNATDiag16143(t, config.NATMatch{
			DestinationAddress:   "203.0.113.10/32",
			DestinationAddresses: []string{"203.0.113.10/32", "not-an-ip"},
		})
		if !strings.Contains(out, "invalid DNAT match address") || !strings.Contains(out, "not-an-ip") {
			t.Errorf("second plural destination must warn as invalid; got:\n%s", out)
		}
		// First (valid) destination still logs compiled.
		if !strings.Contains(out, "destination NAT rule compiled") {
			t.Errorf("valid first destination must still log compiled; got:\n%s", out)
		}
	})

	t.Run("second source-address-name unknown warns", func(t *testing.T) {
		out := runDNATDiag16143(t, config.NATMatch{
			DestinationAddress: "203.0.113.10/32",
			SourceAddressName:  "known-placeholder",
			SourceAddressNames: []string{"known-placeholder", "missing-src-name"},
		})
		// Both names are absent from AddrIDs; the plural-only second name
		// must appear. Scalar-only code would never name it.
		if !strings.Contains(out, "missing-src-name") {
			t.Errorf("second source-address-name must warn by name; got:\n%s", out)
		}
	})

	t.Run("second destination-address-name unknown warns", func(t *testing.T) {
		out := runDNATDiag16143(t, config.NATMatch{
			DestinationAddress:      "203.0.113.10/32",
			DestinationAddressName:  "first-name",
			DestinationAddressNames: []string{"first-name", "missing-dst-name"},
		})
		if !strings.Contains(out, "missing-dst-name") {
			t.Errorf("second destination-address-name must warn by name; got:\n%s", out)
		}
	})

	t.Run("second application unknown warns", func(t *testing.T) {
		out := runDNATDiag16143(t, config.NATMatch{
			DestinationAddress: "203.0.113.10/32",
			Application:        "app-good",
			Applications:       []string{"app-good", "app-missing"},
		})
		if !strings.Contains(out, "app-missing") {
			t.Errorf("second application must warn by name; got:\n%s", out)
		}
		if strings.Contains(out, "app-good") && strings.Contains(out, "DNAT application not found") {
			// app-good resolves; only app-missing may produce that warning.
			// (Guard is name-specific above; this just documents intent.)
		}
	})

	t.Run("scalar-only still warns and compiles", func(t *testing.T) {
		out := runDNATDiag16143(t, config.NATMatch{
			DestinationAddress: "203.0.113.10/32",
			Application:        "app-missing-scalar",
		})
		if !strings.Contains(out, "app-missing-scalar") {
			t.Errorf("scalar-only application must still warn; got:\n%s", out)
		}
		if !strings.Contains(out, "destination NAT rule compiled") {
			t.Errorf("scalar-only rule must still log compiled; got:\n%s", out)
		}
	})

	t.Run("plural-only destination compiles", func(t *testing.T) {
		// Older-peer / hand-built shape: plural populated, scalar empty.
		// Scalar-only code warned "no match destination-address" and skipped.
		out := runDNATDiag16143(t, config.NATMatch{
			DestinationAddresses: []string{"203.0.113.20/32"},
		})
		if strings.Contains(out, "DNAT rule has no match destination-address") {
			t.Errorf("plural-only destination must not be treated as absent; got:\n%s", out)
		}
		if !strings.Contains(out, "destination NAT rule compiled") {
			t.Errorf("plural-only destination must log compiled; got:\n%s", out)
		}
	})
}
