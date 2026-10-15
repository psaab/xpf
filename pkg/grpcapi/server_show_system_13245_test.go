// #13245 (D6-05): the gRPC ShowText twins of `show system core-dumps`,
// `show chassis environment`, `show system alarms`, and `show system
// services` diverged from their hardened local-CLI counterparts (#8321
// items 7/8, CLI fabric-auth alarm, services parity).
//
// Every cell drives the REAL Server renderer through a filesystem/config
// seam, not the helper: a cell calling termsafe/formatMilliCelsius directly
// would pass against a call site that stopped using them — exactly the
// defect being fixed.

package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestShowCoreDumpsSanitizesFilenames_13245: a core file whose name carries
// an ANSI erase-display sequence plus a bell (reachable via the crashing
// process's comm, no root needed) must not emit raw ESC/BEL over gRPC, the
// hostile entry must actually be rendered, and a benign name passes through
// byte-identically.
func TestShowCoreDumpsSanitizesFilenames_13245(t *testing.T) {
	dir := t.TempDir()
	hostile := "core.evil\x1b[2J\x07.1000.abc.500.1700000000"
	if err := os.WriteFile(filepath.Join(dir, hostile), []byte("x"), 0o600); err != nil {
		t.Fatalf("write hostile core file: %v", err)
	}
	benign := "core.xpfd.0.def.501.1700000001"
	if err := os.WriteFile(filepath.Join(dir, benign), []byte("x"), 0o600); err != nil {
		t.Fatalf("write benign core file: %v", err)
	}

	old := coreDumpDirs
	coreDumpDirs = []string{dir}
	t.Cleanup(func() { coreDumpDirs = old })

	s := &Server{}
	var buf strings.Builder
	s.showCoreDumps(nil, &buf)
	out := buf.String()

	if strings.Contains(out, "\x1b") || strings.Contains(out, "\x07") {
		t.Fatalf("gRPC core-dumps emitted raw terminal control bytes: %q", out)
	}
	if !strings.Contains(out, "core.evil") {
		t.Fatalf("hostile core entry was silently skipped (vacuous-sanitize): %q", out)
	}
	if !strings.Contains(out, benign) {
		t.Fatalf("benign core name did not survive byte-identically: %q", out)
	}
}

// TestShowChassisEnvironmentRendersSubZero_13245: sub-zero thermal readings
// must render sign-preserving ("-0.5 C", "-12.5 C"), never "0.-5" / "-12.-5";
// a thermal `type` carrying a control byte must be sanitized.
func TestShowChassisEnvironmentRendersSubZero_13245(t *testing.T) {
	for _, tc := range []struct {
		name       string
		milli      string
		zoneType   string
		want       string
		reject     string
		rejectName string
	}{
		{name: "minus-half-degree", milli: "-500", zoneType: "acpitz", want: "-0.5 C", reject: "0.-5"},
		{name: "minus-twelve-point-five", milli: "-12500", zoneType: "acpitz", want: "-12.5 C", reject: "-12.-5"},
		{name: "positive-control", milli: "41500", zoneType: "acpitz", want: "41.5 C", reject: "41.-5"},
		{name: "hostile-type", milli: "25000", zoneType: "evil\x1b[2Jzone", want: "25.0 C", rejectName: "\x1b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			zone := filepath.Join(root, "thermal_zone0")
			if err := os.MkdirAll(zone, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(zone, "temp"), []byte(tc.milli+"\n"), 0o600); err != nil {
				t.Fatalf("write temp: %v", err)
			}
			if err := os.WriteFile(filepath.Join(zone, "type"), []byte(tc.zoneType+"\n"), 0o600); err != nil {
				t.Fatalf("write type: %v", err)
			}

			old := thermalZoneGlob
			thermalZoneGlob = filepath.Join(root, "thermal_zone*", "temp")
			t.Cleanup(func() { thermalZoneGlob = old })

			s := &Server{}
			var buf strings.Builder
			s.showChassisEnvironment(&buf)
			out := buf.String()

			if !strings.Contains(out, tc.want) {
				t.Fatalf("%s millidegrees must render as %q; got\n%s", tc.milli, tc.want, out)
			}
			if tc.reject != "" && strings.Contains(out, tc.reject) {
				t.Fatalf("output still contains the malformed form %q:\n%s", tc.reject, out)
			}
			if tc.rejectName != "" && strings.Contains(out, tc.rejectName) {
				t.Fatalf("thermal zone name emitted raw control byte %q:\n%q", tc.rejectName, out)
			}
		})
	}
}

// TestShowAlarmsFabricAuthAlarm_13245 pins the pre-existing gRPC surface the
// CLI parity cell is compared against (armed downgrade guard, grace expired).
func TestShowAlarmsFabricAuthAlarm_13245(t *testing.T) {
	s := newActiveConfigServer(t)
	s.fabricAuthKeyFn = func() []byte { return []byte("test-fabric-key") }
	// Grace long expired: first observation stamps the timer in the past.
	s.fabricAuthUnarmedSince = s.fabricAuthNow().Add(-2 * fabricAuthUnarmedGrace)
	s.fabricAuthUnarmedSinceSet = true

	var buf strings.Builder
	s.showAlarms(&buf)
	if out := buf.String(); !strings.Contains(out, "fabric authentication remains unarmed") {
		t.Fatalf("gRPC alarms missing fabric-auth unarmed alarm: %q", out)
	}
}

// TestShowSystemServicesParity_13245: the gRPC renderer must carry the same
// config-derived rows the local console renders — SSH line regardless of
// root-login value, SNMP with the community masked unconditionally (#4111/
// #6532 gRPC-side), DHCP/DHCPv6 servers, and per-stream syslog details.
func TestShowSystemServicesParity_13245(t *testing.T) {
	s := newActiveConfigServer(t)
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config")
	}
	cfg.System.Services = &config.SystemServicesConfig{
		SSH: &config.SSHServiceConfig{RootLogin: "deny"},
	}
	cfg.System.SNMP = &config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"private-secret": {Authorization: "read-only"},
		},
	}
	cfg.System.DHCPServer.DHCPLocalServer = &config.DHCPLocalServerConfig{
		Groups: map[string]*config.DHCPServerGroup{"v4": {}},
	}
	cfg.System.DHCPServer.DHCPv6LocalServer = &config.DHCPLocalServerConfig{
		Groups: map[string]*config.DHCPServerGroup{"v6": {}},
	}
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"remote": {Name: "remote", Host: "192.0.2.1", Port: 514},
	}

	var buf strings.Builder
	s.showSystemServices(&buf)
	out := buf.String()
	for _, want := range []string{
		"SSH:            enabled (root-login: deny)",
		"SNMP:           enabled",
		config.SecretDataPlaceholder,
		"DHCP server:    1 group(s)",
		"DHCPv6 server:  1 group(s)",
		"192.0.2.1:514",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("gRPC system services omitted %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "private-secret") {
		t.Fatalf("gRPC services leaked SNMP community secret: %q", out)
	}
}
