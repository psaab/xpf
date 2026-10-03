package appid

import (
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// catalogProtosFor builds the catalog for a config carrying exactly `app` and
// returns the sorted set of protocol numbers the app's CatalogEntry rows use.
func catalogProtosFor(t *testing.T, app *config.Application) []uint8 {
	t.Helper()
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true
	cfg.Applications.Applications = map[string]*config.Application{app.Name: app}
	cat, err := BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}
	var protos []uint8
	for _, e := range cat.Entries {
		if e.Name == app.Name {
			protos = append(protos, e.Protocol)
		}
	}
	sort.Slice(protos, func(i, j int) bool { return protos[i] < protos[j] })
	return protos
}

// TestCatalogExplicitProtocol0DoesNotFanOut is the #4008 RED-on-revert guard.
//
// An application term with an EXPLICIT `protocol 0` names IANA protocol 0
// (HOPOPT) — a single, specific protocol, NOT a wildcard. It must compile to a
// SINGLE catalog entry for protocol 0. The old builder keyed the "any L4"
// fan-out on the RESOLVED protocol number being 0 (`proto == 0`), so an explicit
// `protocol 0` (which ProtocolNumber resolves to (0, true)) fanned out to BOTH
// TCP (6) and UDP (17) — a policy referencing the app then over-matched (a
// single-protocol intent also matched the TCP and UDP flows on the same port).
//
// On revert this goes RED: the reverted builder emits {6, 17} for `protocol 0`.
func TestCatalogExplicitProtocol0DoesNotFanOut(t *testing.T) {
	got := catalogProtosFor(t, &config.Application{
		Name: "p0", Protocol: "0", DestinationPort: "80",
	})
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("explicit `protocol 0` protos = %v, want [0] (a single "+
			"protocol-0 entry, NOT a TCP+UDP fan-out)", got)
	}
}

// TestCatalogOmittedProtocolFansOut pins the DELIBERATE default: an application
// with NO protocol spec means "any L4" and fans out to both TCP and UDP. #4008
// must not regress this — only the RESOLVED-number-0 conflation is removed.
func TestCatalogOmittedProtocolFansOut(t *testing.T) {
	got := catalogProtosFor(t, &config.Application{
		Name: "pomit", DestinationPort: "80",
	})
	want := []uint8{6, 17}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("omitted protocol protos = %v, want %v (TCP+UDP fan-out is "+
			"the documented Junos default for a portless/omitted protocol)", got, want)
	}
}

// TestOmittedProtocolLabelsParityAcrossAppIDKnob11816 pins the same user app
// to TCP+UDP catalog rows when AppID is enabled and tuple labels when disabled.
func TestOmittedProtocolLabelsParityAcrossAppIDKnob11816(t *testing.T) {
	const (
		appName = "omitted-l4-11816"
		dstPort = 65000
	)
	configFor := func(enabled bool) *config.Config {
		cfg := policyRefConfig(map[string]*config.Application{
			appName: {Name: appName, DestinationPort: "65000"},
		})
		cfg.Services.ApplicationIdentification = enabled
		return cfg
	}

	enabledConfig := configFor(true)
	enabledCatalog, err := BuildCatalog(enabledConfig)
	if err != nil {
		t.Fatalf("BuildCatalog with AppID enabled: %v", err)
	}
	entries := entriesForName(enabledCatalog, appName)
	if len(entries) != 2 {
		t.Fatalf("omitted-protocol catalog entries = %v, want TCP and UDP rows", entries)
	}
	appIDByProtocol := make(map[uint8]uint16, 2)
	for _, entry := range entries {
		if entry.DstPortLow != dstPort || entry.DstPortHigh != dstPort {
			t.Fatalf("omitted-protocol entry has unexpected port range: %+v", entry)
		}
		appIDByProtocol[entry.Protocol] = entry.AppID
	}
	if len(appIDByProtocol) != 2 || appIDByProtocol[6] == 0 || appIDByProtocol[17] == 0 {
		t.Fatalf("omitted-protocol app IDs by protocol = %v, want TCP and UDP", appIDByProtocol)
	}
	if appIDByProtocol[6] != appIDByProtocol[17] {
		t.Fatalf("TCP and UDP fan-out IDs differ: %v", appIDByProtocol)
	}

	disabledConfig := configFor(false)
	disabledCatalog, err := BuildCatalog(disabledConfig)
	if err != nil {
		t.Fatalf("BuildCatalog with AppID disabled: %v", err)
	}
	for _, proto := range []uint8{6, 17} {
		enabledLabel := ResolveSessionName(
			enabledCatalog.AppNames, enabledConfig, proto, 40000, dstPort, appIDByProtocol[proto],
		)
		disabledLabel := ResolveSessionName(
			disabledCatalog.AppNames, disabledConfig, proto, 40000, dstPort, 0,
		)
		if enabledLabel != appName || disabledLabel != enabledLabel {
			t.Errorf(
				"protocol %d labels: AppID enabled=%q, disabled=%q; want %q in both modes",
				proto, enabledLabel, disabledLabel, appName,
			)
		}
	}

	// Omitted protocol is TCP+UDP, not an all-protocol match on either path.
	if got := ResolveSessionName(enabledCatalog.AppNames, enabledConfig, 47, 40000, dstPort, 0); got != Unknown {
		t.Errorf("enabled AppID fallback for GRE = %q, want %q", got, Unknown)
	}
	if got := ResolveSessionName(disabledCatalog.AppNames, disabledConfig, 47, 40000, dstPort, 0); got != Unknown {
		t.Errorf("disabled tuple fallback for GRE = %q, want %q", got, Unknown)
	}
}

// TestCatalogExplicitTCPMatchesOnlyTCP is the companion invariant: a normal
// `protocol tcp` term matches ONLY TCP and is unaffected by the #4008 fix.
func TestCatalogExplicitTCPMatchesOnlyTCP(t *testing.T) {
	got := catalogProtosFor(t, &config.Application{
		Name: "ptcp", Protocol: "tcp", DestinationPort: "80",
	})
	if len(got) != 1 || got[0] != 6 {
		t.Fatalf("`protocol tcp` protos = %v, want [6] (TCP only)", got)
	}
	gotUDP := catalogProtosFor(t, &config.Application{
		Name: "pudp", Protocol: "udp", DestinationPort: "80",
	})
	if len(gotUDP) != 1 || gotUDP[0] != 17 {
		t.Fatalf("`protocol udp` protos = %v, want [17] (UDP only)", gotUDP)
	}
}

// TestCatalogProtocol0FromParsedConfig drives the full config-parse path
// (ParseSetCommand + SetPath, the mandated flat-set test shape) so the fix is
// proven end-to-end: `set applications application hopopt protocol 0` compiles
// to a single protocol-0 catalog entry, not a TCP+UDP fan-out.
func TestCatalogProtocol0FromParsedConfig(t *testing.T) {
	tree := &config.ConfigTree{}
	setLines := []string{
		"set applications application hopopt protocol 0",
		"set services application-identification",
	}
	for _, line := range setLines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	cat, err := BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}
	var protos []uint8
	for _, e := range cat.Entries {
		if e.Name == "hopopt" {
			protos = append(protos, e.Protocol)
		}
	}
	if len(protos) != 1 || protos[0] != 0 {
		t.Fatalf("parsed `protocol 0` protos = %v, want [0] (single protocol-0 "+
			"entry, NOT a TCP+UDP fan-out)", protos)
	}
}
