package dataplane

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
)

// appCatalogParityDP is a no-op DataPlane that satisfies the table-write calls
// compileApplications makes so the test can drive the real compiler and capture
// CompileResult.AppNames (the map `show security flow session` resolves app_id
// through). Only the application-table methods are exercised.
type appCatalogParityDP struct {
	DataPlane
}

func (appCatalogParityDP) SetApplication(proto uint8, port uint16, appID uint32, timeout uint32, algType uint8, srcLow, srcHigh uint16) error {
	return nil
}
func (appCatalogParityDP) SetAppRange(idx uint32, entry AppRangeEntry) error { return nil }
func (appCatalogParityDP) DeleteStaleApplications(written map[AppKey]bool)   {}

// TestAppCatalogIDsMatchCompileResultAppNames is the #2008 M5 make-or-break
// wire-parity check: the app_id values appid.BuildCatalog assigns (and ships to
// the Rust dataplane, which stamps them on sessions) MUST equal the app_id ->
// name map compileApplications builds (CompileResult.AppNames, which the gRPC
// show path consumes via ResolveSessionName). If the two builders ever drift in
// name set or id assignment, a session stamped with id N would resolve to the
// wrong name (or UNKNOWN) on the show path. This asserts the two maps are equal.
func TestAppCatalogIDsMatchCompileResultAppNames(t *testing.T) {
	cfg := &config.Config{}
	// Enable application-identification so CatalogNames returns the full
	// predefined + user catalog (the includeAll branch) — the broadest id set.
	cfg.Services.ApplicationIdentification = true
	cfg.Applications.Applications = map[string]*config.Application{
		"my-custom-app": {Name: "my-custom-app", Protocol: "tcp", DestinationPort: "9000-9100"},
		"my-udp-app":    {Name: "my-udp-app", Protocol: "udp", DestinationPort: "7777"},
		// No protocol => any L4 (TCP+UDP fan-out), exercises the proto==0 path.
		"any-l4-app": {Name: "any-l4-app", DestinationPort: "6000"},
	}

	// Real compiler -> AppNames (the SSOT the show path uses). AppIDs is
	// normally allocated by CompileConfig; compileApplications writes into it.
	result := &CompileResult{AppIDs: make(map[string]uint32)}
	if err := compileApplications(appCatalogParityDP{}, cfg, result); err != nil {
		t.Fatalf("compileApplications: %v", err)
	}
	if len(result.AppNames) == 0 {
		t.Fatal("compileApplications produced no AppNames")
	}

	// Catalog builder -> AppNames (what gets shipped to Rust).
	cat, err := appid.BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	if len(cat.AppNames) != len(result.AppNames) {
		t.Fatalf("AppNames size mismatch: catalog=%d compileApplications=%d",
			len(cat.AppNames), len(result.AppNames))
	}
	for id, name := range result.AppNames {
		if got := cat.AppNames[id]; got != name {
			t.Fatalf("app_id %d: compileApplications=%q catalog=%q (drift breaks show resolution)",
				id, name, got)
		}
	}

	// Spot-check that a known app's catalog entry round-trips through
	// ResolveSessionName: lookup the id the catalog assigned to my-udp-app and
	// confirm ResolveSessionName(appNames, ..., id) returns its name.
	var udpID uint16
	for id, name := range cat.AppNames {
		if name == "my-udp-app" {
			udpID = id
		}
	}
	if udpID == 0 {
		t.Fatal("my-udp-app not assigned an app_id")
	}
	got := appid.ResolveSessionName(result.AppNames, cfg, 17, 0, 7777, udpID)
	if got != "my-udp-app" {
		t.Fatalf("ResolveSessionName(udpID=%d) = %q, want my-udp-app", udpID, got)
	}
}

// TestAppCatalogIDsMatchOnMalformedDestPort is the #2065-review regression: a
// user application with an UNPARSABLE destination-port must NOT consume an
// app_id slot, exactly as the compiler's bad-port `continue` skips its
// loop-tail appID++. Before the fix BuildCatalog bumped appID on a bad port,
// shifting every subsequent id by one vs CompileResult.AppNames so the
// Rust-stamped app_id resolved to the wrong name. With a custom app whose
// SORTED name precedes a good one, the bad app sits at a lower id and the
// divergence is observable: this test FAILS pre-fix.
func TestAppCatalogIDsMatchOnMalformedDestPort(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true
	cfg.Applications.Applications = map[string]*config.Application{
		// "aaa-bad" sorts before "zzz-good"; its dest-port is not parseable.
		"aaa-bad":  {Name: "aaa-bad", Protocol: "tcp", DestinationPort: "not-a-port"},
		"zzz-good": {Name: "zzz-good", Protocol: "tcp", DestinationPort: "8443"},
	}

	result := &CompileResult{AppIDs: make(map[string]uint32)}
	if err := compileApplications(appCatalogParityDP{}, cfg, result); err != nil {
		t.Fatalf("compileApplications: %v", err)
	}
	cat, err := appid.BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	// The id->name maps must be identical despite the malformed app.
	if len(cat.AppNames) != len(result.AppNames) {
		t.Fatalf("AppNames size mismatch with a bad-port app: catalog=%d compiler=%d catalog=%v compiler=%v",
			len(cat.AppNames), len(result.AppNames), cat.AppNames, result.AppNames)
	}
	for id, name := range result.AppNames {
		if got := cat.AppNames[id]; got != name {
			t.Fatalf("app_id %d: compiler=%q catalog=%q (bad-port id drift breaks show resolution)",
				id, name, got)
		}
	}
	// zzz-good must resolve through the id the catalog assigned it.
	var goodID uint16
	for id, name := range cat.AppNames {
		if name == "zzz-good" {
			goodID = id
		}
	}
	if goodID == 0 {
		t.Fatal("zzz-good not assigned an app_id")
	}
	if got := appid.ResolveSessionName(result.AppNames, cfg, 6, 0, 8443, goodID); got != "zzz-good" {
		t.Fatalf("ResolveSessionName(goodID=%d) = %q, want zzz-good (id drift)", goodID, got)
	}
}

// TestAppCatalogParityOnTolerantLoadPortEdges is the #3725 M04/H03/M07 lock-step
// guard. Malformed applications admitted by the tolerant-load path — a bad
// source-port ("70000"), a reversed dst range ("300-200"), and a bad dest-port
// ("nope") that sorts LAST — must keep compileApplications' LIVE result.AppNames
// (the map the show path resolves a stamped app_id through) byte-identical to
// appid.BuildCatalog's AppNames, AND neither map may carry a dangling id (a name
// at an id that stamps no catalog entry). Reverting either fix — restoring the
// "record AppNames before the port parse" placement in compileApplications, or
// dropping the emittable gate in BuildCatalog — makes the two maps diverge or
// re-adds the dangling "zzz-nope" entry, turning this RED.
func TestAppCatalogParityOnTolerantLoadPortEdges(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true
	cfg.Applications.Applications = map[string]*config.Application{
		"aaa-good":     {Name: "aaa-good", Protocol: "tcp", DestinationPort: "8443"},
		"bbb-badsrc":   {Name: "bbb-badsrc", Protocol: "tcp", DestinationPort: "80", SourcePort: "70000"},
		"ccc-revrange": {Name: "ccc-revrange", Protocol: "udp", DestinationPort: "300-200"},
		// Sorts last: a bad dest-port with no later good app to overwrite the id.
		"zzz-nope": {Name: "zzz-nope", Protocol: "tcp", DestinationPort: "nope"},
	}

	result := &CompileResult{AppIDs: make(map[string]uint32)}
	if err := compileApplications(appCatalogParityDP{}, cfg, result); err != nil {
		t.Fatalf("compileApplications: %v", err)
	}
	cat, err := appid.BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	// Lock-step: the two AppNames maps must be identical.
	if len(cat.AppNames) != len(result.AppNames) {
		t.Fatalf("AppNames size mismatch on tolerant-load edges: catalog=%d compiler=%d\n catalog=%v\n compiler=%v",
			len(cat.AppNames), len(result.AppNames), cat.AppNames, result.AppNames)
	}
	for id, name := range result.AppNames {
		if got := cat.AppNames[id]; got != name {
			t.Fatalf("app_id %d: compiler=%q catalog=%q (tolerant-load id drift breaks show resolution)", id, name, got)
		}
	}

	// M04: no dangling name at an id that stamps no catalog entry, in EITHER
	// direction. The malformed apps (badsrc/revrange/nope) must not appear.
	//
	// #3781 exception: ApplicationIdentification=true above pulls in the full
	// predefined catalog, including the type-constrained ICMP app
	// junos-icmp-ping (icmp type 8). The interim DELIBERATELY keeps its
	// AppNames row (for byte-identical parity with compileApplications, asserted
	// above) while DROPPING the over-matching protocol-only ICMP catalog entry.
	// Its id is therefore a SAFE dangling id: no shipped catalog entry carries
	// it, so the helper can never stamp it and it resolves to no live session —
	// unlike a malformed app, whose dangling name is a genuine mislabel risk.
	// Skip type-constrained ICMP apps here; every other dangling id is still a
	// bug.
	stamped := map[uint16]bool{}
	for _, e := range cat.Entries {
		stamped[e.AppID] = true
	}
	for id, name := range result.AppNames {
		if !stamped[id] {
			if app, ok := config.ResolveApplication(name, cfg.Applications.Applications); ok && (app.ICMPType != nil || app.ICMPCode != nil) {
				continue // #3781: intentionally dangling-but-inert type-constrained ICMP app
			}
			t.Fatalf("live AppNames[%d]=%q has no catalog entry to stamp it — a skewed app_id would resolve to it instead of UNKNOWN (M04)", id, name)
		}
		if name == "bbb-badsrc" || name == "ccc-revrange" || name == "zzz-nope" {
			t.Fatalf("malformed app %q must not hold a resolvable app_id (%d)", name, id)
		}
	}

	// The one good app resolves; a skewed app_id that no entry stamps resolves
	// to UNKNOWN, never to a malformed name.
	goodID, ok := appNameID(result.AppNames, "aaa-good")
	if !ok {
		t.Fatal("good app aaa-good missing from live AppNames")
	}
	if got := appid.ResolveSessionName(result.AppNames, cfg, 6, 0, 8443, goodID); got != "aaa-good" {
		t.Fatalf("ResolveSessionName(goodID=%d) = %q, want aaa-good", goodID, got)
	}
	// app_id 60000 is not present; with AppID enabled it must be UNKNOWN.
	if got := appid.ResolveSessionName(result.AppNames, cfg, 6, 0, 80, 60000); got != appid.Unknown {
		t.Fatalf("skewed app_id resolved to %q, want UNKNOWN (no dangling malformed name) (M04)", got)
	}
}

func appNameID(names map[uint16]string, want string) (uint16, bool) {
	for id, name := range names {
		if name == want {
			return id, true
		}
	}
	return 0, false
}

// TestAppCatalogEntryPortsAndProtos asserts the catalog builder emits the right
// match shape: a port range stays a range, an omitted protocol fans out to TCP
// AND UDP under one shared app_id, and a single-port entry is exact.
func TestAppCatalogEntryPortsAndProtos(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"range-app": {Name: "range-app", Protocol: "tcp", DestinationPort: "9000-9100"},
		"any-l4":    {Name: "any-l4", DestinationPort: "6000"},
	}
	// Reference both in a policy so the non-includeAll path picks them up.
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust", ToZone: "untrust",
		Policies: []*config.Policy{{
			Name: "p", Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"range-app", "any-l4"},
			},
		}},
	}}

	cat, err := appid.BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	var rangeEntry *appid.CatalogEntry
	var anyL4Protos []uint8
	var anyL4ID uint16
	for i := range cat.Entries {
		e := &cat.Entries[i]
		switch e.Name {
		case "range-app":
			rangeEntry = e
		case "any-l4":
			anyL4Protos = append(anyL4Protos, e.Protocol)
			anyL4ID = e.AppID
		}
	}

	if rangeEntry == nil {
		t.Fatal("range-app missing from catalog")
	}
	if rangeEntry.Protocol != 6 || rangeEntry.DstPortLow != 9000 || rangeEntry.DstPortHigh != 9100 {
		t.Fatalf("range-app entry = %+v, want tcp 9000-9100", *rangeEntry)
	}

	if len(anyL4Protos) != 2 {
		t.Fatalf("any-l4 should fan out to 2 protocols, got %v", anyL4Protos)
	}
	sawTCP, sawUDP := false, false
	for _, p := range anyL4Protos {
		if p == 6 {
			sawTCP = true
		}
		if p == 17 {
			sawUDP = true
		}
	}
	if !sawTCP || !sawUDP {
		t.Fatalf("any-l4 protos = %v, want both TCP(6) and UDP(17)", anyL4Protos)
	}
	// Both fan-out entries share one app_id and one name.
	if anyL4ID == 0 {
		t.Fatal("any-l4 app_id is 0")
	}
	if cat.AppNames[anyL4ID] != "any-l4" {
		t.Fatalf("AppNames[%d] = %q, want any-l4", anyL4ID, cat.AppNames[anyL4ID])
	}
}

// TestCompileApplicationsRejectsAppIDOverflow is the #3438 H4 fail-on-revert
// guard for the LIVE compile path. CompileUserspaceShim -> CompileConfig ->
// compileApplications builds CompileResult.AppNames, the map the AF_XDP show
// path resolves session app_ids through. app_id narrows to a uint16 on the Rust
// wire with 0 reserved as the unknown sentinel, so a config needing more than
// 65535 ids must be rejected deterministically (fail-closed: the apply aborts
// and the daemon keeps the previous-good snapshot) rather than wrapping a
// 65536th id to 0 and overwriting earlier names. Reverting the boundary check
// (uint16(appID) narrowing with no guard) wraps silently and returns no error,
// failing this test. The boundary sibling proves exactly 65535 is accepted.
func TestCompileApplicationsRejectsAppIDOverflow(t *testing.T) {
	// Reject: 65536 referenced applications.
	result := &CompileResult{AppIDs: make(map[string]uint32)}
	if err := compileApplications(appCatalogParityDP{}, compileOverflowConfig(65536), result); err == nil {
		t.Fatal("compileApplications(65536 apps) returned no error; the uint16 app_id space must be rejected, not wrapped to 0")
	}

	// Accept: exactly 65535 applications; no id 0 assigned to a real app.
	okResult := &CompileResult{AppIDs: make(map[string]uint32)}
	if err := compileApplications(appCatalogParityDP{}, compileOverflowConfig(65535), okResult); err != nil {
		t.Fatalf("compileApplications(65535 apps) error = %v; the boundary must be accepted", err)
	}
	if _, hasZero := okResult.AppNames[0]; hasZero {
		t.Fatal("compileApplications assigned the reserved app_id 0 to a real application")
	}
	if len(okResult.AppNames) != 65535 {
		t.Fatalf("compileApplications(65535 apps) produced %d ids, want 65535", len(okResult.AppNames))
	}
}

// compileOverflowConfig builds a config with n distinct TCP/80 applications,
// each referenced by one policy so CatalogNames(cfg, false) returns exactly n
// names (AppID disabled keeps the catalog at the policy-referenced set).
func compileOverflowConfig(n int) *config.Config {
	apps := make(map[string]*config.Application, n)
	match := make([]string, 0, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("app-%06d", i)
		apps[name] = &config.Application{Name: name, Protocol: "tcp", DestinationPort: "80"}
		match = append(match, name)
	}
	return &config.Config{
		Applications: config.ApplicationsConfig{Applications: apps},
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{
				{Policies: []*config.Policy{{Match: config.PolicyMatch{Applications: match}}}},
			},
		},
	}
}
