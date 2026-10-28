package config

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func compileFingerprintConfig17249(t *testing.T, sets ...string) *Config {
	t.Helper()
	cfg, err := CompileConfig(flatTreeFromSets(t, sets...))
	if err != nil {
		t.Fatalf("CompileConfig(%q): %v", sets, err)
	}
	return cfg
}

func TestConfigSemanticFieldsVisible(t *testing.T) {
	wantIgnore := map[string]bool{
		"Config.Diagnostics":                     true,
		"InterfacesConfig.MalformedAddresses":    true,
		"SecurityConfig.MalformedZonePairs":      true,
		"Policy.MalformedZonePairShapes":         true,
		"Policy.UnknownSecurityPoliciesChildren": true,
		"NATRule.LenientMatchDropped":            true,
		"SystemConfig.NTPTrustedKeyIDs":          true,
		"SystemSyslogConfig.TopLevelInert":       true,
		"UserspaceConfig.RetiredKnobsSeen":       true,
	}
	if !reflect.DeepEqual(fingerprintIgnore, wantIgnore) {
		t.Fatalf("fingerprintIgnore = %v, want exactly %v", fingerprintIgnore, wantIgnore)
	}

	visibleFields := []struct {
		typeOf reflect.Type
		name   string
	}{
		{reflect.TypeOf(StaticRoute{}), "NoInstall"},
		{reflect.TypeOf(StaticRoute{}), "HasPreference"},
		{reflect.TypeOf(SystemConfig{}), "NTPPeers"},
		{reflect.TypeOf(SystemConfig{}), "NTPPeerOptions"},
	}
	jsonName := func(field reflect.StructField) string {
		return strings.Split(field.Tag.Get("json"), ",")[0]
	}
	effectiveJSONName := func(field reflect.StructField) string {
		if name := jsonName(field); name != "" {
			return name
		}
		return field.Name
	}
	for _, want := range visibleFields {
		field, ok := want.typeOf.FieldByName(want.name)
		if !ok {
			t.Fatalf("%s.%s does not exist", want.typeOf.Name(), want.name)
		}
		if field.Tag.Get("json") != want.name {
			t.Errorf("%s.%s json tag = %q, want explicit %q",
				want.typeOf.Name(), want.name, field.Tag.Get("json"), want.name)
		}
	}
	staticHasPreference, _ := reflect.TypeOf(StaticRoute{}).FieldByName("HasPreference")
	nextHopHasPreference, _ := reflect.TypeOf(NextHopEntry{}).FieldByName("HasPreference")
	if effectiveJSONName(staticHasPreference) != effectiveJSONName(nextHopHasPreference) {
		t.Errorf("StaticRoute.HasPreference json name %q differs from NextHopEntry.HasPreference name %q",
			effectiveJSONName(staticHasPreference), effectiveJSONName(nextHopHasPreference))
	}

	// Pin every exported json:"-" field reachable from Config. This inventory
	// is separate from fingerprintIgnore: some hidden fields are semantic and
	// still belong in the fingerprint. A new hidden field anywhere in Config's
	// type graph must be reviewed and explicitly classified before it can pass.
	hiddenAllowlist := make(map[string]struct{})
	for _, path := range strings.Fields(`
Address.DNSAddresses
Address.DNSFamily
Address.DNSLookupFailed
Address.DNSName
Address.DuplicatePrefixes
Address.ExpandedPrefixes
Address.OversizedRange
Address.RangeSpec
Address.WildcardSpec
AddressBook.AttachedBookConflict
AddressBook.AttachedBookName
AddressBook.CollidingNames
AddressBook.UnknownBookEntries
ApplicationsConfig.CollidingNames
BGPNeighbor.CrossFamilyInet
BGPNeighbor.GroupType
BGPNeighbor.UnsupportedInet6SAFI
BGPNeighbor.UnsupportedInetSAFI
BridgeDomainConfig.Members
ClassOfServiceConfig.EXPRewriteRuleDefs
ClassOfServiceConfig.INetPrecedenceRewriteRuleDefs
Config.Diagnostics
Config.LenientNATUndefinedZoneRuleSets
Config.PhysicalInterfaces
Config.QuarantinedBridgeDomains
Config.QuarantinedRIMemberDeviceConflicts
Config.QuarantinedRIMemberPrimaryClaims
Config.QuarantinedRoutingInstances
Config.UnimplementedAAALeaves
Config.ZoneQuarantineNames
DHCPServerGroup.MembersFiltered
FirewallConfig.CollidingNames
FirewallFilterTerm.UncoveredFamilyExcept16001
HostInboundTraffic.UnknownChildren
IKEPolicy.PSKQualifierInvalidSpec
IKEProposal.DHGroupInvalidSpec
IKEProposal.LifetimeSecondsInvalidSpec
IPsecPolicyDef.PFSGroupInvalidSpec
IPsecProposal.DHGroupInvalidSpec
IPsecProposal.LifetimeSecondsInvalidSpec
IPsecVPN.PSKQualifierInvalidSpec
InterfaceConfig.AuthoredUnits
InterfaceUnit.FamilyInet
InterfaceUnit.FamilyInet6
InterfaceUnit.ISOAddresses
InterfacesConfig.MalformedAddresses
LoginClass.IdleTimeoutSet
LoginClass.RegexValues15712
NATPool.AddressInvalidSpec
NATPool.DuplicateAddressStatements
NATPool.InvalidAddressRanges
NATPool.OversizedAddressRanges
NATPool.PortNoRandomAllocationAuthored
NATPool.PortRangeInvalidSpec
NATPool.PortRaw
NATPool.UnknownLeaves
NATRule.LenientMatchDropped
NATRule.UnknownMatchLeaves
OSPFInterface.AuthMD5KeyConflictIDs
Policy.MalformedZonePairShapes
Policy.UnknownSecurityPoliciesChildren
PolicyTerm.CommunityAddResolutionFailed
PolicyTerm.CommunityResolutionFailed
PolicyTerm.TerminalActions
ProxyARPEntry.InvalidRangeSpecs
ProxyARPEntry.MalformedRangeSpecs
ProxyARPEntry.OversizedRangeSpecs
RouteFilter.UptoToken
SchedulerConfig.Unresolvable
ScreenProfile.BadNumericUnresolved
SecurityConfig.EnforcementPoliciesChildren
SecurityConfig.EnforcementPoliciesContent
SecurityConfig.MalformedZonePairs
SecurityConfig.UnknownPoliciesChildren
StaticNATRule.InvalidDestinationPorts
StaticNATRule.MappedPortPresent
StaticNATRule.MappedPortRaw
StaticNATRule.ThenTargetCount
StaticNATRule.UnknownMatchLeaves
SystemConfig.NTPTrustedKeyIDs
SystemSyslogConfig.DefaultSourceAddress
SystemSyslogConfig.TopLevelInert
UserspaceConfig.RetiredKnobsSeen
ZoneConfig.DroppedEnforcementChild
ZoneConfig.DroppedEnforcementInterfaces
ZoneConfig.Functional
ZoneConfig.ScreenProfileConfigured
ZoneConfig.UnknownZoneChildren
`) {
		hiddenAllowlist[path] = struct{}{}
	}
	actualHidden := make(map[string]struct{})
	seenTypes := make(map[reflect.Type]struct{})
	var walkConfigTypes func(reflect.Type)
	walkConfigTypes = func(typ reflect.Type) {
		switch typ.Kind() {
		case reflect.Interface:
			t.Errorf("cannot inventory JSON-hidden fields through interface type %v", typ)
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walkConfigTypes(typ.Elem())
		case reflect.Map:
			walkConfigTypes(typ.Key())
			walkConfigTypes(typ.Elem())
		case reflect.Struct:
			if _, seen := seenTypes[typ]; seen {
				return
			}
			seenTypes[typ] = struct{}{}
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.PkgPath != "" {
					continue
				}
				if jsonName(field) == "-" {
					actualHidden[typ.Name()+"."+field.Name] = struct{}{}
				}
				walkConfigTypes(field.Type)
			}
		}
	}
	walkConfigTypes(reflect.TypeOf(Config{}))
	actualPaths := make([]string, 0, len(actualHidden))
	for path := range actualHidden {
		actualPaths = append(actualPaths, path)
	}
	sort.Strings(actualPaths)
	for _, path := range actualPaths {
		if _, ok := hiddenAllowlist[path]; !ok {
			t.Errorf("new exported JSON-hidden Config field %s needs an explicit visibility disposition", path)
		}
	}
	allowedPaths := make([]string, 0, len(hiddenAllowlist))
	for path := range hiddenAllowlist {
		allowedPaths = append(allowedPaths, path)
	}
	sort.Strings(allowedPaths)
	for _, path := range allowedPaths {
		if _, ok := actualHidden[path]; !ok {
			t.Errorf("JSON-hidden field allowlist entry %s is stale", path)
		}
	}

	cfg := &Config{
		RoutingOptions: RoutingOptionsConfig{StaticRoutes: []*StaticRoute{{
			Destination:   "10.172.49.0/24",
			NoInstall:     true,
			Preference:    5,
			HasPreference: true,
		}}},
		System: SystemConfig{
			NTPPeers: []string{"192.0.2.49"},
			NTPPeerOptions: map[string]NTPServerOption{
				"192.0.2.49": {Prefer: true},
			},
		},
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal compiled config: %v", err)
	}
	var got struct {
		RoutingOptions struct {
			StaticRoutes []struct {
				NoInstall     bool
				HasPreference bool
			} `json:"StaticRoutes"`
		} `json:"RoutingOptions"`
		System struct {
			NTPPeers       []string
			NTPPeerOptions map[string]struct {
				Prefer bool
			}
		}
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("decode compiled config JSON: %v", err)
	}
	if len(got.RoutingOptions.StaticRoutes) != 1 ||
		!got.RoutingOptions.StaticRoutes[0].NoInstall ||
		!got.RoutingOptions.StaticRoutes[0].HasPreference {
		t.Errorf("REST JSON route fields missing or false: %s", encoded)
	}
	if !reflect.DeepEqual(got.System.NTPPeers, []string{"192.0.2.49"}) ||
		!got.System.NTPPeerOptions["192.0.2.49"].Prefer {
		t.Errorf("REST JSON NTP peer fields missing or false: %s", encoded)
	}

	// These compiler/runtime markers remain REST-hidden but are still
	// fingerprint-visible; json tags must not control semantic comparison.
	unresolvable := &Config{Schedulers: map[string]*SchedulerConfig{
		"s": {Name: "s", Unresolvable: true},
	}}
	cleanScheduler := &Config{Schedulers: map[string]*SchedulerConfig{
		"s": {Name: "s"},
	}}
	policyWithTerm := func(term *PolicyTerm) *Config {
		return &Config{PolicyOptions: PolicyOptionsConfig{
			PolicyStatements: map[string]*PolicyStatement{
				"p": {Name: "p", Terms: []*PolicyTerm{term}},
			},
		}}
	}
	policyWithAction := func(action string) *Config {
		return policyWithTerm(&PolicyTerm{Name: "t", TerminalActions: []string{action}})
	}
	hiddenMarkersJSON, err := json.Marshal(&Config{
		Schedulers: unresolvable.Schedulers,
		PolicyOptions: policyWithTerm(&PolicyTerm{
			Name:                         "t",
			TerminalActions:              []string{"accept"},
			CommunityResolutionFailed:    true,
			CommunityAddResolutionFailed: true,
		}).PolicyOptions,
	})
	if err != nil {
		t.Fatalf("json.Marshal hidden semantic markers: %v", err)
	}
	hiddenMarkerFields := []string{
		"Unresolvable",
		"TerminalActions",
		"CommunityResolutionFailed",
		"CommunityAddResolutionFailed",
	}
	for _, field := range hiddenMarkerFields {
		if strings.Contains(string(hiddenMarkersJSON), field) {
			t.Errorf("REST JSON unexpectedly exposed compiler-only semantic field %s: %s",
				field, hiddenMarkersJSON)
		}
	}
	if ConfigsIdentical(cleanScheduler, unresolvable) {
		t.Error("SchedulerConfig.Unresolvable is hidden from JSON but must change the fingerprint")
	}
	if ConfigsIdentical(policyWithAction("accept"), policyWithAction("reject")) {
		t.Error("PolicyTerm.TerminalActions is hidden from JSON but must change the fingerprint")
	}
	cleanTerm := policyWithTerm(&PolicyTerm{Name: "t"})
	for _, tc := range []struct {
		name string
		term *PolicyTerm
	}{
		{"CommunityResolutionFailed", &PolicyTerm{Name: "t", CommunityResolutionFailed: true}},
		{"CommunityAddResolutionFailed", &PolicyTerm{Name: "t", CommunityAddResolutionFailed: true}},
	} {
		if ConfigsIdentical(cleanTerm, policyWithTerm(tc.term)) {
			t.Errorf("PolicyTerm.%s is hidden from JSON but must change the fingerprint", tc.name)
		}
	}

	withDiagnostic := &Config{Interfaces: InterfacesConfig{MalformedAddresses: []string{"bad"}}}
	if !ConfigsIdentical(withDiagnostic, &Config{}) {
		t.Error("documented malformed-address diagnostic must remain excluded from fingerprint")
	}
	withStructuredDiagnostic := &Config{Diagnostics: []Diagnostic{{Gate: "gate", Prose: "warning"}}}
	if !ConfigsIdentical(withStructuredDiagnostic, &Config{}) {
		t.Error("structured diagnostics must remain excluded from ConfigFingerprint")
	}
	withInertSyslog := &Config{System: SystemConfig{Syslog: &SystemSyslogConfig{
		TopLevelInert: []string{"archive"},
	}}}
	emptySyslog := &Config{System: SystemConfig{Syslog: &SystemSyslogConfig{}}}
	if !ConfigsIdentical(withInertSyslog, emptySyslog) {
		t.Error("unimplemented syslog keyword diagnostics must remain excluded from ConfigFingerprint")
	}
	if !ConfigsIdentical(&Config{Warnings: []string{"warning"}}, &Config{}) {
		t.Error("Warnings must remain excluded from ConfigFingerprint")
	}
}

func TestConfigFingerprintIncludesRuntimeSemanticFields17249(t *testing.T) {
	const route = "set routing-options static route 10.172.49.0/24 next-hop 192.0.2.49"
	baseRoute := compileFingerprintConfig17249(t, route)
	noInstallRoute := compileFingerprintConfig17249(t, route,
		"set routing-options static route 10.172.49.0/24 no-install")
	if !noInstallRoute.RoutingOptions.StaticRoutes[0].NoInstall {
		t.Fatal("precondition: no-install did not compile")
	}
	if ConfigsIdentical(baseRoute, noInstallRoute) {
		t.Error("no-install and installable static routes must compare different")
	}

	serverWithoutPeer := compileFingerprintConfig17249(t, "set system ntp server 192.0.2.49")
	serverWithPeer := compileFingerprintConfig17249(t,
		"set system ntp server 192.0.2.49",
		"set system ntp peer 192.0.2.49")
	peerPrefer := compileFingerprintConfig17249(t,
		"set system ntp server 192.0.2.49",
		"set system ntp peer 192.0.2.49",
		"set system ntp peer 192.0.2.49 prefer")
	if !peerPrefer.System.NTPPeerOptions["192.0.2.49"].Prefer {
		t.Fatal("precondition: NTP peer prefer option did not compile")
	}
	if ConfigsIdentical(serverWithoutPeer, serverWithPeer) {
		t.Error("adding an NTP peer must change the fingerprint when the rest of config is unchanged")
	}
	if ConfigsIdentical(serverWithPeer, peerPrefer) {
		t.Error("changing NTP peer options must change the fingerprint")
	}

	withoutPreference := baseRoute
	preferenceFive := compileFingerprintConfig17249(t, route,
		"set routing-options static route 10.172.49.0/24 preference 5")
	if withoutPreference.RoutingOptions.StaticRoutes[0].Preference !=
		preferenceFive.RoutingOptions.StaticRoutes[0].Preference ||
		!preferenceFive.RoutingOptions.StaticRoutes[0].HasPreference {
		t.Fatal("precondition: explicit default preference did not differ only by authored-presence state")
	}
	if ConfigsIdentical(withoutPreference, preferenceFive) {
		t.Error("an explicit preference 5 must compare different from an absent preference")
	}

	serverA := compileFingerprintConfig17249(t, "set system ntp server 192.0.2.11")
	serverB := compileFingerprintConfig17249(t, "set system ntp server 192.0.2.12")
	if ConfigsIdentical(serverA, serverB) {
		t.Error("positive control: different NTP server addresses must compare different")
	}
	preferenceSeven := compileFingerprintConfig17249(t, route,
		"set routing-options static route 10.172.49.0/24 preference 7")
	if ConfigsIdentical(baseRoute, preferenceSeven) {
		t.Error("positive control: preference 7 must compare different from the default")
	}
}
func TestConfigFingerprintIncludesNATUnknownMatchVerdict17249(t *testing.T) {
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	}
	valid := lenientNAT9877(t, lines)
	typoLines := append(append([]string(nil), lines...),
		"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16")
	typo := lenientNAT9877(t, typoLines)
	validRule := sourceRule9877(t, valid, "rs1", "r1")
	typoRule := sourceRule9877(t, typo, "rs1", "r1")
	if reason := SourceNATRuleExcludedReason(validRule); reason != "" {
		t.Fatalf("control rule excluded: %s", reason)
	}
	if reason := SourceNATRuleExcludedReason(typoRule); reason == "" {
		t.Fatal("typo'd match was not marked for fail-closed exclusion")
	}
	if ConfigsIdentical(valid, typo) {
		t.Error("a dropped NAT match leaf changes installation behavior and must change the fingerprint")
	}

	// Warnings are already out-of-band; after removing the one behavioral
	// verdict marker, the compiled configs must otherwise compare equal.
	typoRule.UnknownMatchLeaves = nil
	if !ConfigsIdentical(valid, typo) {
		t.Error("UnknownMatchLeaves must be the only fingerprint difference in this paired fixture")
	}
}

func TestConfigFingerprintIncludesUnredactedValues17249(t *testing.T) {
	secretConfig := func(secret string) *Config {
		return &Config{Chassis: ChassisConfig{Cluster: &ClusterConfig{
			ControlLinkAuthKey: NewSecret(secret),
		}}}
	}
	secretA := secretConfig("distinct-secret-a-17249")
	secretB := secretConfig("distinct-secret-b-17249")
	if ConfigsIdentical(secretA, secretB) {
		t.Error("different Secret values must affect ConfigFingerprint despite MarshalJSON redaction")
	}
	secretFingerprint := ConfigFingerprint(secretA)
	if strings.Contains(secretFingerprint, "distinct-secret-a-17249") {
		t.Error("ConfigFingerprint exposed secret plaintext instead of returning an opaque digest")
	}

	urlA := &Config{System: SystemConfig{LicenseAutoUpdate: "https://user:pass@example.test/?token=alpha"}}
	urlB := &Config{System: SystemConfig{LicenseAutoUpdate: "https://user:pass@example.test/?token=bravo"}}
	if ConfigsIdentical(urlA, urlB) {
		t.Error("different credential URLs must affect ConfigFingerprint despite MarshalJSON redaction")
	}
	urlFingerprint := ConfigFingerprint(urlA)
	if strings.Contains(urlFingerprint, "token=alpha") || strings.Contains(urlFingerprint, "user:pass") {
		t.Error("ConfigFingerprint exposed credential URL content instead of returning an opaque digest")
	}
}

func TestLegacyConfigJSONDecodesWithDefaults17249(t *testing.T) {
	const legacyJSON = `{"RoutingOptions":{"StaticRoutes":[{"Destination":"10.172.49.0/24","Preference":5}]},"System":{}}`
	var cfg Config
	if err := json.Unmarshal([]byte(legacyJSON), &cfg); err != nil {
		t.Fatalf("decode legacy compiled-config JSON without the new fields: %v", err)
	}
	if len(cfg.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("legacy StaticRoutes = %d, want 1", len(cfg.RoutingOptions.StaticRoutes))
	}
	route := cfg.RoutingOptions.StaticRoutes[0]
	if route.NoInstall || route.HasPreference {
		t.Errorf("legacy route defaults = NoInstall:%t HasPreference:%t, want false/false",
			route.NoInstall, route.HasPreference)
	}
	if cfg.System.NTPPeers != nil || cfg.System.NTPPeerOptions != nil {
		t.Errorf("legacy NTP defaults = peers:%v options:%v, want nil/nil",
			cfg.System.NTPPeers, cfg.System.NTPPeerOptions)
	}
}
