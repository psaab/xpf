package dataplane

// #4960 probe: is CompileConfig's ID assignment deterministic across two
// passes with a fresh CompileResult each time?
//
// The additive validate-pre-pass design compiles the config TWICE and discards
// the first result. That is only free if no ID assignment reads or mutates
// state outliving a single CompileResult -- a process-global, a counter on the
// DataPlane, an interned table. A fresh result isolates state IN the result and
// nothing else, so this is measured rather than reasoned about: run the
// ID-assigning phases twice and compare every ID map.
//
// NOT "against the same dp" (#6894 r7 C5): compileIDsOnce constructs a FRESH
// idProbeDP{} per invocation, so a per-instance counter on the dataplane would
// reset between the two passes and both snapshots would compare equal. The
// header used to claim the same-object shape while the implementation did the
// opposite, with a later comment admitting the limitation — the file
// contradicted itself. What this probe detects is state outliving a
// CompileResult that is NOT per-dp-instance: a package-level sequence, an
// interned table, a process global.
//
// The fake embeds the DataPlane interface (the userspace LegacyDataPlaneAdapter
// idiom) so it satisfies all 130 methods while overriding only the 34 the pure
// phases actually call. Any method reached that is NOT overridden nil-panics,
// which is the desired behaviour for a probe: it surfaces an unexpected call
// rather than silently succeeding.

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// idProbeEgressIface is the egress-zone member idProbeConfig declares. It is
// deliberately a name no host carries, so the SNAT-egress branch soft-skips
// everywhere except the one test that seeds a synthetic ifCache entry for it.
const idProbeEgressIface = "xpfp4960e"

type idProbeDP struct{ DataPlane }

func (idProbeDP) IsLoaded() bool { return true }

func (idProbeDP) SetZonePairPolicy(fromZone, toZone uint32, ps PolicySet) error { return nil }
func (idProbeDP) SetPolicyRule(policySetID uint32, ruleIndex uint32, rule PolicyRule) error {
	return nil
}
func (idProbeDP) SetAddressBookEntry(cidr string, addressID uint32) error { return nil }
func (idProbeDP) SetAddressMembership(resolvedID, setID uint32) error     { return nil }
func (idProbeDP) ClearAddressBookV4() error                               { return nil }
func (idProbeDP) ClearAddressBookV6() error                               { return nil }
func (idProbeDP) ClearAddressMembership() error                           { return nil }
func (idProbeDP) SetApplication(protocol uint8, dstPort uint16, appID uint32, timeout uint32, algType uint8, srcPortLow, srcPortHigh uint16) error {
	return nil
}
func (idProbeDP) SetAppRange(index uint32, entry AppRangeEntry) error                     { return nil }
func (idProbeDP) SetDNATEntry(key DNATKey, val DNATValue) error                           { return nil }
func (idProbeDP) SetDNATEntryV6(key DNATKeyV6, val DNATValueV6) error                     { return nil }
func (idProbeDP) SetSNATRule(fromZone, toZone, ruleIdx uint16, val SNATValue) error       { return nil }
func (idProbeDP) SetSNATRuleV6(fromZone, toZone, ruleIdx uint16, val SNATValueV6) error   { return nil }
func (idProbeDP) SetNATPoolConfig(poolID uint32, cfg NATPoolConfig) error                 { return nil }
func (idProbeDP) SetNATPoolIPV4(poolID, index uint32, ip uint32) error                    { return nil }
func (idProbeDP) SetNATPoolIPV6(poolID, index uint32, ip [16]byte) error                  { return nil }
func (idProbeDP) SetSNATEgressIP(key SNATEgressKey, val SNATEgressValue) error            { return nil }
func (idProbeDP) ClearSNATEgressIPs() error                                               { return nil }
func (idProbeDP) SetStaticNATEntryV4(ip uint32, direction uint8, translated uint32) error { return nil }
func (idProbeDP) SetStaticNATEntryV6(ip [16]byte, direction uint8, translated [16]byte) error {
	return nil
}
func (idProbeDP) SetNPTv6Rule(key NPTv6Key, val NPTv6Value) error          { return nil }
func (idProbeDP) DeleteStaleNPTv6(written map[NPTv6Key]bool)               {}
func (idProbeDP) SetNAT64Config(index uint32, cfg NAT64Config) error       { return nil }
func (idProbeDP) SetNAT64Count(count uint32) error                         { return nil }
func (idProbeDP) DeleteStaleZonePairPolicies(written map[ZonePairKey]bool) {}
func (idProbeDP) DeleteStaleApplications(written map[AppKey]bool)          {}
func (idProbeDP) DeleteStaleSNATRules(written map[SNATKey]bool)            {}
func (idProbeDP) DeleteStaleSNATRulesV6(written map[SNATKey]bool)          {}
func (idProbeDP) DeleteStaleDNATStatic(written map[DNATKey]bool)           {}
func (idProbeDP) DeleteStaleDNATStaticV6(written map[DNATKeyV6]bool)       {}
func (idProbeDP) DeleteStaleStaticNAT(writtenV4 map[StaticNATKeyV4]bool, writtenV6 map[StaticNATKeyV6]bool) {
}
func (idProbeDP) GetPersistentNAT() *PersistentNATTable { var z *PersistentNATTable; return z }

// idProbeConfig exercises every ID-assigning phase that the validate-pre-pass
// would run: zones (ZoneIDs), screen profiles (ScreenIDs), the address book
// (AddrIDs + implicitSets), applications (AppIDs), and NAT (PoolIDs +
// NATCounterIDs, the #5099 collision-order-sensitive family).
//
// It is ALSO the fixture TestPrePassShimCoversTheCalledSurface_4960 drives to
// prove discardingDataPlane's override set is complete, and that second job is
// what sizes it (#6894 r3 F1). Reaching every PHASE is not the same as reaching
// every phase's WRITE SURFACE: measured at r2, this config reached 28 of the 40
// overrides, and nine of them -- SetDNATEntry, SetDNATEntryV6, SetNAT64Config,
// SetNATPoolIPV6, SetNPTv6Rule, SetSNATEgressIP, SetSNATRuleV6,
// SetStaticNATEntryV4, SetStaticNATEntryV6 -- were reached by NO test in the
// package, so any one of them could be deleted with the suite still green while
// an ordinary `security nat destination` config nil-panicked the daemon on
// apply. Every NAT family below exists to close that: destination NAT (v4+v6),
// static NAT (v4+v6), NPTv6, NAT64, an IPv6 source pool with its v6 SNAT rule,
// an interface-SNAT rule that yields an egress IP, and a security policy.
//
// Keep it able to reach all 39 pre-pass-reachable overrides when adding to it;
// the 40th, IsLoaded, is called by CompileConfig itself (compiler.go, CompileConfig's IsLoaded gate),
// above the pre-pass, so no config can reach it from validateBeforeMutate.
//
// Interface names are deliberately outside the vSRX scheme. The zone interface
// list became load-bearing here when the interface-SNAT rule was added, and
// `ge-0-0-1` is a real link on the standalone test VM and on loss cluster node
// 0 -- so a vSRX-shaped name would make this fixture resolve differently on a
// firewall than on a dev host, and would name a live link in a config that a
// future test could hand to CompileConfig.
func idProbeConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"xpfp4960a.0"}},
		"untrust": {Name: "untrust", Interfaces: []string{"xpfp4960b.0"}},
		"dmz":     {Name: "dmz", Interfaces: []string{"xpfp4960c.0"}},
		// The interface-SNAT egress zone. Its member is declared with a
		// redundancy group so compileNAT reads the egress addresses from the
		// CONFIG rather than querying the live interface -- the only remaining
		// host dependency is then the ifindex lookup, which
		// TestPrePassShimCoversTheCalledSurface_4960 satisfies with a synthetic
		// ifCache entry rather than a real link.
		"egress": {Name: "egress", Interfaces: []string{idProbeEgressIface + ".0"}},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"zeta": {Name: "zeta"}, "alpha": {Name: "alpha"}, "mid": {Name: "mid"},
	}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"web": {Name: "web", Value: "10.1.0.0/16"},
			"db":  {Name: "db", Value: "10.2.0.0/16"},
			"dns": {Name: "dns", Value: "10.3.0.1/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			"servers": {Name: "servers", Addresses: []string{"web", "db"}},
		},
	}
	// includeAll mode: CatalogNames collects every predefined + user app, so
	// AppIDs is populated without needing a policy to reference each one. Same
	// config.AssignStableAppIDs path either way.
	cfg.Services.ApplicationIdentification = true
	cfg.Applications.Applications = map[string]*config.Application{
		"app-ssh":  {Name: "app-ssh", Protocol: "tcp", DestinationPort: "22"},
		"app-http": {Name: "app-http", Protocol: "tcp", DestinationPort: "80"},
		"app-dns":  {Name: "app-dns", Protocol: "udp", DestinationPort: "53"},
	}
	// The egress-zone member. RedundancyGroup > 0 routes compileNAT's
	// interface-SNAT branch down the RETH path, which takes the egress IPs from
	// these unit addresses instead of querying the live interface.
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		idProbeEgressIface: {
			Name: idProbeEgressIface, RedundancyGroup: 1,
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"203.0.113.7/24", "2001:db8:e::7/64"}},
			},
		},
	}
	// Security policies, so compilePolicies reaches SetZonePairPolicy and
	// SetPolicyRule (neither was reached before r3) and so resolveAddrList
	// builds IMPLICIT ADDRESS SETS (implicitSets was empty before r4).
	//
	// p-multi is what populates implicitSets, and its address lists have to be
	// MULTI-valued to do it: resolveAddrList (compiler.go, resolveAddrList) filters "any"
	// out entirely and returns a single remaining name through the direct-ID
	// branch, so both of p-single's lists resolve without building a set. Only
	// two-or-more surviving names take the implicit-set branch that writes
	// result.implicitSets. p-single is kept alongside precisely because those
	// two shapes are the ones that do NOT populate it — a negative control for
	// the assertion in TestPrePassDoesNotPerturbIDAssignment_4960 that the
	// expected set keys are present.
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{
				{
					Name: "p-multi",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"web", "db"},
						DestinationAddresses: []string{"dns", "servers"},
						Applications:         []string{"app-ssh", "app-http"},
					},
					Action: config.PolicyPermit,
				},
				{
					Name: "p-single",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"servers"},
						Applications:         []string{"app-dns"},
					},
					Action: config.PolicyPermit,
					// #6894 r8 F4: the ONLY writer of
					// result.PolicyScheduleRuleSlots is compilePolicies'
					// `if pol.SchedulerName != ""` branch (compiler.go).
					// Without a scheduled policy that column is an
					// empty-vs-empty DeepEqual forever. compilePolicies does
					// not resolve the name against cfg.Schedulers — it records
					// the slot verbatim — so a name alone reaches the writer.
					SchedulerName: "sched-6894",
				},
			},
		},
	}
	// Source NAT: two pools and three rules across two rule-sets. This is the
	// #5099 dimension -- PoolIDs and the per-rule NATCounterIDs whose streaming
	// assignment was compile-order dependent on a hash collision, which is why
	// finalizeNATCounterIDs exists. Without these the ID comparison is
	// {} == {} and proves nothing about the risk the pre-pass actually carries.
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"pool-b": {Name: "pool-b", Addresses: []string{"192.0.2.10", "192.0.2.11"}},
		"pool-a": {Name: "pool-a", Addresses: []string{"198.51.100.5"}},
		// v6-only pool: hasV6 is what selects the SetSNATRuleV6 write, and the
		// pool addresses are what reach SetNATPoolIPV6.
		"pool-v6": {Name: "pool-v6", Addresses: []string{"2001:db8:6::1", "2001:db8:6::2"}},
		// Referenced only by the NAT64 rule-set below, so compileNAT64 takes its
		// auto-assign branch (a pool defined but never used by an SNAT rule).
		"pool-nat64": {Name: "pool-nat64", Addresses: []string{"192.0.2.64"}},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name: "rs-trust-untrust", FromZone: "trust", ToZone: "untrust",
			Rules: []*config.NATRule{
				{Name: "r-web", Match: config.NATMatch{SourceAddress: "10.1.0.0/16"},
					Then: config.NATThen{Type: config.NATSource, PoolName: "pool-a"}},
				{Name: "r-db", Match: config.NATMatch{SourceAddress: "10.2.0.0/16"},
					Then: config.NATThen{Type: config.NATSource, PoolName: "pool-b"}},
				{Name: "r-v6", Match: config.NATMatch{SourceAddress: "2001:db8:1::/64"},
					Then: config.NATThen{Type: config.NATSource, PoolName: "pool-v6"}},
			},
		},
		{
			Name: "rs-dmz-untrust", FromZone: "dmz", ToZone: "untrust",
			Rules: []*config.NATRule{
				{Name: "r-dmz", Match: config.NATMatch{SourceAddress: "10.3.0.0/16"},
					Then: config.NATThen{Type: config.NATSource, Interface: true}},
			},
		},
		{
			// Interface mode against a to-zone whose member carries configured
			// addresses: this is the SetSNATEgressIP path. It soft-skips unless
			// the interface resolves, which is why the completeness test seeds
			// an ifCache entry for it.
			Name: "rs-trust-egress", FromZone: "trust", ToZone: "egress",
			Rules: []*config.NATRule{
				{Name: "r-egress", Match: config.NATMatch{SourceAddress: "10.1.0.0/16"},
					Then: config.NATThen{Type: config.NATSource, Interface: true}},
			},
		},
	}
	// Destination NAT, v4 and v6. The pool takes `Address` (a single host
	// address) plus `Port`; `Addresses` is source-only and would silently warn
	// "invalid DNAT pool address". The match must be a host address too -- a
	// network prefix is a hard error, not a skip.
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"dpool-v4": {Name: "dpool-v4", Address: "10.4.0.9", Port: 8080},
			"dpool-v6": {Name: "dpool-v6", Address: "2001:db8:d::9", Port: 8080},
		},
		RuleSets: []*config.NATRuleSet{
			{
				Name: "rs-dnat", FromZone: "untrust",
				Rules: []*config.NATRule{
					{Name: "d-v4", Match: config.NATMatch{
						DestinationAddress: "198.51.100.9/32", DestinationPort: 443, Protocol: "tcp"},
						Then: config.NATThen{Type: config.NATDestination, PoolName: "dpool-v4"}},
					{Name: "d-v6", Match: config.NATMatch{
						DestinationAddress: "2001:db8:9::9/128", DestinationPort: 443, Protocol: "tcp"},
						Then: config.NATThen{Type: config.NATDestination, PoolName: "dpool-v6"}},
				},
			},
		},
	}
	// Static NAT (v4 and v6) plus one NPTv6 rule. compileStaticNAT skips
	// IsNPTv6 rules and compileNPTv6 handles only those, so the three rules
	// below reach three different write surfaces from one rule-set. NPTv6
	// prefixes must be IPv6, equal length, and /48 or /64.
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{
			Name: "rs-static", FromZone: "untrust",
			Rules: []*config.StaticNATRule{
				{Name: "s-v4", Match: "198.51.100.20", Then: "10.4.0.20"},
				{Name: "s-v6", Match: "2001:db8:20::20", Then: "fd00:20::20"},
				{Name: "s-npt", IsNPTv6: true,
					Match: "2001:db8:48::/48", Then: "fd00:48::/48"},
			},
		},
	}
	// NAT64: the prefix must be a /96, and the source pool must exist.
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{
		{Name: "rs64", Prefix: "64:ff9b::/96", SourcePool: "pool-nat64"},
	}
	return cfg
}

// compileIDsOnce runs the ID-ASSIGNING phases against a fresh CompileResult
// and returns the assigned IDs. Deliberately NOT the pre-pass's phase set: it
// is the ID-assigning subset PLUS finalizeNATCounterIDs, which the pre-pass
// does not call. The question here is ID stability across two compiles, not
// pre-pass coverage (#6894 r1 F5).
//
// The subset and its ORDER are CompileConfig's, and both matter (#6894 r4).
// Until r4 this ran address book -> applications -> NAT -> finalize, which
// left three of the ID dimensions it compares structurally unable to differ:
//
//   - implicitSets was ALWAYS empty. Its only writer is resolveAddrList
//     (compiler.go, resolveAddrList's implicitSets write), reached through compilePolicies, which was not
//     called. An empty map compares equal to an empty map, so that column of
//     the DeepEqual proved nothing.
//   - The static-NAT counter keys were never assigned. compileStaticNAT
//     assigns them (compiler_nat.go:1013) and production finalizes AFTER it
//     (compiler.go, the finalizeNATCounterIDs call); finalizing straight after compileNAT measured
//     neither the assignment nor its effect on the collision re-derivation.
//   - pool-nat64 never entered PoolIDs and NextPoolID never advanced.
//     compileNAT64's auto-assign branch (compiler_nat.go:1243-1245) is what
//     does both, and it was not called.
//
// So the phases below are CompileConfig Phases 3, 4, 5, 6, 6.5, the
// finalization, and 6.6, in that order. compileNPTv6 (Phase 6.7) is
// deliberately absent: it takes no *CompileResult and assigns no IDs.
// Re-check that when adding a phase — running a phase out of order here is as
// wrong as not running it, because finalizeNATCounterIDs' position is itself
// part of what is being measured.
//
// ScreenIDs was a FOURTH vacuous dimension, failing one level below the r4
// three: the driver did run Phase 1.5, but by RE-IMPLEMENTING it rather than
// calling production, so that column compared this function's own loop against
// itself. Measured: seeding that assignment from a package-level counter, at
// either production site, left the whole package green. The prelude is now the
// single assignScreenIDs (compiler.go) that both production sites call. Call
// production phases here; never restate one.
//
// WHAT A GREEN HERE DOES AND DOES NOT MEAN — this applies to EVERY column, not
// just ScreenIDs, and reading it wrong overstates all of them. The test
// compares two passes of the SAME phases over the SAME config, so it detects
// perturbation ACROSS passes: state outliving a CompileResult — a
// process-global, a package-level sequence, an interned table — which is the
// #4960 question, since the pre-pass compiles twice and throws the first result
// away. It does NOT detect incorrect assignment WITHIN a pass. Anything applied
// identically to both passes (a wrong seed, a wrong sort key, a wrong id
// formula) produces two identical maps and stays green by construction. A green
// says "compiling twice is free", not "the ids are right"; the correctness of
// each assignment is owned by that phase's own tests. The non-vacuity floors
// below are a separate matter again — they only keep a column from being an
// empty-vs-empty comparison.
func compileIDsOnce(t *testing.T, cfg *config.Config) map[string]any {
	t.Helper()
	dp := idProbeDP{}
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)
	if err := compileAddressBook(dp, cfg, result); err != nil {
		t.Fatalf("compileAddressBook: %v", err)
	}
	if err := compileApplications(dp, cfg, result); err != nil {
		t.Fatalf("compileApplications: %v", err)
	}
	if err := compilePolicies(dp, cfg, result); err != nil {
		t.Fatalf("compilePolicies: %v", err)
	}
	if err := compileNAT(dp, cfg, result); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	if err := compileStaticNAT(dp, cfg, result); err != nil {
		t.Fatalf("compileStaticNAT: %v", err)
	}
	// Production finalizes HERE — after static NAT has recorded its counter
	// keys and before NAT64 runs (compiler.go, the finalizeNATCounterIDs call).
	//
	// The POSITION is asserted as a PRECONDITION rather than through the
	// output, because the output cannot see it. finalizeNATCounterIDs only
	// changes an id when two keys share a base hash; with no collision in this
	// fixture the re-derived id equals the streaming one, so finalizing too
	// early produces byte-identical maps. Measured: moving this call above
	// compileStaticNAT left the whole test GREEN. What the position actually
	// buys is that the sorted re-derivation sees EVERY NAT type's keys, so
	// check exactly that. The expectation is derived from the CONFIG and
	// compared against the COMPILER's map — the two sides are independent.
	for _, k := range staticNATCounterKeys(cfg) {
		if _, ok := result.NATCounterIDs[k]; !ok {
			t.Fatalf("finalizeNATCounterIDs is about to run without %q in the "+
				"key set — this driver's phase order has drifted from "+
				"CompileConfig's, which finalizes AFTER Phase 6.5 so the sorted "+
				"re-derivation covers every NAT type (#6894 r4)", k)
		}
	}
	finalizeNATCounterIDs(result)
	if err := compileNAT64(dp, cfg, result); err != nil {
		t.Fatalf("compileNAT64: %v", err)
	}
	return map[string]any{
		"ZoneIDs":       result.ZoneIDs,
		"ScreenIDs":     result.ScreenIDs,
		"AddrIDs":       result.AddrIDs,
		"AppIDs":        result.AppIDs,
		"PoolIDs":       result.PoolIDs,
		"NATCounterIDs": result.NATCounterIDs,
		"implicitSets":  result.implicitSets,
		// #6894 r6 F3: the policy/application NAME + set-count dimensions.
		// compilePolicies and compileApplications are both in this driver, so
		// these were omitted rather than unreachable. PolicyNames is
		// rule-id -> policy name and PolicySets is a running count, so an
		// order-dependent id or a double-increment shows here and nowhere else
		// in this comparison.
		"PolicyNames": result.PolicyNames,
		"PolicySets":  result.PolicySets,
		"AppNames":    result.AppNames,
		// #6894 r8 F4: the scheduler's view of the SAME rule numbering.
		// PolicyNames is keyed by RuleID, so a shifted policySetID moves its
		// keys; this slice carries PolicySetID, RuleIndex and RuleID as
		// FIELDS, which is what UpdatePolicyScheduleState later indexes by
		// (maps_policy.go). A drift the PolicyNames key set happened to absorb
		// still shows here, and the two disagreeing is itself the finding.
		"PolicyScheduleRuleSlots": result.PolicyScheduleRuleSlots,
		// Scalar, not a map: an off-by-one in the NAT64 auto-assign branch
		// would leave every map above identical while the next pool allocated
		// collides with an existing one.
		"NextPoolID": result.NextPoolID,
	}
}

// #4960: the validate-pre-pass compiles the config twice and throws the first
// result away. That is only free if the SECOND pass assigns byte-identical IDs
// to what a single pass would have. If any assignment read or mutated state
// outliving a CompileResult -- a process-global, a package-level sequence, an
// interned table -- pass two would differ and the pre-pass would silently
// change what the live dataplane is programmed with.
//
// "a counter on the DataPlane" was listed here as an example and is INAPT
// (#6894 r5): compileIDsOnce constructs a fresh stateless idProbeDP{} per
// invocation, so per-instance DataPlane state is not something this driver
// could observe in the first place. The examples that hold are the ones whose
// lifetime is the PROCESS, not the dataplane object.
//
// Measured rather than reasoned about: #6819's counters also "looked"
// per-instance until someone constructed two instances.
func TestPrePassDoesNotPerturbIDAssignment_4960(t *testing.T) {
	cfg := idProbeConfig()

	first := compileIDsOnce(t, cfg) // the discarded validate pass

	// SNAPSHOT BEFORE THE SECOND COMPILE (#6894 r9 F3). `first` holds LIVE map
	// and slice references. Comparing them to `second` only after the second
	// compile has run is exactly blind to the failure class this test names: a
	// regression storing IDs in process-global or interned state would mutate
	// BOTH observations at once, so the comparison — and every floor below,
	// which also reads `first` — would stay green while the live dataplane got
	// perturbed IDs.
	//
	// Rendering to a string materialises the values at this instant. fmt sorts
	// map keys, so the rendering is deterministic for every column here (maps
	// of scalars, a struct slice, a scalar), and a differing VALUE differs as a
	// string.
	firstSnapshot := renderColumns(first)

	second := compileIDsOnce(t, cfg) // the real pass that programs the dataplane

	// EVERY key compileIDsOnce returns, derived from the map rather than
	// re-listed (#6894 r8).
	//
	// The history is the argument. PolicyNames / PolicySets / AppNames were
	// added to the driver's return map with non-vacuity floors and NOT to this
	// loop, so nothing read them: a package-level counter perturbing
	// result.PolicyNames across passes left this test PASSING while the
	// identical mutation on implicitSets — a compared column — RED'd. That was
	// fixed by extending the list to eleven names. Deriving the key set instead
	// closes the same hole one level up: the failure mode was a SECOND list
	// falling out of sync with the first, and a list that must be edited when a
	// column is added can fall out of sync again. A derived set compares a new
	// column the moment it exists.
	//
	// The floors below stay, and are not redundant with this: a column that is
	// present but empty compares clean forever ({} DeepEquals {}), which this
	// loop cannot see. Adding a column needs BOTH — membership here, and a
	// floor that fails if the fixture stops producing it.
	//
	// Acceptance for a new column is a MUTATION IN THAT COLUMN, never the
	// column's presence.
	keys := make([]string, 0, len(first))
	for k := range first {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		t.Fatal("compileIDsOnce returned no columns at all")
	}

	secondSnapshot := renderColumns(second)
	for _, k := range keys {
		// The ALIASING-PROOF comparison: firstSnapshot was materialised before
		// the second compile ran, so shared backing storage cannot make the two
		// sides agree.
		if firstSnapshot[k] != secondSnapshot[k] {
			t.Errorf("%s differs between pass 1 and pass 2 — a discarded "+
				"validate pre-pass would PERTURB the IDs the live dataplane is "+
				"programmed with (#4960)\n  pass1: %s\n  pass2: %s",
				k, firstSnapshot[k], secondSnapshot[k])
		}
		// Kept alongside: DeepEqual compares the TYPED values, so a difference
		// two renderings happened to collapse still shows. It cannot see the
		// aliasing class, which is why it is the second check and not the only
		// one.
		if !reflect.DeepEqual(first[k], second[k]) {
			t.Errorf("%s differs between pass 1 and pass 2 (typed comparison) "+
				"— #4960\n  pass1: %v\n  pass2: %v", k, first[k], second[k])
		}
	}

	// UNIVERSAL NON-VACUITY. Every comparison above is an equality, and an
	// always-empty column compares clean forever — `{}` renders identically to
	// `{}` in both directions. The per-dimension floors below name the SPECIFIC
	// entries each column should carry, but they are hand-maintained and a
	// column added without one is exactly the gap #6894 r9 F3 reports. This is
	// the mechanical backstop: a column that is present but carries nothing is
	// a comparison that cannot fail, whatever its name.
	for _, k := range keys {
		if columnIsEmpty(first[k]) {
			t.Errorf("column %q is EMPTY, so comparing it proves nothing — an "+
				"empty map/slice/zero scalar equals itself across both passes "+
				"forever. Either the fixture stopped producing this dimension, "+
				"or the column was added to compileIDsOnce without a config "+
				"shape that reaches its writer (#6894 r9 F3)\n  value: %v",
				k, first[k])
		}
	}

	// NON-VACUITY. Everything above is a DeepEqual, and {} equals {}: a
	// dimension the driver never populates compares clean forever. Three of
	// them did exactly that until r4 (implicitSets empty, no static-NAT counter
	// keys, no pool-nat64), so each dimension below asserts the SPECIFIC entry
	// the fixture is supposed to produce — not merely that the map is
	// non-empty, which a partial regression would still satisfy.
	// #6894 r9 F3: these two said "non-empty", which the paragraph above
	// promises is NOT what a floor here does. A partial regression that dropped
	// three of the four zones, or every user application, satisfied both.
	zones := first["ZoneIDs"].(map[string]uint32)
	for _, want := range []string{"trust", "untrust", "dmz", "egress"} {
		if _, ok := zones[want]; !ok {
			t.Errorf("zone %q is absent from ZoneIDs, so that zone contributes "+
				"nothing to the comparison — the fixture stopped declaring it, or "+
				"assignZoneIDs stopped seeing it (#6894 r9 F3)\n  have: %v",
				want, sortedKeys(zones))
		}
	}
	apps := first["AppIDs"].(map[string]config.AssignedAppID)
	for _, want := range []string{"app-ssh", "app-http", "app-dns"} {
		if _, ok := apps[want]; !ok {
			t.Errorf("application %q is absent from AppIDs. The fixture's own "+
				"three apps are the part it controls; the junos-* catalogue would "+
				"keep this map large even if all three vanished, so a size check "+
				"cannot see them going (#6894 r9 F3)\n  have %d entries", want, len(apps))
		}
	}

	// #6894 r6 F3 floors. These three dimensions were omitted from the driver
	// even though compilePolicies and compileApplications already run in it.
	// PolicyScheduleRuleSlots is deliberately NOT compared: idProbeConfig
	// declares no scheduler, so the slice is empty and an empty slice equals an
	// empty slice — the exact vacuity the r4 round removed from three other
	// columns. Add a `then schedule` to the fixture before adding that column,
	// or it is a comparison that cannot fail.
	policyNames := first["PolicyNames"].(map[uint32]string)
	if _, ok := policyNames[DefaultPolicySentinelID]; !ok {
		t.Errorf("PolicyNames lacks the default-policy sentinel %#x — compilePolicies "+
			"seeds it unconditionally (compiler.go), so its absence means the phase "+
			"did not run and this column compares empty against empty\n  have: %v",
			DefaultPolicySentinelID, policyNames)
	}
	if n := len(policyNames); n < 2 {
		t.Errorf("PolicyNames holds %d entries; the fixture's policies should add real "+
			"rule-id -> name pairs on top of the sentinel, or the column measures only "+
			"a constant", n)
	}
	// EXACT, not non-zero (#6894 r9 F3). compilePolicies increments this once
	// per compiled zone-pair set and the fixture declares exactly one
	// (trust->untrust), so a double-increment reads 2 — which a `!= 0` check
	// accepts. That is the regression the column exists for.
	if ps := first["PolicySets"].(int); ps != 1 {
		t.Errorf("PolicySets is %d, want exactly 1: the fixture declares one "+
			"zone-pair policy set and compilePolicies increments once per set, so "+
			"any other value is a miscount (a `!= 0` floor accepted a "+
			"double-increment) (#6894 r9 F3)", ps)
	}
	// #6894 r8 F4: name the SPECIFIC rule ids, not merely "non-empty". p-multi
	// expands to 2 app ids and p-single to 1, so the trust->untrust set
	// (policySetID 0) occupies rule ids 0,1,2 — and a seeded set id moves all
	// three. A count-only floor is satisfied by a shifted numbering; this is
	// not.
	for id, wantName := range map[uint32]string{0: "p-multi", 1: "p-multi", 2: "p-single"} {
		got, ok := policyNames[id]
		if !ok || got != wantName {
			t.Errorf("PolicyNames[%d] is %q (present=%v), want %q — the policy id "+
				"space is not being measured as written: either the fixture's "+
				"policies changed shape or the rule-id numbering shifted "+
				"(#6894 r8 F4)\n  have: %v", id, got, ok, wantName, policyNames)
		}
	}

	// The scheduler slot's id FIELDS. This column is what DISCRIMINATES: under
	// a seeded policySetID, PolicyNames and this both move while PolicySets (a
	// count) does not — so a fix that wired only some of the columns into the
	// comparison loop shows up as exactly that asymmetry.
	slots := first["PolicyScheduleRuleSlots"].([]PolicyScheduleRuleSlot)
	if len(slots) != 1 {
		t.Fatalf("want exactly 1 scheduled policy slot from the fixture, got %d — "+
			"an empty slice DeepEquals an empty slice, so this column would be "+
			"vacuous (#6894 r8 F4)\n  have: %v", len(slots), slots)
	}
	if sl := slots[0]; sl.PolicyName != "p-single" || sl.SchedulerName != "sched-6894" ||
		sl.PolicySetID != 0 || sl.RuleIndex != 2 || sl.RuleID != 2 {
		t.Errorf("scheduled slot is %+v, want {PolicySetID:0 RuleIndex:2 RuleID:2 "+
			"PolicyName:p-single SchedulerName:sched-6894} — the scheduler's view "+
			"of the rule numbering has drifted from the policy compiler's, and "+
			"UpdatePolicyScheduleState indexes by these fields (#6894 r8 F4)", sl)
	}

	// AppNames is the REVERSE index of AppIDs, so the floor is DERIVED from the
	// other column rather than hand-written: for each of the fixture's own apps,
	// AppNames must map that app's assigned id back to its name. A size check
	// (the previous floor) could not see the two indexes disagreeing, which is
	// the failure that matters — a lookup by id is how the operator surfaces
	// resolve an app (#6894 r9 F3).
	appNames := first["AppNames"].(map[config.AssignedAppID]string)
	for _, want := range []string{"app-ssh", "app-http", "app-dns"} {
		id, ok := apps[want]
		if !ok {
			continue // already reported by the AppIDs floor above
		}
		if got := appNames[id]; got != want {
			t.Errorf("AppNames[%d] is %q but AppIDs[%q] is %d — the forward and "+
				"reverse application indexes disagree (#6894 r9 F3)",
				id, got, want, id)
		}
	}

	// ScreenIDs had no floor at all until the assignScreenIDs extraction: the
	// driver re-implemented Phase 1.5, so the column was doubly unable to
	// observe anything — it compared this test's own loop against itself, and
	// nothing asserted the fixture still carried profiles to assign. Name all
	// three the fixture declares; dropping cfg.Security.Screen would otherwise
	// leave the column an empty-vs-empty DeepEqual forever.
	screens := first["ScreenIDs"].(map[string]uint16)
	for _, want := range []string{"alpha", "mid", "zeta"} {
		if _, ok := screens[want]; !ok {
			t.Errorf("screen profile %q is absent from ScreenIDs, so the screen "+
				"ID dimension is NOT measured — either the fixture no longer "+
				"declares it or assignScreenIDs is not being run (#6894 r5)"+
				"\n  have: %v", want, sortedKeys(screens))
		}
	}

	// AddrIDs was protected only BY ACCIDENT: the implicitSets assertion above
	// demands "db,web" and "dns,servers", which cannot be built without those
	// AddrIDs entries. That covers ONE of the map's two writers. compileNAT's
	// named-pool rule path is the other — resolveSNATMatchAddr synthesizes a
	// "_snat_match_<cidr>" entry per SNAT match CIDR (compiler_nat.go:36) — and
	// nothing pinned it, so that half could stop contributing with the column
	// still comparing clean. Name entries from BOTH writers.
	addrs := first["AddrIDs"].(map[string]uint32)
	for _, want := range []string{
		// compileAddressBook: the three addresses and the one address-set.
		"db", "dns", "servers", "web",
		// compileNAT -> resolveSNATMatchAddr: one synthesized entry per
		// distinct SNAT match CIDR in the fixture, v4 and v6.
		"_snat_match_10.1.0.0/16",
		"_snat_match_10.2.0.0/16",
		"_snat_match_2001:db8:1::/64",
	} {
		if _, ok := addrs[want]; !ok {
			t.Errorf("address id %q is absent, so that WRITER's contribution to "+
				"AddrIDs is not measured — compileAddressBook and compileNAT's "+
				"synthesized-address branch each populate this map and a floor "+
				"naming only one of them leaves the other unpinned (#6894 r5)"+
				"\n  have: %v", want, sortedKeys(addrs))
		}
	}
	// Every pool the fixture declares, not merely "some" (#6894 r9 F3). Each is
	// a distinct writer: three are reached by SNAT rules (v4 pool, second v4
	// pool, v6-only pool) and pool-nat64 only by compileNAT64's auto-assign
	// branch, so naming one leaves the others unpinned.
	if pools := first["PoolIDs"].(map[string]uint8); len(pools) != 4 {
		t.Errorf("PoolIDs holds %d entries, want the fixture's 4 — %v",
			len(pools), sortedKeys(pools))
	} else {
		for _, want := range []string{"pool-a", "pool-b", "pool-v6", "pool-nat64"} {
			if _, ok := pools[want]; !ok {
				t.Errorf("NAT pool %q is absent from PoolIDs, so its writer is not "+
					"measured (#6894 r9 F3)\n  have: %v", want, sortedKeys(pools))
			}
		}
	}

	// The NAT counter IDs are THE dimension this probe exists for: #5099 made
	// their streaming assignment compile-order dependent on a hash collision,
	// which is the one place "compile twice" is not obviously free.
	counters := first["NATCounterIDs"].(map[string]uint32)
	if len(counters) == 0 {
		t.Fatal("fixture assigned no NAT counter IDs — the #5099 dimension of " +
			"this comparison is VACUOUS; add NAT rules to the fixture")
	}
	// One key per NAT type. The static pair is the r4 addition: compileStaticNAT
	// assigns them and production finalizes AFTER it, so a driver that finalized
	// straight after compileNAT measured neither.
	for _, want := range []string{
		NATCounterKey(NATCounterTypeSource, "rs-trust-untrust", "r-web"),
		NATCounterKey(NATCounterTypeDest, "rs-dnat", "d-v4"),
		NATCounterKey(NATCounterTypeStatic, "rs-static", "s-v4"),
		NATCounterKey(NATCounterTypeStatic, "rs-static", "s-v6"),
	} {
		if _, ok := counters[want]; !ok {
			t.Errorf("NAT counter key %q is absent, so that NAT type is NOT "+
				"measured by the stability comparison — the driver is not "+
				"running the phase that assigns it, or is finalizing before it "+
				"(#6894 r4)\n  have: %v", want, sortedKeys(counters))
		}
	}

	// implicitSets: written only by resolveAddrList's multi-address branch,
	// reached only through compilePolicies. Assert the two the fixture's
	// p-multi policy builds — the cache key is the sorted member names joined
	// by commas (compiler.go, resolveAddrList's cacheKey join).
	sets := first["implicitSets"].(map[string]uint32)
	for _, want := range []string{"db,web", "dns,servers"} {
		if _, ok := sets[want]; !ok {
			t.Errorf("implicit address-set %q is absent, so implicitSets is not "+
				"measured — either compilePolicies is not being run or the "+
				"fixture's policy address lists collapsed to the single-name / "+
				"all-\"any\" branches that build no set (#6894 r4)\n  have: %v",
				want, sortedKeys(sets))
		}
	}

	// The NAT64 auto-assign branch is the only writer of both of these for a
	// pool no SNAT rule references. Asserting NextPoolID > the SNAT high-water
	// binds the ADVANCE, not merely that the pool got an id.
	pools := first["PoolIDs"].(map[string]uint8)
	nat64ID, ok := pools["pool-nat64"]
	if !ok {
		t.Errorf("pool-nat64 is absent from PoolIDs, so compileNAT64's "+
			"auto-assign branch is not running in this driver (#6894 r4)"+
			"\n  have: %v", sortedKeys(pools))
	}
	// EXACT, and DERIVED from the pool map rather than pinned to a literal
	// (#6894 r9 F3). "greater than the NAT64 id" is satisfied by any
	// over-advance: an allocator that skipped two ids per pool would leave a
	// permanent hole and still pass. The invariant the allocator actually owes
	// is that the next id is one past the HIGHEST it handed out.
	var maxPoolID uint8
	for _, id := range pools {
		if id > maxPoolID {
			maxPoolID = id
		}
	}
	if next := first["NextPoolID"].(uint8); next != maxPoolID+1 {
		t.Errorf("NextPoolID is %d but the highest assigned pool id is %d "+
			"(pool-nat64 took %d) — the allocator is not sitting exactly one "+
			"past its high-water mark, so the next pool either collides with an "+
			"existing one or leaves an unreachable hole (#6894 r9 F3)"+
			"\n  pools: %v", next, maxPoolID, nat64ID, pools)
	}
}

// renderColumns materialises a compileIDsOnce result as strings, so a later
// compile sharing backing storage with it cannot retroactively change what was
// observed (#6894 r9 F3). fmt sorts map keys, so the rendering is stable.
func renderColumns(cols map[string]any) map[string]string {
	out := make(map[string]string, len(cols))
	for k, v := range cols {
		out[k] = fmt.Sprintf("%v", v)
	}
	return out
}

// columnIsEmpty reports whether a compileIDsOnce column carries nothing — an
// empty map or slice, or a zero scalar. Such a column compares clean across
// both passes forever, whatever regression is present.
func columnIsEmpty(v any) bool {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map, reflect.Slice, reflect.Array, reflect.String:
		return rv.Len() == 0
	case reflect.Invalid:
		return true
	default:
		return rv.IsZero()
	}
}

// staticNATCounterKeys derives, FROM THE CONFIG, the per-rule counter keys
// compileStaticNAT is expected to record. NPTv6 rules are excluded because
// compileStaticNAT skips them (compiler_nat.go:961) and compileNPTv6 assigns
// no counter. Deriving from cfg rather than hardcoding keeps the precondition
// correct when the fixture changes; the assertion that consumes it compares
// against the COMPILER's map, so the two sides stay independent.
func staticNATCounterKeys(cfg *config.Config) []string {
	var keys []string
	for _, rs := range cfg.Security.NAT.Static {
		for _, r := range rs.Rules {
			if r.IsNPTv6 {
				continue
			}
			keys = append(keys, NATCounterKey(NATCounterTypeStatic, rs.Name, r.Name))
		}
	}
	return keys
}

// sortedKeys renders a map's keys in a stable order for failure messages.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
