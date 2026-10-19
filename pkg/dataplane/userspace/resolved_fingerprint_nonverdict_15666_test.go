package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15666 (V2-04): PolicyResolvedFingerprints hashed the raw
// PolicyRuleSnapshot JSON — only PolicyID was zeroed — so under
// `policy-rematch extensive` a non-verdict edit (then log toggle, binding
// or swapping a currently-active scheduler-name, reordering match-list
// elements) changed the fingerprint and tore down live sessions even
// though policyMatchOrActionChanged (set-compare) and
// policySchedulerBecameInactive both correctly said "no verdict change".
// The fingerprint must hash only the resolved verdict-relevant content:
// non-verdict fields zeroed, match collections canonicalized as sets.
//
// RED ON REVERT: restore raw-JSON hashing and every "equal" case below
// differs (verified pre-fix by probe: log/sched/reorder/reorderSrc/global
// scope reorder all changed the fingerprint).

const fingerprintNonVerdictKey15666 = "trust->untrust/web"

// fingerprintNonVerdictConfig builds the report's fixture: trust->untrust
// policy `web` (permit) with two inline literal CIDRs per side and two
// custom applications, with optional log / scheduler-name bindings.
func fingerprintNonVerdictConfig(apps []string, log *config.PolicyLog, schedulerName string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.PolicyRematchExtensive = true
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"h1": {Name: "h1", Value: "10.0.0.1/32"},
			"h2": {Name: "h2", Value: "10.0.0.2/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			"trusted-hosts": {Name: "trusted-hosts", Addresses: []string{"h1", "h2"}},
		},
	}
	cfg.Applications.Applications = map[string]*config.Application{
		"app-a": {Name: "app-a", Protocol: "tcp", DestinationPort: "80"},
		"app-b": {Name: "app-b", Protocol: "tcp", DestinationPort: "443"},
	}
	pol := &config.Policy{
		Name:          "web",
		Action:        config.PolicyPermit,
		Log:           log,
		SchedulerName: schedulerName,
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"10.0.1.0/24", "10.0.2.0/24"},
			DestinationAddresses: []string{"192.0.2.0/24", "198.51.100.0/24"},
			Applications:         apps,
		},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{pol},
	}}
	return cfg
}

func fingerprint15666(cfg *config.Config) string {
	fp := PolicyResolvedFingerprints(cfg, nil)
	if fp[fingerprintNonVerdictKey15666] == "" {
		// t.Fatal needs the test handle; callers check via helper below.
		return ""
	}
	return fp[fingerprintNonVerdictKey15666]
}

func TestPolicyResolvedFingerprintsIgnoresLogSchedulerAndMatchOrder15666(t *testing.T) {
	baseCfg := fingerprintNonVerdictConfig([]string{"app-a", "app-b"}, nil, "")
	fpBase := PolicyResolvedFingerprints(baseCfg, nil)
	if fpBase[fingerprintNonVerdictKey15666] == "" {
		t.Fatalf("precondition: base fingerprint missing: %v", fpBase)
	}

	reorderedSrc := fingerprintNonVerdictConfig([]string{"app-a", "app-b"}, nil, "")
	reorderedSrc.Security.Policies[0].Policies[0].Match.SourceAddresses = []string{"10.0.2.0/24", "10.0.1.0/24"}
	reorderedDst := fingerprintNonVerdictConfig([]string{"app-a", "app-b"}, nil, "")
	reorderedDst.Security.Policies[0].Policies[0].Match.DestinationAddresses = []string{"198.51.100.0/24", "192.0.2.0/24"}

	cases := map[string]*config.Config{
		// Report Case A: then log session-init/session-close toggle.
		"log": fingerprintNonVerdictConfig([]string{"app-a", "app-b"},
			&config.PolicyLog{SessionInit: true, SessionClose: true}, ""),
		// Report Case B: binding a (currently-active) scheduler-name.
		"sched": fingerprintNonVerdictConfig([]string{"app-a", "app-b"}, nil, "active-sched"),
		// Active scheduler swap: two different active scheduler names.
		"sched-swap": fingerprintNonVerdictConfig([]string{"app-a", "app-b"}, nil, "other-active-sched"),
		// Match-list element reordering (applications + both address sides).
		"reorder-apps": fingerprintNonVerdictConfig([]string{"app-b", "app-a"}, nil, ""),
		"reorder-src":  reorderedSrc,
		"reorder-dst":  reorderedDst,
	}
	for name, other := range cases {
		fpOther := PolicyResolvedFingerprints(other, nil)
		if !reflect.DeepEqual(fpBase, fpOther) {
			t.Errorf("%s: non-verdict edit changed PolicyResolvedFingerprints: base=%v other=%v", name, fpBase, fpOther)
		}
		strippedBase := PolicyResolvedIdentityStrippedFingerprints(baseCfg, nil)
		strippedOther := PolicyResolvedIdentityStrippedFingerprints(other, nil)
		if !reflect.DeepEqual(strippedBase, strippedOther) {
			t.Errorf("%s: non-verdict edit changed PolicyResolvedIdentityStrippedFingerprints: base=%v other=%v",
				name, strippedBase, strippedOther)
		}
	}
}

// The canonicalization must not swallow REAL resolved changes — extensive
// rematch exists to catch exactly these (acceptance criterion 2).
func TestPolicyResolvedFingerprintsStillTracksRealChanges15666(t *testing.T) {
	base := fingerprint15666(fingerprintNonVerdictConfig([]string{"app-a", "app-b"}, nil, ""))
	if base == "" {
		t.Fatal("precondition: base fingerprint missing")
	}

	changed := map[string]func(*config.Config){
		"application definition port": func(c *config.Config) {
			c.Applications.Applications["app-a"].DestinationPort = "8080"
		},
		"application membership": func(c *config.Config) {
			c.Security.Policies[0].Policies[0].Match.Applications = []string{"app-a"}
		},
		"source literal narrowed": func(c *config.Config) {
			c.Security.Policies[0].Policies[0].Match.SourceAddresses = []string{"10.0.1.0/24"}
		},
		"action": func(c *config.Config) {
			c.Security.Policies[0].Policies[0].Action = config.PolicyDeny
		},
		"address-set membership": func(c *config.Config) {
			c.Security.Policies[0].Policies[0].Match.SourceAddresses = []string{"trusted-hosts"}
			c.Security.AddressBook.AddressSets["trusted-hosts"].Addresses = []string{"h1"}
		},
	}
	for name, mutate := range changed {
		cfg := fingerprintNonVerdictConfig([]string{"app-a", "app-b"}, nil, "")
		mutate(cfg)
		if got := fingerprint15666(cfg); got == "" || got == base {
			t.Errorf("%s: real resolved change did NOT change fingerprint (got %q, base %q)", name, got, base)
		}
	}

	// Address-set referenced vs direct: switching the match to the set and
	// then tightening the set must move the fingerprint (the #8993 case).
	setCfg := fingerprintNonVerdictConfig([]string{"app-a", "app-b"}, nil, "")
	setCfg.Security.Policies[0].Policies[0].Match.SourceAddresses = []string{"trusted-hosts"}
	setBase := fingerprint15666(setCfg)
	setCfg.Security.AddressBook.Addresses["h2"].Value = "10.0.9.9/32"
	if got := fingerprint15666(setCfg); got == "" || got == setBase {
		t.Errorf("address VALUE change under stable set name did NOT change fingerprint")
	}
}

// Scoped-global zone lists are match sets too: reordering them (and the
// derived singular ScopeSingular stamp) must not move the fingerprint,
// while changing membership must.
func TestPolicyResolvedFingerprintsGlobalScopeReorder15666(t *testing.T) {
	mk := func(fromZones []string) *config.Config {
		cfg := &config.Config{}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"trust": {Name: "trust"}, "untrust": {Name: "untrust"}, "dmz": {Name: "dmz"},
		}
		cfg.Security.AddressBook = &config.AddressBook{
			Addresses:   map[string]*config.Address{},
			AddressSets: map[string]*config.AddressSet{},
		}
		cfg.Security.GlobalPolicies = []*config.Policy{{
			Name:   "g-scoped",
			Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
				FromZones:            fromZones,
				ToZones:              []string{"untrust", "dmz"},
			},
		}}
		return cfg
	}
	const key = "junos-global->junos-global/g-scoped"
	base := PolicyResolvedFingerprints(mk([]string{"trust", "dmz"}), nil)
	if base[key] == "" {
		t.Fatalf("precondition: global fingerprint missing: %v", base)
	}
	if reordered := PolicyResolvedFingerprints(mk([]string{"dmz", "trust"}), nil); !reflect.DeepEqual(base, reordered) {
		t.Fatalf("global scope reorder changed fingerprint: base=%v reordered=%v", base, reordered)
	}
	if narrowed := PolicyResolvedFingerprints(mk([]string{"trust"}), nil); narrowed[key] == base[key] {
		t.Fatalf("global scope membership change did NOT change fingerprint")
	}
}

// Determinism control: a canonicalization bug (map iteration, unstable
// sort) must not make identical configs hash differently across builds.
func TestPolicyResolvedFingerprintsDeterministic15666(t *testing.T) {
	cfg := func() *config.Config {
		return fingerprintNonVerdictConfig([]string{"app-b", "app-a"},
			&config.PolicyLog{SessionClose: true}, "sched")
	}
	first := PolicyResolvedFingerprints(cfg(), nil)
	for range 5 {
		if again := PolicyResolvedFingerprints(cfg(), nil); !reflect.DeepEqual(first, again) {
			t.Fatalf("fingerprint not deterministic: %v vs %v", first, again)
		}
	}
}
