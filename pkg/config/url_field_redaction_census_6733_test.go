package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// #6733: the config redaction pass is keyed on field NAMES that look secret.
// Several fields are sensitive by CONTENT instead — they are URLs, hostnames
// and endpoints, named for what they ARE rather than for the credential they
// may carry — so no amount of adding names to the keyed list generalises. The
// NEXT URL-shaped field will leak the same way.
//
// This is the durable half of that fix. It enumerates every URL-shaped field
// reachable from a *Config by reflection, plants a credential-bearing URL in
// each one INDIVIDUALLY, marshals, and asserts the secret does not survive.
// A new field named like a URL is therefore a failing test rather than a
// silent leak on the authenticated REST GET.
//
// It asserts on BEHAVIOUR (does the secret appear in the JSON), never on the
// presence of a MarshalJSON method — a method can exist and not cover the
// field, and a field can be covered by a parent's marshaller.

// urlShapedFieldNames are the field-name patterns that denote a value which is
// a URL by contract. Matched case-insensitively as substrings.
//
// Deliberately a NAME heuristic used to build the POPULATION, not to decide the
// verdict: the verdict is always "did the planted secret survive marshalling".
//
// It is narrow on purpose. A first, broader version also matched "server",
// "hostname", "target" and "path", and flagged fifteen fields that hold an IP
// address, an FQDN or a policy NAME — System.HostName, System.NameServers,
// System.NTPServers, SNMP TrapGroups.Targets, DHCPRelay.Servers,
// ClassOfService Schedulers.EqualFlowTargetPolicy and the IPsec
// DynamicHostname among them. None of those can carry a credential, so every
// one would have been a census row asserting a defect that does not exist, and
// the gate would have warned on correct configuration. A coverage predicate
// that counts inputs the subject never depended on is worse than the existence
// check it replaced.
var urlShapedFieldNames = []string{
	"url", "uri", "endpoint", "site", "template",
}

// urlBearingByContract are fields whose NAME does not say "URL" but whose
// documented value is one. They are named individually because the whole point
// of #6733 is that a name-keyed rule cannot find them — so the population has
// to be told, and each entry is a claim backed by the field's own contract:
//
//   - FeedServer.Hostname — the compiler joins it with a feed Path to build the
//     fetch URL, so it accepts a full URL including userinfo.
//   - FeedEntry.Path — the other half of that join; accepts a query string.
//   - RPMTest.Target — a URL for the http-get probe type.
//
// Adding a row here is how a reviewer extends the gate to a newly-discovered
// URL-bearing field that is not named like one.
var urlBearingByContract = map[string]bool{
	"Config.Security.DynamicAddress.FeedServers[k].Hostname":            true,
	"Config.Security.DynamicAddress.FeedServers[k].FeedEntries[0].Path": true,
	"Config.Services.RPM.Probes[k].Tests[k].Target":                     true,
	// `system license autoupdate url` — a fetch endpoint whose value routinely
	// carries the entitlement token. Named "LicenseAutoUpdate", not "…URL".
	"Config.System.LicenseAutoUpdate":     true,
	"Config.System.LicenseAutoUpdateURLs": true,
}

// redactionCensus6733 records URL-shaped fields that are KNOWN to render their
// value verbatim, each with the reason it is not a leak. An entry is a claim
// and owes a justification; the test fails if an entry stops being needed, so
// the census cannot rot into an allowlist that hides a regression.
var redactionCensus6733 = map[string]string{}

func urlShaped6733(name, path string) bool {
	if urlBearingByContract[path] {
		return true
	}
	l := strings.ToLower(name)
	for _, p := range urlShapedFieldNames {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

// walkURLFields6733 finds every settable string / []string field whose name is
// URL-shaped, reachable from root, and calls fn with its JSON-ish path and a
// setter. Pointers and maps are materialised as needed so a nil sub-config does
// not hide its fields from the census.
func walkURLFields6733(t *testing.T, root reflect.Value, path string, depth int, fn func(string, func(string))) {
	if depth > 10 {
		return
	}
	switch root.Kind() {
	case reflect.Ptr:
		if root.IsNil() {
			if !root.CanSet() {
				return
			}
			root.Set(reflect.New(root.Type().Elem()))
		}
		walkURLFields6733(t, root.Elem(), path, depth+1, fn)
	case reflect.Struct:
		rt := root.Type()
		for i := 0; i < root.NumField(); i++ {
			f := rt.Field(i)
			if f.PkgPath != "" { // unexported
				continue
			}
			fv := root.Field(i)
			sub := path + "." + f.Name
			switch {
			case fv.Kind() == reflect.String && urlShaped6733(f.Name, sub):
				if !fv.CanSet() {
					continue
				}
				fn(sub, func(s string) { fv.SetString(s) })
			case fv.Kind() == reflect.Slice && fv.Type().Elem().Kind() == reflect.String && urlShaped6733(f.Name, sub+"[]"):
				if !fv.CanSet() {
					continue
				}
				fn(sub+"[]", func(s string) { fv.Set(reflect.ValueOf([]string{s})) })
			default:
				walkURLFields6733(t, fv, sub, depth+1, fn)
			}
		}
	case reflect.Slice:
		if root.Type().Elem().Kind() == reflect.Struct || root.Type().Elem().Kind() == reflect.Ptr {
			if root.Len() == 0 && root.CanSet() {
				root.Set(reflect.MakeSlice(root.Type(), 1, 1))
			}
			if root.Len() > 0 {
				walkURLFields6733(t, root.Index(0), path+"[0]", depth+1, fn)
			}
		}
	case reflect.Map:
		et := root.Type().Elem()
		if et.Kind() != reflect.Ptr && et.Kind() != reflect.Struct {
			return
		}
		if root.IsNil() && root.CanSet() {
			root.Set(reflect.MakeMap(root.Type()))
		}
		if !root.CanSet() && root.IsNil() {
			return
		}
		// A map value is not addressable: build one, walk it, store it back.
		ev := reflect.New(et)
		if et.Kind() == reflect.Ptr {
			ev.Elem().Set(reflect.New(et.Elem()))
		}
		walkURLFields6733(t, ev.Elem(), path+"[k]", depth+1, fn)
		key := reflect.ValueOf("k")
		if root.Type().Key().Kind() == reflect.String {
			root.SetMapIndex(key, ev.Elem())
		}
	}
}

func TestURLShapedFieldsAreRedactedOnMarshal6733(t *testing.T) {
	const secret = "CENSUSLEAKTOKEN"
	planted := "https://user:" + secret + "@example.test/p?token=" + secret

	// Pass 1: enumerate the population against a throwaway config.
	var fields []string
	{
		probe := &Config{}
		walkURLFields6733(t, reflect.ValueOf(probe).Elem(), "Config", 0, func(p string, _ func(string)) {
			fields = append(fields, p)
		})
	}
	if len(fields) < 8 {
		t.Fatalf("census enumerated only %d URL-shaped fields — the walker is broken and a green "+
			"run would prove nothing (a gate that silently stops sweeping is worse than no gate)", len(fields))
	}
	t.Logf("census: %d URL-shaped fields enumerated", len(fields))

	// Pass 2: plant the secret in ONE field at a time so a leak names its own field.
	var leaked []string
	for _, want := range fields {
		cfg := &Config{}
		walkURLFields6733(t, reflect.ValueOf(cfg).Elem(), "Config", 0, func(p string, set func(string)) {
			if p == want {
				set(planted)
			}
		})
		b, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("%s: marshal: %v", want, err)
		}
		if strings.Contains(string(b), secret) {
			leaked = append(leaked, want)
		}
	}

	for _, f := range leaked {
		if _, known := redactionCensus6733[f]; !known {
			t.Errorf("URL-shaped field %s renders an embedded credential VERBATIM through "+
				"json.Marshal, which is what the authenticated REST config GET returns "+
				"(GET /api/v1/config). Redact it in the owning type's MarshalJSON via "+
				"RedactURL — which leaves a credential-free URL, bare hostname or path "+
				"untouched — or add it to redactionCensus6733 with the reason it cannot "+
				"carry a credential (#6733)", f)
		}
	}
	for f, why := range redactionCensus6733 {
		found := false
		for _, l := range leaked {
			if l == f {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("redactionCensus6733 lists %s (%q) as a known-verbatim field, but it no "+
				"longer renders the credential — remove the entry. A census that keeps "+
				"stale rows degrades into an allowlist that hides the next regression", f, why)
		}
	}
}

// TestMarshalDoesNotMutateTheLiveConfig6733 pins the aliasing property the
// redacting marshallers depend on.
//
// These marshallers run on an `alias` COPY of the struct, but a copy is shallow:
// a []string field's backing array is shared with the live *Config. Redacting
// the slice in place would therefore rewrite the RUNNING configuration as a side
// effect of serving a read-only GET — the archive-site list would become
// "<redacted>@host" and the next archival transfer would use it.
//
// Without this test the copy is only asserted in a comment, and a comment cannot
// fail: swapping redactURLSlice to redact in place leaves every other test in
// this file green, because they all inspect the JSON rather than the config
// afterwards.
func TestMarshalDoesNotMutateTheLiveConfig6733(t *testing.T) {
	const site = "scp://user:PW@backup.example.test:/var/archive"
	cfg := &Config{}
	cfg.System.Archival = &ArchivalConfig{
		ArchiveSites:             []string{site},
		ArchiveSitesWithPassword: []string{site},
	}

	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "PW@") {
		t.Fatalf("premise broken: the credential was not redacted in the JSON at all")
	}

	// Marshalling is a READ. The live config must be byte-identical afterwards.
	if got := cfg.System.Archival.ArchiveSites[0]; got != site {
		t.Errorf("marshalling MUTATED the live config: ArchiveSites[0] = %q, want %q — "+
			"the redaction wrote through the alias into the shared backing array, so a "+
			"read-only GET has rewritten the archive destination the next transfer will use", got, site)
	}
	if got := cfg.System.Archival.ArchiveSitesWithPassword[0]; got != site {
		t.Errorf("marshalling MUTATED the live config: ArchiveSitesWithPassword[0] = %q, want %q",
			got, site)
	}

	// And a second marshal must still redact — an in-place implementation would
	// "pass" a repeat check by having already destroyed the value.
	b2, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("second marshal: %v", err)
	}
	if string(b) != string(b2) {
		t.Errorf("marshal is not idempotent: the first call changed what the second sees")
	}
}

// TestRedactionSurvivesValueMarshalling6733 pins the receiver shape.
//
// Config holds `System SystemConfig` and `Services ServicesConfig` BY VALUE.
// encoding/json promotes to a pointer-receiver MarshalJSON only when the value
// is addressable — true for a field reached through a *Config, false when a
// Config is marshalled by value. So a pointer receiver on SystemConfig redacts
// when someone writes json.Marshal(cfg) and silently does NOTHING when someone
// writes json.Marshal(*cfg), on the same data.
//
// That is the worst failure shape available here: the redaction would depend on
// the CALLER'S SYNTAX, and a test written with whichever form the author
// happened to use would be green either way. Both forms are asserted.
func TestRedactionSurvivesValueMarshalling6733(t *testing.T) {
	const secret = "VALUEFORMTOKEN"
	u := "https://user:" + secret + "@example.test/x?token=" + secret

	cfg := &Config{}
	cfg.System.LicenseAutoUpdate = u
	cfg.Services.RPM = &RPMConfig{Probes: map[string]*RPMProbe{
		"p": {Tests: map[string]*RPMTest{"t": {Name: "t", ProbeType: "http-get", Target: u}}},
	}}

	for _, tc := range []struct {
		name string
		v    any
	}{
		{"pointer: json.Marshal(cfg)", cfg},
		{"VALUE: json.Marshal(*cfg)", *cfg},
	} {
		b, err := json.Marshal(tc.v)
		if err != nil {
			t.Fatalf("%s: marshal: %v", tc.name, err)
		}
		if strings.Contains(string(b), secret) {
			t.Errorf("%s leaked the credential — the redacting marshaller is not reached in "+
				"this form. A pointer receiver on a type held BY VALUE in Config is only "+
				"promoted when the value is addressable, so the redaction silently depends "+
				"on how the caller spelled the marshal", tc.name)
		}
	}
}
