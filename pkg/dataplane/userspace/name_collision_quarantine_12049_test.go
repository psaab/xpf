package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileNameCollision12049(t *testing.T, apps, books, appRef, addressRef string) (*config.Config, []PolicyRuleSnapshot) {
	t.Helper()
	text := ""
	if apps != "" {
		text += "applications { " + apps + " } "
	}
	text += `security { zones { security-zone trust; security-zone untrust; } ` + books +
		` policies { default-policy { deny-all; } from-zone trust to-zone untrust { policy p1 { ` +
		`match { source-address ` + addressRef + `; destination-address any; application ` + appRef + `; } ` +
		`then { deny; } } } } }`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build policy snapshots: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("want one policy rule, got %d", len(rules))
	}
	return cfg, rules
}

func TestLenientApplicationNameCollisionsQuarantineReferences12049(t *testing.T) {
	cases := []struct {
		name, apps, ref string
	}{
		{
			name: "application and application-set",
			apps: `application web { protocol tcp; destination-port 80; } application-set web { application junos-https; }`,
			ref:  "web",
		},
		{
			name: "referenced application-set contains a colliding member",
			apps: `application web { protocol tcp; destination-port 80; } application-set web { application junos-https; } application-set group { application web; }`,
			ref:  "group",
		},
		{
			name: "duplicate application definition",
			apps: `application dup { protocol tcp; destination-port 80; } application dup { protocol udp; destination-port 53; }`,
			ref:  "dup",
		},
		{
			name: "duplicate application-set definition",
			apps: `application a { protocol tcp; destination-port 80; } application-set dup { application a; } application-set dup { application junos-https; }`,
			ref:  "dup",
		},
		{
			name: "duplicate generated term name",
			apps: `application a { term dup { protocol tcp; destination-port 80; } term dup { protocol udp; destination-port 53; } }`,
			ref:  "a-dup",
		},
		{
			name: "generated name collides with authored application",
			apps: `application app { term ssh { protocol tcp; destination-port 22; } term web { protocol tcp; destination-port 80; } } application app-ssh { protocol udp; destination-port 53; }`,
			ref:  "app-ssh",
		},
		{
			name: "generated name collides with application-set",
			apps: `application app { term ssh { protocol tcp; destination-port 22; } term web { protocol tcp; destination-port 80; } } application-set app-ssh { application junos-https; }`,
			ref:  "app-ssh",
		},
		{
			name: "cross-parent generated name",
			apps: `application a-b { term c { protocol tcp; destination-port 22; } term x { protocol tcp; destination-port 81; } } application a { term b-c { protocol udp; destination-port 53; } term y { protocol udp; destination-port 54; } }`,
			ref:  "a-b-c",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := `applications { ` + tc.apps + ` } ` +
				`security { zones { security-zone trust; security-zone untrust; } ` +
				`policies { default-policy { deny-all; } from-zone trust to-zone untrust { policy p1 { ` +
				`match { source-address any; destination-address any; application ` + tc.ref + `; } ` +
				`then { deny; } } } } }`
			tree, errs := config.NewParser(text).Parse()
			if len(errs) != 0 {
				t.Fatalf("parse: %v", errs)
			}
			if _, err := config.CompileConfig(tree); err == nil {
				t.Fatal("strict compile accepted a name collision")
			}
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile must keep the config bootable: %v", err)
			}
			rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
			if err != nil || len(rules) != 1 {
				t.Fatalf("build policy snapshots: rules=%d err=%v", len(rules), err)
			}
			terms := rules[0].ApplicationTerms
			if len(terms) != 1 || terms[0].Name != unsupportedApplicationSentinel || terms[0].Protocol != unsupportedApplicationSentinel {
				t.Fatalf("colliding application reference %q must lower to __unsupported__, got %+v", tc.ref, terms)
			}
			reasons := PolicyContentRejectionReasons(cfg, nil)
			if len(reasons) == 0 || !strings.Contains(strings.Join(reasons, "\n"), tc.ref) {
				t.Fatalf("content-rejection mirror must name colliding application %q, got %q", tc.ref, reasons)
			}
		})
	}
}

func TestLenientAddressBookNameCollisionsQuarantineReferences12049(t *testing.T) {
	books := `address-book { global { address blocked 10.0.0.0/8; address other 192.0.2.1/32; address-set blocked { address other; } } }`
	text := `security { zones { security-zone trust; security-zone untrust; } ` + books +
		` policies { default-policy { deny-all; } from-zone trust to-zone untrust { policy p1 { ` +
		`match { source-address blocked; destination-address any; application any; } then { deny; } } } } }`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted an address/address-set name collision")
	}
	cfg, rules := compileNameCollision12049(t, "", books, "any", "blocked")
	if !addressListHasSentinel(rules[0].SourceLiterals) || !addressListHasSentinel(rules[0].SourceAddresses) {
		t.Fatalf("colliding address reference must lower to __unsupported_address__, literals=%v addresses=%v", rules[0].SourceLiterals, rules[0].SourceAddresses)
	}
	reasons := PolicyContentRejectionReasons(cfg, nil)
	if len(reasons) == 0 || !strings.Contains(strings.Join(reasons, "\n"), "blocked") {
		t.Fatalf("content-rejection mirror must name colliding address-book entry, got %q", reasons)
	}
}

func TestLenientAddressCollisionWithFeedOverlayIsQuarantined12049(t *testing.T) {
	books := `address-book { global { address blocked 10.0.0.0/8; address other 192.0.2.1/32; address-set blocked { address other; } } }`
	cfg, _ := compileNameCollision12049(t, "", books, "any", "blocked")
	overlay := map[string][]string{"blocked": {"198.51.100.0/24"}}
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	if err != nil || len(rules) != 1 {
		t.Fatalf("build policy snapshots: rules=%d err=%v", len(rules), err)
	}
	if !addressListHasSentinel(rules[0].SourceLiterals) || !addressListHasSentinel(rules[0].SourceAddresses) {
		t.Fatalf("feed overlay must not bypass collision quarantine: literals=%v addresses=%v",
			rules[0].SourceLiterals, rules[0].SourceAddresses)
	}
	reasons := PolicyContentRejectionReasons(cfg, overlay)
	if len(reasons) == 0 || !strings.Contains(strings.Join(reasons, "\n"), "blocked") {
		t.Fatalf("content-rejection mirror must name feed-backed collision, got %q", reasons)
	}
}

func TestLenientLiteralLikeAddressCollisionIsQuarantined12049(t *testing.T) {
	const collidingName = "10.0.1.0/24"
	books := `address-book { global { address "` + collidingName + `" 10.0.0.0/8; address other 192.0.2.1/32; address-set "` + collidingName + `" { address other; } } }`
	cfg, rules := compileNameCollision12049(t, "", books, "any", collidingName)
	if !addressListHasSentinel(rules[0].SourceLiterals) || !addressListHasSentinel(rules[0].SourceAddresses) {
		t.Fatalf("literal-like colliding address reference must lower to __unsupported_address__, literals=%v addresses=%v",
			rules[0].SourceLiterals, rules[0].SourceAddresses)
	}
	reasons := PolicyContentRejectionReasons(cfg, nil)
	if len(reasons) == 0 || !strings.Contains(strings.Join(reasons, "\n"), collidingName) {
		t.Fatalf("content-rejection mirror must name literal-like colliding address, got %q", reasons)
	}
}

func TestLenientAddressSetContainingCollisionQuarantinesReference12049(t *testing.T) {
	books := `address-book { global { address blocked 10.0.0.0/8; address other 192.0.2.1/32; ` +
		`address-set blocked { address other; } address-set group { address blocked; } } }`
	text := `security { zones { security-zone trust; security-zone untrust; } ` + books +
		` policies { default-policy { deny-all; } from-zone trust to-zone untrust { ` +
		`policy p1 { match { source-address group; destination-address any; application any; } ` +
		`then { deny; } } } } }`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted an address/address-set name collision")
	}
	cfg, rules := compileNameCollision12049(t, "", books, "any", "group")
	if !addressListHasSentinel(rules[0].SourceLiterals) || !addressListHasSentinel(rules[0].SourceAddresses) {
		t.Fatalf("address-set containing a colliding member must lower to __unsupported_address__, literals=%v addresses=%v",
			rules[0].SourceLiterals, rules[0].SourceAddresses)
	}
	reasons := PolicyContentRejectionReasons(cfg, nil)
	if len(reasons) == 0 || !strings.Contains(strings.Join(reasons, "\n"), "group") {
		t.Fatalf("content-rejection mirror must name the refused address-set, got %q", reasons)
	}
}

func TestLenientZoneLocalAddressBookNameCollisionQuarantinesReference12049(t *testing.T) {
	text := `security { zones { security-zone trust { address-book { ` +
		`address blocked 10.0.0.0/8; address other 192.0.2.1/32; ` +
		`address-set blocked { address other; } } } security-zone untrust; } ` +
		`policies { default-policy { deny-all; } from-zone trust to-zone untrust { ` +
		`policy p1 { match { source-address blocked; destination-address any; ` +
		`application any; } then { deny; } } } } }`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted a zone-local address/address-set collision")
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil || len(rules) != 1 {
		t.Fatalf("build policy snapshots: rules=%d err=%v", len(rules), err)
	}
	if !addressListHasSentinel(rules[0].SourceLiterals) || !addressListHasSentinel(rules[0].SourceAddresses) {
		t.Fatalf("zone-local collision must lower to __unsupported_address__, literals=%v addresses=%v",
			rules[0].SourceLiterals, rules[0].SourceAddresses)
	}
	reasons := PolicyContentRejectionReasons(cfg, nil)
	if len(reasons) == 0 || !strings.Contains(strings.Join(reasons, "\n"), "blocked") {
		t.Fatalf("content-rejection mirror must name zone-local collision, got %q", reasons)
	}
}

func TestLenientNamedAddressBookDropQuarantinesCollision12049(t *testing.T) {
	books := `address-book { global { address shared 203.0.113.0/24; } red { address shared 10.0.0.0/8; } }`
	text := `security { zones { security-zone trust; security-zone untrust; } ` + books +
		` policies { default-policy { deny-all; } from-zone trust to-zone untrust { policy p1 { ` +
		`match { source-address shared; destination-address any; application any; } then { deny; } } } } }`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	if err := config.SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), `unknown configuration keyword "red"`) {
		t.Fatalf("strict schema must continue rejecting the unsupported named address book, got %v", err)
	}
	cfg, rules := compileNameCollision12049(t, "", books, "any", "shared")
	if !addressListHasSentinel(rules[0].SourceLiterals) || !addressListHasSentinel(rules[0].SourceAddresses) {
		t.Fatalf("entry dropped from named address book must not fall through to the same-named global object: literals=%v addresses=%v", rules[0].SourceLiterals, rules[0].SourceAddresses)
	}
	reasons := PolicyContentRejectionReasons(cfg, nil)
	if len(reasons) == 0 || !strings.Contains(strings.Join(reasons, "\n"), "shared") {
		t.Fatalf("content-rejection mirror must name dropped named-book collision, got %q", reasons)
	}
}

func TestNoncollidingNamesKeepTheirWireAndMirror12049(t *testing.T) {
	cfg, rules := compileNameCollision12049(t,
		`application web { protocol tcp; destination-port 443; }`,
		`address-book { global { address server 203.0.113.9/32; } }`, "web", "server")
	if len(rules[0].ApplicationTerms) != 1 || rules[0].ApplicationTerms[0].Name != "web" || rules[0].ApplicationTerms[0].Protocol != "tcp" {
		t.Fatalf("noncolliding application changed on wire: %+v", rules[0].ApplicationTerms)
	}
	if addressListHasSentinel(rules[0].SourceLiterals) || addressListHasSentinel(rules[0].SourceAddresses) {
		t.Fatalf("noncolliding address was poisoned: literals=%v addresses=%v", rules[0].SourceLiterals, rules[0].SourceAddresses)
	}
	if len(rules[0].SourceBookIDs) != 1 {
		t.Fatalf("noncolliding address reference must keep its book ID on wire, got %v", rules[0].SourceBookIDs)
	}
	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
		t.Fatalf("noncolliding configuration must not be rejected: %q", reasons)
	}
}
