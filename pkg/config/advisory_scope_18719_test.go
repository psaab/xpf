package config

import (
	"strings"
	"testing"
)

// #18719: the #10105 / #13967 fabric reminders are acknowledgeable and
// change-scoped instead of printing on every commit of every cluster.

var fabricBAClassifier18719 = []string{
	"set class-of-service forwarding-classes queue 0 best-effort",
	"set class-of-service classifiers dscp cls forwarding-class best-effort loss-priority low code-points 0",
}

func compile18719(t *testing.T, extra ...string) *Config {
	t.Helper()
	commands := append(append([]string(nil), fabricStampCluster10105...), extra...)
	return compileFabricStamp10105(t, commands, CompileConfig)
}

func warningPresent18719(cfg *Config, text string) bool {
	for _, w := range cfg.Warnings {
		if w == text {
			return true
		}
	}
	return false
}

func TestFabricZoneStampAdvisorySilencedByAttestation18719(t *testing.T) {
	cfg := compile18719(t, "set chassis cluster fabric-interface-authenticated")
	if hasFabricStamp10105Warning(cfg) {
		t.Fatalf("an attested fabric link must not emit the #10105 reminder; warnings=%v", cfg.Warnings)
	}
	// Control: the same fabric without the attestation still emits it.
	if cfg := compile18719(t); !hasFabricStamp10105Warning(cfg) {
		t.Fatalf("an unattested fabric link must emit the #10105 reminder; warnings=%v", cfg.Warnings)
	}
}

func TestFabricZoneStampAdvisoryNeedsEveryLinkAcknowledged18719(t *testing.T) {
	dual := []string{"set chassis cluster fabric1-interface fab1"}
	const (
		auth0 = "set chassis cluster fabric-interface-authenticated"
		auth1 = "set chassis cluster fabric1-interface-authenticated"
		priv0 = "set chassis cluster fabric-interface-private"
		priv1 = "set chassis cluster fabric1-interface-private"
	)
	cases := []struct {
		name  string
		extra []string
		want  bool
	}{
		{"neither acknowledged", nil, true},
		{"only fab0 authenticated", []string{auth0}, true},
		{"only fab1 authenticated", []string{auth1}, true},
		{"only fab0 private", []string{priv0}, true},
		{"only fab1 private", []string{priv1}, true},
		{"both authenticated", []string{auth0, auth1}, false},
		{"both private", []string{priv0, priv1}, false},
		{"fab0 private, fab1 authenticated", []string{priv0, auth1}, false},
		{"fab0 authenticated, fab1 private", []string{auth0, priv1}, false},
		{"fab0 private and authenticated, fab1 neither", []string{priv0, auth0}, true},
	}
	for _, tc := range cases {
		cfg := compile18719(t, append(append([]string(nil), dual...), tc.extra...)...)
		if got := hasFabricStamp10105Warning(cfg); got != tc.want {
			t.Errorf("%s: #10105 reminder present=%v, want %v; warnings=%v", tc.name, got, tc.want, cfg.Warnings)
		}
	}
}

// TestFabricPrivateLeafSilencesTheReminder18719: on a single fabric, the
// private acknowledgement silences #10105 exactly as the attestation does.
func TestFabricPrivateLeafSilencesTheReminder18719(t *testing.T) {
	cfg := compile18719(t, "set chassis cluster fabric-interface-private")
	if hasFabricStamp10105Warning(cfg) {
		t.Fatalf("a link acknowledged private must not emit the #10105 reminder; warnings=%v", cfg.Warnings)
	}
}

// TestFabricPrivateLeafNeverAuthenticates18719 (#18751 review BLOCKING): the
// private acknowledgement must never turn into the #16023 authentication the
// stamp-trust gate reads. Following the reminder's advice on a plain link
// must not make cloneable stamps trusted.
func TestFabricPrivateLeafNeverAuthenticates18719(t *testing.T) {
	cfg := compile18719(t,
		"set chassis cluster fabric1-interface fab1",
		"set chassis cluster fabric-interface-private",
		"set chassis cluster fabric1-interface-private",
		"set security flow require-authenticated-fabric-stamps",
	)
	cc := cfg.Chassis.Cluster
	if !cc.FabricLinkPrivate || !cc.Fabric1LinkPrivate {
		t.Fatalf("the private leaves did not compile: %+v", cc)
	}
	if cc.FabricLinkAuthenticated || cc.Fabric1LinkAuthenticated {
		t.Fatalf("a private acknowledgement set the authentication attestation: %+v", cc)
	}
	// The #16023 gate still sees no authenticated link and says so.
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "require-authenticated-fabric-stamps configured but no fabric link is attested link-authenticated") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("require-authenticated-fabric-stamps with only private links must still warn that no link is authenticated; warnings=%v", cfg.Warnings)
	}
}

// TestFabricZoneStampAdvisoryTextSteersAwayFromAFalseAttestation18719
// (#18751 review BLOCKING): the reminder must name the private leaf for a
// direct-attached or dedicated link, and reserve the authenticated leaf for
// a link where MACsec/802.1X is actually configured.
func TestFabricZoneStampAdvisoryTextSteersAwayFromAFalseAttestation18719(t *testing.T) {
	for _, want := range []string{
		"fabric-interface-private",
		"fabric1-interface-private",
		"for a direct-attached or dedicated link",
		"fabric-interface-authenticated` only when MACsec/802.1X is actually configured",
	} {
		if !strings.Contains(fabricZoneStampAdvisory10105, want) {
			t.Errorf("the #10105 reminder lacks %q:\n%s", want, fabricZoneStampAdvisory10105)
		}
	}
	for _, leaf := range []string{"fabric-interface-private", "fabric1-interface-private"} {
		n := schemaChassis.children["cluster"].children[leaf]
		if n == nil {
			t.Fatalf("schema has no chassis cluster %s leaf", leaf)
		}
		if !strings.Contains(n.desc, "NOT authentication") {
			t.Errorf("%s description must say it is not authentication: %q", leaf, n.desc)
		}
	}
	for _, leaf := range []string{"fabric-interface-authenticated", "fabric1-interface-authenticated"} {
		n := schemaChassis.children["cluster"].children[leaf]
		if n == nil || !strings.Contains(n.desc, "actually configured") || !strings.Contains(n.desc, "-private") {
			t.Errorf("%s description must reserve it for real MACsec/802.1X and point at the private leaf: %+v", leaf, n)
		}
	}
}

func TestFabricBAFallbackAdvisoryNeedsFabricReachableClassifier18719(t *testing.T) {
	cases := []struct {
		name  string
		extra []string
		want  bool
	}{
		{"no class-of-service at all", nil, false},
		{"classifier defined but bound nowhere", fabricBAClassifier18719, false},
		{"classifier bound on a data unit", append(append([]string(nil), fabricBAClassifier18719...),
			"set class-of-service interfaces reth0 unit 80 classifiers dscp cls"), true},
		{"classifier bound at the interface level", append(append([]string(nil), fabricBAClassifier18719...),
			"set class-of-service interfaces reth0 classifiers dscp cls"), true},
		{"classifier bound only on management", append(append([]string(nil), fabricBAClassifier18719...),
			"set class-of-service interfaces fxp0 unit 0 classifiers dscp cls"), false},
		{"classifier bound only on the fabric member parent", append(append([]string(nil), fabricBAClassifier18719...),
			"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
			"set class-of-service interfaces ge-0/0/0 unit 0 classifiers dscp cls"), false},
		{"classifier bound on a data unit beside the fabric member", append(append([]string(nil), fabricBAClassifier18719...),
			"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
			"set class-of-service interfaces ge-0/0/0 unit 0 classifiers dscp cls",
			"set class-of-service interfaces ge-0/0/1 unit 0 classifiers dscp cls"), true},
	}
	for _, tc := range cases {
		cfg := compile18719(t, tc.extra...)
		if got := hasFabricIngressBaTrustAdvisory13967(cfg); got != tc.want {
			t.Errorf("%s: #13967 reminder present=%v, want %v; warnings=%v", tc.name, got, tc.want, cfg.Warnings)
		}
	}
}

// The #13967 reminder is about BA classification; the #10105 attestation is
// about the link. One must not silence the other.
func TestFabricBAFallbackAdvisoryIgnoresLinkAttestation18719(t *testing.T) {
	cfg := compile18719(t, append(append([]string(nil), fabricBAClassifier18719...),
		"set class-of-service interfaces reth0 unit 80 classifiers dscp cls",
		"set chassis cluster fabric-interface-authenticated")...)
	if hasFabricStamp10105Warning(cfg) || !hasFabricIngressBaTrustAdvisory13967(cfg) {
		t.Fatalf("attested link with a data classifier: want only #13967; warnings=%v", cfg.Warnings)
	}
	cfg = compile18719(t, append(append([]string(nil), fabricBAClassifier18719...),
		"set class-of-service interfaces reth0 unit 80 classifiers dscp cls",
		"set chassis cluster fabric-interface-private")...)
	if hasFabricStamp10105Warning(cfg) || !hasFabricIngressBaTrustAdvisory13967(cfg) {
		t.Fatalf("private link with a data classifier: want only #13967; warnings=%v", cfg.Warnings)
	}
}

func TestDropUnchangedScopedAdvisories18719(t *testing.T) {
	classified := append(append([]string(nil), fabricBAClassifier18719...),
		"set class-of-service interfaces reth0 unit 80 classifiers dscp cls")
	base := func(extra ...string) *Config {
		return compile18719(t, append(append([]string(nil), classified...), extra...)...)
	}
	precondition := base()
	if !warningPresent18719(precondition, fabricZoneStampAdvisory10105) ||
		!warningPresent18719(precondition, fabricBAFallbackAdvisory13967) {
		t.Fatalf("precondition: both reminders emitted; warnings=%v", precondition.Warnings)
	}
	cases := []struct {
		name      string
		prev      *Config
		next      *Config
		want10105 bool
		want13967 bool
	}{
		{"first commit (no previous config)", nil, base(), true, true},
		{"unrelated change", base(), base("set system host-name other"), false, false},
		{"identical recommit", base(), base(), false, false},
		{"fabric peer address changed", base(), base("set chassis cluster fabric-peer-address 10.99.1.2"), true, true},
		{"fabric added to a cluster without one", compileFabricStamp10105(t, fabricStampCluster10105[:3], CompileConfig), base(), true, true},
		{"classifier binding added", compile18719(t, fabricBAClassifier18719...), base(), false, true},
		{"classifier code points changed only", base(), compile18719(t,
			"set class-of-service forwarding-classes queue 0 best-effort",
			"set class-of-service classifiers dscp cls forwarding-class best-effort loss-priority low code-points 10",
			"set class-of-service interfaces reth0 unit 80 classifiers dscp cls"), false, false},
	}
	for _, tc := range cases {
		DropUnchangedScopedAdvisories(tc.prev, tc.next)
		if got := warningPresent18719(tc.next, fabricZoneStampAdvisory10105); got != tc.want10105 {
			t.Errorf("%s: #10105 kept=%v, want %v; warnings=%v", tc.name, got, tc.want10105, tc.next.Warnings)
		}
		if got := warningPresent18719(tc.next, fabricBAFallbackAdvisory13967); got != tc.want13967 {
			t.Errorf("%s: #13967 kept=%v, want %v; warnings=%v", tc.name, got, tc.want13967, tc.next.Warnings)
		}
	}
}

// Removing the attestation is a change of the #10105 region, so the
// reminder returns on exactly that commit.
func TestDropUnchangedScopedAdvisoriesKeepsReminderWhenAttestationRemoved18719(t *testing.T) {
	prev := compile18719(t, "set chassis cluster fabric-interface-authenticated")
	next := compile18719(t)
	DropUnchangedScopedAdvisories(prev, next)
	if !warningPresent18719(next, fabricZoneStampAdvisory10105) {
		t.Fatalf("removing the attestation must re-print the #10105 reminder; warnings=%v", next.Warnings)
	}
	prev = compile18719(t, "set chassis cluster fabric-interface-private")
	next = compile18719(t)
	DropUnchangedScopedAdvisories(prev, next)
	if !warningPresent18719(next, fabricZoneStampAdvisory10105) {
		t.Fatalf("removing the private acknowledgement must re-print the #10105 reminder; warnings=%v", next.Warnings)
	}
}

// Findings are never scoped: only registered reminder texts are dropped.
func TestDropUnchangedScopedAdvisoriesLeavesOtherWarnings18719(t *testing.T) {
	next := compile18719(t)
	next.Warnings = append(next.Warnings, "a finding about this config")
	DropUnchangedScopedAdvisories(compile18719(t), next)
	if !warningPresent18719(next, "a finding about this config") {
		t.Fatalf("an unregistered warning was dropped; warnings=%v", next.Warnings)
	}
	if warningPresent18719(next, fabricZoneStampAdvisory10105) {
		t.Fatalf("unchanged fabric must drop the #10105 reminder; warnings=%v", next.Warnings)
	}
}

// Every registered reminder text must be one the compiler actually emits, so
// rewording a constant cannot silently take it out of scoping (or leave a
// dead registry row).
func TestChangeScopedAdvisoryRegistryMatchesEmitters18719(t *testing.T) {
	cfg := compile18719(t, append(append([]string(nil), fabricBAClassifier18719...),
		"set class-of-service interfaces reth0 unit 80 classifiers dscp cls")...)
	for _, adv := range changeScopedAdvisories18719 {
		if !warningPresent18719(cfg, adv.text) {
			t.Errorf("registered reminder is not emitted verbatim: %q", adv.text)
		}
		if !strings.Contains(adv.text, "(#") {
			t.Errorf("registered reminder must name its issue: %q", adv.text)
		}
	}
}
