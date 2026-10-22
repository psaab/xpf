package userspace

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3406: the firewall-filter snapshot builder previously dropped/capped
// unrepresentable match content on the tolerant-load / peer-sync path instead of
// failing the snapshot in an observable way — siblings of #3367 (tcp-flags) and
// #3365 (unknown action). These guards pin the corrected wire markers; reverting
// the builder change makes each assert FAIL.

// TestFilterSnapshotICMPUnrepresentableSetsMarker is the FAIL-ON-REVERT guard for
// 104-M07. A term carrying a `from icmp-type` / `from icmp-code` token the
// compiler could not resolve to a byte in 0..255 (recorded on
// term.UnknownICMPTypes / term.UnknownICMPCodes) must set the
// ICMPTypeUnrepresentable / ICMPCodeUnrepresentable wire marker so the Rust
// filter compiler fails the snapshot CLOSED. Pre-#3406 the builder dropped the
// unresolved token; an all-unresolvable list emitted an empty vector and the term
// silently WIDENED to match every ICMP packet (fail-open).
func TestFilterSnapshotICMPUnrepresentableSetsMarker(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:             "bad",
			Action:           config.FilterActionDiscard,
			ICMPTypes:        []int{8},          // one resolvable type
			UnknownICMPTypes: []string{"bogus"}, // and one unresolvable name
			UnknownICMPCodes: []string{"300"},   // out-of-range code
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
		t.Fatalf("expected 1 filter with 1 term, got %#v", snaps)
	}
	term := snaps[0].Terms[0]
	if !term.ICMPTypeUnrepresentable {
		t.Error("an unresolvable icmp-type token must set ICMPTypeUnrepresentable (#3406 fail-open)")
	}
	if !term.ICMPCodeUnrepresentable {
		t.Error("an unresolvable icmp-code token must set ICMPCodeUnrepresentable (#3406 fail-open)")
	}
}

// TestFilterSnapshotICMPResolvableNoMarker proves the marker is keyed on the
// unresolved-token list, not on every ICMP term: a fully-resolvable term carries
// no marker and keeps its resolved bytes.
func TestFilterSnapshotICMPResolvableNoMarker(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:      "ok",
			Action:    config.FilterActionAccept,
			ICMPTypes: []int{0, 8},
			ICMPCodes: []int{0},
		}}},
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if term.ICMPTypeUnrepresentable || term.ICMPCodeUnrepresentable {
		t.Errorf("a fully-resolvable ICMP term must carry no unrepresentable marker, got type=%v code=%v",
			term.ICMPTypeUnrepresentable, term.ICMPCodeUnrepresentable)
	}
	if len(term.ICMPTypes) != 2 || len(term.ICMPCodes) != 1 {
		t.Errorf("resolved ICMP bytes dropped: types=%v codes=%v", term.ICMPTypes, term.ICMPCodes)
	}
}

// TestFilterSnapshotDSCPMatchUnrepresentableSetsMarker is the FAIL-ON-REVERT
// guard for the security half of 104-M09. An unrepresentable `from dscp` MATCH
// token (neither a known code-point name nor an integer 0..63) must set
// DSCPMatchUnrepresentable so the Rust filter compiler fails the snapshot CLOSED.
// Pre-#3406 the builder dropped the bad token; an all-unresolvable list emitted
// an empty dscp_values vector and the term silently WIDENED to match all DSCPs.
func TestFilterSnapshotDSCPMatchUnrepresentableSetsMarker(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:   "bad",
			Action: config.FilterActionDiscard,
			DSCPs:  []string{"not-a-code-point"},
		}}},
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if !term.DSCPMatchUnrepresentable {
		t.Error("an unresolvable from-dscp match token must set DSCPMatchUnrepresentable (#3406 fail-open)")
	}
	if len(term.DSCPValues) != 0 {
		t.Errorf("unresolvable DSCP token must not emit a value, got %v", term.DSCPValues)
	}
}

// TestFilterSnapshotDSCPMatchResolvableNoMarker proves a resolvable `from dscp`
// match (name or number) carries no marker and emits its value.
func TestFilterSnapshotDSCPMatchResolvableNoMarker(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:   "ok",
			Action: config.FilterActionAccept,
			DSCPs:  []string{"ef", "10"},
		}}},
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if term.DSCPMatchUnrepresentable {
		t.Error("a resolvable from-dscp match must carry no unrepresentable marker")
	}
	if len(term.DSCPValues) != 2 {
		t.Errorf("resolvable DSCP values dropped, got %v", term.DSCPValues)
	}
}

// TestFilterSnapshotDSCPRewriteUnrepresentableNoMarkerNoValue is the guard for
// the CoS-only half of 104-M09. An unrepresentable `then dscp` REWRITE token does
// NOT set DSCPMatchUnrepresentable (it is not a match-side widening) and emits no
// rewrite — but it is surfaced with a builder warning (CoS marking lost) rather
// than failing the snapshot closed.
func TestFilterSnapshotDSCPRewriteUnrepresentableNoMarkerNoValue(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:        "rw",
			Action:      config.FilterActionAccept,
			DSCPRewrite: "not-a-code-point",
		}}},
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if term.DSCPMatchUnrepresentable {
		t.Error("an unrepresentable then-dscp REWRITE must not set the match marker (CoS-only, no security widening)")
	}
	if term.DSCPRewrite != nil {
		t.Errorf("an unresolvable rewrite token must emit no rewrite, got %v", *term.DSCPRewrite)
	}
}

// TestFilterSnapshotFlexMatchOversizedWidthNotCapped is the FAIL-ON-REVERT guard
// for 104-M08. A flex-match whose bit-length needs more than 4 bytes must carry
// the REAL byte width on the wire (so the Rust filter compiler can reject the
// snapshot), NOT be silently capped to 4. Pre-#3406 the builder capped length to
// 4 and still emitted the term, so only the truncated 4-byte window was compared
// and the match BROADENED (fail-open). BitLength is a uint8, so the snapshot
// builder is the only layer that can see > 32 bits (the commit gate bounds it to
// 1..32) — exercise it directly with a hand-set FlexMatchConfig.
func TestFilterSnapshotFlexMatchOversizedWidthNotCapped(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:   "wide",
			Action: config.FilterActionDiscard,
			FlexMatch: &config.FlexMatchConfig{
				MatchStart: "layer-3",
				ByteOffset: 0,
				BitLength:  40, // 5 bytes — exceeds the u32 wire value
				Value:      0x1,
				Mask:       0xFFFFFFFF,
				ValueSet:   true,
				MaskSet:    true,
			},
		}}},
	}
	fm := buildFirewallFilterSnapshots(cfg)[0].Terms[0].FlexMatch
	if fm == nil {
		t.Fatal("flex-match dropped")
	}
	if fm.Length != 5 {
		t.Errorf("oversized flex width must be carried verbatim (want 5 for 40 bits), got %d "+
			"(a cap to 4 is the #3406 fail-open)", fm.Length)
	}
}

// TestFilterSnapshotMixedPortExceptWarns is the FAIL-ON-REVERT guard for 104-M05.
// A term mixing a positive port list with a `*-port-except` list in one direction
// is resolved positive-wins by the Rust filter compiler (the except side is
// dropped). Pre-#3406 that drop was SILENT. The builder must now emit a warning so
// the lost except set is operator-visible — symmetric with the mixed
// address-except warning (#3359). Reverting the warning makes this assert fail.
func TestFilterSnapshotMixedPortExceptWarns(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:              "mixed",
			Action:            config.FilterActionDiscard,
			SourcePorts:       []string{"80"},
			SourcePortsExcept: []string{"443"},
			DestinationPorts:  []string{"22"},
			DestPortsExcept:   []string{"23"},
		}}},
	}
	buildFirewallFilterSnapshots(cfg)
	out := buf.String()
	if !strings.Contains(out, "positive source-port list") {
		t.Errorf("mixed source positive + except ports must warn (positive-wins drops the except set), got: %q", out)
	}
	if !strings.Contains(out, "positive destination-port list") {
		t.Errorf("mixed dest positive + except ports must warn (positive-wins drops the except set), got: %q", out)
	}
}

// TestFilterSnapshotPureExceptPortNoWarn proves the warning is keyed on the MIXED
// shape, not on every except-port term: an except-only direction (the supported
// negation) carries no warning.
func TestFilterSnapshotPureExceptPortNoWarn(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:              "exceptonly",
			Action:            config.FilterActionAccept,
			SourcePortsExcept: []string{"443"},
		}}},
	}
	buildFirewallFilterSnapshots(cfg)
	if strings.Contains(buf.String(), "positive source-port list") {
		t.Errorf("a pure source-port-except term must not warn, got: %q", buf.String())
	}
}
