package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6459 / #6463: the firewall-filter snapshot builder previously emitted a
// partially-unresolvable port list or a partially-malformed address list
// VERBATIM on the tolerant-load / peer-sync path, and the Rust filter compiler
// dropped the bad token PER-TOKEN — a discard/reject term then silently
// enforced a NARROWER match set than the operator wrote (fail-open via
// fall-through to the implicit accept). These guards pin the corrected
// PortsUnrepresentable / AddressUnrepresentable wire markers; reverting the
// builder change makes each assert FAIL.

// TestFilterSnapshotPortsUnrepresentableSetsMarker is the FAIL-ON-REVERT guard
// for #6459. A term carrying an unresolved port token (recorded on
// term.UnknownPorts by resolveFilterPortTokens) must set the
// PortsUnrepresentable wire marker so the Rust filter compiler fails the
// snapshot CLOSED. Pre-#6459 the builder emitted the list verbatim; the Rust
// per-token drop narrowed a `then discard` term to only the surviving ports.
func TestFilterSnapshotPortsUnrepresentableSetsMarker(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:             "bad",
			Action:           "discard",
			DestinationPorts: []string{"22", "bogussvc"}, // one resolved, one kept verbatim
			UnknownPorts:     []string{"bogussvc"},
		}}},
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if !term.PortsUnrepresentable {
		t.Error("an unresolvable port token must set PortsUnrepresentable (#6459 fail-open)")
	}
	// The surviving token still rides the wire verbatim — the Rust side
	// rejects the WHOLE snapshot on the marker, never a narrowed matcher.
	if len(term.DestPorts) != 2 {
		t.Errorf("port list must be emitted verbatim alongside the marker, got %v", term.DestPorts)
	}
}

// TestFilterSnapshotPortsResolvableNoMarker proves the marker is keyed on the
// unresolved-token list, not on every port-scoped term: a fully-resolvable
// term carries no marker.
func TestFilterSnapshotPortsResolvableNoMarker(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:             "ok",
			Action:           "accept",
			DestinationPorts: []string{"22", "80"},
			SourcePorts:      []string{"1024-65535"},
		}}},
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if term.PortsUnrepresentable {
		t.Error("a fully-resolvable port term must carry no unrepresentable marker")
	}
}

// TestFilterSnapshotAddressUnrepresentableSetsMarker is the FAIL-ON-REVERT
// guard for #6463. A term carrying a malformed address literal (recorded on
// term.UnknownAddresses by recordFilterAddrTokens) must set the
// AddressUnrepresentable wire marker so the Rust filter compiler fails the
// snapshot CLOSED. Pre-#6463 the Rust parse_address dropped the token
// per-token and the term matched only the surviving prefixes.
func TestFilterSnapshotAddressUnrepresentableSetsMarker(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:             "bad",
			Action:           "discard",
			SourceAddresses:  []string{"10.0.0.0/8", "garbage.example"},
			UnknownAddresses: []string{"garbage.example"},
		}}},
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if !term.AddressUnrepresentable {
		t.Error("a malformed address literal must set AddressUnrepresentable (#6463 fail-open)")
	}
}

// TestFilterSnapshotAddressResolvableNoMarker proves a fully-parseable address
// term carries no marker.
func TestFilterSnapshotAddressResolvableNoMarker(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:            "ok",
			Action:          "accept",
			SourceAddresses: []string{"10.0.0.0/8", "192.0.2.1"},
		}}},
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if term.AddressUnrepresentable {
		t.Error("a fully-parseable address term must carry no unrepresentable marker")
	}
}

// TestFilterSnapshotLenientPartialPortListSetsMarker_6459 is the end-to-end
// #6459 guard: flat-set syntax through the TOLERANT compile path
// (CompileConfigLenient — the boot / HA peer-sync path the strict gate
// downgrades to a warning) to the wire snapshot. `from destination-port
// [ ssh bogussvc ]` + `then discard` must produce the marker AND keep the
// resolved "22" on the wire.
func TestFilterSnapshotLenientPartialPortListSetsMarker_6459(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set firewall family inet filter f term t from destination-port [ ssh bogussvc ]",
		"set firewall family inet filter f term t then discard",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if !term.PortsUnrepresentable {
		t.Error("a leniently-loaded partially-unresolvable port list must set PortsUnrepresentable (#6459)")
	}
	if len(term.DestPorts) != 2 || term.DestPorts[0] != "22" || term.DestPorts[1] != "bogussvc" {
		t.Errorf("the resolved port and the verbatim-kept token must both ride the wire, got %v", term.DestPorts)
	}
}

// TestFilterSnapshotLenientPartialAddressListSetsMarker_6463 is the end-to-end
// #6463 guard: `from source-address [ 10.0.0.0/8 garbage.example ]` + `then
// discard` through the tolerant compile path must produce the marker.
func TestFilterSnapshotLenientPartialAddressListSetsMarker_6463(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set firewall family inet filter f term t from source-address [ 10.0.0.0/8 garbage.example ]",
		"set firewall family inet filter f term t then discard",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if !term.AddressUnrepresentable {
		t.Error("a leniently-loaded partially-malformed address list must set AddressUnrepresentable (#6463)")
	}
}

// TestFilterSnapshotLenientZoneScopedAddressSetsMarker_10011 is the
// end-to-end #10011 guard: a `%zone` filter address accepted by the Junos
// lexer must survive the TOLERANT compile path verbatim, be recorded by the
// shared classifier/recording path, and set AddressUnrepresentable before the
// Rust compiler can parse/drop it per-token. The existing Rust
// address_unrepresentable_marker_fails_closed_not_narrowed test proves that
// this marker rejects the whole snapshot rather than silently narrowing the
// matcher to the surviving prefix.
func TestFilterSnapshotLenientZoneScopedAddressSetsMarker_10011(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set firewall family inet6 filter f6 term t from source-address [ 2001:db8::/32 fe80::1%eth0 ]",
		"set firewall family inet6 filter f6 term t then discard",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if !term.AddressUnrepresentable {
		t.Fatal("a leniently-loaded zone-scoped address must set AddressUnrepresentable (#10011)")
	}
	if len(term.SourceAddresses) != 2 ||
		term.SourceAddresses[0] != "2001:db8::/32" ||
		term.SourceAddresses[1] != "fe80::1%eth0" {
		t.Fatalf("the valid prefix and raw scoped token must both ride the wire, got %v",
			term.SourceAddresses)
	}
}

// TestFirewallTermSnapshotUnrepresentableMarkerWireKeys_6459_6463 is the
// Go-encode half of the cross-language wire contract: the exact JSON keys the
// Rust consumer (userspace-dp protocol/security.rs, pinned by
// firewall_term_snapshot_unrepresentable_marker_wire_keys_6459_6463) decodes.
// A key rename on this side fails this test instead of silently decoding to
// the default (false) on the Rust side — which would re-open the per-token
// narrowing both markers close.
func TestFirewallTermSnapshotUnrepresentableMarkerWireKeys_6459_6463(t *testing.T) {
	body, err := json.Marshal(FirewallTermSnapshot{
		Name:                   "t",
		Action:                 "discard",
		PortsUnrepresentable:   true,
		AddressUnrepresentable: true,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["ports_unrepresentable"] != true {
		t.Errorf("wire key ports_unrepresentable must be present and true, got %v (%s)",
			decoded["ports_unrepresentable"], body)
	}
	if decoded["address_unrepresentable"] != true {
		t.Errorf("wire key address_unrepresentable must be present and true, got %v (%s)",
			decoded["address_unrepresentable"], body)
	}

	// omitempty keeps the markers off the wire when clear — an older Rust
	// helper (serde default) and an older Go decoder both see the pre-#6459
	// shape (#1961 parity).
	clearBody, err := json.Marshal(FirewallTermSnapshot{Name: "t", Action: "accept"})
	if err != nil {
		t.Fatalf("marshal clear: %v", err)
	}
	var clearDecoded map[string]any
	if err := json.Unmarshal(clearBody, &clearDecoded); err != nil {
		t.Fatalf("unmarshal clear: %v", err)
	}
	if _, present := clearDecoded["ports_unrepresentable"]; present {
		t.Errorf("a clear PortsUnrepresentable must be omitted (omitempty), got %s", clearBody)
	}
	if _, present := clearDecoded["address_unrepresentable"]; present {
		t.Errorf("a clear AddressUnrepresentable must be omitted (omitempty), got %s", clearBody)
	}
}
