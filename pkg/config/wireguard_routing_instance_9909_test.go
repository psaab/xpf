package config

import (
	"strings"
	"testing"
)

// wgVRF9909Warnings selects the commit warnings this gate (#9909) emits.
// Selection is by the issue identity the message always carries, so a
// reworded diagnostic is still found and a REMOVED diagnostic still reds.
func wgVRF9909Warnings(cfg *Config) []string {
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#9909") {
			out = append(out, w)
		}
	}
	return out
}

// wgBase9909 is the minimal strict-clean WireGuard tunnel spelling (copied
// from the #9587 steering fixtures): interface-level mode + listen-port +
// private-key + one peer. Every #9909 fixture builds on it so the ONLY
// commit error/warning a fixture can draw is this gate's.
func wgBase9909(t *testing.T, iface, port, priv, peer string) []string {
	t.Helper()
	return []string{
		"set interfaces " + iface + " tunnel mode wireguard",
		"set interfaces " + iface + " tunnel wireguard listen-port " + port,
		"set interfaces " + iface + " tunnel wireguard private-key " + priv,
		"set interfaces " + iface + " tunnel wireguard peer " + peer + " allowed-ips 10.1.0.0/24",
		"set system dataplane-type userspace",
	}
}

func wgUnitBase9909(t *testing.T, iface, unit, port, priv, peer string) []string {
	t.Helper()
	pfx := "set interfaces " + iface + " unit " + unit + " tunnel"
	return []string{
		pfx + " mode wireguard",
		pfx + " wireguard listen-port " + port,
		pfx + " wireguard private-key " + priv,
		pfx + " wireguard peer " + peer + " allowed-ips 10.1.0.0/24",
		"set system dataplane-type userspace",
	}
}

// TestWireguardTunnelRoutingInstanceBound9909 covers the explicit
// `tunnel routing-instance` path. Once the userspace outer socket binds
// `vrf-<instance>`, supported VRF instances commit cleanly; a forwarding
// instance still has no VRF device and remains refused.
//
// Fail-on-revert: removing the Rust bind path while relaxing the gate leaves
// the supported case apparently clean but the outer socket on the main table;
// the Rust socket cells and protocol bump catch that regression.
func TestWireguardTunnelRoutingInstanceBound9909(t *testing.T) {
	cases := []struct {
		name       string
		lines      []string
		tun        string
		ri         string
		wantReject bool
	}{
		{
			name: "interface-level VRF",
			lines: append(wgBase9909(t, "wg0", "51820", wgKeyA, wgKeyB),
				"set interfaces wg0 tunnel routing-instance destination blue",
				"set routing-instances blue instance-type virtual-router",
			),
			tun: "wg0",
			ri:  "blue",
		},
		{
			name: "per-unit VRF",
			lines: append(wgUnitBase9909(t, "wg1", "0", "51821", wgKeyB, wgKeyA),
				"set interfaces wg1 unit 0 tunnel routing-instance destination blue",
				"set routing-instances blue instance-type virtual-router",
			),
			tun: "wg1",
			ri:  "blue",
		},
		{
			name: "forwarding has no VRF device",
			lines: append(wgBase9909(t, "wg2", "51822", wgKeyC, wgKeyA),
				"set interfaces wg2 tunnel routing-instance destination fwd",
				"set routing-instances fwd instance-type forwarding",
			),
			tun:        "wg2",
			ri:         "fwd",
			wantReject: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree4953(t, tc.lines))
			if !tc.wantReject {
				if err != nil {
					t.Fatalf("supported WireGuard + VRF scope rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("strict commit accepted unsupported WireGuard scope; want reject naming tunnel %q + instance %q", tc.tun, tc.ri)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.tun) || !strings.Contains(msg, tc.ri) {
				t.Fatalf("reject %q names neither tunnel %q nor instance %q; want both", msg, tc.tun, tc.ri)
			}
			if !strings.Contains(msg, "wireguard") {
				t.Fatalf("reject %q does not say wireguard", msg)
			}
		})
	}
}

// TestWireguardRoutingInstanceMemberBound9909 covers the second scope path —
// `routing-instances <ri> interface <member>`. Supported VRF members now
// commit cleanly because the snapshot row supplies the effective transport
// table; forwarding members remain refused because no VRF device exists.
func TestWireguardRoutingInstanceMemberBound9909(t *testing.T) {
	cases := []struct {
		name       string
		lines      []string
		member     string
		tun        string
		riType     string
		ri         string
		wantReject bool
	}{
		{
			name:   "interface-level bare",
			lines:  wgBase9909(t, "wg0", "51820", wgKeyA, wgKeyB),
			member: "wg0",
			tun:    "wg0",
		},
		{
			name:   "interface-level unit-ref",
			lines:  wgBase9909(t, "wg0", "51820", wgKeyA, wgKeyB),
			member: "wg0.0",
			tun:    "wg0",
		},
		{
			name:   "interface-level slash-dash alias",
			lines:  wgBase9909(t, "gr-0/0/0", "51822", wgKeyA, wgKeyB),
			member: "gr-0-0-0",
			tun:    "gr-0-0-0",
		},
		{
			name:   "per-unit bare",
			lines:  wgUnitBase9909(t, "wg1", "1", "51821", wgKeyB, wgKeyA),
			member: "wg1",
			tun:    "wg1u1",
		},
		{
			name:   "per-unit unit-ref",
			lines:  wgUnitBase9909(t, "wg1", "0", "51821", wgKeyB, wgKeyA),
			member: "wg1.0",
			tun:    "wg1",
		},
		{
			name:   "per-unit slash-dash alias",
			lines:  wgUnitBase9909(t, "gr-0/0/1", "1", "51823", wgKeyC, wgKeyA),
			member: "gr-0-0-1.1",
			tun:    "gr-0-0-1u1",
		},
		{
			name:       "forwarding-type",
			lines:      wgBase9909(t, "wg2", "51824", wgKeyC, wgKeyA),
			member:     "wg2",
			tun:        "wg2",
			riType:     "forwarding",
			ri:         "fwd1",
			wantReject: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			riType := tc.riType
			if riType == "" {
				riType = "virtual-router"
			}
			ri := tc.ri
			if ri == "" {
				ri = "blue"
			}
			lines := append(tc.lines,
				"set routing-instances "+ri+" instance-type "+riType,
				"set routing-instances "+ri+" interface "+tc.member,
			)
			_, err := CompileConfig(buildTree4953(t, lines))
			if !tc.wantReject {
				if err != nil {
					t.Fatalf("supported WireGuard member + VRF scope rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("strict commit accepted unsupported WG member %q of routing-instance %q", tc.member, ri)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.tun) || !strings.Contains(msg, ri) {
				t.Fatalf("reject %q names neither tunnel %q nor instance %q; want both", msg, tc.tun, ri)
			}
		})
	}
}

// TestWireguardRIListMemberBound9909 covers the runtime-normalized scope
// field the daemon stamps while collecting routing-instance members. The
// positive path is accepted because the named instance has a VRF device.
func TestWireguardRIListMemberBound9909(t *testing.T) {
	lines := append(wgBase9909(t, "wg0", "51820", wgKeyA, wgKeyB),
		"set routing-instances blue instance-type virtual-router",
	)
	cfg, err := CompileConfig(buildTree4953(t, lines))
	if err != nil {
		t.Fatalf("unscoped control config rejected before runtime RI member injection: %v", err)
	}
	tc := cfg.Interfaces.Interfaces["wg0"].Tunnel
	tc.RIListMember = "blue"
	if _, err := validateWireguardRoutingInstance9909(cfg, false); err != nil {
		t.Fatalf("supported runtime RIListMember rejected: %v", err)
	}
}

// A shared interface-level WG device cannot serve two different VRF tables.
// Units 0 and 1 both resolve to wg0, so accepting blue + red would leave the
// socket scope order-dependent and could put outer traffic in the wrong VRF.
func TestWireguardConflictingVRFMembersRefused10196(t *testing.T) {
	lines := append(wgBase9909(t, "wg0", "51820", wgKeyA, wgKeyB),
		"set interfaces wg0 unit 0 family inet address 192.0.2.1/31",
		"set interfaces wg0 unit 1 family inet address 192.0.2.3/31",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue interface wg0.0",
		"set routing-instances red instance-type virtual-router",
		"set routing-instances red interface wg0.1",
	)
	if _, err := CompileConfig(buildTree4953(t, lines)); err == nil {
		t.Fatal("strict commit accepted two VRF claims for one shared WireGuard device")
	} else if !strings.Contains(err.Error(), "blue") || !strings.Contains(err.Error(), "red") {
		t.Fatalf("conflict reject %q omits one of the two routing instances", err)
	}
	cfg, err := CompileConfigLenient(buildTree4953(t, lines))
	if err != nil {
		t.Fatalf("tolerant conflict load rejected instead of quarantining: %v", err)
	}
	if len(wgVRF9909Warnings(cfg)) != 1 || !strings.Contains(wgVRF9909Warnings(cfg)[0], "conflicting") {
		t.Fatalf("want one conflict warning, got %v", cfg.Warnings)
	}
	if ifc := cfg.Interfaces.Interfaces["wg0"]; ifc == nil || ifc.Tunnel != nil {
		t.Fatalf("conflicting shared WG endpoint survived tolerant quarantine: %+v", ifc)
	}
}

// TestWireguardRoutingInstanceLenientSkips9909: the tolerant path (boot /
// load / peer-sync of a config persisted before this gate) must warn LOUDLY
// and SKIP the mis-scoped tunnel — a warn-only tunnel would come up
// half-scoped (inner VRF, outer main), which is the live defect. The skip is
// per-tunnel: a clean second tunnel still lands.
func TestWireguardRoutingInstanceLenientSkips9909(t *testing.T) {
	lines := append(wgBase9909(t, "wg0", "51820", wgKeyA, wgKeyB),
		"set interfaces wg0 tunnel routing-instance destination blue",
		"set routing-instances blue instance-type forwarding",
		"set interfaces wg9 tunnel mode wireguard",
		"set interfaces wg9 tunnel wireguard listen-port 51822",
		"set interfaces wg9 tunnel wireguard private-key "+wgKeyC,
		"set interfaces wg9 tunnel wireguard peer "+wgKeyA+" allowed-ips 10.9.0.0/24",
	)
	tree := buildTree4953(t, lines)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must warn+skip, not reject: %v", err)
	}
	warns := wgVRF9909Warnings(cfg)
	if len(warns) != 1 {
		t.Fatalf("want exactly one #9909 warning, got %d: %v", len(warns), cfg.Warnings)
	}
	if !strings.Contains(warns[0], "wg0") || !strings.Contains(warns[0], "blue") {
		t.Fatalf("warning %q names neither tunnel wg0 nor instance blue; want both", warns[0])
	}
	if !strings.Contains(strings.ToLower(warns[0]), "skip") {
		t.Fatalf("warning %q does not say the tunnel is SKIPPED", warns[0])
	}
	if ifc := cfg.Interfaces.Interfaces["wg0"]; ifc == nil || ifc.Tunnel != nil {
		t.Fatalf("mis-scoped wg0 tunnel survives tolerant load; want it dropped from the compiled config")
	}
	if ifc := cfg.Interfaces.Interfaces["wg9"]; ifc == nil || ifc.Tunnel == nil {
		t.Fatalf("clean wg9 tunnel missing after tolerant load; the skip must be per-tunnel")
	}
}

// TestWireguardRoutingInstanceMemberLenientSkips9909: the list-membership half
// of the tolerant skip — the tunnel is dropped so neither the routing manager
// (inner VRF bind) nor the snapshot builder (outer socket spawn) ever sees it.
func TestWireguardRoutingInstanceMemberLenientSkips9909(t *testing.T) {
	lines := append(wgBase9909(t, "wg0", "51820", wgKeyA, wgKeyB),
		"set routing-instances blue instance-type forwarding",
		"set routing-instances blue interface wg0.0",
		"set interfaces ge0 unit 0 family inet address 192.0.2.1/24",
		"set routing-instances blue interface ge0.0",
	)
	tree := buildTree4953(t, lines)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must warn+skip, not reject: %v", err)
	}
	if got := wgVRF9909Warnings(cfg); len(got) != 1 {
		t.Fatalf("want exactly one #9909 warning, got %d: %v", len(got), cfg.Warnings)
	}
	if ifc := cfg.Interfaces.Interfaces["wg0"]; ifc == nil || ifc.Tunnel != nil {
		t.Fatalf("mis-scoped wg0 tunnel survives tolerant load; want it dropped from the compiled config")
	}
	var blue *RoutingInstanceConfig
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name == "blue" {
			blue = ri
			break
		}
	}
	if blue == nil {
		t.Fatal("routing-instance blue disappeared; tolerant quarantine must preserve the RI and unrelated members")
	}
	for _, member := range blue.Interfaces {
		if member == "wg0" || member == "wg0.0" {
			t.Fatalf("quarantined WG member %q survived in blue RI: %v", member, blue.Interfaces)
		}
	}
	var keptUnrelated bool
	for _, member := range blue.Interfaces {
		if member == "ge0.0" {
			keptUnrelated = true
			break
		}
	}
	if !keptUnrelated {
		t.Fatalf("unrelated RI member ge0.0 was removed with WG member: %v", blue.Interfaces)
	}
}

// TestWireguardSharedDeviceLenientQuarantine9909 covers an interface-level WG
// plus a scope-only unit override. Both records name the same persistent wgN
// device; dropping only the violating unit would leave an endpoint alive.
func TestWireguardSharedDeviceLenientQuarantine9909(t *testing.T) {
	lines := append(wgBase9909(t, "wg0", "51820", wgKeyA, wgKeyB),
		"set interfaces wg0 unit 0 tunnel routing-instance destination blue",
		"set routing-instances blue instance-type forwarding",
	)
	cfg, err := CompileConfigLenient(buildTree4953(t, lines))
	if err != nil {
		t.Fatalf("tolerant shared-device load rejected: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["wg0"]
	if ifc == nil || ifc.Tunnel != nil || ifc.Units[0] == nil || ifc.Units[0].Tunnel != nil {
		t.Fatalf("shared wg0 device was not fully quarantined: ifc=%+v", ifc)
	}
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		if ep.Tunnel != nil && ep.Tunnel.Mode == "wireguard" && ep.Tunnel.Name == "wg0" {
			t.Fatalf("shared wg0 endpoint survived tolerant quarantine: %q", ep.Name)
		}
	}
}

// TestWireguardBareMemberLenientNarrowing9909 ensures a bare RI member that
// fans down to one affected WG device and one surviving GRE device is narrowed
// rather than deleted wholesale.
func TestWireguardBareMemberLenientNarrowing9909(t *testing.T) {
	lines := []string{
		"set interfaces gr-0/0/0 unit 0 tunnel mode wireguard",
		"set interfaces gr-0/0/0 unit 0 tunnel wireguard listen-port 51820",
		"set interfaces gr-0/0/0 unit 0 tunnel wireguard private-key " + wgKeyA,
		"set interfaces gr-0/0/0 unit 0 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.1.0.0/24",
		"set interfaces gr-0/0/0 unit 1 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 unit 1 tunnel destination 10.0.0.2",
		"set routing-instances blue instance-type forwarding",
		"set routing-instances blue interface gr-0/0/0",
		"set system dataplane-type userspace",
	}
	cfg, err := CompileConfigLenient(buildTree4953(t, lines))
	if err != nil {
		t.Fatalf("tolerant bare-member load rejected: %v", err)
	}
	if ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]; ifc == nil ||
		ifc.Units[0] == nil || ifc.Units[0].Tunnel != nil ||
		ifc.Units[1] == nil || ifc.Units[1].Tunnel == nil ||
		ifc.Units[1].Tunnel.Mode != "gre" {
		t.Fatalf("WG unit was not dropped while GRE sibling survived: %+v", cfg.Interfaces.Interfaces["gr-0/0/0"])
	}
	var blue *RoutingInstanceConfig
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name == "blue" {
			blue = ri
			break
		}
	}
	if blue == nil {
		t.Fatal("routing-instance blue disappeared during bare-member quarantine")
	}
	if len(blue.Interfaces) != 1 || blue.Interfaces[0] != "gr-0/0/0.1" {
		t.Fatalf("bare member was not narrowed to surviving GRE unit: %v", blue.Interfaces)
	}
}

// TestWireguardForwardingMemberLenientQuarantine9909 locks the broad
// any-routing-instance decision on tolerant load too, not only strict reject.
func TestWireguardForwardingMemberLenientQuarantine9909(t *testing.T) {
	lines := append(wgBase9909(t, "wg0", "51820", wgKeyA, wgKeyB),
		"set routing-instances fwd1 instance-type forwarding",
		"set routing-instances fwd1 interface wg0",
	)
	cfg, err := CompileConfigLenient(buildTree4953(t, lines))
	if err != nil {
		t.Fatalf("tolerant forwarding-member load rejected: %v", err)
	}
	warns := wgVRF9909Warnings(cfg)
	if len(warns) != 1 || !strings.Contains(warns[0], "wg0") || !strings.Contains(warns[0], "fwd1") {
		t.Fatalf("forwarding-member warning must name wg0 and fwd1: %v", warns)
	}
	if ifc := cfg.Interfaces.Interfaces["wg0"]; ifc == nil || ifc.Tunnel != nil {
		t.Fatalf("forwarding-listed wg0 survived tolerant quarantine")
	}
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name == "fwd1" {
			if len(ri.Interfaces) != 0 {
				t.Fatalf("forwarding RI member survived tolerant quarantine: %v", ri.Interfaces)
			}
			return
		}
	}
	t.Fatal("forwarding RI fwd1 disappeared during tolerant quarantine")
}

// TestWireguardUndeclaredUnitMemberUnaffected9909 prevents a fabricated
// parent-device match for a nonzero unit ref the config never declared.
func TestWireguardUndeclaredUnitMemberUnaffected9909(t *testing.T) {
	for _, member := range []string{"wg0.99", "wg0.999"} {
		t.Run(member, func(t *testing.T) {
			lines := append(wgBase9909(t, "wg0", "51820", wgKeyA, wgKeyB),
				"set routing-instances blue instance-type virtual-router",
				"set routing-instances blue interface "+member,
			)
			if cfg, err := CompileConfig(buildTree4953(t, lines)); err != nil {
				t.Fatalf("undeclared unit member falsely rejected on strict compile: %v", err)
			} else if len(wgVRF9909Warnings(cfg)) != 0 {
				t.Fatalf("undeclared unit member drew strict #9909 warnings: %v", wgVRF9909Warnings(cfg))
			}
			cfg, err := CompileConfigLenient(buildTree4953(t, lines))
			if err != nil {
				t.Fatalf("undeclared unit member tolerant load rejected: %v", err)
			}
			if len(wgVRF9909Warnings(cfg)) != 0 {
				t.Fatalf("undeclared unit member drew tolerant #9909 warnings: %v", wgVRF9909Warnings(cfg))
			}
			ifc := cfg.Interfaces.Interfaces["wg0"]
			if ifc == nil || ifc.Tunnel == nil {
				t.Fatalf("unscoped wg0 was removed because of undeclared unit member")
			}
			var endpointFound bool
			for _, ep := range EmitTunnelEndpointNames(cfg) {
				if ep.Tunnel != nil && ep.Tunnel.Mode == "wireguard" && ep.Tunnel.Name == "wg0" {
					endpointFound = true
					break
				}
			}
			if !endpointFound {
				t.Fatalf("unscoped wg0 endpoint disappeared for undeclared member %q", member)
			}
			for _, ri := range cfg.RoutingInstances {
				if ri != nil && ri.Name == "blue" {
					if len(ri.Interfaces) != 1 || ri.Interfaces[0] != member {
						t.Fatalf("undeclared unit member changed during tolerant load: %v", ri.Interfaces)
					}
					return
				}
			}
			t.Fatal("routing-instance blue disappeared during undeclared-unit control")
		})
	}
}

// TestWireguardBareMemberNarrowingDeduplicatesExplicit9909 ensures generated
// survivor refs do not duplicate an already-authored explicit unit member.
func TestWireguardBareMemberNarrowingDeduplicatesExplicit9909(t *testing.T) {
	lines := []string{
		"set interfaces gr-0/0/0 unit 0 tunnel mode wireguard",
		"set interfaces gr-0/0/0 unit 0 tunnel wireguard listen-port 51820",
		"set interfaces gr-0/0/0 unit 0 tunnel wireguard private-key " + wgKeyA,
		"set interfaces gr-0/0/0 unit 0 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.1.0.0/24",
		"set interfaces gr-0/0/0 unit 1 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 unit 1 tunnel destination 10.0.0.2",
		"set routing-instances blue instance-type forwarding",
		"set routing-instances blue interface gr-0/0/0",
		"set routing-instances blue interface gr-0/0/0.1",
		"set system dataplane-type userspace",
	}
	cfg, err := CompileConfigLenient(buildTree4953(t, lines))
	if err != nil {
		t.Fatalf("tolerant duplicate-member load rejected: %v", err)
	}
	var blue *RoutingInstanceConfig
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name == "blue" {
			blue = ri
			break
		}
	}
	if blue == nil {
		t.Fatal("routing-instance blue disappeared during duplicate-member quarantine")
	}
	if len(blue.Interfaces) != 1 || blue.Interfaces[0] != "gr-0/0/0.1" {
		t.Fatalf("bare narrowing duplicated or lost explicit GRE member: %v", blue.Interfaces)
	}
}

// TestWireguardBareMemberVLANUnitZeroNarrowing9909 ensures a VLAN-ID unit
// survives as its VLAN device instead of being redirected to Base.0.
func TestWireguardBareMemberVLANUnitZeroNarrowing9909(t *testing.T) {
	lines := []string{
		"set interfaces gr-0/0/9 flexible-vlan-tagging",
		"set interfaces gr-0/0/9 unit 0 vlan-id 100",
		"set interfaces gr-0/0/9 unit 0 family inet address 192.0.2.1/24",
		"set interfaces gr-0/0/9 unit 1 tunnel mode wireguard",
		"set interfaces gr-0/0/9 unit 1 tunnel wireguard listen-port 51826",
		"set interfaces gr-0/0/9 unit 1 tunnel wireguard private-key " + wgKeyA,
		"set interfaces gr-0/0/9 unit 1 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.1.0.0/24",
		"set routing-instances blue instance-type forwarding",
		"set routing-instances blue interface gr-0/0/9",
		"set system dataplane-type userspace",
	}
	cfg, err := CompileConfigLenient(buildTree4953(t, lines))
	if err != nil {
		t.Fatalf("tolerant VLAN-member load rejected: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["gr-0/0/9"]
	if ifc == nil || ifc.Units[0] == nil || ifc.Units[0].VlanID != 100 ||
		ifc.Units[1] == nil || ifc.Units[1].Tunnel != nil {
		t.Fatalf("VLAN unit or WG quarantine is wrong: %+v", ifc)
	}
	var blue *RoutingInstanceConfig
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name == "blue" {
			blue = ri
			break
		}
	}
	if blue == nil {
		t.Fatal("routing-instance blue disappeared during VLAN-member quarantine")
	}
	if len(blue.Interfaces) != 1 || blue.Interfaces[0] != "gr-0/0/9.0" {
		t.Fatalf("VLAN unit survivor was redirected or duplicated: %v", blue.Interfaces)
	}
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		if ep.Tunnel != nil && ep.Tunnel.Mode == "wireguard" {
			t.Fatalf("quarantined WG endpoint survived VLAN-member narrowing: %q", ep.Name)
		}
	}
}

// TestWireguardWithoutRoutingInstanceUnaffected9909 pins the common cases
// shut: a WG tunnel with no scope and a GRE tunnel WITH a routing-instance
// stanza (the long-supported non-WireGuard shape) must commit clean with no
// #9909 diagnostic. Without these, a gate that fired on "any WireGuard
// tunnel" or "any tunnel with an RI" would pass the reject tests while crying
// wolf on working configs.
func TestWireguardWithoutRoutingInstanceUnaffected9909(t *testing.T) {
	t.Run("plain WG", func(t *testing.T) {
		tree := buildTree4953(t, wgBase9909(t, "wg0", "51820", wgKeyA, wgKeyB))
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("plain WG tunnel rejected: %v", err)
		}
		if got := wgVRF9909Warnings(cfg); len(got) != 0 {
			t.Fatalf("plain WG tunnel drew #9909 warnings: %v", got)
		}
	})
	t.Run("GRE with stanza", func(t *testing.T) {
		lines := []string{
			"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
			"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
			"set interfaces gr-0/0/0 tunnel routing-instance destination dmz-vr",
			"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
			"set routing-instances dmz-vr instance-type virtual-router",
			"set system dataplane-type userspace",
		}
		tree := buildTree4953(t, lines)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("GRE + routing-instance stanza rejected: %v", err)
		}
		if got := wgVRF9909Warnings(cfg); len(got) != 0 {
			t.Fatalf("GRE tunnel drew #9909 warnings: %v", got)
		}
	})
}
