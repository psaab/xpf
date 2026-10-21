// protocol_ifname_9405.go resolves and belts the interface operands the
// routing-protocol stanzas emit into the managed section.
//
// #9405. The FRR renderer took `protocols ospf area 0 interface <ref>` (and
// the OSPFv3 / IS-IS / RIP equivalents) VERBATIM from the compiled config and
// wrote it into frr.conf. The compiled value is the AUTHORED Junos reference —
// `ge-0/0/1.0`, `reth0.50` — and Linux `dev_valid_name()` forbids `/`, so the
// rendered `interface ge-0/0/1.0` block could never bind a netdev. Measured on
// all four config channels (`configstore.CheckText`, `CompileConfig`,
// `CompileConfigLenient`, `SchemaValidate`): every one ACCEPTS, and the daemon
// then writes a stanza no IGP can ever attach to. A dynamic-routing uplink
// blackholes on a green commit with no diagnostic anywhere.
//
// Static routes never had this problem because generateStaticRoute has carried
// its own RETH map + `.0` strip since #5557/#6795. The protocol stanzas were
// the outlier, and the sibling leaf in the same `protocols` container
// (router-advertisement) already resolves via ResolveKernelIfName in
// pkg/daemon.
//
// TWO transforms are applied here, in this order:
//
//  1. RESOLUTION — through FullConfig.IfNameResolver, which the daemon wires to
//     Config.ResolveKernelIfName. That is the canonical resolver: slash->dash,
//     RETH->local member, unit-0 collapse, and the `.<vlan-id>` arm that #5107
//     fixed for RA (a unit numbered 80 carrying `vlan-id 180` is the netdev
//     `<member>.180`, NOT `<member>.80`). A nil resolver is identity, so every
//     direct generateProtocols caller keeps byte-identical output.
//
//  2. THE TOKEN BELT — validFRRInterfaceOperand, the same single-token test
//     #6795 applied to the static-route interface operand. It is applied HERE
//     and not only there because the protocol operands reach frr.conf by the
//     same route: the schema leaf is free-form, so a name carrying whitespace
//     or a newline commits clean and then splits `interface <name>` into extra
//     operands — or, with a newline, appends an attacker-chosen statement to
//     the managed section. Measured before this change: `interface
//     "ge-0/0/1.0 zzz"` and `interface "ge-0/0/1.0; foo"` are ACCEPTED on all
//     four channels and render raw. Same class as #9050.
//
// A reference that fails the belt is DROPPED with a warning rather than
// rendered: it can never name a netdev, and one malformed line fails the whole
// frr-reload (#1880/#2223), which would take down every protocol rather than
// the one interface.
//
// The resolution deliberately produces COPIES. The pointers on FullConfig are
// the daemon's ACTIVE compiled config; mutating them in the renderer is the
// #9141 defect (a render pass that rewrites the config the operator can read
// back). Every struct is copied by value so a field added later to
// OSPFInterface / ISISInterface is carried through without an edit here.
package frr

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
)

// ifNameResolver returns fc's protocol interface-name resolver, or identity
// when none was supplied. Identity is the correct fallback for the direct
// generateProtocols callers in tests and for any FullConfig built without a
// Config in hand; it reproduces the pre-#9405 rendering exactly.
func (fc *FullConfig) ifNameResolver() func(string) string {
	if fc == nil || fc.IfNameResolver == nil {
		return func(s string) string { return s }
	}
	return fc.IfNameResolver
}

// renderableIfName resolves ref and reports whether the result is emittable as
// a single FRR interface operand. proto/where name the call site for the drop
// warning.
func renderableIfName(resolve func(string) string, ref, proto string) (string, bool) {
	resolved := resolve(ref)
	if !validFRRInterfaceOperand(resolved) {
		slog.Warn("frr: dropping unrenderable protocol interface reference",
			"protocol", proto, "configured", ref, "resolved", resolved)
		return "", false
	}
	return resolved, true
}

// resolveOSPFIfNames returns a copy of ospf whose interface references are
// resolved to kernel names, with unrenderable references dropped.
func resolveOSPFIfNames(resolve func(string) string, ospf *config.OSPFConfig) *config.OSPFConfig {
	if ospf == nil {
		return nil
	}
	out := *ospf
	out.Areas = make([]*config.OSPFArea, 0, len(ospf.Areas))
	for _, area := range ospf.Areas {
		if area == nil {
			out.Areas = append(out.Areas, area)
			continue
		}
		ac := *area
		ac.Interfaces = make([]*config.OSPFInterface, 0, len(area.Interfaces))
		for _, iface := range area.Interfaces {
			if iface == nil {
				continue
			}
			name, ok := renderableIfName(resolve, iface.Name, "ospf")
			if !ok {
				continue
			}
			ic := *iface
			ic.Name = name
			ac.Interfaces = append(ac.Interfaces, &ic)
		}
		out.Areas = append(out.Areas, &ac)
	}
	return &out
}

// resolveOSPFv3IfNames is the OSPFv3 twin of resolveOSPFIfNames.
func resolveOSPFv3IfNames(resolve func(string) string, ospfv3 *config.OSPFv3Config) *config.OSPFv3Config {
	if ospfv3 == nil {
		return nil
	}
	out := *ospfv3
	out.Areas = make([]*config.OSPFv3Area, 0, len(ospfv3.Areas))
	for _, area := range ospfv3.Areas {
		if area == nil {
			out.Areas = append(out.Areas, area)
			continue
		}
		ac := *area
		ac.Interfaces = make([]*config.OSPFv3Interface, 0, len(area.Interfaces))
		for _, iface := range area.Interfaces {
			if iface == nil {
				continue
			}
			name, ok := renderableIfName(resolve, iface.Name, "ospf3")
			if !ok {
				continue
			}
			ic := *iface
			ic.Name = name
			ac.Interfaces = append(ac.Interfaces, &ic)
		}
		out.Areas = append(out.Areas, &ac)
	}
	return &out
}

// resolveRIPIfNames resolves the RIP `network` and `passive-interface` operand
// lists. RIP carries bare strings rather than structs, so both lists are
// rebuilt.
func resolveRIPIfNames(resolve func(string) string, rip *config.RIPConfig) *config.RIPConfig {
	if rip == nil {
		return nil
	}
	out := *rip
	out.Interfaces = resolveIfNameList(resolve, rip.Interfaces, "rip")
	out.Passive = resolveIfNameList(resolve, rip.Passive, "rip")
	return &out
}

func resolveIfNameList(resolve func(string) string, refs []string, proto string) []string {
	if refs == nil {
		return nil
	}
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		name, ok := renderableIfName(resolve, ref, proto)
		if !ok {
			continue
		}
		out = append(out, name)
	}
	return out
}

// resolveISISIfNames is the IS-IS twin of resolveOSPFIfNames.
func resolveISISIfNames(resolve func(string) string, isis *config.ISISConfig) *config.ISISConfig {
	if isis == nil {
		return nil
	}
	out := *isis
	out.Interfaces = make([]*config.ISISInterface, 0, len(isis.Interfaces))
	for _, iface := range isis.Interfaces {
		if iface == nil {
			continue
		}
		name, ok := renderableIfName(resolve, iface.Name, "isis")
		if !ok {
			continue
		}
		ic := *iface
		ic.Name = name
		out.Interfaces = append(out.Interfaces, &ic)
	}
	return &out
}
