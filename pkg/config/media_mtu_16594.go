package config

// #16594: Junos interface-level `mtu` is the MEDIA MTU — it counts the
// Ethernet header (14 bytes, plus 4 per 802.1Q tag) — while `family
// inet/inet6 mtu` is the PROTOCOL (L3/IP) MTU and Linux netdev MTU is
// also L3. Before this, ifc.MTU stored the authored media value and every
// writer (planPhysDesired LinkSetMTU, networkd MTUBytes, fabric/bond
// owners) applied it verbatim as L3, so `mtu 1514` (the Junos GE default,
// IP 1500) produced a 1514-byte IP MTU — 14 bytes (18 tagged) larger than
// a Junos peer with the same configured value, black-holing DF packets
// in (N-14, N] toward that peer with no PTB.
//
// Translation lives at COMPILE time, in compileInterfaces, the single
// construction site for InterfaceConfig: ifc.MTU now always holds the
// L3 value to programme (media - 14 - 4*tags). Keeping the compiled
// field L3 means every downstream consumer — dataplane planner, strict
// gates (#9837/#13936/#16244), networkd models, fabric floor, tunnel
// defaults, userspace logical-only fallback — judges and writes the
// same value with no per-site conversion to drift. Family mtu
// (unit.MTU) is already L3 and is never translated.
//
// Tag count: a tagging-enabled interface (vlan-tagging or
// flexible-vlan-tagging) carries exactly one 802.1Q tag on the wire for
// the shapes xpf admits (a QinQ inner tag is rejected at commit, see
// TaggingEnabled), so the deduction is 18 tagged / 14 untagged. The
// count keys on the authored tagging flags, not on whether any unit
// currently carries a vlan-id: the media MTU is a property of the
// physical link's framing.
//
// Floor: a media MTU at or below the header size has no L3 payload.
// compileInterfaces clamps the L3 result to >= 1 (the schema floor for
// the leaf) rather than storing 0, because 0 is the "not set" sentinel
// everywhere downstream — storing it would silently drop the authored
// leaf and materialise the 1500 default instead of the tiny MTU the
// operator asked the kernel to judge. The kernel/driver still owns the
// real floor and rejects loudly at write time.
//
// Tunnel/loopback-class names (gr-/ip-/st/fti/lo) and fab/reth/irb
// logical devices have no Ethernet media on the named device itself:
// their MTU is already an L3/device MTU in Junos terms, so the authored
// value passes through untranslated. Their underlying physical parents,
// when separately configured, translate on their own stanzas. Aggregated
// Ethernet has a media MTU and is translated by the same Ethernet overhead
// rules as other Ethernet.

const (
	ethernetHeaderBytes16594 = 14
	vlanTagBytes16594        = 4
)

// mediaMTUOverhead16594 returns the header bytes counted by a Junos
// media MTU on this interface: 14 untagged, 18 when tagging is enabled.
func mediaMTUOverhead16594(ifc *InterfaceConfig) int {
	if ifc != nil && ifc.TaggingEnabled() {
		return ethernetHeaderBytes16594 + vlanTagBytes16594
	}
	return ethernetHeaderBytes16594
}

// isMediaMTUExempt16594 reports whether the named interface has no
// Ethernet media MTU to translate: tunnel/loopback-class names (via the
// canonical #6731 lexical predicate, plus the authoritative Tunnel
// stanza), fabric overlays, redundant ethernet and IRB logical devices.
// Exempt values are already L3/device MTUs.
func isMediaMTUExempt16594(name string, ifc *InterfaceConfig) bool {
	if ifc == nil {
		return true
	}
	if ifc.Tunnel != nil || ifc.LocalFabricMember != "" || len(ifc.FabricMembers) > 0 {
		return true
	}
	base := name
	if base == "" {
		base = ifc.Name
	}
	if IsTunnelOrLoopbackIfName(base) || IsSecureTunnelIfName(base) {
		return true
	}
	switch {
	case ifNameNumericSuffix(base, "reth"), ifNameNumericSuffix(base, "irb"),
		ifNameNumericSuffix(base, "fab"),
		ifNameNumericSuffix(base, "lo"):
		return true
	}
	return false
}

// translateInterfaceMediaMTU16594 converts an authored interface-level
// media MTU to the L3 MTU stored in ifc.MTU. It must be called once per
// interface, after VlanTagging/FlexibleVlanTagging and Tunnel are known
// and before the InterfaceConfig is published in ifaces.Interfaces.
// A zero (unset) value stays zero.
func translateInterfaceMediaMTU16594(name string, ifc *InterfaceConfig) {
	if ifc == nil || ifc.MTU <= 0 {
		return
	}
	if isMediaMTUExempt16594(name, ifc) {
		return
	}
	l3 := ifc.MTU - mediaMTUOverhead16594(ifc)
	if l3 < 1 {
		l3 = 1
	}
	ifc.MTU = l3
}

// NetdevMTUForInterface returns the L3 MTU to programme on the named
// interface's netdev for documentation/tests: the compiled ifc.MTU,
// which compileInterfaces already translated from the authored media
// MTU. It exists so callers outside the compiler state the contract in
// one place rather than re-deriving header arithmetic.
func (ifc *InterfaceConfig) NetdevMTU() int {
	if ifc == nil {
		return 0
	}
	return ifc.MTU
}
