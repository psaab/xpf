package config

import "fmt"

// snmpTrapOptionsStatements9562 returns the statement keywords a `trap-options`
// node carries, read by POSITION in every AST shape the parser produces:
//
//	trap-options { routing-instance mgmt; context-oid; }   one child per statement (braced)
//	trap-options routing-instance mgmt;                     the node's OWN Keys[1] (brace-elided)
//	set snmp trap-options routing-instance mgmt             Keys[1] again, one node per line (flat-set)
//
// A value sits at Keys[2] or later and is never read, so an advisory cannot echo
// it.
func snmpTrapOptionsStatements9562(n *Node) []string {
	if n == nil {
		return nil
	}
	if len(n.Keys) >= 2 {
		return []string{n.Keys[1]}
	}
	return childNames9414(n)
}

// snmpTrapOptionsAdvisory9562 says, per statement, what actually happens,
// because one blanket "not implemented" would be false for agent-address:
//
//   - source-address: unchanged #4306 text, pinned by three cells.
//   - routing-instance: pkg/snmp opens each trap socket with a plain
//     net.DialTimeout("udp"), so traps leave through the default routing
//     instance.
//   - context-oid: the trap varbinds (sysUpTime, snmpTrapOID, the interface
//     objects) carry no context OID.
//   - agent-address: an SNMPv1 trap's agent-addr is already derived from the
//     source address the kernel selects per target (#9123), which is what
//     `outgoing-interface` asks for, and an SNMPv2c trap has no agent-addr.
func snmpTrapOptionsAdvisory9562(kw string) string {
	switch kw {
	case "source-address":
		return "snmp trap-options source-address: accepted but NOT enforced (traps are sent from the default egress IP)"
	case "routing-instance":
		return "snmp trap-options routing-instance: accepted but NOT enforced (traps are sent through the default routing instance) (#9562)"
	case "context-oid":
		return "snmp trap-options context-oid: accepted but NOT implemented (no context varbind is added to traps) (#9562)"
	case "agent-address":
		return "snmp trap-options agent-address: accepted and ignored (an SNMPv1 trap's agent-addr is already the per-target source address, " +
			"which is what outgoing-interface requests; SNMPv2c traps carry no agent-addr) (#9562)"
	default:
		return fmt.Sprintf("snmp trap-options %s: accepted but NOT implemented (no-op) (#9562)", kw)
	}
}
