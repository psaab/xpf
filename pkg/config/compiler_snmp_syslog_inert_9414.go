package config

import (
	"fmt"
	"sort"
)

// #9414: SNMP and syslog statements that pass every config channel —
// SchemaValidate, strict CompileConfig, CompileConfigLenient and
// configstore.CheckText — and compile to NOTHING, made loud with the #4306 S-5
// accept-with-advisory pattern. Accept, never reject: every one of them
// committed clean before, so a reject would brick the tolerant load / peer-sync
// path on a config an operator already has (#1960).
//
// Messages carry KEYWORDS only, never a configured value: an engine ID, a USM
// user name or password, a match regex and a syslog destination can each be
// sensitive (cf. #7511).

// snmpV3InertWarnings9414 names every `snmp v3` statement compileSNMPv3 does not
// read. compileSNMPv3 reads exactly one path, `usm local-engine user`, so the
// advisory is the COMPLEMENT of that path rather than a list of keywords known to
// be inert: `vacm`, `notify`, `notify-filter`, `target-address`,
// `target-parameters`, `snmp-community` and `usm remote-engine` are covered by
// construction, and so is any statement nobody has thought to list.
func snmpV3InertWarnings9414(v3 *Node) []string {
	v3Kws, usmKws := snmpV3Statements9414(v3)
	var out []string
	for _, kw := range v3Kws {
		if kw != "usm" {
			out = append(out, snmpV3InertMessage9414(kw))
		}
	}
	for _, kw := range usmKws {
		if kw != "local-engine" {
			out = append(out, snmpUSMInertMessage9414(kw))
		}
	}
	return out
}

// snmpV3Statements9414 returns the statement keywords directly under `v3` and
// directly under `v3 usm`, read by POSITION in every AST shape the parser
// produces:
//
//	v3 { vacm { ... } }                child Name()               (braced, flat-set)
//	v3 vacm { ... }                    v3's OWN Keys[1]           (brace-elided)
//	v3 usm remote-engine <id> { ... }  v3's OWN Keys[1], Keys[2]  (brace-elided)
//	v3 { usm remote-engine <id> { } }  the usm child's OWN Keys[1]
//
// In an elided shape the node's Children belong to the PACKED statement, not to
// v3, so they are not read as v3 statements: `v3 vacm { security-to-group ... }`
// is one v3 statement, not two. Values sit at later positions and are never
// read, which is also why a USM user NAMED `vacm` is not reported.
func snmpV3Statements9414(v3 *Node) (v3Kws, usmKws []string) {
	if v3 == nil {
		return nil, nil
	}
	if len(v3.Keys) >= 2 {
		v3Kws = append(v3Kws, v3.Keys[1])
		if v3.Keys[1] == "usm" {
			if len(v3.Keys) >= 3 {
				usmKws = append(usmKws, v3.Keys[2])
			} else {
				usmKws = append(usmKws, childNames9414(v3)...)
			}
		}
		return v3Kws, usmKws
	}
	for _, c := range v3.Children {
		if c == nil {
			continue
		}
		v3Kws = append(v3Kws, c.Name())
		if c.Name() != "usm" {
			continue
		}
		if len(c.Keys) >= 2 {
			usmKws = append(usmKws, c.Keys[1])
		} else {
			usmKws = append(usmKws, childNames9414(c)...)
		}
	}
	return v3Kws, usmKws
}

func childNames9414(n *Node) []string {
	var out []string
	for _, c := range n.Children {
		if c != nil {
			out = append(out, c.Name())
		}
	}
	return out
}

func snmpV3InertMessage9414(kw string) string {
	switch kw {
	case "vacm":
		return "snmp v3 vacm: view-based access control (VACM) is accepted but NOT enforced — no per-user or per-group MIB view is applied, so an authenticated SNMPv3 user is not restricted to a view (#9414)"
	case "notify", "notify-filter", "target-address", "target-parameters":
		return fmt.Sprintf("snmp v3 %s: SNMPv3 notification configuration is accepted but NOT implemented — nothing is sent from it; traps go only to `trap-group` targets (#9414)", kw)
	}
	return fmt.Sprintf("snmp v3 %s: accepted but NOT implemented — xpf reads only `snmp v3 usm local-engine user` (#9414)", kw)
}

func snmpUSMInertMessage9414(kw string) string {
	if kw == "remote-engine" {
		return "snmp v3 usm remote-engine: accepted but NOT implemented — users defined under a remote engine are not created; only `usm local-engine user` accounts exist (#9414)"
	}
	return fmt.Sprintf("snmp v3 usm %s: accepted but NOT implemented — xpf reads only `usm local-engine user` (#9414)", kw)
}

// syslogSkippedModifiers9414 records, per destination kind, the modifier
// keywords compileSystem recognized and SKIPPED. It is written from inside the
// skip arms themselves, so the advisory names exactly what those arms drop: a
// modifier later wired into the runtime moves out of its skip arm and stops
// being reported, with no second list to keep in step. The host arm's comment
// had promised "the S-5 advisory path" since #4303; no such path existed.
type syslogSkippedModifiers9414 map[string]map[string]bool

func (s syslogSkippedModifiers9414) note(kind, keyword string) {
	if s[kind] == nil {
		s[kind] = map[string]bool{}
	}
	s[kind][keyword] = true
}

// warnings renders one advisory per (destination kind, keyword), sorted, so two
// hosts carrying the same modifier produce one line. The destination NAME is not
// rendered (keywords only).
func (s syslogSkippedModifiers9414) warnings() []string {
	kinds := make([]string, 0, len(s))
	for kind := range s {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	var out []string
	for _, kind := range kinds {
		kws := make([]string, 0, len(s[kind]))
		for kw := range s[kind] {
			kws = append(kws, kw)
		}
		sort.Strings(kws)
		for _, kw := range kws {
			out = append(out, fmt.Sprintf("system syslog %s %s: accepted but NOT applied — %s (#9414)",
				kind, kw, syslogSkippedModifierEffect9414(kw)))
		}
	}
	return out
}

// syslogSkippedModifierEffect9414 states what the operator does NOT get. Each
// clause is checked against the runtime: host destinations use xpf's own syslog
// client (pkg/logging), file and user destinations an rsyslog drop-in
// (syslogDropinContents), and neither reads any of these keywords.
func syslogSkippedModifierEffect9414(kw string) string {
	switch kw {
	case "match", "match-strings":
		return "no message filter is applied, so every message the facility/severity selectors pick is delivered"
	case "structured-data":
		return "messages are not written in RFC 5424 structured-data format"
	case "explicit-priority":
		return "the priority is not added to logged messages"
	case "log-prefix":
		return "no prefix is prepended to forwarded messages"
	case "facility-override":
		return "the facility stamped on forwarded messages is not overridden"
	case "exclude-hostname":
		return "the local host name is not omitted from forwarded messages"
	case "routing-instance":
		return "the syslog client is not bound to the named routing instance, so messages follow the default routing table"
	case "allow-duplicates":
		return "xpf renders this destination as an rsyslog drop-in and does not set rsyslog's repeated-message reduction, so whether duplicates are collapsed is decided by the host's rsyslog configuration"
	}
	return "xpf does not implement this modifier"
}

// syslogDestinationHoistSchema9414 is a host / file / user destination schema
// WITHOUT its `<facility> <severity>` wildcard, for hoistAndSplitRun8939 only.
//
// hoistAndSplitRun8939 lifts a nested node out of a chain when its head resolves
// as a leaf of the container. Passing the full destination schema was measured
// wrong by the #8939 ratchet: `system syslog file <f> archive [files |
// no-world-readable | size]` moved from walked to `differs`, because the wildcard
// lets ANY word resolve as a destination leaf, so statements inside the archive
// body qualified for lifting. Stripping the wildcard hoists only the NAMED
// modifiers, which is what a chained `allow-duplicates exclude-hostname` needs.
// A facility pair nested after another statement on one line is therefore left
// as authored, exactly as before this change (not hoisted, and not fixed).
// Shallow copy: the children map is shared and only read.
func syslogDestinationHoistSchema9414(kind string) *schemaNode {
	sn := schemaForPath("system", "syslog", kind)
	if sn == nil {
		return nil
	}
	cp := *sn
	cp.wildcard = nil
	return &cp
}
