package config

import (
	"sort"
	"strconv"
	"strings"
)

// fabricZoneStampAdvisory10105 is the #10105 deployment-constraint reminder:
// the zone-encoded fabric stamp is unauthenticated, so the fabric must be a
// private two-peer L2 domain. #18719: it is a constraint REMINDER, not a
// finding about the config, so it is acknowledgeable (the #16023 per-link
// attestation silences it) and change-scoped (see advisory_scope_18719.go).
const fabricZoneStampAdvisory10105 = "chassis cluster fabric zone stamp (#10105): fabric links MUST be a private two-peer L2 domain (direct-attached, dedicated VLAN/bridge, or operator-provided MACsec); shared switching with a live RG split is unsupported because the zone stamp is cloneable by an L2-adjacent host. Acknowledge it per fabric link: set `chassis cluster fabric-interface-private` (and `fabric1-interface-private` for a second fabric) for a direct-attached or dedicated link; set `fabric-interface-authenticated` only when MACsec/802.1X is actually configured, because that leaf makes stamps trusted under require-authenticated-fabric-stamps (#18719)"

// fabricBAFallbackAdvisory13967 is the #13967 reminder that a fabric arrival
// without a validated V2 scope stamp cannot carry the peer's BA classifier.
// #18719: emitted only when some fabric-reachable unit binds a BA
// classifier, i.e. only when there is a peer classification to lose.
const fabricBAFallbackAdvisory13967 = "class-of-service fabric ingress BA fallback (#13967): packets without a validated V2 scope stamp cannot preserve the peer's classifier and use the fabric parent's local binding; if no local classifier or output filter selects a forwarding class, the egress default queue and loss-priority rewrite apply. V2-scoped arrivals preserve the peer BA classifier"

// fabricStampSharedSegmentAdvisories10105 returns the commit-time operator
// reminders for the unauthenticated zone-encoded fabric stamp (#10105) and
// the fabric BA-classifier fallback (#13967).
//
// Software cannot observe whether a fabric NIC is direct-attached, on a
// two-member bridge, or on a shared switch, so the #10105 constraint stays an
// advisory rather than a hard reject. #18719: the reminder no longer fires on
// every commit regardless of config:
//   - #10105 is silenced when EVERY configured fabric link is acknowledged:
//     `fabric-interface-private` (an isolated two-peer segment, #18719) or
//     the #16023 MACsec/802.1X attestation `fabric-interface-authenticated`
//     (and the fabric1-* pair). One unacknowledged link keeps it. Only the
//     authenticated leaf feeds stamp trust; the private leaf never does.
//   - #13967 fires only when a fabric-reachable unit binds a BA classifier
//     (DSCP, IEEE 802.1p or inet-precedence). With no classifier there is no
//     peer classification for the fallback to lose.
//
// Both are additionally change-scoped on the commit path
// (DropUnchangedScopedAdvisories): a commit that changes neither the fabric
// nor (for #13967) the classifier bindings does not repeat them. `commit
// check` reports them whenever their condition holds.
func fabricStampSharedSegmentAdvisories10105(cfg *Config) []string {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	cc := cfg.Chassis.Cluster
	if cc.FabricInterface == "" && cc.Fabric1Interface == "" {
		return nil
	}
	var out []string
	if !fabricLinksAllAcknowledged18719(cc) {
		out = append(out, fabricZoneStampAdvisory10105)
	}
	if len(fabricReachableBAClassifierBindings18719(cfg)) > 0 {
		out = append(out, fabricBAFallbackAdvisory13967)
	}
	return out
}

// fabricLinksAllAcknowledged18719 reports whether every CONFIGURED fabric
// link is acknowledged as a private two-peer segment: by the #18719 private
// leaf, or by the #16023 authentication attestation (an authenticated link is
// private in the sense #10105 needs). The keys are per resolved link
// (FabricInterface / Fabric1Interface), the same mapping the dataplane fabric
// snapshot uses (pkg/dataplane/userspace/fabric.go).
func fabricLinksAllAcknowledged18719(cc *ClusterConfig) bool {
	if cc == nil {
		return false
	}
	configured := false
	if cc.FabricInterface != "" {
		configured = true
		if !cc.FabricLinkPrivate && !cc.FabricLinkAuthenticated {
			return false
		}
	}
	if cc.Fabric1Interface != "" {
		configured = true
		if !cc.Fabric1LinkPrivate && !cc.Fabric1LinkAuthenticated {
			return false
		}
	}
	return configured
}

// fabricReachableBAClassifierBindings18719 lists, sorted, every BA classifier
// binding ("<iface> unit <n> <kind> <name>") on a unit whose traffic can be
// redirected over the fabric.
//
// "Fabric-reachable" is deliberately BROAD: any data interface or unit
// counts, without asking whether a redundancy group could actually split
// across it or whether a zone/policy would ever send its traffic to the
// peer. Under-reporting this reminder is the defect class #18719 exists to
// avoid, and an over-report costs one extra line on a commit that touched
// the binding. Only interfaces that can never carry peer-classified transit
// are excluded. Management, control and fabric interfaces
// (IsManagementIfName: fxp*, em*, fab*), loopbacks and the fabric member
// parents themselves are excluded: a classifier on the fabric parent is the
// local fallback binding, not a peer classification at risk.
func fabricReachableBAClassifierBindings18719(cfg *Config) []string {
	if cfg == nil || cfg.ClassOfService == nil || len(cfg.ClassOfService.Interfaces) == 0 {
		return nil
	}
	fabricParents := fabricMemberNames18719(cfg)
	var out []string
	for name, ci := range cfg.ClassOfService.Interfaces {
		if ci == nil {
			continue
		}
		base, _, _ := strings.Cut(name, ".")
		if IsManagementIfName(base) || IsLoopbackIfName(base) || fabricParents[normalizeFabricMemberName18719(base)] {
			continue
		}
		if ci.Level != nil {
			out = append(out, unitBABindings18719(name, "*", ci.Level)...)
		}
		for unit, u := range ci.Units {
			if u == nil {
				continue
			}
			out = append(out, unitBABindings18719(name, strconv.Itoa(unit), u)...)
		}
	}
	sort.Strings(out)
	return out
}

func unitBABindings18719(iface, unit string, u *CoSInterfaceUnit) []string {
	var out []string
	if u.DSCPClassifier != "" {
		out = append(out, iface+" unit "+unit+" dscp "+u.DSCPClassifier)
	}
	if u.IEEE8021Classifier != "" {
		out = append(out, iface+" unit "+unit+" ieee-802.1 "+u.IEEE8021Classifier)
	}
	if u.INetPrecedenceClassifier != "" {
		out = append(out, iface+" unit "+unit+" inet-precedence "+u.INetPrecedenceClassifier)
	}
	return out
}

// fabricMemberNames18719 is the set of fabric member parents (fab0/fab1
// `fabric-options member-interfaces` and the resolved local member), keyed by
// normalizeFabricMemberName18719.
func fabricMemberNames18719(cfg *Config) map[string]bool {
	out := map[string]bool{}
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return out
	}
	for _, fab := range []string{"fab0", "fab1"} {
		ifc := cfg.Interfaces.Interfaces[fab]
		if ifc == nil {
			continue
		}
		for _, m := range ifc.FabricMembers {
			out[normalizeFabricMemberName18719(m)] = true
		}
		if ifc.LocalFabricMember != "" {
			out[normalizeFabricMemberName18719(ifc.LocalFabricMember)] = true
		}
	}
	return out
}

// normalizeFabricMemberName18719 folds the Junos slash spelling onto the
// Linux dash spelling (ge-0/0/0 == ge-0-0-0) so a member written either way
// matches a CoS interface written the other way.
func normalizeFabricMemberName18719(name string) string {
	base, _, _ := strings.Cut(name, ".")
	return strings.ReplaceAll(base, "/", "-")
}
