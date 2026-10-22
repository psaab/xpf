package config

import "strings"

// Typed static SchemaRefs (#16147, R3).
//
// A SchemaRef is a typed, static handle to one node of setSchema. It
// replaces two stringly spellings that could rot silently:
//
//   - a literal schemaForPath("security", "nat", ...) /
//     resolveSchemaPath9235(...) call, and
//   - a no-arg resolver func (bgpLeafSchema8939 and its kin) whose only
//     job was to walk setSchema by keyword on every call.
//
// Failure mode being removed: schemaForPath returns nil for a typo'd or
// renamed path, and packedBodyChildren(node, nil) returns the raw
// children unchanged — a bad ref turned a packed body into a silent
// drop, the exact fail-open the packed-body machinery exists to
// prevent. A SchemaRef cannot be typo'd at a call site at all (it is an
// identifier, checked by the compiler), and its path is audited.
//
// Sequence (mandatory, from the validated narrowed form):
//
//  1. Audit FIRST: staticSchemaRefs (below) is the registry; the
//     non-panicking auditSchemaRefs enumerates every entry, and
//     TestSchemaRefsResolve in schema_refs_test.go lists every outcome.
//     A dead path the audit surfaces is a silent-drop BUG to file
//     separately, not refactor fallout to fix inside this change.
//  2. Static refs ONLY for no-arg resolvers. Arg-taking resolvers stay
//     functions: gatewayLeafSchema8939(parent),
//     securityNamedLeafSchema8939(parent, kind),
//     cosBindingSchema8939(which), cosClassifiersSchema15064(kind),
//     cosRewriteRulesSchema15064(kind), dhcpPoolSchema15691(isV6),
//     syslogDestinationHoistSchema9414(kind) (which also copies the
//     node), policySchema9792(global), preferredRouteSchema9792(bool).
//     Their literal path prefixes are audited as argResolverPrefixes.
//     (dhcpPoolSchema15691 delegates to refDHCPPoolV4/V6, which are
//     themselves audited as static refs.)
//  3. Init-panic LAST: validateSchemaRefs runs as the last statement
//     of schema.go's init(), after the groups-wildcard wiring. Go runs
//     package init()s in file order, so this does not by itself
//     guarantee every other init() (firewall family `any`,
//     address-book identity registry) has already run — refs resolve
//     lazily and the audit also runs at test time, when all init()s
//     have completed. It panics naming EVERY dead ref at once — never
//     one per run, and never before the audit had its burn-down chance.
//     A genuinely new bad ref therefore fails every binary importing
//     pkg/config at startup instead of silently dropping a packed body.
//
// Groups-wildcard ordering: no SchemaRef in this registry addresses a
// `groups <name> ...` subtree, so no ref captures the groups wildcard
// before schema.go's init wires it to mirror the top-level children.
// The audit runs at test time (all init()s complete) and the init
// check runs as schema.go's init tail; schemaRefs' own initializer
// only records paths (strings), it never walks setSchema, so Go's
// dependency ordering cannot evaluate a ref against a half-built
// tree. If a future ref needs a groups subtree, it must be added
// knowing it resolves against the post-init tree.
//
// #1960 no-brick: the panic fires at program init on a developer-
// introduced bad ref (a code defect caught by every test binary),
// never on operator configuration. Config-driven resolution
// (schemaForPath with data-dependent elements — address family, syslog
// kind, CoS kind, interface placeholder names) keeps its tolerant
// nil-returning behaviour unchanged; nothing on the lenient
// Store.Load / Store.SyncApply path gained a new panic.

// schemaRef is one static handle. path holds KEYWORDS only (instance
// names resolve through the wildcard child, exactly as schemaForPath
// documents); throughWildcard records whether the named (instance)
// body hangs off the final node's wildcard, mirroring the hand-rolled
// `if n.wildcard != nil { return n.wildcard }` steps the old resolver
// funcs open-coded. resolve walks with resolveSchemaChild, so each
// element likewise resolves through an intermediate wildcard slot —
// the same semantics the resolvers being replaced had.
type schemaRef struct {
	path            []string
	throughWildcard bool
	// then, when non-nil, continues from the node path+throughWildcard
	// resolved to. It models resolvers with a wildcard hop in the
	// MIDDLE of the path (policy-statement <name> term <name> then,
	// rpm probe <p> test <t> thresholds), which a single trailing
	// wildcard cannot express.
	then *schemaRef
}

func (r schemaRef) resolve() *schemaNode {
	n := schemaForPath(r.path...)
	if n == nil {
		return nil
	}
	if r.throughWildcard && n.wildcard != nil {
		n = n.wildcard
	}
	if r.then != nil {
		return resolveFrom(n, r.then)
	}
	return n
}

func resolveFrom(n *schemaNode, r *schemaRef) *schemaNode {
	cur := n
	for _, k := range r.path {
		cur = resolveSchemaChild(cur, k)
		if cur == nil {
			return nil
		}
	}
	if r.throughWildcard && cur.wildcard != nil {
		cur = cur.wildcard
	}
	if r.then != nil {
		return resolveFrom(cur, r.then)
	}
	return cur
}

func (r schemaRef) String() string {
	s := strings.Join(r.path, " ")
	if r.throughWildcard {
		s += " <instance>"
	}
	if r.then != nil {
		s += " " + r.then.String()
	}
	return s
}

func chain(first schemaRef, rest ...schemaRef) schemaRef {
	if len(rest) == 0 {
		return first
	}
	next := chain(rest[0], rest[1:]...)
	first.then = &next
	return first
}

// The registry. One entry per static handle; the audit test iterates
// this map, so a ref that is not registered here is not a SchemaRef
// and is not covered. TestSchemaRefsResolve pins that every registered
// ref resolves and the registry is non-vacuous (>= 80 entries).
var staticSchemaRefs = map[string]schemaRef{}

func regRef(name string, r schemaRef) schemaRef {
	staticSchemaRefs[name] = r
	return r
}

func ref(path ...string) schemaRef {
	return schemaRef{path: path}
}

func refInstance(path ...string) schemaRef {
	return schemaRef{path: path, throughWildcard: true}
}

// auditSchemaRefs resolves every registered ref plus every literal
// path prefix an arg-taking resolver walks, non-panicking, and returns
// one problem string per dead entry (empty = all resolve). It runs
// after package init (tests and validateSchemaRefs both call it
// post-init), so it sees the fully wired tree including the groups
// wildcard and the firewall `any` family.
func auditSchemaRefs() []string {
	var problems []string
	for name, r := range staticSchemaRefs {
		if r.resolve() == nil {
			problems = append(problems, "SchemaRef "+name+" ("+r.String()+") does not resolve")
		}
	}
	for _, p := range argResolverPrefixes {
		if schemaForPath(p...) == nil {
			problems = append(problems, "arg-resolver prefix ("+strings.Join(p, " ")+") does not resolve")
		}
	}
	return problems
}

// validateSchemaRefs is the init-panic (step 3, LAST). It collects ALL
// dead refs before panicking so one run names the whole list.
func validateSchemaRefs() {
	if problems := auditSchemaRefs(); len(problems) > 0 {
		panic("config: unresolved static SchemaRefs (#16147):\n  " + strings.Join(problems, "\n  "))
	}
}

// argResolverPrefixes are the literal keyword-path prefixes walked by
// the arg-taking resolvers that stay functions. The dynamic element
// (branch, kind, which, family, server) is chosen from a closed set by
// the caller; the audit pins the static prefix so a schema rename
// under any of them is caught even though no static ref can name the
// full path.
var argResolverPrefixes = [][]string{
	{"security"},                                                                // gatewayLeafSchema8939 / securityNamedLeafSchema8939: + parent.Keys[0] branch, + gateway|<kind>, instance body via wildcard
	{"class-of-service", "interfaces"},                                          // cosBindingSchema8939: + unit <instance>, + classifiers|rewrite-rules
	{"class-of-service", "classifiers"},                                         // cosClassifiersSchema15064: + dscp|ieee-802.1|inet-precedence
	{"class-of-service", "rewrite-rules"},                                       // cosRewriteRulesSchema15064: + inet-precedence|exp|dscp|ieee-802.1
	{"system", "services", "dhcp-local-server", "group", "pool"},                // dhcpPoolSchema15691(false)
	{"system", "services", "dhcpv6-local-server", "group", "pool"},              // dhcpPoolSchema15691(true)
	{"system", "syslog"},                                                        // syslogDestinationHoistSchema9414: + host|file|user|console
	{"security", "policies", "global", "policy"},                                // policySchema9792(true)
	{"security", "policies", "from-zone", "policy"},                             // policySchema9792(false)
	{"services", "ip-monitoring", "policy", "then", "preferred-route", "route"}, // preferredRouteSchema9792(false)
	{"services", "ip-monitoring", "policy", "then", "preferred-route", "routing-instance", "route"}, // preferredRouteSchema9792(true)
}

// Static SchemaRef handles, grouped by domain. Each var is resolved
// lazily on first use after init (the registry records the path at
// var-init, the walk happens in resolve()), so declaration order
// against setSchema and the schema-mutating init()s does not matter.
var (
	// protocols / routing
	refBGP                = regRef("refBGP", ref("protocols", "bgp"))
	refBGPGroup           = regRef("refBGPGroup", refInstance("protocols", "bgp", "group"))
	refBGPMultipath       = regRef("refBGPMultipath", ref("protocols", "bgp", "multipath"))
	refBGPNeighbor        = regRef("refBGPNeighbor", ref("protocols", "bgp", "group", "neighbor"))
	refRIP                = regRef("refRIP", ref("protocols", "rip"))
	refISIS               = regRef("refISIS", ref("protocols", "isis"))
	refISISInterface      = regRef("refISISInterface", refInstance("protocols", "isis", "interface"))
	refOSPF               = regRef("refOSPF", ref("protocols", "ospf"))
	refOSPFArea           = regRef("refOSPFArea", ref("protocols", "ospf", "area"))
	refOSPFAreaInterface  = regRef("refOSPFAreaInterface", ref("protocols", "ospf", "area", "interface"))
	refOSPFAreaType       = regRef("refOSPFAreaType", ref("protocols", "ospf", "area", "area-type"))
	refOSPF3              = regRef("refOSPF3", ref("protocols", "ospf3"))
	refOSPF3Area          = regRef("refOSPF3Area", ref("protocols", "ospf3", "area"))
	refOSPF3AreaInterface = regRef("refOSPF3AreaInterface", ref("protocols", "ospf3", "area", "interface"))
	refOSPF3AreaType      = regRef("refOSPF3AreaType", ref("protocols", "ospf3", "area", "area-type"))
	refLLDP               = regRef("refLLDP", ref("protocols", "lldp"))
	refRAInterface        = regRef("refRAInterface", refInstance("protocols", "router-advertisement", "interface"))
	refRAPrefix           = regRef("refRAPrefix", ref("protocols", "router-advertisement", "interface", "prefix"))

	// policy-options / routing-options
	refPolicyStatement         = regRef("refPolicyStatement", ref("policy-options", "policy-statement"))
	refPolicyTerm              = regRef("refPolicyTerm", ref("policy-options", "policy-statement", "term"))
	refPolicyTermFrom          = regRef("refPolicyTermFrom", ref("policy-options", "policy-statement", "term", "from"))
	refInterfaceRoutesRibGroup = regRef("refInterfaceRoutesRibGroup", ref("routing-options", "interface-routes", "rib-group"))
	refGenerateRoute           = regRef("refGenerateRoute", refInstance("routing-options", "generate", "route"))
	refStaticQualifiedNextHop  = regRef("refStaticQualifiedNextHop", ref("routing-options", "static", "route", "qualified-next-hop"))
	refRibGroupsInstance       = regRef("refRibGroupsInstance", refInstance("routing-options", "rib-groups"))

	// security
	refSecurityFlow                 = regRef("refSecurityFlow", ref("security", "flow"))
	refFlowTCPSession               = regRef("refFlowTCPSession", ref("security", "flow", "tcp-session"))
	refFlowAging                    = regRef("refFlowAging", ref("security", "flow", "aging"))
	refFlowTraceoptionsPacketFilter = regRef("refFlowTraceoptionsPacketFilter", ref("security", "flow", "traceoptions", "packet-filter"))
	refSecurityLog                  = regRef("refSecurityLog", ref("security", "log"))
	refSecurityLogProfile           = regRef("refSecurityLogProfile", ref("security", "log", "profile"))
	refSecurityLogStreamInstance    = regRef("refSecurityLogStreamInstance", refInstance("security", "log", "stream"))
	refScreenIdsOption              = regRef("refScreenIdsOption", ref("security", "screen", "ids-option"))
	refScreenSynFlood               = regRef("refScreenSynFlood", ref("security", "screen", "ids-option", "tcp", "syn-flood"))
	refScreenLimitSession           = regRef("refScreenLimitSession", ref("security", "screen", "ids-option", "limit-session"))
	refSecurityZone                 = regRef("refSecurityZone", ref("security", "zones", "security-zone"))
	refFunctionalZoneMgmt           = regRef("refFunctionalZoneMgmt", ref("security", "zones", "functional-zone", "management"))
	refSecurityPolicies             = regRef("refSecurityPolicies", ref("security", "policies"))
	refNATDestPool                  = regRef("refNATDestPool", ref("security", "nat", "destination", "pool"))
	refNATDestRule                  = regRef("refNATDestRule", ref("security", "nat", "destination", "rule-set", "rule"))
	refNATSourceRule                = regRef("refNATSourceRule", ref("security", "nat", "source", "rule-set", "rule"))
	refNATStaticRule                = regRef("refNATStaticRule", ref("security", "nat", "static", "rule-set", "rule"))
	refNATSourcePoolInstance        = regRef("refNATSourcePoolInstance", refInstance("security", "nat", "source", "pool"))
	refNATPersistentNAT             = regRef("refNATPersistentNAT", ref("security", "nat", "source", "pool", "persistent-nat"))
	refNATSourcePoolUtilAlarm       = regRef("refNATSourcePoolUtilAlarm", ref("security", "nat", "source", "pool-utilization-alarm"))
	refNAT64RuleSet                 = regRef("refNAT64RuleSet", ref("security", "nat", "nat64", "rule-set"))
	refDynamicAddressFeedServer     = regRef("refDynamicAddressFeedServer", ref("security", "dynamic-address", "feed-server"))
	refIPsecVPNInstance             = regRef("refIPsecVPNInstance", refInstance("security", "ipsec", "vpn"))

	// system / services / snmp / schedulers
	refSystem                = regRef("refSystem", ref("system"))
	refSystemArchivalConfig  = regRef("refSystemArchivalConfig", ref("system", "archival", "configuration"))
	refSystemNTP             = regRef("refSystemNTP", ref("system", "ntp"))
	refNTPServer             = regRef("refNTPServer", ref("system", "ntp", "server"))
	refSystemInternetOptions = regRef("refSystemInternetOptions", ref("system", "internet-options"))
	refSyslog                = regRef("refSyslog", ref("system", "syslog"))
	refSyslogHost            = regRef("refSyslogHost", ref("system", "syslog", "host"))
	refSyslogFile            = regRef("refSyslogFile", ref("system", "syslog", "file"))
	refSyslogUser            = regRef("refSyslogUser", ref("system", "syslog", "user"))
	refSyslogConsole         = regRef("refSyslogConsole", ref("system", "syslog", "console"))
	refSystemServices        = regRef("refSystemServices", ref("system", "services"))
	refSystemServicesSSH     = regRef("refSystemServicesSSH", ref("system", "services", "ssh"))
	refSystemServicesNetconf = regRef("refSystemServicesNetconf", ref("system", "services", "netconf"))
	refWebMgmtHTTPS          = regRef("refWebMgmtHTTPS", ref("system", "services", "web-management", "https"))
	refDHCPStaticBinding     = regRef("refDHCPStaticBinding", ref("system", "services", "dhcp-local-server", "group", "pool", "static-binding"))
	refLoginUserInstance     = regRef("refLoginUserInstance", refInstance("system", "login", "user"))
	refLoginClassInstance    = regRef("refLoginClassInstance", refInstance("system", "login", "class"))
	refSystemDataplane       = regRef("refSystemDataplane", ref("system", "dataplane"))
	refDataplaneCoalescence  = regRef("refDataplaneCoalescence", ref("system", "dataplane", "coalescence"))
	refScheduler             = regRef("refScheduler", ref("schedulers", "scheduler"))
	refSNMPTrapGroup         = regRef("refSNMPTrapGroup", ref("snmp", "trap-group"))
	refSNMPv3                = regRef("refSNMPv3", ref("snmp", "v3"))
	refSNMPv3USM             = regRef("refSNMPv3USM", ref("snmp", "v3", "usm"))
	refSNMPv3USMLocalEngine  = regRef("refSNMPv3USMLocalEngine", ref("snmp", "v3", "usm", "local-engine"))
	refSNMPCommunity         = regRef("refSNMPCommunity", ref("snmp", "community"))
	// rpm probe/test needs two wildcard hops; kept as resolver func (rpmProbeTestSchema8939).

	// firewall / class-of-service / forwarding / interfaces / chassis
	refFirewallPolicerIfExceeding       = regRef("refFirewallPolicerIfExceeding", ref("firewall", "policer", "if-exceeding"))
	refFirewallPolicerThen              = regRef("refFirewallPolicerThen", ref("firewall", "policer", "then"))
	refThreeColorPolicerThen            = regRef("refThreeColorPolicerThen", ref("firewall", "three-color-policer", "then"))
	refThreeColorSingleRate             = regRef("refThreeColorSingleRate", ref("firewall", "three-color-policer", "single-rate"))
	refThreeColorTwoRate                = regRef("refThreeColorTwoRate", ref("firewall", "three-color-policer", "two-rate"))
	refCoSSchedulers                    = regRef("refCoSSchedulers", ref("class-of-service", "schedulers"))
	refCoSTrafficControlProfiles        = regRef("refCoSTrafficControlProfiles", ref("class-of-service", "traffic-control-profiles"))
	refCoSTCPInstance                   = regRef("refCoSTCPInstance", refInstance("class-of-service", "traffic-control-profiles"))
	refCoSSchedulerMaps                 = regRef("refCoSSchedulerMaps", ref("class-of-service", "scheduler-maps"))
	refCoSSchedulerMapsFC               = regRef("refCoSSchedulerMapsFC", ref("class-of-service", "scheduler-maps", "forwarding-class"))
	refCoSInterfaces                    = regRef("refCoSInterfaces", ref("class-of-service", "interfaces"))
	refCoSInterfacesUnit                = regRef("refCoSInterfacesUnit", ref("class-of-service", "interfaces", "unit"))
	refSamplingFlowServer               = regRef("refSamplingFlowServer", ref("forwarding-options", "sampling", "instance", "family", "inet", "output", "flow-server"))
	refIPFIXTemplate                    = regRef("refIPFIXTemplate", ref("services", "flow-monitoring", "version-ipfix", "template"))
	refVersion9Template                 = regRef("refVersion9Template", ref("services", "flow-monitoring", "version9", "template"))
	refInterfaces                       = regRef("refInterfaces", ref("interfaces"))
	refInterfaceInstance                = regRef("refInterfaceInstance", ref("interfaces", "xpfname"))
	refInterfaceUnit                    = regRef("refInterfaceUnit", ref("interfaces", "x", "unit"))
	refChassisCluster                   = regRef("refChassisCluster", ref("chassis", "cluster"))
	refBridgeDomainInstance             = regRef("refBridgeDomainInstance", ref("bridge-domains", "xpfname"))
	refRoutingInstanceInstance          = regRef("refRoutingInstanceInstance", ref("routing-instances", "xpfname"))
	refPolicyStatementInstanceThen      = regRef("refPolicyStatementInstanceThen", chain(refInstance("policy-options", "policy-statement"), ref("then")))
	refPolicyTermThen                   = regRef("refPolicyTermThen", chain(refInstance("policy-options", "policy-statement"), refInstance("term"), ref("then")))
	refPolicyTermChain                  = regRef("refPolicyTermChain", chain(refInstance("policy-options", "policy-statement"), ref("term")))
	refFilterThen                       = regRef("refFilterThen", chain(ref("firewall", "family", "inet", "filter"), refInstance("term"), ref("then")))
	refSchedulerDaily                   = regRef("refSchedulerDaily", chain(refInstance("schedulers", "scheduler"), ref("daily")))
	refDynamicAddressProfile            = regRef("refDynamicAddressProfile", chain(refInstance("security", "dynamic-address", "address-name"), ref("profile")))
	refDHCPrelayOverrides               = regRef("refDHCPrelayOverrides", chain(refInstance("forwarding-options", "dhcp-relay", "group"), ref("overrides")))
	refIPsecTrafficSelector             = regRef("refIPsecTrafficSelector", chain(refInstance("security", "ipsec", "vpn"), refInstance("traffic-selector")))
	refRPMProbeTest                     = regRef("refRPMProbeTest", chain(refInstance("services", "rpm", "probe"), refInstance("test")))
	refRPMThresholds                    = regRef("refRPMThresholds", chain(refInstance("services", "rpm", "probe"), refInstance("test"), ref("thresholds")))
	refSamplingOutput                   = regRef("refSamplingOutput", chain(refInstance("forwarding-options", "sampling", "instance"), ref("family", "inet", "output")))
	refTunnel                           = regRef("refTunnel", schemaRef{path: []string{"interfaces"}, throughWildcard: true, then: &schemaRef{path: []string{"tunnel"}}})
	refSNMPRoutingInstance              = regRef("refSNMPRoutingInstance", ref("snmp", "community", "routing-instance"))
	refSystemDataplaneSharedUMEM        = regRef("refSystemDataplaneSharedUMEM", ref("system", "dataplane", "shared-umem"))
	refSecurityLogTransport             = regRef("refSecurityLogTransport", chain(refInstance("security", "log", "stream"), ref("transport")))
	refDHCPPoolV4                       = regRef("refDHCPPoolV4", ref("system", "services", "dhcp-local-server", "group", "pool"))
	refGigetherOptions                  = regRef("refGigetherOptions", ref("interfaces", "xpfname", "gigether-options"))
	refAggregatedEtherOptions           = regRef("refAggregatedEtherOptions", ref("interfaces", "xpfname", "aggregated-ether-options"))
	refRedundantEtherOptions            = regRef("refRedundantEtherOptions", ref("interfaces", "xpfname", "redundant-ether-options"))
	refTunnelWireguard                  = regRef("refTunnelWireguard", ref("interfaces", "xpfname", "tunnel", "wireguard"))
	refTunnelWireguardPeer              = regRef("refTunnelWireguardPeer", ref("interfaces", "xpfname", "tunnel", "wireguard", "peer"))
	refDHCPPoolV6                       = regRef("refDHCPPoolV6", ref("system", "services", "dhcpv6-local-server", "group", "pool"))
	refDHCPServer                       = regRef("refDHCPServer", ref("system", "services", "dhcp-local-server"))
	refSNMPv3USMUser                    = regRef("refSNMPv3USMUser", ref("snmp", "v3", "usm", "local-engine", "user"))
	refCoSFairnessQueue                 = regRef("refCoSFairnessQueue", ref("class-of-service", "fairness", "rss-expectation", "interface", "queue"))
	refFirewallFlexMatch                = regRef("refFirewallFlexMatch", ref("firewall", "family", "inet", "filter", "term", "from", "flexible-match-range"))
	refFirewallFlexMatchRange           = regRef("refFirewallFlexMatchRange", ref("firewall", "family", "inet", "filter", "term", "from", "flexible-match-range", "range"))
	refRAInterfaceRaw                   = regRef("refRAInterfaceRaw", ref("protocols", "router-advertisement", "interface"))
	refOSPFAreaInterfaceAuth            = regRef("refOSPFAreaInterfaceAuth", ref("protocols", "ospf", "area", "interface", "authentication"))
	refInterfaceUnitFamilyInetDHCP      = regRef("refInterfaceUnitFamilyInetDHCP", ref("interfaces", "x", "unit", "family", "inet", "dhcp"))
	refInterfaceUnitFamilyInet6DHCPv6   = regRef("refInterfaceUnitFamilyInet6DHCPv6", ref("interfaces", "x", "unit", "family", "inet6", "dhcpv6-client"))
	refInterfaceUnitFamilyInet6DHCPv6PD = regRef("refInterfaceUnitFamilyInet6DHCPv6PD", ref("interfaces", "x", "unit", "family", "inet6", "dhcpv6-client", "prefix-delegating"))
	refInterfaceUnitFamilyInet6DHCPv6RA = regRef("refInterfaceUnitFamilyInet6DHCPv6RA", ref("interfaces", "x", "unit", "family", "inet6", "dhcpv6-client", "update-router-advertisement"))
	refInterfaceInstanceRaw             = regRef("refInterfaceInstanceRaw", ref("interfaces", "x"))
	refFirewallFamilyInetFilterTerm     = regRef("refFirewallFamilyInetFilterTerm", ref("firewall", "family", "inet", "filter", "term"))
	refFirewallFamilyInetFilterTermFrom = regRef("refFirewallFamilyInetFilterTermFrom", ref("firewall", "family", "inet", "filter", "term", "from"))
)
