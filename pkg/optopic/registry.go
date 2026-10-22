package optopic

import "github.com/psaab/xpf/pkg/config"

// The registry data. Split by kind so a reader pricing a topic never wades
// through verbs (and vice versa). Ordering inside the literals is lexical
// for review diffs; lookups do not depend on it (build sorts prefix rules
// longest-first and the exact map is unordered).
//
// Provenance, per column:
//   - Key: the dispatcher's own spelling in pkg/grpcapi (server_show.go's
//     ordered prefix arms + `switch req.Topic`, including the default-branch
//     "log:"/"monitor-security-flow" topics, and
//     server_diag_system_action.go's `switch req.Action`). The grpcapi
//     census tests re-derive this set by an independent AST scrape of those
//     handler files and fail on any drift in either direction.
//   - Permission: the price pkg/cli charges the command that emits the
//     topic/verb (show->PermView, clear->PermClear, request/test->
//     PermControl, configure-decision->PermConfig, destructive
//     maintenance->PermMaint). Formerly showTextViewTopics /
//     showTextElevatedTopics / systemActionPermissions in pkg/grpcapi.
//   - Command: the canonical argument-free command, formerly
//     pkg/cmdtree's showTextTopicCommand and pkg/authz's
//     SystemActionVerbCommand. Canonicality is still machine-checked in
//     pkg/grpcapi (every value must resolve against the operational tree).
//   - FabricAllowed: the fabric listener's per-topic/verb admission,
//     formerly fabricAllowedShowTextTopics and the exact-verb arm of
//     isFabricSafeSystemAction in pkg/grpcapi. Only "chassis-forwarding"
//     (the one topic either peer-proxy call site sends) and
//     "clear-persistent-nat" (the exact peer-coordinated verb) are true.
//     The cluster-failover prefix grammar forms are fabric-admitted too,
//     but they are a parsed family with no fixed spelling, so they carry
//     no entry here — the fabric gate keeps validating them through
//     pkg/clusterfailover, and the census names them separately.

var showTextEntries = []Entry{
	{Key: "address-book", Permission: config.PermView, Command: "show security address-book", FabricAllowed: false},
	{Key: "alarms", Permission: config.PermView, Command: "show system alarms", FabricAllowed: false},
	{Key: "alg", Permission: config.PermView, Command: "show security alg", FabricAllowed: false},
	{Key: "application-identification-status", Permission: config.PermView, Command: "show services application-identification status", FabricAllowed: false},
	{Key: "applications", Permission: config.PermView, Command: "show security applications", FabricAllowed: false},
	{Key: "applications:", Permission: config.PermView, Command: "show security applications", FabricAllowed: false},
	{Key: "backup-router", Permission: config.PermView, Command: "show system backup-router", FabricAllowed: false},
	{Key: "bfd-peers", Permission: config.PermView, Command: "show protocols bfd peers", FabricAllowed: false},
	{Key: "bootstrap-import", Permission: config.PermView, Command: "show system bootstrap-import", FabricAllowed: false},
	{Key: "buffers", Permission: config.PermView, Command: "show system buffers", FabricAllowed: false},
	{Key: "buffers-detail", Permission: config.PermView, Command: "show system buffers detail", FabricAllowed: false},
	{Key: "chassis", Permission: config.PermView, Command: "show chassis", FabricAllowed: false},
	{Key: "chassis-cluster", Permission: config.PermView, Command: "show chassis cluster", FabricAllowed: false},
	{Key: "chassis-cluster-control-plane-statistics", Permission: config.PermView, Command: "show chassis cluster control-plane statistics", FabricAllowed: false},
	{Key: "chassis-cluster-data-plane-fairness", Permission: config.PermView, Command: "show chassis cluster data-plane fairness", FabricAllowed: false},
	{Key: "chassis-cluster-data-plane-flows", Permission: config.PermView, Command: "show chassis cluster data-plane flows", FabricAllowed: false},
	{Key: "chassis-cluster-data-plane-interfaces", Permission: config.PermView, Command: "show chassis cluster data-plane interfaces", FabricAllowed: false},
	{Key: "chassis-cluster-data-plane-statistics", Permission: config.PermView, Command: "show chassis cluster data-plane statistics", FabricAllowed: false},
	{Key: "chassis-cluster-fabric-statistics", Permission: config.PermView, Command: "show chassis cluster fabric statistics", FabricAllowed: false},
	{Key: "chassis-cluster-fence-status", Permission: config.PermView, Command: "show chassis cluster fence-status", FabricAllowed: false},
	{Key: "chassis-cluster-information", Permission: config.PermView, Command: "show chassis cluster information", FabricAllowed: false},
	{Key: "chassis-cluster-interfaces", Permission: config.PermView, Command: "show chassis cluster interfaces", FabricAllowed: false},
	{Key: "chassis-cluster-ip-monitoring-status", Permission: config.PermView, Command: "show chassis cluster ip-monitoring status", FabricAllowed: false},
	{Key: "chassis-cluster-statistics", Permission: config.PermView, Command: "show chassis cluster statistics", FabricAllowed: false},
	{Key: "chassis-cluster-status", Permission: config.PermView, Command: "show chassis cluster status", FabricAllowed: false},
	{Key: "chassis-device-map", Permission: config.PermView, Command: "show chassis device-map", FabricAllowed: false},
	{Key: "chassis-device-map-candidates", Permission: config.PermView, Command: "show chassis device-map candidates", FabricAllowed: false},
	{Key: "chassis-environment", Permission: config.PermView, Command: "show chassis environment", FabricAllowed: false},
	{Key: "chassis-forwarding", Permission: config.PermView, Command: "show chassis forwarding", FabricAllowed: true},
	{Key: "chassis-hardware", Permission: config.PermView, Command: "show chassis hardware", FabricAllowed: false},
	{Key: "class-of-service", Permission: config.PermView, Command: "show class-of-service interface", FabricAllowed: false},
	{Key: "class-of-service:", Permission: config.PermView, Command: "show class-of-service interface", FabricAllowed: false},
	{Key: "commit-history", Permission: config.PermView, Command: "show system commit history", FabricAllowed: false},
	{Key: "core-dumps", Permission: config.PermView, Command: "show system core-dumps", FabricAllowed: false},
	{Key: "cos-classifier", Permission: config.PermView, Command: "show class-of-service classifier", FabricAllowed: false},
	{Key: "cos-classifier:", Permission: config.PermView, Command: "show class-of-service classifier", FabricAllowed: false},
	{Key: "cos-forwarding-class", Permission: config.PermView, Command: "show class-of-service forwarding-class", FabricAllowed: false},
	{Key: "cos-rewrite-rule", Permission: config.PermView, Command: "show class-of-service rewrite-rule", FabricAllowed: false},
	{Key: "cos-rewrite-rule:", Permission: config.PermView, Command: "show class-of-service rewrite-rule", FabricAllowed: false},
	{Key: "cos-scheduler-map", Permission: config.PermView, Command: "show class-of-service scheduler-map", FabricAllowed: false},
	{Key: "cos-scheduler-map:", Permission: config.PermView, Command: "show class-of-service scheduler-map", FabricAllowed: false},
	{Key: "dhcp-relay", Permission: config.PermView, Command: "show dhcp-relay", FabricAllowed: false},
	{Key: "dhcp-server", Permission: config.PermView, Command: "show dhcp-server", FabricAllowed: false},
	{Key: "dhcp-server-detail", Permission: config.PermView, Command: "show dhcp-server detail", FabricAllowed: false},
	{Key: "dhcp-server-dynamic-dns", Permission: config.PermView, Command: "show dhcp-server dynamic-dns", FabricAllowed: false},
	{Key: "dhcp-server-dynamic-dns-detail", Permission: config.PermView, Command: "show dhcp-server dynamic-dns detail", FabricAllowed: false},
	{Key: "dynamic-address", Permission: config.PermView, Command: "show security dynamic-address", FabricAllowed: false},
	{Key: "event-options", Permission: config.PermView, Command: "show event-options", FabricAllowed: false},
	{Key: "firewall", Permission: config.PermView, Command: "show firewall", FabricAllowed: false},
	{Key: "firewall-effective", Permission: config.PermView, Command: "show firewall effective", FabricAllowed: false},
	{Key: "firewall-effective-filter:", Permission: config.PermView, Command: "show firewall filter", FabricAllowed: false},
	{Key: "firewall-effective:", Permission: config.PermView, Command: "show firewall effective", FabricAllowed: false},
	{Key: "firewall-filter:", Permission: config.PermView, Command: "show firewall filter", FabricAllowed: false},
	{Key: "flow-monitoring", Permission: config.PermView, Command: "show flow-monitoring", FabricAllowed: false},
	{Key: "flow-monitoring-statistics", Permission: config.PermView, Command: "show flow-monitoring statistics", FabricAllowed: false},
	{Key: "flow-statistics", Permission: config.PermView, Command: "show security flow statistics", FabricAllowed: false},
	{Key: "flow-timeouts", Permission: config.PermView, Command: "show security flow", FabricAllowed: false},
	{Key: "flow-traceoptions", Permission: config.PermView, Command: "show security flow traceoptions", FabricAllowed: false},
	{Key: "forwarding-options", Permission: config.PermView, Command: "show forwarding-options", FabricAllowed: false},
	{Key: "forwarding-options-port-mirroring", Permission: config.PermView, Command: "show forwarding-options port-mirroring", FabricAllowed: false},
	{Key: "ike", Permission: config.PermView, Command: "show security ike", FabricAllowed: false},
	{Key: "interfaces-detail", Permission: config.PermView, Command: "show interfaces detail", FabricAllowed: false},
	{Key: "interfaces-extensive", Permission: config.PermView, Command: "show interfaces extensive", FabricAllowed: false},
	{Key: "interfaces-queue", Permission: config.PermView, Command: "show interfaces queue", FabricAllowed: false},
	{Key: "interfaces-queue:", Permission: config.PermView, Command: "show interfaces queue", FabricAllowed: false},
	{Key: "interfaces-statistics", Permission: config.PermView, Command: "show interfaces statistics", FabricAllowed: false},
	{Key: "internet-options", Permission: config.PermView, Command: "show system internet-options", FabricAllowed: false},
	{Key: "ipsec-statistics", Permission: config.PermView, Command: "show security ipsec statistics", FabricAllowed: false},
	{Key: "ipv6-router-advertisement", Permission: config.PermView, Command: "show ipv6 router-advertisement", FabricAllowed: false},
	{Key: "kernel-upgrade", Permission: config.PermView, Command: "show system kernel-upgrade", FabricAllowed: false},
	{Key: "license", Permission: config.PermView, Command: "show system license", FabricAllowed: false},
	{Key: "lldp", Permission: config.PermView, Command: "show lldp", FabricAllowed: false},
	{Key: "lldp-neighbors", Permission: config.PermView, Command: "show lldp neighbors", FabricAllowed: false},
	{Key: "log", Permission: config.PermView, Command: "show log", FabricAllowed: false},
	{Key: "log:", Permission: config.PermView, Command: "show log", FabricAllowed: false},
	{Key: "login", Permission: config.PermView, Command: "show system login", FabricAllowed: false},
	{Key: "monitor-security-flow", Permission: config.PermView, Command: "show monitor security flow", FabricAllowed: false},
	{Key: "nat-dest-rule-detail", Permission: config.PermView, Command: "show security nat destination rule detail", FabricAllowed: false},
	{Key: "nat-nptv6", Permission: config.PermView, Command: "show security nat nptv6", FabricAllowed: false},
	{Key: "nat-source-rule-detail", Permission: config.PermView, Command: "show security nat source rule detail", FabricAllowed: false},
	{Key: "nat-static", Permission: config.PermView, Command: "show security nat static", FabricAllowed: false},
	{Key: "nat-static-rule", Permission: config.PermView, Command: "show security nat static rule", FabricAllowed: false},
	{Key: "nat-static-rule-detail", Permission: config.PermView, Command: "show security nat static rule detail", FabricAllowed: false},
	{Key: "nat64", Permission: config.PermView, Command: "show security nat nat64", FabricAllowed: false},
	{Key: "ntp", Permission: config.PermView, Command: "show system ntp", FabricAllowed: false},
	{Key: "persistent-nat", Permission: config.PermView, Command: "show security nat source persistent-nat-table", FabricAllowed: false},
	{Key: "persistent-nat-detail", Permission: config.PermView, Command: "show security nat source persistent-nat-table detail", FabricAllowed: false},
	{Key: "policies-check", Permission: config.PermControl, Command: "request security policies check", FabricAllowed: false},
	{Key: "policies-detail", Permission: config.PermView, Command: "show security policies detail", FabricAllowed: false},
	{Key: "policies-hit-count", Permission: config.PermView, Command: "show security policies hit-count", FabricAllowed: false},
	{Key: "policy-options", Permission: config.PermView, Command: "show policy-options", FabricAllowed: false},
	{Key: "root-authentication", Permission: config.PermView, Command: "show system root-authentication", FabricAllowed: false},
	{Key: "route-all", Permission: config.PermView, Command: "show route", FabricAllowed: false},
	{Key: "route-detail", Permission: config.PermView, Command: "show route detail", FabricAllowed: false},
	{Key: "route-fib", Permission: config.PermView, Command: "show route fib", FabricAllowed: false},
	{Key: "route-instance", Permission: config.PermView, Command: "show route instance", FabricAllowed: false},
	{Key: "route-map", Permission: config.PermView, Command: "show route-map", FabricAllowed: false},
	{Key: "route-prefix:", Permission: config.PermView, Command: "show route", FabricAllowed: false},
	{Key: "route-protocol:", Permission: config.PermView, Command: "show route protocol", FabricAllowed: false},
	{Key: "route-summary", Permission: config.PermView, Command: "show route summary", FabricAllowed: false},
	{Key: "route-table:", Permission: config.PermView, Command: "show route table", FabricAllowed: false},
	{Key: "route-terse", Permission: config.PermView, Command: "show route terse", FabricAllowed: false},
	{Key: "routing-instances", Permission: config.PermView, Command: "show routing-instances", FabricAllowed: false},
	{Key: "routing-instances-detail", Permission: config.PermView, Command: "show routing-instances detail", FabricAllowed: false},
	{Key: "routing-options", Permission: config.PermView, Command: "show routing-options", FabricAllowed: false},
	{Key: "rpm", Permission: config.PermView, Command: "show services rpm", FabricAllowed: false},
	{Key: "schedulers", Permission: config.PermView, Command: "show schedulers", FabricAllowed: false},
	{Key: "screen", Permission: config.PermView, Command: "show security screen", FabricAllowed: false},
	{Key: "screen-ids-option-detail:", Permission: config.PermView, Command: "show security screen ids-option", FabricAllowed: false},
	{Key: "screen-ids-option:", Permission: config.PermView, Command: "show security screen ids-option", FabricAllowed: false},
	{Key: "screen-statistics-all", Permission: config.PermView, Command: "show security screen statistics", FabricAllowed: false},
	{Key: "screen-statistics:", Permission: config.PermView, Command: "show security screen statistics zone", FabricAllowed: false},
	{Key: "security-alarms", Permission: config.PermView, Command: "show security alarms", FabricAllowed: false},
	{Key: "security-alarms-detail", Permission: config.PermView, Command: "show security alarms detail", FabricAllowed: false},
	{Key: "security-log", Permission: config.PermView, Command: "show security log", FabricAllowed: false},
	{Key: "services-dynamic-dns", Permission: config.PermView, Command: "show services dynamic-dns", FabricAllowed: false},
	{Key: "services-dynamic-dns-detail", Permission: config.PermView, Command: "show services dynamic-dns detail", FabricAllowed: false},
	{Key: "services-ip-monitoring-status", Permission: config.PermView, Command: "show services ip-monitoring status", FabricAllowed: false},
	{Key: "sessions-top:bytes", Permission: config.PermView, Command: "show security flow session sort-by bytes", FabricAllowed: false},
	{Key: "sessions-top:packets", Permission: config.PermView, Command: "show security flow session sort-by packets", FabricAllowed: false},
	{Key: "snmp", Permission: config.PermView, Command: "show snmp", FabricAllowed: false},
	{Key: "snmp-v3", Permission: config.PermView, Command: "show snmp v3", FabricAllowed: false},
	{Key: "storage", Permission: config.PermView, Command: "show system storage", FabricAllowed: false},
	{Key: "system-services", Permission: config.PermView, Command: "show system services", FabricAllowed: false},
	{Key: "system-syslog", Permission: config.PermView, Command: "show system syslog", FabricAllowed: false},
	{Key: "task", Permission: config.PermView, Command: "show task", FabricAllowed: false},
	{Key: "test-policy:", Permission: config.PermControl, Command: "test policy", FabricAllowed: false},
	{Key: "test-routing:", Permission: config.PermControl, Command: "test routing", FabricAllowed: false},
	{Key: "test-zone:", Permission: config.PermControl, Command: "test security-zone", FabricAllowed: false},
	{Key: "tunnels", Permission: config.PermView, Command: "show interfaces tunnel", FabricAllowed: false},
	{Key: "version", Permission: config.PermView, Command: "show version", FabricAllowed: false},
	{Key: "vlans", Permission: config.PermView, Command: "show vlans", FabricAllowed: false},
	{Key: "wireguard", Permission: config.PermView, Command: "show security wireguard", FabricAllowed: false},
	{Key: "wireguard-detail", Permission: config.PermView, Command: "show security wireguard detail", FabricAllowed: false},
	{Key: "wireguard-public-key", Permission: config.PermView, Command: "show security wireguard public-key", FabricAllowed: false},
	{Key: "zones-detail", Permission: config.PermView, Command: "show security zones detail", FabricAllowed: false},
}

var systemActionEntries = []Entry{
	{Key: "bgp-clear", Permission: config.PermControl, Command: "request protocols bgp clear", FabricAllowed: false},
	{Key: "clear-arp", Permission: config.PermClear, Command: "clear arp", FabricAllowed: false},
	{Key: "clear-config-lock", Permission: config.PermClear, Command: "clear system config-lock", FabricAllowed: false},
	{Key: "clear-firewall-counters", Permission: config.PermClear, Command: "clear firewall all", FabricAllowed: false},
	{Key: "clear-interfaces-statistics", Permission: config.PermClear, Command: "clear interfaces statistics", FabricAllowed: false},
	{Key: "clear-ipv6-neighbors", Permission: config.PermClear, Command: "clear ipv6 neighbors", FabricAllowed: false},
	{Key: "clear-nat-counters", Permission: config.PermClear, Command: "clear security nat statistics", FabricAllowed: false},
	{Key: "clear-persistent-nat", Permission: config.PermClear, Command: "clear security nat source persistent-nat-table", FabricAllowed: true},
	{Key: "clear-policy-counters", Permission: config.PermClear, Command: "clear security policies hit-count", FabricAllowed: false},
	{Key: "cluster-rejoin", Permission: config.PermMaint, Command: "request chassis cluster failover", FabricAllowed: false},
	{Key: "dhcp-renew", Permission: config.PermControl, Command: "request dhcp renew", FabricAllowed: false},
	{Key: "dynamic-address-shrink-ack", Permission: config.PermConfig, Command: "request security dynamic-address acknowledge-shrink", FabricAllowed: false},
	{Key: "dynamic-dns-check", Permission: config.PermControl, Command: "request system dynamic-dns check", FabricAllowed: false},
	{Key: "dynamic-dns-update", Permission: config.PermControl, Command: "request system dynamic-dns update", FabricAllowed: false},
	{Key: "halt", Permission: config.PermMaint, Command: "request system halt", FabricAllowed: false},
	{Key: "in-service-upgrade", Permission: config.PermMaint, Command: "request system software in-service-upgrade", FabricAllowed: false},
	{Key: "ipsec-sa-clear", Permission: config.PermControl, Command: "request security ipsec sa clear", FabricAllowed: false},
	{Key: "ospf-clear", Permission: config.PermControl, Command: "request protocols ospf clear", FabricAllowed: false},
	{Key: "power-off", Permission: config.PermMaint, Command: "request system power-off", FabricAllowed: false},
	{Key: "reboot", Permission: config.PermMaint, Command: "request system reboot", FabricAllowed: false},
	{Key: "rescue-delete", Permission: config.PermControl, Command: "request system configuration rescue delete", FabricAllowed: false},
	{Key: "rescue-save", Permission: config.PermControl, Command: "request system configuration rescue save", FabricAllowed: false},
	{Key: "zeroize", Permission: config.PermMaint, Command: "request system zeroize", FabricAllowed: false},
}

// Prefix-priced SystemAction families: verbs the handler resolves in its
// default / pre-switch branches by prefix, so they have no fixed spelling
// to key an Entry. They are metadata too and live here so every price a
// SystemAction string can be charged is named in this package:
//
//   - "userspace-attest:arm:" costs PermAll: it re-arms the D11 proof-of-
//     life authority and its handler requires root or the configured
//     super-user class. Pricing it at the PermMaint prefix default would
//     let a maintenance-only class reach a handler that must deny it.
//   - The cluster-failover grammar ("cluster-failover:", "cluster-failover-
//     data:", "cluster-failover-reset:") and the userspace dataplane
//     control forms ("userspace-inject:", "userspace-forwarding:",
//     "userspace-queue:", "userspace-binding:") cost PermMaint — the
//     destructive floor. For failover that matches the CLI exactly
//     (`request chassis cluster failover` is PermMaint). For the restorative
//     userspace halves (arm/register) it over-restricts by one tier versus
//     the CLI's PermControl; recovering that tier would mean re-implementing
//     three argument parsers inside the authorization gate, where a parse
//     that disagreed with the handler's would be a bypass. Over-restricting
//     a deep dataplane-diagnostic verb is the cheaper error.
//   - Any other unregistered action also costs PermMaint (the caller's
//     default), never less: an unpriced verb is an unclassified verb.
//
// The failover family's FABRIC admission is not expressed here: it is the
// parsed, node-targeted subset (KindRGFailoverNode / KindDataFailover),
// decided by pkg/clusterfailover.ParseAction at the gate, not by spelling.
const (
	// AttestArmPrefix is the D11 attestation-arm action prefix.
	AttestArmPrefix = "userspace-attest:arm:"
	// AttestArmPermission is the price of AttestArmPrefix actions.
	AttestArmPermission = config.PermAll
)

// SystemActionPrefixPermissions returns the prefix-priced SystemAction
// families other than the attestation arm (which is priced strictly above
// the default and is matched by callers before this list). Every entry
// costs config.PermMaint; the list exists so the census can enumerate the
// families the handler's non-switch branches serve instead of trusting
// prose.
func systemActionPrefixPermissionsList() []Entry {
	return []Entry{
		{Key: "cluster-failover:", Permission: config.PermMaint},
		{Key: "cluster-failover-data:", Permission: config.PermMaint},
		{Key: "cluster-failover-reset:", Permission: config.PermMaint},
		{Key: "userspace-binding:", Permission: config.PermMaint},
		{Key: "userspace-forwarding:", Permission: config.PermMaint},
		{Key: "userspace-inject:", Permission: config.PermMaint},
		{Key: "userspace-queue:", Permission: config.PermMaint},
	}
}

// SystemActionPrefixPermissions returns a copy of the prefix-priced
// SystemAction families.
func SystemActionPrefixPermissions() []Entry {
	return append([]Entry(nil), systemActionPrefixPermissions...)
}
