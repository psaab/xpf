package authz

// SystemActionVerbCommand lives HERE, in the shared authorization package,
// because BOTH local control surfaces dispatch the same verb and must charge it
// the same command (#9952).
//
// It was private to pkg/grpcapi until REST's `deny-commands` gate needed it.
// Copying it would have been the obvious move and it is the one this repo keeps
// paying for: two tables that agree today, drift silently, and each looks right
// on its own. gRPC now reads this one through a one-line alias, so a verb added
// to a handler is charged identically on both surfaces or on neither.
//
// SystemActionVerbCommand maps a SystemAction verb to the canonical operational
// command that sends it.
//
// The verb is NOT the command and cannot be derived from it: `clear-firewall-
// counters` is sent only by `clear firewall all`, `clear-nat-counters` by
// `clear security nat statistics`, and `clear-policy-counters` by
// `clear security policies hit-count`. Three different `clear` subtrees, three
// verb spellings that share a naming convention with none of them.
//
// PREFIX-FORM verbs are absent on purpose and cannot be listed: the handler's
// default branch parses `cluster-failover*` (#5810) and the `userspace-*`
// dataplane control forms out of a packed string, so they have no case label to
// enumerate and no fixed spelling to key. systemActionPermission already
// charges them the destructive floor; 5b must treat a verb with no entry the
// way it treats an unmapped method rather than assuming this table is total
// over what the handler accepts.
//
// The key set is pinned to the handler's own `switch req.Action` in both
// directions by TestEverySystemActionVerbHasACanonicalCommand7172.
var SystemActionVerbCommand = map[string]string{
	// Destructive maintenance — `request system ...`.
	"reboot":             "request system reboot",
	"halt":               "request system halt",
	"power-off":          "request system power-off",
	"zeroize":            "request system zeroize",
	"in-service-upgrade": "request system software in-service-upgrade",

	// The `clear ...` family.
	"clear-config-lock":           "clear system config-lock",
	"clear-arp":                   "clear arp",
	"clear-interfaces-statistics": "clear interfaces statistics",
	"clear-ipv6-neighbors":        "clear ipv6 neighbors",
	"clear-policy-counters":       "clear security policies hit-count",
	"clear-firewall-counters":     "clear firewall all",
	"clear-nat-counters":          "clear security nat statistics",
	"clear-persistent-nat":        "clear security nat source persistent-nat-table",

	// The non-maintenance `request ...` family.
	"ospf-clear":         "request protocols ospf clear",
	"bgp-clear":          "request protocols bgp clear",
	"ipsec-sa-clear":     "request security ipsec sa clear",
	"dhcp-renew":         "request dhcp renew",
	"dynamic-dns-update": "request system dynamic-dns update",
	"dynamic-dns-check":  "request system dynamic-dns check",
	"rescue-save":        "request system configuration rescue save",
	"rescue-delete":      "request system configuration rescue delete",
}
