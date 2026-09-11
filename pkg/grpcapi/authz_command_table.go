package grpcapi

// Canonical command strings for gRPC methods (#7172 cut 5a).
//
// ── WHY THIS TABLE HAS TO EXIST ──────────────────────────────────────────
//
// The remote `cli` binary parses the operator's command line CLIENT-side and
// sends a typed RPC; the line never crosses the wire. `authorizeRPC` sees
// ("/xpfv1.BpfrxService/GetInterfaces", *pb.GetInterfacesRequest) and nothing
// resembling a command. So `deny-commands "show interfaces"` — which cut 3
// enforces on the on-box CLI — has nothing to match against remotely, and the
// remote surface would be an unguarded path to exactly the commands an operator
// denied.
//
// The alternative was adding a command string to the RPCs. It was rejected on
// principle: the string would be CLIENT-SUPPLIED, so a caller wanting to evade
// a deny simply sends a different one. An authorization decision derived from
// attacker-controlled input is not an authorization decision, and being cheap
// to implement is the trap. This table is the server's own answer to "what
// command is this RPC", owned entirely server-side.
//
// ── WHAT MAKES AN ENTRY CORRECT ──────────────────────────────────────────
//
// Every value must be a command that `cmdtree.Canonicalize` resolves TO ITSELF
// — a real, already-canonical operational command. That is machine-checked, and
// it is what structurally excludes the error class that killed the idea of
// DERIVING these strings from method or topic names: `buffers-detail` looks like
// it should map to `show buffers detail`, which is wrong (`buffers` is not a
// child of `show`), and only `show system buffers detail` canonicalizes. A
// derivation would have been right for most entries and quietly wrong for some,
// which is the worst distribution for an authz input.
//
// ── SCOPE OF THIS FILE ───────────────────────────────────────────────────
//
// Methods only. `ShowText`'s topics and `SystemAction`'s verbs are priced from
// the DECODED REQUEST rather than the method name (see methodPermission), so
// they get their own tables in authz_command_table_topics.go (cut 5a-2), which
// also records the ATTRIBUTION limit both files share: canonicality and
// completeness are machine-checked, but "is this the RIGHT command" is a review
// responsibility on both. Both tables are inert: nothing reads either until 5b
// wires them into authorizeRPC.

// methodCanonicalCommand maps a short gRPC method name to the canonical
// operational command it performs, for fine-grained deny-commands matching.
//
// A method with NO entry is deliberate, not an oversight, and the completeness
// test enumerates the permitted absences with a reason for each. The two kinds:
//
//   - CONFIG-MODE methods (Set, Delete, Commit, ...). These are configuration
//     mutations, not operational commands. deny-CONFIGURATION governs them and
//     that is cut 4's gate plus 5b's config arm; matching them against
//     deny-COMMANDS would apply the wrong leaf's regex.
//   - REQUEST-DECODED methods (ShowText, SystemAction). One method serves many
//     commands, so a single string would be a lie. They get per-topic and
//     per-verb tables in 5a-2.
var methodCanonicalCommand = map[string]string{
	// Operational reads.
	"GetStatus":                "show version",
	"GetGlobalStats":           "show security flow statistics",
	"GetZones":                 "show security zones",
	"GetPolicies":              "show security policies",
	"GetSessions":              "show security flow session",
	"GetSessionSummary":        "show security flow session summary",
	"GetZonePairSummary":       "show security match-policies",
	"GetNATSource":             "show security nat source pool",
	"GetNATDestination":        "show security nat destination pool",
	"GetScreen":                "show security screen statistics",
	"GetEvents":                "show log",
	"GetInterfaces":            "show interfaces",
	"ShowInterfacesDetail":     "show interfaces detail",
	"GetDHCPLeases":            "show dhcp leases",
	"GetDHCPClientIdentifiers": "show dhcp client-identifier",
	"GetRoutes":                "show route",
	"GetBGPStatus":             "show bgp summary",
	"GetIPsecSA":               "show security ipsec security-associations",
	"GetNATPoolStats":          "show security nat source pool",
	"GetNATRuleStats":          "show security nat source rule",
	"GetNATDeterministic":      "show security nat source deterministic-nat",
	"MatchPolicies":            "show security match-policies",
	"GetSystemInfo":            "show version",
	"GetConfigModeStatus":      "show version",
	"ShowConfig":               "show configuration",
	"ShowCompare":              "show configuration",
	"ShowRollback":             "show configuration",
	"ListHistory":              "show system commit history",

	// Operational actions.
	"Ping":              "ping",
	"Traceroute":        "traceroute",
	"MonitorPacketDrop": "monitor security packet-drop",
	"MonitorInterface":  "monitor interface",
	"ClearSessions":     "clear security flow session",
	// `clear security counters`, NOT `clear firewall` — corrected in cut 5a-2.
	// This RPC clears ALL dataplane counters (ClearAllCounters) and the only
	// command that reaches it is `clear security counters` (cmd/cli/clear.go
	// handleClearSecurity, case "counters"). `clear firewall all` reaches
	// SystemAction{clear-firewall-counters} instead, which is where 5a-2's verb
	// table maps it — the collision is what made the mistake visible. The
	// original entry left `clear security counters` matched by nothing, which is
	// the under-deny this table exists to prevent.
	"ClearCounters":             "clear security counters",
	"ClearDHCPClientIdentifier": "clear dhcp client-identifier",
}

// methodsWithoutCanonicalCommand records, WITH A REASON, every method that
// deliberately has no entry above.
//
// A bare "not in the map" would be indistinguishable from a forgotten one, and
// the completeness test would have to choose between failing on every intended
// absence or accepting every accidental one. Naming them turns the absence into
// a reviewed decision.
var methodsWithoutCanonicalCommand = map[string]string{
	"EnterConfigure":  "enters config mode; the mutations inside are governed by deny-configuration",
	"ExitConfigure":   "leaves config mode; changes nothing",
	"Set":             "configuration mutation — deny-configuration, not deny-commands",
	"Delete":          "configuration mutation — deny-configuration, not deny-commands",
	"Load":            "configuration mutation — deny-configuration per written path; override refused for a restricted class (#9633)",
	"Commit":          "acts on the candidate as a whole; no path for a command regex to match",
	"CommitCheck":     "acts on the candidate as a whole",
	"CommitConfirmed": "acts on the candidate as a whole",
	"ConfirmCommit":   "acts on the candidate as a whole",
	"Rollback":        "acts on the candidate as a whole; n>0 refused for a class with configuration regexes (#9633)",
	"Complete":        "tab completion; returns candidates and executes nothing",

	// NO OPERATIONAL COMMAND EXISTS IN cmdtree FOR THESE. The routing-protocol
	// status RPCs are served to the remote client, but `show ospf`, `show isis`,
	// `show rip` and `show vrrp` are not nodes in the operational tree — so
	// there is no canonical spelling to map to, and inventing one would put a
	// string in this table that no operator can type and no deny regex is
	// written against.
	//
	// CONSISTENT rather than a gap: cut 3's on-box gate canonicalizes before
	// matching, so it cannot resolve these either and fails closed for a
	// restricted class. Both surfaces refuse them for the same reason.
	//
	// If these are added to cmdtree later nothing here will notice — they stay
	// excused — so deleting an entry below is the deliberate step that makes
	// them mappable.
	"GetOSPFStatus": "no `show ospf` node exists in the operational tree",
	"GetISISStatus": "no `show isis` node exists in the operational tree",
	"GetRIPStatus":  "no `show rip` node exists in the operational tree",
	"GetVRRPStatus": "no `show vrrp` node exists in the operational tree",
	"ShowText":      "priced from the decoded request; the topic selects the command (showTextTopicCommand)",
	"SystemAction":  "priced from the decoded request; the verb selects the command (systemActionVerbCommand)",
}
