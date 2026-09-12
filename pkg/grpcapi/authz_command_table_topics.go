package grpcapi

import (
	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/cmdtree"
)

// Canonical command strings for the two REQUEST-DECODED gRPC methods
// (#7172 cut 5a-2): ShowText's topics and SystemAction's verbs.
//
// This is the other half of authz_command_table.go. That file maps a gRPC
// METHOD to the operational command it performs, and deliberately leaves two
// methods out: ShowText and SystemAction each multiplex many commands through
// one method name, so a single string for either would be a lie. They are
// priced for coarse permissions from the DECODED request (showTextTopicPermission
// / systemActionPermission in authz_methods.go), and for the same reason they
// are mapped to a command from the decoded request here.
//
// ── WHAT THIS FILE VERIFIES, AND WHAT IT DOES NOT ────────────────────────
//
// The tests prove two properties and NEITHER of them is attribution:
//
//   - CANONICALITY. Every value resolves against the operational tree to
//     itself, with every word a real command KEYWORD rather than a word a
//     value slot absorbed. So no entry names a command that cannot be run.
//   - COMPLETENESS. Every topic the ShowText dispatcher serves, and every verb
//     the SystemAction handler serves, has an entry — enumerated out of
//     production source in both directions, so a new topic or verb reds the
//     suite instead of silently going unmapped.
//
// What no test here can prove is that the entry is the RIGHT command:
// `chassis-cluster-status` mapped to `show system uptime` would pass every
// check in this package. ATTRIBUTION IS A REVIEW RESPONSIBILITY, and that is
// a measured conclusion rather than an excuse:
//
//   - DERIVING the command from the topic name does not work. `show ` +
//     topic-with-dashes-as-spaces reproduces only a minority of these entries;
//     the rest drop intermediate hierarchy (`address-book` is
//     `show security address-book`, `alarms` is `show system alarms`,
//     `tunnels` is `show interfaces tunnel`). The exemption list would be the
//     majority of the table, which is not a derivation.
//   - The SERVER's handler name carries no independent signal either: it is
//     camelCase(topic) almost everywhere, so it restates the topic and agrees
//     with it BY CONSTRUCTION.
//
// The only sound attribution source is cmd/cli, which is where the topic is
// chosen. These entries were originally transcribed by READING cmd/cli's
// dispatch, because that dispatch computed topic strings in nested switches
// and could not be walked mechanically.
//
// #8942: that is no longer the shape of the client, and this paragraph
// outlived it. #8058 MADE THE CLIENT MAPPING DECLARATIVE: cmd/cli's
// showCommand resolves through cmdtree.ShowTextTopicForCommand (a lookup in
// the showTextTopicCommand map, ~130 entries, pkg/cmdtree/showtext_topic.go),
// call sites name the COMMAND rather than a topic literal, and an
// unresolvable command fails loudly instead of guessing. So the cross-check
// this paragraph said would "become a table comparison rather than an AST
// walk once it is" IS a table comparison now, and a reader who trusted the
// deferral would go build an AST walk for a correspondence that is already
// one table both binaries read.
//
// ── ARGUMENT-FREE ENTRIES, AND THE GAP THAT CREATES ──────────────────────
//
// Every value is the canonical command with NO operator arguments. Where
// several spellings reach one topic and differ only by arguments, the entry is
// the argument-free one: `show interfaces detail` for `interfaces-detail`, not
// `show interfaces <name> detail`. Where the topic itself is parameter-packed
// (a key ending in ':' — `route-table:<name>`, `screen-statistics:<zone>`,
// `test-policy:from=...`), the entry is the command PREFIX that precedes the
// parameter.
//
// NAMED GAP, not a silent one. pkg/cli's cut-3 gate matches a deny regex
// against the FULL canonicalized line including its arguments and its output
// pipe (evaluateCommandRegex). These strings have neither. So a regex written
// against ARGUMENT text — `deny-commands "show route table secret-vrf"` — matches
// on the box and does NOT match the remote RPC, which under the
// allow-over-deny model of #7172 is an under-deny, i.e. fail-OPEN for that
// class of regex. A regex written against the command PATH — the shape the
// feature is for, and the shape Junos' own examples use — matches identically
// on both surfaces because matching is partial rather than anchored.
//
// #9022 CLOSED THE ANCHORED DIRECTION, which this paragraph had correctly
// scoped itself away from. An ANCHORED path regex used to disagree between the
// surfaces, and in the dangerous direction: `^show log$` denied here (these
// strings carry no arguments) and ALLOWED on the box the moment any argument
// was appended, so an operator who verified the rule over the remote CLI got
// the wrong answer about the console. pkg/cli now matches against the
// argument-free command prefix as well as the full line, so both surfaces
// agree for an anchored rule too. TestAnchoredDenyAgreesAcrossSurfaces9022
// asserts the AGREEMENT rather than each side separately. The ARGUMENT-text
// gap described above is unchanged and still open.
//
// Closing it needs a per-topic decoder turning `route-table:secret-vrf` back
// into `show route table secret-vrf`, i.e. 129 bespoke inverse functions, each
// one a new place the remote string can disagree with the on-box string. That
// is a worse trade than the gap, and it is recorded here rather than
// rediscovered.
//
// These tables are INERT: nothing reads them until 5b wires them into
// authorizeRPC.

// showTextTopicCommand maps a ShowText topic to the canonical operational
// command that emits it.
//
// THE TABLE ITSELF MOVED TO pkg/cmdtree (#8058, showtext_topic.go) and this is
// a view onto it. It used to be transcribed here independently of the remote
// `cli` binary's command -> topic switches, and nothing made the two agree; a
// topic re-attributed on one side left this one pricing an authz decision
// against a command string no operator could type. Both surfaces now read the
// cmdtree table, so that divergence is unrepresentable rather than a bug to be
// caught by a mirrored test. Add or rename a topic THERE.
//
// Everything this file's checks assert about the table is unchanged and still
// asserted HERE, because they are properties of the SERVER's dispatcher rather
// than of the data: every value canonicalizes to itself (#8057), and the key
// set is pinned to server_show.go's own literals in both directions by
// TestEveryShowTextTopicHasACanonicalCommand7172.
//
// A key ending in ':' is the PREFIX form of a parameter-packed topic and is
// spelled exactly as showTextViewTopics / showTextElevatedTopics spell it, so
// whatever rule 5b uses to price a topic finds a command for the same key.
var showTextTopicCommand = cmdtree.ShowTextTopicCommands()

// systemActionVerbCommand is the SHARED table, aliased rather than copied.
//
// #9952 moved it to pkg/authz because the REST surface dispatches the same
// verbs and must charge them the same commands. The alias keeps every reader in
// this package — and, more importantly, the completeness guard that pins this
// key set against the handler's own `switch req.Action` — working unchanged,
// while there is exactly ONE table for both surfaces to disagree with.
var systemActionVerbCommand = authz.SystemActionVerbCommand
