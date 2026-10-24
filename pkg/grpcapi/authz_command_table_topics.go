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
//     value slot absorbed, and no word after a leaf (#12527). So no entry
//     names a command that cannot be run.
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
// ── ARGUMENT-FREE ENTRIES, AND THE RECONSTRUCTION THAT COMPLETES THEM ───
//
// Every value is the canonical command with NO operator arguments. Where
// several spellings reach one topic and differ only by arguments, the entry is
// the argument-free one: `show interfaces detail` for `interfaces-detail`, not
// `show interfaces <name> detail`. Where the topic itself is parameter-packed
// (a key ending in ':' — `route-table:<name>`, `screen-statistics:<zone>`,
// `test-policy:from=...`), the entry is the command PREFIX that precedes the
// parameter.
//
// These entries are the CHARGE, not the whole matched string. Since #16067
// the gate (authz_command_args_16067.go) rebuilds the full canonicalised
// line from the decoded request — topic parameters, typed RPC fields,
// ShowText filter — and matches the pattern against that line AND this
// argument-free charge, so a regex written against ARGUMENT text
// (`deny-commands "show route table secret-vrf"`, `^ping 10\.99\.`,
// `^show log .*`) fires remotely exactly as it does on the box, and a
// regex written against the command PATH matches identically because
// matching is partial rather than anchored. The reconstruction mirrors
// each handler's own decoder; a packing the handler would reject yields
// no command and denies for a restricted class.
//
// #9022 CLOSED THE ANCHORED DIRECTION. An ANCHORED path regex used to
// disagree between the surfaces, and in the dangerous direction:
// `^show log$` denied here (these strings carry no arguments) and
// ALLOWED on the box the moment any argument was appended, so an
// operator who verified the rule over the remote CLI got the wrong
// answer about the console. pkg/cli matches against the argument-free
// command prefix as well as the full line, and this gate does the same
// via EvaluateForms, so both surfaces agree for an anchored rule too.
// TestAnchoredDenyAgreesAcrossSurfaces9022 asserts the AGREEMENT rather
// than each side separately; TestArgumentScopedDenyFiresOnGRPC16067
// asserts the argument-text agreement.
//
// #16472 CLOSED THE BASE-SPELLING DIRECTION. The gate used to judge
// only the registry's selector spelling (`show firewall filter`,
// `show security screen statistics zone`, `show route table`), so
// #15942's anchored base deny (`^show firewall$`, `^show route$`)
// held on the console and not here. The form set now carries the
// canonical base/full/selector spellings of the executed line and of
// the bare charge, derived by the shared cmdtree.CanonicalForms /
// CanonicalFormsForCharge, plus the shared #14687 rescue — see
// authz_command_args_16067.go. One documented asymmetry remains:
// the charge itself (`show route table`) is still a judged form, so
// an anchored rule written against that spelling fires remotely
// while the console, which never mints it for the value-bearing
// line, allows; it is the registry's own spelling and the direction
// is fail-closed. TestRemoteBaseDenyCrossSurface16472 asserts the
// agreement per registry prefix topic and per Filter-carried
// selector topic.

// showTextTopicCommand maps a ShowText topic to the canonical operational
// command that emits it.
//
// THE TABLE ITSELF LIVES IN pkg/optopic (#16136, the topic registry) and
// this is a view onto it via pkg/cmdtree. It used to be transcribed here
// independently of the remote `cli` binary's command -> topic switches, and
// nothing made the two agree; a topic re-attributed on one side left this
// one pricing an authz decision against a command string no operator could
// type. Both surfaces now read the one registry, so that divergence is
// unrepresentable rather than a bug to be caught by a mirrored test. Add or
// rename a topic in pkg/optopic.
//
// Everything this file's checks assert about the table is unchanged and still
// asserted HERE, because they are properties of the SERVER's dispatcher rather
// than of the data: every value canonicalizes to itself (#8057), and the key
// set is pinned to server_show.go's own literals in both directions by
// TestEveryShowTextTopicHasACanonicalCommand7172.
//
// A key ending in ':' is the PREFIX form of a parameter-packed topic and is
// spelled exactly as the optopic registry spells it, so
// whatever rule 5b uses to price a topic finds a command for the same key.
var showTextTopicCommand = cmdtree.ShowTextTopicCommands()

// systemActionVerbCommand is the SHARED table, aliased rather than copied.
//
// #9952 moved it to pkg/authz because the REST surface dispatches the same
// verbs and must charge them the same commands; #16136 derives that table
// from pkg/optopic. The alias keeps every reader in this package — and,
// more importantly, the completeness guard that pins this key set against
// the handler's own `switch req.Action` — working unchanged, while there
// is exactly ONE registry for both surfaces to disagree with.
var systemActionVerbCommand = authz.SystemActionVerbCommand
