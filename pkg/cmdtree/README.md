# pkg/cmdtree

Single source of truth for the **operational** CLI command tree (`run` /
`show` / `clear` / `request` / `monitor` / `ping` / ...). Used by the local
CLI, the remote CLI, and the gRPC tab-completion RPC. Adding an operational
command here automatically propagates to all three frontends.

> [!IMPORTANT]
> **Two-SSOT split (#1319).** cmdtree is the SSOT for the OPERATIONAL tree
> only. The **config-mode `set`/`delete`/`show`/`edit` grammar** — its
> structural completion, flat-set token grouping, value-slot `?`
> completion, AND the commit-check typed-leaf validation — is owned by
> `config.setSchema` in `pkg/config/schema.go`, not by cmdtree. The live
> config-mode completers (`pkg/cli` `completeConfigWithDesc`, `pkg/grpcapi`
> `completeConfigPairs`) route `set` paths through
> `config.CompleteSetPathWithValues` over `setSchema` and never consult a
> cmdtree config-grammar tree. `ConfigTopLevel` here only carries the
> top-level keyword set (`set`/`delete`/`commit`/`load`/...) plus the
> retained `set system dataplane` description overlay. See
> `docs/config-schema.md` and `pkg/config/README.md`.

## Entry points

- `Node` — `tree.go`. Tree node: description, static children,
  `DynamicFn`/`ContextDynamicFn` for config-aware completions. Optional
  typed-leaf fields (`ValueType`, `ValueDesc`, `ValueExamples`,
  `Validator`) describe the value a leaf accepts — see "Typed leaves"
  below.
- `Candidate` — `tree.go`. `(name, desc)` pair surfaced during tab
  completion.
- `OperationalTree` — `tree.go`. Canonical root for `show`, `clear`,
  `request`, `monitor`, `ping`, `traceroute`, etc.
- `ConfigTopLevel` — root for the config-mode TOP-LEVEL keywords
  (`set`/`delete`/`show`/`edit`/`commit`/`load`/...). The config-grammar
  BELOW `set` lives in `config.setSchema`, not here (see the two-SSOT note
  above). The only sub-`set` content retained in cmdtree is the
  `set system dataplane` description overlay (#785/#801 knob help).
- `KeysFromTree(tree)` — `tree.go`. Used by `pkg/cli` and `pkg/grpcapi`
  for Junos-style prefix matching.
- `WriteHelp`, `LookupDesc`, `PrintTreeHelp`, `CompleteFromTree`,
  `CompleteFromTreeWithDesc` — the helper API the three frontends consume
  for the OPERATIONAL tree (and operational typed leaves).
- `ParseCoSNameTypeArgs`, `CoSNameTypeTopic`, `ParseCoSNameTypeTopic` —
  `cos_filter_topic.go`. The `name <n>` / `type <t>` filter grammar shared
  by `show class-of-service classifier|rewrite-rule`, plus the ShowText
  topic encoding that carries those filters to the gRPC server. See
  "Shared argument grammars" below.
- `ShowTextTopicCommands`, `CommandForShowTextTopic`,
  `ShowTextTopicForCommand` — `showtext_topic.go`. The ShowText
  topic <-> canonical operational command correspondence, read by the
  remote CLI (command -> topic, to know what to send) and by the daemon's
  authorization gate (topic -> command, to price `deny-commands`).

## Shared argument grammars

Some operational commands take arguments the tree cannot express as
children — an optional `name <n>` / `type <t>` filter pair, say. When both
the local CLI and the remote CLI must accept the same tokens, the PARSER
belongs here next to the tree nodes that offer those tokens, not copied
into each frontend.

`cos_filter_topic.go` is the worked example (#6858). Its grammar used to
exist three times: `pkg/cli` parsed args into filters, `cmd/cli` parsed the
same args into a gRPC topic, and `pkg/grpcapi` decoded the topic. The two
arg parsers had already drifted, and the topic encoding could not carry a
filter value containing the `,` it used as its own param separator — so
`show class-of-service rewrite-rule "rw,x"` rendered a different rule
remotely than locally. One parser, one encoder and one decoder in this
package make that class of divergence unrepresentable rather than
something a mirrored test table has to catch. Per-frontend tests then
assert only that each surface routes through these functions.

`showtext_topic.go` is the second instance (#8058), and it is here for the
same reason at a larger scale. The ShowText topic for a command existed
twice on opposite sides of a trust boundary: the remote `cli` binary
turned a command into a topic in nested switches, and `pkg/grpcapi` turned
a topic back into a command to price `deny-commands`. Nothing made them
agree, so a topic re-attributed to a different command on one side left
the other authorizing against a command string no operator could type.

An agreement test was the alternative and cannot be made sound here:
recovering the command that reaches each topic needs an AST walk of the
client's switches, and 18 of the topics are COMPUTED at their call sites,
so a literal scan certifies the majority (measured: 104 of 123 base
topics) and reports clean on the rest with nothing distinguishing the two.
Both surfaces now read one table. The remote CLI's call sites name the
COMMAND and resolve the topic through `ShowTextTopicForCommand`, which is
what removed the second transcription — and it reads better besides, since
the command is self-evident in the switch arm while a topic string is an
encoding detail.

Both sides importing this is not the server trusting the client. The
table is a compile-time constant in the daemon binary that no client can
influence, and the server already derives authorization input from this
package (`Canonicalize`, #8057). What would be a trust violation — the
server importing `cmd/cli`'s table — is a different thing and remains
forbidden.

## Canonicalization is the authorization input, so a leaf must END the walk

`Canonicalize` resolves an operator's abbreviated words to their full keyword
spellings, and `pkg/cli`'s `evaluateCommandRegex` matches a login class's
`allow-commands` / `deny-commands` against `strings.Join(canon, " ")`. That
makes the walk a **security surface**, not just a completion helper: whatever
the walk decides the command IS, is what the authorizer judges.

**#8289 — a word after a childless leaf used to resolve against the leaf's own
SIBLINGS.** The walk `continue`d on `node.Children == nil`, leaving `current`
at the PARENT map, so `show version configuration` canonicalized OK as a
three-word command.

The bypass is the reverse of what it looks like. Both dispatchers run it as
plain `show version` — `case "version"` in `pkg/cli/cli_show.go` and
`pkg/grpcapi/server_show.go` each call a no-argument `showVersion` and drop the
rest — so the trailing word is **not** executed as `show configuration`. The
hazard is that the authorizer judged three words while the box ran two, so an
operator's anchored deny missed:

```
deny="^show version$"  line="show version"                -> denied
deny="^show version$"  line="show version configuration"  -> ALLOWED   (pre-fix)
```

The unanchored form never had the hole — matching is unanchored partial, so
`show version` matches inside the longer string. **The operator who followed
Junos's own advice to use anchors is the one who was bypassed**, which is why
the regression cell uses the anchored form; an unanchored-only test passes on
the broken code.

The walk now descends unconditionally, including to a leaf's nil child map, so
the next word falls into the not-a-keyword arm. That arm still admits the
legitimate consumers of a following word — a typed leaf's value, a dynamic
node, a placeholder (one value each since #9505), a node that declares
`AcceptsArgs` — and refuses anything
else as `CanonicalUnknown`, which callers must fail closed on.

Over-rejection is the risk to watch when touching this, because a caller MUST
fail closed on anything other than `CanonicalOK`: refusing too much REFUSES a
lawful command for every operator with a restricted class. The regression cells
therefore carry control rows for value slots (`ping <host>`,
`show interfaces <name>`, `monitor traffic interface <name>`) and for genuine
child descents, and the change was verified differentially against master —
the only row whose result moved is `show version configuration`.

## `AcceptsArgs` — a node that takes an argument it cannot complete

**#8304 — the over-rejection the section above warns about, in the wild.**
`show log messages` and every `show configuration <stanza> <deeper>` are served
by the dispatchers but declared none of the three consumers, so `Canonicalize`
returned `CanonicalUnknown` and every login class with `allow-commands` /
`deny-commands` was refused a lawful command.

The repair is in the TREE, not the walk. All three mechanisms are correct and
load-bearing; those nodes simply declared none of them. `HasDynamic()` was the
near-fit and it does not fit, because it conflates two different properties:

| property | asked by | `show log <filename>` |
|---|---|---|
| offers completions | `CompleteFromTree`, `CompleteFromTreeWithDesc`, `LookupDesc` | no — the set is `/var/log`, not the tree's to enumerate |
| accepts an argument | `Canonicalize` | **yes** |

Expressing the second through `DynamicFn` means attaching a completer that
returns nothing, so `Node.AcceptsArgs` states it directly. It consumes
ARBITRARILY many trailing words and is honoured **only in `Canonicalize`** —
the completion walkers ask the other question and must not see it. That scope
is bound by `TestAcceptsArgsIsHonouredOnlyInCanonicalize_8304`, an AST check
with a `HasDynamic` positive control, so it cannot decay into a comment.

It is OPT-IN AND NEVER A RELAXATION: an unmarked node is exactly as strict as
before, so it cannot re-open #8289. The mutant that deletes the opt-in and
admits any trailing word (`if currentNode != nil`) reds the #8289 and #7172
guards as well as #8304's own controls — that is the cell carrying the weight.

Marked today: `show log`, the 16 `show configuration` stanza children, and
`monitor traffic matching` (#9505). The `count`/`size`/`source` options of `ping`
and `traceroute`, marked by #9064, have been typed leaves since #9505, because
`AcceptsArgs` absorbed every later word.

**Do NOT mark a node whose dispatcher refuses the argument.**
`clear security flow session all` looks like a fourth instance and is not one:
`parseClearSessionFilter` delegates to `parseSessionFilterMode(args, true)`
(`pkg/cli/session_filter.go`), whose token switch has no `all` arm — the
`default:` sets `unknown session filter "all"` — and `hasFilter()` counts
`parseErr != nil` as its FIRST term, so the error never falls through to a
clear-all. The command
is refused by the box, and the tree refusing it is the two agreeing. Marking it
would assert a command that does not exist — the mirror defect of #8304, and
the one #8057's canonicalize-to-self check exists to catch.

## A value slot takes ONE value, and option lists are declared (#9505)

**#9505: the dynamic arm absorbed every later word.** A dynamic node shared
`AcceptsArgs`'s `continue`, which never advances `currentNode`, so
`show route table secret-vrf bypass` canonicalized OK. `handleShowRoute` dropped
`bypass` and ran the command, and an anchored deny on the four-word command
never saw the five:

```
deny="^show route table secret-vrf$"  line="show route table secret-vrf"         -> denied
deny="^show route table secret-vrf$"  line="show route table secret-vrf bypass"  -> ALLOWED  (pre-fix)
```

A childless placeholder had the same shape. It never moves `current`, so it
re-matched every later word, and `ping 1.1.1.1 junk` authorized as a different
string from the ping that ran.

Every value slot (typed leaf, dynamic node, placeholder) now takes exactly one
value. After it, the next word must be a child of the node that took it, or
the line is refused.

That alone would have refused lawful commands. Several dispatchers parse their
children as **options in any order**, and until now the only thing letting a
restricted class run `show security flow session zone trust destination-port 22`
was the absorption itself. `Node.Options` declares those. Under an Options node
the walk returns to the option list once an option is complete, so the next
option resolves and is canonicalized, instead of being absorbed as raw text. The
value-taking options there are typed leaves, so they take one value too.

Marked, each checked against its dispatcher's loop:
- `ping` and `traceroute`
- `show security flow session` and `clear security flow session`
- `monitor security flow file` and `monitor security flow filter`
- `monitor security packet-drop`
- `monitor traffic`: `matching` is `AcceptsArgs` and stops at the next option,
  as its parser does.
- `show security log`, with a `<count>` placeholder.
- `test routing`
- `show firewall filter`: the mark is on the `filter` node, not on
  `show firewall`, because the dispatcher honours `family` and `effective` only
  after `filter <name>`.

**Do NOT mark a first-match dispatcher.** `show route` looks like an option list
and is not: `handleShowRoute` dispatches on `args[0]` and drops the rest, so
`show route table X protocol Y` runs `show route table X`. Marking it would
reopen the bypass through a sibling keyword instead of a junk word. `Options` is
honoured only in `Canonicalize`, bound by
`TestOptionsIsHonouredOnlyInCanonicalize9505`.

Verified differentially against master over 107 lines: every `usage:` string,
plus option-order and junk variants.
- 14 lawful option-list lines moved from UNKNOWN to OK.
- 13 extra-word lines moved from OK to UNKNOWN. Each is a word its handler
  ignores or rejects.
- One abbreviated line moved from OK to AMBIGUOUS, because `dest` names two
  options.
- Nothing else moved.

## Typed leaves

A `Node` with `ValueType != ValueAny` is a typed leaf: it expects exactly
one value of the declared kind at the next slot, and `?` completion
surfaces `ValueDesc` + `ValueExamples` + the placeholder
(`ValueType.Placeholder()`).

`ValueType` is defined in `pkg/config` (`config.ValueType`) and re-exported
here via aliases so cmdtree's operational leaves can carry it without a
`config → cmdtree → config` import cycle. The typed-leaf fields on `Node`
serve OPERATIONAL-tree leaves and the retained `set system dataplane`
overlay.

**Config-mode typed leaves do NOT live here.** The `class-of-service
schedulers` typed leaves (`transmit-rate`/`priority`/`buffer-size`) and the
commit-check gate moved onto `config.setSchema` + `config.SchemaValidate`
in #1319 PR 1, so the completion path and the validation path read one
tree and cannot drift. To add a config-mode typed leaf, edit `setSchema`
(see `docs/config-schema.md`), not cmdtree.

## Callers

`pkg/cli`, `pkg/grpcapi`, `cmd/cli`.

## Dependencies

`pkg/config` only.

## Gotchas

- `DynamicFn` and `ContextDynamicFn` run inside the interactive readline
  loop — they must not block on I/O, locks held by long operations, or
  network calls. Snapshot the candidate config once; iterate.
- `ContextDynamicFn` receives the words consumed so far, so completions
  can depend on earlier args (e.g. zone-pair → policy-name suggestions).
- The `tree.go` file is large by design (it's grammar). Don't refactor it
  into many small files just to reduce LOC — the single-file form is what
  makes it greppable for "where is this command defined?".
