package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_system_login_packed.go carries the #6662 commit-side gate for a
// `system login` body written on the statement line rather than in a nested
// block. Junos accepts both spellings; xpf compiles only the block (and the
// equivalent flat-`set`) form, so the packed spelling commits an EMPTY object:
//
//	system { login { user alice { class ops; } } }      -> Class = "ops"
//	system { login { user alice class ops; } }          -> Class = ""      <- dropped
//	system { login { class ops { permissions [ view configure ]; } } }
//	                                                    -> Permissions = [view configure]
//	system { login { class ops permissions [ view configure ]; } }
//	                                                    -> Permissions = []  <- dropped
//	system { login { user alice { authentication ssh-rsa "..."; } } }
//	                                                    -> SSHKeys = []      <- dropped
//
// The mechanism is the one documented in docs/config-schema.md ("Packed
// statements"): `namedInstances` resolves the instance NAME across both AST
// shapes (it reads Keys[1]) but hands the node back with the body still on
// Keys, and the login compiler then walks `.Children`, which is empty. One
// level down, `authentication` is the only login body statement the compiler
// reads exclusively through `.Children`, so its inline spelling drops the same
// way. Flat-set (`ParseSetCommand` + `SetPath`) is unaffected in every case:
// the schema consumes exactly the instance name as the keyed arg and hangs the
// rest off as children. The exposure is hand-authored hierarchical config text
// and `load override` — precisely how a vSRX config is migrated.
//
// WHY REJECT RATHER THAN UNPACK. Every downstream safety net in this stanza is
// guarded on NON-EMPTINESS, so an empty compile silences the whole belt:
//
//   - an empty user class means pkg/cli's `c.userClass == ""`, which is the
//     DELIBERATE legacy "no RBAC configured" shortcut — checkPermission returns
//     nil (allow everything) and showConfigRedacted returns false (cleartext
//     PSKs, SNMP communities, authentication-keys). The shortcut is correct;
//     the defect is that a config WITH RBAC configured reaches it. That
//     compounds with the #6701 identity fix in the permissive direction, which
//     is why the two ship together;
//   - an empty class permission set maps to the coarse `{none}` bucket, and a
//     dropped `deny-commands` / `deny-configuration` never reaches the #5831
//     gate: that gate reads LoginClass.DenyLeavesPresent, which the packed drop
//     leaves empty, so the commit it would have REFUSED is accepted and the
//     restriction the operator wrote is silently discarded. (Before #5831 the
//     same drop instead suppressed a MORE PERMISSIVE advisory; the gate
//     replaced that advisory, but the field the bug empties is still the one
//     the check reads.);
//   - a dropped `authentication` block leaves the account with no key and no
//     password.
//
// Unpacking would have to be exactly right for every leaf to avoid minting a
// wrong-but-non-empty class, which is worse than an empty one. Rejecting is
// unambiguous and both accepted spellings (nested block, flat `set`) already
// work, so the operator has a mechanical rewrite.
//
// Strictness follows the sibling AST gates: hard-reject at commit /
// commit-check, downgrade to a cfg.Warnings entry on the tolerant load /
// peer-sync paths (#1960 no-brick) so a node that persisted such a config under
// an older binary still BOOTS — leniently loaded, the stanza stays as inert as
// it already was, now with the drop stated.
//
// BOTH-NODE EVALUATION (#6706 review blocker). Both gates below run
// PRE-EXPANSION and evaluate the effective view of EVERY cluster node (the
// node0 AND node1 `${node}`/apply-groups expansions), exactly like the sibling
// union gates validateQinQVLANStackAST (#5879) and validateVLANMapAST (#6178).
// Evaluating only the committing node's view left both gates fully bypassable:
//
//	groups {
//	    node1 { system { login {
//	        class super-user { permissions view; }
//	        user bob { class super-user; }
//	    } } }
//	}
//	apply-groups "${node}";
//
// Committed on node 0, the node-1 body is stripped by ExpandGroupsWithVars
// before either gate sees anything, so strict commit-check passes. The peer
// then ingests the config through Store.SyncApply, which is the TOLERANT path
// (compileTreeLenient) and only warns. On node 1 the stanza is live, and
// pkg/cli resolveClassPerms resolves the built-in `super-user` first — bob
// holds PermAll, and the authored `permissions view` narrowing that the
// operator read as restrictive never applied on either node. The origin commit
// is the only strict check the peer view ever gets, so it has to run here; that
// is the same argument compiler_peer_effective_snat.go makes for source NAT
// (#5876), applied at the AST layer these gates live in rather than on a
// compiled *Config.
//
// Only the two per-node effective views are unioned — deliberately NOT the
// pre-expansion all-groups "View 1" that the COLLISION-shaped union gates
// (validateZoneIDCollisionAST, validateInterfaceUnitAliasCollisionsAST #5878)
// also fold in. Both login gates trip on a SINGLE property, so a View-1 union
// would additionally reject a packed or shadowing body staged in a group that
// no `apply-groups` references — inert dead config that renders on no node.
// TestLoginPackedInsideAppliedGroupRejected_6662 pins that unapplied groups
// stay inert.

// loginInstanceKeywords is the set of `system login` NAMED INSTANCES, i.e. the
// keywords under `login` that take an identity argument and a body. It is the
// full child set of the `login` schema node (schema_system.go); `login` has no
// other children, so the enumeration below is the whole stanza.
//
// Kept in step with the schema by TestLoginInstanceKeywordsMatchSchema_6662.
var loginInstanceKeywords = []string{"class", "user"}

// loginBlockOnlyStatements enumerates, per login instance keyword, the body
// statements whose value the compiler reads ONLY through `node.Children` — so
// writing the body inline on the statement line drops it.
//
// Derived by reading compiler_system.go's `login` arm against the `login`
// schema node, statement by statement. The full body vocabulary and its
// classification:
//
//	class <name>:
//	  permissions          multi-value leaf -> firewallMatchValues reads Keys[1:]
//	                       AND Children and accumulates (#2419) — inline is FINE
//	  idle-timeout         leaf -> nodeVal handles both shapes — FINE
//	  allow-commands       leaf -> nodeVal — FINE
//	  deny-commands        leaf -> nodeVal — FINE
//	  allow-configuration  leaf -> nodeVal — FINE
//	  deny-configuration   leaf -> nodeVal — FINE
//	  login-alarms         flag, no compiler arm at all in EITHER shape (a
//	                       pre-existing accept-but-ignore gap, not a packed
//	                       drop) — not this gate's business
//	  login-tip            flag, same as login-alarms
//
//	user <name>:
//	  uid                  leaf -> nodeVal — FINE
//	  class                leaf -> nodeVal — FINE
//	  authentication       BLOCK ONLY -> the compiler ranges over prop.Children
//	                       for encrypted-password / ssh-ed25519 / ssh-rsa /
//	                       ssh-dsa and never looks at Keys — inline DROPS
//
// So `authentication` is the only entry. It is a map rather than a hardcoded
// check so adding a block-bodied login statement is a one-line change here, and
// TestLoginBlockOnlyStatementsAreSchemaChildren_6662 fails if a name listed
// here is not a real schema child (a typo would silently disable the gate).
//
// The VALUE is the statement's ARITY: how many tokens after the keyword
// legitimately belong to its key rather than being a packed body. `authentication`
// takes none, so anything after the keyword is a packed body. A future
// block-bodied statement that DOES take an argument (`foo <name> { ... }`,
// schema `args: 1`) would carry that argument on Keys in the correct nested
// spelling too, so the packed test has to be `len(Keys) > 1 + arity` rather
// than `> 1` — otherwise the gate would reject the very spelling it is meant to
// accept. Recording the arity here keeps that correct by construction instead of
// leaving an args-bearing block statement outside the guard's scope (#6701
// MINOR-4).
var loginBlockOnlyStatements = map[string]map[string]int{
	"user": {"authentication": 0},
}

// loginPackedConsequence renders the stanza-specific consequence clause of the
// instance-line rejection so the operator is told what the drop actually costs,
// not merely that something was dropped.
func loginPackedConsequence(keyword string) string {
	switch keyword {
	case "user":
		// The consequence is stated as it stands AFTER #6701. A matched
		// non-root account carrying an empty class resolves to the fail-closed
		// `unauthorized` class (cli.ResolveLoginClass decision 3), so the drop
		// now costs the operator the class they wrote, not a promotion. It DID
		// promote before #6701 — an empty class is still pkg/cli's legacy
		// no-RBAC allow-everything shortcut, reached whenever no `system login
		// user` matches — which is why the two ship together and why the
		// warning still names that mode as the older behaviour.
		return "the user compiles with NO login class, so the class the operator wrote is " +
			"silently discarded and the account resolves to the fail-closed `unauthorized` " +
			"class instead of the one named (on a binary before #6701 it instead reached the " +
			"legacy no-RBAC allow-everything mode: allow every command, render secrets in " +
			"cleartext)"
	case "class":
		return "the class compiles with NO permissions and NO allow/deny regexes, so it " +
			"grants nothing and a dropped deny-commands / deny-configuration never reaches " +
			"the #5831 gate that would refuse the commit outright"
	}
	return "the instance compiles with an EMPTY body"
}

// validateLoginPackedStatementsAST walks the `system login` subtree and reports
// every instance whose body is packed onto the instance line, plus every
// block-only body statement whose block is packed onto the statement line.
//
// It reproduces `namedInstances`' own two-shape branch rather than calling it,
// because the gate needs the number of leading IDENTITY keys and that helper
// discards it:
//
//	len(child.Keys) >= 2  -> the node ITSELF; Keys[0] is the keyword, Keys[1]
//	                         the instance name                     -> identity 2
//	otherwise             -> a `sub` CHILD of a bare `user { }` container,
//	                         whose Keys[0] IS the instance name    -> identity 1
//
// Branching on the shape (rather than sniffing Keys[0] against the keyword)
// keeps it correct for an instance literally NAMED `user` or `class`.
//
// Returns (warnings, nil) when lenient, (nil, error) on the first offender when
// strict.
func validateLoginPackedStatementsAST(tree *ConfigTree, lenient bool) ([]string, error) {
	var f loginFindings
	forEachClusterNodeView(tree, func(view *ConfigTree) {
		collectLoginPackedFindings(view.Children, &f)
	})
	return f.verdict(lenient)
}

// loginPathPackedAnywhere reports whether ANY `system login` ancestor path in
// the tree is written packed onto a statement line, across both cluster node
// views.
//
// It is deliberately BROADER than the reporting gate above and answers a
// different question. validateLoginPackedStatementsAST answers "is there
// something to REJECT?", and reportLoginPathPacked stays silent for a prefix
// that names no instance and carries no children (`system login;`,
// `system login user;`) because rejecting those would reject configuration
// master accepts. This answers "did the operator write a `system login` path
// that the compiler did not descend?" — and the answer is yes for those
// prefixes too.
//
// That distinction is the #6706 review finding: the two spellings are not
// equivalent, so calling the short prefixes inert was wrong. Measured directly:
//
//	system { login; }   -> System.Login NON-NIL (0 users) -> every non-root
//	                       caller resolves to `unauthorized`
//	system login;       -> System.Login NIL                -> pkg/cli's legacy
//	                       unset-class mode: every command permitted, secrets
//	                       rendered in CLEARTEXT
//
// The packed spelling is the fail-OPEN one, which is the direction that cannot
// be left to a comment. Reporting them would be a new rejection, so this drives
// the RUNTIME instead
// (Config.System.LoginDroppedByPacking -> pkg/daemon applyCLILoginClass).
//
// An earlier revision ended that sentence "costs nothing an operator can see".
// That is FALSE and is removed (#6706 review r11). For a content-free prefix
// the runtime change is precisely what an operator sees: every non-root command
// flips from permitted to denied — measured as SetUserClass("unauthorized") for
// a plain `system login;` — and it happens with no diagnostic at all, because
// the reporting gate deliberately stays silent for prefixes naming nobody. The
// change is still the right one (it aligns the packed spelling with the nested
// one, which already denied), but calling it invisible is how a reviewer
// concludes no deployment can be affected.
//
// It walks the same two ancestor branches collectLoginPackedFindings walks, so
// the two cannot drift on WHICH shapes count as packed — only on which of them
// are reportable.
//
// CONTENT-FREE PREFIXES ARE MARKED TOO, AND THAT IS DELIBERATE (#6706 review
// r11, #6972). `system login;` and `system login user;` name no user and no
// class, so it is tempting to read the mark as an over-fire and narrow this to
// "only prefixes that carried RBAC away" — the same `len(rest) > nameIndex ||
// len(children) > 0` test reportLoginPathPacked applies. That narrowing was
// written, measured, and REVERTED, because it makes the two spellings of
// identical text disagree:
//
//	"system { login; }"   -> non-nil EMPTY LoginConfig, flag irrelevant -> DENIES
//	"system login;"       -> nil Login, flag -> DENIES        (with this mark)
//	"system login;"       -> nil Login, no flag -> PERMITS     (if narrowed)
//
// The nested spelling denies through a completely different mechanism —
// ResolveLoginClass returns ClassUnidentified for a caller not listed in an
// empty stanza — and never consults this flag. So narrowing here would leave
// `system { login; }` denying while `system login;` permits: a
// spelling-dependent authorization outcome, which is worse than either
// consistent answer. Marking content-free prefixes keeps them aligned.
//
// What this does NOT settle is whether a content-free `system login` should
// deny at all. It arguably should not — the operator configured nothing — but
// both alternatives reach outside this gate (permitting means changing the
// nested empty-stanza path in pkg/cli, pre-existing #6662; rejecting at commit
// would refuse configs that commit clean today, against the #1960 no-brick
// rule). That question is #6972. Until it is answered, do not "fix" the mark
// here in isolation: the divergence above is what you would reintroduce.
func loginPathPackedAnywhere(tree *ConfigTree) bool {
	packed := false
	forEachClusterNodeView(tree, func(view *ConfigTree) {
		_ = forEachChild(view.Children, "system", func(sys *Node) error {
			// #6966: `login` may sit BEHIND another system statement on the
			// same packed line, not only at Keys[1].
			if packedLoginKeyIndex(sys.Keys) > 0 {
				packed = true
				return nil
			}
			return forEachChild(sys.Children, "login", func(login *Node) error {
				if len(login.Keys) > 1 {
					packed = true
				}
				return nil
			})
		})
	})
	return packed
}

// loginPathLevelSystem / loginPathLevelLogin name the two ANCESTOR levels at
// which the `system login` path itself can be packed onto a statement line.
// They are the `%s statement line` token in the rejection message, so they are
// also the per-arm attribution marker the tests assert on.
const (
	loginPathLevelSystem = "system"
	loginPathLevelLogin  = "login"
)

// collectLoginPackedFindings records every packed offender under one
// already-expanded node view.
//
// The packing has THREE levels, not one, and the compiler drops the body at
// every one of them. `system login` is compiled only when the path descends
// through `.Children` at each step — compileSystem reaches `login` only as a
// CHILD of a bare `system` node, and namedInstances reads the instance name off
// Keys[1] of a `login` CHILD:
//
//	system { login { user alice { class ops; } } }   compiles
//	system { login { user alice class ops; } }       INSTANCE line packed
//	                                                 -> the user's body drops
//	system { login user alice class ops; }           `login` line packed
//	                                                 -> the whole stanza drops
//	system login user alice class ops;               `system` line packed
//	                                                 -> the whole stanza drops
//
// The two ancestor levels are the DANGEROUS ones, and the original gate saw
// neither: both `forEachChild` and `FindChildren` match on Keys[0], so with the
// path packed onto the `login` line that node has zero children and
// FindChildren returns nothing, and with it packed onto the `system` line
// sys.Children is empty and the inner walk never runs. The one level the gate
// DID cover is the one whose runtime outcome is fail-CLOSED (an instance with
// an empty class resolves to `unauthorized`), while the two it missed are the
// fail-OPEN ones — see loginPathPackedConsequence (#6706 review blocker).
//
// A prefix finding SUBSUMES everything below it: the stanza the operator wrote
// does not exist at all, so descending to report which of its instances are
// also packed would name statements inside a block that never compiled. The
// rewrite in the prefix message fixes the whole stanza in one edit; if the
// rewritten form still packs an instance line, the existing instance-level arm
// rejects it on the next commit.
//
// Both arms ride the SAME lenientLoginPackedStatements flag as the instance
// arm: identical #6662 defect (a valid Junos spelling xpf silently discards),
// identical #1960 doctrine (strict at commit, warn on the tolerant load /
// peer-sync ingress), so a separate opts field would be a second thing to wire
// and a second thing to wire wrong.
func collectLoginPackedFindings(nodes []*Node, f *loginFindings) {
	_ = forEachChild(nodes, "system", func(sys *Node) error {
		// #6966: the same index scan. rest starts AT the `login` token, so the
		// instance name is at index 2 exactly as it was when login was pinned
		// to Keys[1] — the reporting shape is unchanged, only where the tail
		// starts.
		if i := packedLoginKeyIndex(sys.Keys); i > 0 {
			// rest = [login, <keyword>, <name>, body...] — the instance name
			// would sit at index 2.
			reportLoginPathPacked(loginPathLevelSystem, sys.Keys[i:], 2, sys.Children, f)
			return nil
		}
		return forEachChild(sys.Children, "login", func(login *Node) error {
			if len(login.Keys) > 1 {
				// rest = [<keyword>, <name>, body...] — name at index 1.
				reportLoginPathPacked(loginPathLevelLogin, login.Keys[1:], 1, login.Children, f)
				return nil
			}
			for _, keyword := range loginInstanceKeywords {
				for _, container := range login.FindChildren(keyword) {
					if len(container.Keys) >= 2 {
						checkLoginInstancePacked(keyword, container.Keys[1], container, 2, f)
						continue
					}
					for _, sub := range container.Children {
						checkLoginInstancePacked(keyword, sub.Name(), sub, 1, f)
					}
				}
			}
			return nil
		})
	})
}

// loginPathPackedConsequence renders what the WHOLE-STANZA drop costs at each
// ancestor level. The two differ, and the difference is the reason this gate
// exists: only one of them is fail-closed.
//
//   - `system` line: System.Login compiles as nil. pkg/daemon
//     applyCLILoginClass (cli_rbac.go) takes its `cfg.System.Login == nil` early
//     return, so SetUserClass is never called and the CLI runs with an EMPTY
//     login class. That is pkg/cli's DELIBERATE legacy "no RBAC configured"
//     shortcut — checkPermission returns nil for every command and
//     showConfigRedacted returns false (permissions.go). The shortcut is
//     correct for a deployment that configured no RBAC; the defect is that a
//     config which DOES configure it lands there.
//   - `login` line: System.Login is non-nil but carries no users and no
//     classes, so ResolveLoginClass matches nothing and every non-root caller
//     falls to the fail-closed `unauthorized` class instead of the one written
//     (uid 0 keeps the root default). Not an escalation — a silent lockout from
//     the class the operator authored.
//
// Both levels leave zero configured users, so daemon reconcileAbsentLoginUsers
// (login_password.go) builds an EMPTY desired set and deprovisions every
// xpf-managed operator account.
func loginPathPackedConsequence(level string) string {
	switch level {
	case loginPathLevelSystem:
		return "`system login` compiles ABSENT (System.Login == nil), which is exactly " +
			"pkg/cli's legacy no-RBAC shortcut — every caller runs with an empty login " +
			"class, so every command is permitted and IKE PSKs, SNMP communities and " +
			"authentication-keys render in CLEARTEXT — and, with no configured users, " +
			"every xpf-managed operator account is DEPROVISIONED on the next apply"
	case loginPathLevelLogin:
		return "`system login` compiles EMPTY (no users, no classes), so every non-root " +
			"caller resolves to the fail-closed `unauthorized` class instead of the one " +
			"written — a silent lockout — and every xpf-managed operator account is " +
			"DEPROVISIONED on the next apply"
	}
	return "the stanza compiles EMPTY"
}

// reportLoginPathPacked records one ancestor-level packing. `rest` is the run
// of keys the statement line carries beyond the level's own keyword — starting
// at `login` for the `system` level, at the instance keyword for the `login`
// level — so `set system %s` / `set system login %s` reconstructs the operator's
// intended path verbatim. Rendered through quoteKeys for the same round-trip
// reason the instance arm quotes: the rewrite is meant to be PASTED, and an
// unquoted multi-word token would paste back as several tokens.
//
// nameIndex is where an instance NAME would sit in rest. A prefix that stops
// before it AND has no children below names no user and no class, so there is
// no authored instance to report as dropped, and rejecting it would reject
// config master accepts.
//
// An earlier revision justified that silence by calling `system login;` and
// `system login user;` "inert in both spellings". They are not, and the
// difference runs in the fail-OPEN direction (#6706 review r11). Measured:
//
//	system { login; }   -> System.Login NON-NIL (0 users) -> every non-root
//	                       caller resolves to `unauthorized`
//	system login;       -> System.Login NIL -> pkg/cli's legacy unset-class
//	                       mode: every command permitted, secrets in CLEARTEXT
//
// The silence is still right — a new commit rejection here would be an outage
// of its own, and neither spelling declares anything an operator asked for —
// but the RUNTIME divergence is not acceptable, so it is closed elsewhere:
// loginPathPackedAnywhere records every packed path INCLUDING these prefixes
// into Config.System.LoginDroppedByPacking, and pkg/daemon applyCLILoginClass
// refuses the legacy unset-class mode when it is set. Reporting and posture are
// two decisions, and only one of them needed changing.
// A prefix WITH children is always reportable however short it is:
// `system login { user alice { class ops; } }` packs only the two-token prefix
// yet drops a fully-formed stanza.
func reportLoginPathPacked(level string, rest []string, nameIndex int, children []*Node, f *loginFindings) {
	if len(rest) <= nameIndex && len(children) == 0 {
		return
	}
	packed := quoteKeys(rest)
	setPath := "set system " + packed
	if level == loginPathLevelLogin {
		setPath = "set system login " + packed
	}
	f.add(fmt.Sprintf(
		"system login: `%s` is written on the `%s` statement line, but xpf compiles the "+
			"`system login` stanza only when every level of the path descends into a NESTED "+
			"BLOCK — or is written as a `set` statement — so every user and class written "+
			"here is SILENTLY DROPPED and %s (#6662). Rewrite as `system { login { ... } }` "+
			"with each `user`/`class` instance in its own block, or as `%s`.",
		packed, level, loginPathPackedConsequence(level), setPath))
}

// checkLoginInstancePacked reports the packed body of ONE login instance:
// first the instance line itself, then any block-only body statement written
// inline. identityKeys is how many leading Keys name the instance.
//
// Every name and body token is rendered through quoteKey, the same round-trip
// renderer Node.KeysString / Format use. The rewrite suggestions are meant to
// be PASTED, and the lexer keeps a quoted string as one token: rendering
// `class "noc ops" deny-commands "request system zeroize";` with a bare
// strings.Join produced `class noc ops { deny-commands request system
// zeroize; }`, which preserves neither token boundary and is a different
// (invalid) configuration. Quoting restores both.
func checkLoginInstancePacked(keyword, name string, inst *Node, identityKeys int, f *loginFindings) {
	qname := quoteKey(name)
	if len(inst.Keys) > identityKeys {
		body := quoteKeys(inst.Keys[identityKeys:])
		f.add(fmt.Sprintf(
			"system login %s %s: body `%s` is written on the instance line, but xpf "+
				"compiles a `%s` body only from a nested block or a `set` statement — every "+
				"statement written there is SILENTLY DROPPED and %s (#6662). Rewrite as "+
				"`%s %s { %s; }` or `set system login %s %s %s`.",
			keyword, qname, body, keyword, loginPackedConsequence(keyword),
			keyword, qname, body, keyword, qname, body))
	}
	blockOnly := loginBlockOnlyStatements[keyword]
	if blockOnly == nil {
		return
	}
	for _, prop := range inst.Children {
		stmt := prop.Name()
		arity, isBlockOnly := blockOnly[stmt]
		if !isBlockOnly {
			continue
		}
		// Keys[0] is the statement; the next `arity` tokens are legitimately
		// part of its key. Anything beyond that is a packed body.
		if len(prop.Keys) <= 1+arity {
			continue
		}
		body := quoteKeys(prop.Keys[1+arity:])
		f.add(fmt.Sprintf(
			"system login %s %s %s: body `%s` is written on the statement line, but xpf "+
				"compiles `%s` only from a nested block or a `set` statement — the key or "+
				"password written there is SILENTLY DROPPED and the account is left with no "+
				"usable authentication method (#6662). Rewrite as `%s { %s; }` or "+
				"`set system login %s %s %s %s`.",
			keyword, qname, stmt, body, stmt, stmt, body, keyword, qname, stmt, body))
	}
}

// quoteKeys renders a run of AST keys as pasteable configuration text, quoting
// each token that would not read back as itself (quoteKey, ast.go).
func quoteKeys(keys []string) string {
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = quoteKey(k)
	}
	return strings.Join(parts, " ")
}

// loginFindings accumulates gate messages across the per-node views, dropping a
// finding already recorded by an earlier view. Insertion order is preserved so
// the strict first-offender is the first in SOURCE order of the node-0 view —
// identical to the pre-#6706 single-view behaviour for every non-cluster
// config, and deterministic (node 0 then node 1) for a cluster one.
type loginFindings struct {
	seen  map[string]bool
	order []string
}

func (f *loginFindings) add(msg string) {
	if f.seen == nil {
		f.seen = make(map[string]bool)
	}
	if f.seen[msg] {
		return
	}
	f.seen[msg] = true
	f.order = append(f.order, msg)
}

// verdict renders the collected findings: strict returns the first as an
// error, lenient returns all as warnings (#1960 no-brick).
func (f *loginFindings) verdict(lenient bool) ([]string, error) {
	if len(f.order) == 0 {
		return nil, nil
	}
	if !lenient {
		return nil, fmt.Errorf("%s", f.order[0])
	}
	return f.order, nil
}

// forEachClusterNodeView calls fn with the candidate tree expanded for each
// chassis-cluster node id, so a gate sees what EVERY node will actually render
// — including a `groups nodeN` body that `apply-groups "${node}"` selects only
// on the peer.
//
// Mirrors collectQinQFindingsForNode / collectVLANMapFindingsForNode: clone,
// expand for the node, read the AST. It never calls CompileConfig* (which
// would re-enter the gate). A view that fails to expand contributes nothing —
// a config defining only `groups node1` + `${node}` does not expand for node 0,
// and the real per-node compile path already rejects that on the affected
// node, while the OTHER view still sees the body hidden in the group.
func forEachClusterNodeView(tree *ConfigTree, fn func(*ConfigTree)) {
	if tree == nil {
		return
	}
	for _, nodeID := range []int{0, 1} {
		clone := tree.Clone()
		vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
		if err := clone.ExpandGroupsWithVars(vars); err != nil {
			continue
		}
		fn(clone)
	}
}

// loginBlockOnlyStatementNames returns the flattened `<keyword> <statement>`
// enumeration of loginBlockOnlyStatements in deterministic order. Used by the
// schema-drift guard so a failure names exactly which entry is wrong.
func loginBlockOnlyStatementNames() []string {
	var out []string
	for keyword, stmts := range loginBlockOnlyStatements {
		for stmt := range stmts {
			out = append(out, keyword+" "+stmt)
		}
	}
	sort.Strings(out)
	return out
}

// loginBlockOnlyArity returns the recorded arity for a `<keyword> <statement>`
// entry, and whether it is listed at all. Used by the schema-drift guards so
// they check the SAME arity the gate applies.
func loginBlockOnlyArity(keyword, stmt string) (int, bool) {
	stmts, ok := loginBlockOnlyStatements[keyword]
	if !ok {
		return 0, false
	}
	arity, ok := stmts[stmt]
	return arity, ok
}

// validateLoginClassShadowsBuiltinAST rejects a `system login class <name>`
// whose name is one of the SYSTEM-DEFINED classes.
//
// Found while sweeping the #6701 fail-open for siblings: it is the same defect
// thesis one layer down from the packed drop above — an operator's configured
// restriction silently absent in the PERMISSIVE direction — reached without any
// packing at all.
//
//	system login class super-user { permissions view; }
//	system login user bob { class super-user; }
//
// compiles cleanly, records MappedPermissions=[PermView], and the commit
// advisory even reports "mapped to xpf coarse permissions {view}" — telling the
// operator the narrowing took effect. At runtime it does not: pkg/cli
// resolveClassPerms consults config.LoginClassPermissions FIRST, so `super-user`
// resolves to the BUILT-IN [PermAll] and bob holds every permission including
// destructive maintenance. The custom definition is entirely inert and the only
// operator-visible signal says the opposite.
//
// Built-in-first precedence is itself the SAFE ordering and is deliberately not
// changed here: inverting it would let `class read-only { permissions all; }`
// ESCALATE the built-in, which is strictly worse. The defect is the silence, so
// the fix is to refuse the shadowing definition and name the collision.
//
// Both accepted alternatives are one edit away: pick a distinct class name, or
// assign the built-in directly if the built-in semantics are what was wanted.
//
// Strict at commit / commit-check; warn on the tolerant load / peer-sync path
// (#1960) — leniently loaded the definition stays exactly as inert as it
// already was, now stated. Since #14387 the tolerant path additionally
// neutralises assignments to the shadowed name (see
// neutraliseShadowedLoginAssignments14387), so warn-only no longer leaves
// the assigned user holding the built-in's permissions.
func validateLoginClassShadowsBuiltinAST(tree *ConfigTree, lenient bool) ([]string, error) {
	var f loginFindings
	forEachClusterNodeView(tree, func(view *ConfigTree) {
		collectLoginClassShadowFindings(view.Children, &f)
	})
	return f.verdict(lenient)
}

// neutraliseShadowedLoginAssignments14387 rewrites, on the tolerant load /
// peer-sync path only, every compiled user whose class names a built-in that
// is ALSO shadowed by a custom class definition in cfg (#14387 / DR6-H3).
//
// The shadowing definition is inert (ResolveClassPermissions consults the
// built-in table first), so keeping the assignment would hand the user the
// built-in's permissions — for `super-user`, PermAll — while the authored
// narrowing never applied. Rewriting the assignment to "unauthorized" (a
// built-in whose permission set is empty) makes every consumer agree:
// LoginUserClass, pkg/cli ResolveLoginClass (via the compiled user record),
// pkg/authz, the daemon login-shell selection and the sudoers reconciliation
// all read User.Class. The custom definition itself is left authored so show
// config still displays what was written, and users assigned a built-in with
// NO shadowing definition are untouched (their built-in grant is legitimate).
//
// "unauthorized" is itself a built-in, but it can never be a shadowing target
// that widens anyone: its permission set is empty, so even a (separately
// gated) `class unauthorized { permissions all; }` definition still resolves
// through the built-in empty set. Rewriting to it therefore cannot recurse.
//
// Returns one warning per neutralised user. Must only be called when the
// shadow gate ran leniently; strict compiles never reach a compiled cfg with
// a shadowing definition.
func neutraliseShadowedLoginAssignments14387(cfg *Config) []string {
	if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Classes) == 0 {
		return nil
	}
	shadowed := map[string]bool{}
	for _, lc := range cfg.System.Login.Classes {
		if lc == nil {
			continue
		}
		if _, builtin := LoginClassPermissions[lc.Name]; builtin {
			shadowed[lc.Name] = true
		}
	}
	if len(shadowed) == 0 {
		return nil
	}
	var warnings []string
	for _, u := range cfg.System.Login.Users {
		if u == nil || !shadowed[u.Class] {
			continue
		}
		warnings = append(warnings, fmt.Sprintf(
			"system login user %s: class %q is shadowed by a custom `system login class %s` "+
				"definition that is INERT at runtime (the built-in %q always wins), so the "+
				"authored narrowing was never applied; the assignment was neutralised to "+
				"\"unauthorized\" (no permissions) on this tolerant load — rename the custom "+
				"class or assign the built-in directly (#14387)",
			u.Name, u.Class, u.Class, u.Class))
		u.Class = "unauthorized"
	}
	return warnings
}

// collectLoginClassShadowFindings records every built-in-shadowing class
// definition under one already-expanded node view.
func collectLoginClassShadowFindings(nodes []*Node, f *loginFindings) {
	report := func(name string) {
		if _, builtin := LoginClassPermissions[name]; !builtin {
			return
		}
		f.add(fmt.Sprintf(
			"system login class %s: %q is a SYSTEM-DEFINED login class, and the built-in "+
				"definition always wins at runtime (pkg/cli resolveClassPerms consults the "+
				"built-in table first) — this definition is INERT, so any narrowing it "+
				"expresses is silently not applied while the commit advisory reports that it "+
				"was (#6701). Choose a distinct class name, or reference the built-in %q "+
				"directly from `system login user <name> class %s`.",
			name, name, name, name))
	}

	_ = forEachChild(nodes, "system", func(sys *Node) error {
		return forEachChild(sys.Children, "login", func(login *Node) error {
			// A `login` node carrying extra keys is an INSTANCE line
			// (`login user alice { ... }`), so its children are that
			// instance's body, not login-level containers. Reading a `class`
			// child there misreads a user's class ASSIGNMENT as a class
			// DEFINITION and reports `system login class read-only: this
			// definition is INERT` for a definition the operator never wrote
			// (#6706). The stanza is still rejected — by the ancestor-level
			// arm of the packed gate, which runs first and diagnoses the real
			// defect (the whole stanza is dropped).
			if len(login.Keys) > 1 {
				return nil
			}
			for _, container := range login.FindChildren("class") {
				if len(container.Keys) >= 2 {
					report(container.Keys[1])
					continue
				}
				for _, sub := range container.Children {
					report(sub.Name())
				}
			}
			return nil
		})
	})
}

// packedLoginKeyIndex reports the index in keys at which a `login` statement
// begins, when `login` is packed onto a `system` node's own Keys BEHIND another
// system statement, or -1.
//
// #6966: both detection arms used to test `keys[1] == "login"` only, so
//
//	system host-name fw login user alice class ops;
//	system services ssh login user alice class ops;
//
// were invisible — `login` sits at index 3 and 4. Both commit CLEAN with no
// diagnostic, the stanza is dropped (`Config.System.Login == nil`), and because
// downstream reads nil as "no policy configured" the shell runs with an empty
// class: allow-everything, secrets in cleartext. That is worse than the shape
// #6706 closed, which at least failed a strict commit.
//
// Scanning for the literal `login` anywhere would be wrong in the fail-CLOSED
// direction, which is the worse mistake here. A firewall may legitimately be
// NAMED login:
//
//	system host-name login;
//
// Marking that as packed sets LoginDroppedByPacking and DENIES every non-root
// command — an outage produced by a legal config. So the scan walks the packed
// tokens against the SCHEMA and only reports `login` in a KEYWORD position:
//
//   - a scalar statement consumes `args` value tokens, so `host-name login`
//     consumes `login` as the hostname and this returns -1;
//   - a container statement descends, so tokens after it are read at the child
//     level;
//   - a token that is not consumable at the current level but IS a `system`
//     child re-opens a system-level statement — which is what makes
//     `services ssh login …` report, since `login` is no child of `ssh`.
//
// That last rule is the same reasoning the packed-line splitter uses for
// `chassis cluster` (isClusterStatement): an unrecognized token does not go
// inert, it opens the next statement.
func packedLoginKeyIndex(keys []string) int {
	if len(keys) < 2 || schemaSystem == nil {
		return -1
	}
	level := schemaSystem
	for i := 1; i < len(keys); i++ {
		tok := keys[i]
		if tok == "login" {
			// A keyword position: nothing above consumed it as a value.
			return i
		}
		if node, ok := level.children[tok]; ok {
			// Consume this statement's value tokens, then either descend into
			// it or stay at the same level for the next statement.
			i += node.args
			if len(node.children) > 0 {
				level = node
			}
			continue
		}
		// Not consumable here. If `system` knows it, the previous statement
		// ended and this one opens at the system level; otherwise treat it as
		// an opaque value and keep going.
		if _, ok := schemaSystem.children[tok]; ok {
			level = schemaSystem
		}
	}
	return -1
}
