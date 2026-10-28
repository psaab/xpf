package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const sharedUMEMPhase0ArtifactMaxBytes = 16 << 20

// These exact Junos AAA leaves have no runtime consumer. Refuse them narrowly
// while keeping the surrounding open-world system tree unchanged. `accounting`
// joined the set in #15019: it committed strictly with no warning while its
// `secret` leaves rendered in cleartext on redacted show surfaces.
var unimplementedSystemAAALeaves10831 = map[string]struct{}{
	"radius-server":        {},
	"tacplus-server":       {},
	"authentication-order": {},
	"accounting":           {},
}

func systemAAARefusal10831(leaf string) string {
	return fmt.Sprintf(
		"local-only authentication is the only supported mode; Junos system %s is not implemented and is refused rather than silently ignored (#10831)",
		leaf)
}

// systemAAARefusals15711 collects every unimplemented AAA leaf (#10831)
// authored as a DIRECT `system` statement, in deterministic source order,
// across every AST shape the parsers produce (#15711):
//
//   - braced child: `system { radius-server 192.0.2.10 { ... } }`
//   - brace-elided on the system node: `system radius-server 192.0.2.10 ...;`
//   - packed behind a modelled sibling on the system line:
//     `system host-name fw1 authentication-order [ tacplus password ];`
//     (one node, Keys=[system host-name fw1 authentication-order ...])
//   - packed behind a modelled sibling inside the block:
//     `system { no-redirects tacplus-server 192.0.2.20; }`
//     (one child, Keys=[no-redirects tacplus-server 192.0.2.20])
//   - nested flat-set runs: `set system host-name fw1 authentication-order
//     tacplus` nests the AAA leaf under the preceding leaf's node, and
//     `set system no-redirects tacplus-server 192.0.2.20` likewise.
//
// The scan is schema-driven for modelled siblings: a token is judged as a
// statement head only at a statement position, reached by consuming each
// preceding modelled `system` leaf with its declared arity (multi leaves
// absorb until the next modelled sibling). A VALUE that happens to spell
// an AAA keyword — `host-name radius-server`, a `domain-search` entry,
// `login class radius-server` / `login user radius-server` (deeper than
// the direct `system` level) — is therefore never misread as a statement.
// Quoted tokens are values, never keywords. A token the `system` schema
// does not model stops the packed scan (do-not-guess, the packedBodyChildren
// posture): the schema gate / open-world handling owns unmodelled tokens,
// and a packed AAA leaf behind an unmodelled token cannot be located
// without guessing its arity. The nested-run leg descends only through a
// modelled leaf that declares no children (a flat-set chain link); a
// modelled CONTAINER's children are its body, never judged here.
func systemAAARefusals15711(systemNode *Node) []string {
	if systemNode == nil {
		return nil
	}
	schema := systemSchema9792()
	var leaves []string
	seen := map[string]bool{}
	report := func(tok string) {
		if _, unsupported := unimplementedSystemAAALeaves10831[tok]; !unsupported || seen[tok] {
			return
		}
		seen[tok] = true
		leaves = append(leaves, tok)
	}
	// Packed statements carried on a node's own Keys, starting at index
	// `start` (1 for the `system` node itself, 0 for a direct child whose
	// head is Keys[0]). Consumes modelled `system` statements in order.
	scanPacked := func(n *Node, start int) {
		keys := n.Keys
		for i := start; i < len(keys); {
			tok := keys[i]
			if n.KeyQuoted(i) || isApplyStatementKeyword(tok) {
				return
			}
			if _, unsupported := unimplementedSystemAAALeaves10831[tok]; unsupported {
				report(tok)
				return
			}
			leaf := resolveSchemaChild(schema, tok)
			if leaf == nil {
				return
			}
			i++
			if leaf.multi {
				// A multi leaf owns its value run: it ends only at the
				// next modelled sibling.
				for i < len(keys) && !n.KeyQuoted(i) && resolveSchemaChild(schema, keys[i]) == nil && !isApplyStatementKeyword(keys[i]) {
					i++
				}
				continue
			}
			// A container packs its body's first keyword next, which
			// is not a `system` statement — stop rather than judge it.
			if len(leaf.children) > 0 || leaf.wildcard != nil {
				return
			}
			i += leaf.args
		}
	}
	// Nested flat-set chain: a chain link nests under the preceding
	// modelled leaf. Descend only through modelled leaves that declare
	// no children; a container's body is never a chain link.
	var scanNested func(n *Node)
	scanNested = func(n *Node) {
		for _, c := range n.Children {
			if c == nil || len(c.Keys) == 0 {
				continue
			}
			tok := c.Name()
			if c.KeyQuoted(0) || isApplyStatementKeyword(tok) {
				continue
			}
			if _, unsupported := unimplementedSystemAAALeaves10831[tok]; unsupported {
				report(tok)
				continue
			}
			leaf := resolveSchemaChild(schema, tok)
			if leaf == nil || len(leaf.children) > 0 || leaf.wildcard != nil {
				continue
			}
			scanNested(c)
		}
	}
	scanPacked(systemNode, 1)
	for _, child := range systemNode.Children {
		if child == nil || len(child.Keys) == 0 {
			continue
		}
		tok := child.Name()
		if child.KeyQuoted(0) || isApplyStatementKeyword(tok) {
			continue
		}
		if _, unsupported := unimplementedSystemAAALeaves10831[tok]; unsupported {
			report(tok)
			continue
		}
		// Packed run on this child's Keys (e.g. `no-redirects
		// tacplus-server ...` inside the block), then any chain nested
		// under it.
		scanPacked(child, 0)
		leaf := resolveSchemaChild(schema, tok)
		if leaf != nil && len(leaf.children) == 0 && leaf.wildcard == nil {
			scanNested(child)
		}
	}
	return leaves
}

// UnimplementedAAAWarnings returns one persistent alarm line per retained
// leaf on cfg.UnimplementedAAALeaves (#16077). It re-derives the operator
// signal from the retained marker rather than cfg.Warnings, so alarm
// surfaces that recompute from the active compiled config (show system
// alarms, show security alarms) see the local-only posture for as long
// as the config carries it — across daemon restarts, until the stanza is
// removed and the tree recompiles. Returns nil for a strict-compiled or
// clean config.
func UnimplementedAAAWarnings(cfg *Config) []string {
	if cfg == nil || len(cfg.UnimplementedAAALeaves) == 0 {
		return nil
	}
	warnings := make([]string, 0, len(cfg.UnimplementedAAALeaves))
	for _, leaf := range cfg.UnimplementedAAALeaves {
		warnings = append(warnings, systemAAARefusal10831(leaf)+
			" (unsupported AAA admitted on the tolerant path; local-only authentication is in effect until the stanza is removed)")
	}
	return warnings
}

func systemAAAWarningsOrError10831(systemNode *Node, lenient bool) ([]string, error) {
	leaves := systemAAARefusals15711(systemNode)
	if len(leaves) == 0 {
		return nil, nil
	}
	if !lenient {
		return nil, fmt.Errorf("%s", systemAAARefusal10831(leaves[0]))
	}
	warnings := make([]string, 0, len(leaves))
	for _, leaf := range leaves {
		warnings = append(warnings,
			systemAAARefusal10831(leaf)+" (strict commit would reject this)")
	}
	return warnings, nil
}

// syslogHostCoalesce9854 is the per-address merge record for the #9854
// syslog host coalescing: the destination being built, which scalars have
// been recorded (so an inherited value never overwrites an inline one),
// and which exact facility pairs have been seen (flat-set parity dedupe).
type syslogHostCoalesce9854 struct {
	host    *SyslogHostConfig
	srcSet  bool
	portSet bool
	seenFac map[SyslogFacility]struct{}
}

// syslogFileCoalesce15708 / syslogUserCoalesce15708: #15708 same-name merge records.
type syslogFileCoalesce15708 struct {
	file *SyslogFileConfig
	seen map[SyslogFacility]struct{}
}

type syslogUserCoalesce15708 struct {
	user *SyslogUserConfig
	seen map[SyslogFacility]struct{}
}

// heldAAA, when non-nil, receives this root's tolerated AAA leaves
// instead of cfg.UnimplementedAAALeaves: compileSections merges the
// per-root slices once, deduped across duplicate `system` roots, only
// after the whole dispatch succeeds (#16077 fold). Nil (direct callers)
// keeps the single-root publish-in-place behaviour.
func compileSystem(node *Node, sys *SystemConfig, cfg *Config, opts compileOpts, heldAAA ...*[]string) error {
	aaaWarnings, aaaErr := systemAAAWarningsOrError10831(node, opts.lenientSystemAAA10831)
	if aaaErr != nil {
		return aaaErr
	}
	if cfg != nil {
		cfg.Warnings = append(cfg.Warnings, aaaWarnings...)
		if opts.lenientSystemAAA10831 {
			// #16077: retain the leaf identities so alarm surfaces can
			// recompute the warning from the active config after the
			// transient Warnings slice has done its boot-time job.
			leaves := systemAAARefusals15711(node)
			if len(heldAAA) > 0 && heldAAA[0] != nil {
				*heldAAA[0] = append(*heldAAA[0], leaves...)
			} else {
				cfg.UnimplementedAAALeaves = append(cfg.UnimplementedAAALeaves, leaves...)
			}
		}
	}

	dpType, err := compileSystemDataplaneType(node)
	if err != nil {
		return err
	}
	sys.DataplaneType = dpType

	// #10003: `system host-name fw1;` packs the value onto the `system` node's
	// OWN Keys — `Keys=["system","host-name","fw1"]` with ZERO children — so
	// the child walk below cannot reach the typed leaf. The nested spelling
	// `system { host-name fw1; }` is owned by SchemaValidate's typed-leaf
	// validator; this compact spelling is read here and needs the same
	// admission rule.
	//
	// Keep this check narrowed to the leaf the issue names rather than teaching
	// the gate to validate every packed token on the `system` line. Strict
	// commit rejects a malformed identity; tolerant Load / SyncApply keeps the
	// persisted value and records a warning (#1960 no-brick).
	if len(node.Keys) >= 3 && node.Keys[1] == "host-name" {
		hostName := node.Keys[2]
		if err := ValidateSystemHostname(hostName); err != nil {
			if opts.lenientSystemHostname {
				if cfg != nil {
					cfg.Warnings = append(cfg.Warnings,
						fmt.Sprintf("system host-name %q (downgraded to warning on tolerant path): %v",
							hostName, err))
				}
			} else {
				return fmt.Errorf("system host-name %q: %w", hostName, err)
			}
		}
		sys.HostName = hostName
	}

	// #6957/#6992: spans every `login` child of this `system` node. See the
	// `case "login"` arm.
	var loginUserByName map[string]*LoginUser

	systemChildren := expandResolvingRuns9792(node.Children, systemSchema9792()) // #9792: expand a lenient-path packed run (#9235).
	for _, child := range systemChildren {                                       // #9792: expand a lenient-path packed run (#9235).
		switch child.Name() {
		case "host-name":
			if len(child.Keys) >= 2 {
				sys.HostName = child.Keys[1]
			}
		case "dataplane-type":
			// Already resolved before child compilation so system dataplane
			// dispatch is independent of statement ordering.
		case "domain-name":
			if len(child.Keys) >= 2 {
				sys.DomainName = child.Keys[1]
			}
		case "domain-search":
			// Multi-value leaf (schema_system.go domain-search, multi:true).
			// Handles every AST shape via the #2545 multi-leaf SSOT helper:
			//   - bracket list  `domain-search [ a b ]` collapses every value
			//     onto child.Keys[1:] with no children (#2419);
			//   - hierarchical block `domain-search { a; b; }` carries one
			//     leaf child per value;
			//   - single `domain-search a`.
			// Reading only child.Keys[1] + children kept the first domain and
			// silently dropped the rest of a flat-set bracket list once #2419
			// collapsed it onto Keys (the orphan children this loop relied on
			// vanished) — a #2419 regression for flat-set domain-search.
			sys.DomainSearch = append(sys.DomainSearch, firewallMatchValues(child)...)
		case "time-zone":
			if len(child.Keys) >= 2 {
				sys.TimeZone = child.Keys[1]
			}
		case "no-redirects":
			sys.NoRedirects = true
		case "name-server":
			// Multi-value leaf (schema_system.go name-server, multi:true).
			// Same #2419 collapse as domain-search above: a flat-set bracket
			// list `name-server [ 8.8.8.8 9.9.9.9 ]` now lands every server on
			// child.Keys[1:] with no children, so reading only child.Keys[1] +
			// children dropped every server but the first (broken DNS config).
			// firewallMatchValues unifies bracket / hierarchical block / single
			// shapes.
			sys.NameServers = append(sys.NameServers, firewallMatchValues(child)...)
		case "ntp":
			// #6690: read EVERY server a `server` node carries, not just
			// Keys[1]. `system { ntp { server { a; b; } } }` puts one leaf
			// child per server and leaves the node itself with Keys=["server"]
			// only, so the old `len(Keys) >= 2` read compiled ZERO servers from
			// it — a green commit with no time sync at all. The bracketed
			// spelling `server [ a b ]` collapses onto Keys[1:] (#2419) and
			// kept only the first.
			//
			// This is NOT firewallMatchValues: a `server` node's trailing
			// tokens are ambiguous. `server 1.1.1.1 prefer;` and
			// `server [ 1.1.1.1 2.2.2.2 ];` are structurally identical after
			// the lexer strips the brackets, so the per-server OPTION keywords
			// have to be recognised by name or `prefer` would be compiled as a
			// second NTP server and rendered verbatim into a chrony directive
			// (#4902 types the value for exactly that reason).
			// #8436: a server named by TWO `server` statements is ONE server.
			// Before this the address was appended again — rendering a
			// duplicate chrony `server` directive — and its option entry was
			// REPLACED, so `server 1.1.1.1 { key 5; }` followed by
			// `server 1.1.1.1 { version 4; }` compiled to key 0. The flat-set
			// spelling merges, which is the conservation property #8436 is
			// about.
			//
			// THE DIFFERENT-ADDRESS CASE IS UNTOUCHED: both the dedupe and the
			// option merge are keyed on the ADDRESS, so two statements naming
			// different servers still produce two entries with their own
			// options. That is the only shape this could get wrong, and it has
			// its own control cell.
			//
			// It also has to survive the bracketed spelling. `server [ a b ]`
			// collapses onto one node's Keys (#2419) and ntpServerValues
			// returns BOTH addresses from that single node, so the dedupe runs
			// per address rather than per node — a node-level check would
			// have discarded the second address of a bracket list.
			for _, ntpChild := range child.FindChildren("server") {
				ntpServers, ntpOpts := ntpServerValues(ntpChild)
				for _, addr := range ntpServers {
					if !ntpServerListed(sys.NTPServers, addr) {
						sys.NTPServers = append(sys.NTPServers, addr)
					}
				}
				for addr, opt := range ntpOpts {
					if sys.NTPServerOptions == nil {
						sys.NTPServerOptions = map[string]NTPServerOption{}
					}
					sys.NTPServerOptions[addr] = mergeNTPServerOption(
						sys.NTPServerOptions[addr], opt)
				}
			}
			// #14596: strip per-server `key <id>` into NTPServerKeyIDs.
			// xpf writes no chrony keyfile, so leaving the id on the
			// option would render chrony `key <id>` with no key material
			// behind it and chronyd would never poll the source. The
			// warning naming each id is emitted by
			// systemInertKnobWarnings from NTPServerKeyIDs.
			for addr, opt := range sys.NTPServerOptions {
				if opt.Key <= 0 {
					continue
				}
				found := false
				for _, id := range sys.NTPServerKeyIDs {
					if id == opt.Key {
						found = true
						break
					}
				}
				if !found {
					sys.NTPServerKeyIDs = append(sys.NTPServerKeyIDs, opt.Key)
				}
				opt.Key = 0
				sys.NTPServerOptions[addr] = opt
			}
			sort.Ints(sys.NTPServerKeyIDs)
			// #15709: peers compile like servers but to NTPPeers, rendered
			// as chrony `peer` directives. Packed tails (`ntp peer X
			// prefer;`) ride Keys, expanded via ntpSourceValues.
			ntpChildren15709 := hoistAndSplitRun8939(packedBodyChildren(child, refSystemNTP.resolve()), refSystemNTP.resolve())
			for _, peerChild := range ntpChildren15709 {
				if peerChild.Name() != "peer" {
					continue
				}
				peers, peerOpts := ntpSourceValues(peerChild, "peer")
				for _, addr := range peers {
					if !ntpServerListed(sys.NTPPeers, addr) {
						sys.NTPPeers = append(sys.NTPPeers, addr)
					}
				}
				for addr, opt := range peerOpts {
					if sys.NTPPeerOptions == nil {
						sys.NTPPeerOptions = map[string]NTPServerOption{}
					}
					sys.NTPPeerOptions[addr] = mergeNTPServerOption(sys.NTPPeerOptions[addr], opt)
				}
			}
			// Strip peer keys like server keys (#14596 belt).
			for addr, opt := range sys.NTPPeerOptions {
				if opt.Key <= 0 {
					continue
				}
				found := false
				for _, id := range sys.NTPServerKeyIDs {
					if id == opt.Key {
						found = true
						break
					}
				}
				if !found {
					sys.NTPServerKeyIDs = append(sys.NTPServerKeyIDs, opt.Key)
				}
				opt.Key = 0
				sys.NTPPeerOptions[addr] = opt
			}
			sort.Ints(sys.NTPServerKeyIDs)
			for _, tk := range child.FindChildren("trusted-key") {
				for _, v := range firewallMatchValues(tk) {
					if id, err := strconv.Atoi(v); err == nil && id > 0 {
						found := false
						for _, e := range sys.NTPTrustedKeyIDs {
							if e == id {
								found = true
								break
							}
						}
						if !found {
							sys.NTPTrustedKeyIDs = append(sys.NTPTrustedKeyIDs, id)
						}
					}
				}
			}
			sort.Ints(sys.NTPTrustedKeyIDs)
			if thNode := child.FindChild("threshold"); thNode != nil {
				if v := nodeVal(thNode); v != "" {
					if n, ok := parseIntLeaf(&cfg.Warnings, "system ntp threshold", v); ok {
						sys.NTPThreshold = n
					}
				}
				// Check for inline: threshold 400 action accept;
				for i := 2; i < len(thNode.Keys)-1; i++ {
					if thNode.Keys[i] == "action" {
						sys.NTPThresholdAction = thNode.Keys[i+1]
					}
				}
				// Check for hierarchical: threshold 400 { action accept; } — the
				// value rides the action CHILD's Keys, not a block under it.
				if actNode := thNode.FindChild("action"); actNode != nil {
					sys.NTPThresholdAction = nodeVal(actNode)
				}
			}
		case "login":
			// #6957: allocate ONCE. This arm runs per `login` child, and two
			// sibling `login { … }` blocks under one `system` are legal Junos —
			// a generated or concatenated config produces them routinely, and an
			// operator appending a second stanza to add an account is the
			// motivating case. Reallocating here discarded everything the
			// EARLIER block had contributed, so the compiled set reduced to the
			// last block and the first block's users vanished with no error.
			//
			// That is not merely absent-from-config: `reconcileAbsentLoginUsers`
			// treats the compiled set as authoritative and DEPROVISIONS
			// xpf-managed accounts missing from it, so the lost accounts were
			// removed from the box by a commit that reported success.
			//
			// Everything below this line already appends (`sys.Login.Classes`,
			// `sys.Login.Users`), so allocating once is the whole fix —
			// subsequent blocks accumulate into the same struct.
			//
			// Distinct root from #6956, which is fixed in the same change: that
			// one is a packed tail the walk never reads; this one is two
			// children the walk reads and then overwrites.
			if sys.Login == nil {
				sys.Login = &LoginConfig{}
			}
			// #6957 + #6992: the name->entry index must span blocks too, for the
			// same reason the allocation must. #6992 folds a user NAME authored
			// twice into ONE entry, but its index was declared inside this arm,
			// so it reset per block and could only ever fold WITHIN one. That
			// was invisible while the reallocation above discarded the earlier
			// block — the duplicate never coexisted, so the fold was never asked
			// to span anything and #6992's own cross-block cell passed for the
			// wrong reason. Fixing #6957 makes the duplicate real, which is what
			// surfaced it.
			if loginUserByName == nil {
				loginUserByName = map[string]*LoginUser{}
			}
			// #4304 S-2: parse custom `login class <name>` RBAC definitions so
			// a real vSRX config commits (the `user ... class` enum accepts
			// the defined names) and maps its Junos permission set onto xpf's
			// coarse permission model. Compiled BEFORE users so the class set
			// is complete regardless of stanza order.
			for _, classInst := range namedInstances(child.FindChildren("class")) {
				// #8436: find-or-create. `Login.Classes` is a SLICE, so before
				// this a duplicate `class C { ... }` appended a SECOND entry
				// with the same name — the "append both" disposition. Whichever
				// consumer reads the slice first wins, and the other block's
				// permissions are silently unreachable.
				//
				// Merging into the existing entry makes the hierarchical
				// spelling agree with the flat-set one, which is the #8436
				// conservation property. `mapJunosPermissions` below then runs
				// over the MERGED permission set rather than one block's half.
				var lc *LoginClass
				for _, existing := range sys.Login.Classes {
					if existing != nil && existing.Name == classInst.name {
						lc = existing
						break
					}
				}
				if lc == nil {
					lc = &LoginClass{Name: classInst.name}
					sys.Login.Classes = append(sys.Login.Classes, lc)
				}
				// #8939: `set system login class ops allow-commands "a"
				// allow-configuration "c"` nests the second leaf UNDER the
				// first, so this loop saw ONE child and the class silently lost
				// an ENFORCED allowlist -- and with it the AllowLeavesPresent
				// entry that #7172 keys enforcement on, which turns "restrict
				// this family" into "no rule for this family at all".
				for _, prop := range expandFlatRun(classInst.node.Children, loginClassSchema8939()) {
					// #5831: record RESTRICTIVE leaf PRESENCE from the
					// classification table (compiler_login_deny.go), NOT from
					// the case arms below. Presence, not value: a
					// quoted-empty or valueless deny-commands flattens to ""
					// and would be invisible to a value test, yet an empty
					// regex denies EVERY command in Junos. Driving it from the
					// table means a newly-classified restrictive leaf is gated
					// without also needing a `case` arm here — the missing-arm
					// fail-open the table exists to prevent. Both AST shapes
					// carry the leaf name in Keys[0], so prop.Name() is
					// dual-shape safe, exactly as the switch below relies on.
					if loginClassLeafRestrictive[prop.Name()] {
						lc.DenyLeavesPresent = append(lc.DenyLeavesPresent, prop.Name())
					}
					// #7172 cut 6: the same table-driven PRESENCE record for
					// the ALLOW regexes, now that they are enforced. See
					// AllowLeavesPresent for why an empty allow is not the same
					// as an absent one once a deny is present too.
					if loginClassLeafAllowRegex[prop.Name()] {
						lc.AllowLeavesPresent = append(lc.AllowLeavesPresent, prop.Name())
					}
					switch prop.Name() {
					case "permissions":
						lc.Permissions = append(lc.Permissions, firewallMatchValues(prop)...)
					case "idle-timeout":
						lc.IdleTimeoutSet = true
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								lc.IdleTimeout = n
							}
						}
					case "allow-commands":
						lc.AllowCommands = nodeVal(prop)
						recordLoginClassRegexValue15712(lc, "allow-commands", nodeVal(prop))
					case "deny-commands":
						// Value only. PRESENCE is recorded above, off
						// loginClassLeafRestrictive, because the value cannot
						// carry it: a quoted-empty or valueless deny-commands
						// flattens to "" yet denies EVERY command in Junos.
						lc.DenyCommands = nodeVal(prop)
						recordLoginClassRegexValue15712(lc, "deny-commands", nodeVal(prop))
					case "allow-configuration":
						lc.AllowConfiguration = nodeVal(prop)
						recordLoginClassRegexValue15712(lc, "allow-configuration", nodeVal(prop))
					case "deny-configuration":
						lc.DenyConfiguration = nodeVal(prop)
						recordLoginClassRegexValue15712(lc, "deny-configuration", nodeVal(prop))
					}
				}
				lc.MappedPermissions, _ = mapJunosPermissions(lc.Permissions)
			}
			// #6992: a user NAME authored in two blocks folds into ONE entry.
			//
			// Without the fold both blocks survive in Login.Users and two
			// readers pick different ones: pkg/cli configuredClass returns the
			// FIRST block with a non-empty class, while pkg/daemon
			// applySystemLogin iterates every block in order, so the account
			// state that lands (password, authorized_keys) comes from the LAST.
			// Measured on a config that commits CLEAN at strict: with
			// `class admins` first and `class ops` second, the SSH key the
			// operator wrote under the VIEW-only block authenticates and the
			// CLI then grants super-user. The authorization decision and the
			// credential that reaches it come from different blocks.
			//
			// The fold is per-LEAF last-authored-wins because that is what the
			// FLAT spelling already produces — SetPath merges `set system login
			// user alice ...` written twice onto one node, replacing each leaf —
			// so folding makes the two AST shapes agree rather than inventing a
			// third answer. This is the #5180 dual-AST-equivalence property, and
			// the same reasoning as the #6838 cohort fold one stanza over: make
			// the outcome INDEPENDENT of which reader picks, rather than
			// teaching one reader the other's tie-break, which is a proxy that
			// rots the day the other reader changes. Here it is stronger than a
			// matched tie-break: after the fold there is no tie to break.
			//
			// Deliberately NOT applied to `class`: #6838 already made the class
			// cohort reader-independent by folding permissions across it, and a
			// merge here would fight that design.
			userByName := loginUserByName
			for _, userInst := range namedInstances(child.FindChildren("user")) {
				user := userByName[userInst.name]
				if user == nil {
					user = &LoginUser{Name: userInst.name}
					userByName[userInst.name] = user
					sys.Login.Users = append(sys.Login.Users, user)
				}
				// A later block's `authentication` section replaces the earlier
				// block's PASSWORD wholesale — a scalar, last-writer-wins, the
				// same rule uid and class follow just below.
				//
				// #8863 CHANGED THE KEY HALF, and the distinction is the point:
				// authorized keys are a SET, not a scalar. #6992 originally
				// cleared SSHKeys here too, and it DERIVED that from what the
				// flat spelling did at the time — the flat path then replaced on
				// a repeated `set … ssh-rsa`, so matching it meant clearing.
				//
				// That flat behaviour was itself the #8863 defect: a second
				// `set system root-authentication ssh-ed25519` REVOKED the first
				// key, and applyRootAuth writes the compiled set as the whole of
				// authorized_keys, so the first administrator lost access at the
				// next apply. With the flat path corrected to accumulate, the
				// derivation that produced this reset is stale — so the reset
				// goes and the two spellings agree again on [FIRST, SECOND].
				//
				// #6992's own decision is untouched: uid, class and the password
				// still take the LAST authored value, which is what its comment
				// justified from applySystemLogin rewriting per entry. Only the
				// key expectation moved, and it moved because the thing it was
				// derived from moved.
				// #9391: expand the flat-set run ONCE and read it in BOTH loops
				// below, so the authentication probe and the property switch
				// cannot see different sets.
				//
				// #9391 fixed the earlier flat-set omission: a user run such as
				// `uid 2001 class read-only` must preserve both leaves when the
				// tolerant compiler reads already-stored configuration. #11826
				// types uid as a positive integer; strict compilation rejects an
				// invalid value, while tolerant compilation marks it with a
				// negative sentinel so apply cannot mistake it for an omitted UID
				// (zero) and request automatic allocation.

				// expandFlatRun rather than hoistAndSplitRun8939 DELIBERATELY:
				// the stronger helper descends into a container leaf's body, and
				// `authentication` is one whose packed spelling the #6662 gate
				// exists to REJECT. Lifting out of it would make the lenient path
				// compile a shape the strict path refuses. The run this defect
				// needs is a chain of the container's OWN leaves, which
				// expandFlatRun covers, and it leaves `authentication` exactly as
				// authored.
				userProps := expandFlatRun(userInst.node.Children, loginUserSchema9391())
				authoredAuth := false
				for _, prop := range userProps {
					if prop.Name() == "authentication" {
						authoredAuth = true
						break
					}
				}
				if authoredAuth {
					user.EncryptedPassword = NewSecret("")
				}
				// #16076: `system login user root authentication …` is inert.
				// The daemon never creates/modifies root via `login user`
				// (applySystemLogin and the sudoers sweep both skip root);
				// root's password and SSH keys come only from
				// `system root-authentication` (applyRootAuth). Without this
				// warning the stanza compiles silently and an operator can
				// believe root is key/password-locked when it is not. The
				// `class`/`uid` leaves on `user root` are NOT inert (class is
				// honoured for the CLI class decision), so only an authored
				// `authentication` child triggers this. Emit on both strict
				// and tolerant paths: cfg.Warnings surfaces at commit-check
				// and on load, so the false assurance is removed everywhere.
				if user.Name == "root" && authoredAuth && cfg != nil {
					cfg.Warnings = append(cfg.Warnings,
						"system login user root authentication is ignored: "+
							"root credentials are not applied from `system login user root`; "+
							"use `system root-authentication` (encrypted-password / ssh-*) "+
							"to set root's password and SSH keys (#16076)")
				}
				for _, prop := range userProps {
					switch prop.Name() {
					case "uid":
						raw := nodeVal(prop)
						uid, uidErr := strconv.Atoi(raw)
						if uidErr == nil && uid > 0 {
							user.UID = uid
							break
						}
						msg := fmt.Sprintf("system login user %s uid %q must be a positive integer", user.Name, raw)
						if opts.lenientSystemLoginUID11826 {
							// Negative is an internal invalid-value sentinel: zero
							// means no UID was authored and asks useradd to allocate one.
							user.UID = -1
							if cfg != nil {
								cfg.Warnings = append(cfg.Warnings,
									msg+"; refusing automatic UID allocation on apply (#11826)")
							}
							break
						}
						return fmt.Errorf("%s", msg)
					case "class":
						user.Class = nodeVal(prop)
					case "authentication":
						// Children-only is CORRECT here, unlike the sibling
						// sites fixed for #6818/#6821/#6822. The compact
						// spelling `authentication encrypted-password "$6$..."`
						// is REJECTED at commit by the #6662 packed-login-body
						// gate, which names the rewrite; on the tolerant load /
						// peer-sync path it is a warning and the stanza stays
						// inert, deliberately, so a peer-synced config behaves
						// exactly as the older binary made it behave (#1960).
						// Compiling the value here would silently reverse that
						// decision and change RBAC on the HA sync path.
						for _, authChild := range prop.Children {
							switch authChild.Name() {
							case "encrypted-password":
								user.EncryptedPassword = NewSecret(nodeVal(authChild))
							case "ssh-ed25519", "ssh-rsa", "ssh-dsa":
								// #8863: read EVERY value; see sshKeyValues.
								user.SSHKeys = append(user.SSHKeys, sshKeyValues(authChild)...)
							}
						}
					}
				}
			}
		case "backup-router":
			if len(child.Keys) >= 2 {
				sys.BackupRouter = child.Keys[1]
			}
			// #15780: retain EVERY destination prefix. Junos spells the
			// list three ways and all must compile to the same set:
			//   - packed flat: `backup-router <nh> destination p1` — the
			//     values ride on child.Keys after "destination"; a bracket
			//     list packs further values onto a child of the
			//     destination node (see below);
			//   - hierarchical: one `destination` child per prefix, each
			//     carrying its values on Keys[1:] plus any bracket child.
			// The old scalar read kept only the first packed value (or
			// the last repeated leaf), silently dropping the rest and
			// bypassing validateBackupRouterDst on them.
			var dsts []string
			for i, k := range child.Keys {
				if k == "destination" {
					dsts = append(dsts, child.Keys[i+1:]...)
					break
				}
			}
			for _, dstNode := range child.FindChildren("destination") {
				dsts = append(dsts, firewallMatchValues(dstNode)...)
			}
			// #15944 H21-01: ACCUMULATE across backup-router nodes, do
			// not reset. A second node — a bare next-hop update
			// (`backup-router <nh2>;` with no destination), a sibling
			// destination statement, or a second top-level `system`
			// root re-entering compileSystem via per-root dispatch —
			// previously truncated the list to that one node's
			// destinations, and a bare node wiped it entirely, so the
			// management-VRF builder fell back to the implicit
			// family default route instead of the authored prefixes.
			// Deduplicate exact repeats across the accumulated set (a
			// bracket list repeated as a second leaf installs one
			// route, not two identical ones).
			seenDst := make(map[string]bool, len(sys.BackupRouterDsts)+len(dsts))
			for _, d := range sys.BackupRouterDsts {
				seenDst[d] = true
			}
			for _, d := range dsts {
				if d == "" || seenDst[d] {
					continue
				}
				seenDst[d] = true
				sys.BackupRouterDsts = append(sys.BackupRouterDsts, d)
			}
			if len(sys.BackupRouterDsts) > 0 {
				sys.BackupRouterDst = sys.BackupRouterDsts[0]
			}
		case "commit":
			for _, key := range child.Keys[1:] {
				if key == "persist-groups-inheritance" {
					sys.PersistGroupsInheritance = true
				}
			}
			if child.FindChild("persist-groups-inheritance") != nil {
				sys.PersistGroupsInheritance = true
			}
		case "root-authentication":
			// #15018: allocate ONCE. A repeated block — or a second
			// `system` root, which re-enters compileSystem — must
			// accumulate into the same stanza (the #6957 `login` shape):
			// keys append below, and the password is replaced only when
			// the later block actually authors one. Reallocating reset
			// the stanza, so applyRootAuth then revoked the earlier
			// block's keys and could lock an xpf-provisioned root
			// password after a successful commit.
			if sys.RootAuthentication == nil {
				sys.RootAuthentication = &RootAuthConfig{}
			}
			for _, prop := range child.Children {
				switch prop.Name() {
				case "encrypted-password":
					sys.RootAuthentication.EncryptedPassword = NewSecret(nodeVal(prop))
				case "ssh-ed25519", "ssh-rsa", "ssh-dsa":
					// #8863: read EVERY value, not slot 0. These leaves are
					// multi:true, so repeated `set` lines for one key type
					// accumulate onto this node instead of replacing.
					sys.RootAuthentication.SSHKeys = append(sys.RootAuthentication.SSHKeys, sshKeyValues(prop)...)
				}
			}
		case "archival":
			// #15018: allocate ONCE, defaults only on first allocation;
			// sites append below and scalars apply only when authored,
			// so a repeated block cannot erase an earlier block's sites.
			if sys.Archival == nil {
				sys.Archival = &ArchivalConfig{
					ArchiveDir:  "/var/lib/xpf/archive",
					MaxArchives: 10,
				}
			}
			// #15710: iterate EVERY `configuration` child, not just the
			// first. Two `configuration` blocks under one `archival`
			// (or a packed second block the FindChild-only read missed)
			// must merge: transfer-on-commit is sticky-true, archive
			// sites append, and transfer-interval is last-wins across
			// all blocks. Each block's body is expanded via
			// packedBodyChildren so the compact spelling
			// `configuration transfer-on-commit` (tail packed onto the
			// configuration node's Keys, no children) reads the same
			// as the braced spelling.
			for _, origCfgNode := range child.FindChildren("configuration") {
				cfgNode := origCfgNode
				// #8939: split a packed run. `archival configuration
				// transfer-on-commit transfer-interval 30` is ONE child node
				// carrying both on its Keys, so the first FindChild matched and
				// the interval was dropped — an archive that uploads on commit
				// but never on a schedule, or the reverse.
				if expanded := packedBodyChildren(cfgNode, archivalConfigurationSchema8939()); len(expanded) != len(cfgNode.Children) || (len(expanded) > 0 && len(cfgNode.Children) == 0) {
					clone := *cfgNode
					clone.Children = expanded
					cfgNode = &clone
				} else if expanded := expandFlatRun(cfgNode.Children, archivalConfigurationSchema8939()); len(expanded) != len(cfgNode.Children) {
					clone := *cfgNode
					clone.Children = expanded
					cfgNode = &clone
				}
				if cfgNode.FindChild("transfer-on-commit") != nil {
					sys.Archival.TransferOnCommit = true
				}
				for _, tiNode := range cfgNode.FindChildren("transfer-interval") {
					if v := nodeVal(tiNode); v != "" {
						if n, ok := parseIntLeaf(&cfg.Warnings, "system archival configuration transfer-interval", v); ok {
							sys.Archival.TransferInterval = n
						}
					}
				}
				for _, asNode := range cfgNode.FindChildren("archive-sites") {
					// #6692: archiveSiteEntries reads EVERY authored site
					// across all four AST shapes, so a bracketed list is no
					// longer truncated to its first member. The two things the
					// pre-#6692 warning in this spot demanded of a widening
					// reader are both satisfied here: the `password <secret>`
					// modifier is separated from the URL stream by
					// archiveSiteEntries (it is never promoted to a site), and
					// the #4589 leading-dash gate below now runs over EVERY
					// site rather than slot 1 alone — so widening the read
					// closes the gate escape instead of arming it.
					for _, site := range archiveSiteEntries(asNode) {
						// Reject URL-embedded passwords at commit: scp is
						// invoked with BatchMode=yes, so the password cannot
						// authenticate and otherwise reaches process argv and logs.
						if URLHasPassword(site.url) {
							return fmt.Errorf("system archival archive-sites %q: inline URL password is not supported; use SSH key authentication", RedactURL(site.url))
						}
						// #14691: require a remote scp destination. A
						// colon-less or otherwise local destination makes
						// OpenSSH scp perform a LOCAL copy of the unredacted
						// ShowActive() staging file as root, overwriting an
						// arbitrary local file and disclosing every secret
						// in it — bypassing the #10298 host-key check, which
						// a local copy never consults. The shared validator
						// also carries the #4589 leading-dash gate (a
						// `-`-prefixed destination is parsed by scp getopt
						// as an option, including the user@-oProxyCommand
						// host-position form).
						if err := ArchiveDestinationError(site.url); err != nil {
							return err
						}
						sys.Archival.ArchiveSites = append(sys.Archival.ArchiveSites, site.url)
						if site.hasPassword {
							sys.Archival.ArchiveSitesWithPassword = append(
								sys.Archival.ArchiveSitesWithPassword, site.url)
						}
					}
				}
			}
		case "master-password":
			if prfNode := child.FindChild("pseudorandom-function"); prfNode != nil {
				sys.MasterPassword = nodeVal(prfNode)
			}
		case "license":
			// #15782: retain EVERY url, not just one. `url` is multi:true
			// so flat-set repeats stay siblings; hier repeats are siblings
			// too; a bracket list packs onto one node's Keys/children and
			// plainListValues reads all shapes. Scalar keeps first.
			for _, auNode := range child.FindChildren("autoupdate") {
				for _, urlNode := range auNode.FindChildren("url") {
					for _, u := range plainListValues(urlNode) {
						sys.LicenseAutoUpdateURLs = append(sys.LicenseAutoUpdateURLs, u)
					}
				}
				// Brace-elided `autoupdate { url a; }` packed on Keys handled
				// by FindChildren above via expanded children; also cover
				// `autoupdate url a` packed on the autoupdate node's Keys.
				if len(auNode.Children) == 0 && len(auNode.Keys) >= 3 && auNode.Keys[1] == "url" {
					sys.LicenseAutoUpdateURLs = append(sys.LicenseAutoUpdateURLs, auNode.Keys[2:]...)
				}
			}
			if len(child.Children) == 0 && len(child.Keys) >= 4 && child.Keys[1] == "autoupdate" && child.Keys[2] == "url" {
				sys.LicenseAutoUpdateURLs = append(sys.LicenseAutoUpdateURLs, child.Keys[3:]...)
			}
			if len(sys.LicenseAutoUpdateURLs) > 0 {
				sys.LicenseAutoUpdate = sys.LicenseAutoUpdateURLs[0]
			}
		case "processes":
			for _, proc := range child.Children {
				if proc.FindChild("disable") != nil || nodeVal(proc) == "disable" {
					sys.DisabledProcesses = append(sys.DisabledProcesses, proc.Name())
				}
			}
		case "internet-options":
			// #15018: allocate ONCE; the flag below is only ever set,
			// never cleared, so a repeated empty block must not reset it.
			if sys.InternetOptions == nil {
				sys.InternetOptions = &InternetOptionsConfig{}
			}
			// #15707: accept the leaf in every spelling — braced child,
			// packed on the internet-options line (`internet-options
			// no-ipv6-reject-zero-hop-limit;`, whose tokens ride
			// child.Keys[1:]), or nested under a packed run. FindChild
			// alone dropped the compact spelling.
			if child.FindChild("no-ipv6-reject-zero-hop-limit") != nil {
				sys.InternetOptions.NoIPv6RejectZeroHopLimit = true
			}
			for _, k := range child.Keys[1:] {
				if k == "no-ipv6-reject-zero-hop-limit" {
					sys.InternetOptions.NoIPv6RejectZeroHopLimit = true
				}
			}
			for _, c := range packedBodyChildren(child, refSystemInternetOptions.resolve()) {
				if c.Name() == "no-ipv6-reject-zero-hop-limit" {
					sys.InternetOptions.NoIPv6RejectZeroHopLimit = true
				}
			}
		case "dataplane":
			switch effectiveDataplaneType(sys.DataplaneType) {
			case dataplaneTypeUserspace:
				if sys.UserspaceDataplane == nil {
					sys.UserspaceDataplane = &UserspaceConfig{}
				}
				if err := compileUserspaceDataplane(child, sys.UserspaceDataplane, &cfg.Warnings); err != nil {
					return err
				}
			case dataplaneTypeEBPF:
				// The legacy eBPF dataplane has no system dataplane sub-stanza.
			case dataplaneTypeDPDK:
				// DPDK retired in #1525 / #1528. This branch is reachable
				// only from a direct CompileConfig call on a tree that still
				// carries a `dataplane-type dpdk` leaf — i.e., a commit-path
				// candidate. Store.Load and Store.SyncApply both call
				// rewriteRetiredDataplaneType before compile, which strips
				// the `dataplane-type dpdk` leaf so sys.DataplaneType == ""
				// (→ userspace) and this branch is never entered; the
				// sub-stanza children hit compileUserspaceDataplane instead
				// and are silently dropped there as unknown keys.
				//
				// For the direct-compile case the sub-stanza children
				// (cores, memory, socket-mem, rx-mode, ports) are silently
				// dropped here because the DPDKConfig type is deleted.
				// validateDataplaneTypeStrict in compileExpanded fires
				// immediately after compileSystem and returns
				// ErrDPDKDataplaneRetired, so the no-op here is inconsequential.
			}
		case "syslog":
			if sys.Syslog == nil {
				sys.Syslog = &SystemSyslogConfig{}
			}
			// #9414: every modifier the destination arms below recognize and
			// skip is recorded here and reported once after this walk.
			skipped := syslogSkippedModifiers9414{}
			// #9854: FIND-OR-CREATE on the host address, not one struct per
			// AST node. Two `host <addr>` statements naming one address —
			// authored inline as hierarchical siblings, produced by group
			// expansion beside an inline statement, or split across a
			// flat-set bare leaf plus a body container (SetPath keeps the
			// `host X` leaf and the `host X ...` container as separate
			// nodes: the leaf branch at ast_edit.go:508-553 never matches
			// the container find-or-create at ast_edit.go:720-738) —
			// compiled as TWO destinations, so a message matching both was
			// sent to the same address once per statement. Junos merges
			// repeated blocks; zones (#4818) and BGP neighbors (#9192)
			// already find-or-create for the same reason. The #8436 census
			// skips this site (dupConservationSkipped8436), so the
			// divergence was measured by hand.
			//
			// Precedence is apply-groups precedence, not position.
			// Expansion appends adopted group nodes AFTER inline nodes, so
			// a plain last-wins would let a group's scalar beat the inline
			// block's explicit value — the opposite of Junos and of the
			// repo's typed-merge rule (ast_groups.go:385-386, "inline
			// OVERRIDES the group value"). The compile expands tagged, so
			// each instance node carries its provenance: an INLINE scalar
			// always records (last inline wins, matching flat-set `set`
			// overwrite); an INHERITED scalar records only when nothing
			// did yet (first group wins, matching the expansion's
			// peer-override for scalar leaves). allow-duplicates is OR.
			// Facilities UNION in first-seen order with exact-pair
			// duplicates dropped — flat-set skips an exact duplicate leaf,
			// so `set ... any any` twice is one pair and the hierarchical
			// spelling must be too. First-seen host order is preserved:
			// the append runs only when the address is first seen. A
			// caller that pre-expands untagged and then compiles (no
			// production path does — the compile expands a tagged clone)
			// gets last-wins among same-address siblings.
			//
			// Provenance is read per INSTANCE (slInst.node), never per
			// prop: packedBodyChildren synthesizes the prop nodes from the
			// instance's Keys, and synthesized nodes carry no tags. A mixed
			// container (a group braced body merged into an inline braced
			// host by the expansion's container path) needs no per-child
			// tags either — expansion drops a conflicting group scalar
			// before it lands, so a group scalar present in the container
			// has no inline rival by construction.
			//
			// One boundary is position-dependent, not precedence-ordered:
			// group-vs-group across MIXED shapes. A packed earlier-group
			// node is adopted as a sibling AFTER the inline container,
			// while a braced later-group body merges INTO that container
			// ahead of it — so the later group's value sorts first and the
			// first-inherited-wins rule keeps it (measured: G1 packed 111
			// + G2 braced 222 + inline merges to 222). Same-shape groups
			// resolve correctly (packed+packed drops the later at
			// expansion; braced+braced merges with the first winning).
			// Recovering application order across the mixed shapes needs
			// ordinal provenance, which InheritedFrom does not carry;
			// until then the outcome is defined but positional.
			// Deliberately unpinned: no test enshrines it.
			hostByAddr := make(map[string]*syslogHostCoalesce9854, len(sys.Syslog.Hosts))
			for _, host := range sys.Syslog.Hosts {
				rec := &syslogHostCoalesce9854{
					host:    host,
					srcSet:  host.SourceAddress != "",
					portSet: host.Port != 0,
					seenFac: make(map[SyslogFacility]struct{}, len(host.Facilities)),
				}
				for _, facility := range host.Facilities {
					rec.seenFac[facility] = struct{}{}
				}
				hostByAddr[host.Address] = rec
			}
			for _, slInst := range namedInstances(child.FindChildren("host")) {
				rec := hostByAddr[slInst.name]
				if rec == nil {
					rec = &syslogHostCoalesce9854{
						host:    &SyslogHostConfig{Address: slInst.name},
						seenFac: map[SyslogFacility]struct{}{},
					}
					hostByAddr[slInst.name] = rec
					sys.Syslog.Hosts = append(sys.Syslog.Hosts, rec.host)
				}
				host := rec.host
				// Per-instance provenance (see above): a whole adopted
				// group node is inherited; an inline node is not.
				inherited := slInst.node.InheritedFrom != ""
				// #6684: `host 10.0.0.1 any any;` packs the whole body onto the
				// host node's Keys, leaving Children empty — the host compiled
				// with ZERO facilities and shipped nothing, silently.
				// #9414: hoistAndSplitRun8939, because a flat-set line carrying
				// two host statements (`set ... host X allow-duplicates
				// exclude-hostname`) is built by SetPath as a NESTED chain, and
				// the trailing statement was dropped unread (#8939). It was
				// invisible while every skipped modifier was inert; the #9414
				// advisory made the loss observable. Hoisted against the
				// destination schema WITHOUT its facility wildcard; see
				// syslogDestinationHoistSchema9414.
				hostSchema := refSyslogHost.resolve()
				for _, prop := range hoistAndSplitRun8939(
					packedBodyChildren(slInst.node, hostSchema), syslogDestinationHoistSchema9414("host")) {
					// #4303 S-1: switch on the KNOWN host sub-statements
					// before the facility/severity fallback. Without this
					// every non-`allow-duplicates` child (source-address,
					// port, match, structured-data, ...) was captured as a
					// bogus SyslogFacility{Facility:Keys[0], Severity:Keys[1]}
					// that polluted the facility filter — applySystemSyslog
					// reads Facilities[0].Facility, so a leading
					// `source-address` set the whole client's facility to
					// garbage.
					switch prop.Name() {
					case "allow-duplicates":
						host.AllowDuplicates = true
					case "source-address":
						// Guarded so a valueless repeat cannot wipe the
						// address a previous instance set (#9854 merge).
						// Behavior-preserving for a single instance: a
						// fresh struct already holds "".
						if v := nodeVal(prop); v != "" {
							// Inline always records (last inline wins);
							// inherited records only first (see above).
							if !inherited || !rec.srcSet {
								host.SourceAddress = v
								rec.srcSet = true
							}
						}
					case "port":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								// Same precedence as source-address.
								if !inherited || !rec.portSet {
									host.Port = n
									rec.portSet = true
								}
							}
						}
					case "match", "match-strings", "structured-data",
						"explicit-priority", "log-prefix", "facility-override",
						"routing-instance", "exclude-hostname":
						// Recognized Junos host modifiers that are NOT
						// facility/severity pairs. Accepted so a valid
						// config commits; not wired into the runtime syslog
						// client. #9414: recorded here, at the skip, so the
						// advisory names exactly what this arm drops.
						skipped.note("host", prop.Name())
					default:
						if fac, sev, ok := syslogFacilitySeverity(prop); ok {
							pair := SyslogFacility{Facility: fac, Severity: sev}
							// Exact-pair dedupe: flat-set skips a
							// repeated leaf, so hier must too (#9854).
							if _, dup := rec.seenFac[pair]; !dup {
								rec.seenFac[pair] = struct{}{}
								host.Facilities = append(host.Facilities, pair)
							}
						}
					}
				}
			}
			// #15708: coalesce files by name like hostByAddr (#9854), and
			// expand packed tails (#6684) matching host.
			fileByName := make(map[string]*syslogFileCoalesce15708, len(sys.Syslog.Files))
			for _, f := range sys.Syslog.Files {
				rec := &syslogFileCoalesce15708{file: f, seen: make(map[SyslogFacility]struct{}, len(f.Selectors))}
				for _, s := range f.Selectors {
					rec.seen[s] = struct{}{}
				}
				fileByName[f.Name] = rec
			}
			for _, fileInst := range namedInstances(child.FindChildren("file")) {
				rec := fileByName[fileInst.name]
				if rec == nil {
					rec = &syslogFileCoalesce15708{file: &SyslogFileConfig{Name: fileInst.name}, seen: map[SyslogFacility]struct{}{}}
					fileByName[fileInst.name] = rec
					sys.Syslog.Files = append(sys.Syslog.Files, rec.file)
				}
				file := rec.file
				archiveKnobs := map[string]bool{}
				for _, knob := range file.ArchiveKnobs {
					archiveKnobs[knob] = true
				}
				// #9414 / #8939: read every statement of a flat-set chain.
				// #15708: packedBodyChildren expands compact `file f fac sev;`.
				for _, prop := range hoistAndSplitRun8939(
					packedBodyChildren(fileInst.node, refSyslogFile.resolve()),
					syslogDestinationHoistSchema9414("file")) {
					switch prop.Name() {
					case "archive":
						file.ArchiveConfigured = true
						for _, knob := range syslogArchiveKnobs(prop) {
							archiveKnobs[knob] = true
						}
					case "match", "match-strings", "structured-data",
						"explicit-priority", "allow-duplicates":
						skipped.note("file", prop.Name())
					default:
						if fac, sev, ok := syslogFacilitySeverity(prop); ok {
							pair := SyslogFacility{Facility: fac, Severity: sev}
							if _, dup := rec.seen[pair]; !dup {
								rec.seen[pair] = struct{}{}
								file.Selectors = append(file.Selectors, pair)
							}
						}
					}
				}
				if len(archiveKnobs) > 0 {
					file.ArchiveKnobs = make([]string, 0, len(archiveKnobs))
					for knob := range archiveKnobs {
						file.ArchiveKnobs = append(file.ArchiveKnobs, knob)
					}
					sort.Strings(file.ArchiveKnobs)
				}
			}
			// Parse user destinations: user * { any emergency; }
			// #15708: coalesce by user and expand packed tails.
			userByName := make(map[string]*syslogUserCoalesce15708, len(sys.Syslog.Users))
			for _, u := range sys.Syslog.Users {
				rec := &syslogUserCoalesce15708{user: u, seen: make(map[SyslogFacility]struct{}, len(u.Selectors))}
				for _, s := range u.Selectors {
					rec.seen[s] = struct{}{}
				}
				userByName[u.User] = rec
			}
			for _, userInst := range namedInstances(child.FindChildren("user")) {
				rec := userByName[userInst.name]
				if rec == nil {
					rec = &syslogUserCoalesce15708{user: &SyslogUserConfig{User: userInst.name}, seen: map[SyslogFacility]struct{}{}}
					userByName[userInst.name] = rec
					sys.Syslog.Users = append(sys.Syslog.Users, rec.user)
				}
				user := rec.user
				for _, prop := range hoistAndSplitRun8939(
					packedBodyChildren(userInst.node, refSyslogUser.resolve()),
					syslogDestinationHoistSchema9414("user")) {
					switch prop.Name() {
					case "match", "match-strings", "structured-data",
						"explicit-priority", "allow-duplicates":
						skipped.note("user", prop.Name())
					default:
						if fac, sev, ok := syslogFacilitySeverity(prop); ok {
							pair := SyslogFacility{Facility: fac, Severity: sev}
							if _, dup := rec.seen[pair]; !dup {
								rec.seen[pair] = struct{}{}
								user.Selectors = append(user.Selectors, pair)
							}
						}
					}
				}
			}
			// #15709: top-level syslog statements. Expand packed/chained
			// shapes, inherit source-address, record inert globals.
			{
				syslogTop := hoistAndSplitRun8939(packedBodyChildren(child, refSyslog.resolve()), refSyslog.resolve())
				inert := map[string]bool{}
				for _, kw := range sys.Syslog.TopLevelInert {
					inert[kw] = true
				}
				for _, top := range syslogTop {
					switch top.Name() {
					case "source-address":
						if v := nodeVal(top); v != "" {
							sys.Syslog.DefaultSourceAddress = v
						}
						// Packed value on Keys of syslog node itself.
						if len(top.Keys) >= 2 && top.Name() == "source-address" {
							sys.Syslog.DefaultSourceAddress = top.Keys[len(top.Keys)-1]
						}
					case "console":
						inert["console"] = true
						for _, prop := range hoistAndSplitRun8939(packedBodyChildren(top, refSyslogConsole.resolve()), syslogDestinationHoistSchema9414("host")) {
							switch prop.Name() {
							case "match", "match-strings", "structured-data", "explicit-priority", "allow-duplicates":
								skipped.note("console", prop.Name())
							}
						}
					case "time-format":
						inert["time-format"] = true
					case "archive":
						inert["archive"] = true
					case "log-rotate-frequency":
						inert["log-rotate-frequency"] = true
					}
				}
				// Also scan raw children/Keys for shapes packedBodyChildren missed.
				for _, c := range child.Children {
					switch c.Name() {
					case "console", "time-format", "archive", "log-rotate-frequency":
						inert[c.Name()] = true
					case "source-address":
						if v := nodeVal(c); v != "" {
							sys.Syslog.DefaultSourceAddress = v
						}
					}
				}
				for i := 1; i < len(child.Keys); i++ {
					switch child.Keys[i] {
					case "console", "time-format", "archive", "log-rotate-frequency":
						inert[child.Keys[i]] = true
					case "source-address":
						if i+1 < len(child.Keys) {
							sys.Syslog.DefaultSourceAddress = child.Keys[i+1]
						}
					}
				}
				if len(inert) > 0 {
					sys.Syslog.TopLevelInert = sys.Syslog.TopLevelInert[:0]
					for kw := range inert {
						sys.Syslog.TopLevelInert = append(sys.Syslog.TopLevelInert, kw)
					}
					sort.Strings(sys.Syslog.TopLevelInert)
				}
				if sys.Syslog.DefaultSourceAddress != "" {
					for _, h := range sys.Syslog.Hosts {
						if h.SourceAddress == "" {
							h.SourceAddress = sys.Syslog.DefaultSourceAddress
						}
					}
				}
				for _, kw := range sys.Syslog.TopLevelInert {
					skipped.note("top-level", kw)
				}
			}
			if cfg != nil {
				cfg.Warnings = append(cfg.Warnings, skipped.warnings()...)
			}
		}
	}

	var svcNode *Node
	var sshNode *Node
	var serviceChildren []*Node
	for _, child := range systemChildren {
		if child.Name() != "services" {
			continue
		}
		serviceChildren = append(serviceChildren,
			packedBodyChildren(child, refSystemServices.resolve())...)
	}
	// #15716: also unpack a header-packed `system services ssh
	// root-login <val>` even when braced `services` children exist, so
	// the lenient last-wins reader (and strict gate, via the pooled
	// values) sees the header value instead of silently discarding it.
	if len(node.Keys) > 1 && node.Keys[1] == "services" {
		for _, services := range packedBodyChildren(node, systemSchema9792()) {
			if services.Name() == "services" {
				serviceChildren = append(serviceChildren,
					packedBodyChildren(services, refSystemServices.resolve())...)
			}
		}
		if v, ok := headerPackedRootLogin15716(node.Keys); ok {
			// Prepend the header ssh unless packed expansion already
			// produced an ssh carrying this root-login value.
			found := false
			for _, c := range serviceChildren {
				if c == nil || c.Name() != "ssh" {
					continue
				}
				if len(c.Keys) >= 3 && c.Keys[1] == "root-login" && c.Keys[2] == v {
					found = true
					break
				}
				for _, rl := range c.FindChildren("root-login") {
					if len(rl.Keys) >= 2 && rl.Keys[1] == v {
						found = true
						break
					}
				}
			}
			if !found {
				serviceChildren = append([]*Node{{Keys: []string{"ssh", "root-login", v}}}, serviceChildren...)
			}
		}
	}
	if len(serviceChildren) > 0 {
		svcNode = &Node{Keys: []string{"services"}}
		var sshNodes []*Node
		for _, child := range serviceChildren {
			if child.Name() == "ssh" {
				sshNodes = append(sshNodes, child)
				continue
			}
			svcNode.Children = append(svcNode.Children, child)
		}
		switch len(sshNodes) {
		case 1:
			// Preserve the existing normalizer path for a single SSH block.
			sshNode = sshNodes[0]
		case 0:
		default:
			sshNode = &Node{Keys: []string{"ssh"}}
			for _, child := range sshNodes {
				sshNode.Children = append(sshNode.Children,
					packedBodyChildren(child, refSystemServicesSSH.resolve())...)
			}
		}
		if sshNode != nil {
			svcNode.Children = append(svcNode.Children, sshNode)
		}
	}
	if svcNode != nil {
		dhcpNode := svcNode.FindChild("dhcp-local-server")
		if dhcpNode != nil {
			if err := compileDHCPLocalServer(dhcpNode, &sys.DHCPServer, false); err != nil {
				return err
			}
		}
		dhcp6Node := svcNode.FindChild("dhcpv6-local-server")
		if dhcp6Node != nil {
			if err := compileDHCPLocalServer(dhcp6Node, &sys.DHCPServer, true); err != nil {
				return err
			}
		}
		// SSH service
		if sshNode := svcNode.FindChild("ssh"); sshNode != nil {
			if sys.Services == nil {
				sys.Services = &SystemServicesConfig{}
			}
			if sys.Services.SSH == nil {
				sys.Services.SSH = &SSHServiceConfig{}
			}
			// #9235: `ssh client-alive-interval 30 client-alive-count-max 3
			// connection-limit 10` is ONE command nested into a chain, so the
			// FindChild reads below saw the first knob and missed the rest --
			// sshd kept its defaults for hardening knobs the config declared.
			// Expanded once, for the same reason compileLog does. Lenient path only.
			sshNode = expandRun9235(sshNode, systemServicesSSHSchema9235())
			// #14447: last sibling wins (Junos). Conflicting duplicates
			// are strict-rejected / lenient-warned by
			// validateDuplicateRootLoginAST; this keeps lenient = last.
			for _, rl := range sshNode.FindChildren("root-login") {
				if len(rl.Keys) >= 2 {
					sys.Services.SSH.RootLogin = rl.Keys[1]
				}
			}
			// #6692: key-exchange is `multi: true` and the operator lists
			// methods in PREFERENCE order, so a bracketed list truncated to
			// slot 0 pinned sshd to the FIRST (often the weaker legacy) method
			// and silently discarded the modern one the operator added — a
			// hardening change that appears applied and is not. Read every
			// value via firewallMatchValues, exactly as the ciphers/macs
			// siblings below already do. Widening is safe on the injection axis
			// because validateMultiValueLeaf (schema_walk.go) runs the leaf's
			// ValidateSSHAlgorithm over EVERY token of Keys[1:] and every
			// block-child, not just the first (#4902).
			for _, kx := range sshNode.FindChildren("key-exchange") {
				sys.Services.SSH.KeyExchange = append(sys.Services.SSH.KeyExchange, firewallMatchValues(kx)...)
			}
			// #4305 S-4: SSH hardening knobs. ciphers/macs are repeatable
			// (bracketed list or one-per-child); read every value via
			// firewallMatchValues so a `[ a b c ]` list is not truncated.
			for _, cn := range sshNode.FindChildren("ciphers") {
				sys.Services.SSH.Ciphers = append(sys.Services.SSH.Ciphers, firewallMatchValues(cn)...)
			}
			for _, mn := range sshNode.FindChildren("macs") {
				sys.Services.SSH.MACs = append(sys.Services.SSH.MACs, firewallMatchValues(mn)...)
			}
			if cl := sshNode.FindChild("connection-limit"); cl != nil {
				if n, err := strconv.Atoi(nodeVal(cl)); err == nil {
					sys.Services.SSH.ConnectionLimit = n
				}
			}
			if ci := sshNode.FindChild("client-alive-interval"); ci != nil {
				if n, err := strconv.Atoi(nodeVal(ci)); err == nil {
					sys.Services.SSH.ClientAliveInterval = n
					sys.Services.SSH.ClientAliveIntervalSet = true
				}
			}
			if cc := sshNode.FindChild("client-alive-count-max"); cc != nil {
				if n, err := strconv.Atoi(nodeVal(cc)); err == nil {
					sys.Services.SSH.ClientAliveCountMax = n
					sys.Services.SSH.ClientAliveCountMaxSet = true
				}
			}
			if pv := sshNode.FindChild("protocol-version"); pv != nil {
				sys.Services.SSH.ProtocolVersion = nodeVal(pv)
			}
			// #15282 (V31-S1): boolean leaves, presence is the value.
			if sshNode.FindChild("no-password-authentication") != nil {
				sys.Services.SSH.NoPasswordAuthentication = true
			}
			if sshNode.FindChild("no-passwords") != nil {
				sys.Services.SSH.NoPasswords = true
			}
		}
		// NETCONF over SSH (#15781): declared in the schema, but xpf has
		// no NETCONF daemon. Record the knob so systemInertKnobWarnings
		// can warn and `show system services` can report it as
		// configured-but-not-served instead of a silent no-op; svcNode
		// children carry the packed spellings (#13089 shapes).
		// #15944 H21-03: iterate EVERY `netconf` sibling, not only the
		// first. `netconf { } netconf { ssh; }` under one services node
		// keeps both siblings, and the singular FindChild consulted
		// only the empty first node, so NetconfSSH stayed false and
		// both the show row and the typed-flag warning vanished.
		for _, ncNode := range svcNode.FindChildren("netconf") {
			if blockHasNetconfSSH15781(ncNode) {
				if sys.Services == nil {
					sys.Services = &SystemServicesConfig{}
				}
				sys.Services.NetconfSSH = true
				break
			}
		}
		// DNS service (#15698: iterate every `dns` sibling — a bare
		// `set system services dns` leaf beside a braced dns container
		// is a legitimate two-node shape, and FindChild alone could
		// return the bare leaf and miss the proxy underneath it).

		for _, dnsNode := range svcNode.FindChildren("dns") {
			if sys.Services == nil {
				sys.Services = &SystemServicesConfig{}
			}
			sys.Services.DNSEnabled = true
			if hasDNSProxyChild(dnsNode) {
				sys.Services.DNSProxyConfigured = true
			}
		}
		// Web management
		if wmNode := svcNode.FindChild("web-management"); wmNode != nil {
			if sys.Services == nil {
				sys.Services = &SystemServicesConfig{}
			}
			// #15018 census: allocate ONCE. A second `system` root
			// re-enters here and must merge (flags set, scalars
			// overwritten when authored), not reset the first root's
			// web-management stanza.
			if sys.Services.WebManagement == nil {
				sys.Services.WebManagement = &WebManagementConfig{}
			}
			if httpNode := wmNode.FindChild("http"); httpNode != nil {
				sys.Services.WebManagement.HTTP = true
				if ifNode := httpNode.FindChild("interface"); ifNode != nil {
					sys.Services.WebManagement.HTTPInterface = nodeVal(ifNode)
				}
			}
			if httpsNode := wmNode.FindChild("https"); httpsNode != nil {
				sys.Services.WebManagement.HTTPS = true
				httpsSchema := refWebMgmtHTTPS.resolve()
				for _, prop := range expandFlatRun(packedBodyChildren(httpsNode, httpsSchema), httpsSchema) {
					switch prop.Name() {
					case "system-generated-certificate":
						sys.Services.WebManagement.SystemGeneratedCert = true
					case "certificate":
						sys.Services.WebManagement.TLSCertificate = nodeVal(prop)
					case "private-key":
						sys.Services.WebManagement.TLSPrivateKey = nodeVal(prop)
					case "interface":
						sys.Services.WebManagement.HTTPSInterface = nodeVal(prop)
					}
				}
			}
			// #14448: class/expires are single-valued restrictions read
			// last-wins (Junos semantics); the AST gate
			// validateAPIAuthDuplicateScalarAST rejects conflicting
			// duplicates at strict commit and warns on the tolerant path,
			// so the last sibling is the value both paths install.
			for _, authNode := range wmNode.FindChildren("api-auth") {
				auth := sys.Services.WebManagement.APIAuth
				if auth == nil {
					auth = &APIAuthConfig{DefaultClass: "read-only"}
					sys.Services.WebManagement.APIAuth = auth
				}
				if class := lastAPIAuthClass(authNode); class != "" {
					auth.DefaultClass = class
				}
				if raw, present := lastAPIAuthExpires(authNode); present {
					auth.DefaultExpiresAt, _ = ParseAPIAuthExpiry(raw)
				}
				if authNode.FindChild("metrics-require-auth") != nil {
					auth.MetricsRequireAuth = true
				}
				for _, inst := range namedInstances(authNode.FindChildren("user")) {
					if pwNode := inst.node.FindChild("password"); pwNode != nil {
						class := auth.DefaultClass
						if v := lastAPIAuthClass(inst.node); v != "" {
							class = v
						}
						expires := auth.DefaultExpiresAt
						if raw, present := lastAPIAuthExpires(inst.node); present {
							expires, _ = ParseAPIAuthExpiry(raw)
						}
						auth.Users = append(auth.Users, &APIAuthUser{
							Username:  inst.name,
							Password:  NewSecret(nodeVal(pwNode)),
							Class:     class,
							ExpiresAt: expires,
						})
					}
				}
				// #6692: api-key is `multi: true`, so a bracketed list
				// collapses onto ONE node's Keys and the pre-fix nodeVal read
				// kept slot 0 alone. The values inherit class and expiry from
				// api-auth; named keys can override both.
				for _, ch := range authNode.FindChildren("api-key") {
					for _, key := range multiLeafAuthoredValues(ch) {
						auth.APIKeys = append(auth.APIKeys, NewSecret(key))
					}
				}
				for _, inst := range namedInstances(authNode.FindChildren("key")) {
					secretNode := inst.node.FindChild("secret")
					if secretNode == nil {
						continue
					}
					class := auth.DefaultClass
					if v := lastAPIAuthClass(inst.node); v != "" {
						class = v
					}
					expires := auth.DefaultExpiresAt
					if raw, present := lastAPIAuthExpires(inst.node); present {
						expires, _ = ParseAPIAuthExpiry(raw)
					}
					auth.Keys = append(auth.Keys, &APIAuthKey{
						Name:      inst.name,
						Secret:    NewSecret(nodeVal(secretNode)),
						Class:     class,
						ExpiresAt: expires,
					})
				}
			}
		}
		// system services dynamic-dns — the Surface A provider catalog + engine
		// tunables (#2691 P2, plan §5.9). The per-interface `dynamic-dns`
		// bindings reference these named providers.
		if ddnsNode := svcNode.FindChild("dynamic-dns"); ddnsNode != nil {
			cat, ddnsWarnings, err := compileDDNSServices(ddnsNode, opts.lenientDDNSDuration)
			if err != nil {
				return err
			}
			if cfg != nil {
				cfg.Warnings = append(cfg.Warnings, ddnsWarnings...)
			}
			if cat != nil {
				if sys.Services == nil {
					sys.Services = &SystemServicesConfig{}
				}
				sys.Services.DynamicDNS = cat
			}
		}
	}

	var snmpNodes []*Node
	for _, child := range systemChildren {
		if child.Name() == "snmp" {
			snmpNodes = append(snmpNodes, child)
		}
	}
	if len(node.Keys) > 1 && node.Keys[1] == "snmp" {
		snmpNodes = []*Node{{Keys: node.Keys[1:]}}
	}
	for _, snmpNode := range snmpNodes {
		if err := compileSNMP(snmpNode, sys, cfg, opts.lenientSNMPTrapGroup); err != nil {
			return err
		}
	}

	// #4306 S-5: make the grouped `system` inert knobs (login banner/retry,
	// NTP boot-server/authentication-key/source-address/per-server
	// routing-instance, internet-options extras, ssh rate-limit) loud instead
	// of a silent no-op.
	if cfg != nil {
		cfg.Warnings = append(cfg.Warnings, systemInertKnobWarnings(node, sys)...)
	}

	return nil
}

func compileSystemDataplaneType(node *Node) (string, error) {
	var dpType string
	for _, child := range node.Children {
		if child.Name() != "dataplane-type" || len(child.Keys) < 2 {
			continue
		}
		next := child.Keys[1]
		if !validDataplaneType(next) {
			return "", fmt.Errorf(
				"unknown dataplane-type %q; dataplane-type %q is invalid; "+
					"valid values are userspace or ebpf (deprecated); "+
					"dpdk parses for legacy-config compatibility but is "+
					"rejected at commit per #1525",
				next, next)
		}
		dpType = next
	}
	return dpType, nil
}

// hasDNSProxyChild reports whether a `dns` node carries a `dns-proxy`
// stanza in any authored shape (#15698): as a real child (the braced
// spelling and, after the schema model, the flat-set spelling) or packed
// onto the dns node's own keys (`dns dns-proxy ...` collapsed onto one
// node, or a bare `dns dns-proxy` leaf). Checking only Children missed
// the packed shapes, so the commit warning for the unimplemented proxy
// runtime was silently skipped for those spellings.
func hasDNSProxyChild(node *Node) bool {
	for _, k := range node.Keys[1:] {
		if k == "dns-proxy" {
			return true
		}
	}
	for _, child := range node.Children {
		if child.Name() == "dns-proxy" {
			return true
		}
		for _, k := range child.Keys[1:] {
			if k == "dns-proxy" {
				return true
			}
		}
	}
	return false
}

func compileUserspaceDataplane(node *Node, cfg *UserspaceConfig, warnings *[]string) error {
	// #8939: split a packed run. `set system dataplane binary /x claim-host-tunables true`
	// is ONE child node carrying both on its Keys, so this switch read `binary`
	// and dropped the rest — including `control-socket`, whose loss #9003 shows
	// falls back to a path in /tmp.
	for _, child := range expandFlatRun(node.Children, systemDataplaneSchema8939()) {
		switch child.Name() {
		case "userspace":
			// #903: `set system dataplane userspace ...` is a redundant
			// path — the operator wrote `userspace` again under a
			// dataplane block we are ALREADY processing as the userspace
			// dataplane (entered via `case "dataplane"` after
			// dataplane-type=userspace). Pre-fix this was a silent
			// no-op; we now strip the leading "userspace" key and
			// re-dispatch through this same switch so the inner setting
			// (`workers 4`, `poll-mode interrupt`, etc.) actually takes
			// effect. Backward-compatible: no commit-time hard error,
			// so stored pre-fix configs replay cleanly on upgrade AND
			// finally do what the operator intended.
			if len(child.Keys) >= 2 {
				synthetic := &Node{
					Keys:     child.Keys[1:],
					Children: child.Children,
					IsLeaf:   child.IsLeaf,
				}
				synthParent := &Node{Children: []*Node{synthetic}}
				if err := compileUserspaceDataplane(synthParent, cfg, warnings); err != nil {
					return err
				}
			}
		case "cores", "memory", "socket-mem", "rx-mode", "ports":
			// Retired DPDK-era knobs (#1525 deleted the consumer; #1892
			// documents the disposition). Accepted so stored configs keep
			// loading, but they configure nothing — record the knob name
			// so userspaceRetiredKnobWarnings surfaces a commit warning.
			cfg.RetiredKnobsSeen = append(cfg.RetiredKnobsSeen, child.Name())
		case "binary":
			cfg.Binary = nodeVal(child)
		case "control-socket":
			cfg.ControlSocket = nodeVal(child)
		case "state-file":
			cfg.StateFile = nodeVal(child)
		case "workers":
			if v := nodeVal(child); v != "" {
				if n, ok := parseIntLeaf(warnings, "system dataplane workers", v); ok {
					cfg.Workers = n
				}
			}
		case "ring-entries":
			if v := nodeVal(child); v != "" {
				if n, ok := parseIntLeaf(warnings, "system dataplane ring-entries", v); ok {
					cfg.RingEntries = n
				}
			}
		case "poll-mode":
			if v := nodeVal(child); v == "interrupt" || v == "busy-poll" {
				cfg.PollMode = v
			}
		case "shared-umem":
			cfg.SharedUMEM = compileSharedUMEMConfig(child)
		case "rss-indirection":
			// Defaults to enabled; only the string "disable" flips it off.
			// Anything else (including "enable" and empty) leaves the
			// default behaviour — D3 runs.
			if nodeVal(child) == "disable" {
				cfg.RSSIndirectionDisabled = true
			}
		case "claim-host-tunables":
			// #801 B1 opt-in gate. Defaults false. Only the literal
			// string "true" turns it on; anything else (including
			// "false", "enable", and empty) leaves the default-safe
			// behaviour in which xpfd never touches host-scope knobs.
			if nodeVal(child) == "true" {
				cfg.ClaimHostTunables = true
			}
		case "cpu-governor":
			// `performance` | `schedutil` | `default` (skip). Stored
			// verbatim; daemon maps `default` / "" → no write. Any
			// unrecognised governor is also passed through so bare-metal
			// operators can request `powersave` / `ondemand` if needed
			// without a config-schema change.
			cfg.CPUGovernor = nodeVal(child)
		case "netdev-budget":
			if v := nodeVal(child); v != "" {
				if n, ok := parseIntLeaf(warnings, "system dataplane netdev-budget", v); ok {
					cfg.NetdevBudget = n
				}
			}
		case "coalescence":
			// `coalescence adaptive enable|disable`, `coalescence
			// rx-usecs <n>`, `coalescence tx-usecs <n>`. All three keys
			// live under the same node to mirror the Junos shape
			// (`set system dataplane coalescence <knob> <val>`).
			// #9235: `coalescence adaptive disable rx-usecs 8 tx-usecs 8` is ONE
			// command nested into a chain, so this loop applied `adaptive` and
			// dropped both usec knobs -- the NIC kept its driver defaults while
			// the config said otherwise. Lenient path only.
			for _, sub := range expandRunChildren9235(child.Children, dataplaneCoalescenceSchema9235()) {
				switch sub.Name() {
				case "adaptive":
					// `enable` → operator opt-out of the "disable by
					// default" behaviour; `disable` (or any other value,
					// including "") → apply `ethtool -C adaptive-rx off
					// adaptive-tx off`. Explicit is set whenever the
					// knob was written so the daemon can distinguish
					// "omitted" from "explicitly enable" in logs.
					v := nodeVal(sub)
					cfg.CoalescenceAdaptiveExplicit = true
					if v == "enable" {
						cfg.CoalescenceAdaptiveDisabled = false
					} else {
						// Includes "disable", empty, and unknown values.
						cfg.CoalescenceAdaptiveDisabled = true
					}
				case "rx-usecs":
					if v := nodeVal(sub); v != "" {
						if n, ok := parseIntLeaf(warnings, "system dataplane coalescence rx-usecs", v); ok {
							cfg.CoalescenceRXUsecs = n
						}
					}
				case "tx-usecs":
					if v := nodeVal(sub); v != "" {
						if n, ok := parseIntLeaf(warnings, "system dataplane coalescence tx-usecs", v); ok {
							cfg.CoalescenceTXUsecs = n
						}
					}
				}
			}
		}
	}
	return nil
}

// syslogFacilitySeverity extracts the `<facility> <severity>` pair from a
// system-syslog destination child. The pair is normally flat
// (`daemon warning;` → Keys=["daemon","warning"]) but tolerates the
// hierarchical shape (`daemon { warning; }` → Keys=["daemon"], child
// Keys=["warning"]). Returns ok=false when the node carries no severity
// token, so a bare/garbage leaf is dropped rather than appended as a
// half-populated filter entry (#4303 S-1). Callers must pre-filter the
// known non-facility host/file/user modifiers by keyword.
func syslogFacilitySeverity(prop *Node) (facility, severity string, ok bool) {
	if prop == nil || len(prop.Keys) == 0 {
		return "", "", false
	}
	if len(prop.Keys) >= 2 {
		return prop.Keys[0], prop.Keys[1], true
	}
	for _, c := range prop.Children {
		if len(c.Keys) > 0 && c.Keys[0] != "" {
			return prop.Keys[0], c.Keys[0], true
		}
	}
	return "", "", false
}

// syslogArchiveKeywordArgs enumerates the `system syslog file <f> archive`
// sub-statements setSchema models (schema_system.go) and records, for each,
// whether it is followed by a value token. It is the keyword allowlist the
// token walker below uses to tell a KEYWORD apart from a VALUE in a flattened
// token stream, and the arity it uses to step over a value so an
// `archive-sites` URL that happens to equal a keyword is not mistaken for one
// (#7146).
var syslogArchiveKeywordArgs = map[string]bool{
	"size":              true,
	"files":             true,
	"start-time":        true,
	"transfer-interval": true,
	"archive-sites":     true,
	"world-readable":    false,
	"no-world-readable": false,
}

// syslogArchiveTokens flattens a syslog-file `archive` subtree into its tokens
// in source order, depth-first pre-order: a node contributes its own Keys,
// then each child's subtree. This is what makes ONE walker cover every shape
// the dual AST produces for the same stanza (#7146):
//
//	flat block      `set ... archive files 7` + `set ... archive size 1m`
//	                -> Keys=["archive"], children ["files","7"] ["size","1m"]
//	flat compact    `set ... archive size 1m files 5`
//	                -> Keys=["archive"] -> child ["size","1m"] -> GRANDchild
//	                   ["files","5"] (a nested chain, not siblings)
//	hierarchical    `archive { files 7; size 1m; }` -> same as flat block
//	hier. one-line  `archive size 1m files 5;`
//	                -> Keys=["archive","size","1m","files","5"], NO children
//
// A reader that only walked Children would miss the one-line form entirely;
// one that only read Keys would miss both block forms.
func syslogArchiveTokens(n *Node, out []string) []string {
	if n == nil {
		return out
	}
	out = append(out, n.Keys...)
	for _, c := range n.Children {
		out = syslogArchiveTokens(c, out)
	}
	return out
}

// syslogArchiveKnobs returns the sorted, deduplicated archive sub-statement
// KEYWORDS configured under a syslog-file `archive` node — never their values,
// because an `archive-sites` URL can carry credentials and the caller feeds
// this straight into an operator-visible commit advisory (#7146).
//
// Unrecognized tokens are skipped rather than reported: the schema already
// rejects an unknown leaf at commit, and echoing an arbitrary token here would
// reintroduce the value-leak this function exists to avoid.
func syslogArchiveKnobs(n *Node) []string {
	if n == nil {
		return nil
	}
	tokens := syslogArchiveTokens(n, nil)
	if len(tokens) > 0 {
		// Drop the leading "archive" keyword itself.
		tokens = tokens[1:]
	}
	seen := map[string]bool{}
	var knobs []string
	for i := 0; i < len(tokens); i++ {
		takesValue, isKeyword := syslogArchiveKeywordArgs[tokens[i]]
		if !isKeyword {
			continue
		}
		if !seen[tokens[i]] {
			seen[tokens[i]] = true
			knobs = append(knobs, tokens[i])
		}
		if takesValue {
			// Step over the value so `archive-sites "size"` records
			// archive-sites once, not archive-sites AND size.
			i++
		}
	}
	sort.Strings(knobs)
	return knobs
}

// loginClassPermName renders a coarse xpf permission for the advisory.
func loginClassPermName(p LoginClassPermission) string {
	switch p {
	case PermView:
		return "view"
	case PermClear:
		return "clear"
	case PermControl:
		return "control"
	case PermConfig:
		return "configure"
	case PermMaint:
		return "maintenance"
	case PermAll:
		return "super-user"
	default:
		return "unknown"
	}
}

// loginClassAdvisoryWarnings emits one accept-with-advisory warning per custom
// `system login class <name>` (#4304 S-2). The class is RECOGNIZED (a valid
// vSRX RBAC config commits instead of being hard-rejected), but xpf's coarse
// permission model cannot faithfully represent every Junos permission, so the
// advisory states exactly what maps. It says nothing about the regex leaves:
// #7172 enforces allow-*/deny-* as allowlists/blacklists on both dispatch
// surfaces (compiler_login_deny.go), and #7172 cut 6 retired the former #5831
// reject-and-fold gate. Deterministic order for stable output.
func loginClassAdvisoryWarnings(cfg *Config) []string {
	if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Classes) == 0 {
		return nil
	}
	var warnings []string
	for _, lc := range cfg.System.Login.Classes {
		// #14387: a class whose name shadows a built-in is INERT at runtime
		// (ResolveClassPermissions consults the built-in table first), so
		// reporting its Junos permissions as "mapped to xpf coarse
		// permissions {...}" states the opposite of the installed semantics.
		// On the strict path such a definition never reaches here (the
		// shadow gate rejects it); on the tolerant path the gate warning
		// plus the per-user neutralisation warning carry the signal.
		if _, builtin := LoginClassPermissions[lc.Name]; builtin {
			continue
		}
		_, widened := mapJunosPermissions(lc.Permissions)
		// Report the EFFECTIVE set (lc.MappedPermissions), not a fresh
		// mapJunosPermissions call (#5831). Since #7172 cut 6 retired the
		// fold, MappedPermissions is exactly the authored mapping on every
		// path; reporting the effective set keeps this advisory truthful if
		// a future transform ever adjusts it.
		names := make([]string, 0, len(lc.MappedPermissions))
		for _, p := range lc.MappedPermissions {
			names = append(names, loginClassPermName(p))
		}
		mappedStr := "none"
		if len(names) > 0 {
			sort.Strings(names)
			mappedStr = strings.Join(names, ",")
		}
		msg := fmt.Sprintf("system login class %q: recognized (custom RBAC); Junos permissions [%s] mapped to xpf coarse permissions {%s}",
			lc.Name, strings.Join(lc.Permissions, " "), mappedStr)
		// #16080 (MGMT-01): a class holding configure without all /
		// super-user (PermAll) is fenced out of credential paths at
		// mutation time on every surface. Name that plainly at commit:
		// the old advisory said only that configure maps coarsely, never
		// that credential rewrite was (or now is not) within its reach.
		holdsConfig, holdsAll := false, false
		for _, p := range lc.MappedPermissions {
			if p == PermConfig {
				holdsConfig = true
			}
			if p == PermAll {
				holdsAll = true
			}
		}
		if holdsConfig && !holdsAll {
			msg += "; this class holds configure without super-user (all), so it cannot rewrite login/root/api credentials: mutations under system login, system root-authentication, and system services web-management api-auth are denied and require a super-user (all) class (#16080)"
		}
		if len(widened) > 0 {
			sort.Strings(widened)
			// #16638: these tokens are granted the FULL view bucket,
			// which is wider than the Junos token — PermView admits
			// the whole non-secret configuration and the live session
			// table, not just the named subsystem. Say so; "folded
			// down" claimed the opposite on the read axis.
			msg += fmt.Sprintf("; permissions [%s] granted full view (wider than Junos %s): view admits the whole non-secret configuration and session table; xpf has no finer read bucket, and no secret/configure/control/maintenance grant follows", strings.Join(widened, " "), strings.Join(widened, " "))
		}
		// Neutral not-enforced knobs. #7172 cut 6 removed allow-commands and
		// allow-configuration from this list, because they are no longer
		// inert — they are enforced as ALLOWLISTS on both dispatch surfaces.
		// Leaving them here would tell an operator their allowlist does
		// nothing at the exact commit where it starts denying everything it
		// does not match, which is the "told the wrong reason, reaches for the
		// wrong remedy" failure this file's advisories exist to avoid.
		//
		// idle-timeout remains parsed only for legacy configs, where the
		// tolerant load path must report that it is not enforced.
		var inert []string
		if lc.IdleTimeoutSet {
			inert = append(inert, "idle-timeout")
		}
		if len(inert) > 0 {
			msg += fmt.Sprintf("; %s accepted but NOT enforced by xpf's coarse RBAC", strings.Join(inert, "/"))
		}
		// SECURITY (history): deny-commands / deny-configuration are
		// BLACKLISTS, and the #4304 "accepted but MORE PERMISSIVE" advisory
		// that used to be appended here is GONE (#5831) rather than reworded.
		// Between #5831/#6838 and #7172 the strict path hard-rejected such a
		// class and the tolerant path folded it to a repair floor, because
		// the regexes were unenforced; #7172 implemented enforcement and
		// cut 6 retired both the rejection and the fold. The regexes are
		// now enforced on both dispatch surfaces, so this advisory stays
		// out of the regex business entirely and describes only the
		// permission mapping; the per-surface deny advisory below covers
		// whether a deny pattern can ever fire.
		warnings = append(warnings, msg)
		// #8189: and, as a SEPARATE advisory, whether the class's deny pattern
		// can ever fire on a registered dispatch surface. Separate rather than
		// appended to msg because it answers a different question -- msg is
		// about permission MAPPING, this is about whether a restriction the
		// operator wrote reaches a surface -- and an operator grepping commit
		// output for one should not have to read the other.
		//
		// Only emitted when the class actually compiled a deny pattern and at
		// least one registered surface reports a non-empty command set; see
		// UnenforceableDenySurfaces for why every ambiguous case is silence.
		// OperationalLoginRegexesFor is the SAME entry point the gRPC
		// authorization path uses, deliberately: a commit-time answer built
		// from a second construction could disagree with the runtime one, and
		// two answers to "can this pattern ever fire" is the confusion this
		// advisory exists to remove.
		if rules, ok, err := OperationalLoginRegexesFor(cfg, lc.Name); ok && err == nil {
			if surfaces := UnenforceableDenySurfaces(rules); len(surfaces) > 0 {
				if src, ok := rules.DenySource(); ok {
					warnings = append(warnings, fmt.Sprintf(
						"system login class %q: deny-commands %q matches no command in the "+
							"REGISTERED command set of %s, so it cannot restrict %s there; it "+
							"still applies on the on-box CLI. (The registered set is what those "+
							"surfaces declare, not a census of everything they can dispatch.)",
						lc.Name, src, strings.Join(surfaces, ", "),
						pluralSurface(len(surfaces))))
				}
			}
			// #9340: the same question per ALTERNATIVE, on the surfaces where
			// the whole pattern can fire. One enforceable alternative no longer
			// buys silence for an argument-text alternative beside it.
			// #9633 (V068): an allow pattern that permits nothing refuses the class
			// everything on that surface, and nothing said so.
			if surfaces := UnenforceableAllowSurfaces(rules); len(surfaces) > 0 {
				if src, ok := rules.AllowSource(); ok {
					warnings = append(warnings, fmt.Sprintf(
						"system login class %q: allow-commands %q permits no command in the "+
							"REGISTERED command set of %s, so every command there is refused for this "+
							"class (#9633). (The registered set is what those surfaces declare, not a "+
							"census of everything they can dispatch.)",
						lc.Name, src, strings.Join(surfaces, ", ")))
				}
			}
			for _, f := range UnenforceableDenyAlternatives(rules) {
				if src, ok := rules.DenySource(); ok {
					warnings = append(warnings, fmt.Sprintf(
						"system login class %q: deny-commands %q is only partly enforceable on %s: "+
							"its alternatives %q match no command in the REGISTERED command set of %s, "+
							"so they restrict the on-box CLI only; the other alternatives apply on both. "+
							"(The registered set is what that surface declares, not a census of everything "+
							"it can dispatch.)",
						lc.Name, src, f.Surface, f.Alternatives, f.Surface))
				}
			}
		}
	}
	return warnings
}

// pluralSurface keeps the #8189 advisory grammatical without a second format
// string.
func pluralSurface(n int) string {
	if n == 1 {
		return "that surface"
	}
	return "those surfaces"
}

// sshHardeningAdvisoryWarnings notes the SSH knobs xpf recognizes but does not
// (or cannot) render into the sshd drop-in (#4305 S-4). protocol-version is the
// main one: modern sshd is SSH-2 only, so `v2` is a silent no-op and any other
// value cannot be honored (SSH-1 is unsupported).
func sshHardeningAdvisoryWarnings(cfg *Config) []string {
	if cfg == nil || cfg.System.Services == nil || cfg.System.Services.SSH == nil {
		return nil
	}
	ssh := cfg.System.Services.SSH
	var warnings []string
	if ssh.ProtocolVersion != "" && ssh.ProtocolVersion != "v2" {
		warnings = append(warnings, fmt.Sprintf(
			"system services ssh protocol-version %q: sshd is SSH-2 only; SSH-1 is not supported, so this is accepted but NOT enforced",
			ssh.ProtocolVersion))
	}
	return warnings
}

// userspaceRetiredKnobWarnings turns each retired DPDK-era `system
// dataplane` knob recorded by compileUserspaceDataplane into a commit
// warning (#1892). The knobs (cores, memory, socket-mem, rx-mode, ports)
// lost their consumer in the #1525 DPDK retirement; they stay parseable
// so stored configs keep loading, but the operator must learn the stanza
// is inert. Deduplicated and ordered for stable output.
func userspaceRetiredKnobWarnings(cfg *Config) []string {
	if cfg == nil || cfg.System.UserspaceDataplane == nil {
		return nil
	}
	seen := cfg.System.UserspaceDataplane.RetiredKnobsSeen
	if len(seen) == 0 {
		return nil
	}
	uniq := make([]string, 0, len(seen))
	have := make(map[string]bool, len(seen))
	for _, k := range seen {
		if !have[k] {
			have[k] = true
			uniq = append(uniq, k)
		}
	}
	sort.Strings(uniq)
	warnings := make([]string, 0, len(uniq))
	for _, k := range uniq {
		warnings = append(warnings, fmt.Sprintf(
			"system dataplane %s: retired DPDK-era knob (#1525), accepted for config compatibility but ignored", k))
	}
	return warnings
}

// compileSharedUMEMConfig compiles the `system dataplane shared-umem` stanza
// into typed config. It is intentionally PURE (no file I/O): it records the
// mode, the participating-interface filter, and the operator-DECLARED
// phase0-artifact-file PATH only. The artifact's node-local contents are NEVER
// embedded here — that node-local read happens non-fatally in
// sharedUMEMAuditWarnings so the same committed tree compiles to the same typed
// config on any node (#5300 determinism).
func compileSharedUMEMConfig(node *Node) *SharedUMEMConfig {
	cfg := &SharedUMEMConfig{}
	// #8939: same packed-run split, one level down.
	for _, child := range expandFlatRun(node.Children, systemDataplaneSharedUMEMSchema8939()) {
		switch child.Name() {
		case "mode":
			cfg.Mode = nodeVal(child)
		case "interface":
			// #6692: `interface` is `multi: true` — a bracketed list
			// (`shared-umem { interface [ eth1 eth2 ]; }`) collapses onto ONE
			// node's Keys, so the pre-fix nodeVal read kept eth1 alone and the
			// dataplane's shared-UMEM memory topology differed from what the
			// operator authored. firewallMatchValues reads both sides of the
			// AST and skips empty tokens, matching the previous `v != ""`
			// guard.
			for _, v := range firewallMatchValues(child) {
				cfg.Interfaces = append(cfg.Interfaces, LinuxIfName(v))
			}
		case "phase0-artifact-file", "artifact-file":
			if path := nodeVal(child); path != "" {
				cfg.Phase0ArtifactFile = path
			}
		}
	}
	return cfg
}

// readSharedUMEMPhase0ArtifactForAudit reads and validates the operator-declared
// Phase 0 audit artifact for the AUDIT WARNING path only (#5300). It is
// non-blocking and bounded so it can never hang or OOM a commit:
//   - it stats first and refuses any non-regular file (directory, FIFO, socket,
//     device) — an os.Open on a FIFO/device can block indefinitely;
//   - it refuses an over-cap file by its stat size before opening;
//   - it opens O_RDONLY|O_NONBLOCK (a no-op on a regular file) so a stat->open
//     TOCTOU swap to a FIFO/device still cannot block; and
//   - it bounds the read with a LimitReader.
//
// The returned artifact is used ONLY to derive an operator-visible audit
// warning; it is never stored in the typed config, so it cannot affect
// same-tree->same-config determinism. Every error return here is non-fatal at
// the call site (sharedUMEMAuditWarnings turns it into a warning, not a compile
// error).
func readSharedUMEMPhase0ArtifactForAudit(path string) (map[string]interface{}, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read shared-umem artifact %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("read shared-umem artifact %s: not a regular file (mode %s)", path, info.Mode().Type())
	}
	if info.Size() > sharedUMEMPhase0ArtifactMaxBytes {
		return nil, fmt.Errorf("read shared-umem artifact %s: exceeds %d bytes", path, sharedUMEMPhase0ArtifactMaxBytes)
	}

	// O_NONBLOCK guards a stat->open TOCTOU swap to a FIFO/device; on a regular
	// file it has no effect.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("read shared-umem artifact %s: %w", path, err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, sharedUMEMPhase0ArtifactMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read shared-umem artifact %s: %w", path, err)
	}
	if len(data) > sharedUMEMPhase0ArtifactMaxBytes {
		return nil, fmt.Errorf("read shared-umem artifact %s: exceeds %d bytes", path, sharedUMEMPhase0ArtifactMaxBytes)
	}

	var artifact map[string]interface{}
	if err := json.Unmarshal(data, &artifact); err != nil {
		return nil, fmt.Errorf("decode shared-umem artifact %s: %w", path, err)
	}
	if artifact == nil {
		return nil, fmt.Errorf("decode shared-umem artifact %s: top-level value must be a JSON object", path)
	}
	return artifact, nil
}

// sharedUMEMAuditWarnings performs the NON-BLOCKING, NON-GATING Phase 0 audit
// read for the operator-declared shared-umem artifact (#5300). Per
// docs/shared-umem-plan.md ("Phase 0: Repro and Audit Evidence") the artifact
// is audit evidence only: it does not gate runtime shared-UMEM selection, so a
// read failure must never fail the compile and must never change the typed
// config. Running it as a tail gate keeps the operator audit signal at commit /
// load while keeping the read off the typed-config path:
//
//   - unavailable / unreadable / non-regular / oversized / malformed -> one
//     commit WARNING (visible but non-blocking); the commit still succeeds.
//   - a machine-readable artifact that did not pass (no explicit
//     `passed == true` / pass status, #17134 unified predicate), or whose
//     recorded environment (kernel/PCI/driver/MTU/queue topology) no
//     longer matches this host -> a WARNING surfacing the mismatch.
//
// Because it only appends to cfg.Warnings (a host-local diagnostic) and never
// touches cfg.System.UserspaceDataplane.SharedUMEM, the same committed tree
// still compiles to the identical typed config on a peer / after restart.

// sharedUMEMLiveEnv is the live environment the Phase 0 audit compares
// the artifact against (#17134). Seamed so tests can inject a synthetic
// environment instead of reading the test host's sysfs/proc.
type sharedUMEMLiveEnv struct {
	kernelRelease string
	pciIDs        map[string]struct{} // live PCI ids, keyed by interface
	drivers       map[string]string   // per-interface driver name
	mtus          map[string]int      // per-interface MTU
	rxQueues      map[string]int      // per-interface RX queue count
}

var sharedUMEMLiveEnvFn = readSharedUMEMLiveEnv

func readSharedUMEMLiveEnv(interfaces []string) (*sharedUMEMLiveEnv, error) {
	kernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return nil, fmt.Errorf("read kernel release: %w", err)
	}
	env := &sharedUMEMLiveEnv{
		kernelRelease: strings.TrimSpace(string(kernel)),
		pciIDs:        map[string]struct{}{},
		drivers:       map[string]string{},
		mtus:          map[string]int{},
		rxQueues:      map[string]int{},
	}
	for _, ifname := range interfaces {
		device, err := filepath.EvalSymlinks(filepath.Join("/sys/class/net", ifname, "device"))
		if err != nil {
			return nil, fmt.Errorf("resolve device for %s: %w", ifname, err)
		}
		env.pciIDs[filepath.Base(device)] = struct{}{}
		driverLink, err := os.Readlink(filepath.Join(device, "driver"))
		if err != nil {
			return nil, fmt.Errorf("read driver for %s: %w", ifname, err)
		}
		env.drivers[ifname] = filepath.Base(driverLink)
		mtuRaw, err := os.ReadFile(filepath.Join("/sys/class/net", ifname, "mtu"))
		if err != nil {
			return nil, fmt.Errorf("read MTU for %s: %w", ifname, err)
		}
		mtu, err := strconv.Atoi(strings.TrimSpace(string(mtuRaw)))
		if err != nil {
			return nil, fmt.Errorf("parse MTU for %s: %w", ifname, err)
		}
		env.mtus[ifname] = mtu
		queues, err := os.ReadDir(filepath.Join("/sys/class/net", ifname, "queues"))
		if err != nil {
			return nil, fmt.Errorf("read queues for %s: %w", ifname, err)
		}
		count := 0
		for _, e := range queues {
			if strings.HasPrefix(e.Name(), "rx-") {
				count++
			}
		}
		env.rxQueues[ifname] = count
	}
	return env, nil
}

func sharedUMEMArtifactInterfaces(artifact map[string]interface{}) []string {
	for _, key := range []string{"selected_interfaces", "interfaces"} {
		raw, ok := artifact[key].([]interface{})
		if !ok {
			continue
		}
		var out []string
		for _, v := range raw {
			if s, ok := v.(string); ok && s != "" {
				out = append(out, LinuxIfName(s))
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

func sharedUMEMArtifactStringSet(artifact map[string]interface{}, keys ...string) map[string]struct{} {
	for _, key := range keys {
		raw, ok := artifact[key].([]interface{})
		if !ok {
			continue
		}
		out := map[string]struct{}{}
		for _, v := range raw {
			if s, ok := v.(string); ok && s != "" {
				out[s] = struct{}{}
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

func sharedUMEMArtifactString(v interface{}) (string, bool) {
	s, ok := v.(string)
	return s, ok && s != ""
}

func sharedUMEMArtifactU32(v interface{}) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

// sharedUMEMArtifactPerInterface expands a scalar-or-per-interface-map
// artifact field over interfaces. Keys are LinuxIfName-normalised first,
// mirroring the Rust audit this replaces (#17134).
func sharedUMEMArtifactPerInterface(artifact map[string]interface{}, keys []string, interfaces []string) (map[string]interface{}, bool) {
	var raw interface{}
	found := false
	for _, key := range keys {
		if v, ok := artifact[key]; ok {
			raw, found = v, true
			break
		}
	}
	if !found {
		return nil, false
	}
	if _, isMap := raw.(map[string]interface{}); !isMap {
		out := make(map[string]interface{}, len(interfaces))
		for _, ifname := range interfaces {
			out[ifname] = raw
		}
		return out, true
	}
	m := raw.(map[string]interface{})
	normalized := make(map[string]interface{}, len(m))
	for k, v := range m {
		normalized[LinuxIfName(k)] = v
	}
	out := make(map[string]interface{}, len(interfaces))
	for _, ifname := range interfaces {
		v, ok := normalized[ifname]
		if !ok {
			return nil, false
		}
		out[ifname] = v
	}
	return out, true
}

func sharedUMEMSetsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func sortedSharedUMEMKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sharedUMEMStringSlicesEqualAsSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, s := range a {
		set[s] = struct{}{}
	}
	for _, s := range b {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

// sharedUMEMArtifactEnvironmentMismatch is the #17134 Go port of the
// environment comparison the Rust helper used to run against a
// `phase0_artifact` object no Go build emitted (dead since #5300). It
// compares kernel, selected interfaces, PCI IDs / device set, driver,
// MTU and queue topology against the live host, in that order, and
// returns the first mismatch ("" when the artifact matches).
//
// The interface set under audit is the CONFIGURED `shared-umem
// interface` list when the operator declared one (#17134 fold F3):
// the old Rust audit compared the artifact's selected interfaces
// against exactly that configured set (falling back to the artifact's
// own list only when no interfaces were configured). Deriving the
// list from the artifact alone would let an artifact recorded for
// entirely different NICs pass silently as long as it matched its own
// NICs' live data.
func sharedUMEMArtifactEnvironmentMismatch(artifact map[string]interface{}, configuredInterfaces []string) string {
	artifactKernel, _ := sharedUMEMArtifactString(artifact["kernel_release"])
	if artifactKernel == "" {
		return "Phase 0 artifact missing kernel_release"
	}
	artifactInterfaces := sharedUMEMArtifactInterfaces(artifact)
	if len(artifactInterfaces) == 0 {
		return "Phase 0 artifact missing selected_interfaces"
	}
	interfaces := artifactInterfaces
	if len(configuredInterfaces) > 0 {
		configured := make([]string, 0, len(configuredInterfaces))
		for _, ifname := range configuredInterfaces {
			if ifname != "" {
				configured = append(configured, LinuxIfName(ifname))
			}
		}
		if len(configured) > 0 {
			if !sharedUMEMStringSlicesEqualAsSets(artifactInterfaces, configured) {
				return "Phase 0 artifact selected interfaces do not match configured shared-umem interfaces"
			}
			interfaces = configured
		}
	}
	env, err := sharedUMEMLiveEnvFn(interfaces)
	if err != nil {
		return fmt.Sprintf("unable to read current environment for shared UMEM audit (%v)", err)
	}
	if artifactKernel != env.kernelRelease {
		return fmt.Sprintf("Phase 0 artifact kernel_release %s != current %s", artifactKernel, env.kernelRelease)
	}
	artifactPCI := sharedUMEMArtifactStringSet(artifact, "selected_nic_pci_ids", "pci_ids")
	if artifactPCI == nil {
		return "Phase 0 artifact missing selected_nic_pci_ids"
	}
	if !sharedUMEMSetsEqual(artifactPCI, env.pciIDs) {
		return fmt.Sprintf("Phase 0 artifact PCI IDs %v != current %v", sortedSharedUMEMKeys(artifactPCI), sortedSharedUMEMKeys(env.pciIDs))
	}
	deviceSet := sharedUMEMArtifactStringSet(artifact, "selected_device_set", "selected_devices", "selected_device_pair")
	if deviceSet == nil {
		return "Phase 0 artifact missing selected_device_set/selected_device_pair"
	}
	if !sharedUMEMSetsEqual(deviceSet, env.pciIDs) {
		return fmt.Sprintf("Phase 0 artifact selected device set %v != current %v", sortedSharedUMEMKeys(deviceSet), sortedSharedUMEMKeys(env.pciIDs))
	}
	driverByIface, ok := sharedUMEMArtifactPerInterface(artifact, []string{"driver", "driver_name"}, interfaces)
	if !ok {
		return "Phase 0 artifact missing driver"
	}
	for _, ifname := range interfaces {
		want, _ := sharedUMEMArtifactString(driverByIface[ifname])
		if want == "" || want != env.drivers[ifname] {
			return fmt.Sprintf("Phase 0 artifact driver %v != current %v", driverByIface, env.drivers)
		}
	}
	mtuByIface, ok := sharedUMEMArtifactPerInterface(artifact, []string{"mtu"}, interfaces)
	if !ok {
		return "Phase 0 artifact missing mtu"
	}
	for _, ifname := range interfaces {
		want, ok := sharedUMEMArtifactU32(mtuByIface[ifname])
		if !ok || int(want) != env.mtus[ifname] {
			return fmt.Sprintf("Phase 0 artifact MTU %v != current %v", mtuByIface, env.mtus)
		}
	}
	queueByIface, ok := sharedUMEMArtifactPerInterface(artifact, []string{"queue_topology"}, interfaces)
	if !ok {
		return "Phase 0 artifact missing queue_topology"
	}
	for _, ifname := range interfaces {
		want, ok := sharedUMEMArtifactU32(queueByIface[ifname])
		if !ok || int(want) != env.rxQueues[ifname] {
			return fmt.Sprintf("Phase 0 artifact queue_topology %v != current %v", queueByIface, env.rxQueues)
		}
	}
	return ""
}

func sharedUMEMAuditWarnings(cfg *Config) []string {
	if cfg == nil || cfg.System.UserspaceDataplane == nil ||
		cfg.System.UserspaceDataplane.SharedUMEM == nil {
		return nil
	}
	path := cfg.System.UserspaceDataplane.SharedUMEM.Phase0ArtifactFile
	if path == "" {
		return nil
	}
	artifact, err := readSharedUMEMPhase0ArtifactForAudit(path)
	if err != nil {
		return []string{fmt.Sprintf(
			"system dataplane shared-umem phase0-artifact-file %s: audit artifact unavailable (%v); non-blocking, does not gate the commit or change the compiled config", path, err)}
	}
	if !sharedUMEMArtifactPassed(artifact) {
		return []string{fmt.Sprintf(
			"system dataplane shared-umem phase0-artifact-file %s: audit artifact did not pass; shared-UMEM selection is decided at runtime by live bind validation, not this artifact", path)}
	}
	if reason := sharedUMEMArtifactEnvironmentMismatch(artifact, cfg.System.UserspaceDataplane.SharedUMEM.Interfaces); reason != "" {
		return []string{fmt.Sprintf(
			"system dataplane shared-umem phase0-artifact-file %s: %s; non-blocking, does not gate the commit or change the compiled config", path, reason)}
	}
	return nil
}

// sharedUMEMArtifactPassed unifies the passed predicate (#17134): the Go
// audit previously warned only on an explicit `passed == false` while
// the (dead) Rust audit passed only on `passed == true` or a pass
// status. The Go owner now uses the strict form: pass requires an
// explicit true / pass status.
func sharedUMEMArtifactPassed(artifact map[string]interface{}) bool {
	if passed, ok := artifact["passed"].(bool); ok && passed {
		return true
	}
	switch artifact["status"] {
	case "pass", "passed", "PASS":
		return true
	}
	return false
}

func validateBackupRouterDst(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	nh := cfg.System.BackupRouter
	// #15780: validate EVERY explicit destination, not just the scalar
	// first. Fall back to the scalar for configs constructed without the
	// compiler (hand-built Config values in tests / older persisted
	// state decoded into the struct).
	dsts := cfg.System.BackupRouterDsts
	if len(dsts) == 0 && cfg.System.BackupRouterDst != "" {
		dsts = []string{cfg.System.BackupRouterDst}
	}
	if nh == "" {
		// No backup-router configured — nothing to validate.
		return nil, nil
	}

	var warnings []string

	// #4808: next-hop must be a well-formed IP address. The netlink
	// table-999 route requires an IP gateway.
	if net.ParseIP(nh) == nil {
		msg := fmt.Sprintf(
			"system backup-router %s: not a valid IP address; backup-router "+
				"requires an IP gateway address", nh)
		if !lenient {
			return nil, fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg+" (ignored: backup-router route not installed until corrected)")
	}

	// #9820: an IPv4-mapped IPv6 literal is not supported as a
	// backup-router next-hop (product restriction: a single inert fallback
	// default is a silent lockout risk). It previously rendered
	// `ipv6 route ::/0 ::ffff:… 250` or tripped the family check under a
	// false reason, depending on the destination.
	if FRRAddrIsMapped(nh) {
		msg := fmt.Sprintf(
			"system backup-router %s: IPv4-mapped IPv6 next-hops are not "+
				"supported for backup-router; use a plain IPv4 or IPv6 address", nh)
		if !lenient {
			return nil, fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg+" (ignored: backup-router route not installed until corrected)")
	}

	if len(dsts) == 0 {
		// #2907's next-hop-family-aware default applies; never malformed or
		// a mismatch.
		return warnings, nil
	}

	nhFam := FRRAddrFamily(nh)
	for _, dst := range dsts {
		// #4808: an explicit destination must be a well-formed CIDR prefix.
		// net.ParseCIDR validates the mask too (natCIDRIPPart below only takes
		// the address portion, so "10.0.0.0/99" would otherwise slip through).
		if _, _, err := net.ParseCIDR(dst); err != nil {
			msg := fmt.Sprintf(
				"system backup-router destination %s: not a valid CIDR prefix; "+
					"the management table-999 backup route cannot be installed", dst)
			if !lenient {
				return nil, fmt.Errorf("%s", msg)
			}
			warnings = append(warnings, msg+" (ignored: backup-router route not installed until corrected)")
			continue
		}

		dstFam := FRRAddrFamily(dst)
		// The next-hop did not parse as an IP at all — already reported
		// above; skip the family comparison, it would be meaningless.
		if nhFam == "" || dstFam == "" {
			continue
		}
		if nhFam == dstFam {
			continue
		}
		msg := fmt.Sprintf(
			"system backup-router %s destination %s: destination family (%s) "+
				"does not match next-hop family (%s); backup-router requires a "+
				"next-hop and destination of the same address family",
			nh, dst, dstFam, nhFam)
		if lenient {
			warnings = append(warnings, msg+" (ignored: backup-router route not installed until corrected)")
			continue
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return warnings, nil
}

// ntpServerModifierNames returns the modifier keywords modeled as children of
// the `system ntp server` leaf in setSchema (#7132).
//
// This REPLACES ntpServerOptionArgs, a hand-written keyword->argcount table that
// existed only because the schema could not express "a value leaf that also has
// modifiers". It can: `valueList: true` plus modifier children is the #3872
// shape that static `route next-hop` already uses. The table was a second source
// of truth for the same grammar, and every future leaf in this shape would have
// grown its own copy.
func ntpServerModifierNames() map[string]int {
	return ntpSourceModifierNames("server")
}

// ntpSourceModifierNames returns modifier keywords for an ntp source
// leaf ("server" or "peer") from the schema (#15709, generalizing #7132).
func ntpSourceModifierNames(keyword string) map[string]int {
	out := map[string]int{}
	sys, ok := setSchema.children["system"]
	if !ok || sys == nil {
		return out
	}
	ntp, ok := sys.children["ntp"]
	if !ok || ntp == nil {
		return out
	}
	src, ok := ntp.children[keyword]
	if !ok || src == nil {
		return out
	}
	for name, child := range src.children {
		n := 0
		if child != nil {
			n = child.args
		}
		out[name] = n
	}
	return out
}

// ntpServerValues returns the NTP server addresses carried by one `server` node,
// and the per-server modifiers attached to them (#7132).
//
// Since #7132 a modifier is a schema-modeled CHILD, so the two are separable in
// the AST: `server 1.1.1.1 prefer` files Keys=["server","1.1.1.1"] with a child
// ["prefer"], while `server [ 1.1.1.1 2.2.2.2 ]` still collapses both addresses
// onto Keys. Before that they were byte-identical — Keys=["server",<tok>,<tok>]
// either way — which is why a keyword table was the only available remedy.
//
// The modifiers attach to the LAST address on the node, matching Junos: the
// modifier follows the server it qualifies.
// ntpServerListed reports whether addr is already in the compiled server list.
//
// Linear rather than a set because an NTP server list is a handful of entries
// and the compiled slice is ORDER-SIGNIFICANT — chrony tries sources in the
// order rendered — so it cannot be replaced by a map without changing what is
// emitted (#8436).
func ntpServerListed(servers []string, addr string) bool {
	for _, s := range servers {
		if s == addr {
			return true
		}
	}
	return false
}

// mergeNTPServerOption folds a later `server <addr> ...` statement's modifiers
// onto the ones already compiled for that address (#8436).
//
// FIELD-WISE, AND IT DEPENDS ON ZERO MEANING UNSET — which is not an assumption
// but the declared contract of the type: NTPServerOption documents `Key int
// (0 = unset)`, `Version int (0 = chrony default)` and `RoutingInstance string
// ("" = default)`. A wholesale assignment is what lost `key 5` when a second
// statement set only `version`; taking each field only when the later statement
// actually carries it is the same "a block that never mentions a leaf cannot
// reset it" property the other #8436 sites get from their `switch` arms, made
// explicit here because this struct is materialised whole rather than assigned
// per leaf.
//
// Prefer is a bool with no unset state, so it is a logical OR: `prefer` on
// either statement marks the source preferred, and neither can un-prefer the
// other. That is the only field whose merge is not "later wins if set", and it
// is the conservative direction — an operator who wrote `prefer` once gets it.
func mergeNTPServerOption(base, add NTPServerOption) NTPServerOption {
	out := base
	out.Prefer = base.Prefer || add.Prefer
	if add.Key != 0 {
		out.Key = add.Key
	}
	if add.Version != 0 {
		out.Version = add.Version
	}
	if add.RoutingInstance != "" {
		out.RoutingInstance = add.RoutingInstance
	}
	if add.SourceAddress != "" {
		out.SourceAddress = add.SourceAddress
	}
	return out
}

func ntpServerValues(n *Node) ([]string, map[string]NTPServerOption) {
	return ntpSourceValues(n, "server")
}

func ntpSourceValues(n *Node, keyword string) ([]string, map[string]NTPServerOption) {
	if n == nil {
		return nil, nil
	}
	modifiers := ntpSourceModifierNames(keyword)
	var servers []string
	opts := map[string]NTPServerOption{}
	// The COMPACT spelling puts a modifier and its argument on the parent's Keys
	// (`server 1.1.1.1 key 5;`), while the block spelling files them as a child
	// (`server 1.1.1.1 { key 5; }`). Both must produce the same compiled config —
	// that equivalence is the #2419 contract, and TestCompactBlockEquivalence-
	// Inventory2419 caught this reader dropping the compact value when it merely
	// SKIPPED modifiers here instead of capturing them.
	keyTokens := n.Keys[1:]
	for i := 0; i < len(keyTokens); i++ {
		tok := keyTokens[i]
		if nargs, isMod := modifiers[tok]; isMod {
			arg := ""
			if nargs > 0 && i+1 < len(keyTokens) {
				arg = keyTokens[i+1]
			}
			i += nargs
			if len(servers) > 0 {
				target := servers[len(servers)-1]
				cur := opts[target]
				applyNTPServerModifier(&cur, tok, arg)
				opts[target] = cur
			}
			continue
		}
		if tok != "" {
			servers = append(servers, tok)
		}
	}
	// The child walk runs UNCONDITIONALLY, before any modifier is attached.
	//
	// It used to early-return when Keys carried no server, which silently dropped
	// the #6689 nested-BLOCK spelling — `server { 1.1.1.1; 2.2.2.2; }` files both
	// addresses as CHILDREN and leaves Keys with just "server", so the early
	// return discarded every server on that shape. Caught by
	// Test_6690_NTPServerEveryHierarchicalSpelling. The block is the third shape
	// docs/config-schema.md warns about, and it is exactly the one an
	// early-return on Keys cannot see.
	var mods []*Node
	for _, child := range expandResolvingRuns9792(n.Children, resolveSchemaPath9235("system", "ntp", keyword)) {
		if child == nil || len(child.Keys) == 0 {
			continue
		}
		if _, isMod := modifiers[child.Keys[0]]; isMod {
			mods = append(mods, child)
			continue
		}
		// A bracket-list member or a nested-block server, not a modifier.
		servers = append(servers, child.Keys...)
	}
	if len(servers) == 0 {
		return servers, nil
	}
	target := servers[len(servers)-1]
	cur := opts[target]
	touched := false
	for _, child := range mods {
		name := child.Keys[0]
		touched = true
		arg := ""
		if len(child.Keys) > 1 {
			arg = child.Keys[1]
		}
		applyNTPServerModifier(&cur, name, arg)
	}
	// `touched` records only whether a CHILD modifier was applied to `cur`, so
	// it must not gate the return: the COMPACT spelling files its modifiers on
	// the parent's Keys, and the loop above has already written them into
	// `opts`. Returning nil here because no CHILD was seen discarded every
	// compact-spelled modifier — which is exactly the #2419 divergence this
	// reader was changed to close, reappearing one line below the fix for it.
	//
	// Write `cur` back only when a child actually contributed, so a plain
	// `server 1.1.1.1` with no modifiers at all still yields nil rather than a
	// map holding an all-zero option.
	if touched {
		opts[target] = cur
	}
	if len(opts) == 0 {
		return servers, nil
	}
	return servers, opts
}

// archiveSite is one authored `system archival configuration archive-sites`
// entry: the destination URL, plus whether the operator attached a `password`
// modifier to it.
type archiveSite struct {
	url         string
	hasPassword bool
}

// archiveSiteEntries returns EVERY archive site an `archive-sites` node carries,
// across all four AST shapes the parsers produce (#6692, the #2419 dual-shape
// class). Measured shapes:
//
//	archive-sites [ a b ];                → Keys=["archive-sites","a","b"]
//	archive-sites a password S;           → Keys=["archive-sites","a","password","S"]
//	archive-sites a { password S; }       → Keys=["archive-sites","a"], child ["password","S"]
//	archive-sites { a password S; b; }    → Keys=["archive-sites"], one child per site
//	archive-sites { a { password S; } }   → Keys=["archive-sites"], child "a" with a password child
//
// The pre-#6692 reader took Keys[1] and stopped, so a bracketed list compiled
// its FIRST member only — and because the #4589 leading-dash gate ran on that
// one member, every dropped member also ESCAPED the gate and committed clean.
// The escape was inert while the value was dropped; it stops being inert the
// moment the read widens, which is why the caller now runs the leading-dash
// check over every entry this function returns.
//
// `password` is a MODIFIER, not a value (#6673: a widened read must not PROMOTE
// a token the old reader discarded). It binds to the site immediately preceding
// it and its secret operand is consumed with it, so neither the keyword nor the
// secret can ever land in ArchiveSites and be handed to `scp` as a destination.
// A trailing `password` with no operand still marks the preceding site rather
// than becoming one.
//
// An EMPTY value token is preserved as an entry: the pre-#6692 reader appended
// Keys[1] unconditionally, so `archive-sites ""` compiled one empty site, and
// silently dropping it here would change behaviour on an axis this change is
// not about.
func archiveSiteEntries(n *Node) []archiveSite {
	if n == nil {
		return nil
	}
	// parseTail walks a token stream whose entries are `<url> [password
	// <secret>]` groups. toks excludes the leaf keyword.
	parseTail := func(toks []string) []archiveSite {
		var out []archiveSite
		for i := 0; i < len(toks); i++ {
			if toks[i] == "password" {
				if len(out) > 0 {
					out[len(out)-1].hasPassword = true
				}
				i++ // consume the secret operand, if one was authored
				continue
			}
			out = append(out, archiveSite{url: toks[i]})
		}
		return out
	}
	markLast := func(sites []archiveSite, node *Node) {
		if len(sites) > 0 && node.FindChild("password") != nil {
			sites[len(sites)-1].hasPassword = true
		}
	}

	// Value-on-Keys shapes: the sites ride this node's own tail. Any CHILD here
	// is a modifier block for the last authored site (`archive-sites a {
	// password S; }`), never an additional site.
	if len(n.Keys) > 1 {
		sites := parseTail(n.Keys[1:])
		markLast(sites, n)
		return sites
	}

	// Block shape: one child per site, each child's own Keys carrying that
	// site's `<url> [password <secret>]` tail.
	var out []archiveSite
	for _, child := range n.Children {
		sites := parseTail(child.Keys)
		markLast(sites, child)
		out = append(out, sites...)
	}
	return out
}

// applyNTPServerModifier records one per-server modifier (#7132). Shared by the
// COMPACT (parent Keys) and BLOCK (child node) spellings so the two cannot
// diverge — the divergence being exactly what #2419 is about.
func applyNTPServerModifier(opt *NTPServerOption, name, arg string) {
	switch name {
	case "prefer":
		opt.Prefer = true
	case "key":
		if v, err := strconv.Atoi(arg); err == nil {
			opt.Key = v
		}
	case "version":
		if v, err := strconv.Atoi(arg); err == nil {
			opt.Version = v
		}
	case "routing-instance":
		opt.RoutingInstance = arg
	case "source-address":
		opt.SourceAddress = arg
	}
}

// sshKeyValues returns EVERY authorized-key value carried by an `ssh-rsa` /
// `ssh-dsa` / `ssh-ed25519` leaf (#8863).
//
// Those leaves are `multi: true`, so two `set` lines for the same key type
// collapse onto ONE node and the second value lands on Keys[2:] rather than
// replacing the first. A reader that takes only Keys[1] — which is what
// nodeVal does — would then keep the FIRST key and silently drop every later
// one, which is the #2419 multi-value defect pointed the other way: before the
// schema change the second `set` REVOKED the first, and a Keys[1]-only reader
// would make it revoke every key after the first instead.
//
// The bracketed spelling `ssh-ed25519 [ "K1" "K2" ]` collapses the same way
// (the lexer strips the brackets), and the hierarchical spelling puts each key
// on its own node, so both the Keys tail and the Children have to be read.
// Same shape and same reason as firewallMatchValues.
//
// A key is a single token even when it contains spaces, because the value is
// quoted (`"ssh-ed25519 AAAA... admin@host"`); the lexer keeps a quoted string
// whole, so this never splits one key into several.
func sshKeyValues(node *Node) []string {
	if node == nil {
		return nil
	}
	var out []string
	for _, k := range node.Keys[1:] {
		if k != "" {
			out = append(out, k)
		}
	}
	for _, child := range node.Children {
		for _, k := range child.Keys {
			if k != "" {
				out = append(out, k)
			}
		}
	}
	return out
}

// loginClassSchema8939 resolves `system login class <name>` so expandFlatRun
// can tell one of the class's leaves from a value token.
//
// `permissions` is a MULTI leaf and its values must NOT be split: they are
// permission names, not statements. expandFlatRun cuts only at a token that
// resolves as a schema SIBLING, and no permission name is also a login-class
// leaf name -- asserted, not assumed, by the bracketed-list and
// `permissions all allow-configuration ...` arms of the #8939 cell.
// loginUserSchema9391 resolves the `system login user <name>` container out of
// setSchema, so the run expansion is driven by the same declaration SetPath
// walked. Mirrors loginClassSchema8939 below.
func loginUserSchema9391() *schemaNode {
	return refLoginUserInstance.resolve()
}

func loginClassSchema8939() *schemaNode {
	return refLoginClassInstance.resolve()
}
