package config

// Brace-elided ("compact") statement normalization — #8662, first increment of
// the #2419 normalizer.
//
// Junos accepts a stanza's body without braces:
//
//	match { source-address a1; }     the braced form
//	match source-address a1;         the same statement, braces elided
//
// The parser represents them differently. Braced gives a container node with a
// child; elided packs the whole tail onto the container's own Keys:
//
//	BLOCK    Keys=[match]                   children=[ Keys=[source-address a1] ]
//	COMPACT  Keys=[match source-address a1] children=[]
//
// A compiler stanza that reads only `prop.Children` — which most do — therefore
// sees nothing in the elided form, and the statement is silently dropped on a
// commit that reports success. `pkg/config/testdata/compact_block_divergences_2419.txt`
// is the measured inventory of that: 433 sites, of which 414 compile the elided
// spelling to a config identical to an EMPTY stanza.
//
// This pass rewrites the packed form into the braced form so both spellings
// compile identically. It is deliberately SCOPED for this increment (see
// compactNormalizeInScope) rather than applied to all 433: the full sweep is
// the #2419 normalizer proper, whose stated goal in
// compact_block_inventory_regen_2419_test.go is to "drive this file to zero
// data lines".
//
// WHY TRUNCATING THE TAIL IS SAFE HERE, and why that is not a general licence.
// Some containers DO read their packed tail — `redundancy-group 0 node 0
// priority 200` is the shipped HA config's spelling, and compileChassis reads
// the value straight out of the node's key tail (see the `packedTail` opt-in in
// schema.go). Moving such a tail into a child would BREAK those readers.
//
// Every site in scope here is one the inventory records as DIVERGENT with the
// elided form compiling to the empty stanza — which is a positive measurement
// that the tail is currently ignored at that container. So there is nothing to
// break: the value reaches no reader today. The inventory is the safety
// evidence, and a site may only be added to this pass's scope once it appears
// there.
func normalizeCompactStanzas(tree *ConfigTree) int {
	if tree == nil {
		return 0
	}
	return normalizeCompactStanzasWithScope(tree, compactNormalizeInScope)
}

// compactNormalizeInScope reports whether a packed tail at `container` whose
// first token is `head` is in this increment's scope.
//
// #8662 scope: the 24 `match` criteria under security NAT and security policies,
// and the 6 `authentication-key` leaves under the routing protocols. Chosen
// because that is where a silent drop is a SECURITY outcome rather than a
// cosmetic one — a dropped match criterion silently changes what a rule
// matches, and a dropped authentication key silently changes what authenticates.
// compactNormalizeInScope reports whether a packed tail at `container` whose
// first token is `head` is in the pass's scope. It is a plain function with no
// mutable state; tests that need to observe or vary the decision inject their
// own via normalizeCompactStanzasWithScope rather than reassigning anything.
//
// WHY AN INJECTION POINT EXISTS AT ALL. Scope is decided per (container, head)
// PAIR while the permanent-exclusion register classifies per SITE, so a guard
// has to know which pair governs which site. Every attempt to DERIVE that from
// a site's path has been wrong: the container path carries the schema arg
// placeholder where production passes node.Keys[0], and a site's key chain
// turns out to be a property of the SPELLING rather than of the site. THREE
// SEPARATE DERIVATIONS PRODUCED THREE DIFFERENT WRONG ANSWERS. The only method
// that has been right is to ask the pass which keys it consults.
//
// Do not delete the seam as unnecessary without reading that history — it looks
// like indirection for its own sake precisely until you try to re-derive the
// attribution, which is the thing that keeps failing.
func compactNormalizeInScope(containerKeyword, head string) bool {
	// #8690, second increment: the CREDENTIAL family. Chosen on consequence
	// rather than on count — each of these is a token whose silent drop leaves
	// something authenticating (or authorizing) with NOTHING, on a commit that
	// reports success. That is the failure #8689 demonstrated on its own
	// `authentication-key` above: the brace-elided spelling compiled to an
	// empty AuthKey, rendered as `area-password md5`, and the IS-IS adjacency
	// came up unauthenticated.
	//
	// EVERY ENTRY BELOW WAS MEASURED, not reasoned about. The rule is that a
	// site may enter this pass only once the census shows its elided spelling
	// compiling identically to the EMPTY stanza — a positive measurement that
	// no reader consumes the packed tail today, so moving it cannot break one.
	// `TestCompactNormalizeScopePreservesCompiledResult8690` re-derives that for
	// every admitted site on each run, against the same census machinery the
	// inventory uses, so this list cannot drift from its own justification.
	//
	// The measurement also EXCLUDED members of the family, and NEITHER exclusion
	// came from empty-equivalence — see the two notes below. Membership is by
	// measurement rather than by name, and the measurement that matters is not
	// always the one the rule names.
	//
	// EXCLUDED BY DESIGN, and this is not the empty-equivalence rule — it is a
	// second gate that behaviour measurement cannot see. `system login user
	// <u> authentication <leaf>` measures empty-equivalent (nothing reads the
	// tail), and normalizing it would still be wrong: the compact spelling is
	// REJECTED at commit by the #6662 packed-login-body gate, and on the
	// tolerant load / peer-sync path it is warned and left inert on purpose, so
	// a peer-synced config behaves exactly as the binary that accepted it did
	// (#1960). Compiling the value there would change RBAC across an HA sync,
	// silently, between nodes on different binaries.
	//
	// `filedByDesign` in compact_block_equivalence_2419_test.go is the registry,
	// and its tripwire is what caught this: the empty-equivalence probe said
	// "safe" for all four leaves, because the probe measures whether a reader
	// consumes the tail and cannot see a decision that it SHOULD NOT be read.
	//
	// `user` is excluded too, and the registry does NOT list it — that was
	// found by measuring the gate rather than by reading the registry. The
	// normalizer runs at compiler.go:210 and the #6662 gate at :349, so a
	// rewritten tree reaches the gate already un-packed. Measured before and
	// after admitting `user`/`class`:
	//
	//	before: `system login user u1 class super-user;` -> REJECTED at commit
	//	        ("the account resolves to the fail-closed `unauthorized` class
	//	         ... on a binary before #6701 it instead reached the legacy
	//	         no-RBAC allow-everything mode")
	//	after:  compiles clean
	//
	// Normalizing it does not merely change a spelling: it converts a loud
	// commit-time rejection into a silent acceptance, and makes an RBAC class
	// compile on this binary that a peer on an older one still drops. The
	// registry lists the four `authentication` leaves; the GATE governs the
	// whole packed login body. Only the before/after comparison shows the
	// difference, so the exclusion is by container, not by the registry.
	// NOTE: this exclusion PRE-EMPTS every pair below. With the rules now
	// pair-scoped it is no longer load-bearing for the credential heads --
	// no pair names `authentication` or `user` as its container -- but it is
	// kept as the explicit record of the #6662 decision, and because it also
	// guards anything added above it later.
	//
	// Its cost, stated so it is not rediscovered: a pair naming
	// `authentication` or `user` as its container would silently never fire.
	// A rule that cannot match reads like coverage and passes review, which is
	// the same trap as the wildcard-container site in #8719. If a future family
	// needs one, delete this and re-derive the exclusion as pairs rather than
	// adding an unreachable case below.
	if containerKeyword == "authentication" || containerKeyword == "user" {
		return false
	}
	// #8690, the SCHEDULERS and CHASSIS surfaces. 23 sites, all shape `empty`,
	// all measured safe: no gate disarms, nothing fixture-limited, nothing
	// unsynthesizable, no collision with a `partial` site.
	//
	// The weekday containers are the reason this is 23 pairs and not two. The
	// head `start-time` appears under nine different containers here -- `daily`
	// and each weekday -- so `head == "start-time"` would be a shorter rule
	// covering the same sites today. That is exactly the contingent-on-the-
	// population shape #8727 removed from three older rules, and a schedule is
	// a security control: `security policies ... scheduler <s>` decides WHEN a
	// policy is in force, so a dropped `stop-time` leaves a permit active past
	// the window the operator wrote, on a commit that reported success.
	//
	// `start-date` and `stop-date` were NOT in this family when it was first
	// measured -- they entered the census between the measurement and the
	// change, from another lane's fixture work. Re-deriving rather than reusing
	// the earlier list is what caught them; the count moved 21 -> 23.
	switch containerKeyword + " " + head {
	case
		"schedulers scheduler",
		"scheduler start-date",
		"scheduler start-time",
		"scheduler stop-date",
		"scheduler stop-time",
		"daily start-time",
		"daily stop-time",
		"monday start-time",
		"monday stop-time",
		"tuesday start-time",
		"tuesday stop-time",
		"wednesday start-time",
		"wednesday stop-time",
		"thursday start-time",
		"thursday stop-time",
		"friday start-time",
		"friday stop-time",
		"saturday start-time",
		"saturday stop-time",
		"sunday start-time",
		"sunday stop-time",
		"device-map interface",
		"device-map unmapped-interface-policy":
		return true
	}
	// #8690, the three `system` sites that entered the census AFTER the system
	// family landed in #8719. All shape `empty`, all measured safe: no gate
	// disarms, nothing unmeasurable, nothing introduced-rejection.
	//
	// They are here rather than in #8719 because the census GREW under the
	// family -- improved value synthesis made three previously-unruled leaves
	// visible. That is worth stating because a family is not finished when its
	// count reaches zero; it is finished when nothing new arrives, and nothing
	// announces an arrival except the inventory changing size.
	//
	// The `system` residue after these is 17 lines and is DELIBERATE: 15
	// gate-disarming, 1 unmeasurable, 1 unreachable by a pair rule. See #8719.
	// `system` cannot reach 0 under pair scoping, so a count driving toward
	// zero will point at an exclusion set rather than at work.
	switch containerKeyword + " " + head {
	case
		"dataplane control-socket",
		"system domain-name",
		"ssh protocol-version":
		return true
	}
	// EVERY RULE HERE IS SCOPED BY (container, head) PAIR. None matches a head
	// alone or a container alone, and that is a deliberate change from how the
	// first two increments were written.
	//
	// WHY: a head-only rule is safe only for as long as no container acquires
	// that head with a tail somebody reads, and a container-only rule is safe
	// only for as long as no head appears under it that somebody reads. Both
	// make the predicate's correctness contingent on the CURRENT INVENTORY
	// rather than on the rule. The inventory moves — this sweep moves it — so
	// such a rule fails at the moment a family lands, inside someone else's
	// merge conflict, which is the worst possible place to be redesigning a
	// predicate.
	//
	// The measured case for the container-only direction: `containerKeyword ==
	// "match"` was written for security policies and NAT rule-sets, and it also
	// admitted `services ip-monitoring policy <p> match rpm-probe` — a
	// different feature in a different subtree, reached only because it happens
	// to spell its criteria block `match`. It is in scope below because it
	// measured safe, not because the rule intended it.
	//
	// The head-only direction is the same defect mirrored, and is the one
	// lane-8526's illustration names: `term <t> from community <c>` is shape
	// `empty` and admissible while `term <t> then community <c>` is `partial`
	// and must never be admitted. Same head, one token apart, opposite sides of
	// the safety rule.
	//
	// SOME PAIRS BELOW TRIP A COMMIT GATE and are in scope anyway, because the
	// gate objects to the DROP rather than to the spelling and the pass repairs
	// the drop. `snmp trap-group <t> targets` is one. Those are classified,
	// with their measurement, in `benign` in
	// compact_normalize_scope_8690_test.go -- not here, because the
	// classification gates a guard VERDICT and never makes a site in scope. A
	// reader of this list would otherwise see an ordinary-looking pair with no
	// sign that it was a deliberate call.
	//
	// These 32 pairs are exactly what the three former rules admitted, measured
	// at the production call site rather than derived from the schema — so this
	// is a restatement of the existing scope, not a widening. The admitted-site
	// count and the inventory are unchanged by it.
	switch containerKeyword + " " + head {
	case
		// #8689: the authentication-key family, formerly `head ==
		// "authentication-key"` unqualified.
		"cluster authentication-key",
		"group authentication-key",
		"interface authentication-key",
		"isis authentication-key",
		"neighbor authentication-key",
		"rip authentication-key",
		// REMOVED BY #8763: `vrrp-group authentication-key` and
		// `vrrp-group authentication-type`. Both sit ONLY below a `family`, so
		// before the traversal fix above they folded nothing; and once it
		// reaches them the fold moves the whole remaining key run into one
		// child, so `vrrp-group 1 authentication-key <s> track-interface X
		// track-interface Y` puts both track-interfaces inside the
		// authentication-key node and validateVRRPTrackInterfaceAST stops
		// seeing the duplicate (the two #5195 secret-leak cells red).
		//
		// Removing them costs nothing, and that is MEASURED rather than
		// inferred from "folds nothing today". In every spelling the pass can
		// reach, the value is refused at commit either way:
		//
		//	family { inet { address a { vrrp-group 1 authentication-key s; } } }
		//	    folds=1, pass OFF and ON compile IDENTICALLY -- both REJECTED:
		//	    "VRRP authentication-key is configured but NOT enforced -- the
		//	     dataplane is RFC 5798 VRRPv3, which removed authentication"
		//
		// So the fold was never delivering anything here and the #5195 reds
		// would be pure loss. Re-admitting them needs `vrrp-group` to opt into
		// packedStatements, which in turn needs #8768's registry keyed by
		// schema PATH -- `vrrpGroupSchemaNode(false)` and `(true)` are two
		// nodes and the name-keyed registry refuses the opt-in.
		//
		// #8689: the security match family, formerly `containerKeyword ==
		// "match"` unqualified. `match rpm-probe` is the ip-monitoring site
		// noted above.
		"match application",
		"match destination-address",
		"match destination-address-excluded",
		"match destination-address-name",
		"match destination-port",
		"match from-zone",
		"match protocol",
		"match rpm-probe",
		"match source-address",
		"match source-address-excluded",
		"match source-address-name",
		"match to-zone",
		// #8708: the credential family, formerly a head-only map lookup.
		"interface authentication-type",
		"isis authentication-type",
		"manual authentication-algorithm",
		"master-password pseudorandom-function",
		"peer preshared-key",
		"proposal authentication-algorithm",
		"proposal authentication-method",
		"rip authentication-type",
		"root-authentication encrypted-password",
		"root-authentication ssh-dsa",
		"root-authentication ssh-ed25519",
		"root-authentication ssh-rsa",
		"policy pre-shared-key",
		"vpn pre-shared-key",
		"wireguard private-key",
		// #8708: `key`, already container-scoped, restated in the same form.
		"tunnel key",
		"md5 key":
		return true
	}
	// #8690 family 2: the POLICY-ENFORCEMENT surface — security zones and
	// security policies. 20 sites left the inventory and none entered it, and
	// every one of the 20 was recorded with drop shape "empty": the
	// measurement that no reader consumes the tail today, and therefore that
	// truncating it takes nothing away.
	//
	// 20 rather than the 17 zones+policies sites the pairs were chosen for.
	// Three came along because they share a pair: `security address-book global
	// address-set <s> {address,address-set}` and `security pre-id-default-policy
	// then log`. They are the same shape and the same consequence class, so they
	// are in scope deliberately rather than tolerated — but they are named here
	// because "the diff is bigger than the families I listed" is exactly the
	// sentence a reviewer should be able to check.
	//
	// `security policies from-zone <a> <b> <c> policy` is NOT covered: its pair
	// is `from-zone policy`, which is not listed, so the bare policy instance
	// remains in the inventory. Left out rather than added quietly, so the
	// inventory diff continues to equal the declared scope.
	//
	// The consequential members are not the descriptions:
	//
	//	security-zone <z> screen <profile>      the zone's IDS screen binding
	//	security-zone <z> host-inbound-traffic  what the box itself accepts there
	//	security-zone <z> interfaces <if> ...   per-interface admission
	//	policy <p> then log                     session logging for the policy
	//
	// A brace-elided `screen` leaves the zone with no screen profile applied,
	// on a commit that reports success — the same shape as #8689's IS-IS
	// authentication key, one layer up.
	//
	// SCOPED BY (container, head) PAIR RATHER THAN BY CONTAINER KEYWORD, and
	// the difference is load-bearing. `then` is not specific enough: the
	// `then log` sites here are shape "empty", but
	// `policy-options policy-statement <p> term <t> then <action>` is shape
	// "partial" for eight actions — something DOES consume part of that tail,
	// so truncating it could remove a value that is currently read. A
	// containerKeyword == "then" rule would have crossed into them silently.
	//
	// That is why the widening rule is per SITE rather than per family: a
	// family label is not a safety property, and this is the case that proves
	// it. TestNormalizerScopeNeverCoversAPartialSite8690 binds it mechanically
	// so the next widening cannot make the same mistake by inspection.
	// #8690: `policy proposal-set`, the two sites lane-8015's security family
	// could not take.
	//
	// It landed the rest of security in 950df1331 while I was measuring the
	// same family — so 45 of the 47 sites I had scoped were already done, and
	// my pair list for them is dropped rather than landed redundantly. These
	// two are what remained:
	//
	//	security ike   policy <p> proposal-set
	//	security ipsec policy <p> proposal-set
	//
	// They share one pair, and they were blocked by a commit gate rather than
	// by anything about the fold. The disarm arm flags
	// `security ipsec policy xpfarg proposal-set` as REJECTED without the pass
	// and ACCEPTED with it, which is a red until a person classifies it.
	//
	// Classified benign, with the measurement in the guard's `benign` map: the
	// gate refuses the CONSEQUENCE of the drop and says so itself — the elided
	// spelling loses the proposal-set, and the gate rejects with "has no
	// resolvable ipsec proposal ... the configured perfect-forward-secrecy
	// group would be SILENTLY DROPPED". With the pass the proposal-set survives
	// and the same gate accepts. The braced spelling is accepted either way, so
	// the config was always legitimate and only the elided form lost it.
	//
	// That gate exists to catch this exact drop, so the pass repairing the drop
	// and the gate then passing is the intended interaction. Without the
	// classification these two sites are unreachable by any widening — which is
	// why they were still here.
	if containerKeyword == "policy" && head == "proposal-set" {
		return true
	}

	// #8690: the three sites the two independent classifications agreed were
	// the only available work left.
	//
	//	system dataplane control-socket
	//	system domain-name
	//	system services ssh protocol-version
	//
	// lane-8015 classified these `unclassified` — "in lane-8388's family and
	// NOT measured by this lane", which was the correct record of its evidence:
	// "nobody has checked" is a third state and calling them available would
	// have asserted a measurement nobody took. I measured them, which is a
	// different instrument reading rather than a correction, and they resolve
	// to open:
	//
	//	admitted alone, arm 2 reports NO disarm, and the whole tree passes but
	//	for TestNewlyVisibleSitesAreAccountedFor_8690 — a bookkeeping cell that
	//	tracks sites made visible by synthesis and states in its own message
	//	that normalization legitimately shrinks its list.
	//
	// Measured at 5c54f2f0f. The stamp matters here more than usual: whether a
	// site disarms a gate depends on whether it was ADMITTED when the
	// measurement was taken, so a gate verdict without a commit is not
	// checkable. That is the provenance requirement applied to my own entry
	// rather than to someone else's register.
	switch containerKeyword + " " + head {
	case "dataplane control-socket",
		"system domain-name",
		"ssh protocol-version":
		return true
	}

	// #8690 family 6: the five sites the register carried as `open` — the
	// BENIGN residue of the gate arm, now admitted.
	//
	// Each was classified through step 3 by hand, with the BRACED CONTROL that
	// distinguishes benign from genuine: braced accepted with the pass both off
	// and on (so the config is legitimate), elided REJECTED with the pass off,
	// elided ACCEPTED with the pass on. The gate exists to catch the dropped
	// value and the pass restores it, so the gate then passing is the intended
	// interaction and not a disarm. Same argument and same shape as `security
	// ipsec policy <p> proposal-set` in 0c4818aa0.
	//
	// The braced leg is the one that matters and it is easy to omit: without it
	// "elided rejected, then accepted" is equally consistent with the pass
	// papering over a config the gate should refuse on its own merits.
	//
	// PAIR SCOPING CHECKED AGAINST THE SCHEMA, NOT THE INVENTORY. The inventory
	// is a census of DIVERGENT sites; a pair rule applies to the whole schema,
	// so "no other inventory line carries this head" is the wrong question.
	// Three of these four heads appear under other containers, and the pair is
	// what keeps them out:
	//
	//	peer-as        also under `group`     (schema_routing.go) — NOT admitted
	//	hostname       also under `dynamic`   (IKE dynamic peer, x2) and ddns
	//	url            also under `autoupdate` and under rpm `target`
	//	fixed-address  one definition, dhcpStaticBindingSchema()
	//
	// A head-only rule would have taken the IKE dynamic-peer FQDN and the
	// autoupdate URL along with the feed-server pair.
	//
	// `static-binding fixed-address` is ONE rule covering TWO sites, the
	// dhcp-local-server and dhcpv6-local-server twins. That is sound here and
	// was checked rather than assumed: both reach the same subtree through the
	// shared dhcpLocalServerGroupSchema(), so there is a single definition to
	// reason about. The v4/v6 asymmetry that does exist in this subtree —
	// `dhcp-socket-type`, IPv4-only because Kea's Dhcp6 has no raw mode — is
	// two levels up and does not touch the pair. The twins were also measured
	// SEPARATELY: arm 2 caught the v4 side, and the v6 side was hand-measured
	// out of the fixture-limited bucket the arm could not examine. One measured
	// member of a shape says nothing about the other, which is the lesson that
	// bucket produced.
	switch containerKeyword + " " + head {
	case "neighbor peer-as",
		"feed-server hostname",
		"feed-server url",
		"static-binding fixed-address":
		return true
	}

	// #8690 family 7: the ONE measurable member of the rpm-test bucket.
	//
	// lane-8526 classified all ten `services rpm probe <p> test <t> <leaf>`
	// sites and only `target` behaves as a benign disarm; re-derived here
	// rather than relayed, with the pair ADMITTED, because a measurement of an
	// excluded pair is a restatement of the exclusion:
	//
	//	leaf                    pass OFF   pass ON
	//	target                  rejects    ACCEPTED, test registers
	//	probe-count             rejects    still rejects
	//	probe-type              rejects    still rejects
	//	source-address          rejects    still rejects
	//	(and the other five)    rejects    still rejects
	//
	// `target` is the benign pattern: the gate refuses the CONSEQUENCE of the
	// drop ("target is required") and the pass repairs it. THE OTHER NINE ARE
	// NOT — the pass splits their tail correctly and the test still has no
	// target, so the same gate still fires and nothing changes at the commit
	// boundary. They need a required sibling the compact spelling cannot carry,
	// which makes them unreachable by construction rather than merely
	// unmeasured, and is the same wall #8725 turns on.
	//
	// NINE OF TEN WOULD HAVE INHERITED `target`'s VERDICT under any family-level
	// judgement. That is the v4/v6 static-binding lesson reached from the
	// opposite direction: there the twins differed in whether the INSTRUMENT
	// could see them, here they differ in whether the PASS changes anything. A
	// shape is not a verdict in either direction.
	//
	// Pair scoping: `source-address` has 16 definitions in setSchema and
	// `routing-instance` 14, which looks alarming on the head alone — but
	// exactly ONE container named `test` exists (schema_system.go:627), so
	// ("test", <head>) cannot reach any of them. Checking the head raises a
	// false alarm; checking the inventory answers a different question.
	switch containerKeyword + " " + head {
	case "test target":
		return true
	}

	// #8755 family 8: the part of the interface-unit family that is NOT blocked
	// by the compoundKey traversal defect (#8763).
	//
	// 20 of that issue's 23 open sites sit under `family inet` / `family inet6`,
	// which the pass cannot enter at the spelling operators write — so a scope
	// entry for them closes one spelling and leaves the idiomatic one open, and
	// they wait on #8763 and #8768. These two do not: `unit <n>` is an ARGS
	// container, where the second token is an instance argument consumed by
	// `identity`, so the recursion accounts for it correctly and the pass
	// reaches the leaf.
	//
	// Measured at 97ba4fe2b:
	//
	//	unit 0 description "uplink";   before  folds=0 desc=""        after  folds=1 desc="uplink"
	//	unit 0 vlan-id 10;             before  folds=0 vlan=0         after  folds=1 vlan=10
	//	braced reference               desc="uplink" vlan=10 either way
	//
	// DELIBERATELY EXCLUDES `unit <n> inner-vlan-id`, the third unblocked site.
	// That one INVERTS: braced `inner-vlan-id` is REJECTED by the QinQ /
	// stacked-VLAN gate, and the elided form commits clean with the value
	// dropped, so normalizing it RESTORES a rejection and turns a config that
	// commits today into one that does not. Right outcome, different decision,
	// and it belongs with #8755's introduces-rejection class rather than in a
	// slice justified as "unblocked".
	switch containerKeyword + " " + head {
	case "unit description",
		"unit vlan-id":
		return true
	}

	// #8755: the interface-unit family, completed.
	//
	// The two symptoms #8755 names -- a lost ADDRESS and a lost FILTER binding
	// -- look like one defect and are two, and that was measured rather than
	// assumed. They need DIFFERENT NUMBERS OF CHAIN LINKS:
	//
	//	family inet address 10.0.0.1/24;   ONE link.  (inet, address) was not
	//	                                   admitted, so the pass folded NOTHING
	//	                                   -- the whole statement stayed one node
	//	                                   and the address never reached a reader.
	//
	//	family inet filter input f1;       TWO links. (inet, filter) WAS already
	//	                                   admitted, so the pass folded once, to
	//	                                   `family inet` + `filter input f1` --
	//	                                   and then stopped, because
	//	                                   (filter, input) was not admitted. The
	//	                                   binding was still lost.
	//
	// The filter half is the more instructive one: a scope entry existed, it
	// fired, and it accomplished nothing on its own, because ADMISSION IS A
	// CHAIN and only the first link was in. An admitted pair that delivers
	// nothing reads as coverage, which is why #8763 recorded it as
	// `chain-incomplete` rather than leaving it to be rediscovered.
	//
	// PAIR REACH CHECKED AGAINST THE SCHEMA, not the inventory. Both heads
	// exist under other containers, and the pair is what keeps them out:
	//
	//	filter   is also `firewall family inet filter <name>` -- args:1, children
	//	         {term, interface-specific}. It has NO `input`/`output` child, so
	//	         (filter, input) cannot reach it. Exactly two paths each, both the
	//	         interface unit.
	//	inet     is also under firewall, forwarding-options, protocols bgp and
	//	         rib-group. None of them has an `address` child. (inet, address)
	//	         reaches exactly ONE path.
	//
	// A head-only rule would have been wrong for both.
	//
	// Measured with the statement REMOVED as well as braced and packed, so
	// "the two spellings agree" cannot pass a value neither of them delivers:
	//
	//	                         baseline   braced      packed OFF   packed ON
	//	family inet address      addrs=[]   [10.0.0.1/24]  []         [10.0.0.1/24]
	//	family inet filter input ""         "f1"           ""         "f1"
	switch containerKeyword + " " + head {
	case "inet address",
		"inet6 address",
		"filter input",
		"filter output":
		return true
	}

	// #8690 family 5: applications, services, snmp, event-options. 30 sites,
	// every one drop shape "empty" in the inventory.
	//
	// PROVISIONAL until the disarm arm has run over them: the drop shape
	// answers a question about READERS and does not see commit gates. lane-8388
	// established that `system login` sites measure "empty" while the #6662
	// packed-login-body gate makes normalizing them unsafe, and flagged
	// `snmp trap-group <t> targets` as one of the same class. I am not taking
	// that on trust either way — the pairs go in, the disarm guard runs, and
	// anything it flags gets classified by hand rather than assumed.
	switch containerKeyword + " " + head {
	case "applications application",
		"applications application-set",
		"application alg",
		"application description",
		"application destination-port",
		"application icmp-code",
		"application icmp-type",
		"application inactivity-timeout",
		"application protocol",
		"application source-port",
		"application term",
		"application timeout",
		"event-options policy",
		"policy within",
		"version-ipfix template",
		"version9 template",
		"template flow-active-timeout",
		"template flow-inactive-timeout",
		"template-refresh-rate seconds",
		"rpm probe",
		"snmp community",
		"snmp trap-group",
		"community clients",
		"trap-group categories",
		"trap-group targets",
		"trap-group version",
		"local-engine user":
		return true
	}

	// #8690 family 4: interfaces. 15 sites, every one drop shape "empty".
	//
	// Measured, not taken from the brief: the family was described to me as
	// 18 empty / 8 partial for interfaces plus 0/2 for bridge-domains. The
	// inventory says 15 empty / 10 partial across the two. The file is the
	// instrument.
	//
	// The same head-on-both-sides shape as family 3 appears here too:
	//
	//	interfaces <if> tunnel destination <addr>                     empty
	//	interfaces <if> tunnel routing-instance destination <ri>      partial
	//
	// so `destination` is admitted under `tunnel` and not under
	// `routing-instance`. A head-only rule would take both.
	//
	// The other ten partials — `interfaces <if> {description,duplex,mtu,speed,
	// unit,...}` and the two bridge-domains sites — fold at the INSTANCE level,
	// where production passes the instance name (`ge-0-0-0`) as the container
	// keyword. No static pair can match them, so they are safe from a pair rule
	// by construction rather than by being listed. That is worth knowing before
	// someone "simplifies" this to a head-only match: it is exactly the rule
	// shape those ten are NOT protected from.
	//
	// bridge-domains has ZERO admissible sites — both of its inventory entries
	// are partial — so there is nothing to normalize there and its verdict is
	// recorded rather than left looking unstarted.
	switch containerKeyword + " " + head {
	//
	// `lacp periodic` was withheld in #8721 because it was one of the census's
	// two hand-verified known-true anchors, and normalizing it blinded the
	// instrument. It is admitted now: the anchor moved to a PARTIAL site
	// (`interfaces <if> mtu`), which no scope may ever cover, so the control no
	// longer depends on leaving a defect unfixed. The withheld site cost one
	// increment; the structural fix ends the recurrence.
	case "aggregated-ether-options link-speed",
		"aggregated-ether-options minimum-links",
		"lacp periodic",
		"gigether-options 802.3ad",
		"gigether-options redundant-parent",
		"tunnel destination",
		"tunnel source",
		"tunnel mode",
		"tunnel ttl",
		"tunnel keepalive-retry",
		"wireguard listen-port",
		"wireguard peer",
		"peer allowed-ips",
		"peer endpoint",
		"peer persistent-keepalive":
		return true
	}

	// #8690 family 3: policy-options. Taken PER SITE rather than as a family
	// sweep, because this is the family where a family sweep is actively
	// harmful: of its 17 inventory sites, 9 are drop shape "empty" and 8 are
	// "partial" — and all 8 partials sit under `then`.
	//
	//	policy-statement <p> term <t> from community <c>   empty    admitted
	//	policy-statement <p> term <t> then community <c>   partial  NOT admitted
	//
	// The same head, one token apart, on opposite sides of the safety rule.
	// That pair is the clearest argument in the tree for scoping on
	// (container, head) rather than on either token alone: a head-only rule
	// admits both, and a container-only rule on `then` admits all eight
	// partials. Both mistakes were available and neither is visible by reading.
	//
	// Every one of the 9 below was checked individually against the inventory's
	// drop shape, and TestNormalizerScopeNeverCoversAPartialSite8690 re-checks
	// the whole set against the LIVE normalizer rather than against my reading
	// of it.
	switch containerKeyword + " " + head {
	case "policy-options community",
		"policy-options policy-statement",
		"policy-options prefix-list",
		"community members",
		"policy-statement term",
		"from as-path",
		"from community",
		"from prefix-list":
		return true
	}

	// #8690, the SYSTEM surface — 44 sites out of the 61 the census
	// lists under `system`. Scoped by (container, head) PAIR per family 2's
	// rule, and the 17 exclusions are the whole point of this increment.
	//
	// WHAT WAS EXCLUDED, AND WHY THE INVENTORY MARKER COULD NOT SAY SO:
	//
	// 15 sites are GATE-DISARMING — compiled through the strict path with this
	// pass disabled they are REJECTED, and with it enabled they are ACCEPTED.
	// That is the whole `system login` subtree (`class` and its six children,
	// `user`, the four `authentication` leaves, `class`, `uid`) plus
	// `dhcp-local-server ... static-binding <b> fixed-address`. Every one of
	// them measures `empty`, so the inventory marker calls them safe: it
	// records whether a READER consumes the packed tail, and these are held by
	// a GATE that refuses the packed spelling. The pass runs before the commit
	// gates, so a rewritten tree reaches them with nothing left to refuse.
	//
	// 1 site is UNMEASURABLE rather than safe:
	// `dhcpv6-local-server ... static-binding <b> fixed-address`. Its census
	// fixture supplies an IPv4 literal, so with the pass enabled it fails a
	// DIFFERENT validator ("is not an IPv6 address") instead of compiling. A
	// two-state safe/unsafe test reads that as "no gate was disarmed", which is
	// the fixture answering rather than the site. It shares its pair with the
	// v4 site above, so excluding that pair covers both.
	//
	// 1 site is UNREACHABLE by a pair rule at all:
	// `services web-management api-auth user <name> password`. Its container is
	// WILDCARD-NAMED, so production passes the actual username as the container
	// keyword -- `("alice", "password")`, never a fixed token. A pair rule for
	// it would be dead code that reads like coverage. Admitting it needs a
	// head-only rule, which is a different safety argument than this increment
	// makes, so it stays out.
	//
	// The pairs below were MEASURED by instrumenting the production call site,
	// not reconstructed from the inventory path. Those disagree: the path
	// carries a schema placeholder where production passes the stanza keyword,
	// so `system login class <c> allow-commands` is ("class", "allow-commands")
	// to production and ("xpfarg", "allow-commands") to a path reader.
	switch containerKeyword + " " + head {
	case
		"api-auth api-key",
		"autoupdate url",
		"coalescence adaptive",
		"coalescence rx-usecs",
		"coalescence tx-usecs",
		"configuration archive-sites",
		"configuration transfer-interval",
		"dataplane binary",
		"dataplane claim-host-tunables",
		"dataplane cpu-governor",
		"dataplane netdev-budget",
		"dataplane poll-mode",
		"dataplane ring-entries",
		"dataplane state-file",
		"dataplane workers",
		"dhcp-local-server group",
		"dhcpv6-local-server group",
		"group interface",
		"group pool",
		"http interface",
		"https interface",
		"ntp server",
		"ntp threshold",
		"pool dns-server",
		"pool static-binding",
		"shared-umem artifact-file",
		"shared-umem interface",
		"shared-umem mode",
		"shared-umem phase0-artifact-file",
		"ssh client-alive-count-max",
		"ssh client-alive-interval",
		"ssh connection-limit",
		"ssh key-exchange",
		"ssh root-login",
		"static-binding host-name",
		"system backup-router",
		"system domain-search",
		"system name-server",
		"system time-zone":
		return true
	}
	switch containerKeyword + " " + head {
	case "zones security-zone",
		"security-zone screen",
		"security-zone description",
		"security-zone interfaces",
		"security-zone address-book",
		"security-zone host-inbound-traffic",
		"host-inbound-traffic protocols",
		"host-inbound-traffic system-services",
		"address-set address",
		"address-set address-set",
		"address-book address-set",
		"policies default-policy-log",
		"policies from-zone",
		"policies global",
		"policy description",
		"policy then",
		"then log",
		"global policy":
		return true
	}

	// #8690 family 3: the FORWARDING-BEHAVIOUR surface — class-of-service,
	// forwarding-options and firewall. 52 inventory sites, every one recorded
	// with drop shape "empty": the positive measurement that no reader consumes
	// the tail today, so truncating it takes nothing away.
	//
	// SCOPED ON PAIRS, NEVER ON A CONTAINER KEYWORD ALONE — and here that is
	// the difference between correct and destructive, not a style preference.
	// `then` is shared. These families need (then, {count, dscp,
	// forwarding-class, loss-priority, policer, routing-instance,
	// traffic-class}); `policy-options policy-statement <p> term <t> then`
	// carries EIGHT sites with drop shape "partial" — as-path-prepend,
	// community, load-balance, local-preference, metric, metric-type, next-hop,
	// origin. "partial" means something ALREADY CONSUMES part of that tail, so
	// normalizing it removes a value that is read today while the config still
	// commits clean. A scope written as `containerKeyword == "then"` would have
	// swallowed all eight. The two head sets are disjoint, which is what makes
	// the pairs below safe and the keyword unsafe.
	//
	// `group` is shared the same way: (group, interface) is wanted here for
	// dhcp-relay, while `protocols bgp group <g>` uses the same container and
	// holds `neighbor <n> peer-as` — one of the sites where widening DISARMS a
	// commit gate despite measuring empty-equivalent. Admitting the pair rather
	// than the keyword leaves bgp untouched.
	//
	// THE PAIRS WERE MEASURED, NOT READ OFF THE INVENTORY PATH. Production
	// passes kw = node.Keys[0] and head = node.Keys[1+args], so the `xpfarg` in
	// an inventory line is the node's ARG, not its container keyword. Deriving
	// pairs by reading the path yields a predicate that silently UNDER-reports
	// — the #8708 method note, where `system login user` was asked about as
	// ("xpfarg", "class") and matched nothing. These came from running the pass
	// with an instrumented gate and recording what it encountered.
	//
	// THREE SITES OUTSIDE THE THREE FAMILIES COME ALONG because they share a
	// pair. Named here, because "the diff is bigger than the families I listed"
	// is exactly the sentence a reviewer should be able to check:
	//
	//	policy-options policy-statement <p> term <t> from protocol  (from protocol)
	//	system services dhcp-local-server group <g> interface       (group interface)
	//	system services dhcpv6-local-server group <g> interface     (group interface)
	//
	// All three are recorded "empty", so the same safety measurement covers
	// them. The policy-options member is a `from` site, NOT one of the eight
	// forbidden `then` partials — the distinction the pair scoping exists to
	// preserve.
	switch containerKeyword + " " + head {
	// class-of-service: 49 pairs.
	case "buffer-size temporal",
		"class-of-service interfaces",
		"class-of-service scheduler-maps",
		"class-of-service schedulers",
		"class-of-service traffic-control-profiles",
		"classifiers dscp",
		"classifiers ieee-802.1",
		"classifiers inet-precedence",
		"dscp forwarding-class",
		"exp forwarding-class",
		"forwarding-class loss-priority",
		"forwarding-class scheduler",
		"ieee-802.1 forwarding-class",
		"inet-precedence forwarding-class",
		"interface queue",
		"interfaces output-traffic-control-profile",
		"interfaces priority-low-min-share",
		"interfaces scheduler-map",
		"interfaces shaping-rate",
		"interfaces unit",
		"loss-priority code-point",
		"loss-priority code-points",
		"oversubscription-policy guarantee-rate",
		"queue active-workers",
		"queue at-least-active-workers",
		"queue cstruct",
		"queue cstruct-max",
		"queue max-worker-flow-share",
		"rewrite-rules dscp",
		"rewrite-rules exp",
		"rewrite-rules ieee-802.1",
		"rewrite-rules inet-precedence",
		"rss-expectation interface",
		"scheduler-maps forwarding-class",
		"schedulers buffer-size",
		"schedulers codel-target",
		"schedulers equal-flow-target-policy",
		"schedulers priority",
		"schedulers transmit-rate",
		"shaping-rate burst-size",
		"traffic-control-profiles delay-buffer-rate",
		"traffic-control-profiles guaranteed-rate",
		"traffic-control-profiles scheduler-map",
		"traffic-control-profiles shaping-rate",
		"transmit-rate percent",
		"unit output-traffic-control-profile",
		"unit priority-low-min-share",
		"unit scheduler-map",
		"unit shaping-rate":
		return true
	// forwarding-options: 16 pairs.
	case "dhcp-relay group",
		"dhcp-relay server-group",
		"flow-server port",
		"flow-server source-address",
		"flow-server version-ipfix-template",
		"flow-server version9-template",
		"group active-server-group",
		"group interface",
		"inet6 mode",
		"input rate",
		"output flow-server",
		"output source-address",
		"overrides maximum-hop-count",
		"overrides maximum-packet-rate",
		"port-mirroring instance",
		"sampling instance":
		return true
	// firewall: 34 pairs.
	case "filter term",
		"firewall policer",
		"firewall three-color-policer",
		"flexible-match-range range",
		"from destination-address",
		"from destination-port",
		"from destination-port-except",
		"from dscp",
		"from icmp-code",
		"from icmp-type",
		"from protocol",
		"from source-address",
		"from source-port",
		"from source-port-except",
		"from tcp-flags",
		"from traffic-class",
		"if-exceeding bandwidth-limit",
		"if-exceeding burst-size-limit",
		"inet filter",
		"inet6 filter",
		"single-rate committed-burst-size",
		"single-rate committed-information-rate",
		"single-rate excess-burst-size",
		"then count",
		"then dscp",
		"then forwarding-class",
		"then loss-priority",
		"then policer",
		"then routing-instance",
		"then traffic-class",
		"two-rate committed-burst-size",
		"two-rate committed-information-rate",
		"two-rate peak-burst-size",
		"two-rate peak-information-rate":
		return true
	}

	// #8690 family 4: the ROUTING surface — protocols, routing-instances and
	// routing-options. 80 inventory sites, every one recorded "empty".
	//
	// THESE THREE CANNOT BE SPLIT, and that is a measured fact rather than a
	// convenience. `routing-instances <n> protocols ospf ...` and
	// `routing-instances <n> routing-options static ...` are the SAME GRAMMAR
	// re-hosted under an instance, so they resolve to the same (container, head)
	// pairs as their top-level spellings. Admitting `routing-instances` alone
	// necessarily admits the matching `protocols` and `routing-options` sites;
	// the pair set is only closed over all three. Splitting them into separate
	// increments would have produced an inventory diff much larger than each
	// increment declared, which is precisely the thing a reviewer is asked to
	// check.
	//
	// `protocols` was deliberately EXCLUDED from family 3 because it holds
	// `protocols bgp group <g> neighbor <n> peer-as`, one of the sites where a
	// widening DISARMS a commit gate while measuring empty-equivalent — so the
	// inventory marker is necessary but not sufficient evidence there. It is
	// admitted here on a different basis: arm 2 of the widening rule
	// (TestCompactNormalizeScopePreservesCompiledResult8690) compiles every
	// admitted site through the strict path with the pass disabled and compares
	// acceptance, which is the check the marker cannot perform. That guard runs
	// over whatever scope is current, so it adjudicates these sites rather than
	// a list adjudicating them.
	//
	// ONE PAIR REACHES OUTSIDE the three families: (route, next-hop) is also
	// used by `services ip-monitoring policy <p> then preferred-route route
	// <r>`. That site is NOT in the inventory, which is NOT evidence that it
	// conserves — a site the census cannot see is absent for the same reason a
	// safe site is. It is admitted on arm 2's verdict, not on its absence.
	//
	// Pairs measured by running the pass with an instrumented gate, not derived
	// from inventory paths (the path carries the schema arg placeholder where
	// production passes node.Keys[0]).
	//
	// ("neighbor", "peer-as") IS DELIBERATELY ABSENT, and arm 2 is what removed
	// it rather than a list. Admitting it made
	// TestCompactNormalizeScopePreservesCompiledResult8690 report:
	//
	//	1 site(s) in the normalizer's scope are REJECTED at strict commit with
	//	the pass disabled and ACCEPTED with it enabled:
	//	[protocols bgp group xpfarg neighbor xpfarg peer-as]
	//
	// That is the gate-disarm failure the "empty" marker cannot see: the site
	// measures empty-equivalent (no reader consumes the tail) AND a commit gate
	// rejects the packed spelling, so normalizing it would make a configuration
	// that is refused today start committing clean. `protocols bgp group <g>
	// neighbor <n> peer-as` therefore stays in the inventory. Retiring its gate
	// is a separate, deliberate decision — not a side effect of a family sweep.
	switch containerKeyword + " " + head {
	case "area interface",
		"area virtual-link",
		"authentication md5",
		"authentication simple-password",
		"bfd-liveness-detection minimum-interval",
		"bfd-liveness-detection multiplier",
		"bgp cluster-id",
		"bgp export",
		"bgp group",
		"bgp import",
		"bgp local-as",
		"bgp router-id",
		"damping half-life",
		"damping max-suppress",
		"damping reuse",
		"damping suppress",
		"forwarding-table export",
		"generate route",
		"group authentication-key",
		"group description",
		"group export",
		"group hold-time",
		"group import",
		"group local-address",
		"group local-as",
		"group loops",
		"group multihop",
		"group neighbor",
		"group peer-as",
		"interface authentication-key",
		"interface authentication-type",
		"interface cost",
		"interface dead-interval",
		"interface default-lifetime",
		"interface dns-server-address",
		"interface hello-interval",
		"interface interface-type",
		"interface level",
		"interface link-mtu",
		"interface max-advertisement-interval",
		"interface metric",
		"interface min-advertisement-interval",
		"interface nat-prefix",
		"interface nat64prefix",
		"interface preference",
		"interface prefix",
		"interface priority",
		"interface reachable-time",
		"interface retransmit-interval",
		"interface retransmit-timer",
		"isis authentication-key",
		"isis authentication-type",
		"isis export",
		"isis interface",
		"isis is-type",
		"isis level",
		"isis net",
		"lldp hold-multiplier",
		"lldp interface",
		"lldp transmit-interval",
		"md5 key",
		"nat-prefix lifetime",
		"nat64prefix lifetime",
		"neighbor authentication-key",
		"neighbor description",
		"neighbor export",
		"neighbor hold-time",
		"neighbor import",
		"neighbor local-address",
		"neighbor local-as",
		"neighbor loops",
		"neighbor multihop",
		"next-hop interface",
		"ospf area",
		"ospf export",
		"ospf reference-bandwidth",
		"ospf router-id",
		"ospf3 area",
		"ospf3 export",
		"ospf3 router-id",
		"prefix preferred-lifetime",
		"prefix valid-lifetime",
		"prefix-limit maximum",
		"qualified-next-hop interface",
		"qualified-next-hop metric",
		"qualified-next-hop preference",
		"rib-group inet",
		"rib-group inet6",
		"rip authentication-key",
		"rip authentication-type",
		"rip group",
		"rip neighbor",
		"rip passive-interface",
		"rip redistribute",
		"route next-hop",
		"route next-table",
		"route policy",
		"route preference",
		"route qualified-next-hop",
		"router-advertisement interface",
		"routing-options autonomous-system",
		"routing-options rib",
		"routing-options rib-groups",
		"static route",
		"virtual-link transit-area":
		return true
	}

	// #8690 family 7: the SECURITY remainder and schedulers. 114 inventory
	// sites, every one drop shape "empty"; schedulers goes to zero and security
	// 99 -> 4.
	//
	// SEVEN PAIRS ARE EXCLUDED and each exclusion has a different provenance,
	// which is the reason to list them here rather than to say "measured":
	//
	//   arm 2 named three — ("feed-server","hostname"), ("policy",
	//   "proposal-set") and, in another lane's family, ("trap-group","targets").
	//   Excluding ("policy","proposal-set") also holds `security ike policy <p>
	//   proposal-set`, which shares the pair.
	//
	//   ("feed-server","url") was found BY HAND. Arm 2 reports a third state —
	//   sites whose gate status it could not measure because the census
	//   fixture's value fails a different validator — and says they are NOT
	//   known-safe. Measured with a type-valid URL, that site is a real
	//   gate disarm: rejected at strict commit without the pass, accepted with
	//   it. No guard in the tree would have caught it.
	//
	//   ("dynamic","hostname") disarms a TRAILING-TOKEN gate (`security ike
	//   gateway <g> dynamic hostname <fqdn> <extra>`). Arm 2's fixture emits one
	//   clean value, so it cannot build the input that trips that gate.
	//
	//   ("deterministic","block-size"), ("host","address") and ("policy",
	//   "scheduler-name") are excluded because the scope guard cannot EXAMINE
	//   them: their reference spelling does not compile in isolation. Its
	//   instruction is to give them a compilable fixture instead, which does not
	//   work here — `contextFor` injects siblings INSIDE the parent path, while
	//   these need context ABOVE it (the policy needs its zones declared under
	//   `security zones`; the pool needs an address at pool level). None is an
	//   inventory site, so excluding them costs no coverage.
	//
	// Pairs measured by running the pass with an instrumented gate, not derived
	// from inventory paths, and checked for over-reach against every site
	// outside the two families: NONE, which is why this scope carries no
	// "neighbours come along" note where the earlier families did.
	switch containerKeyword + " " + head {
	case "address-book address-set",
		"address-set address",
		"address-set address-set",
		"address-set description",
		"aging early-ageout",
		"aging high-watermark",
		"aging low-watermark",
		"daily start-time",
		"daily stop-time",
		"dead-peer-detection interval",
		"dead-peer-detection threshold",
		"deny log",
		"destination pool",
		"destination rule-set",
		"destination-nat pool",
		"dynamic-address address-name",
		"dynamic-address feed-server",
		"feed-name path",
		"feed-server feed-name",
		"feed-server hold-interval",
		"feed-server update-interval",
		"flood threshold",
		"flow multicast-session-lifetime",
		"flow route-change-timeout",
		"friday start-time",
		"friday stop-time",
		"from interface",
		"from routing-instance",
		"from zone",
		"from-zone policy",
		"gateway address",
		"gateway external-interface",
		"gateway ike-policy",
		"gateway local-address",
		"gateway local-identity",
		"gateway local-certificate",
		"gateway nat-traversal",
		"gateway remote-identity",
		"gateway version",
		"global address-set",
		"global policy",
		"host-inbound-traffic protocols",
		"host-inbound-traffic system-services",
		"icmp-session timeout",
		"ike gateway",
		"ike ipsec-policy",
		"ike policy",
		"ike proposal",
		"interface address",
		"ip-sweep threshold",
		"ipsec gateway",
		"ipsec policy",
		"ipsec proposal",
		"ipsec vpn",
		"limit-session destination-ip-based",
		"limit-session source-ip-based",
		"log format",
		"log mode",
		"log profile",
		"log source-interface",
		"log stream",
		"manual authentication-algorithm",
		"manual encryption-algorithm",
		"manual protocol",
		"manual spi",
		"match application",
		"match destination-address",
		"match destination-address-name",
		"match destination-port",
		"match from-zone",
		"match protocol",
		"match source-address",
		"match source-address-name",
		"match to-zone",
		"monday start-time",
		"monday stop-time",
		"nat64 rule-set",
		"packet-filter destination-prefix",
		"packet-filter protocol",
		"packet-filter source-prefix",
		"persistent-nat inactivity-timeout",
		"persistent-nat permit",
		"policies default-policy",
		"policies default-policy-log",
		"policy description",
		"policy mode",
		"policy proposals",
		"policy-stats system-wide",
		"pool address",
		"pool port-overloading-factor",
		"pool routing-instance",
		"port-scan threshold",
		"profile feed-name",
		"profile stream-name",
		"proposal authentication-algorithm",
		"proposal authentication-method",
		"proposal description",
		"proposal dh-group",
		"proposal encryption-algorithm",
		"proposal lifetime-kilobytes",
		"proposal lifetime-seconds",
		"proposal protocol",
		"proxy-arp interface",
		"rule-set prefix",
		"rule-set rule",
		"rule-set source-pool",
		"saturday start-time",
		"saturday stop-time",
		"scheduler start-time",
		"scheduler stop-time",
		"schedulers scheduler",
		"screen ids-option",
		"security-zone description",
		"security-zone interfaces",
		"security-zone screen",
		"session field-extra-name",
		"source pool",
		"source rule-set",
		"source-nat pool",
		"ssh-known-hosts host",
		"static rule-set",
		"stream category",
		"stream facility",
		"stream format",
		"stream host",
		"stream port",
		"stream severity",
		"stream source-address",
		"stream source-interface",
		"sunday start-time",
		"sunday stop-time",
		"syn-flood alarm-threshold",
		"syn-flood attack-threshold",
		"syn-flood destination-threshold",
		"syn-flood source-threshold",
		"syn-flood timeout",
		"tcp-session closing-timeout",
		"tcp-session established-timeout",
		"tcp-session initial-timeout",
		"tcp-session time-wait-timeout",
		"then log",
		"thursday start-time",
		"thursday stop-time",
		"to interface",
		"to routing-instance",
		"to zone",
		"traceoptions file",
		"traceoptions flag",
		"traceoptions packet-filter",
		"traffic-selector local-ip",
		"traffic-selector remote-ip",
		"transport protocol",
		"transport tls-profile",
		"tuesday start-time",
		"tuesday stop-time",
		"udp-session timeout",
		"vpn bind-interface",
		"vpn df-bit",
		"vpn establish-tunnels",
		"vpn local-address",
		"vpn local-identity",
		"vpn pre-shared-key",
		"vpn remote-identity",
		"vpn traffic-selector",
		"vpn-monitor destination-ip",
		"vpn-monitor source-interface",
		"wednesday start-time",
		"wednesday stop-time",
		"zones security-zone":
		return true
	}
	return false
}

// normalizeCompactStanzasWithScope is normalizeCompactStanzas with the scope
// decision supplied by the caller. Production has exactly one caller and passes
// compactNormalizeInScope; tests pass a recorder to observe which keys the pass
// consults, or a widened predicate to explore past a refusal.
//
// An injection point rather than a reassignable package var, deliberately: a
// mutable global is reassignable by anything in the package, a test that
// forgets to restore it poisons every later test, and it makes t.Parallel() a
// data race. None of those failure modes announce themselves. This shape has no
// rule to remember. (Design: team-lead, reviewing the var form.)
func normalizeCompactStanzasWithScope(tree *ConfigTree, inScope func(containerKeyword, head string) bool) int {
	if tree == nil {
		return 0
	}
	return normalizeCompactNodes(tree.Children, setSchema, inScope)
}

func normalizeCompactNodes(nodes []*Node, schema *schemaNode, inScope func(containerKeyword, head string) bool) int {
	if schema == nil {
		return 0
	}
	n := 0
	for _, node := range nodes {
		if node == nil || len(node.Keys) == 0 {
			continue
		}
		kw := node.Keys[0]
		child := schema.children[kw]
		if child == nil {
			child = schema.wildcard
		}
		if child == nil {
			continue
		}
		// The node's own identity is its keyword plus its declared args.
		identity := 1 + child.args
		// #8763: a compoundKey container carries its second key as an
		// enumerated CHILD rather than an `args` token, so `identity` does not
		// count it. `family inet` is one node whose schema is
		// family.children["inet"]; without this the recursion below would hand
		// that node's children the schema for `family`, advancing the schema
		// one level where the node advanced two, and NOTHING beneath a braced
		// `family inet { … }` would ever be visited -- not "declined to fold",
		// never asked.
		//
		// It bites exactly where the second token is a child keyword. `unit 0`
		// is unaffected because there the second token is an instance arg and
		// `args` is precisely what `identity` counts. Every compoundKey
		// declaration in the schema is named `family`
		// (TestCompoundKeyNodesAreExactlyTheFamilyNodes8763), so this is a
		// bounded surface rather than an open-ended one.
		childSub := child
		if child.compoundKey && len(node.Keys) > identity {
			if sub, ok := child.children[node.Keys[identity]]; ok && sub != nil {
				identity++
				childSub = sub
			}
		}
		if len(node.Keys) > identity && len(node.Children) == 0 {
			head := node.Keys[identity]
			// The tail only reads as an elided BODY if its first token names a
			// child of this container. Otherwise it is this node's own
			// multi-value payload (a bracketed list, a multi: true leaf) and
			// must be left alone.
			// The container the scope predicate is asked about is the one that
			// actually HOLDS the head. After a compoundKey descent that is the
			// sub-key (`inet`), not the compound keyword (`family`) -- which is
			// the same pair production already asks for the separately-braced
			// spelling `family { inet filter …; }`, so the two spellings resolve
			// to one scope entry instead of two.
			ckw := kw
			if childSub != child && identity >= 2 {
				ckw = node.Keys[identity-1]
			}
			if _, isBody := childSub.children[head]; isBody && inScope(ckw, head) {
				tail := append([]string(nil), node.Keys[identity:]...)
				node.Keys = append([]string(nil), node.Keys[:identity]...)
				node.IsLeaf = false
				for _, stmt := range splitPackedStatements8768(tail, childSub) {
					node.Children = append(node.Children, &Node{Keys: stmt, IsLeaf: true})
				}
				n++
			}
		}
		n += normalizeCompactNodes(node.Children, childSub, inScope)
	}
	return n
}

// splitPackedStatements8768 divides a packed tail into one node per STATEMENT,
// instead of moving the whole run into a single child.
//
// The fold emitted `tail` as one node, which is right only when the run holds
// one statement. A run may hold several, and then every statement after the
// first was swallowed into the first one's Keys and lost:
//
//	policy p1 pre-shared-key ascii-text SEKRIT mode main;
//	  before -> policy p1 { [pre-shared-key ascii-text SEKRIT mode main] }
//	  after  -> policy p1 { [pre-shared-key ascii-text SEKRIT] [mode main] }
//
// THE BOUNDARY IS ANSWERED BY consumeNodeKeys, NOT GUESSED. Asking "is this
// token a sibling keyword" is not sufficient and is actively wrong: a VALUE may
// coincide with a sibling keyword, and #4313 makes some tails open-world. The
// measured case is `then { source-nat pool P persistent-nat permit off; }`,
// where `off` is a source-nat child AND a value inside a sub-grammar the schema
// does not model. Splitting on the name invents a second translation action and
// rejects a config that commits today — there is a cell for it,
// TestOpenWorldTailContainingOffStillCommits_7033, and it is why the
// name-matching version of this function was abandoned.
//
// So this borrows packedBodyChildren's contract: consume each statement by the
// schema's own count, and THE MOMENT a token leaves the modelled grammar, stop
// and hand back the whole tail unsplit. Not guessing is the entire safety
// argument; a partial split is worse than none because it publishes a shape the
// operator did not write.
func splitPackedStatements8768(tail []string, container *schemaNode) [][]string {
	if len(tail) == 0 || container == nil || !container.packedStatements {
		return [][]string{tail}
	}
	var out [][]string
	rest := tail
	for len(rest) > 0 {
		childSchema := resolveSchemaChild(container, rest[0])
		if childSchema == nil {
			// Outside the modelled grammar: do not guess where the next
			// statement starts. Everything measured so far is discarded and the
			// tail is returned whole, which is the pre-#8768 behaviour.
			return [][]string{tail}
		}
		n, _ := consumeNodeKeys(rest, childSchema)
		if n <= 0 || n > len(rest) {
			return [][]string{tail}
		}
		out = append(out, append([]string(nil), rest[:n]...))
		rest = rest[n:]
	}
	if len(out) <= 1 {
		return [][]string{tail}
	}
	return out
}
