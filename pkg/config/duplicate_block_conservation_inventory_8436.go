package config

// dupConservationInventory8436 is the ENUMERATION #8436 asked for: every named
// container where two hierarchical blocks do NOT compile to what the flat-set
// spelling produces.
//
// Why this instead of another registry row, in #8436's own words: every instance
// so far (#3884, #4287, #5180, #5631/#5878, #5649, #8426, #8427, #8433) was
// closed by adding a row or a bespoke gate, which is an OPT-IN pattern whose
// opt-ins were being discovered one review at a time. A registry-row test proves
// the row exists; it cannot see the next uncovered container, and the uncovered
// set was written down nowhere. It is written down here.
//
// A LINE HERE IS NOT AN ACCEPTED DEFECT. Each is one of two things, and the
// census's second (strict) compile is what tells them apart:
//
//   - REJECTED AT COMMIT — conservation achieved by refusal (namedDupRules or a
//     bespoke gate). The census compiles LENIENTLY, so it still sees the
//     reduction and the site stays listed; an operator never reaches it.
//   - SILENT — no commit gate at all. Configuration the operator authored is lost
//     with no diagnostic. THESE ARE THE CANDIDATES for the next fix.
//
// Reachability, which narrows the class usefully: flat-set `set` merges correctly
// in every measured case, so none of this is reachable through `set` commands —
// only a hierarchical config file, `load merge` or `load override`.
//
// Regenerate with TestDuplicateBlockConservationCensus8436 -v and read the
// NOT CONSERVED lines, which carry the verdict. Do not paste them in without
// reading the verdict column: a pinned list nobody reads is a list of defects
// with a checkmark next to it.
var dupConservationInventory8436 = []string{
	// #9024: THESE BECAME VISIBLE WHEN THE CENSUS LEARNED TO BUILD A NESTED
	// FIXTURE. Every one was in the SKIP list before — "no two synthesizable
	// single-value leaf children" — so the census formed no verdict about any
	// of them and reported a clean board. They are not new defects; they are
	// defects that were never inspected.
	//
	// FOUR ARE SILENT (no commit gate at all) and two were verified by hand
	// away from the census, because a widened instrument reporting new findings
	// is a claim about the instrument first:
	//
	//	firewall policer   two blocks -> bw=0 burst=15000
	//	                   merged     -> bw=125000 burst=15000
	//	                   The bandwidth limit is LOST: a rate limiter with no
	//	                   rate, which admits everything it was written to cap.
	//
	//	protocols ospf area  two blocks -> TWO area entries, same ID, 1 iface each
	//	                     merged     -> ONE area, 2 interfaces
	//	                     Not a loss but a DUPLICATE: two `area 0.0.0.0`
	//	                     stanzas reach FRR.
	//
	// The other two SILENT sites are `security ipsec policy` and `system
	// services dhcp-local-server group`. The remaining rows are
	// `rejected-at-commit` — conservation BY REFUSAL, a different and
	// acceptable disposition that the census reports separately.
	"firewall family any filter xpfname term",
	"firewall family inet filter xpfname term",
	"firewall family inet6 filter xpfname term",
	// #9899: implicit inet term diverges like its three family siblings --
	// same two-block vs merged reduction, same verdict as the inet row.
	"firewall filter xpfname term",
	"security screen ids-option",
	"system services dhcpv6-local-server group",
	// ---- SILENT: no commit gate at all. ----
	//
	// EMPTY — and this time the sentence is load-bearing rather than an
	// artefact of what the census could reach.
	//
	// It said EMPTY for a long time because the census could not REACH the
	// containers that were losing configuration. #9024 taught the fixture
	// builder to descend through container-only children, the population went
	// 30 -> 44, and four SILENT sites appeared at once:
	//
	//	firewall policer                        bandwidth-limit LOST
	//	protocols ospf area                     area DUPLICATED, not merged
	//	security ipsec policy                   rejected with a MISDIRECTING
	//	                                        message about missing proposals
	//	system services dhcp-local-server group
	//
	// Issue 9209 fixed all four by extending mergeDuplicateBlocks9023's site
	// list, so the set is empty again for the reason the sentence claims. What
	// the episode is worth remembering for:
	//
	//	AN INSTRUMENT THAT FILTERS ITS POPULATION BEFORE MEASURING REPORTS THE
	//	HEALTH OF WHAT SURVIVED THE FILTER, AND REPORTS IT AS THE HEALTH OF THE
	//	WHOLE.
	//
	// The reader who needs this is the one about to conclude that this class
	// is handled. Ask what the census cannot reach before believing a zero.
	//
	// The hedge was true when written and did all the work of the sentence,
	// which is how a reader arrives at "this class is handled". An empty
	// section plus an unmeasured majority is not evidence of absence; it is
	// evidence of reach. What remains below is conservation achieved by
	// REFUSAL, where an operator is told rather than quietly given a different
	// config.
	//
	// An empty section is not the end of the census's job — it is the state in
	// which the census earns its keep, because the next NEW non-conserving
	// container now fails TestDuplicateBlockConservationIsPinned8436 as a
	// regression instead of joining a list. Do not delete the section header:
	// a future site belongs here with a reason, not silently.

	// ---- Already REJECTED at strict commit (conservation by refusal) (8). ----
	//
	// #9192 removed `protocols bgp group xpfname neighbor` from this section:
	// the site now CONSERVES for a stronger reason than refusal. compileBGP
	// does find-or-create on (GroupName, Address) instead of appending one
	// *BGPNeighbor per AST node, so two `neighbor <ip>` blocks under one group
	// merge into one peer that carries both blocks' statements. The line is
	// deleted rather than re-homed because a stale entry hides the next
	// regression at that site, which is what this file exists to prevent.
	"applications application",
	"chassis device-map interface",
	"security flow traceoptions packet-filter",
	"security ike proposal",
	"security ipsec vpn xpfname traffic-selector",
	"security nat nat64 rule-set",
	"system services dhcp-local-server group xpfname pool xpfname static-binding",
	"system services dhcpv6-local-server group xpfname pool xpfname static-binding",
}

// dupConservationSkipped8436 is every named container the census could not
// CHECK — the second half of the enumeration, and the half that was missing.
//
// A SKIP IS NOT A PASS. Until this list existed the census reported skips as
// two integers, and `services rpm probe xpfname test` sat inside one of them
// for seven batches while silently losing configuration: two `test T` blocks
// overwrote each other, and the synthesized fixture omits the required
// `target`, so the compile failed and the site was COUNTED rather than checked.
// A number cannot be read as a defect. (That site is fixed now — see
// compiler_services.go — but it stays listed, because the census still cannot
// probe it.)
//
// TestDuplicateBlockConservationIsPinned8436 fails on a NEW skip and on a stale
// one, so a container the census cannot probe is a recorded decision rather
// than the one place a defect can hide from the guard #8436 asked for.
var dupConservationSkipped8436 = []string{
	// Issue 9024: the 85 containers below were INVISIBLE to this census until
	// the collector stopped dropping them. They are ELIGIBLE -- named
	// containers with children -- but no two-block fixture could be built, so
	// the collector discarded them BEFORE the census ran. They reached neither
	// the population nor this list, and the skip ratchet could not guard them
	// because the ratchet guards the population and the population was
	// filtered first.
	//
	// Measured: 139 eligible containers, 85 dropped (61%). The census was
	// examining 9 of them and reporting "SILENT: 0".
	//
	// Two of these are CONFIRMED silent drops proven end-to-end elsewhere
	// (#9023): `forwarding-options sampling instance` and `snmp trap-group`.
	// They are listed here as UNPROBED, which is the honest state -- this
	// census still cannot check them, and now says so by name instead of by
	// omission. Fixing the fixture so they become CHECKED is the follow-on.
	"applications application-set",
	"chassis cluster control-ports fpc",
	"chassis cluster redundancy-group xpfname node",
	"class-of-service classifiers dscp",
	"class-of-service classifiers dscp xpfname forwarding-class",
	"class-of-service classifiers dscp xpfname forwarding-class xpfname loss-priority",
	"class-of-service classifiers ieee-802.1",
	"class-of-service classifiers ieee-802.1 xpfname forwarding-class",
	"class-of-service classifiers ieee-802.1 xpfname forwarding-class xpfname loss-priority",
	"class-of-service classifiers inet-precedence",
	"class-of-service classifiers inet-precedence xpfname forwarding-class",
	"class-of-service classifiers inet-precedence xpfname forwarding-class xpfname loss-priority",
	"class-of-service fairness rss-expectation interface",
	"class-of-service interfaces xpfname shaping-rate",
	"class-of-service interfaces xpfname unit xpfname shaping-rate",
	"class-of-service rewrite-rules dscp",
	"class-of-service rewrite-rules dscp xpfname forwarding-class",
	"class-of-service rewrite-rules dscp xpfname forwarding-class xpfname loss-priority",
	"class-of-service rewrite-rules exp",
	"class-of-service rewrite-rules exp xpfname forwarding-class",
	"class-of-service rewrite-rules exp xpfname forwarding-class xpfname loss-priority",
	"class-of-service rewrite-rules ieee-802.1",
	"class-of-service rewrite-rules ieee-802.1 xpfname forwarding-class",
	"class-of-service rewrite-rules ieee-802.1 xpfname forwarding-class xpfname loss-priority",
	"class-of-service rewrite-rules inet-precedence",
	"class-of-service rewrite-rules inet-precedence xpfname forwarding-class",
	"class-of-service rewrite-rules inet-precedence xpfname forwarding-class xpfname loss-priority",
	"class-of-service scheduler-maps",
	"class-of-service scheduler-maps xpfname forwarding-class",
	"class-of-service schedulers xpfname buffer-size",
	"class-of-service schedulers xpfname transmit-rate",
	"event-options policy",
	"event-options policy xpfname within",
	// #9017: `family any` joins its two siblings, for the same structural
	// reason they are here -- the census cannot synthesize a two-block
	// duplicate fixture for a filter container. Nothing about `any` is
	// different; it is a third family declared so that
	// `set firewall family any filter ... then discard` stops committing
	// clean and minting zero filters.
	"firewall family any filter",
	"firewall family inet6 filter",
	"firewall family inet filter",
	// #9899: implicit inet filter joins its three family siblings, for the
	// same structural reason -- the census cannot synthesize a two-block
	// duplicate fixture for a filter container. Duplicate filter names are
	// still refused at strict commit (#8426, exercised for the implicit
	// spelling in TestImplicitInetFilterGates9899), so the skip is not a
	// silent loss.
	"firewall filter",
	"firewall three-color-policer",
	"forwarding-options port-mirroring instance",
	"policy-options community",
	"policy-options policy-statement",
	"policy-options policy-statement xpfname term",
	"protocols lldp interface",
	"protocols ospf3 area",
	"protocols ospf area xpfname interface xpfname authentication md5",
	"protocols ospf area xpfname virtual-link",
	"protocols router-advertisement interface xpfname nat64prefix",
	"protocols router-advertisement interface xpfname nat-prefix",
	"routing-options generate route",
	"routing-options rib",
	"routing-options rib xpfname static route xpfname next-hop",
	"routing-options static route xpfname next-hop",
	"security address-book global address-set",
	"security dynamic-address address-name",
	"security dynamic-address feed-server xpfname feed-name",
	"security nat destination pool",
	"security nat destination rule-set",
	"security nat destination rule-set xpfname rule",
	"security nat proxy-arp interface",
	"security nat source rule-set",
	"security nat source rule-set xpfname rule",
	"security nat static rule-set",
	"security nat static rule-set xpfname rule",
	"security policies from-zone",
	"security zones security-zone xpfname address-book address-set",
	"services ip-monitoring policy",
	"services ip-monitoring policy xpfname then preferred-route routing-instance",
	"services rpm probe",
	// #9416: `snmp community` left this list. It became PROBEABLE when
	// `client-list-name` was declared — the census needs two distinct
	// synthesizable body statements to build a duplicate fixture, and
	// `authorization` (an enum) plus `clients` (multi) did not give it one.
	// A stale skip entry claims the census cannot see a site it now checks, so
	// the line is deleted rather than kept "just in case".
	//
	// Its replacement is one level down: the community's own
	// `routing-instance` body, which the census still cannot build a fixture
	// for. Listed by name rather than left in a skip COUNT, which is the whole
	// point of this file.
	"snmp community xpfname routing-instance",
	"snmp trap-group",
	"system backup-router",
	"system ntp threshold",
	"system services dhcp-local-server group xpfname pool",
	"system services dhcpv6-local-server group xpfname pool",

	// ---- "a spelling did not parse or compile" (5). ----
	//
	// The synthesized duplicate did not survive commit, which is EITHER
	// conservation by refusal OR a fixture the census cannot build. The two are
	// indistinguishable from the census alone, so each was checked BY HAND with
	// a complete config and the verdict recorded here.
	//
	// REFUSED at commit — duplicate policy name in a zone pair is a hard reject
	// (#3473: the duplicate shares a name-keyed hit counter).
	//
	// #8752: THAT REASON IS A STRICT-PATH FACT, AND THIS CENSUS GOVERNS BOTH
	// PATHS. `Store.Load` and `Store.SyncApply` compile leniently — which is the
	// entire point of them, since they read configurations the operator did not
	// just author — and the lenient path does NOT refuse. So both entries were
	// exempted here on a rejection that does not happen on the path where the
	// defect lives.
	//
	// THE DEFECT THAT FINDING EXPOSED IS NOW FIXED, and this note is kept
	// because the exemption is still taken and a reader has to be able to tell
	// which half of it was answered. As measured BEFORE the fix
	// (TestTheDuplicatePolicyPoisonsTheSnapshot8752, since re-pointed):
	//
	//	policy[0] src=[10.0.0.0/8] dst=[any] app=[any] permit  dropped=false
	//	policy[1] src=[]           dst=[]    app=[]    deny    dropped=TRUE
	//
	// The spurious policy sat SECOND, so it never won a first-match evaluation,
	// and an all-empty match reads as match-ANY — a deny-all exactly where the
	// zone pair already has an implicit default-deny. On its own that was close
	// to inert, and "the duplicate wins" was the wrong reading: it invites
	// making the FIRST occurrence authoritative, which would have left the real
	// harm in place.
	//
	// THE OPERATIVE HARM WAS `LenientContentDropped`. compilePolicy sets it
	// because the tolerant path accepted the policy only by dropping a required
	// match dimension, and policies_lower.go then poisons the rule with the
	// `__unsupported__` application sentinel SO THAT the Rust integrity
	// preflight rejects the WHOLE SNAPSHOT — previous-good retained, fresh-boot
	// default-deny. The consequence was therefore not an altered policy set an
	// operator could read in `show`: it was that the operator's ENTIRE
	// configuration did not load. On a fresh boot, a blackout.
	//
	// THE FIX (mergeDuplicateNamedInstances, gated on the tolerant path) folds
	// the repeated `policy <p>` into the first occurrence, carrying its children
	// and any packed tail onto the surviving policy. Measured after it:
	//
	//	security policies from-zone <a> <b> <c> policy   strict REJECTED, lenient ACCEPTED -> 1 policy
	//	security policies global policy                  strict REJECTED, lenient ACCEPTED -> 1 policy
	//
	//	policy[0] src=[10.0.0.0/8] dst=[any] app=[any] deny    dropped=false
	//
	// — one policy, criteria intact, the poison flag CLEAR, so the snapshot
	// loads. The terminal action resolves to the later statement's `deny`, which
	// is what the flat `set` spelling produces for the same input, and the
	// existing conflicting-terminal-action gate still reports the disagreement.
	// The fold also warns, so a configuration a strict commit REJECTS does not
	// load silently.
	//
	// WHAT THIS MEANS FOR THE TWO ENTRIES: the strict-path premise they are
	// skipped on is UNCHANGED and still asserted — both are still refused at
	// commit — so the skip remains correct. What changed is that the tolerant
	// path now has an answer instead of an unexamined gap. The finding that
	// produced this annotation was not that the entries were wrong to skip; it
	// was that their stated reason could not speak for the path where the
	// defect lived.
	// The entries STAY — the census genuinely cannot synthesize these, so
	// skipping is right — but the REASON is annotated rather than left standing,
	// because a skip with a stated reason reads as settled and nobody
	// re-derives it. A census governing two compile paths cannot take an
	// exception justified on only one; "REFUSED at commit" is unanswerable for
	// the tolerant path by construction.
	"security policies from-zone xpfname xpfname xpfname policy",
	"security policies global policy",
	// REFUSED at commit — "duplicate expectation \"any\" conflicts with
	// \"balanced\"".
	// #8752: re-checked on the LENIENT path too, and this one is correctly
	// skipped — it is refused on BOTH paths (lenient rejects it as well), so the
	// exemption does not rest on a strict-path-only fact. Recorded so the
	// re-check is visible: two of the three entries in this group were wrong and
	// this one was not, which is the difference a reader needs.
	"class-of-service fairness rss-expectation interface xpfname queue",
	// CONSERVES. The census fixture omits the required `match rpm-probe`; with a
	// complete config the duplicate compiles identically to the merged form.
	"services ip-monitoring policy xpfname then preferred-route route",
	// DID NOT CONSERVE, now FIXED. The census fixture omits the required
	// `target`. With a complete config two `test T` blocks overwrote each other
	// — the probe level had been fixed, the test level one layer down had not.
	// This is the site that motivated pinning the skip set.
	"services rpm probe xpfname test",

	// ---- "second leaf not observable in the typed config" (13). ----
	//
	// #8662: was 15. `system login user` left this list when the compact/block
	// census's value synthesis learned to read the schema's valueHint — its
	// second leaf became observable, so the skip entry was claiming a blindness
	// the census no longer has. The two censuses share synthPair, so an
	// improvement to the instrument moves both.
	//
	// #9125: was 14. `routing-options static route` left it for a different
	// reason, and one worth distinguishing: nothing about the CENSUS changed.
	// The compiler gained a HasPreference bit, so an explicit `preference 5`
	// stopped compiling identically to a block that omits it — the leaf became
	// observable because the PRODUCT learned to represent it, not because the
	// instrument got sharper.
	//
	// That is #9181's mechanism running in reverse, and it is the useful half
	// of that finding: a `vacuous` verdict is a statement about what the typed
	// config can EXPRESS, so fixing an expressiveness gap silently un-vacuums a
	// census row. The site is CHECKED now and conserves.
	//
	// The census's own VACUITY guard. The merged form compiles identically to a
	// block carrying only the first leaf, so the census sees nothing.
	//
	// #9181: THE REASON THIS SET USED TO GIVE WAS FALSE, and it is corrected
	// here rather than deleted. It said the second leaf "is invisible to the
	// typed config and the site cannot show a loss either way". The first
	// clause is a true observation about THE FIXTURE; the second is a claim
	// about the SITE, and it was wrong for all three entries below. Each SHOWED
	// a real loss once the fixture could express what the site needs, and each
	// needed a DIFFERENT thing — which is why one shared sentence covered them
	// and was wrong about every one:
	//
	//	protocols bgp group      needed a SIBLING (`neighbor`) plus that
	//	                         sibling's own prerequisite (`peer-as`, required
	//	                         by the compiler and not declared in the schema).
	//	                         Group settings fold into BGPNeighbor, so with no
	//	                         neighbor there was nothing for them to land in.
	//	                         THE LOSS ITSELF IS NOW FIXED (#9199): the packed
	//	                         and split spellings both yield one neighbor,
	//	                         measured. The entry stays skipped because the
	//	                         FIXTURE still cannot express the prerequisite —
	//	                         which is the distinction this comment exists to
	//	                         draw, now demonstrated by a site that is
	//	                         unmeasurable AND correct rather than
	//	                         unmeasurable and broken.
	//	cos interfaces .. unit   needs the referenced object DEFINED: a
	//	                         `scheduler-map` reference to an undefined map is
	//	                         rejected outright, so the fixture never compiles.
	//	RA .. prefix             needs a THIRD leaf: its first two are booleans
	//	                         that collapse identically, so two leaves cannot
	//	                         separate the spellings at all.
	//
	// So these stay skipped because THE FIXTURE CANNOT EXPRESS THE
	// PREREQUISITE, not because the site is unobservable. That distinction is
	// the whole of #9181: "not measured" and "nothing to measure" had the same
	// spelling here, and the second reading hardened into a justification a
	// reader would not re-check.
	//
	// Listed so the set is BOUNDED — a container that newly becomes
	// unobservable is a change worth noticing, not a silent drop in coverage.
	"class-of-service interfaces xpfname unit",
	"protocols bgp group",
	"protocols router-advertisement interface xpfname prefix",

	// Issue 9151: `protocols rip group` gained its two real children
	// (`neighbor`, `export`) when the schema was corrected to declare what
	// compiler_protocols.go actually reads. BOTH are `multi: true`, so
	// `twoLeaves8436` finds no two SINGLE-VALUE leaves and cannot synthesize a
	// duplicate fixture. The skip is structural, not a coverage regression.
	//
	// A SKIP IS NOT A PASS, so this one was checked BY HAND before being
	// recorded, in both spellings:
	//
	//	set ... group g1 neighbor ge-0/0/0        ifaces=[ge-0/0/0 ge-0/0/1]
	//	set ... group g1 neighbor ge-0/0/1        redist=[static direct]
	//	group g1 { neighbor ge-0/0/0; }           ifaces=[ge-0/0/0 ge-0/0/1]
	//	group g1 { neighbor ge-0/0/1; }
	//
	// The site CONSERVES. Note also that "conservation" means something
	// different for a multi leaf than for a single-value one -- multi
	// ACCUMULATES where single-value REPLACES -- so this census's model does
	// not apply here even if a fixture could be built.
	"protocols rip group",
	"routing-options rib xpfname static route",
	"routing-options rib xpfname static route xpfname qualified-next-hop",
	"routing-options static route xpfname qualified-next-hop",
	"security ipsec proposal",
	"security log stream",
	"system services dhcp-local-server group xpfname interface",
	"system services dhcpv6-local-server group xpfname interface",
	"system syslog file",
	"system syslog host",
	"system syslog user",
	// #9553: DHCPv6 `group` is a named container whose required
	// `active-server-group` and `interface` children cannot be synthesized by
	// this generic duplicate fixture without also constructing a valid
	// server-group. The typed compiler and dedicated relay tests cover it.
	"forwarding-options dhcp-relay dhcpv6 group",
}
