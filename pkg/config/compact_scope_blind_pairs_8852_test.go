package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// #8852: a scope widening whose pair yields ZERO census sites is
// indistinguishable from one the guard fully adjudicated. Both are green.
//
// THE DEFECT. TestCompactNormalizeScopePreservesCompiledResult8690 (arm 2)
// adjudicates the sites collectCompactSites generates. That census emits a site
// only for a SINGLE-ARG VALUED LEAF or a NAMED-INSTANCE container:
//
//	wildcardNamed := ch.args == 0 && ch.wildcard != nil
//	if (ch.wildcard == nil && ch.args == 1 || wildcardNamed) && len(path) >= 1 {
//
// So admitting a pair whose HEAD is a plain container, a zero-arg leaf, or a
// multi-arg node produces no site at all — the pair is adjudicated by nothing,
// and nothing in the output says so. It does not even reach a skip bucket:
// the unsynthesizable / unparsable / inScopeUnexaminable buckets are populated
// per SITE, and there is no site.
//
// MEASURED. #8847 admitted three top-level pairs and arm 2 adjudicated NONE of
// them. Attribution was established by REMOVING the three entries from
// compactNormalizeInScope and re-counting: the adjudicated total was unchanged,
// so no adjudicated site depended on them. That toggle is the only sound
// instrument here — a substring or path-prefix test over the site paths
// attributes `routing-options static route` to ("routing-options","static")
// when its actual pair is ("static","route"), because the arm derives
// `stanza := container[len-1]`. A site's path prefix is not its pair.
//
// WHY A SET AND NOT A THRESHOLD, and why the reason is DERIVED rather than
// declared. This is the same shape as the inScopeUnexaminable list above it: a
// NEW blind pair reds, and a pair that BECOMES adjudicated also reds, so the
// list cannot quietly outlive its reason. The registered reason is then
// RE-DERIVED from the schema on every run and compared, so registration cannot
// become a silent escape hatch — you cannot park a pair here with a reason that
// is not true of its node. And a pair blind for NO recognised structural reason
// fails outright: that is a bug in the census, not a registrable exception.
//
// Registering a pair here is NOT a statement that its folding is correct. It
// records that this arm does not measure it. Blind means unmeasured, not safe.
//
// DO NOT READ THIS LIST AS A BENIGN INVENTORY, and do not read it as a defect
// list either. Those are different properties with different lifetimes, and the
// first version of this comment mixed them and rotted within hours.
//
// BLINDNESS IS DURABLE: a pair is here because arm 2's census emits no site for
// its head, which is a property of the census and changes only when the census
// changes. WHETHER THE FOLD IS BROKEN IS VOLATILE: it changes the moment
// someone lands a fold fix, and #8850 landed three while this comment was being
// written.
//
// So defect status lives in #8850, not here. What follows is a dated SNAPSHOT,
// kept because it shows the list has real defects in it and is not decorative —
// not as a register anyone should trust to be current.
//
//	measured at 887400000        measured at b24e26d3b (after #8850)
//	 address-book   1 -> 0        address-book   1 -> 0   still broken
//	 policies       1 -> 0        policies       1 -> 1   FIXED
//	 host-inbound   1 -> 0        host-inbound   1 -> 1   FIXED
//
// The `host-inbound` row is the one worth understanding, because two people
// measured it and got opposite answers WITHOUT either being wrong. Elision has
// DEPTH, and only one depth lost:
//
//	host-inbound-traffic { system-services { ping; } }   braced   -> 1
//	host-inbound-traffic system-services { ping; }       PARTIAL  -> 0   lost
//	host-inbound-traffic system-services ping;           PACKED   -> 1   fine
//
// The fully-packed form has no children, so the fold handled it; the partially
// elided form carries a packed tail AND a braced body, and the gate
// `len(node.Keys) > identity && len(node.Children) == 0` declined it silently.
// A fixture on the packed side of that boundary shows no defect by a completely
// sound method. Fixed by 648ff4690 ("fold a packed tail even when the node has
// a braced body").
//
// TWO FIXTURE TRAPS, recorded because each produced a confident wrong answer:
//
//   - The `policies` comparison needs its zones DEFINED in the braced arm.
//     Without `security-zone trust` / `untrust` the braced arm fails an
//     undefined-zone gate and yields NOTHING, so braced and elided agree at
//     zero. Which conclusion that supports depends only on how the assertion is
//     phrased — it reads as "no defect" or as "value lost" with equal ease.
//   - Elision depth, above: test the packed spelling only and a real defect is
//     invisible.
//
// AND REPAIRING A FOLD DOES NOT REMOVE ITS PAIR FROM THIS LIST. `policies` and
// `host-inbound` are fixed and still registered here, correctly: they remain
// pairs arm 2 adjudicates nothing for. A pair leaves only when the census
// starts generating a site for it.
var knownBlindScopePairs8852 = map[string]string{
	// Head is a plain container (args==0, no wildcard, has children).
	"policies global": "plain-container",
	// #8879 batch 1. Admitted after measuring their elided spelling SILENT;
	// all four are blind to arm 2 for the same structural reason as the rest of
	// this group, so their fold correctness rests on the per-pair cells in
	// elision_admissions_8879_test.go rather than on the census.
	"protocols bgp": "plain-container",
	// #8879 batch 2, same reasoning as batch 1: admitted after measuring the
	// elided spelling SILENT, blind to arm 2 for the same structural reason, so
	// their fold correctness rests on the per-pair cells rather than the census.
	// #8943 final: shapes derived by the sentinel method; all plain-container.
	"address-book global":           "plain-container",
	"archival configuration":        "plain-container",
	"bgp damping":                   "plain-container",
	"bgp multipath":                 "plain-container",
	"dataplane coalescence":         "plain-container",
	"dataplane shared-umem":         "plain-container",
	"flow-monitoring version9":      "plain-container",
	"flow-monitoring version-ipfix": "plain-container",
	"interface-routes rib-group":    "plain-container",
	"license autoupdate":            "plain-container",
	"policies policy-rematch":       "plain-container",
	"pre-id-default-policy then":    "plain-container",
	"rib static":                    "plain-container",
	// The three syslog destinations were REGISTERED here as `named-container`
	// and are now REMOVED, because the census can SEE them: collectCompactSites
	// gained the arg-named-with-wildcard-body clause, so they emit sites like
	// any other pair.
	//
	// Registering correctly DIAGNOSED why they were blind. It did not remove
	// the consequence: while blind, the standing empty-equivalence
	// verification passed over all three admissions by examining nothing.
	// Measured 0 sites before the census fix, 6 after.
	//
	// This is the removal this registry exists to force -- a registration that
	// outlives its reason is a recorded blindness nobody re-opens, and this
	// cell reds the moment one does.
	// #8943, the flow family; shapes derived by the sentinel method.
	"flow aging":        "plain-container",
	"flow icmp-session": "plain-container",
	"flow tcp-session":  "plain-container",
	"flow traceoptions": "plain-container",
	"flow udp-session":  "plain-container",
	// #8943, the nat family; shapes derived by the sentinel method.
	"nat destination": "plain-container",
	"nat nat64":       "plain-container",
	"nat natv6v4":     "plain-container",
	"nat proxy-arp":   "plain-container",
	"nat static":      "plain-container",
	// #8929, a DEPTH-2 pair; shape derived by the sentinel method.
	"nat source": "plain-container",
	// #8925. Shapes derived by the sentinel method, and this is the batch where
	// that mattered: they are NOT all plain-container. Every earlier batch
	// derived plain-container four times running -- exactly the run of
	// confirmations that makes assuming the fifth feel safe.
	"class-of-service forwarding-classes": "plain-container",
	"policy-options as-path":              "multi-arg",
	"system internet-options":             "plain-container",
	// #8879 batch 9, shapes derived by the sentinel method.
	"forwarding-options port-mirroring": "plain-container",
	"routing-options interface-routes":  "plain-container",
	"security ssh-known-hosts":          "plain-container",
	"services flow-monitoring":          "plain-container",
	"services ip-monitoring":            "plain-container",
	// #8879 batch 8, shapes derived by the sentinel method.
	"forwarding-options family": "plain-container",
	"protocols ospf3":           "plain-container",
	"security dynamic-address":  "plain-container",
	"system dataplane":          "plain-container",
	// #8879 batch 7, shapes derived by the sentinel method.
	"class-of-service classifiers":   "plain-container",
	"class-of-service rewrite-rules": "plain-container",
	"protocols lldp":                 "plain-container",
	"security pre-id-default-policy": "plain-container",
	// #8879 batch 6, shapes derived by the sentinel method.
	"forwarding-options dhcp-relay":    "plain-container",
	"protocols rip":                    "plain-container",
	"routing-options forwarding-table": "plain-container",
	// #8879 batch 5, shapes derived by the sentinel method.
	"class-of-service fairness": "plain-container",
	"security policy-stats":     "plain-container",
	"security ipsec":            "plain-container",
	"services rpm":              "plain-container",
	// #8879 batch 4. Shapes derived the same way as batch 3 — sentinel first,
	// then read back off this cell's own re-derivation.
	"forwarding-options sampling":    "plain-container",
	"protocols router-advertisement": "plain-container",
	"snmp v3":                        "plain-container",
	"system archival":                "plain-container",
	// #8879 batch 3. Shapes DERIVED, not assumed — registered with a sentinel
	// first and read back off this cell's own re-derivation, which is the only
	// reading that cannot be my expectation echoed back at me.
	"protocols isis":           "plain-container",
	"routing-options generate": "plain-container",
	"system license":           "plain-container",
	"security log":             "plain-container",
	"chassis device-map":       "plain-container",
	"protocols ospf":           "plain-container",
	"security address-book":    "plain-container",
	"system ntp":               "plain-container",
	"security ike":             "plain-container",
	"security nat":             "plain-container",
	"system syslog":            "plain-container",
	"policy then":              "plain-container",
	"routing-options static":   "plain-container",
	"security alg":             "plain-container",
	"security flow":            "plain-container",
	// #8850 admitted ("firewall","family") so an elided `firewall family inet
	// { filter ... }` compiles its filters instead of silently producing zero.
	// `family` is args:0 with children and no wildcard, so blindShape8852
	// classifies it plain-container like the rest of this group -- the census
	// emits no site for it, which is why arm 2 adjudicates nothing.
	//
	// COVERED THERE IS NOT ADJUDICATED HERE. TestElidedFirewallFamily8850
	// compares the WHOLE Firewall struct braced-vs-elided for inet and inet6,
	// so the pair's BEHAVIOUR is asserted -- but this entry records that arm 2
	// is BLIND to it, and that stays true however the fold behaves. Fixing or
	// breaking the fold does not remove this pair from the map; only the census
	// gaining a site for it does. Read this as a boundary, not as a clearance.
	"firewall family": "plain-container",
	// issue 8858. Unlike the two confirmed-broken entries above, this pair's
	// fold IS repaired and measured -- but by its own cells, not by arm 2, and
	// a pair leaves this list only when arm 2 starts generating a site for it.
	// The four `root-authentication <leaf>` pairs are NOT here: their heads are
	// single-arg valued leaves, so arm 2 does adjudicate them.
	// issue 8898. Same shape as root-authentication below: arm 2 emits no site
	// for a zero-arg plain container. Its fold IS measured -- across all three
	// depths and on the enforced value -- by the cells in
	// pkg/configstore/master_password_elision_8898_test.go, which is where the
	// real consumer lives; registration records only that THIS arm does not
	// measure it.
	"system master-password":     "plain-container",
	"system root-authentication": "plain-container",
	// issue 8875. Their folds ARE measured -- by
	// TestSecurityTopLevelElisionKeepsContents8875, across all three depths and
	// on compiled CONTENTS -- but not by arm 2, and a pair leaves this list
	// only when arm 2 generates a site for it. Registration records that this
	// arm does not measure them; it is not a claim that they are unfixed.
	"security policies":                  "plain-container",
	"security screen":                    "plain-container",
	"security zones":                     "plain-container",
	"security-zone address-book":         "plain-container",
	"security-zone host-inbound-traffic": "plain-container",
	// Head takes two or more identity args.
	//
	// #8850 admitted ("address-book","address") and ("global","address") so that
	// an elided `address-book address a1 10.0.0.1/32;` compiles its entries
	// instead of silently producing an EMPTY book. `address` is args:2 (name and
	// prefix), so blindShape8852 classifies both multi-arg and the census emits
	// no site -- arm 2 adjudicates nothing for them.
	//
	// Same boundary as `firewall family` above. TestElidedAddressBook8850
	// asserts the BEHAVIOUR -- compiled address NAMES braced-vs-elided, for both
	// books, at one AND at two entries, the two-entry arm being the one that
	// matters because the scope entry alone folds a multi-statement run into one
	// and silently keeps only the first. That cell existing is why these pairs
	// are registered instead of red; it is NOT why they are in the map. They are
	// in the map because arm 2 emits no site for them, which no amount of
	// behavioural coverage changes.
	//
	// So: if TestElidedAddressBook8850 is ever deleted, this comment becomes
	// false and should break loudly. If the fold is repaired, broken, or
	// rewritten, these entries stay exactly as they are.
	"address-book address":    "multi-arg",
	"global address":          "multi-arg",
	"gateway local-identity":  "multi-arg",
	"gateway remote-identity": "multi-arg",
	"policies from-zone":      "multi-arg",
	"policy pre-shared-key":   "multi-arg",
	// #9056 RETIRED FOUR `zero-arg-leaf` ENTRIES, and the retirement is the
	// change working rather than a loosening. `flow tcp-mss`, `match
	// {source,destination}-address-excluded` and `services
	// application-identification` were blind because collectCompactSites
	// admitted a site only when the head declared an `args` token or a
	// wildcard, so a VALUELESS head yielded nothing to adjudicate. The census
	// now enumerates that shape with a PRESENCE discriminator, so all four are
	// adjudicated by TestCompactNormalizeScopePreservesCompiledResult8690 and a
	// registration for them would be a claim that is no longer true.
	//
	// The `zero-arg-leaf` branch of blindShape8852 is KEPT: it still describes
	// the shape correctly, and the classifier must be able to name it if a
	// future change re-narrows the census. A branch with no current member is
	// not the same as a wrong branch, and deleting it would mean the next
	// re-narrowing reported "a reason this model does not explain" instead of
	// naming the cause.
}

// blindShape8852 classifies WHY the census emits no site for a head node,
// mirroring the emission condition in collectCompactSites. Returns "" when the
// node's shape IS one the census emits, so a caller can tell "blind for a known
// structural reason" from "blind for a reason this model does not explain".
func blindShape8852(n *schemaNode) string {
	switch {
	case n == nil:
		return "not-found"
	case n.args >= 2:
		return "multi-arg"
	// #8943: a NAMED container -- it takes an instance name AND declares a
	// wildcard, so every site the census synthesises for it carries the
	// instance name in the container element (`host xpfarg`, not `host`).
	// A pair-keyed census cannot match that against the bare (syslog, host)
	// the scope predicate is keyed on, so the pair is blind for the same
	// permanent reason `interfaces <name>` is unreachable to the predicate.
	//
	// Added because admitting `syslog host` / `file` / `user` made three pairs
	// blind with shape "" -- which this cell correctly refuses to let anyone
	// register, since an unexplained blindness is a census bug rather than an
	// exception. It was not a bug: the reason is structural and real, and the
	// model simply had no branch for args>=1 WITH a wildcard (every other case
	// requires wildcard == nil).
	case n.args >= 1 && n.wildcard != nil:
		return "named-container"
	case n.args == 0 && n.wildcard == nil && n.children != nil:
		return "plain-container"
	case n.args == 0 && n.wildcard == nil && n.children == nil:
		return "zero-arg-leaf"
	}
	return "" // the census DOES emit sites for this shape
}

func TestScopeWideningYieldsAdjudicatedSites8852(t *testing.T) {
	// Sites per (container, head). A container ELEMENT may hold several
	// space-separated tokens ("application xpfarg" is ONE element), so flatten
	// and split before walking back past the schema arg placeholders — keying
	// on container[len-1] verbatim makes almost every named-instance pair look
	// blind, which is how this census first reported 213 instead of 14.
	siteCount := map[[2]string]int{}
	for _, s := range collectCompactSites() {
		if len(s.container) == 0 {
			continue
		}
		toks := strings.Fields(strings.Join(s.container, " "))
		ci := len(toks) - 1
		for ci > 0 && strings.HasPrefix(toks[ci], "xpf") {
			ci--
		}
		siteCount[[2]string{toks[ci], s.leaf}]++
	}

	admitted := map[[2]string]*schemaNode{}
	var walk func(n *schemaNode, kw string, d int)
	walk = func(n *schemaNode, kw string, d int) {
		if n == nil || d > 9 {
			return
		}
		for name, ch := range n.children {
			if kw != "" && compactNormalizeInScope(kw, name) {
				admitted[[2]string{kw, name}] = ch
			}
			walk(ch, name, d+1)
		}
		if n.wildcard != nil {
			walk(n.wildcard, kw, d+1)
		}
	}
	walk(setSchema, "", 0)

	if len(admitted) == 0 {
		t.Fatal("DEGENERACY: no admitted pair was reachable in the schema, so " +
			"every check below is vacuous")
	}

	var blind []string
	unexplained := map[string]string{}
	derived := map[string]string{}
	for p, node := range admitted {
		if siteCount[p] > 0 {
			continue
		}
		key := p[0] + " " + p[1]
		blind = append(blind, key)
		shape := blindShape8852(node)
		derived[key] = shape
		if shape == "" || shape == "not-found" {
			unexplained[key] = shape
		}
	}
	sort.Strings(blind)

	// A pair blind for no recognised structural reason is a census bug, not a
	// registrable exception — registration is bounded to the width of the
	// mechanism it describes.
	if len(unexplained) > 0 {
		t.Errorf("%d admitted pair(s) yield NO census site for a reason this "+
			"model does not explain: %v\nThe census emits a site only for a "+
			"single-arg valued leaf or a named-instance container. A pair "+
			"blind outside that set means collectCompactSites changed and this "+
			"classifier did not — fix the census or the classifier, do NOT "+
			"register it (#8852).", len(unexplained), unexplained)
	}

	var want []string
	for k := range knownBlindScopePairs8852 {
		want = append(want, k)
	}
	sort.Strings(want)
	if strings.Join(blind, "\n") != strings.Join(want, "\n") {
		t.Errorf("the set of admitted pairs arm 2 adjudicates NOTHING for has "+
			"changed.\n got %d:\n  %s\nwant %d:\n  %s\n"+
			"A NEW entry means a widening was admitted that "+
			"TestCompactNormalizeScopePreservesCompiledResult8690 does not "+
			"measure at all — it is green and silent about that pair, which is "+
			"indistinguishable from having adjudicated it. A REMOVED entry "+
			"means a pair became adjudicated and its registration must go, so "+
			"this list cannot outlive its reason (#8852).",
			len(blind), strings.Join(blind, "\n  "),
			len(want), strings.Join(want, "\n  "))
	}

	// The registered reason is RE-DERIVED and compared, so a pair cannot be
	// parked here under a reason that is not true of its node.
	for key, reg := range knownBlindScopePairs8852 {
		got, ok := derived[key]
		if !ok {
			continue // set mismatch already reported above
		}
		if got != reg {
			t.Errorf("blind pair %q is registered as %q but its schema node is "+
				"%q. The reason is re-derived every run precisely so a "+
				"registration cannot drift from the shape that causes it "+
				"(#8852).", key, reg, got)
		}
	}

	t.Logf("#8852: %d admitted pairs, %d with >=1 adjudicated site, %d blind (all registered)",
		len(admitted), len(admitted)-len(blind), len(blind))
	_ = fmt.Sprint
}
