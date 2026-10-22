package grpcapi

import (
	"context"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/clusterfailover"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/optopic"
)

// #16136 — the equivalence cycle, retained after the flip.
//
// The optopic registry (pkg/optopic) is now the one place a ShowText topic /
// SystemAction verb is written down with its price, canonical command, and
// fabric admission. Typed handlers stay here in pkg/grpcapi. This file is
// the retained INDEPENDENT instrument, and it has three independent legs —
// none of them reads an expected value out of pkg/optopic:
//
//   - KEY CENSUS (what the handlers serve): ShowText via AST extraction of
//     `switch req.Topic` case labels, `req.Topic == "x"`, and
//     `strings.HasPrefix(req.Topic, "x")` in server_show.go
//     (showTextTopicsFromDispatcher), PLUS a differently-shaped second
//     scrape: the #6532 fabric audit's regexp extraction (dispatcherTopics),
//     which walks every production file's `req.Topic ==` /
//     `HasPrefix(req.Topic, ...)` text and the switch's case lines. The two
//     scrapes must agree with each other before either is compared to the
//     registry — a scrape bug cannot silently shrink both. SystemAction via
//     AST `switch req.Action` case labels (systemActionVerbsFromHandler),
//     PLUS the HasPrefix literals the handler branches on outside the
//     switch, PLUS the cluster-failover grammar family.
//   - ATTRIBUTION (what each key costs and which command emits it): the
//     FROZEN pre-registry tables in authz_registry_frozen_16136_test.go,
//     captured as literals from the merge-base literal tables
//     (ba55ef764a: cmdtree's showTextTopicCommand, grpcapi's
//     showTextViewTopics/showTextElevatedTopics/systemActionPermissions,
//     authz's SystemActionVerbCommand) with the single justified delta
//     `applications:`. Production lookups (showTextTopicPermission,
//     showTextTopicCanonicalCommand, systemActionPermission,
//     systemActionVerbCommand) are graded against THOSE rows, never
//     against optopic entries — comparing them to the registry row they
//     are derived from would prove only that the derivation ran.
//   - ENUMERATED ARMS: prefix-priced families, fabric admission, and
//     unknown-content strictness keep the literal expectations below.
//
// …and asserts, over the full census, separately enumerated:
//
//  1. exact handler cases ≡ exact registry keys (both directions);
//  2. prefix handler arms ≡ prefix registry keys (both directions);
//  3. every scraped key is PRICED and COMMANDED at exactly the frozen
//     pre-registry expectation (attribution: a syntactically valid but
//     wrong command, or a wrong price, reds here even though every
//     derived view agrees with the registry);
//  4. prefix-priced families: every prefix the handler serves is a
//     registered PermMaint/PermAll family, and every registered family is
//     served (no stale family, no unpriced family);
//  5. fabric admission: the registry's FabricAllowed set is exactly
//     {"chassis-forwarding"} for topics and {"clear-persistent-nat"} plus
//     the parsed node-targeted failover forms for verbs — enumerated here,
//     not read back from the registry as its own oracle for the failover
//     half (that half is decided by clusterfailover.ParseAction);
//  6. anonymous/anonymous-equivalent admission stays narrow: an unknown
//     topic prices at PermAll (super-user only) and resolves to no
//     command, an unknown verb falls to PermMaint with no command, and
//     neither is fabric-admitted.
//
//// RED on revert: drop or rename one registry entry, reprice one entry,
// add a handler case without registering it, or register a topic the
// dispatcher does not serve — each reds a distinctly-named arm below.

// defaultBranchShowTextTopics are the ShowText topics the dispatcher's
// default branch serves without a case/==/HasPrefix literal of the shapes
// the AST scrape collects: "log:<file>[:<count>]" (the `log:` prefix arm)
// and "monitor-security-flow" (an equality test inside the default
// branch, invisible to a scrape keyed on dispatch position). They are the
// ONE hand-named part of this census; the behavioural test below drives
// both through showText so a rename in the handler reds by execution.
var defaultBranchShowTextTopics = []string{"log:", "monitor-security-flow"}

func scrapedShowTextCensus(t *testing.T) (exact, prefix map[string]bool) {
	t.Helper()
	astTopics := showTextTopicsFromDispatcher(t)

	// Second, differently-filtered scrape (#6532's regexp extraction over
	// every production file). It must agree with the AST scrape on every
	// topic except the two default-branch names the AST shapes cannot see.
	reTopics := map[string]bool{}
	for _, topic := range dispatcherTopics(t) {
		reTopics[topic] = true
	}
	astSet := map[string]bool{}
	for _, topic := range astTopics {
		astSet[topic] = true
	}
	for topic := range reTopics {
		if !astSet[topic] {
			t.Errorf("regexp scrape sees ShowText topic %q but the AST scrape does not; "+
				"the two independent scrapes disagree, so neither can certify the registry (#16136)", topic)
		}
	}
	for topic := range astSet {
		if !reTopics[topic] {
			t.Errorf("AST scrape sees ShowText topic %q but the regexp scrape does not; "+
				"the two independent scrapes disagree (#16136)", topic)
		}
	}

	exact = map[string]bool{}
	prefix = map[string]bool{}
	classify := func(topic string) {
		if strings.HasSuffix(topic, ":") {
			prefix[topic] = true
		} else {
			exact[topic] = true
		}
	}
	for _, topic := range astTopics {
		classify(topic)
	}
	for _, topic := range defaultBranchShowTextTopics {
		classify(topic)
	}
	if len(exact)+len(prefix) < 100 {
		t.Fatalf("scraped only %d ShowText topics; the census source moved and a pass would certify nothing (#16136)",
			len(exact)+len(prefix))
	}
	return exact, prefix
}

func registryKeys(entries []optopic.Entry) (exact, prefix map[string]bool) {
	exact = map[string]bool{}
	prefix = map[string]bool{}
	for _, e := range entries {
		if e.IsPrefix() {
			prefix[e.Key] = true
		} else {
			exact[e.Key] = true
		}
	}
	return exact, prefix
}

func diffKeys(t *testing.T, what string, scraped, registered map[string]bool) {
	t.Helper()
	for k := range scraped {
		if !registered[k] {
			t.Errorf("%s %q is dispatched by the handler but has no optopic registry entry: "+
				"it would be priced strict / denied to restricted classes. Register it in pkg/optopic (#16136)", what, k)
		}
	}
	for k := range registered {
		if !scraped[k] {
			t.Errorf("%s %q is registered in pkg/optopic but the handler does not dispatch it: "+
				"a stale entry hides an unregistered real topic/verb (#16136)", what, k)
		}
	}
}

func TestRegistryShowTextCensusEquivalence16136(t *testing.T) {
	scrapedExact, scrapedPrefix := scrapedShowTextCensus(t)
	regExact, regPrefix := registryKeys(optopic.ShowTextEntries())
	diffKeys(t, "ShowText exact topic", scrapedExact, regExact)
	diffKeys(t, "ShowText prefix topic", scrapedPrefix, regPrefix)
}

func TestRegistryShowTextEveryScrapedTopicPricedAndCommanded16136(t *testing.T) {
	scrapedExact, scrapedPrefix := scrapedShowTextCensus(t)
	// The frozen fixture and the live scrape must cover exactly the same
	// keys: a handler topic with no frozen row has no independent
	// expectation (registering it in pkg/optopic alone must NOT make this
	// pass — its frozen row is added by hand, with the emitting command
	// as justification), and a frozen row the handler no longer serves is
	// a stale contract.
	scraped := map[string]bool{}
	for k := range scrapedExact {
		scraped[k] = true
	}
	for k := range scrapedPrefix {
		scraped[k] = true
	}
	if len(scraped) != len(frozenShowText16136) {
		t.Errorf("scraped %d ShowText topics but the frozen contract holds %d; a topic was added or removed without updating the frozen expectation (#16136)",
			len(scraped), len(frozenShowText16136))
	}
	for k := range scraped {
		if _, ok := frozenShowText16136[k]; !ok {
			t.Errorf("ShowText topic %q is dispatched but has no frozen pre-registry expectation; add its row to authz_registry_frozen_16136_test.go by hand (#16136)", k)
		}
	}
	for k := range frozenShowText16136 {
		if !scraped[k] {
			t.Errorf("frozen contract prices/commands ShowText topic %q, which the handler no longer dispatches (#16136)", k)
		}
	}
	// Attribution: production price and production command for every key
	// must equal the FROZEN row. The registry row is consulted only for
	// existence (a scraped key the registry dropped), never as the
	// expected value — an incorrect-but-valid command association (the
	// discriminator in the #16136 review: applications: -> `show version`)
	// moves registry, price view, and command view together and must
	// still red here.
	probe := func(key, probeTopic string) {
		want, ok := frozenShowText16136[key]
		if !ok {
			return // reported above
		}
		if _, registered := optopic.LookupShowText(probeTopic); !registered {
			t.Errorf("ShowText topic %q: registry lookup misses, so it prices at the strict default (#16136)", probeTopic)
		}
		if perm, priced := showTextTopicPermission(probeTopic); !priced || perm != want.permission {
			t.Errorf("ShowText topic %q: production price=(%s,%v) but the frozen pre-registry contract says %s (#16136)",
				probeTopic, permName(perm), priced, permName(want.permission))
		}
		if cmd, resolved := showTextTopicCanonicalCommand(probeTopic); !resolved || cmd != want.command {
			t.Errorf("ShowText topic %q: production command=(%q,%v) but the frozen pre-registry contract says %q — wrong command attribution would charge deny-commands against the wrong path (#16136)",
				probeTopic, cmd, resolved, want.command)
		}
	}
	for topic := range scrapedExact {
		probe(topic, topic)
	}
	for topic := range scrapedPrefix {
		probe(topic, topic+"probe-value")
	}
	// Elevated (non-view) topics are exactly the non-`show` emitters in
	// the frozen contract, at the frozen prices (the converse direction
	// the key-set check cannot express: nothing may sit at view that the
	// contract elevates, which the probe above already asserts per key).
	for key, want := range frozenShowText16136 {
		if want.permission != config.PermView {
			switch key {
			case "policies-check", "test-policy:", "test-routing:", "test-zone:":
			default:
				t.Errorf("frozen contract prices ShowText topic %q at %s; only the test-*/policies-check family may sit above view (#16136)",
					key, permName(want.permission))
			}
		}
	}
}

func scrapedSystemActionCensus(t *testing.T) (verbs map[string]bool, prefixArms map[string]string) {
	t.Helper()
	verbs = map[string]bool{}
	for _, v := range systemActionVerbsFromHandler(t) {
		verbs[v] = true
	}
	if len(verbs) < 20 {
		t.Fatalf("scraped only %d SystemAction verbs; the census source moved (#16136)", len(verbs))
	}
	// Prefix arms: every HasPrefix(req.Action, "x") literal in the handler
	// file, scraped by regexp over the source text — a different filter
	// from the AST case-label walk above.
	src := readHandlerSource(t, "server_diag_system_action.go")
	prefixArms = map[string]string{}
	for _, m := range regexp.MustCompile(`HasPrefix\(req\.Action, "([^"]+)"\)`).FindAllStringSubmatch(src, -1) {
		prefixArms[m[1]] = m[1]
	}
	if len(prefixArms) < 5 {
		t.Fatalf("scraped only %d SystemAction prefix arms; the handler shape moved (#16136)", len(prefixArms))
	}
	return verbs, prefixArms
}

func readHandlerSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func showTextReq(topic string) any { return &pb.ShowTextRequest{Topic: topic} }
func sysActionReq(action string) any {
	return &pb.SystemActionRequest{Action: action}
}

func TestRegistrySystemActionCensusEquivalence16136(t *testing.T) {
	verbs, _ := scrapedSystemActionCensus(t)
	regExact, regPrefix := registryKeys(optopic.SystemActionEntries())
	// Exact verbs: handler switch ≡ registry exact keys, both directions.
	diffKeys(t, "SystemAction exact verb", verbs, regExact)
	// The registry must carry no SystemAction prefix ENTRY keys other than
	// the priced families (which live in SystemActionPrefixPermissions,
	// not Entries) — exact-verb equivalence above is the whole Entries set.
	if len(regPrefix) != 0 {
		t.Errorf("optopic SystemActionEntries carries prefix keys %v; prefix families belong in SystemActionPrefixPermissions (#16136)", keysOf(regPrefix))
	}
	// Attribution: production price and production command for every verb
	// must equal the FROZEN pre-registry row, never the registry entry the
	// production views are derived from. An incorrect exact-verb price
	// (e.g. clear-arp repriced in pkg/optopic alone) moves registry, price
	// view, and command view together and must still red here; the
	// handler key census above stays unchanged while it does.
	for verb := range verbs {
		want, ok := frozenSystemAction16136[verb]
		if !ok {
			t.Errorf("SystemAction verb %q is served but has no frozen pre-registry expectation; add its row to authz_registry_frozen_16136_test.go by hand (#16136)", verb)
			continue
		}
		if _, registered := optopic.LookupSystemAction(verb); !registered {
			t.Errorf("SystemAction verb %q: registry lookup misses (#16136)", verb)
		}
		if got := systemActionVerbCommand[verb]; got != want.command {
			t.Errorf("SystemAction verb %q: production command=%q but the frozen pre-registry contract says %q (#16136)", verb, got, want.command)
		}
		if perm := systemActionPermission(verb); perm != want.permission {
			t.Errorf("SystemAction verb %q: production price=%s but the frozen pre-registry contract says %s (#16136)",
				verb, permName(perm), permName(want.permission))
		}
	}
	for verb := range frozenSystemAction16136 {
		if !verbs[verb] {
			t.Errorf("frozen contract prices/commands SystemAction verb %q, which the handler no longer serves (#16136)", verb)
		}
	}
}

func TestRegistrySystemActionPrefixFamilies16136(t *testing.T) {
	_, prefixArms := scrapedSystemActionCensus(t)
	registered := map[string]config.LoginClassPermission{}
	for _, e := range optopic.SystemActionPrefixPermissions() {
		registered[e.Key] = e.Permission
	}
	// Every prefix the handler branches on is priced: the attestation arm
	// at PermAll, the rest at the PermMaint family price.
	for arm := range prefixArms {
		if arm == optopic.AttestArmPrefix {
			if got := systemActionPermission(arm + "run:1:aa"); got != config.PermAll {
				t.Errorf("attestation arm priced %s, want PermAll (#16136)", permName(got))
			}
			continue
		}
		if _, ok := registered[arm]; !ok {
			t.Errorf("SystemAction prefix arm %q is served by the handler but is not a registered prefix family in pkg/optopic (#16136)", arm)
		}
		if got := systemActionPermission(arm + "probe"); got != config.PermMaint {
			t.Errorf("SystemAction prefix arm %q priced %s, want PermMaint (#16136)", arm, permName(got))
		}
	}
	// Every registered family is served (no stale family).
	for fam := range registered {
		if _, ok := prefixArms[fam]; !ok {
			// The failover family is admitted through clusterfailover, not a
			// HasPrefix literal in the handler; it is served if the grammar
			// package claims the prefix (checked just below).
			if strings.HasPrefix(fam, "cluster-failover") && clusterfailover.IsFailoverAction(fam+"1") {
				continue
			}
			t.Errorf("registered SystemAction prefix family %q is not served by the handler (#16136)", fam)
		}
	}
	// The failover grammar family, enumerated separately: its three
	// prefixes are registered, priced PermMaint, and fabric-admitted ONLY
	// in their parsed node-targeted forms.
	for _, fam := range []string{"cluster-failover:", "cluster-failover-data:", "cluster-failover-reset:"} {
		if _, ok := registered[fam]; !ok {
			t.Errorf("cluster-failover family %q is not registered in pkg/optopic (#16136)", fam)
		}
	}
	for _, action := range []string{"cluster-failover:1", "cluster-failover:1:node0", "cluster-failover-data:node1", "cluster-failover-reset:1"} {
		if got := systemActionPermission(action); got != config.PermMaint {
			t.Errorf("systemActionPermission(%q)=%s, want PermMaint (#16136)", action, permName(got))
		}
		if !clusterfailover.IsFailoverAction(action) {
			t.Errorf("clusterfailover.IsFailoverAction(%q)=false; the census grammar anchor moved (#16136)", action)
		}
	}
}

func TestRegistryFabricAdmissionCensus16136(t *testing.T) {
	// Topics: exactly the one peer-proxied topic, per the registry AND per
	// the derived grpcapi view the fabric gate actually reads.
	var regTopics []string
	for _, e := range optopic.ShowTextEntries() {
		if e.FabricAllowed {
			regTopics = append(regTopics, e.Key)
		}
	}
	if len(regTopics) != 1 || regTopics[0] != "chassis-forwarding" {
		t.Fatalf("registry fabric topics = %v, want [chassis-forwarding] (#16136)", regTopics)
	}
	if len(fabricAllowedShowTextTopics) != 1 || !fabricAllowedShowTextTopics["chassis-forwarding"] {
		t.Fatalf("fabricAllowedShowTextTopics = %v, want exactly {chassis-forwarding} (#16136)", fabricAllowedShowTextTopics)
	}
	// Verbs: exactly the one exact peer-coordinated verb.
	var regVerbs []string
	for _, e := range optopic.SystemActionEntries() {
		if e.FabricAllowed {
			regVerbs = append(regVerbs, e.Key)
		}
	}
	if len(regVerbs) != 1 || regVerbs[0] != "clear-persistent-nat" {
		t.Fatalf("registry fabric verbs = %v, want [clear-persistent-nat] (#16136)", regVerbs)
	}
	// Behavioural: the fabric gates themselves admit exactly those plus
	// the parsed node-targeted failover forms, and nothing else sampled.
	if !isFabricSafeShowText(showTextReq("chassis-forwarding")) || isFabricSafeShowText(showTextReq("route-all")) {
		t.Error("fabric ShowText gate drifted from the registry census (#16136)")
	}
	if !isFabricSafeSystemAction(sysActionReq("clear-persistent-nat")) ||
		!isFabricSafeSystemAction(sysActionReq("cluster-failover:1:node1")) ||
		!isFabricSafeSystemAction(sysActionReq("cluster-failover-data:node1")) ||
		isFabricSafeSystemAction(sysActionReq("zeroize")) ||
		isFabricSafeSystemAction(sysActionReq("cluster-failover-reset:1")) ||
		isFabricSafeSystemAction(sysActionReq("cluster-failover:1")) {
		t.Error("fabric SystemAction gate drifted: want clear-persistent-nat + targeted failover only (#16136)")
	}
}

func TestRegistryUnknownStaysStrict16136(t *testing.T) {
	// Anonymous-equivalent / unclassified admission: unknown content is
	// priced at the strictest tier, resolves to no command, and is never
	// fabric-admitted. Fail-open in any of the three reds here.
	if perm, ok := showTextTopicPermission("zzbogus-topic-16136"); ok || perm != unmappedMethodPermission {
		t.Errorf("unknown topic priced (%s,%v), want (PermAll,false) (#16136)", permName(perm), ok)
	}
	if _, ok := optopic.LookupShowText("zzbogus-topic-16136"); ok {
		t.Error("unknown topic registered (#16136)")
	}
	if cmd, resolved := showTextTopicCanonicalCommand("zzbogus-topic-16136"); resolved || cmd != "" {
		t.Errorf("unknown topic resolved to command %q (#16136)", cmd)
	}
	if isFabricSafeShowText(showTextReq("zzbogus-topic-16136")) {
		t.Error("unknown topic fabric-admitted (#16136)")
	}
	if got := systemActionPermission("zzbogus-verb-16136"); got != config.PermMaint {
		t.Errorf("unknown verb priced %s, want PermMaint (#16136)", permName(got))
	}
	if _, mapped := systemActionVerbCommand["zzbogus-verb-16136"]; mapped {
		t.Error("unknown verb has a canonical command (#16136)")
	}
	if isFabricSafeSystemAction(sysActionReq("zzbogus-verb-16136")) {
		t.Error("unknown verb fabric-admitted (#16136)")
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestRegistryCensusBehavioural16136 drives the two default-branch topics
// and a sample of every dispatch shape through the REAL showText handler,
// so the census's hand-named arm is verified by execution. It also pins
// that an unknown topic still earns InvalidArgument from the dispatcher
// itself (the registry flip must not invent a success path).
//
// Byte-identical operator output: the handler bodies are untouched by the
// flip (dispatch stays the ordered prefix arms + switch in server_show.go),
// so a topic that rendered before renders the same bytes — this test
// asserts reachability (not InvalidArgument), which is exactly the
// property a registry/dispatch divergence would break.
func TestRegistryCensusBehavioural16136(t *testing.T) {
	s := &Server{store: newConfigStore(t, t.TempDir()+"/xpf.conf")}
	ctx := context.Background()
	served := func(topic string) {
		t.Helper()
		_, err := s.ShowText(ctx, &pb.ShowTextRequest{Topic: topic})
		if err != nil && strings.Contains(err.Error(), "unknown topic") {
			t.Errorf("topic %q: dispatcher reports unknown topic, but the census registers it (#16136)", topic)
		}
	}
	// Default-branch topics (the hand-named arm).
	served("monitor-security-flow")
	served("log:messages")
	// One representative per dispatch shape.
	for _, topic := range []string{
		"route-table:inet.0",      // leading prefix arm
		"class-of-service",        // equality-or-prefix arm
		"applications:junos-ssh",  // applications: prefix arm (#15207)
		"test-policy:from=a,to=b", // test- prefix arm
		"version",                 // main switch
		"chassis-cluster-status",  // multi-label switch case
		"sessions-top:bytes",      // colon-bearing exact switch case
	} {
		served(topic)
	}
	// Unknown topic: dispatcher itself refuses.
	if _, err := s.ShowText(ctx, &pb.ShowTextRequest{Topic: "zzbogus-topic-16136"}); err == nil ||
		!strings.Contains(err.Error(), "unknown topic") {
		t.Errorf("unknown topic: ShowText err=%v, want an 'unknown topic' refusal (#16136)", err)
	}
	// Every registered exact topic must at least not be "unknown" to the
	// dispatcher. Errors from nil subsystems are fine; the refusal string
	// is the divergence signal.
	for _, e := range optopic.ShowTextEntries() {
		topic := e.Key
		if e.IsPrefix() {
			topic += "probe"
		}
		_, err := s.ShowText(ctx, &pb.ShowTextRequest{Topic: topic})
		if err != nil && strings.Contains(err.Error(), "unknown topic") {
			t.Errorf("registered topic %q (probe %q): dispatcher reports unknown topic (#16136)", e.Key, topic)
		}
	}
}
