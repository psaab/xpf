package grpcapi

import (
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
)

// #7172 cut 5a-2 — the ShowText-topic and SystemAction-verb command tables.
//
// These mirror the cut-5a method-table guards deliberately: the same validity
// rule (an entry must be a real, already-canonical, argument-free command) and
// the same completeness rule (the key set is pinned to PRODUCTION SOURCE in
// both directions, so a new topic or verb reds the suite rather than silently
// going unmapped).
//
// What they do NOT prove is attribution. `chassis-cluster-status` mapped to
// `show system uptime` passes every check in this file, because no independent
// signal for "which command reaches this topic" exists server-side: deriving
// the command from the topic name reproduces only a minority of the table
// (TestTopicNameDerivationDoesNotReproduceTheTable7172 measures it), and the
// handler name is camelCase(topic), which restates the topic and therefore
// agrees with it by construction. Attribution is a review responsibility and
// authz_command_table_topics.go says so in those words.

// assertCanonicalCommands is the shared validity rule, identical to the one
// TestEveryMappedCommandIsCanonical7172 applies to the method table.
//
// The three arms run in order and only the first failure reports. Since
// #12527 only the first and the last can fire. cmdtree.EveryWordIsAKeyword
// rejects any entry whose words are not one command path through the tree:
// garbage in a VALUE slot (`show interfaces zzbogus` canonicalizes fine —
// value slots absorb operator data by design, #8094), literal placeholder
// words, any word after a LEAF (`show version zzbogus`, and `show security
// flow session summary zone`, which Canonicalize accepts by re-entering the
// Options map, #9505), and an abbreviation (`show ver`), because its lookups
// are EXACT.

// The Canonicalize arm cannot fail on an entry the keyword arm passed. That
// walk took one exact child-map hit per word with a leaf only at the end, and
// resolveTreeWord takes its exact-hit branch for each of those words, so
// Canonicalize walks the same nodes to CanonicalOK and returns the words
// unchanged. Before #12527 the keyword walk stopped at the first leaf without
// reading on, so Canonicalize was what refused `show version zzbogus`, and
// canon != cmd caught an abbreviated option after a leaf (`monitor traffic
// matching match`). The Canonicalize arm is kept rather than deleted because
// it comes back to life if cmdtree.EveryWordIsAKeyword is loosened — exactly
// the direction a future change would loosen it — and it is documented as
// unable to fire so nobody reads a green suite as evidence that it was
// exercised.
//
// canon != cmd is now reached only by WHITESPACE. strings.Fields collapses
// and trims it, so `show  version` or ` show version` passes both arms above
// and canonicalizes to the single-spaced string. That failure is not
// cosmetic: authorizeRPCCommand matches deny regexes against the entry
// exactly as written, so `show  version` would escape a `^show version$`
// deny that the on-box CLI's canonical spelling meets.
//
// #14687: Canonicalize now refuses a line ending mid-value, which the bare
// argument-free path of a PREFIX-form topic (`route-table:` ->
// `show route table`) and the flows topic (whose <limit> is optional,
// carried in the topic value, not the command path) legitimately are. Those
// entries are exempt from the Canonicalize arm only: the keyword arm above
// still proves every word is a real node, and the dispatcher only reaches
// them with a value packed in the topic. Bare (non-prefix) entries whose
// path ends mid-value remain refused — they would name a command no
// operator can run bare.
func assertCanonicalCommands(t *testing.T, what string, table map[string]string) {
	t.Helper()
	if len(table) == 0 {
		t.Fatalf("the %s table is empty, so this test would certify nothing", what)
	}
	keys := make([]string, 0, len(table))
	for k := range table {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		cmd := table[key]
		words := strings.Fields(cmd)
		if len(words) == 0 {
			t.Errorf("%s %q maps to an empty command", what, key)
			continue
		}
		if !cmdtree.EveryWordIsAKeyword(cmdtree.OperationalTree, words) {
			t.Errorf("%s %q maps to %q, which is not an argument-free command path: "+
				"either some word is not a command KEYWORD — a value slot (a dynamic, "+
				"typed or placeholder child) is absorbing it — or a word follows a "+
				"LEAF, which fails even when both words are keywords (an option after "+
				"a complete command, #12527). Every word must be a real node, and only "+
				"the last may be a leaf.", what, key, cmd)
			continue
		}
		// #14687: prefix-form topics, the flows path, and `route-instance`
		// (whose instance name rides in req.Filter, not the topic) pack
		// their value outside the command path, so the argument-free path
		// ends mid-value by design.
		if strings.HasSuffix(key, ":") || cmd == "show chassis cluster data-plane flows" || cmd == "show route instance" {
			continue
		}
		canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, words)
		if res != cmdtree.CanonicalOK {
			t.Errorf("%s %q maps to %q, which does not resolve against the operational "+
				"tree (%v). A deny regex is matched against this string, so an "+
				"unresolvable entry means the gate compares against a command no "+
				"operator can run.", what, key, cmd, res)
			continue
		}
		if got := strings.Join(canon, " "); got != cmd {
			t.Errorf("%s %q maps to %q, which canonicalizes to %q. The table must hold "+
				"the CANONICAL spelling.", what, key, cmd, got)
		}
	}
}

func TestEveryTopicCommandIsCanonical7172(t *testing.T) {
	assertCanonicalCommands(t, "ShowText topic", showTextTopicCommand)
}

func TestEverySystemActionVerbCommandIsCanonical7172(t *testing.T) {
	assertCanonicalCommands(t, "SystemAction verb", systemActionVerbCommand)
}

// COMPLETENESS for topics, both directions, against the dispatcher's own
// literals.
//
// showTextTopicsFromDispatcher is the same extraction
// TestEveryShowTextTopicHasAPermission_5278 uses — it collects all three
// dispatch shapes in server_show.go (`switch req.Topic` case labels,
// `req.Topic == "x"`, and `strings.HasPrefix(req.Topic, "x")`) and t.Fatals if
// the enumeration source has moved. Sharing it is the point: a topic that is
// PRICED but has no command would leave 5b unable to evaluate deny-commands for
// a request it just charged a permission for.
//
// RED on revert: delete an entry from showTextTopicCommand (the "unmapped"
// arm), or add one naming a topic the dispatcher does not serve (the "stale"
// arm).
func TestEveryShowTextTopicHasACanonicalCommand7172(t *testing.T) {
	topics := showTextTopicsFromDispatcher(t)
	if len(topics) < 50 {
		t.Fatalf("only %d ShowText topics parsed out of the dispatcher; the extraction "+
			"is broken and a pass would certify nothing", len(topics))
	}
	inDispatcher := make(map[string]bool, len(topics))
	for _, topic := range topics {
		inDispatcher[topic] = true
		if _, ok := showTextTopicCommand[topic]; !ok {
			t.Errorf("ShowText topic %q is dispatched but has no canonical command. 5b "+
				"cannot evaluate deny-commands for it, so a class that configured "+
				"regexes would be DENIED the topic outright. Add it to "+
				"showTextTopicCommand in authz_command_table_topics.go, reading "+
				"cmd/cli for the command that emits it. If NO operational command "+
				"emits it, this table needs the named-absence mechanism "+
				"methodsWithoutCanonicalCommand uses — do not invent a mapping.", topic)
		}
	}
	for topic := range showTextTopicCommand {
		if !inDispatcher[topic] {
			t.Errorf("showTextTopicCommand maps %q, which the ShowText dispatcher does "+
				"not serve — a stale entry hides the fact that some real topic is "+
				"unmapped", topic)
		}
	}
}

// COMPLETENESS for verbs, both directions, against the handler's own switch.
//
// RED on revert: drop an entry from systemActionVerbCommand, or add a
// `case "something-new":` to server_diag_system_action.go without mapping it.
func TestEverySystemActionVerbHasACanonicalCommand7172(t *testing.T) {
	verbs := systemActionVerbsFromHandler(t)
	if len(verbs) == 0 {
		t.Fatal("no SystemAction verbs parsed out of the handler")
	}
	inHandler := make(map[string]bool, len(verbs))
	for _, v := range verbs {
		inHandler[v] = true
		if _, ok := systemActionVerbCommand[v]; !ok {
			t.Errorf("SystemAction verb %q is served but has no canonical command; 5b "+
				"cannot evaluate deny-commands for it. Map it in "+
				"systemActionVerbCommand, reading cmd/cli for the command that sends "+
				"it — the verb spelling is NOT the command (`clear-firewall-counters` "+
				"is sent by `clear firewall all`).", v)
		}
	}
	for v := range systemActionVerbCommand {
		if !inHandler[v] {
			t.Errorf("systemActionVerbCommand maps %q, which the SystemAction handler "+
				"does not serve — a stale entry hides an unmapped real verb", v)
		}
	}
}

// The file rejects deriving a topic's command from its NAME, and this measures
// the claim rather than leaving it as prose a later reader has to trust.
//
// The naive derivation is `show ` + the topic with dashes as spaces. It works
// for the topics that happen to sit directly under `show`, and fails for every
// topic that drops intermediate hierarchy (`alarms` is `show system alarms`,
// `address-book` is `show security address-book`, `tunnels` is
// `show interfaces tunnel`).
//
// If this ever goes GREEN in the majority direction, the comment in
// authz_command_table_topics.go is wrong and the rejected design deserves a
// second look — which is the whole point of pinning it. Parameter-packed keys
// are excluded because a trailing ':' cannot be part of any command.
func TestTopicNameDerivationDoesNotReproduceTheTable7172(t *testing.T) {
	var derivable, total int
	for topic, cmd := range showTextTopicCommand {
		if strings.HasSuffix(topic, ":") {
			continue
		}
		total++
		if "show "+strings.ReplaceAll(topic, "-", " ") == cmd {
			derivable++
		}
	}
	if total == 0 {
		t.Fatal("no exact-keyed topics to measure; a pass would certify nothing")
	}
	if derivable*2 >= total {
		t.Errorf("deriving the command from the topic name reproduces %d of %d exact "+
			"topics (%d%%), a MAJORITY. authz_command_table_topics.go rejects that "+
			"design on the grounds that the exemption list would be the larger half; "+
			"if that is no longer true the comment is stale and the design decision "+
			"should be revisited rather than the threshold moved.",
			derivable, total, derivable*100/total)
	}
	t.Logf("topic-name derivation reproduces %d of %d exact topics (%d%%)",
		derivable, total, derivable*100/total)
}
