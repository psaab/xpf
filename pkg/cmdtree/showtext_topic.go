package cmdtree

// #8058: the ShowText topic <-> operational command correspondence, owned here
// so it exists ONCE.
//
// ── IF YOU ARE ABOUT TO WRITE THIS DOWN SOMEWHERE ELSE, DON'T ───────────
//
// This fact used to live twice, on opposite sides of a trust boundary: the
// remote `cli` binary turned a command into a topic (client-side, nested
// switches over args[N]), and pkg/grpcapi turned a topic back into a command
// for deny-commands matching (server-side). Nothing made them agree. A topic
// re-attributed to a different command on one side left the other pricing an
// authorization decision against a command string no operator could type.
//
// It lives in cmdtree for the same reason cos_filter_topic.go does: the package
// is already the SSOT for "the same command means the same thing on the local
// CLI, the remote CLI, and gRPC", and BOTH surfaces already import it. Both now
// read this table, so a divergence is not a bug to be caught by a mirrored test
// table — it is unrepresentable.
//
// An agreement test was the obvious alternative and it cannot be made sound.
// Recovering the command that reaches each topic needs an AST walk of the
// client's nested switches, and 18 of these topics are COMPUTED at their call
// sites rather than written as literals, so a literal scan certifies the
// majority and reports clean on the rest with nothing in its output
// distinguishing the two. Measured at the time of the move: a literal scan of
// cmd/cli sees 104 of the 123 base topics. That is existence standing in for
// coverage.
//
// ── WHY BOTH SIDES IMPORTING THIS IS NOT A TRUST VIOLATION ──────────────
//
// The server must never import the CLIENT's table — an authorization decision
// cannot derive from client-side data. Both sides importing a leaf is not that.
// This is a compile-time constant in the daemon binary that no client can
// influence at runtime, and the server already derives authz input from this
// package: #8057 canonicalizes every entry against Canonicalize. If importing
// cmdtree were a trust violation, that would already be one.
//
// ── WHAT MAKES AN ENTRY CORRECT ─────────────────────────────────────────
//
// Every value must be a command that Canonicalize resolves TO ITSELF — a real,
// already-canonical operational command. pkg/grpcapi machine-checks that
// (#8057, which caught 12 hand-authored errors) and pins this key set against
// its own ShowText dispatcher in both directions. Those checks stay where they
// are: they are properties of the SERVER's dispatcher, and this file is the
// data they check.
//
// A key ending in ':' is the PREFIX form of a parameter-packed topic, spelled
// exactly as the dispatcher spells it. Prefix keys are deliberately EXCLUDED
// from the command -> topic direction: a command like `show class-of-service
// classifier` keys both the bare topic and its prefix form, so the reverse
// lookup would be ambiguous. Those 18 topics are built by explicit encoders at
// their call sites (see CoSNameTypeTopic in cos_filter_topic.go for the shape).
// Among the bare keys the reverse map is one-to-one, and
// TestShowTextTopicReverseMapIsUnambiguous_8058 keeps it that way.

import (
	"strings"
	"sync"

	"github.com/psaab/xpf/pkg/optopic"
)

// showTextTopicCommand is DERIVED from the optopic registry (#16136):
// the topic -> command column of pkg/optopic's ShowText entries. It was a
// hand-maintained literal here until #16136; the registry is now the one
// place a topic, its price, its command, and its fabric admission are
// written down. This map (and the reverse lookup below) is built from it
// so the client and server surfaces keep reading one fact.
var showTextTopicCommand = func() map[string]string {
	entries := optopic.ShowTextEntries()
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		out[e.Key] = e.Command
	}
	return out
}()

// ShowTextTopicCommands returns the topic -> canonical command table.
//
// The returned map is a COPY: callers hold it for the life of the process
// (pkg/grpcapi assigns it once at package init) and must not be able to mutate
// the SSOT out from under the other surface.
func ShowTextTopicCommands() map[string]string {
	out := make(map[string]string, len(showTextTopicCommand))
	for topic, command := range showTextTopicCommand {
		out[topic] = command
	}
	return out
}

// CommandForShowTextTopic returns the canonical operational command that emits
// a ShowText topic. This is the direction pkg/grpcapi needs: it holds a decoded
// topic and must price it against deny-commands.
func CommandForShowTextTopic(topic string) (string, bool) {
	command, ok := showTextTopicCommand[topic]
	return command, ok
}

var showTextCommandTopic = sync.OnceValue(func() map[string]string {
	// Bare keys only — see the prefix-form note in this file's header. A
	// prefix key shares its command with the bare form, so including them
	// would make this lookup depend on map iteration order.
	out := make(map[string]string, len(showTextTopicCommand))
	for topic, command := range showTextTopicCommand {
		if strings.HasSuffix(topic, ":") {
			continue
		}
		out[command] = topic
	}
	return out
})

// ShowTextTopicForCommand returns the ShowText topic that a canonical
// operational command emits. This is the direction the remote `cli` binary
// needs: it knows the command the operator typed and must name a topic to send.
//
// Naming the COMMAND at the call site rather than the topic is what removes the
// second transcription. The command is self-evident where it is written — it is
// the switch arm the reader is already looking at — while a topic string is an
// encoding detail that has to be looked up somewhere to be checked.
//
// Reports ok=false for a command with no topic, which callers must treat as a
// programming error rather than falling back to a guessed topic: a guess is how
// the client would start disagreeing with the server again.
func ShowTextTopicForCommand(command string) (string, bool) {
	topic, ok := showTextCommandTopic()[command]
	return topic, ok
}
