package eventengine

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// Tests for #2008 M7 — attributes-match is a regex match (Junos `matches`
// semantics), with the compiled regex cached at Apply() time so the event
// hot path never recompiles.

func newTestEngine(t *testing.T, policies []*config.EventPolicy) *Engine {
	t.Helper()
	e := New(nil, nil) // nil store/commitFn: matcher tests never commit
	applyPolicies9984(e, policies)
	return e
}
// Existing matcher/remediation fixtures predate persisted planting classes.
// Keep their trusted setup explicit without weakening production Apply, which
// remains fail-closed for payloads with no recorded class.
func applyPolicies9984(e *Engine, policies []*config.EventPolicy) {
	e.apply(policies, nil, false)
}

func policyWithMatch(name, event, match string) *config.EventPolicy {
	return &config.EventPolicy{
		Name:            name,
		Events:          []string{event},
		AttributesMatch: []string{match},
	}
}

// A pattern that is an anchored exact match behaves like the old literal
// equality for the matching value, and rejects a non-matching value.
func TestAttributesMatch_AnchoredExact(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed",
		"ping_test_failed.test-owner matches ^Comcast$")
	e := newTestEngine(t, []*config.EventPolicy{pol})

	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "Comcast"}) {
		t.Error("anchored ^Comcast$ should match TestOwner=Comcast")
	}
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "ComcastBusiness"}) {
		t.Error("anchored ^Comcast$ should NOT match TestOwner=ComcastBusiness")
	}
}

// The behavior change vs the old literal equality: an UNANCHORED pattern is
// a regex substring match (Junos semantics). `Com` matches `Comcast` — the
// old code required exact equality and would have returned false.
func TestAttributesMatch_UnanchoredSubstring(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed",
		"ping_test_failed.test-owner matches Com")
	e := newTestEngine(t, []*config.EventPolicy{pol})

	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "Comcast"}) {
		t.Error("unanchored Com should substring-match Comcast (regex behavior)")
	}
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "ATT"}) {
		t.Error("unanchored Com should NOT match ATT")
	}
}

// A metacharacter pattern is honored as a regex, not as a literal string.
// `.*down` matches `link-down` (the `.` and `*` are regex operators); the
// old literal code would only have matched the exact string ".*down".
func TestAttributesMatch_MetacharactersBehaveAsRegex(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed",
		"ping_test_failed.test-name matches .*down")
	e := newTestEngine(t, []*config.EventPolicy{pol})

	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestName: "link-down"}) {
		t.Error(".*down should regex-match link-down")
	}
	// The literal string ".*down" is NOT what TestName equals here, proving
	// the match is regex, not literal equality on the pattern text.
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestName: "up"}) {
		t.Error(".*down should NOT match up")
	}
}

// test-name field is supported in addition to test-owner.
func TestAttributesMatch_TestNameField(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed",
		"ping_test_failed.test-name matches ^wan-probe$")
	e := newTestEngine(t, []*config.EventPolicy{pol})
	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestName: "wan-probe"}) {
		t.Error("test-name field should match")
	}
}

// #2141 FAIL-CLOSED: an unknown field (which can only reach the runtime on a
// legacy lenient-load path, since strict commit now rejects it) makes the
// policy NOT fire, rather than being silently dropped and broadening the
// policy. This is the behavior change vs the old default:continue fail-open.
func TestAttributesMatch_UnknownFieldFailsClosed(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed",
		"ping_test_failed.nonexistent matches whatever")
	e := newTestEngine(t, []*config.EventPolicy{pol})
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "x"}) {
		t.Error("unknown attribute field should fail closed (policy does not match)")
	}
	if got := e.Stats().AttributesInvalid; got == 0 {
		t.Error("AttributesInvalid counter should bump on an unknown field")
	}
}

// #2141 FAIL-CLOSED: a malformed line (no " matches ") that slipped through a
// lenient load also fails closed.
func TestAttributesMatch_MalformedLineFailsClosed(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed", "garbage with no separator")
	e := newTestEngine(t, []*config.EventPolicy{pol})
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "x"}) {
		t.Error("malformed attributes-match line should fail closed")
	}
}

// SSOT drift guard (#2141): the config-side known-field set and the runtime
// matcher's switch must stay identical. Every known field must resolve in the
// matcher (i.e. a policy matching ^anything against that field with the right
// event value must be able to return true), and an unknown field must fail.
func TestEventAttributesKnownFields_MatchesRuntimeSwitch(t *testing.T) {
	// The matcher resolves these fields; assert exactly this set is the known
	// fields. If a field is added to the SSOT, this test forces the matcher
	// switch to be updated in lockstep (#3756 H14 added the three static
	// per-test strings target / routing-instance / destination-interface).
	want := map[string]bool{
		"test-owner":            true,
		"test-name":             true,
		"target":                true,
		"routing-instance":      true,
		"destination-interface": true,
	}
	if len(config.EventAttributesKnownFields) != len(want) {
		t.Fatalf("known-field set %v has unexpected size; runtime switch resolves %v",
			config.EventAttributesKnownFields, want)
	}
	for f := range want {
		if !config.EventAttributesFieldKnown(f) {
			t.Errorf("field %q is resolved by the matcher but missing from the SSOT", f)
		}
	}
	for f := range config.EventAttributesKnownFields {
		if !want[f] {
			t.Errorf("field %q is in the SSOT but the runtime matcher switch does not resolve it", f)
		}
	}
}

// Cached-compile: Apply() must populate the regex cache for every valid
// pattern so the hot path reads a pre-compiled regex. This proves the
// matcher does NOT compile per event (it reads e.regexCache[pattern]).
func TestAttributesMatch_RegexCachedAtApply(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed",
		"ping_test_failed.test-owner matches ^Comcast$")
	e := newTestEngine(t, []*config.EventPolicy{pol})

	pattern := "^Comcast$"
	re, ok := e.regexCache[pattern]
	if !ok || re == nil {
		t.Fatalf("Apply() did not cache the compiled regex for %q; cache=%v",
			pattern, e.regexCache)
	}

	// The cached pointer must be stable across matches — the hot path reads
	// the same compiled object, never recompiling. Capture it, run several
	// matches, and confirm the cache entry is identical (same pointer).
	before := e.regexCache[pattern]
	for i := 0; i < 5; i++ {
		e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "Comcast"})
	}
	after := e.regexCache[pattern]
	if before != after {
		t.Error("regex cache entry changed across matches — hot path recompiled")
	}

	// Re-Apply rebuilds the cache (new map); the same pattern is present.
	applyPolicies9984(e, []*config.EventPolicy{pol})
	if _, ok := e.regexCache[pattern]; !ok {
		t.Error("Apply() rebuild dropped the cached pattern")
	}
}

// #3753: an attributes-match constraint carries an event-name prefix that
// SCOPES it to a single event of a multi-event policy. The constraint must
// apply ONLY when the current event is that event; a constraint written for
// event_a must NOT gate event_b (and vice-versa).
//
// RED-on-revert: before the fix the parser dropped the "event_a." prefix, so
// attributesMatch applied the test-owner=^owner$ constraint to EVERY event.
// event_b arriving with test-owner="other" would then be rejected (the
// event_a-scoped constraint wrongly gated it) — this test's event_b/other
// assertion goes RED.
func TestAttributesMatch_EventNamePrefixScopesConstraint(t *testing.T) {
	pol := &config.EventPolicy{
		Name:            "p",
		Events:          []string{"event_a", "event_b"},
		AttributesMatch: []string{"event_a.test-owner matches ^owner$"},
	}
	e := newTestEngine(t, []*config.EventPolicy{pol})

	// event_a IS scoped by the constraint.
	if !e.attributesMatch(pol, rpm.Event{Name: "event_a", TestOwner: "owner"}) {
		t.Error("event_a with matching owner must match (constraint applies to event_a)")
	}
	if e.attributesMatch(pol, rpm.Event{Name: "event_a", TestOwner: "other"}) {
		t.Error("event_a with non-matching owner must NOT match (constraint gates event_a)")
	}

	// event_b is NOT scoped by an event_a constraint: it must pass regardless
	// of the test-owner value. This is the discriminating assertion.
	if !e.attributesMatch(pol, rpm.Event{Name: "event_b", TestOwner: "other"}) {
		t.Error("event_b must NOT be gated by an event_a-scoped constraint (#3753)")
	}
	if !e.attributesMatch(pol, rpm.Event{Name: "event_b", TestOwner: "owner"}) {
		t.Error("event_b must match irrespective of an event_a-scoped constraint (#3753)")
	}
}

// #3753 vice-versa: with a constraint scoped to each of two events, each
// constraint gates ONLY its own event.
func TestAttributesMatch_PerEventScopingBothDirections(t *testing.T) {
	pol := &config.EventPolicy{
		Name:   "p",
		Events: []string{"event_a", "event_b"},
		AttributesMatch: []string{
			"event_a.test-owner matches ^a-owner$",
			"event_b.test-name matches ^b-name$",
		},
	}
	e := newTestEngine(t, []*config.EventPolicy{pol})

	// event_a is gated by the a-owner constraint only; the b-name constraint
	// (scoped to event_b) must be skipped for event_a.
	if !e.attributesMatch(pol, rpm.Event{Name: "event_a", TestOwner: "a-owner", TestName: "irrelevant"}) {
		t.Error("event_a must match on the a-owner constraint alone; the event_b constraint must not apply")
	}
	if e.attributesMatch(pol, rpm.Event{Name: "event_a", TestOwner: "wrong"}) {
		t.Error("event_a with wrong owner must be gated")
	}
	// event_b is gated by the b-name constraint only.
	if !e.attributesMatch(pol, rpm.Event{Name: "event_b", TestOwner: "irrelevant", TestName: "b-name"}) {
		t.Error("event_b must match on the b-name constraint alone; the event_a constraint must not apply")
	}
	if e.attributesMatch(pol, rpm.Event{Name: "event_b", TestName: "wrong"}) {
		t.Error("event_b with wrong name must be gated")
	}
}

// #3756 H14: the three new static per-test fields (target, routing-instance,
// destination-interface) resolve against the corresponding rpm.Event field and
// regex-match like test-owner/test-name.
//
// RED-on-revert: before H14 these fields are absent from the SSOT and the
// matcher switch, so a policy keyed on them fails CLOSED (unknown field →
// policy never matches) — the match assertions below go RED (attributesMatch
// returns false for a matching value).
func TestAttributesMatch_TargetField_3756(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed",
		"ping_test_failed.target matches ^192\\.0\\.2\\.1$")
	e := newTestEngine(t, []*config.EventPolicy{pol})
	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", Target: "192.0.2.1"}) {
		t.Error("target field should match the event Target")
	}
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", Target: "192.0.2.2"}) {
		t.Error("target field should NOT match a different Target")
	}
}

func TestAttributesMatch_RoutingInstanceField_3756(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed",
		"ping_test_failed.routing-instance matches ^ISP-B$")
	e := newTestEngine(t, []*config.EventPolicy{pol})
	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", RoutingInstance: "ISP-B"}) {
		t.Error("routing-instance field should match the event RoutingInstance")
	}
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", RoutingInstance: "ISP-A"}) {
		t.Error("routing-instance field should NOT match a different RoutingInstance")
	}
}

func TestAttributesMatch_DestinationInterfaceField_3756(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed",
		"ping_test_failed.destination-interface matches ^ge-0/0/1$")
	e := newTestEngine(t, []*config.EventPolicy{pol})
	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", DestinationInterface: "ge-0/0/1"}) {
		t.Error("destination-interface field should match the event DestinationInterface")
	}
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", DestinationInterface: "ge-0/0/2"}) {
		t.Error("destination-interface field should NOT match a different DestinationInterface")
	}
}

// The new fields honor the #3753 event-name scoping: a constraint keyed on one
// event of a multi-event policy must not gate a DIFFERENT event.
func TestAttributesMatch_NewFieldsEventScoped_3756(t *testing.T) {
	pol := &config.EventPolicy{
		Name:            "p",
		Events:          []string{"ping_test_failed", "ping_test_completed"},
		AttributesMatch: []string{"ping_test_failed.target matches ^10\\.0\\.0\\.1$"},
	}
	e := newTestEngine(t, []*config.EventPolicy{pol})

	// ping_test_failed IS scoped by the target constraint.
	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", Target: "10.0.0.1"}) {
		t.Error("scoped event must match its target constraint")
	}
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", Target: "10.0.0.2"}) {
		t.Error("scoped event must be gated by a non-matching target")
	}
	// ping_test_completed is NOT scoped by a ping_test_failed constraint.
	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_completed", Target: "10.0.0.9"}) {
		t.Error("a ping_test_failed-scoped target constraint must not gate ping_test_completed (#3753)")
	}
}

// Multiple attributes-match lines must ALL match (AND semantics) — one
// failing constraint blocks the policy.
func TestAttributesMatch_AllMustMatch(t *testing.T) {
	pol := &config.EventPolicy{
		Name:   "p",
		Events: []string{"ping_test_failed"},
		AttributesMatch: []string{
			"ping_test_failed.test-owner matches ^Comcast$",
			"ping_test_failed.test-name matches ^wan$",
		},
	}
	e := newTestEngine(t, []*config.EventPolicy{pol})

	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "Comcast", TestName: "wan"}) {
		t.Error("both constraints satisfied should match")
	}
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "Comcast", TestName: "lan"}) {
		t.Error("one failing constraint should block the match")
	}
}
