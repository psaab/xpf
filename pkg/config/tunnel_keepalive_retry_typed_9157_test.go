package config

import (
	"strings"
	"testing"
)

// #9157 — `interfaces <*> tunnel keepalive-retry` was the only UNTYPED leaf
// among four typed siblings.
//
// `key`, `ttl` and `keepalive` each declare `valueType: ValueInteger` plus an
// explicit `ValidateInteger` range; `keepalive-retry` declared neither, and
// schema_walk.go builds a value checker exactly when `n.validator != nil`, so
// the leaf was walked and waved through.
//
// THE HARM IS REACHABILITY, NOT OVERFLOW. `keepaliveLoop` transitions the
// tunnel down at `state.Failures >= state.MaxRetries`
// (pkg/routing/tunnel_keepalive_runner.go), `Failures` increments once per probe
// tick, and `startKeepalive` normalizes only `<= 0 -> 3`. So a value large
// enough makes that comparison unreachable: a GRE keepalive the operator
// enabled never declares the tunnel down, the anchor stays up, and static routes
// over it keep forwarding into a dead peer. The reachable spelling is
// `set … tunnel keepalive 30 keepalive-retry 99999999999`, because the runner is
// gated on `tc.Keepalive > 0`.
//
// The second half is the typo: `abc` parsed to 0 through a discarded
// `strconv.Atoi` error and became the runtime default 3, so a mistyped value was
// silently a working config rather than a commit error.

// keepaliveRetryTree9157 builds the flat-set candidate an operator types.
func keepaliveRetryTree9157(t *testing.T, retry string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	lines := []string{
		"set interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 unit 0 tunnel destination 10.0.0.2",
		"set interfaces gr-0/0/0 unit 0 tunnel keepalive 30",
	}
	if retry != "" {
		lines = append(lines, "set interfaces gr-0/0/0 unit 0 tunnel keepalive-retry "+retry)
	}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	return tree
}

// keepaliveTree9157 is the IN-CONTAINER POSITIVE CONTROL: the same fixture with
// the value on `keepalive`, a sibling that has carried a range since #5705.
//
// It is what makes a rejection of `keepalive-retry` readable. Without it, "the
// commit was rejected" cannot be told from "my fixture never reached the tunnel
// walk at all" — and the fixture reaching the walk is precisely what was in
// doubt, since this leaf sits three levels down under a wildcard interface name.
func keepaliveTree9157(t *testing.T, ka string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range []string{
		"set interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 unit 0 tunnel destination 10.0.0.2",
		"set interfaces gr-0/0/0 unit 0 tunnel keepalive " + ka,
	} {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	return tree
}

func tunnelRetry9157(cfg *Config) (int, bool) {
	if cfg == nil {
		return 0, false
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		for _, u := range ifc.Units {
			if u.Tunnel != nil {
				return u.Tunnel.KeepaliveRetry, true
			}
		}
	}
	return 0, false
}

// TestKeepaliveRetryIsRangeValidated9157 is the commit-gate table.
//
// CHANNEL: config.SchemaValidate — the typed-leaf walk, which is what
// configstore.CheckText runs through compileTreeStrict on the operator's commit
// path. It is NOT config.CompileConfig: the strict COMPILER gates do not cover
// this leaf and never did, and asserting there would have measured a layer that
// rejects neither the leaf nor its already-typed sibling.
func TestKeepaliveRetryIsRangeValidated9157(t *testing.T) {
	// POSITIVE CONTROL FIRST, both directions. A range gate that rejects
	// everything and one that rejects nothing are both satisfiable by a
	// one-directional table.
	if err := SchemaValidate(keepaliveTree9157(t, "99999999999")); err == nil {
		t.Fatal("CONTROL: the sibling `keepalive` must REJECT an out-of-range value at " +
			"this layer. If it does not, the fixture never reached the tunnel walk and " +
			"nothing below can be read as being about keepalive-retry")
	}
	if err := SchemaValidate(keepaliveTree9157(t, "30")); err != nil {
		t.Fatalf("CONTROL: the sibling `keepalive` must ACCEPT an in-range value; got %v", err)
	}

	for _, tc := range []struct {
		value  string
		reject bool
		why    string
	}{
		{"99999999999", true, "the value this issue was filed on: `Failures >= MaxRetries` becomes unreachable"},
		{"256", true, "one past the Junos ceiling"},
		{"0", true, "0 used to mean the runtime default 3, which is a value the operator did not write"},
		{"-5", true, "negative also normalized to 3 at runtime"},
		{"abc", true, "a typo became the default 3 through a discarded strconv error"},
		{"1", false, "the floor: one failed probe declares the tunnel down"},
		{"3", false, "the Junos default"},
		{"255", false, "the Junos ceiling"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			err := SchemaValidate(keepaliveRetryTree9157(t, tc.value))
			switch {
			case tc.reject && err == nil:
				t.Errorf("#9157: `keepalive-retry %s` was ACCEPTED at the commit gate (%s). "+
					"The leaf declares no valueType/validator, so schema_walk.go builds no "+
					"checker for it", tc.value, tc.why)
			case !tc.reject && err != nil:
				t.Errorf("#9157: `keepalive-retry %s` was REJECTED (%s): %v", tc.value, tc.why, err)
			case tc.reject && err != nil:
				// A rejection by the WRONG branch reads as a working guard, so
				// assert the leaf is NAMED and the range is the reason.
				if !strings.Contains(err.Error(), "keepalive-retry") {
					t.Errorf("#9157: `keepalive-retry %s` was rejected, but the message does "+
						"not name the leaf, so this cell cannot tell its own gate from an "+
						"unrelated one: %v", tc.value, err)
				}
			}
		})
	}
}

// TestKeepaliveRetryCompilesInRange9157 asserts the value SURVIVES to the typed
// config, not merely that the gate accepts it.
//
// A range check plus a reader that drops the value is the same outage with a
// commit gate in front of it.
func TestKeepaliveRetryCompilesInRange9157(t *testing.T) {
	for _, v := range []struct {
		text string
		want int
	}{{"1", 1}, {"3", 3}, {"255", 255}} {
		cfg, err := CompileConfig(keepaliveRetryTree9157(t, v.text))
		if err != nil {
			t.Fatalf("compile %q: %v", v.text, err)
		}
		got, ok := tunnelRetry9157(cfg)
		if !ok {
			t.Fatalf("no tunnel compiled for keepalive-retry %q — the fixture is broken, "+
				"so the assertion below would pass at zero", v.text)
		}
		if got != v.want {
			t.Errorf("keepalive-retry %q compiled to %d, want %d", v.text, got, v.want)
		}
	}
}

// TestEveryTunnelValueLeafIsTyped9157 is the coverage assertion the issue asks
// for, and it exists because a PER-LEAF test cannot see the defect.
//
// The finding is not "this leaf has no bound". It is "this leaf has no bound
// AND its three siblings do" — an omission among typed siblings, which is
// invisible to any cell that looks at one leaf. This walks the container from
// setSchema, so a leaf ADDED later without a type reds here rather than waiting
// for someone to notice the asymmetry again.
//
// Childless value leaves only: `routing-instance` and `wireguard` are
// containers, and a container has no value slot to type.
func TestEveryTunnelValueLeafIsTyped9157(t *testing.T) {
	tunnel := tunnelSchema9156()
	if tunnel == nil {
		t.Fatal("could not resolve the `interfaces <name> tunnel` schema; this cell is blind")
	}
	if len(tunnel.children) == 0 {
		t.Fatal("the tunnel container declares no children; this cell asserts nothing")
	}
	typed, untyped := 0, []string{}
	for name, ch := range tunnel.children {
		if ch == nil || len(ch.children) > 0 || ch.wildcard != nil {
			continue // a container, not a value leaf
		}
		if ch.args == 0 {
			continue // a valueless flag has no value slot to type
		}
		if ch.valueType == ValueAny || ch.validator == nil {
			untyped = append(untyped, name)
			continue
		}
		typed++
	}
	// NON-VACUITY: if the walk classified every child as a container the loop
	// would report a clean board over nothing.
	if typed == 0 && len(untyped) == 0 {
		t.Fatal("no value leaf under `tunnel` was examined — the shape predicate stopped " +
			"matching and this cell is reporting clean over an empty set")
	}
	if len(untyped) > 0 {
		t.Errorf("#9157: %d value leaf/leaves under `interfaces <*> tunnel` declare no "+
			"valueType or no validator: %v.\n"+
			"    Every sibling here carries an explicit range, and the one that did not "+
			"(`keepalive-retry`) accepted 99999999999 — which makes the runtime's "+
			"`Failures >= MaxRetries` dead-peer check unreachable. An untyped leaf is "+
			"walked and waved through: schema_walk.go builds a checker exactly when "+
			"`n.validator != nil`.", len(untyped), untyped)
	}
	t.Logf("#9157: %d typed value leaves under `interfaces <*> tunnel`", typed)
}

// TestKeepaliveRetryHeadIsRejectedOnceTyped9157 records what typing this leaf
// COST, in the direction that keeps it falsifiable.
//
// Before #9157 `keepalive-retry` was one of the `tunnel` container's two UNTYPED
// ADMISSION HEADS: `validateModifierChild` rejects a flat run whose head is
// typed, so an untyped head carried the whole run past the strict gate. #9156
// fixed the READER so such a run expands correctly instead of being dropped, and
// its cells used `keepalive-retry` as the head.
//
// Typing the leaf removes that head, so the spelling is now REJECTED at commit
// rather than accepted-and-expanded. That is a deliberate narrowing — Junos does
// not accept several statements on one `set` line either, and the typed-head
// order (`destination B keepalive-retry 5`) has always been rejected, so the two
// orders now agree — but it is a behaviour change and it must not be inferred
// from a test that simply stopped being written.
//
// `routing-instance` is the container's remaining untyped head, so the #9156
// cells keep their subject; see the note in tunnel_flat_run_9156_test.go.
func TestKeepaliveRetryHeadIsRejectedOnceTyped9157(t *testing.T) {
	tree := &ConfigTree{}
	p, err := ParseSetCommand(
		"set interfaces gr-0/0/0 unit 0 tunnel keepalive-retry 5 source 10.0.0.1 destination 10.0.0.2")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := tree.SetPath(p); err != nil {
		t.Fatalf("setpath: %v", err)
	}
	err = SchemaValidateWithDefinitions(tree, tree)
	if err == nil {
		t.Fatal("#9157: a flat run headed by `keepalive-retry` is ACCEPTED again. The leaf " +
			"has lost its valueType or its validator, which also removes the range bound " +
			"that keeps the runtime's dead-peer check reachable")
	}
	if !strings.Contains(err.Error(), "keepalive-retry") {
		t.Errorf("#9157: the run is rejected, but not at `keepalive-retry` — a rejection "+
			"from a different leaf would read as this guard working: %v", err)
	}

	// THE SURVIVING HEAD, asserted in the same run. Without it, "the run is
	// rejected" could equally mean the flat-run expansion itself regressed, and
	// the two have opposite fixes.
	riTree := &ConfigTree{}
	rp, err := ParseSetCommand(
		"set interfaces gr-0/0/0 unit 0 tunnel routing-instance destination VR1 source 10.0.0.1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := riTree.SetPath(rp); err != nil {
		t.Fatalf("setpath: %v", err)
	}
	if err := SchemaValidateWithDefinitions(riTree, riTree); err != nil {
		t.Fatalf("CONTROL: `routing-instance` is still an untyped admission head and its "+
			"run must still be admitted; got %v", err)
	}
}
