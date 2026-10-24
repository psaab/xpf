package config

import (
	"strings"
	"testing"
)

// #9154: the `*-configuration` regexes were evaluated on exactly ONE of three
// dispatch surfaces — the on-box CLI. The gRPC listener the shipped `cli`
// binary speaks to, and the REST API, both mutated configuration without ever
// consulting them.
//
// #7172's own acceptance says this must not happen: "configuration regexes
// apply to EVERY config mutation form … Both dispatch surfaces must use it —
// pkg/cli and pkg/grpcapi — and neither may be gated alone."
//
// This file pins the DECISION, now shared. The surface wiring is asserted in
// pkg/grpcapi and pkg/api; what matters here is that one class definition means
// one thing, so the three cannot drift.

func classWithConfigRegex9154(t *testing.T, allow, deny string) *Config {
	t.Helper()
	var b strings.Builder
	b.WriteString("system { login { class limited { permissions [ configure view ]; ")
	if allow != "" {
		b.WriteString("allow-configuration \"" + allow + "\"; ")
	}
	if deny != "" {
		b.WriteString("deny-configuration \"" + deny + "\"; ")
	}
	b.WriteString("} } }")
	root, perrs := NewParser(b.String()).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(&ConfigTree{Children: root.Children})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func TestAuthorizeConfigMutation9154(t *testing.T) {
	for _, tc := range []struct {
		name        string
		allow, deny string
		editPath    []string
		line        string
		wantDenied  bool
	}{
		{"deny matches", "", "system root-authentication", nil,
			"set system root-authentication plain-text-password hunter2", true},
		{"deny does not match", "", "system root-authentication", nil,
			"set system host-name fw1", false},

		// THE EDIT-PATH BYPASS the CLI gate exists to close: matching the typed
		// remainder alone lets `edit system` walk the deny. Asserted here so the
		// shared decision keeps that property for every surface.
		{"resolved through the edit path", "", "system root-authentication",
			[]string{"system"}, "set root-authentication plain-text-password hunter2", true},

		// Navigation changes nothing and is not gated — gating it would stop an
		// operator merely LOOKING at a subtree.
		{"edit is not gated", "", "system root-authentication", nil, "edit system root-authentication", false},
		{"top is not gated", "", "system", nil, "top", false},

		// A class with NO configuration regexes is unrestricted EXCEPT
		// for credential paths, which #16080 prices above PermConfig
		// even without any regex fencing (see
		// credential_surcharge_16080_test.go).
		{"no regexes configured", "", "", nil,
			"set system host-name fw1", false},
		{"no regexes credential fenced 16080", "", "", nil,
			"set system root-authentication plain-text-password hunter2", true},

		// Every mutating verb is gated, not just `set`.
		{"delete is gated", "", "system root-authentication", nil,
			"delete system root-authentication", true},
		{"deactivate is gated", "", "system root-authentication", nil,
			"deactivate system root-authentication", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := classWithConfigRegex9154(t, tc.allow, tc.deny)
			err := AuthorizeConfigMutation(cfg, "limited", tc.editPath, tc.line)
			if (err != nil) != tc.wantDenied {
				t.Fatalf("denied=%v, want %v (err=%v)\n  line: %s", err != nil, tc.wantDenied, err, tc.line)
			}
			if err == nil {
				return
			}
			// AUDIT BOUND: a config path's trailing tokens are operator data —
			// `set system root-authentication plain-text-password <secret>` puts
			// the secret in the path itself — so the message must never carry
			// the full path.
			if strings.Contains(err.Error(), "hunter2") {
				t.Errorf("the denial leaked the operator's secret into its message: %v", err)
			}
		})
	}
}

// TestAuthorizeConfigMutationIsSurfaceIndependent9154 pins the property the
// whole change is for: the decision takes only (config, class, editPath, line),
// so it cannot mean different things on different surfaces. If someone adds a
// surface-specific parameter, this is what should make them stop and think.
func TestAuthorizeConfigMutationIsSurfaceIndependent9154(t *testing.T) {
	cfg := classWithConfigRegex9154(t, "", "system root-authentication")
	const line = "set system root-authentication plain-text-password hunter2"

	// The CLI passes an edit path; the two remote surfaces pass nil because
	// they receive an already-resolved line. Both must reach the same verdict
	// for the same RESOLVED path.
	viaCLI := AuthorizeConfigMutation(cfg, "limited", []string{"system"},
		"set root-authentication plain-text-password hunter2")
	viaRemote := AuthorizeConfigMutation(cfg, "limited", nil, line)
	if (viaCLI == nil) != (viaRemote == nil) {
		t.Errorf("the same resolved path is judged differently depending on who resolved it:\n"+
			"  cli    %v\n  remote %v", viaCLI, viaRemote)
	}
	if viaRemote == nil {
		t.Error("the remote form was ALLOWED — this is the #9154 defect")
	}
}
