package config

import (
	"strings"
	"testing"
)

// #18744: a strict commit refuses a published placeholder key that it
// INTRODUCES over an active config, keeps a pre-existing one as a warning,
// and leaves fresh state and the tolerant paths warning-only.

const (
	// Both are long enough to clear the #16025 length floor, so every cell
	// below exercises the placeholder gate rather than the short-key one.
	placeholderP18744  = "xpf-lab-ha-psk-cluster-22-CHANGE-ME"
	placeholderP218744 = "example-only-psk-0123456789abcdef"
)

const placeholderRefusal18744 = "would introduce a published placeholder"

func requirePlaceholderRefusal18744(t *testing.T, err error, leaf string) {
	t.Helper()
	if err == nil {
		t.Fatalf("committed a newly introduced published placeholder in %s (#18744)", leaf)
	}
	msg := err.Error()
	if !strings.Contains(msg, placeholderRefusal18744) {
		t.Fatalf("refused, but not by the #18744 placeholder gate: %v", err)
	}
	if !strings.Contains(msg, "`"+leaf+"`") {
		t.Fatalf("refusal does not name the %s leaf: %v", leaf, err)
	}
	// Neither the key nor its marker may be echoed: when the key IS a
	// marker, naming the marker prints the key.
	lower := strings.ToLower(msg)
	for _, s := range []string{placeholderP18744, placeholderP218744, "change-me", "example-only"} {
		if strings.Contains(lower, strings.ToLower(s)) {
			t.Fatalf("refusal echoes key material or a marker (%q): %v", s, err)
		}
	}
}

func placeholderWarned18744(cfg *Config, leaf string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "chassis cluster "+leaf+" matches a published placeholder") {
			return true
		}
	}
	return false
}

// Rotating TO a placeholder: staging one as the additional key over an
// active config that does not hold it is refused.
func TestPlaceholderStagedAsAdditionalRefused18744(t *testing.T) {
	activeA := currentConfig16858(t, keyA16858, "")
	_, err := CompileConfigWithCurrentClusterPrimary(clusterTree16858(t, keyA16858, placeholderP18744), activeA)
	requirePlaceholderRefusal18744(t, err, "additional-authentication-key")
}

// A one-shot change to a placeholder primary is refused by THIS gate's
// message, not the #16858 transition message: the operator has to change
// the value, not run the overlap procedure with it.
func TestPlaceholderPrimaryNamedBeforeTransition18744(t *testing.T) {
	activeA := currentConfig16858(t, keyA16858, "")
	_, err := CompileConfigWithCurrentClusterPrimary(clusterTree16858(t, placeholderP18744, ""), activeA)
	requirePlaceholderRefusal18744(t, err, "authentication-key")
	if strings.Contains(err.Error(), "#16858") {
		t.Fatalf("the transition gate answered first; the placeholder gate must be ordered before it: %v", err)
	}
}

// Keying a running node with a placeholder is introducing one, whether the
// active config has an unkeyed cluster stanza or no cluster at all.
func TestPlaceholderKeyingActiveConfigRefused18744(t *testing.T) {
	unkeyed := currentConfig16858(t, "", "")
	_, err := CompileConfigWithCurrentClusterPrimary(clusterTree16858(t, placeholderP18744, ""), unkeyed)
	requirePlaceholderRefusal18744(t, err, "authentication-key")

	standalone, err := CompileConfigLenient(buildTree(t, []string{"set system host-name fw"}))
	if err != nil {
		t.Fatalf("standalone active fixture: %v", err)
	}
	_, err = CompileConfigWithCurrentClusterPrimary(clusterTree16858(t, placeholderP18744, ""), standalone)
	requirePlaceholderRefusal18744(t, err, "authentication-key")
}

// A different placeholder is a new value even when the active config already
// holds one.
func TestSecondPlaceholderOverPreexistingRefused18744(t *testing.T) {
	activeP := currentConfig16858(t, placeholderP18744, "")
	_, err := CompileConfigWithCurrentClusterPrimary(
		clusterTree16858(t, placeholderP18744, placeholderP218744), activeP)
	requirePlaceholderRefusal18744(t, err, "additional-authentication-key")
}

// Pre-existing is judged byte for byte: a padded spelling of the active
// placeholder is a different key.
func TestPaddedPlaceholderIsNotPreexisting18744(t *testing.T) {
	activeP := currentConfig16858(t, placeholderP18744, "")
	padded := `" ` + placeholderP18744 + ` "`
	_, err := CompileConfigWithCurrentClusterPrimary(clusterTree16858(t, padded, placeholderP18744), activeP)
	requirePlaceholderRefusal18744(t, err, "authentication-key")
}

// The marker match is case-insensitive, as the warning's is.
func TestPlaceholderMarkerCaseInsensitive18744(t *testing.T) {
	activeA := currentConfig16858(t, keyA16858, "")
	_, err := CompileConfigWithCurrentClusterPrimary(
		clusterTree16858(t, keyA16858, "xpf-lab-ha-psk-cluster-22-Change-Me"), activeA)
	requirePlaceholderRefusal18744(t, err, "additional-authentication-key")
}

// The whole rotation off a placeholder commits, each step warning while the
// placeholder is still held, and the finalized config stops warning.
func TestRotationOffPlaceholderCommits18744(t *testing.T) {
	steps := []struct {
		name                       string
		activeP, activeA           string
		candP, candA               string
		warnPrimary, warnAdditonal bool
	}{
		{"routine commit on a placeholder-keyed node", placeholderP18744, "", placeholderP18744, "", true, false},
		{"step 1-2: stage the real key beside the placeholder signer", placeholderP18744, "", placeholderP18744, keyA16858, true, false},
		{"step 3-4: stage the retiring placeholder signer as additional", placeholderP18744, keyA16858, keyA16858, placeholderP18744, false, true},
		// A routine commit while the window sits at steps 3-4, and backing out
		// of them: both are judged against an active config that holds the
		// placeholder as the ADDITIONAL key, so the additional slot must count
		// as accepted.
		{"routine commit at steps 3-4", keyA16858, placeholderP18744, keyA16858, placeholderP18744, false, true},
		{"backing out of steps 3-4", keyA16858, placeholderP18744, placeholderP18744, keyA16858, true, false},
		{"step 5: finalize", keyA16858, placeholderP18744, keyA16858, "", false, false},
	}
	for _, st := range steps {
		active := currentConfig16858(t, st.activeP, st.activeA)
		cfg, err := CompileConfigWithCurrentClusterPrimary(clusterTree16858(t, st.candP, st.candA), active)
		if err != nil {
			t.Fatalf("%s: refused: %v", st.name, err)
		}
		if got := placeholderWarned18744(cfg, "authentication-key"); got != st.warnPrimary {
			t.Fatalf("%s: authentication-key placeholder warning = %v, want %v (%q)", st.name, got, st.warnPrimary, cfg.Warnings)
		}
		if got := placeholderWarned18744(cfg, "additional-authentication-key"); got != st.warnAdditonal {
			t.Fatalf("%s: additional-authentication-key placeholder warning = %v, want %v (%q)", st.name, got, st.warnAdditonal, cfg.Warnings)
		}
	}
}

// Rolling back to a config that brings a retired placeholder back is
// introducing it again.
func TestRollbackReintroducingPlaceholderRefused18744(t *testing.T) {
	finalized := currentConfig16858(t, keyA16858, "")
	_, err := CompileConfigWithCurrentClusterPrimary(
		clusterTree16858(t, keyA16858, placeholderP18744), finalized)
	requirePlaceholderRefusal18744(t, err, "additional-authentication-key")
	_, err = CompileConfigWithCurrentClusterPrimary(
		clusterTree16858(t, placeholderP18744, keyA16858), finalized)
	requirePlaceholderRefusal18744(t, err, "authentication-key")
}

// Fresh state is not judged: no active config (empty store, bootstrap import,
// check-config, direct CompileConfig) keeps the warning only, so a reimaged
// node bootstrapping a placeholder conf still gets an active config.
// The caller decides whether to judge (configstore). Judged with no active
// config, the accepted set is empty, so any placeholder is introduced: that
// is an interactive first commit on a store that never committed.
func TestJudgedWithNoActiveConfigRefusesAnyPlaceholder18744(t *testing.T) {
	_, err := CompileConfigJudgingPlaceholders(clusterTree16858(t, placeholderP18744, ""), nil, true)
	requirePlaceholderRefusal18744(t, err, "authentication-key")
	_, err = CompileConfigForNodeJudgingPlaceholders(clusterTree16858(t, keyA16858, placeholderP18744), 0, nil, true)
	requirePlaceholderRefusal18744(t, err, "additional-authentication-key")
	// CONTROL: the same compile not judged only warns.
	cfg, err := CompileConfigJudgingPlaceholders(clusterTree16858(t, placeholderP18744, ""), nil, false)
	if err != nil {
		t.Fatalf("not judged, a placeholder was refused: %v", err)
	}
	if !placeholderWarned18744(cfg, "authentication-key") {
		t.Fatalf("not judged, the placeholder warning is missing: %q", cfg.Warnings)
	}
}

func TestPlaceholderFreshStateWarnsOnly18744(t *testing.T) {
	for name, compile := range map[string]func() (*Config, error){
		"CompileConfig": func() (*Config, error) {
			return CompileConfig(clusterTree16858(t, placeholderP18744, ""))
		},
		"empty store (current nil)": func() (*Config, error) {
			return CompileConfigWithCurrentClusterPrimary(clusterTree16858(t, placeholderP18744, ""), nil)
		},
		"empty store, node-aware": func() (*Config, error) {
			return CompileConfigForNodeWithCurrentClusterPrimary(clusterTree16858(t, placeholderP18744, ""), 0, nil)
		},
	} {
		cfg, err := compile()
		if err != nil {
			t.Fatalf("%s: a placeholder in fresh state was refused: %v", name, err)
		}
		if !placeholderWarned18744(cfg, "authentication-key") {
			t.Fatalf("%s: fresh-state placeholder committed without its warning: %q", name, cfg.Warnings)
		}
	}
}

// The tolerant path downgrades the refusal to a warning (#1960 no-brick).
// No public tolerant entry supplies the active state, so build the options
// directly to reach the downgrade branch.
func TestPlaceholderRefusalDowngradedOnTolerantPath18744(t *testing.T) {
	opts := currentClusterOpts(currentConfig16858(t, keyA16858, ""))
	opts.judgePlaceholders18744 = true
	opts.lenientClusterAuthKey = true
	cfg, err := compileTree(clusterTree16858(t, keyA16858, placeholderP18744), opts, nil)
	if err != nil {
		t.Fatalf("tolerant path refused an introduced placeholder (no-brick violated): %v", err)
	}
	downgraded := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "downgraded to warning on tolerant path") &&
			strings.Contains(w, placeholderRefusal18744) {
			downgraded = true
		}
	}
	if !downgraded {
		t.Fatalf("tolerant path dropped the refusal instead of downgrading it: %q", cfg.Warnings)
	}
}
