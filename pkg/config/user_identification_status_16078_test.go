package config

import (
	"strings"
	"testing"
)

// #16078 FA-02: user-identification stanzas commit wholly inert while their
// credentials are stored. The accepted-only warning fires at commit, but
// `show`/`status` displayed the stanza as ordinary config, so an operator
// could believe user-identification was active. The compiled config must
// record which stanzas are configured (both spellings) and the shared
// renderer must name them inert.

func TestUserIdentificationConfigured16078(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
		want  []string
	}{
		{"services wrapped", []string{
			"set services user-identification active-directory-access domain-name corp.example",
			"set services user-identification identity-management connection primary",
		}, []string{"active-directory-access", "identity-management"}},
		{"security wrapped", []string{
			"set security user-identification authentication-source local-authentication-table auth1",
		}, []string{"authentication-source"}},
		{"security direct", []string{
			"set security authentication-source jims",
			"set security device-information source foo",
		}, []string{"authentication-source", "device-information"}},
		{"services flat duplicate collapses", []string{
			"set services user-identification active-directory-access domain-name a.example",
			"set services user-identification active-directory-access domain-name b.example",
		}, []string{"active-directory-access"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got := cfg.UserIdentificationConfigured()
			if len(got) != len(tc.want) {
				t.Fatalf("UserIdentificationConfigured=%v want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("UserIdentificationConfigured=%v want %v", got, tc.want)
				}
			}
		})
	}

	// No stanza -> none configured.
	cfg, err := CompileConfig(buildTree(t, []string{"set system host-name r1"}))
	if err != nil {
		t.Fatalf("compile empty: %v", err)
	}
	if got := cfg.UserIdentificationConfigured(); len(got) != 0 {
		t.Fatalf("no user-identification configured, got %v", got)
	}
	var nilCfg *Config
	if got := nilCfg.UserIdentificationConfigured(); got != nil {
		t.Fatalf("nil config must yield nil, got %v", got)
	}
}

func TestRenderUserIdentificationStatus16078(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set services user-identification active-directory-access domain-name corp.example",
		"set security user-identification identity-management connection primary",
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var b strings.Builder
	RenderUserIdentificationStatus(&b, cfg)
	out := b.String()
	for _, want := range []string{
		"User identification status:",
		"INERT",
		"active-directory-access",
		"identity-management",
		"no runtime effect",
		"#16078",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "enabled") || strings.Contains(out, "active") && !strings.Contains(out, "INERT") {
		t.Errorf("render must not claim user-identification is active/enabled:\n%s", out)
	}

	// Unconfigured: must say so, not render inert rows.
	cfg2, err := CompileConfig(buildTree(t, []string{"set system host-name r1"}))
	if err != nil {
		t.Fatalf("compile empty: %v", err)
	}
	b.Reset()
	RenderUserIdentificationStatus(&b, cfg2)
	if !strings.Contains(b.String(), "No user-identification configured") {
		t.Errorf("unconfigured render must say so:\n%s", b.String())
	}
	if strings.Contains(b.String(), "INERT") {
		t.Errorf("unconfigured render must not claim INERT stanzas:\n%s", b.String())
	}

	// Nil config.
	b.Reset()
	RenderUserIdentificationStatus(&b, nil)
	if !strings.Contains(b.String(), "No active configuration") {
		t.Errorf("nil render:\n%s", b.String())
	}
}
