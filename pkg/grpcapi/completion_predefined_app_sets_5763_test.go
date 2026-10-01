package grpcapi

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

var predefinedApplicationSetNames5763 = []string{
	"junos-ms-rpc",
	"junos-sun-rpc",
	"junos-cifs",
	"junos-routing-inbound",
	"junos-sip",
	"junos-smb",
	"junos-h323",
}

type completionPath5763 struct {
	name        string
	words       []string
	hint        config.ValueHint
	placeholder string
}

func matchingCompletionDescriptions5763(pairs []completionPair, name string) []string {
	var descriptions []string
	for _, pair := range pairs {
		if pair.name == name {
			descriptions = append(descriptions, pair.desc)
		}
	}
	return descriptions
}

func requireCompletionCount5763(t *testing.T, pairs []completionPair, name string, want int) []string {
	t.Helper()
	descriptions := matchingCompletionDescriptions5763(pairs, name)
	if len(descriptions) != want {
		t.Errorf(
			"completion %q occurrence count = %d, want %d; matching descriptions = %q; all pairs = %#v",
			name,
			len(descriptions),
			want,
			descriptions,
			pairs,
		)
	}
	return descriptions
}

func requireCompletion5763(t *testing.T, pairs []completionPair, name, wantDesc string) {
	t.Helper()
	descriptions := requireCompletionCount5763(t, pairs, name, 1)
	if len(descriptions) == 1 && descriptions[0] != wantDesc {
		t.Errorf("completion %q description = %q, want %q", name, descriptions[0], wantDesc)
	}
}

func TestCompleteConfigPairs_PredefinedApplicationSets_5763(t *testing.T) {
	paths := []completionPath5763{
		{
			name:        "zone-pair-policy",
			words:       []string{"set", "security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "match", "application"},
			hint:        config.ValueHintPolicyApp,
			placeholder: "<application>",
		},
		{
			name:        "global-policy",
			words:       []string{"set", "security", "policies", "global", "policy", "p", "match", "application"},
			hint:        config.ValueHintPolicyApp,
			placeholder: "<application>",
		},
		{
			name:        "application-name",
			words:       []string{"set", "applications", "application"},
			hint:        config.ValueHintAppName,
			placeholder: "<name>",
		},
		{
			name:        "application-set-name",
			words:       []string{"set", "applications", "application-set"},
			hint:        config.ValueHintAppSetName,
			placeholder: "<name>",
		},
	}

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if active := store.ActiveConfig(); active != nil {
		t.Fatalf("ActiveConfig() after construction = %#v, want nil", active)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if active := store.ActiveConfig(); active != nil {
		t.Fatalf("ActiveConfig() after EnterConfigure() = %#v, want nil", active)
	}
	s := &Server{store: store}

	for _, path := range paths {
		path := path
		t.Run("pre-commit/"+path.name, func(t *testing.T) {
			pairs := s.completeConfigPairs(path.words, "")
			if len(pairs) != 1 {
				t.Errorf("pre-commit pairs = %#v, want only %q", pairs, path.placeholder)
			}
			requireCompletionCount5763(t, pairs, path.placeholder, 1)
			for _, name := range predefinedApplicationSetNames5763 {
				requireCompletionCount5763(t, pairs, name, 0)
			}
		})
	}

	committed, err := store.Commit()
	if err != nil {
		t.Fatalf("first Commit() error = %v", err)
	}
	if committed == nil {
		t.Fatal("first Commit() returned nil config")
	}
	if active := store.ActiveConfig(); active == nil {
		t.Fatal("ActiveConfig() remained nil after first Commit()")
	}

	for _, path := range paths {
		path := path
		t.Run("default-catalog/"+path.name, func(t *testing.T) {
			pairs := s.completeConfigPairs(path.words, "")
			for _, name := range predefinedApplicationSetNames5763 {
				requireCompletion5763(t, pairs, name, "predefined application-set")
			}
			switch path.hint {
			case config.ValueHintPolicyApp:
				requireCompletion5763(t, pairs, "any", "Any application")
				requireCompletion5763(t, pairs, "junos-http", "predefined")
			case config.ValueHintAppName:
				requireCompletion5763(t, pairs, "junos-http", "predefined")
			case config.ValueHintAppSetName:
				requireCompletionCount5763(t, pairs, "any", 0)
				requireCompletionCount5763(t, pairs, "junos-http", 0)
			default:
				t.Fatalf("unexpected value hint %v", path.hint)
			}
		})
	}

	for _, command := range []string{
		"applications application junos-ms-rpc protocol tcp",
		"applications application junos-ms-rpc destination-port 9999",
		"applications application junos-ms-rpc description \"configured application shadow\"",
		"applications application-set junos-sip application junos-http",
	} {
		if err := store.SetFromInput(command); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", command, err)
		}
	}

	shadowConfig, err := store.Commit()
	if err != nil {
		t.Fatalf("shadow Commit() error = %v", err)
	}
	if shadowConfig == nil {
		t.Fatal("shadow Commit() returned nil config")
	}
	if active := store.ActiveConfig(); active == nil {
		t.Fatal("ActiveConfig() remained nil after shadow Commit()")
	}
	shadowApp := shadowConfig.Applications.Applications["junos-ms-rpc"]
	if shadowApp == nil {
		t.Fatal("compiled Applications[\"junos-ms-rpc\"] is nil")
	}
	if shadowApp.Description != "configured application shadow" {
		t.Fatalf("compiled junos-ms-rpc description = %q, want %q", shadowApp.Description, "configured application shadow")
	}
	if shadowSet := shadowConfig.Applications.ApplicationSets["junos-sip"]; shadowSet == nil {
		t.Fatal("compiled ApplicationSets[\"junos-sip\"] is nil")
	}

	for _, path := range paths {
		path := path
		t.Run("configured-shadows/"+path.name, func(t *testing.T) {
			pairs := s.completeConfigPairs(path.words, "")
			if path.hint == config.ValueHintAppSetName {
				requireCompletion5763(t, pairs, "junos-ms-rpc", "predefined application-set")
			} else {
				requireCompletion5763(t, pairs, "junos-ms-rpc", "configured application shadow")
			}
			requireCompletion5763(t, pairs, "junos-sip", "application-set")
			for _, name := range predefinedApplicationSetNames5763 {
				if name == "junos-ms-rpc" || name == "junos-sip" {
					continue
				}
				requireCompletion5763(t, pairs, name, "predefined application-set")
			}
		})
	}
}
