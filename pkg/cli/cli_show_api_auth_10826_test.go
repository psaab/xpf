package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestShowSystemServicesCountsNamedAPIKeys10826(t *testing.T) {
	tests := []struct {
		name     string
		commands []string
		want     string
	}{
		{
			name: "named key only",
			commands: []string{
				"set system services web-management api-auth expires 2099-01-01",
				"set system services web-management api-auth key automation secret 0123456789abcdef",
			},
			want: "API auth:       0 user(s), 1 API key(s)",
		},
		{
			name: "mixed named and legacy credentials",
			commands: []string{
				"set system services web-management api-auth expires 2099-01-01",
				"set system services web-management api-auth user admin password very-long-password",
				"set system services web-management api-auth api-key 0123456789abcdef-legacy",
				"set system services web-management api-auth key automation secret 0123456789abcdef",
			},
			want: "API auth:       1 user(s), 2 API key(s)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure(): %v", err)
			}
			for _, command := range tc.commands {
				if _, err := store.LoadSet(command); err != nil {
					t.Fatalf("LoadSet(%q): %v", command, err)
				}
			}
			if _, err := store.Commit(); err != nil {
				t.Fatalf("Commit(): %v", err)
			}

			c := &CLI{store: store}
			out := captureStdout(t, func() {
				if err := c.showSystemServices(); err != nil {
					t.Fatalf("showSystemServices(): %v", err)
				}
			})
			if !strings.Contains(out, tc.want) {
				t.Fatalf("API-auth credential counts = %q, want %q:\n%s", out, tc.want, out)
			}
		})
	}
}
