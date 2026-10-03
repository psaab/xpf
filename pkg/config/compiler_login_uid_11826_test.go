package config

import (
	"strings"
	"testing"
)

func loginUIDTree11826(t *testing.T, uid string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	commands := []string{
		"set system login user alice class super-user",
	}
	if uid != "" {
		commands = append(commands, "set system login user alice uid "+uid)
	}
	for _, command := range commands {
		path, err := ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	return tree
}

func TestLoginUserUIDSchemaAndStrictCompile11826(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{value: "1000", valid: true},
		{value: "garbage"},
		{value: "-5"},
		{value: "0"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			tree := loginUIDTree11826(t, tc.value)
			validateErr := SchemaValidate(tree, nil)
			_, compileErr := CompileConfig(tree)
			if tc.valid {
				if validateErr != nil || compileErr != nil {
					t.Fatalf("valid uid %q: SchemaValidate=%v CompileConfig=%v", tc.value, validateErr, compileErr)
				}
				return
			}
			if validateErr == nil {
				t.Errorf("SchemaValidate accepted invalid login uid %q", tc.value)
			}
			if compileErr == nil {
				t.Errorf("strict CompileConfig accepted invalid login uid %q", tc.value)
			} else if !strings.Contains(compileErr.Error(), "alice") || !strings.Contains(compileErr.Error(), tc.value) {
				t.Errorf("strict error %q does not name user and uid value", compileErr)
			}
		})
	}
}

func TestLoginUserUIDLenientCompileDoesNotRequestAutomaticUID11826(t *testing.T) {
	for _, raw := range []string{"garbage", "-5", "0"} {
		t.Run(raw, func(t *testing.T) {
			cfg, err := CompileConfigLenient(loginUIDTree11826(t, raw))
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			if cfg.System.Login == nil || len(cfg.System.Login.Users) != 1 {
				t.Fatalf("compiled login users = %+v, want alice", cfg.System.Login)
			}
			if got := cfg.System.Login.Users[0].UID; got >= 0 {
				t.Fatalf("invalid authored uid compiled as %d; zero would request automatic UID allocation", got)
			}
			found := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "system login user alice uid") && strings.Contains(warning, raw) && strings.Contains(warning, "automatic UID allocation") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("warnings %q do not name invalid uid %q or the refused automatic assignment", cfg.Warnings, raw)
			}
		})
	}
}

func TestLoginUserUIDUnsetAndValidValues11826(t *testing.T) {
	for _, tc := range []struct {
		name string

		uid  string
		want int
	}{
		{name: "unset retains automatic assignment semantics", want: 0},
		{name: "explicit positive uid", uid: "2001", want: 2001},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(loginUIDTree11826(t, tc.uid))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			if got := cfg.System.Login.Users[0].UID; got != tc.want {
				t.Fatalf("compiled uid = %d, want %d", got, tc.want)
			}
		})
	}
}
func TestLoginUserUIDTypedLeafRejectsPackedTail11826(t *testing.T) {
	tree := loginUIDTree11826(t, "2001")
	path, err := ParseSetCommand("set system login user bob uid 2001 class read-only")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	if err := SchemaValidate(tree, nil); err == nil {
		t.Fatal("typed login UID accepted a packed class tail; author UID and class as separate set statements")
	}
}
