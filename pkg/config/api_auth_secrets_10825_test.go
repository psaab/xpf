package config

import (
	"crypto/sha256"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func parseAPIAuthSecretsTree10825(t *testing.T, commands ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
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

func parseAPIAuthSecretsConfig10825(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse API-auth fixture: %v", errs)
	}
	return tree
}

func TestHashAPIAuthSecretsScopesActualWebManagementPath10825(t *testing.T) {
	cases := []struct {
		name     string
		commands []string
		provider string
	}{
		{
			name:     "DDNS provider named api-auth",
			commands: []string{"set system services dynamic-dns provider api-auth password provider-password-unchanged"},
			provider: "api-auth",
		},
		{
			name: "DDNS inside group named api-auth",
			commands: []string{
				"set groups api-auth system services dynamic-dns provider inside password group-password-unchanged",
				"set apply-groups api-auth",
			},
			provider: "inside",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseAPIAuthSecretsTree10825(t, tc.commands...)
			before := tree.Format()
			changed, err := HashAPIAuthSecrets(tree)
			if err != nil {
				t.Fatalf("HashAPIAuthSecrets: %v", err)
			}
			if changed {
				t.Fatalf("non-API-auth DDNS password was treated as an API credential:\n%s", tree.Format())
			}

			if HasMalformedAPIAuthSecretTag(tree) {
				t.Fatal("unrelated DDNS password was treated as a malformed API-auth verifier")
			}
			if got := tree.Format(); got != before {
				t.Fatalf("HashAPIAuthSecrets mutated unrelated DDNS config:\nbefore:\n%s\nafter:\n%s", before, got)
			}

			compiled, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			if got := tree.Format(); got != before {
				t.Fatalf("CompileConfigLenient mutated source DDNS config:\nbefore:\n%s\nafter:\n%s", before, got)
			}
			if compiled.System.Services == nil || compiled.System.Services.DynamicDNS == nil {
				t.Fatal("DDNS config did not compile")
			}
			provider := compiled.System.Services.DynamicDNS.Providers[tc.provider]
			if provider == nil {
				t.Fatalf("DDNS provider %q missing after compilation", tc.provider)
			}
			want := "provider-password-unchanged"
			if tc.provider == "inside" {
				want = "group-password-unchanged"
			}
			if got := provider.Password.Reveal(); got != want {
				t.Fatalf("compiled DDNS password = %q, want byte-exact %q", got, want)
			}
		})
	}
}

func TestHashAPIAuthSecretsHashesCredentialSlots10825(t *testing.T) {
	const (
		basic = "correct-horse-battery"
		keyA  = "machine-generated-key-alpha"
		keyB  = "machine-generated-key-bravo"
		named = "automation-key-secret-alpha"
	)
	tree := parseAPIAuthSecretsConfig10825(t, `system {
 services {
  web-management {
   api-auth {
    user admin { password "correct-horse-battery"; }
    api-key machine-generated-key-alpha;
    api-key machine-generated-key-bravo;
    key automation { secret "automation-key-secret-alpha"; }
   }
  }
 }
}`)
	changed, err := HashAPIAuthSecrets(tree)
	if err != nil {
		t.Fatalf("HashAPIAuthSecrets: %v", err)
	}
	if !changed {
		t.Fatal("actual web-management API-auth credentials were not hashed")
	}

	if HasMalformedAPIAuthSecretTag(tree) {
		t.Fatal("valid API-auth verifiers were reported malformed")
	}

	system := tree.FindChild("system")
	if system == nil || system.FindChild("services") == nil || system.FindChild("services").FindChild("web-management") == nil {
		t.Fatal("web-management tree missing")
	}
	auth := system.FindChild("services").FindChild("web-management").FindChild("api-auth")
	if auth == nil {
		t.Fatal("api-auth tree missing")
	}
	user := auth.FindChild("user")
	if user == nil || user.FindChild("password") == nil {
		t.Fatal("Basic user password missing")
	}
	basicHash := user.FindChild("password").Keys[1]
	if !IsAPIAuthSecretHash(basicHash) || !VerifyAPIAuthSecret(basicHash, basic) {
		t.Fatal("Basic password was not stored as a usable tagged verifier")
	}

	var seenKeys int
	expectedKeys := []string{keyA, keyB}
	for _, node := range auth.FindChildren("api-key") {
		for _, value := range node.Keys[1:] {
			seenKeys++
			if seenKeys > len(expectedKeys) ||
				!IsAPIAuthSecretHash(value) || !VerifyAPIAuthSecret(value, expectedKeys[seenKeys-1]) {
				t.Fatalf("repeated API key %d was not stored as its matching usable tagged verifier", seenKeys)
			}
		}
	}
	if seenKeys != len(expectedKeys) {
		t.Fatalf("saw %d repeated API-key values, want %d", seenKeys, len(expectedKeys))
	}
	keyNode := auth.FindChild("key")
	if keyNode == nil || keyNode.FindChild("secret") == nil {
		t.Fatal("named API key secret missing")
	}
	namedHash := keyNode.FindChild("secret").Keys[1]
	if !IsAPIAuthSecretHash(namedHash) || !VerifyAPIAuthSecret(namedHash, named) {
		t.Fatal("named API-key secret was not stored as a usable tagged verifier")
	}
}

func TestHashAPIAuthSecretsHandlesActualSchemaPathInsideGroup10825(t *testing.T) {
	const cleartext = "group-basic-credential"
	tree := parseAPIAuthSecretsTree10825(t,
		"set groups g-auth system services web-management api-auth user admin password "+cleartext,
		"set apply-groups g-auth",
	)
	changed, err := HashAPIAuthSecrets(tree)
	if err != nil {
		t.Fatalf("HashAPIAuthSecrets: %v", err)
	}
	if !changed {
		t.Fatal("API-auth credential in a group definition was not hashed")
	}
	var password string
	var findPassword func([]*Node)
	findPassword = func(nodes []*Node) {
		for _, node := range nodes {
			if node == nil {
				continue
			}
			if len(node.Keys) >= 2 && node.Keys[0] == "password" {
				password = node.Keys[1]
			}
			findPassword(node.Children)
		}
	}
	findPassword(tree.Children)
	if !IsAPIAuthSecretHash(password) || !VerifyAPIAuthSecret(password, cleartext) {
		t.Fatal("group-defined web-management API-auth password was not a usable tagged verifier")
	}
}

func TestHashAPIAuthSecretsKeepsDeniedShortLegacyVerifierStable10825(t *testing.T) {
	tree := parseAPIAuthSecretsConfig10825(t, `system { services { web-management { api-auth {
		expires 2099-01-01;
		user admin { password tiny; }
		api-key tiny;
	} } } }`)
	changed, err := HashAPIAuthSecrets(tree)
	if err != nil || !changed {
		t.Fatalf("first HashAPIAuthSecrets = (%v, %v), want changed=true without error", changed, err)
	}
	auth := tree.FindChild("system").FindChild("services").
		FindChild("web-management").FindChild("api-auth")
	password := auth.FindChild("user").FindChild("password").Keys[1]
	apiKey := auth.FindChild("api-key").Keys[1]
	for _, marker := range []string{password, apiKey} {
		if !taggedAPIAuthHash(marker, apiAuthInvalidBcryptPrefix) {
			t.Fatalf("short legacy credential was not stored as a valid denied marker: %q", marker)
		}
		if VerifyAPIAuthSecret(marker, "tiny") {
			t.Fatal("denied short-credential marker authenticated as its legacy cleartext")
		}
	}
	if HasMalformedAPIAuthSecretTag(tree) {
		t.Fatal("well-formed denied legacy markers were reported as malformed")
	}
	changed, err = HashAPIAuthSecrets(tree)
	if err != nil || changed {
		t.Fatalf("repeat HashAPIAuthSecrets = (%v, %v), want changed=false without error", changed, err)
	}
	if _, err := CompileConfigLenient(tree); err != nil {
		t.Fatalf("lenient compile rejected denied legacy markers before repair: %v", err)
	}
	if err := SchemaValidate(tree, nil); err == nil ||
		!strings.Contains(err.Error(), "invalid stored verifier") {
		t.Fatalf("strict schema validation error = %v, want denied-marker rejection", err)
	}
}

func TestHashAPIAuthSecretsReportsDeniedLeafPaths11820(t *testing.T) {
	tree := parseAPIAuthSecretsTree10825(t,
		"set system services web-management api-auth user admin password tiny-basic",
		"set system services web-management api-auth api-key tiny-key-a",
		"set system services web-management api-auth api-key tiny-key-b",
		"set system services web-management api-auth key automation secret named-tiny",
		"set system services web-management api-auth user healthy password correct-horse-battery",
		"set groups g-auth system services web-management api-auth user group-user password group-tiny",
	)

	changed, paths, err := HashAPIAuthSecretsWithInvalidPaths(tree)
	if err != nil || !changed {
		t.Fatalf("HashAPIAuthSecretsWithInvalidPaths = (%v, %v, %v), want changes without error", changed, paths, err)
	}
	wantPaths := []string{
		`system services web-management api-auth user "admin" password`,
		"system services web-management api-auth api-key",
		`system services web-management api-auth key "automation" secret`,
		`groups "g-auth" system services web-management api-auth user "group-user" password`,
	}
	if len(paths) != len(wantPaths) {
		t.Fatalf("denied credential paths = %v, want one entry per distinct leaf %v", paths, wantPaths)
	}
	for _, want := range wantPaths {
		found := false
		for _, path := range paths {
			if path == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("denied credential paths %v do not contain %q", paths, want)
		}
	}
	for _, secret := range []string{"tiny-basic", "tiny-key-a", "tiny-key-b", "named-tiny", "group-tiny"} {
		for _, path := range paths {
			if strings.Contains(path, secret) {
				t.Errorf("credential path %q contains secret value %q", path, secret)
			}
		}
	}
	if strings.Contains(strings.Join(paths, "\n"), "$xpf-invalid$") {
		t.Fatalf("denied credential paths contain a verifier marker: %v", paths)
	}

	changed, paths, err = HashAPIAuthSecretsWithInvalidPaths(tree)
	if err != nil || changed || len(paths) != 0 {
		t.Fatalf("rehashing stored verifiers = (%v, %v, %v), want no change and no paths", changed, paths, err)
	}
}

func TestHashAPIAuthSecretsDoesNotLaunderTaggedVerifier10825(t *testing.T) {
	for _, tc := range []struct {
		name      string
		value     string
		wantError string
	}{
		{name: "corrupt bcrypt tag", value: apiAuthBcryptPrefix + "not-a-bcrypt-verifier", wantError: "malformed stored verifier"},
		{name: "malformed bcrypt body", value: apiAuthBcryptPrefix + "$2a$10$" + strings.Repeat("!", 53), wantError: "malformed stored verifier"},
		{name: "invalid verifier tag", value: apiAuthInvalidBcryptPrefix + "not-a-bcrypt-verifier", wantError: "invalid stored verifier"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseAPIAuthSecretsConfig10825(t,
				"system { services { web-management { api-auth { user admin { password "+
					strconv.Quote(tc.value)+"; } } } } }")
			before := tree.Format()
			if !HasMalformedAPIAuthSecretTag(tree) {
				t.Fatal("malformed or invalid API-auth verifier tag was not detected")
			}
			changed, err := HashAPIAuthSecrets(tree)
			if err == nil || !strings.Contains(err.Error(), "malformed reserved verifier tag") {
				t.Fatalf("HashAPIAuthSecrets error = %v, want malformed reserved verifier rejection", err)
			}
			if changed || tree.Format() != before {
				t.Fatalf("tagged verifier was rewritten (changed=%v):\n%s", changed, tree.Format())
			}
			if VerifyAPIAuthSecret(tc.value, "not-a-bcrypt-verifier") {
				t.Fatal("malformed or invalid tagged verifier unexpectedly verified")
			}
			if err := SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("strict schema validation error = %v, want distinct %q diagnosis", err, tc.wantError)
			}
		})
	}
}

func TestAPIAuthStrictSchemaValidationRunsCredentialValidators10825(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{
			name: "short Basic password",
			text: `system { services { web-management { api-auth { user admin { password "short"; } } } } }`,
			want: "at least 12 characters",
		},
		{
			name: "short repeated API key",
			text: `system { services { web-management { api-auth { api-key "short"; } } } }`,
			want: "at least 16 characters",
		},
		{
			name: "short named API key",
			text: `system { services { web-management { api-auth { key automation { secret "short"; } } } } }`,
			want: "at least 16 characters",
		},
		{
			name: "invalid expiry",
			text: `system { services { web-management { api-auth { expires 2099-99-99; } } } }`,
			want: "UTC date in YYYY-MM-DD form",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseAPIAuthSecretsConfig10825(t, tc.text)
			err := SchemaValidate(tree, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SchemaValidate error = %v, want %q", err, tc.want)
			}
		})
	}

	valid := parseAPIAuthSecretsConfig10825(t, `system { services { web-management { api-auth {
		expires 2099-01-01;
		user admin { password "correct-horse-battery"; }
		api-key "machine-generated-key-alpha";
		key automation { secret "automation-key-secret-012345"; }
	} } } }`)
	if err := SchemaValidate(valid, nil); err != nil {
		t.Fatalf("SchemaValidate rejected API-auth credentials at their minimum lengths: %v", err)
	}
}
func TestHasMalformedAPIAuthSecretTagUsesExactGroupScope10825(t *testing.T) {
	malformed := parseAPIAuthSecretsTree10825(t,
		"set groups g-auth system services web-management api-auth user admin password "+
			strconv.Quote(apiAuthInvalidBcryptPrefix+"bad"))
	before := malformed.Format()
	if !HasMalformedAPIAuthSecretTag(malformed) {
		t.Fatal("malformed verifier in a group-defined API-auth slot was not detected")
	}
	if malformed.Format() != before {
		t.Fatal("malformed-tag detection mutated the input tree")
	}

	if _, err := HashAPIAuthSecrets(malformed); err == nil ||
		!strings.Contains(err.Error(), "malformed reserved verifier tag") {
		t.Fatalf("HashAPIAuthSecrets error for group malformed tag = %v, want rejection", err)
	}
	if malformed.Format() != before {
		t.Fatal("HashAPIAuthSecrets changed a tree containing a malformed group verifier")
	}

	unrelated := parseAPIAuthSecretsTree10825(t,
		"set groups api-auth system services dynamic-dns provider p password "+
			strconv.Quote(apiAuthBcryptPrefix+"not-a-verifier"))
	if HasMalformedAPIAuthSecretTag(unrelated) {
		t.Fatal("malformed-looking DDNS password under a group named api-auth was treated as an API-auth verifier")
	}

	rootUnrelated := parseAPIAuthSecretsTree10825(t,
		"set system services dynamic-dns provider api-auth password "+
			strconv.Quote(apiAuthBcryptPrefix+"not-a-verifier"))
	if HasMalformedAPIAuthSecretTag(rootUnrelated) {
		t.Fatal("malformed-looking root DDNS password for provider api-auth was treated as an API-auth verifier")
	}
}

func TestConfigTreesEquivalentForSyncAPIAuthMigration10825(t *testing.T) {
	base := []string{
		"set system host-name sync-equivalence-node",
		"set system services web-management api-auth user admin password correct-horse-battery",
		"set system services web-management api-auth api-key machine-generated-key-alpha",
		"set system services web-management api-auth api-key machine-generated-key-bravo",
		"set system services web-management api-auth key automation secret automation-key-secret-alpha",
	}
	active := parseAPIAuthSecretsTree10825(t, base...)
	incoming := parseAPIAuthSecretsTree10825(t, base...)
	changed, err := HashAPIAuthSecrets(active)
	if err != nil || !changed {
		t.Fatalf("hash active source tree: changed=%v err=%v", changed, err)
	}
	activeBefore, incomingBefore := active.Format(), incoming.Format()
	if !ConfigTreesEquivalentForSync(active, incoming) {
		t.Fatal("stored bcrypt credentials and their matching incoming cleartexts should be sync-equivalent")
	}
	if active.Format() != activeBefore || incoming.Format() != incomingBefore {
		t.Fatal("sync equivalence mutated one of its source trees")
	}

	changedCredential := append([]string(nil), base...)
	changedCredential[3] = "set system services web-management api-auth api-key machine-generated-key-changed"
	if ConfigTreesEquivalentForSync(active, parseAPIAuthSecretsTree10825(t, changedCredential...)) {
		t.Fatal("changed API-auth credential was considered sync-equivalent")
	}

	changedNoncredential := append([]string(nil), base...)
	changedNoncredential[0] = "set system host-name different-node"
	if ConfigTreesEquivalentForSync(active, parseAPIAuthSecretsTree10825(t, changedNoncredential...)) {
		t.Fatal("noncredential difference was considered sync-equivalent")
	}
}

func TestConfigTreesEquivalentForSyncHandlesPackedAPIKeyValues10825(t *testing.T) {
	packedTree := func(values ...string) *ConfigTree {
		keys := []string{"system", "services", "web-management", "api-auth", "api-key"}
		keys = append(keys, values...)
		return &ConfigTree{Children: []*Node{{Keys: keys, IsLeaf: true}}}
	}
	const (
		keyA = "machine-generated-key-alpha"
		keyB = "machine-generated-key-bravo"
	)
	active := packedTree(keyA, keyB)
	incoming := packedTree(keyA, keyB)
	changed, err := HashAPIAuthSecrets(active)
	if err != nil || !changed {
		t.Fatalf("hash packed API-key values: changed=%v err=%v", changed, err)
	}
	if !VerifyAPIAuthSecret(active.Children[0].Keys[6], keyB) {
		t.Fatal("HashAPIAuthSecrets did not hash the packed API-key suffix")
	}
	if !ConfigTreesEquivalentForSync(active, incoming) {
		t.Fatal("packed API-key cleartexts did not match their active tagged verifiers")
	}
}

func TestConfigTreesEquivalentForSyncUsesExactGroupScope10825(t *testing.T) {
	groupCommands := []string{
		"set groups g-auth system services web-management api-auth user admin password grouped-api-password",
		"set apply-groups g-auth",
	}
	active := parseAPIAuthSecretsTree10825(t, groupCommands...)
	incoming := parseAPIAuthSecretsTree10825(t, groupCommands...)
	changed, err := HashAPIAuthSecrets(active)
	if err != nil || !changed {
		t.Fatalf("hash group-scoped active credentials: changed=%v err=%v", changed, err)
	}
	if !ConfigTreesEquivalentForSync(active, incoming) {
		t.Fatal("group-scoped API-auth cleartext did not match its stored active verifier")
	}

	unrelatedActive := parseAPIAuthSecretsTree10825(t,
		"set groups api-auth system services dynamic-dns provider p password ddns-password-active")
	unrelatedIncoming := parseAPIAuthSecretsTree10825(t,
		"set groups api-auth system services dynamic-dns provider p password ddns-password-changed")
	if _, err := HashAPIAuthSecrets(unrelatedActive); err != nil {
		t.Fatalf("HashAPIAuthSecrets for unrelated group content: %v", err)
	}
	if ConfigTreesEquivalentForSync(unrelatedActive, unrelatedIncoming) {
		t.Fatal("DDNS password below a group named api-auth was treated as an API-auth credential")
	}
}

func TestHashAPIAuthSecretUsesReviewedCost11492(t *testing.T) {
	const password = "a sufficiently long authentication secret"

	encoded, err := HashAPIAuthSecret(password)
	if err != nil {
		t.Fatalf("HashAPIAuthSecret: %v", err)
	}
	if !IsAPIAuthSecretHash(encoded) || !VerifyAPIAuthSecret(encoded, password) {
		t.Fatal("newly hashed API-auth secret is not a usable tagged verifier")
	}
	cost, err := bcrypt.Cost([]byte(strings.TrimPrefix(encoded, apiAuthBcryptPrefix)))
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if cost != 12 {
		t.Fatalf("new API-auth bcrypt cost = %d, want reviewed cost 12", cost)
	}
}

func TestHashAPIAuthSecretPreservesExistingCost10Verifier11492(t *testing.T) {
	const password = "previously stored authentication secret"
	prehash := sha256.Sum256([]byte(password))
	legacy, err := bcrypt.GenerateFromPassword(prehash[:], 10)
	if err != nil {
		t.Fatalf("generate legacy cost-10 verifier: %v", err)
	}
	stored := apiAuthBcryptPrefix + string(legacy)

	got, err := HashAPIAuthSecret(stored)
	if err != nil {
		t.Fatalf("HashAPIAuthSecret(existing verifier): %v", err)
	}
	if got != stored {
		t.Fatal("existing cost-10 verifier changed without its cleartext secret")
	}
	if !VerifyAPIAuthSecret(got, password) {
		t.Fatal("existing cost-10 verifier is no longer usable")
	}
	cost, err := bcrypt.Cost([]byte(strings.TrimPrefix(got, apiAuthBcryptPrefix)))
	if err != nil || cost != 10 {
		t.Fatalf("existing verifier cost = %d, err = %v; want preserved cost 10", cost, err)
	}
}
