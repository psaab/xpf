package eventengine

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/rpm"
)

// plantClassField9984 keeps the RED cells buildable against the pre-#9984
// configuration type. The field must become a real typed field in the fix;
// silently keeping it absent is exactly the persistence bug under test.
func plantClassField9984(t *testing.T, pol *config.EventPolicy, value string) {
	t.Helper()
	v := reflect.ValueOf(pol).Elem()
	field := v.FieldByName("PlantClass")
	if !field.IsValid() || field.Kind() != reflect.String {
		t.Fatalf("EventPolicy.PlantClass is missing; payload attribution cannot survive persistence")
	}
	field.SetString(value)
}

func event9984(name string) rpm.Event {
	return rpm.Event{Name: name, TestOwner: "owner", TestName: "test"}
}

func wait9984(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func statsField9984(t *testing.T, stats Stats, name string) uint64 {
	t.Helper()
	v := reflect.ValueOf(stats)
	field := v.FieldByName(name)
	if !field.IsValid() || field.Kind() != reflect.Uint64 {
		t.Fatalf("Stats.%s is missing; the quarantine fault is not observable", name)
	}
	return field.Uint()
}

func applyWithConfig9984(t *testing.T, e *Engine, policies []*config.EventPolicy, cfg *config.Config) {
	t.Helper()
	method := reflect.ValueOf(e).MethodByName("ApplyWithConfig")
	if !method.IsValid() {
		t.Fatal("Engine.ApplyWithConfig is missing; fire-time authorization has no config snapshot")
	}
	method.Call([]reflect.Value{reflect.ValueOf(policies), reflect.ValueOf(cfg)})
}

func restrictedConfigSource9984(deny string) string {
	return strings.TrimSpace(`
system {
    host-name base;
    login {
        class planter {
            permissions [ configure view ];
            deny-configuration "` + deny + `";
        }
    }
}
`)
}

func restrictedConfig9984(t *testing.T, deny string) *config.Config {
	t.Helper()
	tree, errs := config.NewParser(restrictedConfigSource9984(deny)).Parse()
	if len(errs) != 0 {
		t.Fatalf("restricted class fixture parse failed: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("restricted class fixture compile failed: %v", err)
	}
	return cfg
}
func installRestrictedConfig9984(t *testing.T, s *configstore.Store, deny string) *config.Config {
	t.Helper()
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("enter restricted fixture config: %v", err)
	}
	defer s.ExitConfigure()
	if err := s.LoadOverrideAsPlantClass("", config.EventPlantClassSuperuser, restrictedConfigSource9984(deny)); err != nil {
		t.Fatalf("load restricted fixture config: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit restricted fixture config: %v", err)
	}
	cfg := restrictedConfig9984(t, deny)
	if _, ok := config.ResolveClassPermissions(cfg, "planter"); !ok {
		t.Fatal("restricted fixture did not resolve planter")
	}
	if !config.ClassHasPermission(cfg, "planter", config.PermConfig) {
		t.Fatal("restricted fixture planter lacks configure permission")
	}
	return cfg
}

func permissiveConfigSource9984() string {
	return strings.TrimSpace(`
system {
    host-name base;
    login {
        class planter {
            permissions [ configure view ];
        }
    }
}`)
}

func compiledConfigSource9984(t *testing.T, source string) *config.Config {
	t.Helper()
	tree, errs := config.NewParser(source).Parse()
	if len(errs) != 0 {
		t.Fatalf("config fixture parse failed: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("config fixture compile failed: %v", err)
	}
	return cfg
}

func installConfigSource9984(t *testing.T, s *configstore.Store, source string) *config.Config {
	t.Helper()
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("enter config fixture: %v", err)
	}
	defer s.ExitConfigure()
	if err := s.LoadOverrideAsPlantClass("", config.EventPlantClassSuperuser, source); err != nil {
		t.Fatalf("load config fixture: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit config fixture: %v", err)
	}
	return compiledConfigSource9984(t, source)
}

func aliceConfigSource9984() string {
	return strings.TrimSpace(`
system {
    host-name base;
    login {
        class alice {
            permissions [ configure view ];
        }
    }
}`)
}

func eventPolicyFromConfig9984(t *testing.T, cfg *config.Config, name string) *config.EventPolicy {
	t.Helper()
	for _, pol := range cfg.EventOptions {
		if pol != nil && pol.Name == name {
			return pol
		}
	}
	t.Fatalf("config has no event policy %q", name)
	return nil
}

// This is the end-to-end positive control: a flat-set policy is stamped,
// committed, reloaded, and then fires under Alice's snapshot. The later
// forged-marker and marker-delete phases prove the same persisted policy never
// turns into root execution.
func TestFlatStoreSeedCommitReloadFiresAsAlice9984(t *testing.T) {
	s := newStore(t)
	installConfigSource9984(t, s, aliceConfigSource9984())
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure for flat seed: %v", err)
	}
	for _, input := range []string{
		`event-options policy p events ping_test_failed`,
		`event-options policy p then change-configuration commands "set system host-name alice-fired"`,
	} {
		if err := s.SetFromInputAsPlantClass("", "alice", input); err != nil {
			t.Fatalf("flat Alice set %q: %v", input, err)
		}
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("flat Alice commit: %v", err)
	}
	s.ExitConfigure()
	if err := s.Load(); err != nil {
		t.Fatalf("flat Alice reload: %v", err)
	}
	cfg := s.ActiveConfig()
	pol := eventPolicyFromConfig9984(t, cfg, "p")
	if pol.PlantClass != "alice" {
		t.Fatalf("reloaded flat seed PlantClass=%q, want alice", pol.PlantClass)
	}
	e := New(s, nil)
	applyWithConfig9984(t, e, cfg.EventOptions, cfg)
	e.HandleEvent(event9984("ping_test_failed"))
	wait9984(t, "Alice flat remediation", func() bool { return e.Stats().Committed >= 1 })
	if got := s.ActiveConfig().System.HostName; got != "alice-fired" {
		t.Fatalf("Alice flat remediation did not fire; host-name=%q", got)
	}
	e.Close()

	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure for forged marker: %v", err)
	}
	if err := s.SetFromInputAsPlantClass("", "mallory", `event-options policy p plant-class super-user`); err != nil {
		t.Fatalf("flat forged marker: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("forged marker commit: %v", err)
	}
	s.ExitConfigure()
	if err := s.Load(); err != nil {
		t.Fatalf("forged marker reload: %v", err)
	}
	cfg = s.ActiveConfig()
	pol = eventPolicyFromConfig9984(t, cfg, "p")
	if pol.PlantClass != "mallory" {
		t.Fatalf("forged marker reloaded PlantClass=%q, want mallory", pol.PlantClass)
	}
	e = New(s, nil)
	applyWithConfig9984(t, e, cfg.EventOptions, cfg)
	e.HandleEvent(event9984("ping_test_failed"))
	wait9984(t, "forged marker rejection", func() bool { return e.Stats().Rejected >= 1 })
	if got := s.ActiveConfig().System.HostName; got != "alice-fired" {
		t.Fatalf("forged marker fired as root; host-name=%q", got)
	}
	e.Close()

	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure for marker delete: %v", err)
	}
	if err := s.DeleteFromInputAsPlantClass("", "mallory", `event-options policy p plant-class`); err != nil {
		t.Fatalf("flat marker delete: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("marker delete commit: %v", err)
	}
	s.ExitConfigure()
	if err := s.Load(); err != nil {
		t.Fatalf("marker delete reload: %v", err)
	}
	cfg = s.ActiveConfig()
	pol = eventPolicyFromConfig9984(t, cfg, "p")
	if pol.PlantClass != "" {
		t.Fatalf("deleted marker reloaded PlantClass=%q, want empty quarantine marker", pol.PlantClass)
	}
	e = New(s, nil)
	applyWithConfig9984(t, e, cfg.EventOptions, cfg)
	e.HandleEvent(event9984("ping_test_failed"))
	wait9984(t, "deleted marker fire rejection", func() bool { return e.Stats().Rejected >= 1 })
	if got := s.ActiveConfig().System.HostName; got != "alice-fired" {
		t.Fatalf("deleted marker fired under root authority; host-name=%q", got)
	}
	e.Close()
}

// ApplyWithConfig's snapshot is the authorization source at fire time. The
// active store config deliberately permits this target while the supplied
// snapshot denies it. An implementation that consults Store.ActiveConfig()
// instead of the snapshot would mutate the host name and fail this cell.
func TestApplyWithConfigSnapshotDenialOverridesActiveAllow9984(t *testing.T) {
	s := newStore(t)
	installConfigSource9984(t, s, permissiveConfigSource9984())
	snapshot := restrictedConfig9984(t, `^system host-name`)
	pol := &config.EventPolicy{
		Name:         "snapshot-denial",
		PlantClass:   "planter",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name must-not-fire"},
	}
	e := New(s, nil)
	defer e.Close()
	applyWithConfig9984(t, e, []*config.EventPolicy{pol}, snapshot)
	e.HandleEvent(event9984("ping_test_failed"))
	wait9984(t, "snapshot denial", func() bool { return e.Stats().Rejected >= 1 })
	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Fatalf("snapshot denial allowed host-name mutation to %q", got)
	}
}

// The reverse distinguishes snapshot authority in the other direction:
// Store.ActiveConfig() denies the target, but ApplyWithConfig's snapshot
// permits it. The event must fire using the supplied snapshot.
func TestApplyWithConfigSnapshotAllowOverridesActiveDeny9984(t *testing.T) {
	s := newStore(t)
	installConfigSource9984(t, s, restrictedConfigSource9984(`^system host-name`))
	snapshot := compiledConfigSource9984(t, permissiveConfigSource9984())
	pol := &config.EventPolicy{
		Name:         "snapshot-allow",
		PlantClass:   "planter",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name snapshot-fired"},
	}
	e := New(s, nil)
	defer e.Close()
	applyWithConfig9984(t, e, []*config.EventPolicy{pol}, snapshot)
	e.HandleEvent(event9984("ping_test_failed"))
	wait9984(t, "snapshot allow commit", func() bool { return e.Stats().Committed >= 1 })
	if got := s.ActiveConfig().System.HostName; got != "snapshot-fired" {
		t.Fatalf("snapshot allow did not fire; host-name=%q", got)
	}
}

func deletedClassSnapshotSource9984() string {
	return strings.TrimSpace(`
system {
    host-name base;
    login {
        class other {
            permissions [ configure view ];
        }
    }
}`)
}

func groupedPlanterConfigSource9984() string {
	return strings.TrimSpace(`
groups {
    planter-login {
        system {
            login {
                class planter {
                    permissions [ configure view ];
                }
            }
        }
    }
}
apply-groups planter-login;
system {
    host-name base;
}`)
}

func TestUnknownPlantingClassSnapshotIsQuarantined9984(t *testing.T) {
	s := newStore(t)
	installConfigSource9984(t, s, permissiveConfigSource9984())
	snapshot := compiledConfigSource9984(t, deletedClassSnapshotSource9984())
	pol := &config.EventPolicy{
		Name:         "deleted-class",
		PlantClass:   "planter",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name deleted-class-fired"},
	}
	e := New(s, nil)
	defer e.Close()
	applyWithConfig9984(t, e, []*config.EventPolicy{pol}, snapshot)
	e.HandleEvent(event9984("ping_test_failed"))
	wait9984(t, "deleted class rejection", func() bool { return e.Stats().Rejected >= 1 })
	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Fatalf("unknown/deleted class mutated host-name to %q", got)
	}
}

func TestNilSnapshotNonSuperuserIsQuarantined9984(t *testing.T) {
	s := newStore(t)
	installConfigSource9984(t, s, permissiveConfigSource9984())
	pol := &config.EventPolicy{
		Name:         "nil-snapshot",
		PlantClass:   "planter",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name nil-snapshot-fired"},
	}
	e := New(s, nil)
	defer e.Close()
	applyWithConfig9984(t, e, []*config.EventPolicy{pol}, nil)
	e.HandleEvent(event9984("ping_test_failed"))
	wait9984(t, "nil snapshot rejection", func() bool { return e.Stats().Rejected >= 1 })
	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Fatalf("nil snapshot non-superuser mutated host-name to %q", got)
	}
}

func TestGroupDerivedPlantingClassCanFire9984(t *testing.T) {
	s := newStore(t)
	snapshot := installConfigSource9984(t, s, groupedPlanterConfigSource9984())
	if _, ok := config.ResolveClassPermissions(snapshot, "planter"); !ok {
		t.Fatal("group-derived snapshot did not resolve planter")
	}
	pol := &config.EventPolicy{
		Name:         "grouped-class",
		PlantClass:   "planter",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name grouped-class-fired"},
	}
	e := New(s, nil)
	defer e.Close()
	applyWithConfig9984(t, e, []*config.EventPolicy{pol}, snapshot)
	e.HandleEvent(event9984("ping_test_failed"))
	wait9984(t, "group-derived class commit", func() bool { return e.Stats().Committed >= 1 })
	if got := s.ActiveConfig().System.HostName; got != "grouped-class-fired" {
		t.Fatalf("group-derived class did not fire; host-name=%q", got)
	}
}

func TestDeletingPlantClassLeavesRemediationQuarantined9984(t *testing.T) {
	const source = `event-options {
    policy p {
        events ping_test_failed;
        plant-class alice;
        then { change-configuration { commands "set system host-name deleted-marker"; } }
    }
}`
	before, errs := config.NewParser(source).Parse()
	if len(errs) != 0 {
		t.Fatalf("marker fixture parse failed: %v", errs)
	}
	after := before.Clone()
	if err := after.DeletePath([]string{"event-options", "policy", "p", "plant-class"}); err != nil {
		t.Fatalf("delete plant-class: %v", err)
	}
	config.StampChangedEventPlantClasses(before, after, "mallory")
	cfg, err := config.CompileConfigLenient(after)
	if err != nil {
		t.Fatalf("compile marker-deleted policy: %v", err)
	}
	if len(cfg.EventOptions) != 1 || cfg.EventOptions[0].PlantClass != "" {
		t.Fatalf("deleted marker compiled as %+v, want empty quarantine metadata", cfg.EventOptions)
	}
	s := newStore(t)
	e := New(s, nil)
	defer e.Close()
	applyWithConfig9984(t, e, cfg.EventOptions, nil)
	e.HandleEvent(event9984("ping_test_failed"))
	wait9984(t, "deleted marker rejection", func() bool { return e.Stats().Rejected >= 1 })
	if got := s.ActiveConfig().System.HostName; got == "deleted-marker" {
		t.Fatal("remediation with deleted plant-class fired under root authority")
	}
}

// A payload persisted before #9984 has no planter to re-adjudicate. It must be
// quarantined at fire time rather than applied under the event daemon's root
// authority. Before the fix this commits the host-name change and this cell is
// RED; the policy has no class metadata by construction.
func TestLegacyPayloadWithoutPlantClassIsQuarantined9984(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{PlantClass: config.EventPlantClassSuperuser, Name: "legacy",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name legacy-fired"}}
	plantClassField9984(t, pol, "")
	e := New(s, nil)
	defer e.Close()
	applyWithConfig9984(t, e, []*config.EventPolicy{pol}, nil)
	e.HandleEvent(event9984("ping_test_failed"))
	wait9984(t, "legacy rejection", func() bool { return e.Stats().Rejected >= 1 })
	if got := statsField9984(t, e.Stats(), "PlantClassInvalid"); got == 0 {
		t.Fatal("legacy refusal did not expose a planting-class fault")
	}
	if got := s.ActiveConfig().System.HostName; got == "legacy-fired" {
		t.Fatal("legacy payload without planting class fired as root; #9984 requires quarantine")
	}
}

// A newly stamped payload remains executable when its recorded class is valid.
// This positive control prevents the migration guard from refusing every
// event-options remediation and demonstrates that the class-bearing shape is
// usable. It also fails RED before the PlantClass field exists.
func TestPayloadWithPlantClassStillFires9984(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{PlantClass: config.EventPlantClassSuperuser, Name: "new",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name new-fired"}}
	plantClassField9984(t, pol, "super-user")
	e := New(s, nil)
	defer e.Close()
	applyWithConfig9984(t, e, []*config.EventPolicy{pol}, nil)
	e.HandleEvent(event9984("ping_test_failed"))
	wait9984(t, "class-bearing commit", func() bool { return e.Stats().Committed >= 1 })
	if got := s.ActiveConfig().System.HostName; got != "new-fired" {
		t.Fatalf("class-bearing payload did not fire: host-name=%q", got)
	}
}

// The planting class is config data, not runtime-only state. A compiler and
// persistence implementation that drops the field cannot pass this cell.
func TestPlantClassCompilesAndSurvivesSetRender9984(t *testing.T) {
	tree, errs := config.NewParser(strings.TrimSpace(`
event-options {
    policy stamped {
        events ping_test_failed;
        plant-class super-user;
        then { change-configuration { commands "set system host-name stamped"; } }
    }
}`)).Parse()
	if len(errs) != 0 {
		t.Fatalf("plant-class fixture parse failed: %v", errs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("plant-class fixture compile failed: %v", err)
	}
	if len(cfg.EventOptions) != 1 {
		t.Fatalf("compiled event-options policies=%d, want 1", len(cfg.EventOptions))
	}
	v := reflect.ValueOf(cfg.EventOptions[0]).Elem().FieldByName("PlantClass")
	if !v.IsValid() || v.String() != "super-user" {
		t.Fatalf("compiled PlantClass=%v, want super-user", v)
	}
	if got := tree.FormatSet(); !strings.Contains(got, "plant-class super-user") {
		t.Fatalf("set render dropped plant-class: %q", got)
	}
}

func TestRestrictedPlantClassRefusesSetBeforeMutation9984(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{PlantClass: config.EventPlantClassSuperuser, Name: "restricted-set",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name denied-set"}}
	plantClassField9984(t, pol, "planter")
	e := New(s, nil)
	defer e.Close()
	cfg := installRestrictedConfig9984(t, s, `^system host-name`)
	applyWithConfig9984(t, e, []*config.EventPolicy{pol}, cfg)
	e.HandleEvent(event9984("ping_test_failed"))
	wait9984(t, "restricted set rejection", func() bool { return e.Stats().Rejected >= 1 })
	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Fatalf("denied set mutated host-name to %q", got)
	}
}

func TestRestrictedPlantClassRefusesDeleteBeforeMutation9984(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{PlantClass: config.EventPlantClassSuperuser, Name: "restricted-delete",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"delete system host-name"}}
	plantClassField9984(t, pol, "planter")
	e := New(s, nil)
	defer e.Close()
	cfg := installRestrictedConfig9984(t, s, `^system host-name`)
	applyWithConfig9984(t, e, []*config.EventPolicy{pol}, cfg)
	e.HandleEvent(event9984("ping_test_failed"))
	wait9984(t, "restricted delete rejection", func() bool { return e.Stats().Rejected >= 1 })
	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Fatalf("denied delete mutated host-name to %q", got)
	}
}

func TestRestrictedPlantClassRejectsMixedBatchBeforeMutation9984(t *testing.T) {
	s := newStore(t)
	cfg := installRestrictedConfig9984(t, s, `^system domain-name`)
	pol := &config.EventPolicy{
		Name:         "restricted-mixed",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name changed-first", "set system domain-name changed-second"},
	}
	plantClassField9984(t, pol, "planter")
	commitCalls := 0
	e := New(s, func(_ context.Context, _ string) (*config.Config, error) {
		commitCalls++
		return s.ActiveConfig(), nil
	})
	defer e.Close()
	applyWithConfig9984(t, e, []*config.EventPolicy{pol}, cfg)
	e.HandleEvent(event9984("ping_test_failed"))
	wait9984(t, "mixed-batch rejection", func() bool { return e.Stats().Rejected >= 1 })
	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Fatalf("allowed first op mutated active host-name to %q", got)
	}
	if got := s.ActiveConfig().System.DomainName; got != "" {
		t.Fatalf("denied second op mutated active domain-name to %q", got)
	}
	if commitCalls != 0 {
		t.Fatalf("commit callback called %d times after pre-mutation denial", commitCalls)
	}
}
