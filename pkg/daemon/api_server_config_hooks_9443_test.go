package daemon

import (
	"reflect"
	"testing"
)

// apiConfigInjectionSeams9443 are the api.Config func fields that are TEST
// injection seams, where nil selects the production default. The daemon leaves
// them unset on purpose. Every other func field is an observability or behaviour
// hook the daemon must wire.
var apiConfigInjectionSeams9443 = map[string]string{
	"ListenFunc":     "nil selects net.Listen (#5866)",
	"PeerLookupFn":   "nil selects pkg/authz's kernel peer lookup (#5278)",
	"PeerLocalityFn": "nil selects the fresh local-address enumeration",
}

// #9443: the daemon built api.Config inline in startHTTPServer, which no test
// calls, so the ASSIGNMENT of every hook was unbound. Deleting
// `SyslogDropsFn: d.syslogDropStats,` compiled and failed no test, although the
// hook's function and api.NewServer's field copy were both covered. This cell
// binds that link for every func field at once, so a hook added to api.Config
// and not wired here fails too.
func TestAPIServerConfigBindsEveryHook_9443(t *testing.T) {
	cfg := (&Daemon{}).apiServerConfig(nil)
	v := reflect.ValueOf(cfg)
	ty := v.Type()
	funcs := 0
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		if f.Type.Kind() != reflect.Func {
			continue
		}
		funcs++
		set := !v.Field(i).IsNil()
		reason, seam := apiConfigInjectionSeams9443[f.Name]
		switch {
		case seam && set:
			t.Errorf("#9443: api.Config.%s is listed as an injection seam (%s) but apiServerConfig now sets it; remove it from the seam list", f.Name, reason)
		case !seam && !set:
			t.Errorf("#9443: api.Config.%s is not assigned by apiServerConfig, so the hook is unbound; wire it there or, if nil is a deliberate production default, list it as a seam with its reason", f.Name)
		}
	}
	for name := range apiConfigInjectionSeams9443 {
		if _, ok := ty.FieldByName(name); !ok {
			t.Errorf("#9443: seam %s no longer exists on api.Config; remove it from the seam list", name)
		}
	}
	// Precondition: the walk must be looking at the real hook set. If the
	// reflection scope shrinks, this cell must not go green by checking nothing.
	if funcs < 40 {
		t.Fatalf("precondition: expected api.Config to carry dozens of func hooks, found %d", funcs)
	}
}
