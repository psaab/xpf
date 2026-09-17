// #9943: a DHCP-learned classless route (option 121 / legacy 249) covered by
// a RENDERED static route in the same VRF must not be emitted — longest-prefix
// match would otherwise let an untrusted DHCP server override operator statics
// (a 0.0.0.0/1 + 128.0.0.0/1 pair beats a static 0.0.0.0/0 at any admin
// distance), defeating the documented "DHCP-learned routes are lower priority
// than static routes" contract. Suppression is containment, not mere overlap: a
// learned route covering a static (less-specific) still installs, since it
// overrides nothing and suppressing it would blackhole the uncovered space.
// XPF_DHCP_TRUST_CLASSLESS_OVERRIDE=1 restores the pre-#9943 learned-wins
// behavior for operators who need it.
//
// RED-on-revert: drop the classless arm of the suppression and the
// "suppressed" cells below render the rogue routes again.
package frr

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func renderDHCP9943(t *testing.T, fc *FullConfig) string {
	t.Helper()
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "")
	var b strings.Builder
	renderDHCPDefaults(&b, fc)
	return b.String()
}

func static9943(dst string) *config.StaticRoute {
	return &config.StaticRoute{
		Destination: dst,
		NextHops:    []config.NextHopEntry{{Address: "172.16.50.1"}},
	}
}

// The filed attack: a rogue option-121 /1 pair must lose to a configured
// static default. A covered legitimate route (10.20.0.0/16) is suppressed
// alongside — containment cannot distinguish rogue from legitimate, only
// covered from uncovered.
func TestDHCPClasslessCoveredByStaticDefaultIsSuppressed_9943(t *testing.T) {
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{static9943("0.0.0.0/0")},
		DHCPRoutes: []DHCPRoute{
			{Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
			{Destination: "0.0.0.0/1", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
			{Destination: "128.0.0.0/1", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
			{Destination: "10.20.0.0/16", Gateway: "192.0.2.9", Interface: "ge-0-0-3"},
		},
	}
	got := renderDHCP9943(t, fc)
	for _, wantAbsent := range []string{
		"ip route 0.0.0.0/0 192.0.2.1",
		"ip route 0.0.0.0/1 192.0.2.1",
		"ip route 128.0.0.0/1 192.0.2.1",
		"ip route 10.20.0.0/16 192.0.2.9",
	} {
		if strings.Contains(got, wantAbsent) {
			t.Errorf("covered DHCP-learned route %q rendered; must be suppressed:\n%s", wantAbsent, got)
		}
	}
	if got != "" {
		t.Errorf("all routes in this fixture are covered and must be suppressed:\n%s", got)
	}
}

// A learned /9 over a static /8 is the same override at a narrower scope and
// must be suppressed; an equal-prefix learned route ties on longest-match and
// would lose on distance anyway, so it is suppressed too. An uncovered route
// (192.168.0.0/16) must still install — the #4118 legitimate core survives.
func TestDHCPClasslessCoveredByStaticPrefixIsSuppressed_9943(t *testing.T) {
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{static9943("10.0.0.0/8")},
		DHCPRoutes: []DHCPRoute{
			{Destination: "10.0.0.0/9", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
			{Destination: "10.128.0.0/9", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
			{Destination: "10.0.0.0/8", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
			{Destination: "192.168.0.0/16", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
		},
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	got := renderDHCP9943(t, fc)
	for _, wantAbsent := range []string{
		"ip route 10.0.0.0/9 ",
		"ip route 10.128.0.0/9 ",
		"ip route 10.0.0.0/8 192.0.2.1",
	} {
		if strings.Contains(got, wantAbsent) {
			t.Errorf("covered DHCP-learned route %q rendered; must be suppressed:\n%s", wantAbsent, got)
		}
	}
	if !strings.Contains(got, "ip route 192.168.0.0/16 192.0.2.1 ge-0-0-3 200\n") {
		t.Errorf("uncovered classless route missing (must still install):\n%s", got)
	}
	if !strings.Contains(logs.String(), "suppressing DHCP classless route covered by") ||
		!strings.Contains(logs.String(), "static_destination=10.0.0.0/8") {
		t.Fatalf("FRR suppression WARN missing covering static destination: %s", logs.String())
	}
}

// Direction pin: a learned route COVERING a static (less-specific) overrides
// nothing — the static still wins its scope by longest-match — and suppressing
// it would blackhole the rest of its space. It must install.
func TestDHCPClasslessCoveringStaticStillInstalls_9943(t *testing.T) {
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{static9943("10.20.0.0/16")},
		DHCPRoutes: []DHCPRoute{
			{Destination: "10.0.0.0/8", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
		},
	}
	if got := renderDHCP9943(t, fc); !strings.Contains(got, "ip route 10.0.0.0/8 192.0.2.1 ge-0-0-3 200\n") {
		t.Errorf("learned route covering (not covered by) a static must install:\n%s", got)
	}
}

// Suppression is per-VRF (#8963): a static default in one table says nothing
// about a learned route in another.
func TestDHCPClasslessSuppressionIsPerVRF_9943(t *testing.T) {
	fc := &FullConfig{
		Instances: []InstanceConfig{{
			Name:         "tenant",
			VRFName:      "vrf-tenant",
			StaticRoutes: []*config.StaticRoute{static9943("0.0.0.0/0")},
		}},
		DHCPRoutes: []DHCPRoute{
			{Destination: "10.20.0.0/16", Gateway: "192.0.2.9", Interface: "ge-0-0-1", VRF: "tenant"},
			{Destination: "10.20.0.0/16", Gateway: "192.0.2.9", Interface: "ge-0-0-2"},
		},
	}
	got := renderDHCP9943(t, fc)
	if strings.Contains(got, "10.20.0.0/16 192.0.2.9 ge-0-0-1") {
		t.Errorf("tenant-VRF classless route covered by the tenant static default rendered:\n%s", got)
	}
	if !strings.Contains(got, "ip route 10.20.0.0/16 192.0.2.9 ge-0-0-2 200\n") {
		t.Errorf("default-context classless route (no covering static there) missing:\n%s", got)
	}
}

// With no statics an ordinary, non-broad classless route still installs.
func TestDHCPClasslessWithoutStaticsInstalls_9943(t *testing.T) {
	fc := &FullConfig{
		DHCPRoutes: []DHCPRoute{
			{Destination: "10.0.0.0/8", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
			{Destination: "192.168.0.0/16", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
		},
	}
	got := renderDHCP9943(t, fc)
	if !strings.Contains(got, "ip route 10.0.0.0/8 192.0.2.1 ge-0-0-3 200\n") ||
		!strings.Contains(got, "ip route 192.168.0.0/16 192.0.2.1 ge-0-0-3 200\n") {
		t.Errorf("ordinary classless routes with no statics must install:\n%s", got)
	}
}

// A classless /1 is broad enough to replace the effective default and is
// refused even when no static route exists. The explicit trust knob is the
// only way to permit it.
func TestDHCPClasslessBroadPrefixRefused_9943(t *testing.T) {
	fc := &FullConfig{
		DHCPRoutes: []DHCPRoute{
			{Destination: "0.0.0.0/1", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
			{Destination: "128.0.0.0/1", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
		},
	}
	if got := renderDHCP9943(t, fc); got != "" {
		t.Fatalf("broad /1 classless routes must be refused by default:\n%s", got)
	}
}

func TestDHCPClasslessMartianPrefixRefused_9943(t *testing.T) {
	fc := &FullConfig{DHCPRoutes: []DHCPRoute{
		{Destination: "0.0.0.0/8", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
		{Destination: "127.0.0.0/8", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
		{Destination: "169.254.0.0/16", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
		{Destination: "224.0.0.0/4", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
		{Destination: "240.0.0.0/4", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
	}}
	if got := renderDHCP9943(t, fc); got != "" {
		t.Fatalf("martian classless routes must be refused by default:\n%s", got)
	}
}

// Only a static that actually RENDERS a FIB entry suppresses (#5519): a
// zero-next-hop, non-discard static default installs nothing, so it must not
// suppress an ordinary learned classless route.
func TestDHCPClasslessUnrenderableStaticDoesNotSuppress_9943(t *testing.T) {
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{{Destination: "0.0.0.0/0"}},
		DHCPRoutes: []DHCPRoute{
			{Destination: "10.0.0.0/8", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
		},
	}
	if got := renderDHCP9943(t, fc); !strings.Contains(got, "ip route 10.0.0.0/8 192.0.2.1 ge-0-0-3 200\n") {
		t.Errorf("unrenderable static must not suppress learned classless:\n%s", got)
	}
}

// A next-table static renders no FRR FIB line (it becomes an `ip rule`), so it
// covers nothing in the FRR table and suppresses nothing.
func TestDHCPClasslessNextTableStaticDoesNotSuppress_9943(t *testing.T) {
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{{Destination: "10.0.0.0/8", NextTable: "vr"}},
		DHCPRoutes: []DHCPRoute{
			{Destination: "10.20.0.0/16", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
		},
	}
	if got := renderDHCP9943(t, fc); !strings.Contains(got, "ip route 10.20.0.0/16 192.0.2.1 ge-0-0-3 200\n") {
		t.Errorf("next-table static must not suppress learned classless:\n%s", got)
	}
}

// The trust knob restores learned-wins for operators who need it, including
// the covered-prefix warning path.
func TestDHCPClasslessTrustKnobRestoresCovered_9943(t *testing.T) {
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "1")
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{static9943("10.0.0.0/8")},
		DHCPRoutes: []DHCPRoute{
			{Destination: "10.0.0.0/9", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
			{Destination: "10.128.0.0/9", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
		},
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	var b strings.Builder
	renderDHCPDefaults(&b, fc)
	got := b.String()
	logText := logs.String()
	for _, field := range []string{
		"level=WARN",
		"env=XPF_DHCP_TRUST_CLASSLESS_OVERRIDE",
		"destination=10.0.0.0/9",
		"destination=10.128.0.0/9",
		"static_destination=10.0.0.0/8",
	} {
		if !strings.Contains(logText, field) {
			t.Errorf("trust override warning missing %q: %s", field, logText)
		}
	}
	if got := strings.Count(logText, "msg=\"SECURITY: DHCP classless trust override allows a route covered"); got != 2 {
		t.Errorf("expected one covered-route WARN per trusted /9, got %d: %s", got, logText)
	}
	if !strings.Contains(got, "ip route 10.0.0.0/9 192.0.2.1 ge-0-0-3 200\n") ||
		!strings.Contains(got, "ip route 10.128.0.0/9 192.0.2.1 ge-0-0-3 200\n") {
		t.Errorf("trust knob set: covered classless routes must install:\n%s", got)
	}
}

func TestDHCPClasslessBroadTrustOverrideAllows_9943(t *testing.T) {
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "1")
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{static9943("0.0.0.0/0")},
		DHCPRoutes: []DHCPRoute{
			{Destination: "0.0.0.0/1", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
		},
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	var b strings.Builder
	renderDHCPDefaults(&b, fc)
	if !strings.Contains(b.String(), "ip route 0.0.0.0/1 192.0.2.1 ge-0-0-3 200\n") {
		t.Fatalf("trust override must permit the broad classless route:\n%s", b.String())
	}
	for _, field := range []string{
		"level=WARN",
		"env=XPF_DHCP_TRUST_CLASSLESS_OVERRIDE",
		"destination=0.0.0.0/1",
		"static_destination=0.0.0.0/0",
	} {
		if !strings.Contains(logs.String(), field) {
			t.Errorf("broad trust warning missing %q: %s", field, logs.String())
		}
	}
	if got := strings.Count(logs.String(), "msg=\"SECURITY: DHCP classless trust override allows an unsafe"); got != 1 {
		t.Errorf("expected one unsafe WARN for trusted broad route, got %d: %s", got, logs.String())
	}
	if got := strings.Count(logs.String(), "msg=\"SECURITY: DHCP classless trust override allows a route covered"); got != 1 {
		t.Errorf("expected covering-static WARN alongside unsafe WARN, got %d: %s", got, logs.String())
	}
}

func TestDHCPClasslessMartianTrustOverrideAllows_9943(t *testing.T) {
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "1")
	fc := &FullConfig{DHCPRoutes: []DHCPRoute{
		{Destination: "127.0.0.0/8", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
		{Destination: "169.254.0.0/16", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
		{Destination: "240.0.0.0/4", Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
	}}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	var b strings.Builder
	renderDHCPDefaults(&b, fc)
	got := b.String()
	logText := logs.String()
	for _, destination := range []string{"127.0.0.0/8", "169.254.0.0/16", "240.0.0.0/4"} {
		if !strings.Contains(got, "ip route "+destination+" 192.0.2.1 ge-0-0-3 200\n") ||
			!strings.Contains(logText, "destination="+destination) {
			t.Errorf("trust override did not install and warn for %s: routes=%s logs=%s", destination, got, logText)
		}
	}
	if count := strings.Count(logText, "msg=\"SECURITY: DHCP classless trust override allows an unsafe"); count != 3 {
		t.Errorf("expected one unsafe WARN per trusted martian route, got %d: %s", count, logText)
	}
}
