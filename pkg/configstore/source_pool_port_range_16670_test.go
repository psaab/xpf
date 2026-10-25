package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const sourcePoolSet16670 = `set security zones security-zone trust
set security zones security-zone untrust
set security nat source rule-set RS from zone trust
set security nat source rule-set RS to zone untrust
set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24
set security nat source rule-set RS rule R1 then source-nat pool P
set security nat source pool P address 203.0.113.5/32
`

func TestSourcePoolPortStrictCommit16670(t *testing.T) {
	// Use the real strict entrypoint for the hierarchical comparison too.
	hier, err := CheckText(`security { nat { source { pool P {
		address 203.0.113.5/32; port { range 1024 to 2048; }
	} } } }`, -1)
	if err != nil {
		t.Fatalf("hierarchical CheckText: %v", err)
	}
	want := hier.Security.NAT.SourcePools["P"]
	if want == nil || want.PortLow != 1024 || want.PortHigh != 2048 {
		t.Fatalf("hierarchical pool: %+v", want)
	}

	for _, tc := range []struct {
		name, port string
		low, high  int
		random     bool
		preserve   bool
	}{
		{"junos", "range 1024 to 2048", want.PortLow, want.PortHigh, false, false},
		{"legacy", "range low 1024 high 2048", want.PortLow, want.PortHigh, false, false},
		{"single", "3000", 3000, 3000, false, false},
		{"boundaries", "range 1 to 65535", 1, 65535, false, false},
		{"modifier", "range 1024 to 2048 random-allocation", 1024, 2048, true, false},
		{"preserve", "no-translation", 0, 0, false, true},
	} {
		for _, loadSet := range []bool{false, true} {
			mode := "set"
			if loadSet {
				mode = "load-set"
			}
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				s := newTestStore(t)
				if err := s.EnterConfigure(); err != nil {
					t.Fatal(err)
				}
				text := sourcePoolSet16670 + "set security nat source pool P port " + tc.port + "\n"
				if loadSet {
					if _, err := s.LoadSet(text); err != nil {
						t.Fatalf("LoadSet: %v", err)
					}
				} else {
					for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
						if err := s.SetFromInput(strings.TrimPrefix(line, "set ")); err != nil {
							t.Fatalf("SetFromInput(%q): %v", line, err)
						}
					}
				}
				check := func(cfg *config.Config, err error) {
					t.Helper()
					if err != nil {
						t.Fatalf("strict commit: %v", err)
					}
					pool := cfg.Security.NAT.SourcePools["P"]
					if pool == nil || pool.PortLow != tc.low || pool.PortHigh != tc.high ||
						pool.PortRandomAllocation != tc.random || pool.PortNoTranslation != tc.preserve {
						t.Fatalf("compiled pool: %+v; want %d-%d random=%v preserve=%v", pool, tc.low, tc.high, tc.random, tc.preserve)
					}
				}
				check(s.CommitCheck())
				exported := s.ShowCandidateSet()
				check(s.Commit())

				// Replaying display-set backups must preserve the compiled window.
				replay := newTestStore(t)
				if err := replay.EnterConfigure(); err != nil {
					t.Fatal(err)
				}
				if _, err := replay.LoadSet(exported); err != nil {
					t.Fatalf("LoadSet(display set): %v", err)
				}
				check(replay.Commit())
			})
		}
	}
}

func TestSourcePoolPortMalformedStrict16670(t *testing.T) {
	for _, port := range []string{
		"range", "range 0 to 2048", "range 1024 to 65536",
		"range 2048 to 1024", "range low 1024 high 65536",
		"range 1024 to", "range 1024 to 2048 bogus", "bogus-allocation",
	} {
		t.Run(port, func(t *testing.T) {
			_, err := CheckText(sourcePoolSet16670+"set security nat source pool P port "+port+"\n", -1)
			if err == nil {
				t.Fatal("malformed port specification passed strict commit")
			}
			if !strings.Contains(err.Error(), "port") {
				t.Fatalf("unrelated rejection: %v", err)
			}
		})
	}
}
