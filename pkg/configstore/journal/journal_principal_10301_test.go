// #10301: the audit journal records no principal — commits, zeroize and
// reboot are unattributable on-box. Entry.Principal names the proximate
// actor; Log normalizes a missing principal to UnknownPrincipal and Tail
// backfills pre-#10301 rows the same way. These cells RED pre-fix: Entry
// has no Principal field and the sentinels do not exist.
package journal

import (
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestLogCarriesPrincipalEndToEnd10301 pins that a supplied principal
// survives Log -> disk bytes -> Tail verbatim.
func TestLogCarriesPrincipalEndToEnd10301(t *testing.T) {
	const want = `uid 1001 (ops, class "super-user")`
	j := testJournal(t)
	mustLog(t, j, &Entry{Action: "commit", Detail: "c0", Principal: want})

	raw, err := os.ReadFile(j.path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"principal":"uid 1001 (ops, class \"super-user\")"`) {
		t.Fatalf("raw journal line lacks the principal verbatim; got:\n%s", string(raw))
	}

	got, err := j.Tail(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("Tail(0) = %d entries, want 1", len(got))
	}
	if got[0].Principal != want {
		t.Errorf("Tail principal = %q, want %q", got[0].Principal, want)
	}
}

// TestLogBlankPrincipalBecomesUnknown10301 pins that an omitted or blank
// principal is recorded as the explicit UnknownPrincipal sentinel — never
// an empty string, never a guess.
func TestLogBlankPrincipalBecomesUnknown10301(t *testing.T) {
	for _, tc := range []struct{ name, principal string }{
		{"omitted", ""},
		{"spaces", "   "},
		{"whitespace", "\t\n "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := testJournal(t)
			mustLog(t, j, &Entry{Action: "commit", Detail: "c", Principal: tc.principal})

			raw, err := os.ReadFile(j.path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), `"principal":"`+UnknownPrincipal+`"`) {
				t.Fatalf("raw journal line lacks explicit %q; got:\n%s", UnknownPrincipal, string(raw))
			}

			got, err := j.Tail(0)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("Tail(0) = %d entries, want 1", len(got))
			}
			if got[0].Principal != UnknownPrincipal {
				t.Errorf("Tail principal = %q, want explicit %q", got[0].Principal, UnknownPrincipal)
			}
		})
	}
}

// TestLegacyRowsBackfillUnknownPrincipal10301 pins the #10301 migration:
// rows written before the principal field existed (v1 fat lines and v2
// compact lines without it) read back with UnknownPrincipal, so no audit
// record is ever principal-less in memory regardless of when it was
// written.
func TestLegacyRowsBackfillUnknownPrincipal10301(t *testing.T) {
	j := testJournal(t)
	v1 := `{"timestamp":"2026-01-02T03:04:05Z","action":"commit","detail":"old","before":{"a":1},"after":{"a":2}}`
	v2 := `{"v":2,"timestamp":"2026-06-02T03:04:05Z","action":"commit","detail":"newer","config_hash":"abc"}`
	if err := os.WriteFile(j.path, []byte(v1+"\n"+v2+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := j.Tail(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("Tail(0) = %d entries, want 2", len(got))
	}
	for i, e := range got {
		if e.Principal != UnknownPrincipal {
			t.Errorf("row %d: Principal = %q, want backfilled %q", i, e.Principal, UnknownPrincipal)
		}
	}
	if got[0].Detail != "old" || got[1].Detail != "newer" {
		t.Errorf("backfill must not disturb other fields: %+v %+v", got[0], got[1])
	}
}

// TestPrincipalSanitized10301 pins the #10301 principal hygiene belt: a
// hostile principal can neither break the renderers' line discipline
// (control characters are neutralized) nor bloat the bounded tail
// scanner (length is capped with an explicit marker, UTF-8-safe).
func TestPrincipalSanitized10301(t *testing.T) {
	t.Run("controls neutralized", func(t *testing.T) {
		j := testJournal(t)
		mustLog(t, j, &Entry{Action: "commit", Principal: "alice\nINJECTED\r\nbob\x00root\x7fbld"})
		got, err := j.Tail(0)
		if err != nil {
			t.Fatal(err)
		}
		p := got[0].Principal
		if strings.ContainsAny(p, "\n\r\x00\x7f") {
			t.Fatalf("control characters survive in the principal: %q", p)
		}
		if want := "alice?INJECTED??bob?root?bld"; p != want {
			t.Errorf("sanitized principal = %q, want %q", p, want)
		}
	})

	t.Run("bounded with marker", func(t *testing.T) {
		j := testJournal(t)
		mustLog(t, j, &Entry{Action: "commit", Principal: strings.Repeat("u", maxPrincipalBytes+500)})
		got, err := j.Tail(0)
		if err != nil {
			t.Fatal(err)
		}
		p := got[0].Principal
		if !utf8.ValidString(p) {
			t.Fatalf("truncated principal is not valid UTF-8: %q", p)
		}
		if !strings.Contains(p, "[truncated ") {
			t.Errorf("over-long principal truncated silently (len=%d); want an explicit marker", len(p))
		}
		if len(p) > maxPrincipalBytes+64 {
			t.Errorf("truncated principal len = %d, want bounded near %d", len(p), maxPrincipalBytes)
		}
	})

	t.Run("multibyte truncation stays valid", func(t *testing.T) {
		j := testJournal(t)
		// "ü" is 2 bytes; a naive byte cut can split a rune.
		mustLog(t, j, &Entry{Action: "commit", Principal: strings.Repeat("ü", maxPrincipalBytes)})
		got, err := j.Tail(0)
		if err != nil {
			t.Fatal(err)
		}
		if !utf8.ValidString(got[0].Principal) {
			t.Errorf("truncated multibyte principal is not valid UTF-8: %q", got[0].Principal)
		}
	})
}
