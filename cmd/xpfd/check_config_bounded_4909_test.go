package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// countingReader counts bytes consumed so a test can assert an over-cap source
// is NOT fully drained (the allocation-bound guarantee of the #4909 fix).
type countingReader struct {
	r    io.Reader
	read int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += int64(n)
	return n, err
}

// TestReadBoundedStopsAtCap pins the #4909 allocation bound: readBounded must
// read at most max+1 bytes from an over-cap source and reject it — it must NOT
// drain the whole source (the TOCTOU where os.ReadFile ballooned memory before
// the size cap). A large finite source stands in for a FUSE/racing file that
// under-reports its Stat size.
//
// RED on revert: model the pre-fix path as io.ReadAll(r) (no LimitReader) + a
// post-read cap and this drains all bigN bytes — the consumed-bytes assertion
// (≤ max+1) fails.
func TestReadBoundedStopsAtCap(t *testing.T) {
	const max = 4 << 10
	const bigN = max * 64

	cr := &countingReader{r: bytes.NewReader(bytes.Repeat([]byte("z"), bigN))}
	data, err := configstore.ReadBounded(cr, max)
	if err == nil {
		t.Fatalf("readBounded accepted an over-cap source (%d bytes)", len(data))
	}
	if data != nil {
		t.Fatalf("over-cap readBounded returned %d bytes; want nil", len(data))
	}
	if cr.read > max+1 {
		t.Fatalf("readBounded drained %d bytes; want at most %d (allocation not bounded)", cr.read, max+1)
	}

	// Exactly max round-trips.
	ok := &countingReader{r: bytes.NewReader(bytes.Repeat([]byte("y"), max))}
	got, err := configstore.ReadBounded(ok, max)
	if err != nil || len(got) != max {
		t.Fatalf("at-max: err=%v len=%d want %d", err, len(got), max)
	}
}

// TestReadBoundedFile pins #4909: check-config must bound both the accept/reject
// decision AND the allocation. The pre-fix path did os.Stat then os.ReadFile
// (whole-file alloc) then a post-read cap — a TOCTOU where a FUSE/racing file
// under-reports its Stat size then streams an unbounded body, ballooning memory
// before the post-read cap fires. readBoundedFile reads through
// io.LimitReader(max+1) on one descriptor, so an over-cap file is rejected with
// nil data and the allocation is bounded to max+1 regardless of Stat.
//
// RED on revert: without the helper this file fails to build (the inline
// os.Stat+os.ReadFile logic offered no reusable bounded reader); the contract
// checks below (nil data on over-cap, non-regular rejected, exact-max accepted)
// pin the fixed behavior.
func TestReadBoundedFile(t *testing.T) {
	dir := t.TempDir()
	const max = 4 << 10 // small cap for the test

	write := func(name string, n int) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, bytes.Repeat([]byte("a"), n), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	// Exactly at the cap → accepted, full content returned.
	atMax := write("atmax", max)
	if data, err := readBoundedFile(atMax, max); err != nil || len(data) != max {
		t.Fatalf("at-max: err=%v len=%d want %d", err, len(data), max)
	}

	// One byte over the cap → rejected, nil data (the +1 sentinel is caught).
	over := write("over", max+1)
	if data, err := readBoundedFile(over, max); err == nil || data != nil {
		t.Fatalf("over-cap: err=%v len=%d; want error + nil data", err, len(data))
	}

	// A much larger file → still rejected with nil data (allocation bounded, the
	// whole file is never materialized).
	huge := write("huge", max*64)
	if data, err := readBoundedFile(huge, max); err == nil || data != nil {
		t.Fatalf("huge: err=%v len=%d; want error + nil data", err, len(data))
	}

	// A directory (non-regular) → rejected.
	if _, err := readBoundedFile(dir, max); err == nil {
		t.Fatal("directory accepted as a regular file")
	}

	// A small valid file round-trips.
	small := filepath.Join(dir, "small")
	if err := os.WriteFile(small, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write small: %v", err)
	}
	if data, err := readBoundedFile(small, max); err != nil || string(data) != "hello" {
		t.Fatalf("small: err=%v data=%q", err, data)
	}
}
