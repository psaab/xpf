package userspace

// #18696: a helper respawn stalled 225 s with transit dead. clearStaleSteeringRows
// deleted each key and then asked the kernel for the key after it. For a key that is no
// longer in the map, the kernel hash map's get_next_key falls back to a scan from
// bucket 0 (htab_map_get_next_key -> find_first_elem), so every delete rescanned the
// 8,388,608-bucket userspace_sessions map from the start.
//
// The walk is now walkDeleteBPFKeys, which reads the next key while the current one
// still exists. The cells here count WORK (bucket checks, NextKey calls), never time
// (docs/engineering-style.md "Time in tests"). Wall-clock is reported only by the
// opt-in measurement at the bottom.

import (
	"encoding/binary"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"hash/fnv"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// htabModel models a kernel BPF hash map's iteration: bucket order, and the
// get_next_key fallback that makes delete-then-next quadratic. NextKey on a PRESENT
// key returns the next element in its bucket, else the first element of a later
// bucket. On a MISSING key it scans from bucket 0. bucketChecks counts bucket scans,
// the kernel's actual work.
type htabModel struct {
	keySize      int
	buckets      [][]string
	where        map[string]int
	bucketChecks int
	nextKeyCalls int
}

func newHtabModel(buckets, keySize int) *htabModel {
	return &htabModel{keySize: keySize, buckets: make([][]string, buckets), where: map[string]int{}}
}

func (h *htabModel) insert(key []byte) {
	f := fnv.New32a()
	_, _ = f.Write(key)
	b := int(f.Sum32()) % len(h.buckets)
	h.buckets[b] = append(h.buckets[b], string(key))
	h.where[string(key)] = b
}

func (h *htabModel) KeySize() uint32    { return uint32(h.keySize) }
func (h *htabModel) MaxEntries() uint32 { return uint32(len(h.buckets)) }
func (h *htabModel) len() int           { return len(h.where) }

func (h *htabModel) NextKey(key, nextKeyOut interface{}) error {
	h.nextKeyCalls++
	out := nextKeyOut.([]byte)
	start := 0
	if k, ok := key.([]byte); ok {
		if b, present := h.where[string(k)]; present {
			list := h.buckets[b]
			for i, e := range list {
				if e == string(k) && i+1 < len(list) {
					copy(out, list[i+1])
					return nil
				}
			}
			start = b + 1
		}
		// Missing key: find_first_elem, from bucket 0.
	}
	for i := start; i < len(h.buckets); i++ {
		h.bucketChecks++
		if len(h.buckets[i]) > 0 {
			copy(out, h.buckets[i][0])
			return nil
		}
	}
	return ebpf.ErrKeyNotExist
}

func (h *htabModel) Delete(key interface{}) error {
	k := string(key.([]byte))
	b, present := h.where[k]
	if !present {
		return ebpf.ErrKeyNotExist
	}
	list := h.buckets[b]
	for i, e := range list {
		if e == k {
			h.buckets[b] = append(list[:i], list[i+1:]...)
			break
		}
	}
	delete(h.where, k)
	return nil
}

func modelWithRows(buckets, rows int) *htabModel {
	h := newHtabModel(buckets, 16)
	for i := 0; i < rows; i++ {
		key := make([]byte, 16)
		binary.BigEndian.PutUint64(key[8:], uint64(i)+1)
		h.insert(key)
	}
	return h
}

// deleteThenNextKeyWalk is the pre-#18696 loop, verbatim in shape. It is kept as the
// control proving the model can tell the two shapes apart, and as the "before" arm of
// the opt-in measurement.
func deleteThenNextKeyWalk(m bpfKeyWalker) (deleted int) {
	key := make([]byte, m.KeySize())
	nextKey := make([]byte, m.KeySize())
	for {
		if err := m.NextKey(key, nextKey); err != nil {
			break
		}
		copy(key, nextKey)
		_ = m.Delete(key)
		deleted++
	}
	return deleted
}

const (
	walkBuckets = 1 << 15
	walkRows    = 2048
)

func TestWalkDeleteBPFKeysIsLinear18696(t *testing.T) {
	// Control: on this model, the replaced shape does quadratic work. Without this,
	// a model that never restarts would let a quadratic walk pass the bound below.
	old := modelWithRows(walkBuckets, walkRows)
	if got := deleteThenNextKeyWalk(old); got != walkRows || old.len() != 0 {
		t.Fatalf("control walk deleted %d of %d rows, %d left", got, walkRows, old.len())
	}
	if quadratic := walkRows * walkBuckets / 8; old.bucketChecks < quadratic {
		t.Fatalf("the model does not reproduce the kernel restart: the replaced loop took %d bucket "+
			"checks, want >= %d (rows x buckets / 8)", old.bucketChecks, quadratic)
	}

	h := modelWithRows(walkBuckets, walkRows)
	deleted, kept := walkDeleteBPFKeys(h, nil)
	if deleted != walkRows || kept != 0 || h.len() != 0 {
		t.Fatalf("walkDeleteBPFKeys deleted=%d kept=%d left=%d, want %d/0/0", deleted, kept, h.len(), walkRows)
	}
	// One forward pass: every bucket is checked at most once, plus one NextKey per row.
	if bound := walkBuckets + walkRows; h.bucketChecks > bound {
		t.Fatalf("walkDeleteBPFKeys took %d bucket checks for %d rows in %d buckets, want <= %d "+
			"(linear). The replaced loop took %d: is the walk deleting before reading the next key?",
			h.bucketChecks, walkRows, walkBuckets, bound, old.bucketChecks)
	}
	if h.nextKeyCalls != walkRows+1 {
		t.Fatalf("walkDeleteBPFKeys made %d NextKey calls for %d rows, want %d", h.nextKeyCalls, walkRows, walkRows+1)
	}
}

// The ctrl-enable flush keeps some rows. Kept rows must stay, the rest must go, and
// the walk stays linear.
func TestWalkDeleteBPFKeysKeepsAndStaysLinear18696(t *testing.T) {
	h := modelWithRows(walkBuckets, walkRows)
	keep := func(key []byte) bool { return binary.BigEndian.Uint64(key[8:])%3 == 0 }
	deleted, kept := walkDeleteBPFKeys(h, func(key []byte) bool { return !keep(key) })
	wantKept := walkRows / 3
	if kept != wantKept || deleted != walkRows-wantKept || h.len() != wantKept {
		t.Fatalf("deleted=%d kept=%d left=%d, want deleted=%d kept=%d left=%d",
			deleted, kept, h.len(), walkRows-wantKept, wantKept, wantKept)
	}
	for k := range h.where {
		if !keep([]byte(k)) {
			t.Fatalf("a row the predicate dropped is still in the map: %x", k)
		}
	}
	if bound := walkBuckets + walkRows; h.bucketChecks > bound {
		t.Fatalf("keep-walk took %d bucket checks, want <= %d (linear)", h.bucketChecks, bound)
	}
}

// An all-zero key is a real row. The walk starts from NextKey(nil), so it is visited.
func TestWalkDeleteBPFKeysVisitsTheZeroKey18696(t *testing.T) {
	h := newHtabModel(64, 16)
	h.insert(make([]byte, 16))
	if deleted, _ := walkDeleteBPFKeys(h, nil); deleted != 1 || h.len() != 0 {
		t.Fatalf("the all-zero key was not deleted: deleted=%d left=%d", deleted, h.len())
	}
}

// restartingMap restarts every walk from its first element: a map the walk can never
// get through. The step bound must stop it. The fake itself ends the walk after 1000
// steps, so a missing bound shows up as a count instead of a hang.
type restartingMap struct{ steps int }

func (r *restartingMap) KeySize() uint32    { return 4 }
func (r *restartingMap) MaxEntries() uint32 { return 10 }
func (r *restartingMap) NextKey(_, out interface{}) error {
	r.steps++
	if r.steps > 1000 {
		return ebpf.ErrKeyNotExist
	}
	copy(out.([]byte), []byte{1, 2, 3, 4})
	return nil
}
func (r *restartingMap) Delete(interface{}) error { return nil }

func TestWalkDeleteBPFKeysTerminatesUnderChurn18696(t *testing.T) {
	r := &restartingMap{}
	walkDeleteBPFKeys(r, func([]byte) bool { return false })
	if r.steps > 2*10+2 {
		t.Fatalf("the walk did not stop at its bound: %d NextKey calls on a 10-entry map", r.steps)
	}
}

// deleteDuringWalk reports, for each loop in file that walks a map and calls Delete
// in its body, the position and the enclosing function's name. A walk is a for loop
// whose condition or body calls Next (an iterator) or NextKey, or a range over a
// Keys/All/Iterate call (a range-over-func iterator).
func deleteDuringWalk(t *testing.T, fset *token.FileSet, file *ast.File) []string {
	t.Helper()
	var hits []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			var walks bool
			var body *ast.BlockStmt
			switch loop := n.(type) {
			case *ast.ForStmt:
				body = loop.Body
				for _, part := range []ast.Node{loop.Cond, loop.Body} {
					if part != nil && (callsMethod(part, "Next") || callsMethod(part, "NextKey")) {
						walks = true
					}
				}
			case *ast.RangeStmt:
				body = loop.Body
				walks = callsMethod(loop.X, "Keys") || callsMethod(loop.X, "All") || callsMethod(loop.X, "Iterate")
			default:
				return true
			}
			if walks && (callsMethod(body, "Delete") || callsMethod(body, "BatchDelete")) {
				hits = append(hits, fset.Position(n.Pos()).String()+" "+fn.Name.Name)
			}
			return true
		})
	}
	return hits
}

func callsMethod(n ast.Node, name string) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
				found = true
			}
		}
		return !found
	})
	return found
}

// Census guard (#18696): no other loop in pkg/ deletes from a map it is walking.
// walkDeleteBPFKeys is the one walk-and-delete, and it reads the next key first. A
// loop that walks and deletes some other way must go through it. A walk that only
// COLLECTS keys and deletes after the loop is fine and is not flagged.
func TestNoDeleteDuringBPFMapWalk18696(t *testing.T) {
	// Positive controls: the detector flags every walk-and-delete shape, one hit each.
	fset := token.NewFileSet()
	control, err := parser.ParseFile(fset, "control.go", `package p
type walker interface {
	NextKey(a, b interface{}) error
	Delete(a interface{}) error
	Iterate() interface{ Next(k, v interface{}) bool }
	Keys() func(func([]byte) bool)
}
func nextKeyInBody(m walker) {
	key, next := make([]byte, 4), make([]byte, 4)
	for {
		if err := m.NextKey(key, next); err != nil { break }
		copy(key, next)
		_ = m.Delete(key)
	}
}
func nextKeyInCondition(m walker) {
	for k := make([]byte, 4); m.NextKey(k, k) == nil; {
		_ = m.Delete(k)
	}
}
func iteratorNext(m walker) {
	var k, v []byte
	for it := m.Iterate(); it.Next(&k, &v); {
		_ = m.Delete(k)
	}
}
func rangeOverKeys(m walker) {
	for k := range m.Keys() {
		_ = m.Delete(k)
	}
}
func collectThenDelete(m walker) {
	var k, v []byte
	var stale [][]byte
	for it := m.Iterate(); it.Next(&k, &v); {
		stale = append(stale, k)
	}
	for _, s := range stale {
		_ = m.Delete(s)
	}
}`, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, hit := range deleteDuringWalk(t, fset, control) {
		got[hit[strings.LastIndex(hit, " ")+1:]]++
	}
	for _, shape := range []string{"nextKeyInBody", "nextKeyInCondition", "iteratorNext", "rangeOverKeys"} {
		if got[shape] != 1 {
			t.Errorf("detector control: shape %s flagged %d times, want 1 (hits %v)", shape, got[shape], got)
		}
	}
	if got["collectThenDelete"] != 0 {
		t.Errorf("detector control: collect-then-delete is fine and must not be flagged (hits %v)", got)
	}
	if t.Failed() {
		t.FailNow()
	}

	_, here, _, _ := runtime.Caller(0)
	pkgRoot := filepath.Join(filepath.Dir(here), "..", "..")
	var offenders []string
	scanned := 0
	err = filepath.WalkDir(pkgRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(src), ".Delete(") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}
		scanned++
		for _, hit := range deleteDuringWalk(t, fset, file) {
			if !strings.HasSuffix(hit, " walkDeleteBPFKeys") {
				offenders = append(offenders, hit)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned == 0 {
		t.Fatal("census scanned no files: the pkg/ root is wrong")
	}
	if len(offenders) != 0 {
		t.Fatalf("loops delete from a map while walking it; use walkDeleteBPFKeys (#18696):\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// newPrivilegedHashMap creates a real BPF hash map shaped like userspace_sessions,
// or skips when the environment cannot create one (unprivileged CI).
func newPrivilegedHashMap(t *testing.T, maxEntries uint32) *ebpf.Map {
	t.Helper()
	_ = rlimit.RemoveMemlock()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: 16, ValueSize: 1, MaxEntries: maxEntries, Flags: unix.BPF_F_NO_PREALLOC,
	})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOMEM) {
			t.Skipf("creating a BPF hash map needs privileges: %v", err)
		}
		t.Fatalf("create BPF hash map: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func fillHashMap(t *testing.T, m *ebpf.Map, rows int) {
	t.Helper()
	for i := 0; i < rows; i++ {
		key := make([]byte, 16)
		binary.BigEndian.PutUint64(key[8:], uint64(i)+1)
		if err := m.Put(key, []byte{1}); err != nil {
			t.Fatalf("insert row %d: %v", i, err)
		}
	}
}

// On a real kernel map (privileged environments only), clearStaleSteeringRows deletes
// every row, including an all-zero key.
func TestClearStaleSteeringRowsRealMap18696(t *testing.T) {
	m := newPrivilegedHashMap(t, 1<<16)
	fillHashMap(t, m, 5000)
	if err := m.Put(make([]byte, 16), []byte{1}); err != nil {
		t.Fatalf("insert zero key: %v", err)
	}
	if got := clearStaleSteeringRows(m); got != 5001 {
		t.Fatalf("clearStaleSteeringRows deleted %d rows, want 5001", got)
	}
	if err := m.NextKey(nil, make([]byte, 16)); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("map not empty after the clear: NextKey = %v", err)
	}
}

// Opt-in measurement: XPF_18696_MEASURE=<rows> times the replaced loop against
// walkDeleteBPFKeys on a real map with the production userspace_sessions capacity
// (8,388,608 entries). It needs root, and the replaced arm takes minutes at 50,000
// rows. The numbers are logged, never asserted.
func TestMeasureSteeringFlush18696(t *testing.T) {
	spec := os.Getenv("XPF_18696_MEASURE")
	if spec == "" {
		t.Skip("set XPF_18696_MEASURE=<rows> to measure (root, minutes)")
	}
	var rows int
	for _, c := range spec {
		if c < '0' || c > '9' {
			t.Fatalf("XPF_18696_MEASURE=%q is not a row count", spec)
		}
		rows = rows*10 + int(c-'0')
	}
	const productionEntries = 16 * 131072 * 4
	for _, arm := range []struct {
		name string
		walk func(*ebpf.Map) int
	}{
		{"walkDeleteBPFKeys", func(m *ebpf.Map) int { d, _ := walkDeleteBPFKeys(m, nil); return d }},
		{"replaced-delete-then-next", func(m *ebpf.Map) int { return deleteThenNextKeyWalk(m) }},
	} {
		m := newPrivilegedHashMap(t, productionEntries)
		fillHashMap(t, m, rows)
		start := time.Now()
		got := arm.walk(m)
		t.Logf("MEASURE %s: deleted %d of %d rows in %s (map capacity %d)",
			arm.name, got, rows, time.Since(start).Round(time.Millisecond), productionEntries)
		_ = m.Close()
	}
}
