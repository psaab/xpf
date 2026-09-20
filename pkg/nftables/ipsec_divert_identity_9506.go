package nftables

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	gnft "github.com/google/nftables"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// IpsecDivertLabelSchema9506 identifies the on-wire metadata layout. The
// schema is deliberately explicit: a daemon must never interpret a witness
// written by a future layout as if it were this one.
const IpsecDivertLabelSchema9506 = "v1"

const (
	ipsecQuarantineMetaChainPrefix9506 = "xpf_ipsec_quarantine_meta_g"
	ipsecDivertMetaChainPrefix9506     = "xpf_ipsec_divert_meta_s"
	ipsecDivertIdentityLockSuffix9506  = ".lock"
)

// IpsecDivertIdentity is the durable identity of one nftables mutation. The
// RunID identifies a daemon incarnation; InstallSequence is a persisted
// operation number, not the logical queue/generation number carried by
// IpsecDivertSpec.QuarantineGeneration; LabelSchema identifies this witness
// layout. A new sequence is consumed for every install or remove operation.
type IpsecDivertIdentity struct {
	RunID           string
	InstallSequence uint64
	LabelSchema     string
}

func (id IpsecDivertIdentity) valid() error {
	if id.RunID == "" {
		return errors.New("ipsec divert: missing run identity")
	}
	if id.InstallSequence == 0 {
		return errors.New("ipsec divert: missing install sequence")
	}
	if id.LabelSchema != IpsecDivertLabelSchema9506 {
		return fmt.Errorf("ipsec divert: unknown label schema %q", id.LabelSchema)
	}
	return nil
}

func (id IpsecDivertIdentity) legacy() bool {
	return id.LabelSchema == "" && id.InstallSequence == 0
}

func (id IpsecDivertIdentity) stale() bool {
	return id.legacy()
}

func (want IpsecDivertIdentity) refusesRollback(have IpsecDivertIdentity) bool {
	if have.legacy() {
		return false
	}
	return have.InstallSequence > want.InstallSequence
}

type ipsecDivertIdentityFile9506 struct {
	RunID        string `json:"run_id"`
	NextSequence uint64 `json:"next_sequence"`
	LabelSchema  string `json:"label_schema"`
}

// IpsecDivertIdentityAllocator is backed by one durable state file. The file
// is intentionally not written by the constructor: merely starting a daemon
// that never enables IPsec must not create fleet-wide state. Allocate writes
// the incremented next sequence before returning, using the repository's
// durable atomic writer; a restart therefore cannot reuse a sequence.
type IpsecDivertIdentityAllocator struct {
	mu   sync.Mutex
	path string
	run  string
	next uint64
}

// NewIpsecDivertIdentityAllocator opens a durable allocator at path. A missing
// file is a valid first-use state; malformed or unknown-schema state fails
// closed rather than resetting the counter and risking a duplicate identity.
func NewIpsecDivertIdentityAllocator(path string) (*IpsecDivertIdentityAllocator, error) {
	if path == "" {
		return nil, errors.New("ipsec divert identity: empty state path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("ipsec divert identity state dir: %w", err)
	}
	a := &IpsecDivertIdentityAllocator{path: path, run: newIpsecDivertRunID9506(), next: 1}
	if state, ok, err := readIpsecDivertIdentityFile9506(path); err != nil {
		return nil, err
	} else if ok {
		if state.LabelSchema != IpsecDivertLabelSchema9506 || state.RunID == "" {
			return nil, fmt.Errorf("ipsec divert identity: invalid persisted identity schema=%q run=%q", state.LabelSchema, state.RunID)
		}
		if state.NextSequence == 0 {
			return nil, errors.New("ipsec divert identity: persisted sequence exhausted")
		}
		a.next = state.NextSequence
	}
	return a, nil
}

// Allocate reserves and durably records one operation identity. A sidecar
// advisory lock serializes concurrent daemon incarnations that share the
// state root; the state file is reread while holding that lock so a stale
// in-memory cache can never hand out a duplicate sequence.
func (a *IpsecDivertIdentityAllocator) Allocate() (IpsecDivertIdentity, error) {
	if a == nil {
		return IpsecDivertIdentity{}, errors.New("ipsec divert identity: nil allocator")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	lock, err := os.OpenFile(a.path+ipsecDivertIdentityLockSuffix9506, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return IpsecDivertIdentity{}, fmt.Errorf("ipsec divert identity lock: %w", err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return IpsecDivertIdentity{}, fmt.Errorf("ipsec divert identity lock: %w", err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN) // best effort on close

	next := a.next
	if state, ok, err := readIpsecDivertIdentityFile9506(a.path); err != nil {
		return IpsecDivertIdentity{}, err
	} else if ok {
		if state.LabelSchema != IpsecDivertLabelSchema9506 || state.RunID == "" {
			return IpsecDivertIdentity{}, fmt.Errorf("ipsec divert identity: invalid persisted identity schema=%q run=%q", state.LabelSchema, state.RunID)
		}
		if state.NextSequence == 0 {
			return IpsecDivertIdentity{}, errors.New("ipsec divert identity: persisted sequence exhausted")
		}
		next = state.NextSequence
	}
	if next == 0 || next == ^uint64(0) {
		return IpsecDivertIdentity{}, errors.New("ipsec divert identity: install sequence exhausted")
	}
	id := IpsecDivertIdentity{RunID: a.run, InstallSequence: next, LabelSchema: IpsecDivertLabelSchema9506}
	if err := persistIpsecDivertIdentityFile9506(a.path, ipsecDivertIdentityFile9506{
		RunID: a.run, NextSequence: next + 1, LabelSchema: IpsecDivertLabelSchema9506,
	}); err != nil {
		return IpsecDivertIdentity{}, err
	}
	a.next = next + 1
	return id, nil
}

// CurrentRunID returns the incarnation identity without touching disk.
func (a *IpsecDivertIdentityAllocator) CurrentRunID() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.run
}

// StatePath is exposed for diagnostics and tests; it does not read or write.
func (a *IpsecDivertIdentityAllocator) StatePath() string {
	if a == nil {
		return ""
	}
	return a.path
}

func readIpsecDivertIdentityFile9506(path string) (ipsecDivertIdentityFile9506, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ipsecDivertIdentityFile9506{}, false, nil
	}
	if err != nil {
		return ipsecDivertIdentityFile9506{}, false, fmt.Errorf("ipsec divert identity state read: %w", err)
	}
	var state ipsecDivertIdentityFile9506
	if err := json.Unmarshal(raw, &state); err != nil {
		return ipsecDivertIdentityFile9506{}, false, fmt.Errorf("ipsec divert identity state decode: %w", err)
	}
	return state, true, nil
}

func persistIpsecDivertIdentityFile9506(path string, state ipsecDivertIdentityFile9506) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("ipsec divert identity state encode: %w", err)
	}
	if err := fsatomic.WriteFileDurable(path, raw, 0o600); err != nil {
		return fmt.Errorf("ipsec divert identity state persist: %w", err)
	}
	return nil
}

func newIpsecDivertRunID9506() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return fmt.Sprintf("xpfd-%x", raw)
	}
	return fmt.Sprintf("xpfd-entropy-unavailable-%d-%d", os.Getpid(), time.Now().UnixNano())
}

// formatIpsecDivertIdentity renders the metadata witness. Empty identity
// fields are retained as an explicit unassigned witness for legacy/unit-only
// callers; daemon production paths always provide a durable identity.
func formatIpsecDivertIdentity(spec IpsecDivertSpec) []byte {
	runID := spec.RunID
	if runID == "" {
		runID = "unassigned"
	}
	schema := spec.LabelSchema
	if schema == "" {
		schema = IpsecDivertLabelSchema9506
	}
	return []byte(fmt.Sprintf("run=%s install_sequence=%d label_schema=%s generation=%d primary=%s raw_reason=%d mask=0x%08x raw_mask=0x%08x",
		runID, spec.InstallSequence, schema, spec.QuarantineGeneration,
		spec.QuarantinePrimaryReason.String(), uint8(spec.QuarantineRawReason),
		uint32(spec.QuarantineReasonMask), uint32(spec.QuarantineRawMask)))
}

// parseIpsecDivertIdentity parses both the current install_sequence key and
// the short key emitted by an early development build, treating a missing
// schema/sequence as stale legacy metadata rather than as current identity.
func parseIpsecDivertIdentity(meta []byte) (IpsecDivertIdentity, error) {
	var id IpsecDivertIdentity
	for _, field := range strings.Fields(string(meta)) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch key {
		case "run":
			id.RunID = value
		case "install_sequence", "install_seq":
			seq, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return IpsecDivertIdentity{}, fmt.Errorf("ipsec divert identity: bad install sequence %q", value)
			}
			id.InstallSequence = seq
		case "label_schema":
			id.LabelSchema = value
		}
	}
	if id.RunID == "" {
		return IpsecDivertIdentity{}, errors.New("ipsec divert identity: witness without run")
	}
	if id.LabelSchema != "" && id.LabelSchema != IpsecDivertLabelSchema9506 {
		return IpsecDivertIdentity{}, fmt.Errorf("ipsec divert identity: unknown label schema %q", id.LabelSchema)
	}
	if id.LabelSchema == IpsecDivertLabelSchema9506 && id.InstallSequence == 0 {
		return IpsecDivertIdentity{}, errors.New("ipsec divert identity: current schema missing install sequence")
	}
	if id.LabelSchema == "" && id.InstallSequence != 0 {
		return IpsecDivertIdentity{}, errors.New("ipsec divert identity: schema-less witness has install sequence")
	}
	return id, nil
}

// readIpsecDivertIdentities9506 scans both families and returns one witness
// per family that has a metadata rule. tables is the number of existing
// family tables, allowing identity-aware removal to reject a partially
// installed current witness rather than checking only one family.
func (in *netlinkInstaller) readIpsecDivertIdentities9506(tableName string) ([]IpsecDivertIdentity, int, error) {
	c, err := in.newConn()
	if err != nil {
		return nil, 0, fmt.Errorf("nftables identity readback conn: %w", err)
	}
	var identities []IpsecDivertIdentity
	tables := 0
	for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
		exists, err := tableExistsInFamily(c, family, tableName)
		if err != nil {
			return nil, tables, err
		}
		if !exists {
			continue
		}
		tables++
		chains, err := c.ListChainsOfTableFamily(family)
		if err != nil {
			return nil, tables, err
		}
		tbl := &gnft.Table{Family: family, Name: tableName}
		for _, chain := range chains {
			if chain == nil || chain.Table == nil || chain.Table.Name != tableName ||
				(!strings.HasPrefix(chain.Name, ipsecQuarantineMetaChainPrefix9506) &&
					!strings.HasPrefix(chain.Name, ipsecDivertMetaChainPrefix9506)) {
				continue
			}
			rules, err := c.GetRules(tbl, chain)
			if err != nil {
				if errors.Is(err, unix.ENOENT) {
					continue
				}
				return nil, tables, err
			}
			for _, rule := range rules {
				if rule == nil || len(rule.UserData) == 0 {
					continue
				}
				id, err := parseIpsecDivertIdentity(rule.UserData)
				if err != nil {
					return nil, tables, err
				}
				identities = append(identities, id)
				break
			}
			if len(identities) == tables {
				break
			}
		}
	}
	return identities, tables, nil
}

// readIpsecDivertIdentity is the single-witness convenience used by install
// rollback checks. It rejects disagreeing family witnesses.
func (in *netlinkInstaller) readIpsecDivertIdentity(tableName string) (IpsecDivertIdentity, bool, error) {
	identities, _, err := in.readIpsecDivertIdentities9506(tableName)
	if err != nil {
		return IpsecDivertIdentity{}, false, err
	}
	if len(identities) == 0 {
		return IpsecDivertIdentity{}, false, nil
	}
	for _, id := range identities[1:] {
		if id != identities[0] {
			return IpsecDivertIdentity{}, false, fmt.Errorf("ipsec divert: %s family identity mismatch", tableName)
		}
	}
	return identities[0], true, nil
}

func (in *netlinkInstaller) checkIpsecDivertNoRollback(spec IpsecDivertSpec) error {
	if spec.RunID == "" && spec.InstallSequence == 0 && spec.LabelSchema == "" {
		return nil
	}
	want := IpsecDivertIdentity{RunID: spec.RunID, InstallSequence: spec.InstallSequence, LabelSchema: spec.LabelSchema}
	if err := want.valid(); err != nil {
		return err
	}
	for _, tableName := range []string{IpsecDivertTableName, IpsecQuarantineTableName} {
		identities, tables, err := in.readIpsecDivertIdentities9506(tableName)
		if err != nil {
			return err
		}
		if len(identities) == 0 {
			continue
		}
		if len(identities) != tables {
			return fmt.Errorf("ipsec divert: %s identity missing in one family", tableName)
		}
		for _, have := range identities {
			if have != identities[0] {
				return fmt.Errorf("ipsec divert: %s family identity mismatch", tableName)
			}
			if want.refusesRollback(have) {
				return fmt.Errorf("ipsec divert: refusing rollback over %s run=%s install_sequence=%d with requested sequence=%d", tableName, have.RunID, have.InstallSequence, want.InstallSequence)
			}
		}
	}
	return nil
}

// UsesDurableIpsecIdentity9506 marks the production netlink installer for the
// daemon wiring. Test installers intentionally do not implement this method,
// so unit tests never create /var/lib/xpf state merely by constructing a fake.
func (in *netlinkInstaller) UsesDurableIpsecIdentity9506() bool { return true }

func withIpsecDivertIdentityLock9506(path string, fn func() error) error {
	if path == "" {
		return fn()
	}
	lock, err := os.OpenFile(path+ipsecDivertIdentityLockSuffix9506, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("ipsec divert identity lock: %w", err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("ipsec divert identity lock: %w", err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	return fn()
}

// IpsecDivertRemovalIdentity9506 separates ownership authorization from the
// operation event. Owner must match the active table's witness exactly; the
// fresh Operation sequence is persisted before the remove and is useful for
// audit/dedup but must never replace the owner check.
type IpsecDivertRemovalIdentity9506 struct {
	Owner     IpsecDivertIdentity
	Operation IpsecDivertIdentity
	LockPath  string
}

// RemoveIpsecDivertWithIdentity9506 serializes witness authorization and the
// following kernel deletion against concurrent daemon installs/removes.
func (in *netlinkInstaller) RemoveIpsecDivertWithIdentity9506(req IpsecDivertRemovalIdentity9506) error {
	return withIpsecDivertIdentityLock9506(req.LockPath, func() error {
		return in.removeIpsecDivertWithIdentityUnlocked9506(req)
	})
}

// removeIpsecDivertWithIdentityUnlocked9506 performs the witness check while
// its caller holds the shared identity lock.
func (in *netlinkInstaller) removeIpsecDivertWithIdentityUnlocked9506(req IpsecDivertRemovalIdentity9506) error {
	if err := req.Operation.valid(); err != nil {
		return err
	}
	for _, tableName := range []string{IpsecDivertTableName, IpsecQuarantineTableName} {
		identities, tables, err := in.readIpsecDivertIdentities9506(tableName)
		if err != nil {
			return err
		}
		if len(identities) == 0 {
			continue // schema-less legacy table; ordinary removal handles it.
		}
		if len(identities) != tables {
			return fmt.Errorf("ipsec divert: %s identity missing in one family", tableName)
		}
		for _, have := range identities {
			if have.stale() {
				continue
			}
			if req.Owner.RunID == "" || req.Owner.InstallSequence == 0 || req.Owner.LabelSchema == "" ||
				have.RunID != req.Owner.RunID || have.InstallSequence != req.Owner.InstallSequence ||
				have.LabelSchema != req.Owner.LabelSchema {
				return fmt.Errorf("ipsec divert: remove owner mismatch in %s (active run=%s sequence=%d, requested run=%s sequence=%d)",
					tableName, have.RunID, have.InstallSequence, req.Owner.RunID, req.Owner.InstallSequence)
			}
		}
	}
	return in.RemoveIpsecDivert()
}
