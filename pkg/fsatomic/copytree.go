package fsatomic

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CopyTreeOptions configures CopyTreeDurable (#17176).
type CopyTreeOptions struct {
	// Hash, when non-nil, receives the sorted (relpath, content) stream —
	// relpath + "\x00" + the copied file's bytes, in sorted-relpath order —
	// so a caller can derive an integrity checksum over the copy (the
	// pkg/upgrade snapshot path hashes with sha256 and re-checks the copy
	// against a recomputation). Nil disables hashing (first-install seed
	// and staged-generation publish re-run idempotently and need none).
	Hash io.Writer
	// SyncDir is the directory-fsync primitive used for every copied
	// directory. Nil selects the package default (SyncDir, indirected
	// through copyTreeSyncDir so fsatomic tests can substitute a recorder).
	SyncDir func(string) error
}

// copyTreeSyncDir is the default directory-fsync primitive used by
// CopyTreeDurable when CopyTreeOptions.SyncDir is nil. It is a package var
// so tests can substitute a recorder and prove CopyTreeDurable actually
// fsyncs each copied directory (deepest-first, with error propagation) —
// otherwise deleting the fsync loop would not fail any test (#17176,
// formerly the pkg/upgrade copyTreeSyncDir seam from 52411be163).
var copyTreeSyncDir = SyncDir

// CopyTreeDurable recursively copies src into dst (which must not exist),
// preserving file modes (including setuid/setgid/sticky bits), fsyncing
// each copied file before close, then fsyncing every created directory
// deepest-first so a child's entries are durable before the parent entry
// referencing it. This is the single shared implementation for the upgrade
// snapshot copy, the first-install seed copy, and staged-generation
// publish, which previously each carried an identical private copy
// (#17176).
func CopyTreeDurable(src, dst string, opt CopyTreeOptions) error {
	syncDir := opt.SyncDir
	if syncDir == nil {
		syncDir = copyTreeSyncDir
	}
	type ent struct {
		rel  string
		info os.FileInfo
		path string
	}
	var ents []ent
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		ents = append(ents, ent{rel: rel, info: info, path: p})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].rel < ents[j].rel })

	var createdDirs []string
	for _, e := range ents {
		target := filepath.Join(dst, e.rel)
		switch {
		case e.info.IsDir():
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
			// Preserve the SOURCE dir's permissions (MkdirAll applies the
			// umask and won't chmod an existing dir) so a copied tree is
			// not silently restricted to 0700 under a tight operator
			// umask, which would break non-root execution of copied
			// binaries via the sbin links.
			if err := os.Chmod(target, PreservedMode(e.info.Mode())); err != nil {
				return fmt.Errorf("chmod %s: %w", target, err)
			}
			createdDirs = append(createdDirs, target)
		case e.info.Mode().IsRegular():
			if err := CopyFileDurable(e.path, target, e.info.Mode()); err != nil {
				return err
			}
			if opt.Hash != nil {
				f, oerr := os.Open(target)
				if oerr != nil {
					return oerr
				}
				io.WriteString(opt.Hash, e.rel+"\x00")
				if _, cerr := io.Copy(opt.Hash, f); cerr != nil {
					f.Close()
					return cerr
				}
				f.Close()
			}
		default:
			return fmt.Errorf("CopyTreeDurable: unsupported file type for %s", e.path)
		}
	}
	// Fsync every copied directory. CopyFileDurable commits file
	// *contents*, but a newly-created directory entry (a file or a nested
	// subdir) is durable only once its parent directory fd is fsynced.
	// Callers fsync only the top-level copy root; nested dirs are NOT
	// covered there, so a power loss after the atomic rename could orphan
	// nested entries. Latent while the copied trees are flat, but this
	// makes the copy durable for any future nesting.
	if err := fsyncDirsDeepestFirst(createdDirs, syncDir); err != nil {
		return err
	}
	return nil
}

// fsyncDirsDeepestFirst fsyncs each directory deepest-first (by
// path-component depth, NOT string length — a deeper path can be shorter)
// so a child dir's entries are committed before the parent dir entry that
// references it. Correctness does not depend on order (every dir is
// fsynced, so every dentry becomes durable); the ordering only tightens
// the crash window.
func fsyncDirsDeepestFirst(dirs []string, syncDir func(string) error) error {
	ordered := append([]string(nil), dirs...)
	sort.Slice(ordered, func(i, j int) bool {
		di := strings.Count(ordered[i], string(os.PathSeparator))
		dj := strings.Count(ordered[j], string(os.PathSeparator))
		if di != dj {
			return di > dj
		}
		return ordered[i] > ordered[j]
	})
	for _, d := range ordered {
		if err := syncDir(d); err != nil {
			return fmt.Errorf("fsync copied dir %s: %w", d, err)
		}
	}
	return nil
}

// PreservedMode returns the chmod-applicable mode bits of m: the rwx
// permission bits PLUS the setuid/setgid/sticky special bits. m.Perm()
// alone masks the special bits off, so a setgid staged dir or setuid
// staged binary would lose those bits in the copy. (Staged content is
// 0755 today, so this is forward-looking exactness, not a current bug.)
func PreservedMode(m os.FileMode) os.FileMode {
	return m.Perm() | (m & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky))
}

// CopyFileDurable copies src -> dst with mode, fsyncing dst before close.
func CopyFileDurable(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	// OpenFile applies the umask to the create mode; chmod to the exact
	// source mode (incl. setuid/setgid/sticky) so copied binaries stay
	// 0755-executable regardless of the operator's umask.
	if err := out.Chmod(PreservedMode(mode)); err != nil {
		out.Close()
		return fmt.Errorf("chmod %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return fmt.Errorf("fsync %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dst, err)
	}
	return nil
}
