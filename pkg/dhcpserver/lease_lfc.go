package dhcpserver

import "os"

// Kea Lease File Cleanup (LFC) file-set naming + read order (#5796).
//
// Kea's memfile backend never rewrites the lease file in place between LFC
// compactions — every renewal / release / decline / expiry-reclaim is APPENDED
// — and it periodically runs kea-lfc to compact the log. During AND after a
// cleanup the live lease set is NOT the current file alone; it spans Kea's LFC
// file set. Reading only the current file loses every lease that currently
// lives in the previous or input file: right after LFC rotates the current
// file, that file is a fresh (often header-only) append log while the active
// leases sit in the compacted previous file. A header-only current file must
// therefore never by itself authorize the destructive DDNS trusted-empty diff.
//
// File naming is authoritative from Kea source
// (src/lib/dhcpsrv/memfile_lease_mgr.cc, appendSuffix / LFCFileType) for a
// current lease file <f>:
//
//	<f>            CURRENT  — the live append log the server writes now.
//	<f>.1          INPUT    — the current file the server MOVES ASIDE at the
//	                          START of a cleanup; kea-lfc reads it. Present only
//	                          while a cleanup is in progress (or left behind by a
//	                          crashed cleanup).
//	<f>.2          PREVIOUS — the COMPACTED result of the last COMPLETED cleanup
//	                          (one row per active lease). Present once any LFC
//	                          has run.
//	<f>.output     kea-lfc's temporary compaction output.
//	<f>.completed  kea-lfc's finished, lease-bearing compacted output.
//	<f>.pid        kea-lfc's pid file.
//
// Kea's startup loader gives .completed precedence over .2/.1 when it exists
// (memfile_lease_mgr.cc loadLeasesFromFiles). The reader must use the same
// source selection: an existing .completed is authoritative over the older
// generation files, while the current append log remains newer. If no
// .completed exists, the reader falls back to .2 → .1 → current.
//
// #5938 Invariant 3 — crash-interrupted-cleanup handling for the display/DDNS
// reader. A cleanup can leave `.output` and/or `.completed` behind. `.output`
// is safe to skip because it is built by merging INPUT (.1) and PREVIOUS (.2);
// every lease key it could contain is already in the .1/.2 union. `.completed`
// is different: it is lease-bearing and Kea startup gives it precedence over
// `.2`/.1. Kea's rotation removes old `.2`, removes `.1`, then renames
// `.completed` to `.2`; a crash between those removals and the rename can leave
// leases only in `.completed`. The reader therefore recovers it and preserves
// Kea's precedence instead of treating it as an ignored intermediate.
//
// NOTE the suffix mapping: .1 is INPUT and .2 is PREVIOUS. Without a
// .completed file, the chronological read order (oldest → newest) is
// .2 → .1 → current: previous-compacted snapshot first, then input file, then
// current append log.
//
// keaLFCLeaseFileSetPaths returns all names whose identity matters to a
// stability check. Selection is intentionally separate: callers snapshot this
// complete set BEFORE deciding which generation to parse, so a `.completed`
// file that appears during selection cannot be missed by the rotation guard.
func keaLFCLeaseFileSetPaths(current string) []string {
	return []string{current + ".completed", current + ".2", current + ".1", current}
}

// keaLFCLeaseFilePaths returns the candidate paths in Kea's source-selection
// order. It is the convenience form for callers without an already captured
// identity snapshot; parseActiveLeases uses keaLFCLeaseFileSetPaths plus
// keaLFCLeaseFilePathsFromIdentity to close the selection/stability race.
func keaLFCLeaseFilePaths(current string) []string {
	all := keaLFCLeaseFileSetPaths(current)
	return keaLFCLeaseFilePathsFromIdentity(all, leaseSetIdentity(all))
}

// keaLFCLeaseFilePathsFromIdentity selects Kea's authoritative source from a
// pre-read identity snapshot. An existing or inaccessible `.completed` is
// selected so its parser fails closed instead of silently falling back.
func keaLFCLeaseFilePathsFromIdentity(all []string, identities []os.FileInfo) []string {
	if len(all) > 0 && len(identities) > 0 {
		if identities[0] != nil {
			return []string{all[0], all[len(all)-1]}
		}
		if _, err := os.Stat(all[0]); err == nil || !os.IsNotExist(err) {
			return []string{all[0], all[len(all)-1]}
		}
	}
	if len(all) < 1 {
		return nil
	}
	return all[1:]
}
