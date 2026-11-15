//go:build !xpf_faultinject

package daemon

// faultinjectBulkExport19115 is the release twin of the #19115 lab fault
// (faultinject_bulk_export_19115.go, built only with -tags xpf_faultinject):
// it never fails and holds no state.
func faultinjectBulkExport19115() error { return nil }
