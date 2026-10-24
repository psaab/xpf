package api

// newCollector builds a collector with every descriptor initialized.
// #16202: the per-family init list is driven by collectorDescFamilies
// (metrics_descriptor_table.go), the same table Describe iterates, so
// adding a family is one table row instead of separate init and
// Describe edits. The dataplane-safety family keeps its sync.Once
// laziness inside its init, so calling it eagerly here does not
// allocate its descriptors until first use is requested — the Once
// still defers the NewDesc calls to Describe/Collect time.
func newCollector(srv *Server) *xpfCollector {
	c := &xpfCollector{srv: srv}
	for _, fam := range collectorDescFamilies {
		fam.init(c)
	}
	return c
}
