package api

// newCollector builds a collector with every descriptor initialized.
// #16202: the per-family init list is driven by collectorDescFamilies
// (metrics_descriptor_table.go), the same table Describe iterates, so
// adding a family is one table row instead of separate init and
// Describe edits. Every family's init — including dataplane-safety —
// runs eagerly here, so its descriptors are allocated at construction.
func newCollector(srv *Server) *xpfCollector {
	c := &xpfCollector{deps: collectorDepsFromServer(srv)}
	for _, fam := range collectorDescFamilies {
		fam.init(c)
	}
	return c
}
