package api

func newCollector(srv *Server) *xpfCollector {
	c := &xpfCollector{srv: srv}
	c.initGlobalDescriptors()
	c.initHostInboundDescriptors()
	c.initForwardingDescriptors()
	c.initInterfaceDescriptors()
	c.initZoneDescriptors()
	c.initPolicyDescriptors()
	c.initSessionDescriptors()
	c.initNATDescriptors()
	c.initDHCPDescriptors()
	c.initSystemDescriptors()
	c.initControlPlaneDescriptors()
	c.initAutomationDescriptors()
	c.initSyslogDropDescriptors()
	c.initFlowExportBuildDescriptors()
	c.initIPMonitoringDescriptors()
	c.initCoSDescriptors()
	c.initWorkerDescriptors()
	c.initUserspaceSessionDescriptors()
	c.initUserspaceDropsDescriptors()
	c.initSlowPathDescriptors()
	c.initUserspaceStreamDescriptors()
	c.initColdPathDescriptors()
	c.initBindingDescriptors()
	c.initFairnessDescriptors()
	c.initNeighborDescriptors()
	c.initWireGuardDescriptors()
	c.initFlowExportDescriptors()
	return c
}
