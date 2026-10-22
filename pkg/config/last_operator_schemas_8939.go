package config

// archivalConfigurationSchema8939 resolves `system archival configuration`.
func archivalConfigurationSchema8939() *schemaNode {
	return refSystemArchivalConfig.resolve()
}

// rpmProbeTestSchema8939 resolves `services rpm probe <p> test <t>`.
func rpmProbeTestSchema8939() *schemaNode {
	return refRPMProbeTest.resolve()
}

// rpmThresholdsSchema14615 resolves `services rpm probe <p> test <t>
// thresholds` so compileRPM can expand the one-line spelling
// `thresholds successive-loss N;` through the same schema the block
// spelling is validated against (#14615).
func rpmThresholdsSchema14615() *schemaNode {
	return refRPMThresholds.resolve()
}
