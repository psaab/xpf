package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initUserspaceIoUring13292Descriptors() {
	c.userspaceIoUringActive = prometheus.NewDesc(
		"xpf_userspace_io_uring_active",
		"Whether the state writer is actively using io_uring rather than synchronous writes.",
		nil, nil,
	)
	c.userspaceIoUringRetainedBuffers = prometheus.NewDesc(
		"xpf_userspace_io_uring_retained_buffers_total",
		"Cumulative number of io_uring write buffers retained because teardown could not prove the kernel had stopped referencing them.",
		nil, nil,
	)
	c.userspaceIoUringRetainedBytes = prometheus.NewDesc(
		"xpf_userspace_io_uring_retained_bytes_total",
		"Cumulative bytes in io_uring write buffers retained because teardown could not prove the kernel had stopped referencing them.",
		nil, nil,
	)
}
