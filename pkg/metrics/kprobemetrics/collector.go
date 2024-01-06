// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package kprobemetrics

import (
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

// bpfCollector implements prometheus.Collector. It collects metrics directly from BPF maps.
type bpfCollector struct{}

func NewBPFCollector() prometheus.Collector {
	return &bpfCollector{}
}

func (c *bpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- MissedProbes.Desc()
}

func (c *bpfCollector) Collect(ch chan<- prometheus.Metric) {
	allPrograms := sensors.AllPrograms()
	for _, prog := range allPrograms {

		if prog.Link == nil {
			continue
		}

		info, err := prog.Link.Info()
		if err != nil {
			continue
		}

		missed := uint64(0)

		switch info.Type {
		case link.PerfEventType:
			if bpf.HasMissedStatsPerfEvent() {
				pevent := info.PerfEvent()
				switch pevent.Type {
				case unix.BPF_PERF_EVENT_KPROBE, unix.BPF_PERF_EVENT_KRETPROBE:
					kprobe := pevent.Kprobe()
					missed, _ = kprobe.Missed()
				}
			}
		case link.KprobeMultiType:
			if bpf.HasMissedStatsKprobeMulti() {
				kmulti := info.KprobeMulti()
				missed, _ = kmulti.Missed()
			}
		default:
		}

		ch <- MissedProbes.MustMetric(float64(missed), prog.Policy, prog.Attach)
	}
}

// bpfZeroCollector implements prometheus.Collector. It collects "zero" metrics.
// It's intended to be used when BPF metrics are not collected, but we still want
// Prometheus metrics to be exposed.
type bpfZeroCollector struct {
	bpfCollector
}

func NewBPFZeroCollector() prometheus.Collector {
	return &bpfZeroCollector{
		bpfCollector: bpfCollector{},
	}
}

func (c *bpfZeroCollector) Describe(ch chan<- *prometheus.Desc) {
	c.bpfCollector.Describe(ch)
}

func (c *bpfZeroCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- MissedProbes.MustMetric(0, "policy", "attach")
}
