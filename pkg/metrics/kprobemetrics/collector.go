// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package kprobemetrics

import (
	"fmt"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
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

type KprobeStatsValue struct {
	Id      uint64
	Nmissed uint64
	Hit     uint64
}

func kprobeMissed(lnk link.Link) uint64 {
	fmt.Printf("KRAVA kprobeMissed1\n")
	pe, ok := lnk.(link.PerfEvent)
	if !ok {
		return 0
	}

	file, err := pe.PerfEvent()
	if err != nil {
		return 0
	}

	fd := int(file.Fd())

	fmt.Printf("KRAVA kprobeMissed2 fd %d\n", fd)

	id, err := unix.IoctlGetInt(fd, unix.PERF_EVENT_IOC_ID)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to get kprobe event ID")
	}

	v := &KprobeStatsValue{
		Id:      uint64(id),
		Nmissed: 0,
		Hit:     0,
	}
	base.KprobeStatsMap.MapHandle.Put(uint32(0), v)

	var buf []byte
	syscall.Read(fd, buf)

	err = base.KprobeStatsMap.MapHandle.Lookup(int32(0), v)

	if err == nil {
		fmt.Printf("KRAVA id %d hit %d missed %d\n", id, v.Hit, v.Nmissed)
	} else {
		fmt.Printf("ERROR %v\n", err)
	}

	file.Close()
	return v.Nmissed
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
			} else {
				missed = kprobeMissed(prog.Link)
			}
		case link.KprobeMultiType:
			if bpf.HasMissedStatsKprobeMulti() {
				kmulti := info.KprobeMulti()
				missed, _ = kmulti.Missed()
			} else {
				// warn
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
