// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	CgrpNsMapName      = "cgroup_namespace_map"
	namespaceCacheSize = 1024
)

// ExecObj returns the exec object based on the kernel version
func execObj() string {
	if kernels.EnableV61Progs() {
		return "bpf_execve_event_v61.o"
	} else if kernels.MinKernelVersion("5.11") {
		return "bpf_execve_event_v511.o"
	} else if kernels.EnableLargeProgs() {
		return "bpf_execve_event_v53.o"
	}
	return "bpf_execve_event.o"
}

// NamespaceMap is a simple wrapper for ebpf.Map so that we can write methods for it
type NamespaceMap struct {
	cgroupIdMap *ebpf.Map
	nsIdMap     *lru.Cache[uint64, string]
	id          uint64
}

// newNamespaceMap returns a new namespace mapping. The namespace map consists of
// two pieces. First a cgroup to ID map. The ID is useful for BPF so we can avoid
// strings in BPF side. Then a stable ID to namespace mapping.
func newNamespaceMap() (*NamespaceMap, error) {
	cache, err := lru.New[uint64, string](namespaceCacheSize)
	if err != nil {
		return nil, fmt.Errorf("create namespace ID cache failed")
	}

	objName := execObj()
	objPath := path.Join(option.Config.HubbleLib, objName)
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("loading spec for %s failed: %w", objPath, err)
	}
	nsMapSpec, ok := spec.Maps[CgrpNsMapName]
	if !ok {
		return nil, fmt.Errorf("%s not found in %s", CgrpNsMapName, objPath)
	}

	ret, err := ebpf.NewMap(nsMapSpec)
	if err != nil {
		return nil, err
	}

	mapDir := bpf.MapPrefixPath()
	pinPath := filepath.Join(mapDir, CgrpNsMapName)
	os.Remove(pinPath)
	os.Mkdir(mapDir, os.ModeDir)
	err = ret.Pin(pinPath)
	if err != nil {
		ret.Close()
		return nil, fmt.Errorf("failed to pin Namespace map in %s: %w", pinPath, err)
	}

	return &NamespaceMap{
		cgroupIdMap: ret,
		nsIdMap:     cache,
	}, err
}

// release closes the namespace BPF map, removes (unpin) the bpffs file.
// Then the LRU cache is cleared.
func (m NamespaceMap) release() error {
	if err := m.cgroupIdMap.Close(); err != nil {
		return err
	}

	// nolint:revive // ignore "if-return: redundant if just return error" for clarity
	if err := m.cgroupIdMap.Unpin(); err != nil {
		return err
	}

	m.nsIdMap.Purge()
	return nil
}

func (m NamespaceMap) readBpf() (map[uint64]uint64, error) {
	var mapping map[uint64]uint64
	var err error

	file := filepath.Join(bpf.MapPrefixPath(), CgrpNsMapName)

	m.cgroupIdMap, err = ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("Could not open process tree map")
		return mapping, err
	}

	defer m.cgroupIdMap.Close()

	var (
		key uint64
		val uint64
	)

	iter := m.cgroupIdMap.Iterate()
	for iter.Next(&key, &val) {
		mapping[key] = val
	}

	return mapping, nil
}

func (m NamespaceMap) readNamespace(cgrps map[uint64]uint64) (map[uint64]string, error) {
	var mapping map[uint64]string

	for _, k := range cgrps {
		v, ok := m.nsIdMap.Get(k)
		if ok == false {
			logger.GetLogger().WithField("cgrpid", k).Warn("Cgrpid not in namespace mapping")
			continue
		}
		mapping[k] = v
	}
	return mapping, nil
}

// addCgroupIDs add cgroups ids to the policy map
// todo: use batch operations when supported
func (m NamespaceMap) addCgroupIDs(cinfo []containerInfo) error {
	for _, c := range cinfo {
		if err := m.cgroupIdMap.Update(&c.cgID, m.id, ebpf.UpdateAny); err != nil {
			logger.GetLogger().WithError(err).WithField("cgid", c.cgID).WithField("id", m.id).WithField("ns", c.name).Warn("Unable to insert cgroup id map")
			continue
		}
		if ok := m.nsIdMap.Add(m.id, c.name); ok != false {
			logger.GetLogger().WithField("cgid", c.cgID).WithField("id", m.id).WithField("ns", c.name).Warn("Id to namespace map caused eviction")
		}
		m.id++
	}

	return nil
}
