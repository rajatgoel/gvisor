// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nvconf

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/log"
)

// HostSettings contains properties of the host Nvidia driver that must be
// observed before filter installation, or entering a chroot or pivot_root.
type HostSettings struct {
	// ProcDriverNvidiaParams is the contents of /proc/driver/nvidia/params.
	ProcDriverNvidiaParams string

	// If HaveFabricIMEXManagement is true, FabricIMEXManagementDevMinor is the
	// device minor number advertised in
	// /proc/driver/nvidia/capabilities/fabric-imex-mgmt.
	HaveFabricIMEXManagement     bool
	FabricIMEXManagementDevMinor uint32

	// MIGCaps are the MIG capabilities advertised under
	// /proc/driver/nvidia/capabilities/gpu#/mig/.
	MIGCaps []MIGCap
}

// MIGCap describes one MIG capability advertised by the host driver.
type MIGCap struct {
	// ProcPath is the capability's path relative to
	// /proc/driver/nvidia/capabilities/, e.g. "gpu0/mig/gi3/access".
	ProcPath string

	// DevMinor is DeviceFileMinor, the minor number of the corresponding
	// /dev/nvidia-caps/nvidia-cap# file.
	DevMinor uint32

	// Mode is DeviceFileMode.
	Mode uint32
}

// HostSettingsOptions holds arguments to GetHostSettings.
type HostSettingsOptions struct {
	// If WantFabricIMEXManagement is true, ensure that
	// HaveFabricIMEXManagement and FabricIMEXManagementDevMinor are set in the
	// returned HostSettings.
	WantFabricIMEXManagement bool

	// If WantMIGCaps is true, populate MIGCaps in the returned HostSettings.
	WantMIGCaps bool
}

// GetHostSettings returns HostSettings.
func GetHostSettings(opts HostSettingsOptions) (*HostSettings, error) {
	settings := &HostSettings{}

	params, err := os.ReadFile("/proc/driver/nvidia/params")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/driver/nvidia/params: %w", err)
	}
	settings.ProcDriverNvidiaParams = string(params)

	if opts.WantFabricIMEXManagement {
		fabricImexMgmt, err := os.ReadFile("/proc/driver/nvidia/capabilities/fabric-imex-mgmt")
		if err != nil {
			return nil, fmt.Errorf("failed to read /proc/driver/nvidia/capabilities/fabric-imex-mgmt: %w", err)
		}
		m := regexp.MustCompile(`DeviceFileMinor: (\d+)`).FindSubmatch(fabricImexMgmt)
		if m == nil {
			return nil, fmt.Errorf("failed to find DeviceFileMinor in /proc/driver/nvidia/capabilities/fabric-imex-mgmt")
		}
		minor, err := strconv.ParseUint(string(m[1]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DeviceFileMinor %s: %w", string(m[1]), err)
		}
		settings.HaveFabricIMEXManagement = true
		settings.FabricIMEXManagementDevMinor = uint32(minor)
	}

	if opts.WantMIGCaps {
		migCaps, err := getMIGCaps()
		if err != nil {
			return nil, err
		}
		settings.MIGCaps = migCaps
	}

	return settings, nil
}

const procDriverNvidiaCapabilities = "/proc/driver/nvidia/capabilities"

var capFileRegexp = regexp.MustCompile(`DeviceFileMinor: (\d+)\nDeviceFileMode: (\d+)`)

// getMIGCaps returns the MIG GPU instance and compute instance capabilities
// advertised by the host driver. MIG scopes a container to a GPU instance by
// the /dev/nvidia-caps/nvidia-cap# files it can open, and libnvidia-container
// maps instances to minor numbers through this procfs tree; see
// nvidia-container-toolkit's internal/info/proc/devices and
// libnvidia-container's src/nvcap.c.
func getMIGCaps() ([]MIGCap, error) {
	// The tree only exists when at least one GPU has MIG enabled.
	giPaths, err := filepath.Glob(procDriverNvidiaCapabilities + "/gpu*/mig/gi*/access")
	if err != nil {
		return nil, err
	}
	ciPaths, err := filepath.Glob(procDriverNvidiaCapabilities + "/gpu*/mig/gi*/ci*/access")
	if err != nil {
		return nil, err
	}
	var caps []MIGCap
	for _, path := range append(giPaths, ciPaths...) {
		contents, err := os.ReadFile(path)
		if err != nil {
			// The tree changes as instances are created and destroyed, so a
			// file disappearing between the glob and the read is expected.
			log.Warningf("Failed to read %s: %v", path, err)
			continue
		}
		m := capFileRegexp.FindSubmatch(contents)
		if m == nil {
			return nil, fmt.Errorf("failed to parse %s", path)
		}
		minor, err := strconv.ParseUint(string(m[1]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DeviceFileMinor in %s: %w", path, err)
		}
		mode, err := strconv.ParseUint(string(m[2]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DeviceFileMode in %s: %w", path, err)
		}
		caps = append(caps, MIGCap{
			ProcPath: strings.TrimPrefix(path, procDriverNvidiaCapabilities+"/"),
			DevMinor: uint32(minor),
			Mode:     uint32(mode),
		})
	}
	return caps, nil
}

// EncodeMIGCaps serializes caps for transport to the sentry as a flag value.
func EncodeMIGCaps(caps []MIGCap) string {
	entries := make([]string, 0, len(caps))
	for _, c := range caps {
		entries = append(entries, fmt.Sprintf("%s:%d:%d", c.ProcPath, c.DevMinor, c.Mode))
	}
	return strings.Join(entries, ",")
}

// DecodeMIGCaps is the inverse of EncodeMIGCaps.
func DecodeMIGCaps(str string) ([]MIGCap, error) {
	if str == "" {
		return nil, nil
	}
	entries := strings.Split(str, ",")
	caps := make([]MIGCap, 0, len(entries))
	for _, entry := range entries {
		fields := strings.Split(entry, ":")
		if len(fields) != 3 {
			return nil, fmt.Errorf("invalid MIG capability %q", entry)
		}
		minor, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid minor in MIG capability %q: %w", entry, err)
		}
		mode, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid mode in MIG capability %q: %w", entry, err)
		}
		caps = append(caps, MIGCap{ProcPath: fields[0], DevMinor: uint32(minor), Mode: uint32(mode)})
	}
	return caps, nil
}

// IMEXChannelCount returns the number of IMEX channels indicated by
// /proc/driver/nvidia/params. See description of NVreg_ImexChannelCount in the
// Nvidia GPU driver's kernel-open/nvidia/nv-reg.h.
func (s *HostSettings) IMEXChannelCount() uint32 {
	m := regexp.MustCompile(`ImexChannelCount: (\d+)`).FindStringSubmatch(s.ProcDriverNvidiaParams)
	if m == nil {
		return 0
	}
	imexChannelCount, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		log.Warningf("Failed to parse ImexChannelCount %s: %v", m[1], err)
		return 0
	}
	return uint32(imexChannelCount)
}
