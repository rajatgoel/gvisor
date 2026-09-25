// Copyright 2024 The gVisor Authors.
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

package stack

import (
	"context"
	"encoding/binary"
	"math/rand"

	cryptorand "gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// beforeSave is invoked by stateify.
func (s *Stack) beforeSave() {
	s.mu.Lock()
	s.retainedNICs = make(map[tcpip.NICID]*nic)
	for id, n := range s.nics {
		if n.retainedAcrossRestore() {
			s.retainedNICs[id] = n
		}
	}
	s.retainedAddrs = make(map[tcpip.NICID][]retainedAddress)
	for id, n := range s.retainedNICs {
		s.retainedAddrs[id] = n.staticAddresses()
	}
	s.retainedPorts = make(map[string]tcpip.NICID)
	for _, n := range s.nics {
		if _, ok := s.retainedNICs[n.id]; ok || n.Primary == nil {
			continue
		}
		if _, ok := s.retainedNICs[n.Primary.id]; ok {
			s.retainedPorts[n.Name()] = n.Primary.id
		}
	}
	s.retainedRoutes = nil
	for _, r := range s.GetRouteTable() {
		if _, ok := s.retainedNICs[r.NIC]; ok {
			s.retainedRoutes = append(s.retainedRoutes, r)
		}
	}

	// removeConf will be set only in case of save/restore.
	if !s.removeConf {
		s.mu.Unlock()
		return
	}

	// Remove all the host-backed NICs and routes from the stack as they will
	// be created again during restore based on the new network config.
	deferActs := make([]func(), 0)
	for id := range s.nics {
		if _, ok := s.retainedNICs[id]; ok {
			continue
		}
		act, _ := s.removeNICLocked(id, true /* closeLinkEndpoint */)
		if act != nil {
			deferActs = append(deferActs, act)
		}
	}
	s.mu.Unlock()

	for _, act := range deferActs {
		act()
	}
}

// afterLoad is invoked by stateify.
func (s *Stack) afterLoad(context.Context) {
	var v int64
	if err := binary.Read(cryptorand.Reader, binary.LittleEndian, &v); err != nil {
		panic(err)
	}
	randSrc := &lockedRandomSource{src: rand.NewSource(v)}
	s.insecureRNG = rand.New(randSrc)
	s.secureRNG = cryptorand.RNGFrom(cryptorand.Reader)
}
