package main

import (
	"sync"

	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
)

type (
	storagePolicyService struct {
		mu       *sync.RWMutex
		provider servicePolicyProvider
	}

	servicePolicyProvider interface {
		GetPlacementPolicy(userAddr util.Uint160, policyName string) (*layer.PlacementPolicy, error)
		GetDefaultPolicy() (layer.PlacementPolicy, error)
	}
)

func newStoragePolicyService(provider servicePolicyProvider) *storagePolicyService {
	return &storagePolicyService{
		provider: provider,
		mu:       &sync.RWMutex{},
	}
}

func (s *storagePolicyService) GetPlacementPolicy(userAddr util.Uint160, policyName string) (*layer.PlacementPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.provider.GetPlacementPolicy(userAddr, policyName)
}

func (s *storagePolicyService) GetDefaultPolicy() (layer.PlacementPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.provider.GetDefaultPolicy()
}

func (s *storagePolicyService) UpdateProvider(p servicePolicyProvider) {
	s.mu.Lock()
	s.provider = p
	s.mu.Unlock()
}
