package router

import (
	"context"
	"slices"
	sync "sync"

	"github.com/xtls/xray-core/app/observatory"
	proxyman_outbound "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
)

type BalancingStrategy interface {
	PickOutbound([]string) string
}

type BalancingPrincipleTarget interface {
	GetPrincipleTarget([]string) []string
}

type RoundRobinStrategy struct {
	FallbackTag string

	ctx         context.Context
	observatory extension.Observatory
	mu          sync.Mutex
	index       int
}

func (s *RoundRobinStrategy) InjectContext(ctx context.Context) {
	s.ctx = ctx
	if len(s.FallbackTag) > 0 {
		common.Must(core.RequireFeatures(s.ctx, func(observatory extension.Observatory) error {
			s.observatory = observatory
			return nil
		}))
	}
}

func (s *RoundRobinStrategy) GetPrincipleTarget(strings []string) []string {
	return strings
}

func (s *RoundRobinStrategy) PickOutbound(tags []string) string {
	if s.observatory != nil {
		observeReport, err := s.observatory.GetObservation(s.ctx)
		if err == nil {
			aliveTags := make([]string, 0)
			if result, ok := observeReport.(*observatory.ObservationResult); ok {
				status := result.Status
				statusMap := make(map[string]*observatory.OutboundStatus)
				for _, outboundStatus := range status {
					statusMap[outboundStatus.OutboundTag] = outboundStatus
				}
				for _, candidate := range tags {
					if outboundStatus, found := statusMap[candidate]; found {
						if outboundStatus.Alive {
							aliveTags = append(aliveTags, candidate)
						}
					} else {
						// unfound candidate is considered alive
						aliveTags = append(aliveTags, candidate)
					}
				}
				tags = aliveTags
			}
		}
	}

	n := len(tags)
	if n == 0 {
		// goes to fallbackTag
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tag := tags[s.index%n]
	s.index = (s.index + 1) % n
	return tag
}

type Balancer struct {
	selectors    []string
	selectors_mu sync.RWMutex

	strategy    BalancingStrategy
	ohm         outbound.Manager
	fallbackTag string

	override override
}

func (b *Balancer) PickOutbound() (string, error) {
	candidates, err := b.SelectOutbounds()
	if err != nil {
		if b.fallbackTag != "" {
			errors.LogInfo(context.Background(), "fallback to [", b.fallbackTag, "], due to error: ", err)
			return b.fallbackTag, nil
		}
		return "", err
	}
	var tag string
	if o := b.override.Get(); o != "" {
		tag = o
	} else {
		tag = b.strategy.PickOutbound(candidates)
	}
	if tag == "" {
		if b.fallbackTag != "" {
			errors.LogInfo(context.Background(), "fallback to [", b.fallbackTag, "], due to empty tag returned")
			return b.fallbackTag, nil
		}
		// will use default handler
		return "", errors.New("balancing strategy returns empty tag")
	}
	return tag, nil
}

func (b *Balancer) InjectContext(ctx context.Context) {
	if contextReceiver, ok := b.strategy.(extension.ContextReceiver); ok {
		contextReceiver.InjectContext(ctx)
	}
}

// SelectOutbounds select outbounds with selectors of the Balancer
func (b *Balancer) SelectOutbounds() ([]string, error) {
	hs, ok := b.ohm.(outbound.HandlerSelector)
	if !ok {
		return nil, errors.New("outbound.Manager is not a HandlerSelector")
	}
	b.selectors_mu.RLock()
	defer b.selectors_mu.RUnlock()
	return hs.Select(b.selectors), nil
}

func (r *Router) PickBalancerOutbound(balancerTag string) (string, error) {
	balancer, ok := r.getbalancer(balancerTag)
	if !ok {
		return "", errors.New("balancer ", balancerTag, " not found")
	}
	return balancer.PickOutbound()
}

func (r *Router) SelectBalancerOutbounds(balancerTag string) ([]string, error) {
	balancer, ok := r.getbalancer(balancerTag)
	if !ok {
		return nil, errors.New("balancer ", balancerTag, " not found")
	}
	return balancer.SelectOutbounds()
}

func (r *Router) SetBalancerSelectors(balancerTag string, selectors []string) error {
	balancer, ok := r.getbalancer(balancerTag)
	if !ok {
		return errors.New("balancer ", balancerTag, " not found")
	}
	manager, ok := balancer.ohm.(*proxyman_outbound.Manager)
	if !ok {
		return errors.New("outbound.Manager is not a Manager")
	}
	manager.ClearTagsCache()

	balancer.selectors_mu.Lock()
	defer balancer.selectors_mu.Unlock()
	balancer.selectors = slices.Clone(selectors)
	return nil
}

// GetPrincipleTarget implements routing.BalancerPrincipleTarget
func (r *Router) GetPrincipleTarget(tag string) ([]string, error) {
	if b, ok := r.getbalancer(tag); ok {
		if s, ok := b.strategy.(BalancingPrincipleTarget); ok {
			candidates, err := b.SelectOutbounds()
			if err != nil {
				return nil, errors.New("unable to select outbounds").Base(err)
			}
			return s.GetPrincipleTarget(candidates), nil
		}
		return nil, errors.New("unsupported GetPrincipleTarget")
	}
	return nil, errors.New("cannot find tag")
}

// SetOverrideTarget implements routing.BalancerOverrider
func (r *Router) SetOverrideTarget(tag, target string) error {
	if b, ok := r.getbalancer(tag); ok {
		b.override.Put(target)
		return nil
	}
	return errors.New("cannot find tag")
}

// GetOverrideTarget implements routing.BalancerOverrider
func (r *Router) GetOverrideTarget(tag string) (string, error) {
	if b, ok := r.getbalancer(tag); ok {
		return b.override.Get(), nil
	}
	return "", errors.New("cannot find tag")
}
