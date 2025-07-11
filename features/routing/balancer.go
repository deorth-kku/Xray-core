package routing

type BalancerOverrider interface {
	SetOverrideTarget(tag, target string) error
	GetOverrideTarget(tag string) (string, error)
}

type BalancerPrincipleTarget interface {
	GetPrincipleTarget(tag string) ([]string, error)
}

type BalancerManager interface {
	SelectBalancerOutbounds(balancerTag string) ([]string, error)
	SetBalancerSelectors(balancerTag string, selectors []string) error
	PickBalancerOutbound(balancerTag string) (string, error)
}
