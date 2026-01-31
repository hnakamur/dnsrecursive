package dnsplay

import "go.yaml.in/yaml/v4"

type Scenario struct {
	Name        string
	Description string
	Exchanges   []Exchange
}

func MustLoadScenario(p []byte) *Scenario {
	s, err := LoadScenario(p)
	if err != nil {
		panic("failed to unmarshal scenario")
	}
	return s
}

func LoadScenario(p []byte) (*Scenario, error) {
	var s Scenario
	if err := yaml.Unmarshal(p, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func DumpScenario(s *Scenario) ([]byte, error) {
	return yaml.Dump(s, yaml.WithIndent(2))
}
