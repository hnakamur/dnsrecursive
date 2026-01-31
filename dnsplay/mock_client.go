package dnsplay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"codeberg.org/miekg/dns"
)

type MockClient struct {
	scenario Scenario
	step     int
}

func NewMockClient(scenario Scenario) *MockClient {
	return &MockClient{
		scenario: scenario,
	}
}

const dnsPortStr = "53"

func (c *MockClient) Exchange(ctx context.Context, m *dns.Msg, network, address string) (r *dns.Msg, rtt time.Duration, err error) {
	if c.step >= len(c.scenario.Responses) {
		return nil, 0, fmt.Errorf("failed to exchange: unexpected to be called more than %d times", len(c.scenario.Responses))
	}
	resp := &c.scenario.Responses[c.step]
	c.step++
	if err := resp.Query.chcekInput(m, network, address); err != nil {
		return nil, 0, fmt.Errorf("failed to exchange: step=%d, err=%s", c.step, err)
	}

	if resp.Error != "" {
		return nil, 0, errors.New(resp.Error)
	}
	r, err = resp.ToMsg(m)
	return r, 0, err
}
