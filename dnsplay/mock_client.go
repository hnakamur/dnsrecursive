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
	if c.step >= len(c.scenario.Exchanges) {
		return nil, 0, fmt.Errorf("failed to exchange: unexpected to be called more than %d times", len(c.scenario.Exchanges))
	}
	xchg := &c.scenario.Exchanges[c.step]
	c.step++
	if err := xchg.Query.chcekInput(m, network, address); err != nil {
		return nil, 0, fmt.Errorf("failed to exchange: step=%d, err=%s", c.step, err)
	}

	if xchg.Response.Error != "" {
		return nil, 0, errors.New(xchg.Response.Error)
	}
	r, err = xchg.Response.ToMsg(m)
	return r, 0, err
}
