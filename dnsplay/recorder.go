package dnsplay

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"

	"codeberg.org/miekg/dns"
	"go.yaml.in/yaml/v4"
)

type RecorderInput struct {
	Name        string
	Description string
	Queries     []Query
}

func LoadRecorderInput(p []byte) (*RecorderInput, error) {
	var i RecorderInput
	if err := yaml.Unmarshal(p, &i); err != nil {
		return nil, err
	}
	return &i, nil
}

type Recorder struct{}

func (r *Recorder) RunFile(ctx context.Context, inputFilename, outputFilename string) error {
	inputData, err := os.ReadFile(inputFilename)
	if err != nil {
		return err
	}
	input, err := LoadRecorderInput(inputData)
	if err != nil {
		return err
	}
	scenario, err := r.Run(ctx, input)
	if err != nil {
		return err
	}
	scenarioData, err := DumpScenario(scenario)
	if err != nil {
		return err
	}
	return os.WriteFile(outputFilename, scenarioData, 0o644)
}

func (r *Recorder) Run(ctx context.Context, input *RecorderInput) (*Scenario, error) {
	s := &Scenario{
		Name:        input.Name,
		Description: input.Description,
		Exchanges:   make([]Exchange, len(input.Queries)),
	}

	for i, q := range input.Queries {
		resp, err := r.runQuery(ctx, q)
		if err != nil {
			return nil, err
		}
		s.Exchanges[i] = *resp
	}
	return s, nil
}

func (r *Recorder) runQuery(ctx context.Context, q Query) (*Exchange, error) {
	qtype, ok := dns.StringToType[q.QType]
	if !ok {
		return nil, fmt.Errorf("recorder failed to run query, unsupported qtype=%s", q.QType)
	}

	addr, err := netip.ParseAddr(q.Nameserver)
	if err != nil {
		return nil, fmt.Errorf("recorder failed to run query, cannot parse nameserver address: %s", q.Nameserver)
	}

	m := dns.NewMsg(q.Name, qtype)
	setHeaderFlagsByStrings(m, q.Flags)
	respMsg, err := dns.Exchange(ctx, m, q.Protocol, net.JoinHostPort(q.Nameserver, dnsPortStr))
	if err != nil {
		return nil, fmt.Errorf("recorder failed to run query, %s", err)
	}

	return NewExchangeFromMsg(addr, q.Protocol, m, respMsg), nil
}
