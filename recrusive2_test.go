package dnsrecursive

import (
	"log"
	"log/slog"
	"net/netip"
	"os"
	"testing"

	"github.com/hnakamur/dnsrecursive/dnsplay"
)

func TestResolver2(t *testing.T) {
	h, level := newSlogJSONHandlerAndLevel(os.Stdout)
	slog.SetDefault(slog.New(h))
	level.Set(slog.LevelDebug)

	testCases := []struct {
		scenarioFilename  string
		rootServerAddress string
		name              string
		qType             string
	}{
		{
			scenarioFilename:  "testdata/www.jprs.jp_A_scenario.yaml",
			rootServerAddress: "202.12.27.33",
			name:              "www.jprs.jp.",
			qType:             "A",
		},
		{
			scenarioFilename:  "testdata/www.ietf.org_AAAA_scenario.yaml",
			rootServerAddress: "198.41.0.4",
			name:              "www.ietf.org.",
			qType:             "AAAA",
		},
	}
	for _, tc := range testCases {
		slog.Debug("=== testcase start ===")
		scenarioBytes, err := os.ReadFile(tc.scenarioFilename)
		if err != nil {
			log.Fatal(err)
		}
		scenario := dnsplay.MustLoadScenario(scenarioBytes)
		mc := dnsplay.NewMockClient(*scenario)
		addr := netip.MustParseAddr(tc.rootServerAddress)
		c := NewResolver2(mc, []netip.Addr{addr})
		rr, err := c.LookupRecord(t.Context(), tc.name, tc.qType)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("rr=%+v", rr)
	}
}
