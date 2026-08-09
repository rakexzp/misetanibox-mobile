package convert

import (
	"strings"
	"testing"

	"misetanibox/mobilecore/internal/xray"
)

// balancerConfig is a configuration with three balanced nodes and one plain
// node, which is the shape a panel emits.
const balancerConfig = `[{
	"remarks": "Germany",
	"outbounds": [
		{"tag":"proxy-de-1","protocol":"vless","settings":{"vnext":[{"address":"de1.example.com",
			"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}},
		{"tag":"proxy-de-2","protocol":"vless","settings":{"vnext":[{"address":"de2.example.com",
			"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}},
		{"tag":"proxy-de-3","protocol":"vless","settings":{"vnext":[{"address":"de3.example.com",
			"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}},
		{"tag":"direct","protocol":"freedom"}
	],
	"routing": {
		"balancers": [{"tag":"balancer","selector":["proxy-de"],"strategy":{"type":"leastPing"}}],
		"rules": [{"type":"field","network":"tcp,udp","balancerTag":"balancer"}]
	}
}]`

func convertWith(t *testing.T, jsonText string, opts Options) *Result {
	t.Helper()
	configs, err := xray.ParseConfigs([]byte(jsonText))
	if err != nil {
		t.Fatalf("ParseConfigs: %v", err)
	}
	res, err := Convert(configs, opts)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	return res
}

func TestBalancerBecomesOneGroup(t *testing.T) {
	res := convertWith(t, balancerConfig, DefaultOptions())

	// Every node is still defined; mihomo needs them to build the group.
	if len(res.Proxies) != 3 {
		t.Fatalf("got %d proxies, want 3", len(res.Proxies))
	}
	if len(res.Groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(res.Groups))
	}

	g := res.Groups[0]
	if g.Type != "url-test" {
		t.Errorf("group type = %q, want url-test", g.Type)
	}
	// The balancer tag is generic and the configuration has a label, so the
	// label names the group.
	if g.Name != "Germany" {
		t.Errorf("group name = %q, want \"Germany\"", g.Name)
	}
	want := []string{"proxy-de-1", "proxy-de-2", "proxy-de-3"}
	if strings.Join(g.Members, ",") != strings.Join(want, ",") {
		t.Errorf("members = %v, want %v", g.Members, want)
	}
}

func TestBalancedNodesAreNotSelectable(t *testing.T) {
	res := convertWith(t, balancerConfig, DefaultOptions())

	// This is the point of the feature: the user picks the balancer, never the
	// individual servers behind it.
	selectable := res.Selectable()
	if len(selectable) != 1 || selectable[0] != "Germany" {
		t.Fatalf("selectable = %v, want just the group", selectable)
	}
	for _, name := range []string{"proxy-de-1", "proxy-de-2", "proxy-de-3"} {
		for _, s := range selectable {
			if s == name {
				t.Errorf("balanced node %q must not be selectable", name)
			}
		}
	}
}

func TestSelectorMatchesByPrefix(t *testing.T) {
	// Xray selects outbounds whose tag starts with the selector, so "proxy"
	// claims "proxy-a" but not "other".
	res := convertWith(t, `[{
		"outbounds": [
			{"tag":"proxy-a","protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}},
			{"tag":"proxy-b","protocol":"vless","settings":{"vnext":[{"address":"b.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}},
			{"tag":"other","protocol":"vless","settings":{"vnext":[{"address":"c.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}
		],
		"routing": {"balancers": [{"tag":"lb","selector":["proxy"]}]}
	}]`, DefaultOptions())

	if len(res.Groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(res.Groups))
	}
	if got := strings.Join(res.Groups[0].Members, ","); got != "proxy-a,proxy-b" {
		t.Errorf("members = %q, want \"proxy-a,proxy-b\"", got)
	}

	// The unselected node stays a normal, selectable proxy.
	selectable := res.Selectable()
	if len(selectable) != 2 || selectable[1] != "other" {
		t.Errorf("selectable = %v, want the group plus \"other\"", selectable)
	}
}

func TestMultipleSelectorsAreUnioned(t *testing.T) {
	res := convertWith(t, `[{
		"outbounds": [
			{"tag":"de-1","protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}},
			{"tag":"nl-1","protocol":"vless","settings":{"vnext":[{"address":"b.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}},
			{"tag":"jp-1","protocol":"vless","settings":{"vnext":[{"address":"c.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}
		],
		"routing": {"balancers": [{"tag":"eu","selector":["de-","nl-"]}]}
	}]`, DefaultOptions())

	if got := strings.Join(res.Groups[0].Members, ","); got != "de-1,nl-1" {
		t.Errorf("members = %q, want \"de-1,nl-1\"", got)
	}
}

func TestSeveralBalancersBecomeSeveralGroups(t *testing.T) {
	res := convertWith(t, `[{
		"remarks": "Mixed",
		"outbounds": [
			{"tag":"de-1","protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}},
			{"tag":"de-2","protocol":"vless","settings":{"vnext":[{"address":"b.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}},
			{"tag":"nl-1","protocol":"vless","settings":{"vnext":[{"address":"c.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}
		],
		"routing": {"balancers": [
			{"tag":"germany","selector":["de-"]},
			{"tag":"netherlands","selector":["nl-"]}
		]}
	}]`, DefaultOptions())

	if len(res.Groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(res.Groups))
	}
	// Both balancers share the one label, so the tag tells them apart while
	// the label still leads the name.
	if res.Groups[0].Name != "Mixed (germany)" || res.Groups[1].Name != "Mixed (netherlands)" {
		t.Errorf("group names = %q, %q", res.Groups[0].Name, res.Groups[1].Name)
	}
	if got := res.Selectable(); len(got) != 2 {
		t.Errorf("selectable = %v, want the two groups", got)
	}
}

func TestGroupNameComesFromRemarksNotTheTag(t *testing.T) {
	// The balancer tag is an internal routing name; "remarks" is what names
	// the location to a person, so it wins even when the tag looks usable.
	res := convertWith(t, `[{
		"remarks": "🇩🇪 Germany · Premium",
		"outbounds": [
			{"tag":"vless-de-frankfurt-01","protocol":"vless","settings":{"vnext":[{
				"address":"a.example.com","port":443,
				"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}},
			{"tag":"vless-de-frankfurt-02","protocol":"vless","settings":{"vnext":[{
				"address":"b.example.com","port":443,
				"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}
		],
		"routing": {"balancers": [{"tag":"vless-de","selector":["vless-de"]}]}
	}]`, DefaultOptions())

	if len(res.Groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(res.Groups))
	}
	if got := res.Groups[0].Name; got != "🇩🇪 Germany · Premium" {
		t.Errorf("group name = %q, want the remarks", got)
	}
}

func TestGroupNameUsesEveryRemarksSpelling(t *testing.T) {
	// Generators label a configuration in several ways; any of them names the
	// group.
	for _, key := range []string{"remarks", "remark", "name", "ps"} {
		t.Run(key, func(t *testing.T) {
			res := convertWith(t, `[{
				"`+key+`": "Tokyo",
				"outbounds": [
					{"tag":"n-1","protocol":"vless","settings":{"vnext":[{
						"address":"a.example.com","port":443,
						"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}
				],
				"routing": {"balancers": [{"tag":"balancer","selector":["n-"]}]}
			}]`, DefaultOptions())

			if got := res.Groups[0].Name; got != "Tokyo" {
				t.Errorf("group name = %q, want \"Tokyo\"", got)
			}
		})
	}
}

func TestGroupNameFallsBackToTheTagWithoutRemarks(t *testing.T) {
	res := convertWith(t, `[{
		"outbounds": [
			{"tag":"n-1","protocol":"vless","settings":{"vnext":[{
				"address":"a.example.com","port":443,
				"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}
		],
		"routing": {"balancers": [{"tag":"my-balancer","selector":["n-"]}]}
	}]`, DefaultOptions())

	if got := res.Groups[0].Name; got != "my-balancer" {
		t.Errorf("group name = %q, want the balancer tag", got)
	}
}

func TestFallbackGroupIsNamedFromRemarks(t *testing.T) {
	// With a fallbackTag the user-facing group is the outer one, so that is
	// the one that carries the remarks.
	res := convertWith(t, `[{
		"remarks": "Netherlands",
		"outbounds": [
			{"tag":"nl-1","protocol":"vless","settings":{"vnext":[{
				"address":"a.example.com","port":443,
				"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}},
			{"tag":"spare","protocol":"vless","settings":{"vnext":[{
				"address":"b.example.com","port":443,
				"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}
		],
		"routing": {"balancers": [{"tag":"lb","selector":["nl-"],"fallbackTag":"spare"}]}
	}]`, DefaultOptions())

	if got := res.Selectable(); len(got) != 1 || got[0] != "Netherlands" {
		t.Fatalf("selectable = %v, want just \"Netherlands\"", got)
	}
	if got := res.Groups[0].Name; got != "Netherlands pool" {
		t.Errorf("inner group = %q, want it derived from the remarks", got)
	}
}

func TestFallbackTagWrapsTheBalancer(t *testing.T) {
	// Xray uses fallbackTag when every balanced node is down. mihomo's
	// fallback group takes the first member that passes its health check,
	// which is the same behaviour.
	res := convertWith(t, `[{
		"outbounds": [
			{"tag":"nl-1","protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}},
			{"tag":"nl-2","protocol":"vless","settings":{"vnext":[{"address":"b.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}},
			{"tag":"spare","protocol":"vless","settings":{"vnext":[{"address":"c.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}
		],
		"routing": {"balancers": [
			{"tag":"pool","selector":["nl-"],"fallbackTag":"spare"}
		]}
	}]`, DefaultOptions())

	if len(res.Groups) != 2 {
		t.Fatalf("got %d groups, want 2 (the balancer and its fallback wrapper)", len(res.Groups))
	}
	inner, outer := res.Groups[0], res.Groups[1]

	if inner.Type != "url-test" || strings.Join(inner.Members, ",") != "nl-1,nl-2" {
		t.Errorf("inner group = %+v", inner)
	}
	if outer.Type != "fallback" {
		t.Errorf("outer group type = %q, want fallback", outer.Type)
	}
	if got := strings.Join(outer.Members, ","); got != inner.Name+",spare" {
		t.Errorf("outer members = %q, want the pool then the spare", got)
	}
	// Only the outer group is offered; the pool and the spare are reached
	// through it.
	if got := res.Selectable(); len(got) != 1 || got[0] != "pool" {
		t.Errorf("selectable = %v, want just \"pool\"", got)
	}
}

func TestFallbackTagPointingNowhereIsReported(t *testing.T) {
	res := convertWith(t, `[{
		"outbounds": [
			{"tag":"nl-1","protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}
		],
		"routing": {"balancers": [{"tag":"pool","selector":["nl-"],"fallbackTag":"missing"}]}
	}]`, DefaultOptions())

	if len(res.Groups) != 1 {
		t.Fatalf("got %d groups, want just the balancer", len(res.Groups))
	}
	if !hasDiagnostic(res, "fallbackTag") {
		t.Errorf("the dangling fallbackTag was not reported: %v", res.Diagnostics)
	}
}

func TestBalancerWithNoConvertibleNodeIsDropped(t *testing.T) {
	// The only selected outbound uses a transport mihomo cannot express.
	res := convertWith(t, `[{
		"outbounds": [
			{"tag":"proxy-1","protocol":"vmess","settings":{"vnext":[{"address":"a.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":0}]}]},
				"streamSettings":{"network":"quic"}}
		],
		"routing": {"balancers": [{"tag":"pool","selector":["proxy"]}]}
	}]`, DefaultOptions())

	if len(res.Groups) != 0 {
		t.Errorf("an empty group would make mihomo refuse the file, got %v", res.Groups)
	}
	if !hasDiagnostic(res, "selected no node") {
		t.Errorf("the empty balancer was not reported: %v", res.Diagnostics)
	}
}

func TestBalancerGroupNameDoesNotCollideWithAProxy(t *testing.T) {
	// mihomo needs proxies and groups to have distinct names.
	res := convertWith(t, `[{
		"outbounds": [
			{"tag":"pool","protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}},
			{"tag":"pool-2","protocol":"vless","settings":{"vnext":[{"address":"b.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}
		],
		"routing": {"balancers": [{"tag":"pool","selector":["pool"]}]}
	}]`, DefaultOptions())

	if len(res.Groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(res.Groups))
	}
	group := res.Groups[0].Name
	for _, proxy := range res.Names() {
		if proxy == group {
			t.Errorf("the group %q shares its name with a proxy", group)
		}
	}
}

func TestStrategyMappedToLoadBalanceOnRequest(t *testing.T) {
	opts := DefaultOptions()
	opts.BalancerGroupType = "load-balance"
	res := convertWith(t, strings.Replace(balancerConfig, "leastPing", "roundRobin", 1), opts)

	g := res.Groups[0]
	if g.Type != "load-balance" {
		t.Fatalf("group type = %q, want load-balance", g.Type)
	}
	if g.Strategy != "round-robin" {
		t.Errorf("strategy = %q, want round-robin", g.Strategy)
	}
}

func TestSpreadingStrategyIsReportedUnderURLTest(t *testing.T) {
	// url-test picks the fastest node rather than spreading traffic, so a
	// roundRobin balancer does not behave identically and should say so.
	res := convertWith(t, strings.Replace(balancerConfig, "leastPing", "roundRobin", 1), DefaultOptions())

	if res.Groups[0].Type != "url-test" {
		t.Fatalf("group type = %q, want url-test", res.Groups[0].Type)
	}
	if !hasDiagnostic(res, "spreads traffic") {
		t.Errorf("the strategy change was not reported: %v", res.Diagnostics)
	}
}

func TestLatencyStrategiesAreNotFlagged(t *testing.T) {
	for _, strategy := range []string{"leastPing", "leastLoad"} {
		t.Run(strategy, func(t *testing.T) {
			res := convertWith(t, strings.Replace(balancerConfig, "leastPing", strategy, 1), DefaultOptions())
			if hasDiagnostic(res, "spreads traffic") {
				t.Errorf("%s matches url-test and needs no warning: %v", strategy, res.Diagnostics)
			}
		})
	}
}

func TestUnusedBalancerIsReported(t *testing.T) {
	// A balancer no rule routes to does nothing in Xray.
	res := convertWith(t, `[{
		"outbounds": [
			{"tag":"proxy-1","protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}
		],
		"routing": {
			"balancers": [{"tag":"unused","selector":["proxy"]}],
			"rules": [{"type":"field","network":"tcp","outboundTag":"proxy-1"}]
		}
	}]`, DefaultOptions())

	if len(res.Groups) != 1 {
		t.Fatalf("the nodes still need a home, got %d groups", len(res.Groups))
	}
	if !hasDiagnostic(res, "no routing rule") {
		t.Errorf("the unused balancer was not reported: %v", res.Diagnostics)
	}
}

func TestConfigWithoutBalancerIsUnchanged(t *testing.T) {
	res := convertWith(t, `[{"remarks":"Plain","outbounds":[{"protocol":"vless","settings":{
		"vnext":[{"address":"a.example.com","port":443,
		"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}]}]`, DefaultOptions())

	if len(res.Groups) != 0 {
		t.Errorf("a configuration without a balancer needs no group, got %v", res.Groups)
	}
	// Every proxy stays selectable, exactly as before balancers were handled.
	if got := res.Selectable(); len(got) != 1 || got[0] != "Plain" {
		t.Errorf("selectable = %v, want the proxy itself", got)
	}
}

func TestBalancerWithoutSelectorsIsIgnored(t *testing.T) {
	// Xray refuses such a balancer outright.
	res := convertWith(t, `[{
		"outbounds": [
			{"tag":"proxy-1","protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}
		],
		"routing": {"balancers": [{"tag":"broken"}]}
	}]`, DefaultOptions())

	if len(res.Groups) != 0 {
		t.Errorf("got %d groups, want none", len(res.Groups))
	}
	if got := res.Selectable(); len(got) != 1 || got[0] != "proxy-1" {
		t.Errorf("selectable = %v, want the ungrouped proxy", got)
	}
}

func TestNamePrefixAppliesToBalancerGroups(t *testing.T) {
	opts := DefaultOptions()
	opts.NamePrefix = "[EU] "
	res := convertWith(t, balancerConfig, opts)

	if got := res.Groups[0].Name; got != "[EU] Germany" {
		t.Errorf("group name = %q, want the prefix applied", got)
	}
}

func hasDiagnostic(res *Result, substring string) bool {
	for _, d := range res.Diagnostics {
		if strings.Contains(d.Message, substring) {
			return true
		}
	}
	return false
}
