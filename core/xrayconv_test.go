package mobilecore

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub/executor"
)

// The conversion is only worth anything if the core accepts what comes out of
// it, so the tests below run the generated file through the very parser
// Start uses. A field renamed upstream, or one that never existed, fails here
// rather than on a phone with the tunnel up and no traffic flowing.
//
// Run them with the tags the shipped core is built with:
//
//	go test -tags with_gvisor,cmfa ./...
//
// Without with_gvisor mihomo refuses to build a WireGuard proxy, and the
// sample set contains one.

func convertFile(t *testing.T, path string) *ConvertResult {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	res, err := ConvertSubscription(string(raw))
	if err != nil {
		t.Fatalf("converting %s: %v", path, err)
	}
	return res
}

// parseWithCore feeds the configuration to mihomo and returns what it made of
// it.
func parseWithCore(t *testing.T, body string) *config.Config {
	t.Helper()
	cfg, err := executor.ParseWithBytes([]byte(body))
	if err != nil {
		t.Fatalf("mihomo rejected the generated configuration: %v\n%s", err, body)
	}
	return cfg
}

func TestSampleConfigsLoadInTheCore(t *testing.T) {
	res := convertFile(t, "testdata/sample-configs.json")

	if res.Format != FormatXray {
		t.Fatalf("format = %q, want %q", res.Format, FormatXray)
	}
	if res.Proxies < 12 {
		t.Fatalf("converted %d proxies, want at least 12", res.Proxies)
	}

	cfg := parseWithCore(t, res.Config)
	// mihomo adds DIRECT, REJECT and friends to the same map, so the count is
	// only checked for being at least what was converted.
	if len(cfg.Proxies) < res.Proxies {
		t.Errorf("the core built %d proxies, want at least %d", len(cfg.Proxies), res.Proxies)
	}
	if _, ok := cfg.Proxies["PROXY"]; !ok {
		t.Error("the core has no PROXY group; the app switches servers through it")
	}
	if _, ok := cfg.Proxies["AUTO"]; !ok {
		t.Error("the core has no AUTO group")
	}

	// Every node of the sample set has to survive, since each one stands for a
	// protocol or transport the client claims to support.
	for _, name := range []string{
		"VLESS · REALITY · Vision",
		"VLESS · XHTTP · encryption · xmux",
		"VLESS · XHTTP · packet-up obfuscation",
		"VMess · WebSocket · early data",
		"Trojan · gRPC",
		"Hysteria2 · Salamander",
		"Shadowsocks 2022",
		"VMess · HTTP masquerade over raw TCP",
		"WireGuard",
		"VLESS · HTTPUpgrade",
		"Hysteria2 · Xray native form",
		"SOCKS5 with credentials",
	} {
		if _, ok := cfg.Proxies[name]; !ok {
			t.Errorf("the core did not build the proxy %q", name)
		}
	}
}

func TestBalancersBecomeProxyGroups(t *testing.T) {
	res := convertFile(t, "testdata/balancer-config.json")

	if res.Groups != 3 {
		t.Fatalf("produced %d groups, want 3 (two balancers plus a fallback wrapper)", res.Groups)
	}
	cfg := parseWithCore(t, res.Config)

	// leastPing asks for the best node, which is what url-test does.
	assertGroupType(t, res.Config, "Germany", "url-test")
	// A balancer with a fallbackTag gains an outer group that reaches for the
	// spare only when the balanced ones are down.
	assertGroupType(t, res.Config, "Netherlands", "fallback")

	for _, name := range []string{"Germany", "Netherlands", "Japan"} {
		if _, ok := cfg.Proxies[name]; !ok {
			t.Errorf("the core did not build the group %q", name)
		}
	}

	// The nodes a balancer covers are reached through their group; offering
	// them separately would undo the balancing the panel asked for.
	selectable := groupMembers(t, res.Config, "PROXY")
	for _, hidden := range []string{"proxy-de-1", "proxy-de-2", "nl-1", "spare"} {
		if selectable[hidden] {
			t.Errorf("%q is a balanced node and should not be offered on its own", hidden)
		}
	}
	for _, shown := range []string{"Germany", "Netherlands", "Japan"} {
		if !selectable[shown] {
			t.Errorf("%q should be offered in the PROXY group", shown)
		}
	}
}

// TestNamesOfferGroupsInsteadOfBalancedNodes covers what the server list shows:
// the client reads Names straight from the converter rather than parsing the
// YAML back, so a balanced node must not reach it.
func TestNamesOfferGroupsInsteadOfBalancedNodes(t *testing.T) {
	res := convertFile(t, "testdata/balancer-config.json")

	names := strings.Split(res.Names, "\n")
	want := []string{"Germany", "Netherlands", "Japan"}
	if len(names) != len(want) {
		t.Fatalf("Names = %q, want exactly %q", names, want)
	}
	for i, n := range want {
		if names[i] != n {
			t.Errorf("Names[%d] = %q, want %q", i, names[i], n)
		}
	}
}

// TestBalancerStrategyPicksTheGroupType checks that a strategy which spreads
// traffic does not become a group that pins it to one node.
func TestBalancerStrategyPicksTheGroupType(t *testing.T) {
	for _, tc := range []struct {
		strategy string
		want     string
	}{
		{"leastPing", "url-test"},
		{"leastLoad", "url-test"},
		{"random", "load-balance"},
		{"roundRobin", "load-balance"},
	} {
		t.Run(tc.strategy, func(t *testing.T) {
			config := `[{"remarks":"Pool","outbounds":[
				{"tag":"a","protocol":"trojan","settings":{"servers":[{"address":"a.example.com","port":443,"password":"p"}]}},
				{"tag":"b","protocol":"trojan","settings":{"servers":[{"address":"b.example.com","port":443,"password":"p"}]}}
			],"routing":{"balancers":[{"tag":"bal","selector":["a","b"],"strategy":{"type":"` + tc.strategy + `"}}],
				"rules":[{"balancerTag":"bal"}]}}]`

			res, err := ConvertSubscription(config)
			if err != nil {
				t.Fatal(err)
			}
			assertGroupType(t, res.Config, "Pool", tc.want)
			parseWithCore(t, res.Config)
		})
	}
}

// TestXHTTPExtraIsCarriedOver covers the transport the client is most likely
// to meet a hand-tuned panel on: every advanced setting lives in "extra", and
// Xray replaces the outer object with it rather than merging the two.
func TestXHTTPExtraIsCarriedOver(t *testing.T) {
	res := convertFile(t, "testdata/sample-configs.json")
	parseWithCore(t, res.Config)

	for _, want := range []string{
		"network: xhttp",
		"mode: auto",
		"mode: packet-up",
		// xmux, which mihomo spells reuse-settings
		"reuse-settings:",
		"max-concurrency: 16-32",
		"h-keep-alive-period: 45",
		// the separate download endpoint
		"download-settings:",
		"server: download.example.com",
		// padding and session controls
		"x-padding-bytes: 200-800",
		"x-padding-placement: cookie",
		"x-padding-method: tokenish",
		"session-placement: cookie",
		"seq-placement: header",
		"uplink-data-placement: cookie",
		"uplink-http-method: GET",
		"sc-max-each-post-bytes:",
		"sc-min-posts-interval-ms:",
	} {
		if !strings.Contains(res.Config, want) {
			t.Errorf("the generated configuration is missing %q", want)
		}
	}
}

// TestVlessEncryptionIsCarriedOver covers post-quantum VLESS, where the whole
// value is one string that mihomo parses with Xray's grammar.
func TestVlessEncryptionIsCarriedOver(t *testing.T) {
	res := convertFile(t, "testdata/sample-configs.json")
	const want = "encryption: mlkem768x25519plus.native.1rtt."
	if !strings.Contains(res.Config, want) {
		t.Fatalf("the generated configuration is missing %q", want)
	}
	parseWithCore(t, res.Config)
}

// TestVlessEncryptionIsRejectedWhenInvalid guards the reason the value is
// validated at all: mihomo refuses the whole file over one bad node, so a
// subscription with a broken key would take every other server down with it.
func TestVlessEncryptionIsRejectedWhenInvalid(t *testing.T) {
	config := `[{"remarks":"Bad","outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"e.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"mlkem768x25519plus.native.600s.RvI5xPRmxvhVMSxOsCUDIF1uu4sN0-1Z9RXTVIrGYFk"}]}]},
		"streamSettings":{"network":"tcp","security":"tls"}}]}]`

	if _, err := ConvertSubscription(config); err == nil {
		t.Fatal("an encryption string with a server-side lifetime should not convert")
	}
}

// TestHysteria2FromXrayNativeForm covers the shape Xray itself writes, where
// the outbound holds only the address and the password lives in
// streamSettings.
func TestHysteria2FromXrayNativeForm(t *testing.T) {
	config := `[{"remarks":"HY2","outbounds":[{"protocol":"hysteria","settings":{"version":2,
		"address":"hy2.example.com","port":443},
		"streamSettings":{"network":"hysteria","security":"tls",
			"tlsSettings":{"serverName":"hy2.example.com","alpn":["h3"]},
			"hysteriaSettings":{"version":2,"auth":"a-strong-password","udpHop":{"ports":"20000-30000","interval":"30"}},
			"finalmask":{"quicParams":{"brutalUp":"50 Mbps","brutalDown":"200 Mbps","congestion":"brutal"},
				"udp":[{"type":"salamander","settings":{"password":"obfs-secret"}}]}}}]}]`

	res, err := ConvertSubscription(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"type: hysteria2",
		"password: a-strong-password",
		"obfs: salamander",
		"obfs-password: obfs-secret",
		"up: 50 Mbps",
		"down: 200 Mbps",
		"ports: 20000-30000",
		"hop-interval: '30'",
	} {
		if !strings.Contains(res.Config, want) {
			t.Errorf("the generated configuration is missing %q", want)
		}
	}
	parseWithCore(t, res.Config)
}

func TestDetectFormat(t *testing.T) {
	uriList := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=tcp&security=tls#Node\n"

	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"xray array", `[{"outbounds":[]}]`, FormatXray},
		{"xray object", `{"outbounds":[]}`, FormatXray},
		{"xray behind a line comment", "// generated\n[{\"outbounds\":[]}]", FormatXray},
		{"xray behind a block comment", "/* generated */\n{\"outbounds\":[]}", FormatXray},
		{"mihomo yaml", "proxies:\n  - name: a\n", FormatMihomo},
		{"mihomo provider", "proxy-providers:\n  main:\n    url: https://example.com\n", FormatMihomo},
		{"uri list", uriList, FormatURI},
		{"uri list base64", base64.StdEncoding.EncodeToString([]byte(uriList)), FormatURI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := detectFormat(tc.body); got != tc.want {
				t.Errorf("detectFormat = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMihomoYAMLPassesThroughUntouched keeps the promise the existing
// subscriptions rely on: a configuration its author wrote is the one that runs,
// selectors, rules and all.
func TestMihomoYAMLPassesThroughUntouched(t *testing.T) {
	const body = "proxies:\n  - {name: a, type: socks5, server: 127.0.0.1, port: 1080}\nproxy-groups:\n  - {name: PROXY, type: select, proxies: [a]}\nrules:\n  - MATCH,PROXY\n"

	res, err := ConvertSubscription(body)
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != FormatMihomo {
		t.Fatalf("format = %q, want %q", res.Format, FormatMihomo)
	}
	if res.Config != body {
		t.Errorf("the body was rewritten:\n%s", res.Config)
	}
}

// TestMihomoYAMLWithProxyURLsIsNotMistakenForALinkList guards the detection
// against a configuration whose own contents mention the proxy schemes.
func TestMihomoYAMLWithProxyURLsIsNotMistakenForALinkList(t *testing.T) {
	const body = "proxy-providers:\n  main:\n    url: https://panel.example.com/sub\n" +
		"proxy-groups:\n  - name: PROXY\n    type: url-test\n    url: https://www.gstatic.com/generate_204\n"

	if got, _ := detectFormat(body); got != FormatMihomo {
		t.Fatalf("detectFormat = %q, want %q", got, FormatMihomo)
	}
}

func TestURIListConversion(t *testing.T) {
	list := strings.Join([]string{
		"vless://b831381d-6324-4d53-ad4f-8cda48b30811@vless.example.com:443?type=ws&security=tls&path=%2Fws&host=vless.example.com#VLESS%20node",
		"trojan://password@trojan.example.com:443?sni=trojan.example.com#Trojan%20node",
		"hysteria2://a-strong-password@hy2.example.com:443?sni=hy2.example.com#HY2%20node",
	}, "\n")

	for _, tc := range []struct {
		name string
		body string
	}{
		{"plain", list},
		{"base64", base64.StdEncoding.EncodeToString([]byte(list))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ConvertSubscription(tc.body)
			if err != nil {
				t.Fatal(err)
			}
			if res.Format != FormatURI {
				t.Fatalf("format = %q, want %q", res.Format, FormatURI)
			}
			if res.Proxies != 3 {
				t.Fatalf("converted %d proxies, want 3", res.Proxies)
			}
			cfg := parseWithCore(t, res.Config)
			for _, name := range []string{"VLESS node", "Trojan node", "HY2 node"} {
				if _, ok := cfg.Proxies[name]; !ok {
					t.Errorf("the core did not build the proxy %q", name)
				}
			}
		})
	}
}

func TestConvertSubscriptionRejectsAnEmptyBody(t *testing.T) {
	if _, err := ConvertSubscription("   \n  "); err == nil {
		t.Fatal("an empty body should not convert")
	}
}

// assertGroupType checks the type of a named group in the generated YAML.
func assertGroupType(t *testing.T, config, group, want string) {
	t.Helper()
	block, ok := groupBlock(config, group)
	if !ok {
		t.Fatalf("the generated configuration has no group %q", group)
	}
	if !strings.Contains(block, "type: "+want) {
		t.Errorf("group %q is not of type %q:\n%s", group, want, block)
	}
}

// groupMembers returns the names listed in a group's "proxies" list.
func groupMembers(t *testing.T, config, group string) map[string]bool {
	t.Helper()
	block, ok := groupBlock(config, group)
	if !ok {
		t.Fatalf("the generated configuration has no group %q", group)
	}
	out := map[string]bool{}
	inList := false
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "proxies:" {
			inList = true
			continue
		}
		if inList && strings.HasPrefix(trimmed, "- ") {
			out[strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))] = true
		}
	}
	return out
}

// groupBlock cuts one entry out of the proxy-groups list.
func groupBlock(config, group string) (string, bool) {
	marker := "- name: " + group + "\n"
	start := strings.Index(config, marker)
	if start < 0 {
		return "", false
	}
	rest := config[start+len(marker):]
	// The next entry starts at the same indentation, so the block ends there.
	if end := strings.Index(rest, "\n  - "); end >= 0 {
		return marker + rest[:end], true
	}
	return marker + rest, true
}
