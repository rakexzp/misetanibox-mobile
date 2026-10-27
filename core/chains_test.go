package mobilecore

import (
	"testing"

	"gopkg.in/yaml.v3"
)

const chainTestCfg = `
proxies:
  - {name: NL, type: vless, server: 1.1.1.1, port: 443, uuid: x}
  - {name: DE, type: vless, server: 2.2.2.2, port: 443, uuid: y}
proxy-groups:
  - {name: MAIN, type: select, proxies: [Europe]}
  - {name: Europe, type: fallback, proxies: [NL, DE], url: http://x, interval: 300}
rules:
  - MATCH,MAIN
`

type testCfg struct {
	Proxies []map[string]interface{} `yaml:"proxies"`
	Groups  []struct {
		Name    string   `yaml:"name"`
		Proxies []string `yaml:"proxies"`
	} `yaml:"proxy-groups"`
}

func TestInjectChainsAndWarp(t *testing.T) {
	SetChains(`[{"name":"NL-DE-WARP","nodes":["NL","DE","WARP"]},{"name":"bad","nodes":["NL","nope"]}]`)
	SetWarp(`{"private_key":"a","public_key":"b","address4":"172.16.0.2","address6":"::1","reserved":[1,2,3]}`)
	defer SetChains("")
	defer SetWarp("")
	var cfg testCfg
	if err := yaml.Unmarshal([]byte(prepareConfig(chainTestCfg)), &cfg); err != nil {
		t.Fatal(err)
	}
	byName := map[string]map[string]interface{}{}
	for _, p := range cfg.Proxies {
		byName[p["name"].(string)] = p
	}
	if byName["WARP"] == nil || byName["WARP"]["type"] != "wireguard" {
		t.Fatal("нет узла WARP")
	}
	hop := byName["⛓ NL-DE-WARP 1"]
	if hop == nil || hop["dialer-proxy"] != "NL" || hop["server"] != "2.2.2.2" {
		t.Fatalf("промежуточный хоп неверен: %v", hop)
	}
	exit := byName["🔗 NL-DE-WARP"]
	if exit == nil || exit["dialer-proxy"] != "⛓ NL-DE-WARP 1" || exit["type"] != "wireguard" {
		t.Fatalf("выход неверен: %v", exit)
	}
	if byName["🔗 bad"] != nil {
		t.Fatal("цепочка с несуществующим узлом не должна собираться")
	}
	found := false
	for _, g := range cfg.Groups {
		if g.Name == "MAIN" {
			for _, n := range g.Proxies {
				if n == "🔗 NL-DE-WARP" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("выход не добавлен в главный селектор (MATCH-политику)")
	}
}

func TestPrepareConfigNoop(t *testing.T) {
	SetChains("")
	SetWarp("")
	if prepareConfig(chainTestCfg) != chainTestCfg {
		t.Fatal("без цепочек конфиг должен остаться как есть")
	}
}

// в подписках бывают имена с пробелами по краям, а UI присылает их обрезанными
func TestInjectChainsPaddedNames(t *testing.T) {
	const cfgText = `
proxies:
  - {name: " NL ", type: vless, server: 1.1.1.1, port: 443, uuid: x}
  - {name: "DE", type: vless, server: 2.2.2.2, port: 443, uuid: y}
proxy-groups:
  - {name: MAIN, type: select, proxies: [" NL ", DE]}
rules:
  - MATCH,MAIN
`
	SetChains(`[{"name":"NL-DE","nodes":["NL","DE"]},{"name":"DE-NL","nodes":["DE"," NL "]}]`)
	defer SetChains("")
	var cfg testCfg
	if err := yaml.Unmarshal([]byte(prepareConfig(cfgText)), &cfg); err != nil {
		t.Fatal(err)
	}
	byName := map[string]map[string]interface{}{}
	for _, p := range cfg.Proxies {
		byName[p["name"].(string)] = p
	}
	if e := byName["🔗 NL-DE"]; e == nil || e["dialer-proxy"] != " NL " || e["server"] != "2.2.2.2" {
		t.Fatalf("цепочка с обрезанным именем входа не собралась: %v", e)
	}
	if e := byName["🔗 DE-NL"]; e == nil || e["dialer-proxy"] != "DE" || e["server"] != "1.1.1.1" {
		t.Fatalf("цепочка с точным именем выхода не собралась: %v", e)
	}
}
