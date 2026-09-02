package mobilecore

import (
	"strings"
	"testing"
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

func TestInjectChainsAndWarp(t *testing.T) {
	SetChains(`[{"name":"NL-DE-WARP","nodes":["NL","DE","WARP"]},{"name":"bad","nodes":["NL","nope"]}]`)
	SetWarp(`{"private_key":"a","public_key":"b","address4":"172.16.0.2","address6":"::1","reserved":[1,2,3]}`)
	defer SetChains("")
	defer SetWarp("")
	out := prepareConfig(chainTestCfg)
	for _, want := range []string{"name: WARP", "name: ⛓ NL-DE-WARP 1", "name: 🔗 NL-DE-WARP", "dialer-proxy: NL", "dialer-proxy: ⛓ NL-DE-WARP 1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет %q в:\n%s", want, out)
		}
	}
	if strings.Contains(out, "🔗 bad") {
		t.Fatalf("цепочка с несуществующим узлом не должна собираться")
	}
	// выход попал в главный селектор (MATCH-политика без прямых узлов)
	if !strings.Contains(out, "- 🔗 NL-DE-WARP") {
		t.Fatalf("выход не добавлен в главный селектор:\n%s", out)
	}
}

func TestPrepareConfigNoop(t *testing.T) {
	SetChains("")
	SetWarp("")
	if prepareConfig(chainTestCfg) != chainTestCfg {
		t.Fatal("без цепочек конфиг должен остаться как есть")
	}
}
