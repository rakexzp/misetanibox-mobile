package mobilecore

import (
	"strings"
	"testing"
)

func TestMihomoSheet(t *testing.T) {
	cfg := `
proxies:
  - {name: NL, type: vless, server: 1.1.1.1, port: 443, uuid: x}
proxy-groups:
  - {name: MAIN, type: select, proxies: [DIRECT, Fast, Europe, NL]}
  - {name: Fast, type: url-test, proxies: [NL], url: http://x, interval: 300}
  - {name: Europe, type: fallback, proxies: [NL], url: http://x, interval: 300}
rules:
  - MATCH,MAIN
`
	s := mihomoSheet(cfg)
	for _, want := range []string{`"main":"MAIN"`, `"auto":"Fast"`, `"members":["Fast","Europe","NL"]`} {
		if !strings.Contains(s, want) {
			t.Fatalf("нет %s в %s", want, s)
		}
	}
}
