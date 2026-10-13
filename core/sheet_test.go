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
	for _, want := range []string{`"main":"MAIN"`, `"auto":"Fast"`, `"members":["Fast","Europe","NL"]`, `"Europe":["NL"]`} {
		if !strings.Contains(s, want) {
			t.Fatalf("нет %s в %s", want, s)
		}
	}
}

// Страны панели собираются фильтром, а не списком: без разбора filter лист
// серверов остаётся без узлов и пинговать нечего.
func TestMihomoSheetFilterGroups(t *testing.T) {
	cfg := `
proxies:
  - {name: DE-1, type: vless, server: 1.1.1.1, port: 443, uuid: x}
  - {name: DE-torrent, type: vless, server: 2.2.2.2, port: 443, uuid: x}
  - {name: NL-1, type: vless, server: 3.3.3.3, port: 443, uuid: x}
proxy-groups:
  - {name: MAIN, type: select, proxies: [Germany, Netherlands]}
  - name: Germany
    type: fallback
    include-all-proxies: true
    filter: 'DE'
    exclude-filter: '(?i)torrent'
  - name: Netherlands
    type: fallback
    use: [all]
    filter: 'NL'
rules:
  - MATCH,MAIN
`
	s := mihomoSheet(cfg)
	for _, want := range []string{`"Germany":["DE-1"]`, `"Netherlands":["NL-1"]`} {
		if !strings.Contains(s, want) {
			t.Fatalf("нет %s в %s", want, s)
		}
	}
}
