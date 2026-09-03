package mobilecore

import (
	"gopkg.in/yaml.v3"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	mconvert "github.com/metacubex/mihomo/common/convert"

	"misetanibox/mobilecore/internal/convert"
	"misetanibox/mobilecore/internal/mihomo"
	"misetanibox/mobilecore/internal/xray"
	"misetanibox/mobilecore/internal/yamlx"
)

// A subscription arrives in one of three shapes, and the panel decides which
// one without asking: a mihomo YAML document, an Xray Core JSON configuration
// (or a list of them), or a list of proxy URIs, plain or base64-wrapped.
//
// The core only speaks the first. ConvertSubscription recognises the other two
// and turns them into it, so the client can accept a subscription link without
// the user knowing what the panel puts behind it.

// Subscription formats, as reported in ConvertResult.Format.
const (
	FormatMihomo = "mihomo" // a mihomo/clash YAML document, used as it stands
	FormatXray   = "xray"   // an Xray Core JSON configuration
	FormatURI    = "uri"    // a list of vless://, vmess://, ss://... links
)

// ConvertResult is a subscription that the core can run.
type ConvertResult struct {
	// Config is the mihomo YAML configuration.
	Config string
	// Format is the format the body was recognised as.
	Format string
	// Proxies and Groups count what a conversion produced. Both are zero for
	// a body that was already mihomo YAML and passed through untouched.
	Proxies int
	Groups  int
	// Names lists what to offer the user, one per line: a balancer's group
	// stands there in place of the nodes it covers, so the servers the panel
	// meant to balance over are not shown as separate choices.
	//
	// It is a single string because a list of them is not something gomobile
	// can carry across to Java. Empty for a pass-through mihomo document,
	// whose own groups the client reads from the running core instead.
	Names string
	// Notes holds one line per setting that could not be carried over, for
	// the diagnostics screen. Empty when everything converted cleanly.
	Notes string
	// Sheet — JSON {main, auto, members[]}: состав главного селектора (политика MATCH)
	// для листа серверов до подключения; только для mihomo-YAML.
	Sheet string
	// Nodes — JSON {имя: "host:port"} inline-узлов (для tcp/icmp-пинга в приложении); только mihomo-YAML.
	Nodes string
}

// proxyURISchemes are the URI schemes a proxy subscription uses.
//
// Plain http and https are deliberately absent: a mihomo YAML is full of
// https:// URLs -- health-check targets, provider addresses, DoH resolvers --
// and treating one as a node list would misread the whole document.
var proxyURISchemes = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "trojan-go": true,
	"ss": true, "ssr": true, "ssh": true, "snell": true,
	"hysteria": true, "hysteria2": true, "hy2": true, "tuic": true,
	"anytls": true, "mieru": true, "juicity": true,
	"socks": true, "socks4": true, "socks5": true,
	"wireguard": true, "wg": true,
}

// mihomoTopLevelKeys are keys that only a mihomo configuration carries. One of
// them at the start of a line settles the format before anything else is
// guessed at.
var mihomoTopLevelKeys = []string{
	"proxies:", "proxy-providers:", "proxy-groups:", "rule-providers:",
}

// ConvertSubscription turns a subscription body of any supported format into a
// mihomo YAML configuration.
//
// A body that is already mihomo YAML is returned untouched, so a subscription
// that used to work keeps running exactly the configuration its author wrote.
func ConvertSubscription(body string) (*ConvertResult, error) {
	// Panels that generate the file on Windows often leave a byte-order mark on
	// it, which the YAML parser reads as part of the first key.
	text := strings.TrimPrefix(body, "\ufeff")
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("подписка пустая")
	}

	switch format, payload := detectFormat(text); format {
	case FormatXray:
		return convertXray(payload)
	case FormatURI:
		return convertURIList(payload)
	default:
		return &ConvertResult{Config: text, Format: FormatMihomo, Sheet: mihomoSheet(text), Nodes: mihomoNodes(text)}, nil
	}
}

// detectFormat recognises the body, and returns the payload to convert. The
// payload differs from the input only when the body was base64-wrapped, which
// is how most panels hand out a URI list.
func detectFormat(text string) (string, string) {
	if format := formatOf(text); format != FormatMihomo {
		return format, text
	}
	// A wrapped body is one long base64 blob, so only bodies that are not
	// already recognisable are worth the decode attempt.
	if decoded, err := mconvert.TryDecodeBase64(strings.TrimSpace(text)); err == nil {
		if format := formatOf(string(decoded)); format != FormatMihomo {
			return format, string(decoded)
		}
	}
	return FormatMihomo, text
}

// formatOf reports the format of an unwrapped body.
func formatOf(text string) string {
	if startsJSON(text) {
		return FormatXray
	}
	// A mihomo document is checked for before the URI schemes, because its
	// own contents may well mention them.
	for _, line := range strings.Split(text, "\n") {
		for _, key := range mihomoTopLevelKeys {
			if strings.HasPrefix(line, key) {
				return FormatMihomo
			}
		}
	}
	for _, line := range strings.Split(text, "\n") {
		scheme, _, found := strings.Cut(strings.TrimSpace(line), "://")
		if found && proxyURISchemes[strings.ToLower(scheme)] {
			return FormatURI
		}
	}
	return FormatMihomo
}

// startsJSON reports whether the body's first meaningful character opens a
// JSON object or array.
//
// The comments have to be skipped rather than the first character taken as it
// comes: Xray accepts // and /* */ in its configuration files, and a generated
// one usually opens with a comment naming the panel that wrote it.
func startsJSON(text string) bool {
	for i := 0; i < len(text); {
		rest := text[i:]
		switch {
		case text[i] == ' ' || text[i] == '\t' || text[i] == '\r' || text[i] == '\n':
			i++
		case strings.HasPrefix(rest, "//"):
			end := strings.IndexByte(rest, '\n')
			if end < 0 {
				return false
			}
			i += end + 1
		case strings.HasPrefix(rest, "/*"):
			end := strings.Index(rest[2:], "*/")
			if end < 0 {
				return false
			}
			i += 2 + end + 2
		default:
			return text[i] == '{' || text[i] == '['
		}
	}
	return false
}

// convertXray converts an Xray Core JSON configuration.
func convertXray(text string) (*ConvertResult, error) {
	configs, err := xray.ParseConfigs([]byte(text))
	if err != nil {
		return nil, fmt.Errorf("разбор Xray-конфига: %w", err)
	}

	result, err := convert.Convert(configs, convert.Options{
		UDP: true,
		// Each balancer becomes the mihomo group that behaves the way its
		// strategy does, rather than one type for all of them.
		BalancerGroupType: "auto",
	})
	if err != nil {
		return nil, fmt.Errorf("конвертация Xray → mihomo: %w", err)
	}
	if len(result.Proxies) == 0 {
		return nil, fmt.Errorf("в Xray-конфиге нет узлов, которые удалось перевести в mihomo:\n%s",
			diagnosticsText(result))
	}

	selectable := result.Selectable()
	doc := mihomo.BuildAndroid(result.Proxies, result.Groups, selectable)
	yamlText, err := mihomo.Render(doc, []string{
		"Сконвертировано из Xray JSON клиентом Misetanibox.",
		fmt.Sprintf("Узлов: %d, групп: %d.", result.Converted, len(result.Groups)),
	})
	if err != nil {
		return nil, fmt.Errorf("сборка YAML: %w", err)
	}

	return &ConvertResult{
		Config:  yamlText,
		Format:  FormatXray,
		Proxies: result.Converted,
		Groups:  len(result.Groups),
		Names:   strings.Join(selectable, "\n"),
		Notes:   diagnosticsText(result),
	}, nil
}

func diagnosticsText(result *convert.Result) string {
	lines := make([]string, 0, len(result.Diagnostics))
	for _, d := range result.Diagnostics {
		lines = append(lines, d.String())
	}
	return strings.Join(lines, "\n")
}

// convertURIList converts a list of proxy URIs, which is what a subscription
// written for the V2Ray-family clients contains.
//
// The parsing is the core's own, so a link the core understands converts here
// as well -- and one it does not is not silently turned into a broken node.
func convertURIList(text string) (*ConvertResult, error) {
	raw, err := mconvert.ConvertsV2Ray([]byte(text))
	if err != nil {
		return nil, fmt.Errorf("разбор списка ссылок: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("в подписке нет ссылок, которые удалось разобрать")
	}

	proxies := make([]*yamlx.Map, 0, len(raw))
	names := make([]string, 0, len(raw))
	for _, p := range raw {
		name, _ := p["name"].(string)
		if name == "" {
			continue
		}
		proxies = append(proxies, yamlMapOf(p))
		names = append(names, name)
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("в подписке нет ссылок, которые удалось разобрать")
	}

	doc := mihomo.BuildAndroid(proxies, nil, names)
	yamlText, err := mihomo.Render(doc, []string{
		"Сконвертировано из списка ссылок клиентом Misetanibox.",
		fmt.Sprintf("Узлов: %d.", len(proxies)),
	})
	if err != nil {
		return nil, fmt.Errorf("сборка YAML: %w", err)
	}

	return &ConvertResult{
		Config:  yamlText,
		Format:  FormatURI,
		Proxies: len(proxies),
		Names:   strings.Join(names, "\n"),
	}, nil
}

// leadingProxyKeys come first in a converted node, so that a person reading
// the generated file sees what the node is before how it is dialled.
var leadingProxyKeys = []string{"name", "type", "server", "port"}

// yamlMapOf renders a decoded proxy as an ordered map. The order is fixed
// rather than whatever the map iteration produces, so the same subscription
// always converts to the same file.
func yamlMapOf(src map[string]any) *yamlx.Map {
	out := yamlx.NewMap()
	for _, key := range leadingProxyKeys {
		if v, ok := src[key]; ok {
			out.Set(key, yamlValueOf(v))
		}
	}
	rest := make([]string, 0, len(src))
	for k := range src {
		if !containsString(leadingProxyKeys, k) {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		out.Set(k, yamlValueOf(src[k]))
	}
	return out
}

// yamlValueOf converts a decoded JSON value into something yamlx can write.
func yamlValueOf(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return yamlMapOf(val)
	case []any:
		return yamlSeqOf(val)
	case []string:
		items := make([]any, 0, len(val))
		for _, s := range val {
			items = append(items, s)
		}
		return yamlSeqOf(items)
	default:
		return v
	}
}

// yamlSeqOf writes a list inline when every item is a scalar, which keeps
// short lists such as alpn on one line.
func yamlSeqOf(items []any) any {
	scalars := true
	converted := make([]any, 0, len(items))
	for _, item := range items {
		c := yamlValueOf(item)
		switch c.(type) {
		case *yamlx.Map, yamlx.Seq, yamlx.FlowSeq:
			scalars = false
		}
		converted = append(converted, c)
	}
	if scalars {
		return yamlx.FlowSeq(converted)
	}
	return yamlx.Seq(converted)
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// mihomoSheet — {main, auto, members[]} главного селектора из YAML подписки.
func mihomoSheet(text string) string {
	var root struct {
		Groups []struct {
			Name    string   `yaml:"name"`
			Type    string   `yaml:"type"`
			Proxies []string `yaml:"proxies"`
		} `yaml:"proxy-groups"`
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(text), &root); err != nil || len(root.Groups) == 0 {
		return ""
	}
	main := ""
	for _, r := range root.Rules {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(r)), "MATCH,") {
			if parts := strings.Split(r, ","); len(parts) >= 2 {
				main = strings.TrimSpace(parts[1])
			}
		}
	}
	types := map[string]string{}
	for _, gr := range root.Groups {
		types[gr.Name] = strings.ToLower(gr.Type)
	}
	if main == "" || types[main] != "select" {
		for _, gr := range root.Groups {
			if strings.ToLower(gr.Type) == "select" && gr.Name != "GLOBAL" {
				main = gr.Name
				break
			}
		}
	}
	out := struct {
		Main    string              `json:"main"`
		Auto    string              `json:"auto"`
		Members []string            `json:"members"`
		Groups  map[string][]string `json:"groups"`
	}{Main: main, Groups: map[string][]string{}}
	for _, gr := range root.Groups {
		if gr.Name != main && len(gr.Proxies) > 0 {
			out.Groups[gr.Name] = gr.Proxies
		}
	}
	for _, gr := range root.Groups {
		if gr.Name != main {
			continue
		}
		for _, m := range gr.Proxies {
			switch strings.ToUpper(m) {
			case "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE":
				continue
			}
			if types[m] == "url-test" && out.Auto == "" {
				out.Auto = m
			}
			out.Members = append(out.Members, m)
		}
	}
	if len(out.Members) == 0 {
		return ""
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// mihomoNodes — {имя: "server:port"} по proxies подписки.
func mihomoNodes(text string) string {
	var root struct {
		Proxies []struct {
			Name   string      `yaml:"name"`
			Server string      `yaml:"server"`
			Port   interface{} `yaml:"port"`
		} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(text), &root); err != nil || len(root.Proxies) == 0 {
		return ""
	}
	m := map[string]string{}
	for _, p := range root.Proxies {
		if p.Name == "" || p.Server == "" || p.Port == nil {
			continue
		}
		m[p.Name] = p.Server + ":" + strings.TrimSpace(strings.Trim(fmt.Sprint(p.Port), "\""))
	}
	b, _ := json.Marshal(m)
	return string(b)
}
