package mobilecore

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"
)

// Цепочки и WARP-выход — та же механика, что на десктопе (core/clash/chains.go, warp.go):
// каждый хоп после входа — копия узла с dialer-proxy на предыдущий, выход «🔗 Имя»
// добавляется в select-группы; WARP — узел type: wireguard из зарегистрированных кредов.

const (
	ChainPrefix    = "🔗 "
	ChainHopPrefix = "⛓ "
	WarpNodeName   = "WARP"

	warpServer = "engage.cloudflareclient.com"
	warpPort   = 2408
)

type ProxyChain struct {
	Name  string   `json:"name"`
	Nodes []string `json:"nodes"`
}

type WarpCreds struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Address4   string `json:"address4"`
	Address6   string `json:"address6"`
	Reserved   []int  `json:"reserved"`
}

var (
	injectMu   sync.Mutex
	chainsJSON string
	warpJSON   string
)

// SetChains — JSON-массив [{name, nodes:[...]}]; применяется при следующем Start.
func SetChains(js string) {
	injectMu.Lock()
	chainsJSON = js
	injectMu.Unlock()
}

// SetWarp — JSON кредов WARP ("" = выключен); применяется при следующем Start.
func SetWarp(js string) {
	injectMu.Lock()
	warpJSON = js
	injectMu.Unlock()
}

func currentChains() []ProxyChain {
	injectMu.Lock()
	js := chainsJSON
	injectMu.Unlock()
	var out []ProxyChain
	if strings.TrimSpace(js) == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(js), &out); err != nil {
		return nil
	}
	return out
}

func currentWarp() *WarpCreds {
	injectMu.Lock()
	js := warpJSON
	injectMu.Unlock()
	if strings.TrimSpace(js) == "" {
		return nil
	}
	var c WarpCreds
	if err := json.Unmarshal([]byte(js), &c); err != nil || c.PrivateKey == "" || c.PublicKey == "" {
		return nil
	}
	return &c
}

// prepareConfig — вшивает WARP и цепочки в YAML подписки. Любая ошибка → исходный конфиг.
func prepareConfig(configYAML string) string {
	chains := currentChains()
	warp := currentWarp()
	if len(chains) == 0 && warp == nil {
		return configYAML
	}
	var root map[string]interface{}
	if err := yaml.Unmarshal([]byte(configYAML), &root); err != nil || root == nil {
		return configYAML
	}
	if warp != nil {
		injectWarp(root, warp)
	}
	if len(chains) > 0 {
		injectChains(root, chains)
	}
	out, err := yaml.Marshal(root)
	if err != nil {
		return configYAML
	}
	return string(out)
}

func toList(v interface{}) []interface{} {
	l, _ := v.([]interface{})
	return l
}

func injectWarp(root map[string]interface{}, creds *WarpCreds) {
	proxies := toList(root["proxies"])
	for _, p := range proxies {
		if pm, ok := p.(map[string]interface{}); ok {
			if n, _ := pm["name"].(string); n == WarpNodeName {
				return
			}
		}
	}
	reserved := make([]interface{}, 0, 3)
	for _, r := range creds.Reserved {
		reserved = append(reserved, r)
	}
	warp := map[string]interface{}{
		"name":               WarpNodeName,
		"type":               "wireguard",
		"server":             warpServer,
		"port":               warpPort,
		"ip":                 creds.Address4,
		"ipv6":               creds.Address6,
		"private-key":        creds.PrivateKey,
		"public-key":         creds.PublicKey,
		"reserved":           reserved,
		"udp":                true,
		"mtu":                1280,
		"remote-dns-resolve": true,
	}
	root["proxies"] = append(proxies, warp)
}

// matchPolicy — политика последнего правила MATCH (главный селектор подписки).
func matchPolicy(root map[string]interface{}) string {
	policy := ""
	for _, r := range toList(root["rules"]) {
		s, _ := r.(string)
		s = strings.TrimSpace(s)
		if strings.HasPrefix(strings.ToUpper(s), "MATCH,") {
			parts := strings.Split(s, ",")
			if len(parts) >= 2 {
				policy = strings.TrimSpace(parts[1])
			}
		}
	}
	return policy
}

func injectChains(root map[string]interface{}, chains []ProxyChain) {
	proxies := toList(root["proxies"])
	if len(proxies) == 0 {
		return
	}
	byName := make(map[string]map[string]interface{}, len(proxies))
	for _, p := range proxies {
		if pm, ok := p.(map[string]interface{}); ok {
			if n, _ := pm["name"].(string); n != "" {
				byName[n] = pm
			}
		}
	}
	groups := toList(root["proxy-groups"])
	groupNames := map[string]bool{}
	for _, g := range groups {
		if gm, ok := g.(map[string]interface{}); ok {
			if n, _ := gm["name"].(string); n != "" {
				groupNames[n] = true
			}
		}
	}

	var added []interface{}
	var exits []string
	for _, ch := range chains {
		name := strings.TrimSpace(ch.Name)
		if name == "" {
			continue
		}
		nodes := make([]string, 0, len(ch.Nodes))
		for _, n := range ch.Nodes {
			if n = strings.TrimSpace(n); n != "" {
				nodes = append(nodes, n)
			}
		}
		if len(nodes) < 2 {
			continue
		}
		// вход может быть группой (dialer-proxy умеет группы), остальные хопы — только реальные узлы
		if byName[nodes[0]] == nil && !groupNames[nodes[0]] {
			continue
		}
		valid := true
		for _, n := range nodes[1:] {
			if byName[n] == nil {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		prev := nodes[0]
		for i := 1; i < len(nodes); i++ {
			src := byName[nodes[i]]
			def := make(map[string]interface{}, len(src)+2)
			for k, v := range src {
				def[k] = v
			}
			var cname string
			if i == len(nodes)-1 {
				cname = ChainPrefix + name
			} else {
				cname = ChainHopPrefix + name + " " + strconv.Itoa(i)
			}
			def["name"] = cname
			def["dialer-proxy"] = prev
			added = append(added, def)
			prev = cname
		}
		exits = append(exits, ChainPrefix+name)
	}
	if len(added) == 0 {
		return
	}
	root["proxies"] = append(proxies, added...)

	mainSel := matchPolicy(root)
	for _, g := range groups {
		gm, ok := g.(map[string]interface{})
		if !ok {
			continue
		}
		if t, _ := gm["type"].(string); t != "select" {
			continue
		}
		if ia, _ := gm["include-all"].(bool); ia {
			continue
		}
		if ia, _ := gm["include-all-proxies"].(bool); ia {
			continue
		}
		gname, _ := gm["name"].(string)
		if strings.HasPrefix(gname, ChainPrefix) || strings.HasPrefix(gname, ChainHopPrefix) {
			continue
		}
		gp := toList(gm["proxies"])
		hasRealNode := gname == mainSel
		for _, m := range gp {
			if mn, _ := m.(string); byName[mn] != nil {
				hasRealNode = true
				break
			}
		}
		if !hasRealNode {
			continue
		}
		for _, e := range exits {
			gp = append(gp, e)
		}
		gm["proxies"] = gp
	}
}

func genWGKeypair() (priv, pub string, err error) {
	var privKey [32]byte
	if _, err = rand.Read(privKey[:]); err != nil {
		return
	}
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64
	pubKey, err := curve25519.X25519(privKey[:], curve25519.Basepoint)
	if err != nil {
		return
	}
	return base64.StdEncoding.EncodeToString(privKey[:]), base64.StdEncoding.EncodeToString(pubKey), nil
}

func stripCIDR(addr string) string {
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		return addr[:i]
	}
	return addr
}

// WarpKeypair — пара ключей WireGuard "priv\npub" (регистрацию в Cloudflare делает Kotlin:
// у Go-резолвера на Android нет /etc/resolv.conf, а системный DNS ему недоступен).
func WarpKeypair() (string, error) {
	priv, pub, err := genWGKeypair()
	if err != nil {
		return "", err
	}
	return priv + "\n" + pub, nil
}
