package convert

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"misetanibox/mobilecore/internal/xray"
	"misetanibox/mobilecore/internal/yamlx"
)

// unmarshalSettings decodes an outbound's settings object.
func unmarshalSettings(ob *xray.Outbound, dst any) error {
	if len(ob.Settings) == 0 || strings.TrimSpace(string(ob.Settings)) == "null" {
		return fmt.Errorf("the outbound has no settings")
	}
	if err := json.Unmarshal(ob.Settings, dst); err != nil {
		return fmt.Errorf("parsing settings: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- VLESS ----

func (c *converter) convertVLESS(ob *xray.Outbound, preferred string) ([]*yamlx.Map, error) {
	var settings xray.VLESSSettings
	if err := unmarshalSettings(ob, &settings); err != nil {
		return nil, err
	}
	endpoints := settings.Endpoints()
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("the vless outbound has no server")
	}
	if strings.TrimSpace(string(settings.Seed)) != "" {
		c.warn("vless \"seed\" has no mihomo equivalent and was dropped")
	}

	var out []*yamlx.Map
	for _, ep := range endpoints {
		name := c.name(preferred, ob.Tag, "vless", ep.Address, ep.Port)
		m, err := c.base(name, "vless", ep.Address, ep.Port)
		if err != nil {
			return nil, err
		}
		if ep.ID == "" {
			return nil, fmt.Errorf("the vless outbound has no user id")
		}
		m.Set("uuid", ep.ID)

		if flow := normaliseFlow(ep.Flow); flow != "" {
			switch flow {
			case "xtls-rprx-vision":
				m.Set("flow", flow)
			default:
				return nil, fmt.Errorf("mihomo only supports the xtls-rprx-vision flow, not %q", ep.Flow)
			}
		}

		if enc, err := c.vlessEncryption(ep.Encryption); err != nil {
			return nil, err
		} else if enc != "" {
			m.Set("encryption", enc)
		}

		c.udpFlag(m)
		c.applyMux(m, ob, "vless")
		c.applyTLS(m, ob.StreamSettings, tlsV2Ray)
		if err := c.applyTransport(m, ob.StreamSettings, "vless"); err != nil {
			return nil, err
		}
		c.applyDialer(m, ob)
		out = append(out, m)
	}
	return out, nil
}

// normaliseFlow trims the flow to the part mihomo understands. Xray's
// "-udp443" suffix only changes how UDP/443 is handled and mihomo drops it.
func normaliseFlow(flow string) string {
	flow = strings.TrimSpace(flow)
	if flow == "" || flow == "none" {
		return ""
	}
	return strings.TrimSuffix(flow, "-udp443")
}

// vlessEncryption validates Xray's VLESS encryption string and returns it in
// the form mihomo expects, which is the same string.
//
// mihomo parses this field with the identical grammar Xray uses, so the value
// passes through untouched -- but an invalid one makes mihomo reject the whole
// configuration file, so it is checked here rather than passed on blindly.
func (c *converter) vlessEncryption(enc string) (string, error) {
	enc = strings.TrimSpace(enc)
	if enc == "" || enc == "none" {
		return "", nil
	}

	parts := strings.Split(enc, ".")
	if len(parts) < 4 || parts[0] != "mlkem768x25519plus" {
		return "", fmt.Errorf("unsupported vless encryption %q: mihomo only implements mlkem768x25519plus", enc)
	}
	switch parts[1] {
	case "native", "xorpub", "random":
	default:
		return "", fmt.Errorf("invalid vless encryption %q: mode must be native, xorpub or random", enc)
	}
	switch parts[2] {
	case "1rtt", "0rtt":
	default:
		// A "600s"-style value belongs in the server's decryption field; using
		// it on a client makes mihomo (and Xray) reject the node.
		return "", fmt.Errorf("invalid vless encryption %q: the client field takes 1rtt or 0rtt, not %q "+
			"(a value like \"600s\" belongs in the server's decryption field)", enc, parts[2])
	}

	// Remaining tokens are either padding descriptors or base64 keys. mihomo
	// tells them apart by length, so the same rule is applied here.
	keys := 0
	var padding []string
	for _, token := range parts[3:] {
		if len(token) < 20 {
			padding = append(padding, token)
			continue
		}
		raw, err := decodeBase64RawURL(token)
		if err != nil {
			return "", fmt.Errorf("invalid vless encryption %q: key %q is not raw-URL base64", enc, truncate(token))
		}
		// 32 bytes is an X25519 public key, 1184 an ML-KEM-768 encapsulation key.
		if len(raw) != 32 && len(raw) != 1184 {
			return "", fmt.Errorf("invalid vless encryption %q: key %q decodes to %d bytes, expected 32 or 1184",
				enc, truncate(token), len(raw))
		}
		keys++
	}
	if keys == 0 {
		return "", fmt.Errorf("invalid vless encryption %q: no server key found", enc)
	}
	if err := validatePadding(padding); err != nil {
		return "", fmt.Errorf("invalid vless encryption %q: %w", enc, err)
	}
	return enc, nil
}

// validatePadding checks the padding descriptors of a VLESS encryption
// string. Each one is "a-b-c"; they alternate between length and gap
// descriptors, and the first one has minimum values.
//
// mihomo rejects the entire configuration file when a single proxy carries a
// malformed value here, so the rules are mirrored rather than trusted.
func validatePadding(tokens []string) error {
	if len(tokens) == 0 {
		return nil
	}
	maxLen := 0
	for i, token := range tokens {
		fields := strings.Split(token, "-")
		if len(fields) < 3 || fields[0] == "" || fields[1] == "" || fields[2] == "" {
			return fmt.Errorf("padding parameter %q must have the form a-b-c", token)
		}
		var values [3]int
		for j := 0; j < 3; j++ {
			n, err := strconv.Atoi(fields[j])
			if err != nil {
				return fmt.Errorf("padding parameter %q is not numeric", token)
			}
			values[j] = n
		}
		if i == 0 && (values[0] < 100 || values[1] < 35 || values[2] < 35) {
			return fmt.Errorf("the first padding parameter %q must be at least 100-35-35", token)
		}
		if i%2 == 0 {
			maxLen += max(values[1], values[2])
		}
	}
	if maxLen > 18+65535 {
		return fmt.Errorf("the total padding length must not exceed 65553")
	}
	return nil
}

func truncate(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "..."
}

// ---------------------------------------------------------------- VMess ----

func (c *converter) convertVMess(ob *xray.Outbound, preferred string) ([]*yamlx.Map, error) {
	var settings xray.VMessSettings
	if err := unmarshalSettings(ob, &settings); err != nil {
		return nil, err
	}
	endpoints := settings.Endpoints()
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("the vmess outbound has no server")
	}

	var out []*yamlx.Map
	for _, ep := range endpoints {
		name := c.name(preferred, ob.Tag, "vmess", ep.Address, ep.Port)
		m, err := c.base(name, "vmess", ep.Address, ep.Port)
		if err != nil {
			return nil, err
		}
		if ep.ID == "" {
			return nil, fmt.Errorf("the vmess outbound has no user id")
		}
		m.Set("uuid", ep.ID)
		// mihomo requires alterId, including the modern value of 0.
		m.Set("alterId", ep.AlterID)
		m.Set("cipher", vmessCipher(ep.Security))

		if ep.Experiments != "" {
			// The experiment flags have dedicated mihomo options.
			if strings.Contains(ep.Experiments, "AuthenticatedLength") {
				m.Set("authenticated-length", true)
			}
			if strings.Contains(ep.Experiments, "NoTerminationSignal") {
				c.warn("the vmess NoTerminationSignal experiment has no mihomo equivalent and was dropped")
			}
		}

		c.udpFlag(m)
		c.applyMux(m, ob, "vmess")
		c.applyTLS(m, ob.StreamSettings, tlsV2Ray)
		if err := c.applyTransport(m, ob.StreamSettings, "vmess"); err != nil {
			return nil, err
		}
		c.applyDialer(m, ob)
		out = append(out, m)
	}
	return out, nil
}

// vmessCipher maps Xray's user security to a cipher mihomo accepts.
func vmessCipher(security string) string {
	switch strings.ToLower(strings.TrimSpace(security)) {
	case "aes-128-gcm":
		return "aes-128-gcm"
	case "chacha20-poly1305":
		return "chacha20-poly1305"
	case "none":
		return "none"
	case "zero":
		return "zero"
	default:
		return "auto"
	}
}

// --------------------------------------------------------------- Trojan ----

func (c *converter) convertTrojan(ob *xray.Outbound, preferred string) ([]*yamlx.Map, error) {
	var settings xray.TrojanSettings
	if err := unmarshalSettings(ob, &settings); err != nil {
		return nil, err
	}
	servers := settings.Endpoints()
	if len(servers) == 0 {
		return nil, fmt.Errorf("the trojan outbound has no server")
	}

	var out []*yamlx.Map
	for _, sv := range servers {
		name := c.name(preferred, ob.Tag, "trojan", string(sv.Address), sv.Port.Int())
		m, err := c.base(name, "trojan", string(sv.Address), sv.Port.Int())
		if err != nil {
			return nil, err
		}
		password := strings.TrimSpace(string(sv.Password))
		if password == "" {
			return nil, fmt.Errorf("the trojan outbound has no password")
		}
		m.Set("password", password)

		if flow := normaliseFlow(string(sv.Flow)); flow != "" {
			// mihomo's trojan has no flow field at all.
			c.warn("trojan flow %q has no mihomo equivalent and was dropped", sv.Flow)
		}

		c.udpFlag(m)
		c.applyMux(m, ob, "trojan")
		c.applyTLS(m, ob.StreamSettings, tlsTrojan)
		if err := c.applyTransport(m, ob.StreamSettings, "trojan"); err != nil {
			return nil, err
		}
		c.applyDialer(m, ob)
		out = append(out, m)
	}
	return out, nil
}

// ---------------------------------------------------------- Shadowsocks ----

func (c *converter) convertShadowsocks(ob *xray.Outbound, preferred string) ([]*yamlx.Map, error) {
	var settings xray.ShadowsocksSettings
	if err := unmarshalSettings(ob, &settings); err != nil {
		return nil, err
	}
	servers := settings.Endpoints()
	if len(servers) == 0 {
		return nil, fmt.Errorf("the shadowsocks outbound has no server")
	}

	var out []*yamlx.Map
	for _, sv := range servers {
		name := c.name(preferred, ob.Tag, "ss", string(sv.Address), sv.Port.Int())
		m, err := c.base(name, "ss", string(sv.Address), sv.Port.Int())
		if err != nil {
			return nil, err
		}
		cipher := ssCipher(string(sv.Method))
		if cipher == "" {
			return nil, fmt.Errorf("unsupported shadowsocks method %q", sv.Method)
		}
		m.Set("cipher", cipher)
		m.Set("password", string(sv.Password))
		c.udpFlag(m)
		if sv.UoT.Bool() {
			m.Set("udp-over-tcp", true)
			if v := sv.UoTVer.Int(); v != 0 {
				m.Set("udp-over-tcp-version", v)
			}
		}

		// Shadowsocks in Xray ignores streamSettings, but generated configs
		// sometimes carry one anyway.
		if ob.StreamSettings != nil && ob.StreamSettings.NetworkName() != "tcp" {
			c.warn("shadowsocks ignores streamSettings; the %s transport was dropped", ob.StreamSettings.NetworkName())
		}
		c.applyDialer(m, ob)
		out = append(out, m)
	}
	return out, nil
}

// ssCipher normalises a shadowsocks method name to mihomo's spelling.
func ssCipher(method string) string {
	m := strings.ToLower(strings.TrimSpace(method))
	switch m {
	case "":
		return ""
	case "plain", "none":
		return "none"
	case "chacha20-poly1305", "chacha20-ietf-poly1305":
		return "chacha20-ietf-poly1305"
	case "xchacha20-poly1305", "xchacha20-ietf-poly1305":
		return "xchacha20-ietf-poly1305"
	}
	// AEAD, AEAD-2022 and the stream ciphers all use the same names in both
	// projects.
	return m
}

// ------------------------------------------------------- SOCKS and HTTP ----

func (c *converter) convertSocks(ob *xray.Outbound, preferred string) ([]*yamlx.Map, error) {
	var settings xray.ProxyServerSettings
	if err := unmarshalSettings(ob, &settings); err != nil {
		return nil, err
	}
	endpoints := settings.Endpoints()
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("the socks outbound has no server")
	}

	var out []*yamlx.Map
	for _, ep := range endpoints {
		name := c.name(preferred, ob.Tag, "socks5", ep.Address, ep.Port)
		m, err := c.base(name, "socks5", ep.Address, ep.Port)
		if err != nil {
			return nil, err
		}
		m.SetStr("username", ep.User)
		m.SetStr("password", ep.Pass)
		c.udpFlag(m)
		if ob.StreamSettings != nil && ob.StreamSettings.SecurityName() == "tls" {
			m.Set("tls", true)
			if t := ob.StreamSettings.TLS(); t != nil {
				if t.AllowInsecure.Bool() || c.opts.SkipCertVerify {
					m.Set("skip-cert-verify", true)
				}
			}
		}
		c.applyDialer(m, ob)
		out = append(out, m)
	}
	return out, nil
}

func (c *converter) convertHTTP(ob *xray.Outbound, preferred string) ([]*yamlx.Map, error) {
	var settings xray.ProxyServerSettings
	if err := unmarshalSettings(ob, &settings); err != nil {
		return nil, err
	}
	endpoints := settings.Endpoints()
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("the http outbound has no server")
	}

	var out []*yamlx.Map
	for _, ep := range endpoints {
		name := c.name(preferred, ob.Tag, "http", ep.Address, ep.Port)
		m, err := c.base(name, "http", ep.Address, ep.Port)
		if err != nil {
			return nil, err
		}
		m.SetStr("username", ep.User)
		m.SetStr("password", ep.Pass)
		if ob.StreamSettings != nil && ob.StreamSettings.SecurityName() == "tls" {
			m.Set("tls", true)
			if t := ob.StreamSettings.TLS(); t != nil {
				m.SetStr("sni", strings.TrimSpace(string(t.ServerName)))
				if t.AllowInsecure.Bool() || c.opts.SkipCertVerify {
					m.Set("skip-cert-verify", true)
				}
			}
		}
		if len(ep.Headers) > 0 {
			headers := yamlx.NewMap()
			for _, k := range sortedKeys(ep.Headers) {
				headers.SetStr(k, string(ep.Headers[k]))
			}
			m.Set("headers", headers)
		}
		c.applyDialer(m, ob)
		out = append(out, m)
	}
	return out, nil
}

// ------------------------------------------------------------ WireGuard ----

func (c *converter) convertWireGuard(ob *xray.Outbound, preferred string) ([]*yamlx.Map, error) {
	var settings xray.WireGuardSettings
	if err := unmarshalSettings(ob, &settings); err != nil {
		return nil, err
	}
	if len(settings.Peers) == 0 {
		return nil, fmt.Errorf("the wireguard outbound has no peers")
	}
	secret := strings.TrimSpace(string(settings.SecretKey))
	if secret == "" {
		return nil, fmt.Errorf("the wireguard outbound has no secretKey")
	}

	// mihomo takes the first peer's endpoint as the proxy address and carries
	// any further peers in a "peers" list.
	primary := settings.Peers[0]
	host, port, err := splitEndpoint(string(primary.Endpoint))
	if err != nil {
		return nil, fmt.Errorf("peer endpoint: %w", err)
	}

	name := c.name(preferred, ob.Tag, "wireguard", host, port)
	m, err := c.base(name, "wireguard", host, port)
	if err != nil {
		return nil, err
	}
	m.Set("private-key", secret)
	m.SetStr("public-key", strings.TrimSpace(string(primary.PublicKey)))
	m.SetStr("pre-shared-key", strings.TrimSpace(string(primary.PreSharedKey)))

	for _, addr := range settings.Address {
		a := strings.TrimSpace(addr)
		if a == "" {
			continue
		}
		// mihomo wants the bare interface address, not a CIDR.
		if i := strings.IndexByte(a, '/'); i >= 0 {
			a = a[:i]
		}
		if strings.Contains(a, ":") {
			if !m.Has("ipv6") {
				m.Set("ipv6", a)
			}
		} else if !m.Has("ip") {
			m.Set("ip", a)
		}
	}

	if len(primary.AllowedIPs) > 0 {
		m.Set("allowed-ips", toFlowSeq(primary.AllowedIPs))
	}
	m.SetInt("mtu", settings.MTU.Int())
	m.SetInt("persistent-keepalive", primary.KeepAlive.Int())
	if reserved := parseReserved(settings.Reserved); len(reserved) > 0 {
		seq := make(yamlx.FlowSeq, 0, len(reserved))
		for _, b := range reserved {
			seq = append(seq, int(b))
		}
		m.Set("reserved", seq)
	}
	c.udpFlag(m)

	if len(settings.Peers) > 1 {
		peers := make(yamlx.Seq, 0, len(settings.Peers))
		for _, p := range settings.Peers {
			ph, pp, err := splitEndpoint(string(p.Endpoint))
			if err != nil {
				c.warn("wireguard peer with endpoint %q was dropped: %v", p.Endpoint, err)
				continue
			}
			pm := yamlx.NewMap()
			pm.Set("server", ph)
			pm.Set("port", pp)
			pm.SetStr("public-key", strings.TrimSpace(string(p.PublicKey)))
			pm.SetStr("pre-shared-key", strings.TrimSpace(string(p.PreSharedKey)))
			if len(p.AllowedIPs) > 0 {
				pm.Set("allowed-ips", toFlowSeq(p.AllowedIPs))
			}
			peers = append(peers, pm)
		}
		if len(peers) > 1 {
			m.Set("peers", peers)
		}
	}

	c.applyDialer(m, ob)
	return []*yamlx.Map{m}, nil
}

// parseReserved accepts the reserved bytes as a JSON array or a base64 string.
func parseReserved(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var nums []int
		if err := json.Unmarshal(raw, &nums); err != nil {
			return nil
		}
		out := make([]byte, 0, len(nums))
		for _, n := range nums {
			out = append(out, byte(n))
		}
		return out
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	decoded, err := decodeBase64Any(s)
	if err != nil {
		return nil
	}
	return decoded
}

// splitEndpoint splits a "host:port" endpoint, handling bracketed IPv6.
func splitEndpoint(endpoint string) (string, int, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", 0, fmt.Errorf("the endpoint is empty")
	}
	host, portStr, err := splitHostPort(endpoint)
	if err != nil {
		return "", 0, err
	}
	port, err := atoiPort(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}
