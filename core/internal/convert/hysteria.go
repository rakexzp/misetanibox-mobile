package convert

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"misetanibox/mobilecore/internal/xray"
	"misetanibox/mobilecore/internal/yamlx"
)

// A Hysteria2 node reaches this converter in two shapes.
//
// Xray writes one natively: the "hysteria" outbound protocol holds nothing but
// the address and port, while the password and everything else live in
// streamSettings -- "hysteriaSettings" for the credential, "finalmask" for the
// QUIC parameters and the obfuscator. Configuration sets that mix protocols
// carry the other shape, written the way the Hysteria2 client or a sing-box
// style generator writes it, with every field inside "settings".
//
// Both describe the same server, and both become a mihomo hysteria2 proxy.

// hysteriaParams gathers the settings of a Hysteria2 node from wherever the
// configuration happens to put them. Values found in the outbound's own
// settings win, since a generator that fills those means them.
type hysteriaParams struct {
	password     string
	up, down     string
	ports        string
	hopInterval  string
	obfs         string
	obfsPassword string
	obfsMinSize  int
	obfsMaxSize  int
	bbrProfile   string

	initStreamWindow     uint64
	maxStreamWindow      uint64
	initConnectionWindow uint64
	maxConnectionWindow  uint64
}

// fromStream reads the parts of a Hysteria2 node that Xray keeps in
// streamSettings, which is where a natively written config puts the password.
func (p *hysteriaParams) fromStream(c *converter, ss *xray.StreamSettings) {
	if ss == nil {
		return
	}

	if h := ss.HysteriaSettings; h != nil {
		p.password = xray.FirstNonEmpty(p.password, string(h.Auth))
		p.up = xray.FirstNonEmpty(p.up, string(h.Up))
		p.down = xray.FirstNonEmpty(p.down, string(h.Down))
		if h.UdpHop != nil {
			p.ports = xray.FirstNonEmpty(p.ports, h.UdpHop.Ports.String())
			p.hopInterval = xray.FirstNonEmpty(p.hopInterval, h.UdpHop.Interval.String())
		}
		if h.UdpIdleTimeout.Int() != 0 {
			c.warn("hysteriaSettings.udpIdleTimeout has no mihomo equivalent and was dropped")
		}
	}

	// Newer Xray builds moved the bandwidth, port hopping and QUIC window
	// settings out of hysteriaSettings and into finalmask.
	if q := ss.QuicParams(); q != nil {
		p.up = xray.FirstNonEmpty(p.up, string(q.BrutalUp))
		p.down = xray.FirstNonEmpty(p.down, string(q.BrutalDown))
		p.bbrProfile = xray.FirstNonEmpty(p.bbrProfile, string(q.BbrProfile))
		if q.UdpHop != nil {
			p.ports = xray.FirstNonEmpty(p.ports, q.UdpHop.Ports.String())
			p.hopInterval = xray.FirstNonEmpty(p.hopInterval, q.UdpHop.Interval.String())
		}
		p.initStreamWindow = q.InitStreamReceiveWindow
		p.maxStreamWindow = q.MaxStreamReceiveWindow
		p.initConnectionWindow = q.InitConnectionReceiveWindow
		p.maxConnectionWindow = q.MaxConnectionReceiveWindow

		// mihomo uses Brutal when a rate is given and BBR otherwise, which is
		// what the congestion field selects here, so it needs no mapping.
		switch strings.ToLower(strings.TrimSpace(q.Congestion)) {
		case "", "bbr", "brutal":
		default:
			c.warn("quicParams.congestion %q has no mihomo equivalent; mihomo uses Brutal "+
				"when a rate is set and BBR otherwise", q.Congestion)
		}
	}

	// The Hysteria obfuscator is a finalmask UDP mask.
	if mask := ss.UDPMask("salamander"); mask != nil && p.obfs == "" {
		var settings xray.SalamanderMask
		if len(mask.Settings) > 0 {
			_ = json.Unmarshal(mask.Settings, &settings)
		}
		p.obfsPassword = xray.FirstNonEmpty(p.obfsPassword, string(settings.Password))
		if settings.PacketSize.Set && settings.PacketSize.To > 0 {
			// A packet size range selects the gecko variant of the obfuscator.
			p.obfs = "gecko"
			p.obfsMinSize = int(settings.PacketSize.From)
			p.obfsMaxSize = int(settings.PacketSize.To)
		} else {
			p.obfs = "salamander"
		}
	}
}

// hysteriaEndpoint is a resolved Hysteria server.
type hysteriaEndpoint struct {
	address  string
	port     int
	ports    string
	password string
	up       string
	down     string
}

// endpoints resolves the server list of a Hysteria settings object, falling
// back to the flat form.
func hysteriaEndpoints(s *xray.HysteriaSettings) []hysteriaEndpoint {
	flatPassword := xray.FirstNonEmpty(
		string(s.Password), string(s.Auth), string(s.AuthStr), string(s.AuthStrAlt))
	flatUp, flatDown := hysteriaBandwidth(s)

	var out []hysteriaEndpoint
	for _, sv := range s.Servers {
		if sv == nil {
			continue
		}
		up := xray.FirstNonEmpty(string(sv.Up), mbpsString(sv.UpMbps.Int()), flatUp)
		down := xray.FirstNonEmpty(string(sv.Down), mbpsString(sv.DownMbps.Int()), flatDown)
		out = append(out, hysteriaEndpoint{
			address: xray.FirstNonEmpty(string(sv.Address), string(sv.Server)),
			port:    sv.Port.Int(),
			ports:   strings.TrimSpace(string(sv.Ports)),
			password: xray.FirstNonEmpty(
				string(sv.Password), string(sv.Auth), string(sv.AuthStr), flatPassword),
			up:   up,
			down: down,
		})
	}
	if len(out) == 0 {
		address := xray.FirstNonEmpty(string(s.Address), string(s.Server))
		port := s.Port.Int()
		ports := strings.TrimSpace(string(s.Ports))
		// A "host:port" address is common in Hysteria2-style configs.
		if host, p, err := splitHostPort(address); err == nil && port == 0 {
			if parsed, err := atoiPort(p); err == nil {
				address, port = host, parsed
			}
		}
		out = append(out, hysteriaEndpoint{
			address:  address,
			port:     port,
			ports:    ports,
			password: flatPassword,
			up:       flatUp,
			down:     flatDown,
		})
	}
	return out
}

// hysteriaBandwidth resolves the up/down rates from any of the spellings the
// Hysteria clients accept.
func hysteriaBandwidth(s *xray.HysteriaSettings) (string, string) {
	up := strings.TrimSpace(string(s.Up))
	down := strings.TrimSpace(string(s.Down))
	if s.Bandwidth != nil {
		up = xray.FirstNonEmpty(up, string(s.Bandwidth.Up))
		down = xray.FirstNonEmpty(down, string(s.Bandwidth.Down))
	}
	up = xray.FirstNonEmpty(up, mbpsString(s.UpMbps.Int()))
	down = xray.FirstNonEmpty(down, mbpsString(s.DownMbps.Int()))
	return up, down
}

func mbpsString(v int) string {
	if v <= 0 {
		return ""
	}
	return strconv.Itoa(v) + " Mbps"
}

// normaliseBandwidth renders a rate the way mihomo expects. A bare number is
// megabits per second there, so a unit-less value passes through unchanged.
func normaliseBandwidth(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return v + " Mbps"
	}
	return v
}

func (c *converter) convertHysteria2(ob *xray.Outbound, preferred string) ([]*yamlx.Map, error) {
	var settings xray.HysteriaSettings
	if err := unmarshalSettings(ob, &settings); err != nil {
		return nil, err
	}

	obfsMode, obfsPassword := settings.ParsedObfs()
	sni, insecure, alpn := hysteriaTLS(&settings, ob.StreamSettings)

	var out []*yamlx.Map
	for _, ep := range hysteriaEndpoints(&settings) {
		// Anything the outbound's own settings did not supply comes from
		// streamSettings, which is where Xray itself keeps it.
		params := hysteriaParams{
			password:     ep.password,
			up:           ep.up,
			down:         ep.down,
			ports:        ep.ports,
			hopInterval:  hysteriaHopInterval(&settings),
			obfs:         obfsMode,
			obfsPassword: obfsPassword,
		}
		params.fromStream(c, ob.StreamSettings)

		port := ep.port
		if port == 0 && params.ports != "" {
			// Port hopping without a base port: use the low end of the range
			// so mihomo has something to dial before it starts hopping.
			if p, ok := firstPortOfRange(params.ports); ok {
				port = p
			}
		}
		name := c.name(preferred, ob.Tag, "hysteria2", ep.address, port)
		m, err := c.base(name, "hysteria2", ep.address, port)
		if err != nil {
			return nil, err
		}
		m.SetStr("ports", params.ports)
		if params.password == "" {
			return nil, fmt.Errorf("the hysteria2 outbound has no password " +
				"(Xray keeps it in streamSettings.hysteriaSettings.auth)")
		}
		m.Set("password", params.password)

		switch {
		case params.obfs != "":
			m.Set("obfs", params.obfs)
			m.SetStr("obfs-password", params.obfsPassword)
			m.SetInt("obfs-min-packet-size", params.obfsMinSize)
			m.SetInt("obfs-max-packet-size", params.obfsMaxSize)
		case params.obfsPassword != "":
			// A password without a type means Salamander, the only
			// obfuscator Hysteria2 shipped for a long time.
			m.Set("obfs", "salamander")
			m.Set("obfs-password", params.obfsPassword)
		}

		m.SetStr("up", normaliseBandwidth(params.up))
		m.SetStr("down", normaliseBandwidth(params.down))

		if params.hopInterval != "" {
			m.Set("hop-interval", params.hopInterval)
		}
		m.SetStr("sni", sni)
		if len(alpn) > 0 {
			m.Set("alpn", toFlowSeq(alpn))
		}
		if insecure || c.opts.SkipCertVerify {
			m.Set("skip-cert-verify", true)
		}
		if settings.TLS != nil {
			c.applyCertPin(m, strings.TrimSpace(string(settings.TLS.Pin)))
		}
		if t := ob.StreamSettings.TLS(); t != nil {
			c.applyCertPin(m, string(t.PinnedPeerCertSha256))
			c.applyCertificates(m, t)
			if fp := strings.TrimSpace(string(t.Fingerprint)); fp != "" {
				// Hysteria2 is QUIC, so there is no TLS ClientHello for a uTLS
				// profile to shape and mihomo offers no field for one.
				c.warn("the uTLS fingerprint %q does not apply to a QUIC protocol and was dropped", fp)
			}
		}
		m.SetStr("bbr-profile", params.bbrProfile)
		m.SetInt("cwnd", settings.CWND.Int())
		m.SetInt("udp-mtu", settings.UDPMTU.Int())
		if params.initStreamWindow > 0 {
			m.Set("initial-stream-receive-window", params.initStreamWindow)
		}
		if params.maxStreamWindow > 0 {
			m.Set("max-stream-receive-window", params.maxStreamWindow)
		}
		if params.initConnectionWindow > 0 {
			m.Set("initial-connection-receive-window", params.initConnectionWindow)
		}
		if params.maxConnectionWindow > 0 {
			m.Set("max-connection-receive-window", params.maxConnectionWindow)
		}
		c.udpFlag(m)
		c.applyDialer(m, ob)
		out = append(out, m)
	}
	return out, nil
}

// isHysteria2 reports whether a "hysteria" outbound is version 2.
//
// The version may be stated in the outbound settings, in hysteriaSettings, or
// implied by Xray's hysteria transport, whose outbound protocol only ever
// speaks version 2.
func isHysteria2(s *xray.HysteriaSettings, ss *xray.StreamSettings) bool {
	if s.Version.Int() == 2 {
		return true
	}
	if ss == nil {
		return false
	}
	if ss.HysteriaSettings != nil && ss.HysteriaSettings.Version.Int() == 2 {
		return true
	}
	return ss.NetworkName() == "hysteria"
}

// hysteriaHopInterval returns the port-hopping interval in seconds.
func hysteriaHopInterval(s *xray.HysteriaSettings) string {
	if v := strings.TrimSpace(string(s.HopInterval)); v != "" {
		// Hysteria2 writes durations as "30s"; mihomo takes plain seconds.
		return strings.TrimSuffix(v, "s")
	}
	if v := s.HopIntervalAlt.Int(); v > 0 {
		return strconv.Itoa(v)
	}
	return ""
}

// hysteriaTLS resolves the TLS parameters, which may live in the settings
// object or in streamSettings depending on which tool wrote the config.
func hysteriaTLS(s *xray.HysteriaSettings, ss *xray.StreamSettings) (sni string, insecure bool, alpn []string) {
	if s.TLS != nil {
		sni = xray.FirstNonEmpty(string(s.TLS.SNI), string(s.TLS.ServerName))
		insecure = s.TLS.Insecure.Bool()
		alpn = s.TLS.ALPN
	}
	sni = xray.FirstNonEmpty(sni, string(s.SNI))
	if s.Insecure.Bool() {
		insecure = true
	}
	if len(alpn) == 0 {
		alpn = s.ALPN
	}
	if t := ss.TLS(); t != nil {
		sni = xray.FirstNonEmpty(sni, string(t.ServerName))
		if t.AllowInsecure.Bool() {
			insecure = true
		}
		if len(alpn) == 0 {
			alpn = t.ALPN
		}
	}
	return sni, insecure, alpn
}

// firstPortOfRange returns the first port of a "443-8443,9000" style list.
func firstPortOfRange(ports string) (int, bool) {
	for _, part := range strings.Split(ports, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.IndexByte(part, '-'); i > 0 {
			part = part[:i]
		}
		if p, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && p > 0 && p <= 65535 {
			return p, true
		}
	}
	return 0, false
}

// convertHysteria handles a "hysteria" outbound, which may be either version.
func (c *converter) convertHysteria(ob *xray.Outbound, preferred string) ([]*yamlx.Map, error) {
	var settings xray.HysteriaSettings
	if err := unmarshalSettings(ob, &settings); err != nil {
		return nil, err
	}
	if isHysteria2(&settings, ob.StreamSettings) {
		return c.convertHysteria2(ob, preferred)
	}

	obfsMode, obfsPassword := settings.ParsedObfs()
	sni, insecure, alpn := hysteriaTLS(&settings, ob.StreamSettings)

	var out []*yamlx.Map
	for _, ep := range hysteriaEndpoints(&settings) {
		name := c.name(preferred, ob.Tag, "hysteria", ep.address, ep.port)
		m, err := c.base(name, "hysteria", ep.address, ep.port)
		if err != nil {
			return nil, err
		}
		// Hysteria v1 authenticates with a plain string.
		m.SetStr("auth-str", ep.password)
		// Version 1 requires both rates; mihomo refuses the node without them.
		up := normaliseBandwidth(ep.up)
		down := normaliseBandwidth(ep.down)
		if up == "" || down == "" {
			return nil, fmt.Errorf("hysteria v1 needs both up and down rates")
		}
		m.Set("up", up)
		m.Set("down", down)

		if obfsPassword != "" {
			m.Set("obfs", obfsPassword)
		} else if obfsMode != "" {
			m.Set("obfs", obfsMode)
		}
		m.SetStr("sni", sni)
		if len(alpn) > 0 {
			m.Set("alpn", toFlowSeq(alpn))
		}
		if insecure || c.opts.SkipCertVerify {
			m.Set("skip-cert-verify", true)
		}
		m.SetStr("ports", ep.ports)
		c.udpFlag(m)
		c.applyDialer(m, ob)
		out = append(out, m)
	}
	return out, nil
}

// convertTUIC handles standalone TUIC nodes.
func (c *converter) convertTUIC(ob *xray.Outbound, preferred string) ([]*yamlx.Map, error) {
	var settings xray.TUICSettings
	if err := unmarshalSettings(ob, &settings); err != nil {
		return nil, err
	}

	type endpoint struct {
		address               string
		port                  int
		uuid, password, token string
	}
	var endpoints []endpoint
	for _, sv := range settings.Servers {
		if sv == nil {
			continue
		}
		endpoints = append(endpoints, endpoint{
			address:  xray.FirstNonEmpty(string(sv.Address), string(sv.Server)),
			port:     sv.Port.Int(),
			uuid:     strings.TrimSpace(string(sv.UUID)),
			password: strings.TrimSpace(string(sv.Password)),
			token:    strings.TrimSpace(string(sv.Token)),
		})
	}
	if len(endpoints) == 0 {
		endpoints = append(endpoints, endpoint{
			address:  xray.FirstNonEmpty(string(settings.Address), string(settings.Server)),
			port:     settings.Port.Int(),
			uuid:     strings.TrimSpace(string(settings.UUID)),
			password: strings.TrimSpace(string(settings.Password)),
			token:    strings.TrimSpace(string(settings.Token)),
		})
	}

	var out []*yamlx.Map
	for _, ep := range endpoints {
		name := c.name(preferred, ob.Tag, "tuic", ep.address, ep.port)
		m, err := c.base(name, "tuic", ep.address, ep.port)
		if err != nil {
			return nil, err
		}
		switch {
		case ep.uuid != "":
			m.Set("uuid", ep.uuid)
			m.SetStr("password", ep.password)
		case ep.token != "":
			// TUIC v4 authenticates with a token instead of a uuid/password.
			m.Set("token", ep.token)
		default:
			return nil, fmt.Errorf("the tuic outbound has neither a uuid nor a token")
		}

		sni := strings.TrimSpace(string(settings.SNI))
		insecure := settings.Insecure.Bool()
		alpn := settings.ALPN
		if t := ob.StreamSettings.TLS(); t != nil {
			sni = xray.FirstNonEmpty(sni, string(t.ServerName))
			if t.AllowInsecure.Bool() {
				insecure = true
			}
			if len(alpn) == 0 {
				alpn = t.ALPN
			}
		}
		m.SetStr("sni", sni)
		if len(alpn) > 0 {
			m.Set("alpn", toFlowSeq(alpn))
		}
		if insecure || c.opts.SkipCertVerify {
			m.Set("skip-cert-verify", true)
		}
		m.SetStr("congestion-controller", xray.FirstNonEmpty(
			string(settings.CongestionControl), string(settings.CongestionControlAlt)))
		m.SetStr("udp-relay-mode", xray.FirstNonEmpty(
			string(settings.UDPRelayMode), string(settings.UDPRelayModeAlt)))
		if settings.ReduceRTT.Bool() || settings.ReduceRTTAlt.Bool() {
			m.Set("reduce-rtt", true)
		}
		m.SetInt("heartbeat-interval", settings.HeartbeatInterval.Int())
		if settings.DisableSNI.Bool() {
			m.Set("disable-sni", true)
		}
		c.udpFlag(m)
		c.applyDialer(m, ob)
		out = append(out, m)
	}
	return out, nil
}

// ---------------------------------------------------------------- shared ---

// splitHostPort splits "host:port", accepting a bracketed IPv6 literal.
func splitHostPort(s string) (string, string, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		end := strings.LastIndex(s, "]")
		if end < 0 {
			return "", "", fmt.Errorf("malformed IPv6 address %q", s)
		}
		host := s[1:end]
		rest := s[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("no port in %q", s)
		}
		return host, rest[1:], nil
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", fmt.Errorf("no port in %q", s)
	}
	host := s[:i]
	if strings.Contains(host, ":") {
		return "", "", fmt.Errorf("IPv6 address %q must be bracketed", s)
	}
	return host, s[i+1:], nil
}

func atoiPort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	if p <= 0 || p > 65535 {
		return 0, fmt.Errorf("port %d is out of range", p)
	}
	return p, nil
}

// decodeBase64RawURL decodes the unpadded URL-safe base64 that VLESS
// encryption keys use.
func decodeBase64RawURL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
}
