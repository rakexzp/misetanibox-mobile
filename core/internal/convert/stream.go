package convert

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"misetanibox/mobilecore/internal/xray"
	"misetanibox/mobilecore/internal/yamlx"
)

// tlsTarget describes how a protocol spells its TLS fields, which differs
// between the V2Ray-family protocols and the rest.
type tlsTarget struct {
	// sniKey is "servername" for vless/vmess and "sni" for everything else.
	sniKey string
	// explicitTLS is true when the protocol needs "tls: true" to enable TLS.
	// Trojan, Hysteria2 and TUIC are always TLS and have no such field.
	explicitTLS bool
	// supportsReality is true when mihomo accepts reality-opts.
	supportsReality bool
	// supportsECH is true when mihomo accepts ech-opts.
	supportsECH bool
}

var (
	tlsV2Ray  = tlsTarget{sniKey: "servername", explicitTLS: true, supportsReality: true, supportsECH: true}
	tlsTrojan = tlsTarget{sniKey: "sni", supportsReality: true, supportsECH: true}
)

// applyTLS maps the stream's security layer onto the proxy entry.
func (c *converter) applyTLS(m *yamlx.Map, ss *xray.StreamSettings, target tlsTarget) {
	security := ss.SecurityName()
	tlsCfg := ss.TLS()

	switch security {
	case "none":
		if target.explicitTLS {
			// Nothing to do: mihomo defaults to plaintext.
			return
		}
		// Trojan and friends always speak TLS in mihomo; an Xray config that
		// disables it cannot be represented.
		if tlsCfg == nil {
			c.warn("the source has no TLS layer, but mihomo always uses TLS for this protocol")
		}
	case "tls":
		if target.explicitTLS {
			m.Set("tls", true)
		}
	case "reality":
		if target.explicitTLS {
			m.Set("tls", true)
		}
		if !target.supportsReality {
			c.warn("REALITY is not supported by mihomo for this protocol and was dropped")
		}
	default:
		c.warn("unknown security %q was treated as plaintext", security)
		return
	}

	if security == "reality" {
		c.applyReality(m, ss, target)
		return
	}
	if tlsCfg == nil {
		return
	}

	// The SNI is kept even when it repeats the server address: it is what the
	// source asked for, and it keeps the output easy to compare with it.
	m.SetStr(target.sniKey, strings.TrimSpace(string(tlsCfg.ServerName)))

	if len(tlsCfg.ALPN) > 0 {
		m.Set("alpn", toFlowSeq(tlsCfg.ALPN))
	}
	if tlsCfg.AllowInsecure.Bool() || c.opts.SkipCertVerify {
		m.Set("skip-cert-verify", true)
	}
	c.applyClientFingerprint(m, string(tlsCfg.Fingerprint))
	c.applyCertPin(m, string(tlsCfg.PinnedPeerCertSha256))
	m.SetStr("name-cert-verify", strings.TrimSpace(string(tlsCfg.VerifyPeerCertByName)))
	c.applyCertificates(m, tlsCfg)
	c.applyECH(m, tlsCfg, target)

	if v := strings.TrimSpace(string(tlsCfg.MinVersion)); v != "" {
		c.warn("tlsSettings.minVersion is not configurable per proxy in mihomo and was dropped")
	}
	if len(tlsCfg.CurvePreferences) > 0 {
		c.warn("tlsSettings.curvePreferences has no mihomo equivalent and was dropped")
	}
}

// applyReality maps realitySettings onto mihomo's reality-opts.
func (c *converter) applyReality(m *yamlx.Map, ss *xray.StreamSettings, target tlsTarget) {
	r := ss.RealitySettings
	if r == nil {
		c.warn("security is REALITY but realitySettings is missing")
		return
	}
	if !target.supportsReality {
		return
	}

	if sni := r.SNI(); sni != "" {
		m.Set(target.sniKey, sni)
	}
	c.applyClientFingerprint(m, string(r.Fingerprint))
	if c.opts.SkipCertVerify {
		m.Set("skip-cert-verify", true)
	}

	opts := yamlx.NewMap()
	pub := r.PublicKeyValue()
	if pub == "" {
		c.warn("realitySettings has no publicKey; mihomo will refuse the node")
	}
	opts.SetStr("public-key", pub)
	opts.SetStr("short-id", r.ShortIDValue())
	m.Set("reality-opts", opts)

	if strings.TrimSpace(string(r.Mldsa65Verify)) != "" {
		c.warn("realitySettings.mldsa65Verify (post-quantum certificate verification) is not supported by mihomo and was dropped")
	}
	// An X25519MLKEM768 REALITY handshake is opt-in on the mihomo side.
	if ss.TLS() != nil && len(ss.TLS().ALPN) > 0 {
		m.Set("alpn", toFlowSeq(ss.TLS().ALPN))
	}
}

// utlsFingerprints are the uTLS profiles mihomo knows by name.
var utlsFingerprints = map[string]string{
	"chrome": "chrome", "firefox": "firefox", "safari": "safari",
	"ios": "ios", "android": "android", "edge": "edge",
	"360": "360", "qq": "qq", "random": "random", "randomized": "randomized",
	"chrome120": "chrome120", "firefox120": "firefox120", "safari16": "safari16",
}

func (c *converter) applyClientFingerprint(m *yamlx.Map, fp string) {
	fp = strings.ToLower(strings.TrimSpace(fp))
	if fp == "" {
		if c.opts.ClientFingerprint != "" {
			m.Set("client-fingerprint", c.opts.ClientFingerprint)
		}
		return
	}
	if mapped, ok := utlsFingerprints[fp]; ok {
		m.Set("client-fingerprint", mapped)
		return
	}
	switch fp {
	case "randomizednoalpn", "randomizedalpn":
		m.Set("client-fingerprint", "randomized")
		c.warn("uTLS fingerprint %q has no exact mihomo equivalent; used \"randomized\"", fp)
	case "unsafe", "golang", "hellogolang":
		c.warn("uTLS fingerprint %q has no mihomo equivalent and was dropped", fp)
	default:
		c.warn("unknown uTLS fingerprint %q was dropped", fp)
	}
}

// applyCertPin converts Xray's base64 certificate pin to the hex form mihomo
// expects for its "fingerprint" field.
func (c *converter) applyCertPin(m *yamlx.Map, pin string) {
	pin = strings.TrimSpace(pin)
	if pin == "" {
		return
	}
	raw, err := decodeBase64Any(pin)
	if err != nil || len(raw) != 32 {
		// It may already be hex, in which case mihomo takes it as-is.
		clean := strings.ReplaceAll(pin, ":", "")
		if decoded, hexErr := hex.DecodeString(clean); hexErr == nil && len(decoded) == 32 {
			m.Set("fingerprint", strings.ToLower(clean))
			return
		}
		c.warn("could not decode tlsSettings.pinnedPeerCertSha256 as a SHA-256 value; it was dropped")
		return
	}
	m.Set("fingerprint", hex.EncodeToString(raw))
}

// applyCertificates carries a pinned CA certificate over to mihomo.
func (c *converter) applyCertificates(m *yamlx.Map, tlsCfg *xray.TLSConfig) {
	for _, cert := range tlsCfg.Certificates {
		if cert == nil {
			continue
		}
		usage := strings.ToLower(strings.TrimSpace(string(cert.Usage)))
		switch usage {
		case "verify", "":
			if pem := cert.PEM(); pem != "" {
				m.Set("certificate", pem)
			} else if file := strings.TrimSpace(string(cert.CertificateFile)); file != "" {
				c.warn("tlsSettings.certificates references the file %q; copy it next to the mihomo config and set \"certificate\" by hand", file)
			}
			if key := cert.KeyPEM(); key != "" {
				m.Set("private-key", key)
			}
		case "encipherment", "issue":
			c.warn("tlsSettings.certificates with usage %q is a server-side setting and was dropped", usage)
		}
	}
}

// applyECH maps Xray's ECH configuration list onto mihomo's ech-opts.
func (c *converter) applyECH(m *yamlx.Map, tlsCfg *xray.TLSConfig, target tlsTarget) {
	list := strings.TrimSpace(string(tlsCfg.ECHConfigList))
	if list == "" {
		return
	}
	if !target.supportsECH {
		c.warn("ECH is not supported by mihomo for this protocol and was dropped")
		return
	}
	opts := yamlx.NewMap()
	opts.Set("enable", true)
	if strings.HasPrefix(list, "http://") || strings.HasPrefix(list, "https://") {
		// Xray can fetch the list over DoH; mihomo instead queries the HTTPS
		// record itself when no literal config is given.
		c.warn("tlsSettings.echConfigList points at a URL; mihomo will look the ECH config up in DNS instead")
	} else if _, err := base64.StdEncoding.DecodeString(list); err == nil {
		opts.Set("config", list)
	} else if raw, err := decodeBase64Any(list); err == nil {
		opts.Set("config", base64.StdEncoding.EncodeToString(raw))
	} else {
		c.warn("could not decode tlsSettings.echConfigList; only ECH itself was enabled")
	}
	m.Set("ech-opts", opts)
}

// networkSupport lists the transports mihomo implements per protocol.
var networkSupport = map[string]map[string]bool{
	"vless":  {"tcp": true, "ws": true, "h2": true, "grpc": true, "xhttp": true, "httpupgrade": true},
	"vmess":  {"tcp": true, "ws": true, "h2": true, "grpc": true, "kcp": true, "httpupgrade": true},
	"trojan": {"tcp": true, "ws": true, "grpc": true, "httpupgrade": true},
}

// applyTransport maps streamSettings onto mihomo's network and *-opts fields.
func (c *converter) applyTransport(m *yamlx.Map, ss *xray.StreamSettings, proto string) error {
	network := ss.NetworkName()

	// Transports mihomo does not implement for any protocol get a specific
	// explanation, since the generic message would not tell the user why.
	switch network {
	case "quic":
		return fmt.Errorf("mihomo has no QUIC transport for the V2Ray-family protocols")
	case "hysteria":
		return fmt.Errorf("the Xray Hysteria transport carries %s inside a Hysteria tunnel, which mihomo cannot express; "+
			"use a standalone hysteria2 outbound instead", proto)
	}

	if supported, known := networkSupport[proto]; known && !supported[network] {
		return fmt.Errorf("mihomo does not support the %s transport for %s", network, proto)
	}

	switch network {
	case "tcp":
		return c.applyTCP(m, ss, proto)
	case "ws":
		return c.applyWebsocket(m, ss, false)
	case "httpupgrade":
		return c.applyWebsocket(m, ss, true)
	case "h2":
		return c.applyH2(m, ss)
	case "grpc":
		return c.applyGRPC(m, ss)
	case "xhttp":
		return c.applyXHTTP(m, ss)
	case "kcp":
		return c.applyKCP(m, ss)
	default:
		return fmt.Errorf("unsupported transport %q", network)
	}
}

// applyTCP handles the raw transport, including its HTTP masquerade, which
// mihomo exposes as network "http".
func (c *converter) applyTCP(m *yamlx.Map, ss *xray.StreamSettings, proto string) error {
	tcp := ss.TCP()
	if tcp == nil || tcp.Header == nil {
		return nil // plain TCP is mihomo's default
	}
	headerType := strings.ToLower(strings.TrimSpace(string(tcp.Header.Type)))
	switch headerType {
	case "", "none":
		return nil
	case "http":
		if proto == "trojan" {
			return fmt.Errorf("mihomo does not support the HTTP masquerade over raw TCP for trojan")
		}
		m.Set("network", "http")
		opts := yamlx.NewMap()
		if req := tcp.Header.Request; req != nil {
			opts.SetStr("method", strings.TrimSpace(string(req.Method)))
			if len(req.Path) > 0 {
				opts.Set("path", toFlowSeq(req.Path))
			}
			if len(req.Headers) > 0 {
				headers := yamlx.NewMap()
				for _, k := range sortedKeys(req.Headers) {
					headers.Set(k, toFlowSeq(req.Headers[k]))
				}
				opts.Set("headers", headers)
			}
		}
		m.Set("http-opts", opts)
		return nil
	default:
		return fmt.Errorf("unsupported raw header type %q", headerType)
	}
}

// applyWebsocket handles both the websocket transport and HTTPUpgrade, which
// mihomo models as websocket with a flag.
func (c *converter) applyWebsocket(m *yamlx.Map, ss *xray.StreamSettings, httpUpgrade bool) error {
	m.Set("network", "ws")
	opts := yamlx.NewMap()

	var (
		path    string
		host    string
		headers map[string]xray.String
		maxED   int
		edName  string
	)
	if httpUpgrade {
		hu := ss.HTTPUpgradeSettings
		if hu != nil {
			path, host, headers = string(hu.Path), string(hu.Host), hu.Headers
		}
	} else if ws := ss.WS(); ws != nil {
		path, host, headers = string(ws.Path), string(ws.Host), ws.Headers
		maxED = ws.MaxEarlyData.Int()
		edName = strings.TrimSpace(string(ws.EarlyDataHeaderName))
		if ws.UseBrowserForwarder.Bool() {
			c.warn("wsSettings.useBrowserForwarding has no mihomo equivalent and was dropped")
		}
	}

	// Xray encodes WebSocket early data as an "ed" query parameter on the
	// path; mihomo takes it as a separate option.
	cleanPath, ed := splitEarlyData(path)
	if ed > 0 {
		maxED = ed
		if edName == "" {
			edName = "Sec-WebSocket-Protocol"
		}
	}
	opts.SetStr("path", cleanPath)

	hdr := yamlx.NewMap()
	for _, k := range sortedKeys(headers) {
		v := strings.TrimSpace(string(headers[k]))
		if strings.EqualFold(k, "host") {
			// Xray moves a Host header into the dedicated host field.
			if host == "" {
				host = v
			}
			continue
		}
		hdr.SetStr(k, v)
	}
	if host = strings.TrimSpace(host); host != "" {
		// mihomo reads the SNI/Host override from the Host header.
		hdr.Set("Host", host)
	}
	opts.Set("headers", hdr)

	if maxED > 0 {
		opts.Set("max-early-data", maxED)
		if edName == "" {
			edName = "Sec-WebSocket-Protocol"
		}
		opts.Set("early-data-header-name", edName)
	}
	if httpUpgrade {
		opts.Set("v2ray-http-upgrade", true)
	}
	m.Set("ws-opts", opts)
	return nil
}

// applyH2 handles the HTTP/2 transport.
func (c *converter) applyH2(m *yamlx.Map, ss *xray.StreamSettings) error {
	m.Set("network", "h2")
	opts := yamlx.NewMap()
	if h := ss.HTTPSettings; h != nil {
		if len(h.Host) > 0 {
			opts.Set("host", toFlowSeq(h.Host))
		}
		opts.SetStr("path", strings.TrimSpace(string(h.Path)))
		if method := strings.TrimSpace(string(h.Method)); method != "" && !strings.EqualFold(method, "PUT") {
			c.warn("httpSettings.method %q is not configurable in mihomo's h2-opts and was dropped", method)
		}
		if len(h.Headers) > 0 {
			c.warn("httpSettings.headers has no mihomo equivalent for the h2 transport and was dropped")
		}
	}
	m.Set("h2-opts", opts)
	if ss.SecurityName() == "none" {
		c.warn("the h2 transport without TLS is unusual; mihomo requires TLS for h2")
	}
	return nil
}

// applyGRPC handles the gRPC transport.
func (c *converter) applyGRPC(m *yamlx.Map, ss *xray.StreamSettings) error {
	m.Set("network", "grpc")
	opts := yamlx.NewMap()
	if g := ss.GRPC(); g != nil {
		opts.SetStr("grpc-service-name", strings.TrimSpace(string(g.ServiceName)))
		opts.SetStr("grpc-user-agent", strings.TrimSpace(string(g.UserAgent)))
		if g.MultiMode.Bool() {
			c.warn("grpcSettings.multiMode has no mihomo equivalent; the node will use single mode")
		}
		if auth := strings.TrimSpace(string(g.Authority)); auth != "" {
			c.warn("grpcSettings.authority has no mihomo equivalent and was dropped")
		}
	}
	m.Set("grpc-opts", opts)
	return nil
}

// applyKCP handles the mKCP transport, which mihomo supports for vmess only.
func (c *converter) applyKCP(m *yamlx.Map, ss *xray.StreamSettings) error {
	m.Set("network", "kcp")
	opts := yamlx.NewMap()
	if k := ss.KCPSettings; k != nil {
		opts.SetInt("mtu", k.MTU.Int())
		opts.SetInt("tti", k.TTI.Int())
		opts.SetInt("uplink-capacity", k.UplinkCapacity.Int())
		opts.SetInt("downlink-capacity", k.DownlinkCapacity.Int())
		opts.SetBoolTrue("congestion", k.Congestion.Bool())
		opts.SetStr("seed", strings.TrimSpace(string(k.Seed)))
		if k.Header != nil {
			if t := strings.ToLower(strings.TrimSpace(string(k.Header.Type))); t != "" && t != "none" {
				opts.Set("header", t)
			}
		}
		if k.ReadBufferSize.Int() != 0 || k.WriteBufferSize.Int() != 0 {
			c.warn("kcpSettings read/write buffer sizes use different units in mihomo and were dropped")
		}
	}
	m.Set("mkcp-opts", opts)
	return nil
}

// applyXHTTP maps Xray's XHTTP transport, including the "extra" object, xmux
// and downloadSettings, onto mihomo's xhttp-opts.
func (c *converter) applyXHTTP(m *yamlx.Map, ss *xray.StreamSettings) error {
	m.Set("network", "xhttp")
	cfg := ss.XHTTP()
	if cfg == nil {
		m.Set("xhttp-opts", yamlx.NewMap().Set("mode", "auto"))
		return nil
	}
	opts, err := c.buildXHTTPOpts(cfg)
	if err != nil {
		return err
	}
	m.Set("xhttp-opts", opts)
	return nil
}

// xhttpModes are the transfer modes Xray accepts.
var xhttpModes = map[string]bool{
	"auto": true, "packet-up": true, "stream-up": true, "stream-one": true,
}

func (c *converter) buildXHTTPOpts(cfg *xray.XHTTPConfig) (*yamlx.Map, error) {
	opts := yamlx.NewMap()

	opts.SetStr("path", strings.TrimSpace(string(cfg.Path)))
	opts.SetStr("host", strings.TrimSpace(string(cfg.Host)))

	mode := strings.ToLower(strings.TrimSpace(string(cfg.Mode)))
	if mode == "" {
		mode = "auto"
	}
	if !xhttpModes[mode] {
		return nil, fmt.Errorf("unsupported xhttp mode %q", mode)
	}
	opts.Set("mode", mode)

	if len(cfg.Headers) > 0 {
		headers := yamlx.NewMap()
		for _, k := range sortedKeys(cfg.Headers) {
			if strings.EqualFold(k, "host") {
				// Xray rejects a Host header here; fold it into "host".
				if !opts.Has("host") {
					opts.Set("host", strings.TrimSpace(string(cfg.Headers[k])))
				}
				continue
			}
			headers.SetStr(k, strings.TrimSpace(string(cfg.Headers[k])))
		}
		opts.Set("headers", headers)
	}

	opts.SetBoolTrue("no-grpc-header", cfg.NoGRPCHeader)

	// Padding controls.
	opts.SetStr("x-padding-bytes", cfg.XPaddingBytes.String())
	opts.SetBoolTrue("x-padding-obfs-mode", cfg.XPaddingObfsMode.Bool())
	opts.SetStr("x-padding-key", strings.TrimSpace(string(cfg.XPaddingKey)))
	opts.SetStr("x-padding-header", strings.TrimSpace(string(cfg.XPaddingHeader)))
	if v := strings.TrimSpace(string(cfg.XPaddingPlacement)); v != "" {
		if !isOneOf(v, "cookie", "header", "query", "queryInHeader") {
			return nil, fmt.Errorf("unsupported xPaddingPlacement %q", v)
		}
		opts.Set("x-padding-placement", v)
	}
	if v := strings.TrimSpace(string(cfg.XPaddingMethod)); v != "" {
		if !isOneOf(v, "repeat-x", "tokenish") {
			return nil, fmt.Errorf("unsupported xPaddingMethod %q", v)
		}
		opts.Set("x-padding-method", v)
	}

	// Uplink and session controls.
	if v := strings.TrimSpace(string(cfg.UplinkHTTPMethod)); v != "" {
		upper := strings.ToUpper(v)
		if upper == "GET" && mode != "packet-up" {
			return nil, fmt.Errorf("uplinkHTTPMethod GET is only valid in packet-up mode")
		}
		opts.Set("uplink-http-method", upper)
	}
	if v := strings.TrimSpace(string(cfg.SessionIDPlacement)); v != "" {
		if !isOneOf(v, "path", "cookie", "header", "query") {
			return nil, fmt.Errorf("unsupported sessionIDPlacement %q", v)
		}
		opts.Set("session-placement", v)
	}
	opts.SetStr("session-key", strings.TrimSpace(string(cfg.SessionIDKey)))
	opts.SetStr("session-table", strings.TrimSpace(string(cfg.SessionIDTable)))
	opts.SetStr("session-length", cfg.SessionIDLength.String())

	if v := strings.TrimSpace(string(cfg.SeqPlacement)); v != "" {
		if !isOneOf(v, "path", "cookie", "header", "query") {
			return nil, fmt.Errorf("unsupported seqPlacement %q", v)
		}
		opts.Set("seq-placement", v)
	}
	opts.SetStr("seq-key", strings.TrimSpace(string(cfg.SeqKey)))

	if v := strings.TrimSpace(string(cfg.UplinkDataPlacement)); v != "" {
		if !isOneOf(v, "auto", "body", "cookie", "header") {
			return nil, fmt.Errorf("unsupported uplinkDataPlacement %q", v)
		}
		if (v == "cookie" || v == "header") && mode != "packet-up" {
			return nil, fmt.Errorf("uplinkDataPlacement %q is only valid in packet-up mode", v)
		}
		opts.Set("uplink-data-placement", v)
	}
	opts.SetStr("uplink-data-key", strings.TrimSpace(string(cfg.UplinkDataKey)))
	opts.SetStr("uplink-chunk-size", cfg.UplinkChunkSize.String())

	opts.SetStr("sc-max-each-post-bytes", cfg.ScMaxEachPostBytes.String())
	opts.SetStr("sc-min-posts-interval-ms", cfg.ScMinPostsIntervalMs.String())

	// Settings that only exist on the Xray side.
	if cfg.NoSSEHeader {
		c.warn("xhttp noSSEHeader has no mihomo equivalent and was dropped")
	}
	if cfg.ScMaxBufferedPosts.Int() != 0 {
		c.warn("xhttp scMaxBufferedPosts is a server-side option and was dropped")
	}
	if cfg.ScStreamUpServerSecs.Set {
		c.warn("xhttp scStreamUpServerSecs is a server-side option and was dropped")
	}

	// XMUX, which mihomo calls reuse-settings.
	if !cfg.Xmux.IsZero() {
		reuse := yamlx.NewMap()
		reuse.SetStr("max-concurrency", nonZeroRange(cfg.Xmux.MaxConcurrency))
		reuse.SetStr("max-connections", nonZeroRange(cfg.Xmux.MaxConnections))
		reuse.SetStr("c-max-reuse-times", nonZeroRange(cfg.Xmux.CMaxReuseTimes))
		reuse.SetStr("h-max-request-times", nonZeroRange(cfg.Xmux.HMaxRequestTimes))
		reuse.SetStr("h-max-reusable-secs", nonZeroRange(cfg.Xmux.HMaxReusableSecs))
		reuse.SetInt("h-keep-alive-period", cfg.Xmux.HKeepAlivePeriod.Int())
		if cfg.Xmux.CMaxLifetimeMs.Set {
			c.warn("xmux cMaxLifetimeMs has no mihomo equivalent and was dropped")
		}
		if reuse.Len() > 0 {
			opts.Set("reuse-settings", reuse)
		}
	}

	// downloadSettings splits the download half onto a separate endpoint.
	if cfg.DownloadSettings != nil {
		dl, err := c.buildXHTTPDownload(cfg.DownloadSettings)
		if err != nil {
			return nil, fmt.Errorf("downloadSettings: %w", err)
		}
		if dl.Len() > 0 {
			opts.Set("download-settings", dl)
		}
	}
	return opts, nil
}

// buildXHTTPDownload maps an XHTTP downloadSettings block, which is a full
// stream configuration plus its own address.
func (c *converter) buildXHTTPDownload(dl *xray.StreamConfig) (*yamlx.Map, error) {
	out := yamlx.NewMap()

	if addr := strings.TrimSpace(string(dl.Address)); addr != "" {
		out.Set("server", stripBrackets(addr))
	}
	if port := dl.Port.Int(); port > 0 {
		out.Set("port", port)
	}

	if net := dl.StreamSettings.NetworkName(); net != "xhttp" && net != "tcp" {
		c.warn("downloadSettings uses the %s transport, which mihomo only supports as xhttp here", net)
	}
	if cfg := dl.StreamSettings.XHTTP(); cfg != nil {
		opts, err := c.buildXHTTPOpts(cfg)
		if err != nil {
			return nil, err
		}
		// The download half reuses the upload settings for anything it does
		// not override; mihomo only accepts this subset.
		if v, ok := opts.Get("path"); ok {
			out.Set("path", v)
		}
		if v, ok := opts.Get("host"); ok {
			out.Set("host", v)
		}
		if v, ok := opts.Get("headers"); ok {
			out.Set("headers", v)
		}
		if v, ok := opts.Get("reuse-settings"); ok {
			out.Set("reuse-settings", v)
		}
	}

	// The download endpoint carries its own security layer.
	switch dl.StreamSettings.SecurityName() {
	case "tls":
		out.Set("tls", true)
		if t := dl.StreamSettings.TLS(); t != nil {
			out.SetStr("servername", strings.TrimSpace(string(t.ServerName)))
			if len(t.ALPN) > 0 {
				out.Set("alpn", toFlowSeq(t.ALPN))
			}
			if t.AllowInsecure.Bool() || c.opts.SkipCertVerify {
				out.Set("skip-cert-verify", true)
			}
			if fp := strings.ToLower(strings.TrimSpace(string(t.Fingerprint))); fp != "" {
				if mapped, ok := utlsFingerprints[fp]; ok {
					out.Set("client-fingerprint", mapped)
				}
			}
		}
	case "reality":
		out.Set("tls", true)
		if r := dl.StreamSettings.RealitySettings; r != nil {
			out.SetStr("servername", r.SNI())
			reality := yamlx.NewMap()
			reality.SetStr("public-key", r.PublicKeyValue())
			reality.SetStr("short-id", r.ShortIDValue())
			out.Set("reality-opts", reality)
			if fp := strings.ToLower(strings.TrimSpace(string(r.Fingerprint))); fp != "" {
				if mapped, ok := utlsFingerprints[fp]; ok {
					out.Set("client-fingerprint", mapped)
				}
			}
		}
	}
	return out, nil
}

// splitEarlyData pulls Xray's "ed" query parameter out of a transport path.
func splitEarlyData(path string) (string, int) {
	if path == "" || !strings.Contains(path, "ed=") {
		return path, 0
	}
	u, err := url.Parse(path)
	if err != nil {
		return path, 0
	}
	q := u.Query()
	edStr := q.Get("ed")
	if edStr == "" {
		return path, 0
	}
	ed, err := strconv.Atoi(edStr)
	if err != nil || ed <= 0 {
		return path, 0
	}
	q.Del("ed")
	u.RawQuery = q.Encode()
	return u.String(), ed
}

// nonZeroRange renders a range, treating an all-zero one as unset. Xray reads
// zero in the xmux fields as "use the default", so passing "0" through would
// tell mihomo something the source never asked for.
func nonZeroRange(r xray.Int32Range) string {
	if !r.Set || (r.From == 0 && r.To == 0) {
		return ""
	}
	return r.String()
}

func isOneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

// decodeBase64Any decodes standard or URL-safe base64, padded or not.
func decodeBase64Any(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	encodings := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, nil
		} else {
			lastErr = err
		}
	}
	return nil, lastErr
}

func toFlowSeq[T ~string](items []T) yamlx.FlowSeq {
	out := make(yamlx.FlowSeq, 0, len(items))
	for _, s := range items {
		if v := strings.TrimSpace(string(s)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Deterministic output matters: the same input must always produce the
	// same file.
	sort.Strings(keys)
	return keys
}
