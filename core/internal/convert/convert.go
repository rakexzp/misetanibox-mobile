// Package convert turns Xray Core outbounds into mihomo (Clash Meta) proxy
// entries.
package convert

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"misetanibox/mobilecore/internal/mihomo"
	"misetanibox/mobilecore/internal/xray"
	"misetanibox/mobilecore/internal/yamlx"
)

// Options controls how outbounds are converted.
type Options struct {
	// UDP sets "udp: true" on protocols that can relay UDP.
	UDP bool
	// SkipCertVerify forces certificate verification off on every node, on top
	// of whatever the source config asked for.
	SkipCertVerify bool
	// ClientFingerprint is the uTLS fingerprint applied to TLS nodes that do
	// not specify one. Empty leaves mihomo's default in place.
	ClientFingerprint string
	// NamePrefix is prepended to every generated proxy name.
	NamePrefix string
	// Strict makes an unconvertible outbound a hard error instead of a skip.
	Strict bool
	// BalancerGroupType is the mihomo group type an Xray balancer becomes:
	// url-test, load-balance, fallback or select. Empty means url-test.
	BalancerGroupType string
}

// DefaultOptions returns the options used when the caller does not care.
func DefaultOptions() Options {
	return Options{UDP: true}
}

// Diagnostic is a note about one outbound.
type Diagnostic struct {
	// Source identifies the outbound, e.g. "config[0].outbounds[1] (vless)".
	Source string
	// Message explains what happened.
	Message string
	// Fatal marks a node that was dropped rather than degraded.
	Fatal bool
}

func (d Diagnostic) String() string {
	kind := "warning"
	if d.Fatal {
		kind = "skipped"
	}
	return fmt.Sprintf("%s: %s: %s", kind, d.Source, d.Message)
}

// Result holds the converted proxies and everything worth reporting.
type Result struct {
	Proxies []*yamlx.Map
	// Groups are the proxy groups an Xray balancer produced.
	Groups      []mihomo.Group
	Diagnostics []Diagnostic
	Converted   int
	Skipped     int
	// balanced holds the proxy names a balancer claimed, which are offered
	// through their group instead of on their own.
	balanced map[string]bool
}

// Names returns every proxy name in output order.
func (r *Result) Names() []string {
	out := make([]string, 0, len(r.Proxies))
	for _, p := range r.Proxies {
		if v, ok := p.Get("name"); ok {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// Selectable returns the entries to offer the user: one name per balancer
// group, plus every proxy no balancer claimed.
//
// A node that belongs to a balancer is reachable through its group and does
// not appear here, which is what keeps the balanced servers out of the
// user-facing lists.
func (r *Result) Selectable() []string {
	out := make([]string, 0, len(r.Groups)+len(r.Proxies))
	inner := map[string]bool{}
	for _, g := range r.Groups {
		// A group that only exists to be wrapped by another one is not
		// offered on its own.
		for _, m := range g.Members {
			inner[m] = true
		}
	}
	for _, g := range r.Groups {
		if !inner[g.Name] {
			out = append(out, g.Name)
		}
	}
	for _, name := range r.Names() {
		if !r.balanced[name] {
			out = append(out, name)
		}
	}
	return out
}

// converter carries the state shared by one conversion run.
type converter struct {
	opts Options
	res  Result
	// used counts how often each proxy name has been handed out.
	used map[string]int
	// src identifies the outbound currently being converted, for diagnostics.
	src string
}

// Convert converts every outbound of every configuration into mihomo proxies,
// and every load balancer into a proxy group over them.
func Convert(configs []*xray.Config, opts Options) (*Result, error) {
	c := &converter{opts: opts, used: map[string]int{}}
	c.res.balanced = map[string]bool{}

	for ci, cfg := range configs {
		if cfg == nil {
			continue
		}
		label := cfg.Label()
		balancers := cfg.Balancers()
		// A configuration label only names a node unambiguously when the file
		// holds a single proxy outbound, which is the usual shape of a
		// generated per-node config. With a balancer the label describes the
		// group instead, so it is left for that.
		proxyOutbounds := countProxyOutbounds(cfg)

		// The tag of each outbound, mapped to the proxies it produced, so the
		// balancers below can find the nodes their selectors cover.
		tagNames := map[string][]string{}

		for oi, ob := range cfg.Outbounds {
			if ob == nil {
				continue
			}
			proto := strings.ToLower(strings.TrimSpace(ob.Protocol))
			if isNonProxyProtocol(proto) {
				continue
			}
			c.src = fmt.Sprintf("config[%d].outbounds[%d] (%s)", ci, oi, protoOrUnknown(proto))

			preferred := ""
			if proxyOutbounds == 1 && len(balancers) == 0 {
				preferred = label
			}
			proxies, err := c.convertOutbound(ob, proto, preferred)
			if err != nil {
				if opts.Strict {
					return nil, fmt.Errorf("%s: %w", c.src, err)
				}
				c.skip("%s", err.Error())
				continue
			}
			for _, p := range proxies {
				c.res.Proxies = append(c.res.Proxies, p)
				c.res.Converted++
				if tag := strings.TrimSpace(ob.Tag); tag != "" {
					if name, ok := p.Get("name"); ok {
						if s, ok := name.(string); ok {
							tagNames[tag] = append(tagNames[tag], s)
						}
					}
				}
			}
		}

		for name := range c.buildBalancers(cfg, ci, tagNames) {
			c.res.balanced[name] = true
		}
	}

	sort.SliceStable(c.res.Diagnostics, func(i, j int) bool {
		return c.res.Diagnostics[i].Fatal && !c.res.Diagnostics[j].Fatal
	})
	return &c.res, nil
}

func (c *converter) warn(format string, args ...any) {
	c.res.Diagnostics = append(c.res.Diagnostics, Diagnostic{
		Source:  c.src,
		Message: fmt.Sprintf(format, args...),
	})
}

func (c *converter) skip(format string, args ...any) {
	c.res.Diagnostics = append(c.res.Diagnostics, Diagnostic{
		Source:  c.src,
		Message: fmt.Sprintf(format, args...),
		Fatal:   true,
	})
	c.res.Skipped++
}

func countProxyOutbounds(cfg *xray.Config) int {
	n := 0
	for _, ob := range cfg.Outbounds {
		if ob != nil && !isNonProxyProtocol(strings.ToLower(strings.TrimSpace(ob.Protocol))) {
			n++
		}
	}
	return n
}

// isNonProxyProtocol reports whether the outbound is a local action rather
// than a remote server. These become mihomo's built-in DIRECT/REJECT targets
// and never appear in the proxies list.
func isNonProxyProtocol(proto string) bool {
	switch proto {
	case "freedom", "blackhole", "dns", "loopback", "":
		return true
	}
	return false
}

func protoOrUnknown(proto string) string {
	if proto == "" {
		return "no protocol"
	}
	return proto
}

// convertOutbound dispatches on the outbound protocol.
func (c *converter) convertOutbound(ob *xray.Outbound, proto, preferredName string) ([]*yamlx.Map, error) {
	switch proto {
	case "vless":
		return c.convertVLESS(ob, preferredName)
	case "vmess":
		return c.convertVMess(ob, preferredName)
	case "trojan":
		return c.convertTrojan(ob, preferredName)
	case "shadowsocks", "ss":
		return c.convertShadowsocks(ob, preferredName)
	case "socks", "socks5":
		return c.convertSocks(ob, preferredName)
	case "http", "https":
		return c.convertHTTP(ob, preferredName)
	case "wireguard":
		return c.convertWireGuard(ob, preferredName)
	case "hysteria2", "hy2":
		return c.convertHysteria2(ob, preferredName)
	case "hysteria", "hy":
		return c.convertHysteria(ob, preferredName)
	case "tuic":
		return c.convertTUIC(ob, preferredName)
	case "vlite":
		return nil, fmt.Errorf("the VLITE protocol has no mihomo equivalent")
	case "mtproto":
		return nil, fmt.Errorf("the MTProto protocol has no mihomo equivalent")
	default:
		return nil, fmt.Errorf("unsupported protocol %q", proto)
	}
}

// name builds a unique proxy name, preferring the configuration label, then
// the outbound tag, and falling back to protocol/host/port.
func (c *converter) name(preferred, tag, proto, host string, port int) string {
	candidate := strings.TrimSpace(preferred)
	if candidate == "" {
		candidate = meaningfulTag(tag)
	}
	if candidate == "" {
		// JoinHostPort brackets an IPv6 literal itself, so hand it the bare
		// address rather than one that is already bracketed.
		candidate = fmt.Sprintf("%s-%s", proto, net.JoinHostPort(stripBrackets(host), strconv.Itoa(port)))
	}
	if c.opts.NamePrefix != "" {
		candidate = c.opts.NamePrefix + candidate
	}
	candidate = sanitizeName(candidate)

	// Mihomo rejects a proxy list that repeats a name, so make them unique.
	// The first node keeps the plain name and the next ones get "#2", "#3"...
	if n, seen := c.used[candidate]; seen {
		for {
			n++
			next := fmt.Sprintf("%s #%d", candidate, n)
			if _, taken := c.used[next]; !taken {
				c.used[candidate] = n
				c.used[next] = 1
				return next
			}
		}
	}
	c.used[candidate] = 1
	return candidate
}

// genericTags are outbound tags that describe a role rather than a server, so
// they make poor proxy names.
var genericTags = map[string]bool{
	"proxy": true, "proxies": true, "out": true, "outbound": true,
	"default": true, "direct": true, "block": true, "blocked": true,
	"agentout": true, "main": true, "node": true,
}

func meaningfulTag(tag string) string {
	t := strings.TrimSpace(tag)
	if t == "" || genericTags[strings.ToLower(t)] {
		return ""
	}
	return t
}

// sanitizeName strips characters that break mihomo's proxy references or make
// a name unusable in a group.
func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		// Control characters and line breaks cannot appear in a name.
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if s == "" {
		return "proxy"
	}
	const maxNameLen = 120
	if len(s) > maxNameLen {
		// Trim on a rune boundary so the name stays valid UTF-8.
		trimmed := s[:maxNameLen]
		for len(trimmed) > 0 && !isUTF8Boundary(s, len(trimmed)) {
			trimmed = trimmed[:len(trimmed)-1]
		}
		s = strings.TrimSpace(trimmed)
	}
	return s
}

func isUTF8Boundary(s string, i int) bool {
	if i >= len(s) {
		return true
	}
	return s[i]&0xC0 != 0x80
}

// base builds the common head of a proxy entry.
func (c *converter) base(name, typ, server string, port int) (*yamlx.Map, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return nil, fmt.Errorf("the outbound has no server address")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid server port %d", port)
	}
	m := yamlx.NewMap()
	m.Set("name", name)
	m.Set("type", typ)
	m.Set("server", stripBrackets(server))
	m.Set("port", port)
	return m, nil
}

// stripBrackets removes the brackets from a literal IPv6 address, which
// mihomo expects to be bare in the "server" field.
func stripBrackets(host string) string {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}
	return host
}

// applyDialer maps Xray's sockopt onto mihomo's per-proxy dialer options.
func (c *converter) applyDialer(m *yamlx.Map, ob *xray.Outbound) {
	var so *xray.Sockopt
	if ob.StreamSettings != nil {
		so = ob.StreamSettings.Sockopt
	}
	if so != nil {
		m.SetBoolTrue("tfo", so.TCPFastOpen.Bool())
		m.SetBoolTrue("mptcp", so.TCPMptcp.Bool())
		m.SetStr("interface-name", strings.TrimSpace(string(so.Interface)))
		m.SetInt("routing-mark", so.Mark.Int())

		switch strings.ToLower(strings.TrimSpace(string(so.DomainStrategy))) {
		case "useip4", "useipv4", "forceip4", "forceipv4":
			m.Set("ip-version", "ipv4")
		case "useip6", "useipv6", "forceip6", "forceipv6":
			m.Set("ip-version", "ipv6")
		}
		if dp := strings.TrimSpace(string(so.DialerProxy)); dp != "" {
			// mihomo resolves dialer-proxy by proxy name; the Xray tag only
			// matches if a proxy with that name exists in the output.
			m.Set("dialer-proxy", dp)
			c.warn("sockopt.dialerProxy %q was mapped to dialer-proxy; it only works if a proxy with that exact name exists", dp)
		}
		if tp := strings.TrimSpace(string(so.Tproxy)); tp != "" && tp != "off" {
			c.warn("sockopt.tproxy is an inbound-side option and was dropped")
		}
	}

	// proxySettings chains this outbound through another one by tag, which is
	// the same idea as mihomo's dialer-proxy.
	if ob.ProxySettings != nil {
		if tag := strings.TrimSpace(ob.ProxySettings.Tag); tag != "" && !m.Has("dialer-proxy") {
			m.Set("dialer-proxy", tag)
			c.warn("proxySettings.tag %q was mapped to dialer-proxy; it only works if a proxy with that exact name exists", tag)
		}
	}
}

// applyMux maps Xray's mux.cool settings. Mihomo does not implement mux.cool,
// but the XUDP fields still describe how UDP is packed.
func (c *converter) applyMux(m *yamlx.Map, ob *xray.Outbound, proto string) {
	if ob.Mux == nil || !ob.Mux.Enabled.Bool() {
		return
	}
	switch proto {
	case "vless", "vmess":
		if ob.Mux.XudpConcurrency.Int() != 0 {
			m.Set("packet-encoding", "xudp")
		}
		c.warn("mux.cool is enabled but mihomo does not implement it; only the XUDP packet encoding was carried over")
	default:
		c.warn("mux.cool is enabled but mihomo does not implement it; it was dropped")
	}
}

// udpFlag sets "udp: true" when the option asks for it.
func (c *converter) udpFlag(m *yamlx.Map) {
	if c.opts.UDP {
		m.Set("udp", true)
	}
}
