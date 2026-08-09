package xray

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Config is one Xray Core configuration. Only the parts the converter needs
// are modelled; everything else is ignored.
type Config struct {
	// Subscription generators label configurations in several different ways.
	Remarks   String      `json:"remarks"`
	Remark    String      `json:"remark"`
	Name      String      `json:"name"`
	PS        String      `json:"ps"`
	Tag       String      `json:"tag"`
	Outbounds []*Outbound `json:"outbounds"`

	// Some tools emit a single outbound at the top level instead of a list.
	Outbound *Outbound `json:"outbound"`

	// Routing carries the client-side load balancers.
	Routing *RoutingConfig `json:"routing"`
}

// RoutingConfig is Xray's routing section. Only the balancers are modelled;
// the routing rules themselves have no place in a proxy list.
type RoutingConfig struct {
	DomainStrategy String           `json:"domainStrategy"`
	Balancers      []*BalancingRule `json:"balancers"`
	Rules          []*RoutingRule   `json:"rules"`
}

// RoutingRule is one entry of routing.rules. Only the balancer reference is
// read, so that a balancer nothing routes to can be reported.
type RoutingRule struct {
	Type        String `json:"type"`
	BalancerTag String `json:"balancerTag"`
	OutboundTag String `json:"outboundTag"`
}

// BalancingRule is one client-side load balancer.
type BalancingRule struct {
	Tag         String         `json:"tag"`
	Selectors   StringList     `json:"selector"`
	Strategy    StrategyConfig `json:"strategy"`
	FallbackTag String         `json:"fallbackTag"`
}

// StrategyConfig selects how a balancer picks among its outbounds.
type StrategyConfig struct {
	Type     String          `json:"type"`
	Settings json.RawMessage `json:"settings"`
}

// StrategyName returns the strategy in Xray's normalised spelling. An unset
// strategy means "random", which is what Xray falls back to.
func (b *BalancingRule) StrategyName() string {
	switch s := strings.ToLower(strings.TrimSpace(string(b.Strategy.Type))); s {
	case "":
		return "random"
	default:
		return s
	}
}

// StrategyDisplay returns the strategy as the configuration spelled it, for
// messages a person reads.
func (b *BalancingRule) StrategyDisplay() string {
	if v := strings.TrimSpace(string(b.Strategy.Type)); v != "" {
		return v
	}
	return "random"
}

// Selects reports whether the balancer covers the outbound with this tag.
//
// Xray matches a selector against the start of the tag, so a selector of
// "proxy" claims "proxy-de-1" as well as "proxy".
func (b *BalancingRule) Selects(tag string) bool {
	for _, selector := range b.Selectors {
		if strings.HasPrefix(tag, selector) {
			return true
		}
	}
	return false
}

// Balancers returns the configuration's load balancers.
func (c *Config) Balancers() []*BalancingRule {
	if c.Routing == nil {
		return nil
	}
	out := make([]*BalancingRule, 0, len(c.Routing.Balancers))
	for _, b := range c.Routing.Balancers {
		// Xray refuses a balancer without a tag or without selectors.
		if b == nil || strings.TrimSpace(string(b.Tag)) == "" || len(b.Selectors) == 0 {
			continue
		}
		out = append(out, b)
	}
	return out
}

// Label returns the human-readable name of the configuration, if it carries
// one.
func (c *Config) Label() string {
	for _, s := range []String{c.Remarks, c.Remark, c.Name, c.PS, c.Tag} {
		if v := strings.TrimSpace(string(s)); v != "" {
			return v
		}
	}
	return ""
}

// Outbound is an Xray outbound.
type Outbound struct {
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings *StreamSettings `json:"streamSettings"`
	Mux            *MuxConfig      `json:"mux"`
	ProxySettings  *ProxySettings  `json:"proxySettings"`
	SendThrough    String          `json:"sendThrough"`
}

// MuxConfig is Xray's mux.cool setting. Mihomo has no mux.cool support, but
// the xudp fields still tell us which UDP packet encoding the node expects.
type MuxConfig struct {
	Enabled         Bool   `json:"enabled"`
	Concurrency     Int    `json:"concurrency"`
	XudpConcurrency Int    `json:"xudpConcurrency"`
	XudpProxyUDP443 String `json:"xudpProxyUDP443"`
}

// ProxySettings chains one outbound through another by tag.
type ProxySettings struct {
	Tag string `json:"tag"`
}

// StreamSettings is Xray's transport configuration.
type StreamSettings struct {
	Network  String `json:"network"`
	Type     String `json:"type"` // some generators use "type" for the network
	Security String `json:"security"`

	TLSSettings     *TLSConfig     `json:"tlsSettings"`
	XTLSSettings    *TLSConfig     `json:"xtlsSettings"`
	RealitySettings *RealityConfig `json:"realitySettings"`

	TCPSettings         *TCPConfig         `json:"tcpSettings"`
	RawSettings         *TCPConfig         `json:"rawSettings"`
	KCPSettings         *KCPConfig         `json:"kcpSettings"`
	WSSettings          *WSConfig          `json:"wsSettings"`
	WebSocketSettings   *WSConfig          `json:"websocketSettings"`
	HTTPSettings        *HTTPConfig        `json:"httpSettings"`
	QUICSettings        *QUICConfig        `json:"quicSettings"`
	GRPCSettings        *GRPCConfig        `json:"grpcSettings"`
	GunSettings         *GRPCConfig        `json:"gunSettings"`
	HTTPUpgradeSettings *HTTPUpgradeConfig `json:"httpupgradeSettings"`
	XHTTPSettings       *XHTTPConfig       `json:"xhttpSettings"`
	SplitHTTPSettings   *XHTTPConfig       `json:"splithttpSettings"`
	HysteriaSettings    *HysteriaTransport `json:"hysteriaSettings"`

	FinalMask *FinalMaskConfig `json:"finalmask"`
	Sockopt   *Sockopt         `json:"sockopt"`
}

// NetworkName returns the normalised transport name.
func (s *StreamSettings) NetworkName() string {
	if s == nil {
		return "tcp"
	}
	n := strings.ToLower(strings.TrimSpace(string(s.Network)))
	if n == "" {
		n = strings.ToLower(strings.TrimSpace(string(s.Type)))
	}
	switch n {
	case "", "tcp", "raw", "none":
		return "tcp"
	case "websocket":
		return "ws"
	case "splithttp":
		return "xhttp"
	case "mkcp":
		return "kcp"
	case "gun":
		return "grpc"
	case "http", "h2", "h3":
		// In Xray, "http" is the HTTP/2 transport. It is not the same thing
		// as mihomo's "http" network, which is the HTTP masquerade that Xray
		// spells as a raw-TCP header.
		return "h2"
	default:
		return n
	}
}

// SecurityName returns the normalised security layer name.
func (s *StreamSettings) SecurityName() string {
	if s == nil {
		return "none"
	}
	sec := strings.ToLower(strings.TrimSpace(string(s.Security)))
	switch sec {
	case "", "none", "auto":
		// A config may omit "security" but still carry tlsSettings; Xray
		// ignores that, and so do we, except for REALITY which is only ever
		// present deliberately.
		if s.RealitySettings != nil && sec == "" {
			return "reality"
		}
		return "none"
	case "xtls":
		return "tls"
	default:
		return sec
	}
}

// TLS returns the effective TLS settings for the stream.
func (s *StreamSettings) TLS() *TLSConfig {
	if s == nil {
		return nil
	}
	if s.TLSSettings != nil {
		return s.TLSSettings
	}
	return s.XTLSSettings
}

// TCP returns the raw/tcp transport settings under either spelling.
func (s *StreamSettings) TCP() *TCPConfig {
	if s == nil {
		return nil
	}
	if s.RawSettings != nil {
		return s.RawSettings
	}
	return s.TCPSettings
}

// WS returns the websocket settings under either spelling.
func (s *StreamSettings) WS() *WSConfig {
	if s == nil {
		return nil
	}
	if s.WSSettings != nil {
		return s.WSSettings
	}
	return s.WebSocketSettings
}

// GRPC returns the gRPC settings under either spelling.
func (s *StreamSettings) GRPC() *GRPCConfig {
	if s == nil {
		return nil
	}
	if s.GRPCSettings != nil {
		return s.GRPCSettings
	}
	return s.GunSettings
}

// XHTTP returns the XHTTP settings under either spelling, with "extra"
// already applied.
func (s *StreamSettings) XHTTP() *XHTTPConfig {
	if s == nil {
		return nil
	}
	cfg := s.XHTTPSettings
	if cfg == nil {
		cfg = s.SplitHTTPSettings
	}
	if cfg == nil {
		return nil
	}
	return cfg.Resolved()
}

// TLSConfig is Xray's tlsSettings.
type TLSConfig struct {
	ServerName           String           `json:"serverName"`
	AllowInsecure        Bool             `json:"allowInsecure"`
	ALPN                 StringList       `json:"alpn"`
	Fingerprint          String           `json:"fingerprint"`
	Certificates         []*TLSCertConfig `json:"certificates"`
	PinnedPeerCertSha256 String           `json:"pinnedPeerCertSha256"`
	VerifyPeerCertByName String           `json:"verifyPeerCertByName"`
	ECHConfigList        String           `json:"echConfigList"`
	MinVersion           String           `json:"minVersion"`
	MaxVersion           String           `json:"maxVersion"`
	DisableSystemRoot    Bool             `json:"disableSystemRoot"`
	CurvePreferences     StringList       `json:"curvePreferences"`
}

// TLSCertConfig is one entry of tlsSettings.certificates.
type TLSCertConfig struct {
	Usage           String     `json:"usage"`
	CertificateFile String     `json:"certificateFile"`
	Certificate     StringList `json:"certificate"`
	KeyFile         String     `json:"keyFile"`
	Key             StringList `json:"key"`
}

// PEM joins a certificate given as a list of lines into a PEM block.
func (c *TLSCertConfig) PEM() string {
	if len(c.Certificate) == 0 {
		return ""
	}
	return strings.Join(c.Certificate, "\n")
}

// KeyPEM joins a private key given as a list of lines into a PEM block.
func (c *TLSCertConfig) KeyPEM() string {
	if len(c.Key) == 0 {
		return ""
	}
	return strings.Join(c.Key, "\n")
}

// RealityConfig is Xray's realitySettings. Only the client-side fields matter
// here; the server-side ones are accepted and ignored.
type RealityConfig struct {
	ServerName    String     `json:"serverName"`
	ServerNames   StringList `json:"serverNames"`
	Fingerprint   String     `json:"fingerprint"`
	PublicKey     String     `json:"publicKey"`
	Password      String     `json:"password"`
	ShortID       String     `json:"shortId"`
	ShortIds      StringList `json:"shortIds"`
	SpiderX       String     `json:"spiderX"`
	Mldsa65Verify String     `json:"mldsa65Verify"`
}

// SNI returns the REALITY server name.
func (r *RealityConfig) SNI() string {
	if v := strings.TrimSpace(string(r.ServerName)); v != "" {
		return v
	}
	if len(r.ServerNames) > 0 {
		return r.ServerNames[0]
	}
	return ""
}

// ShortIDValue returns the REALITY short id.
func (r *RealityConfig) ShortIDValue() string {
	if v := strings.TrimSpace(string(r.ShortID)); v != "" {
		return v
	}
	if len(r.ShortIds) > 0 {
		return r.ShortIds[0]
	}
	return ""
}

// PublicKeyValue returns the REALITY public key. Newer Xray builds call the
// client-side field "password"; older ones call it "publicKey".
func (r *RealityConfig) PublicKeyValue() string {
	if v := strings.TrimSpace(string(r.PublicKey)); v != "" {
		return v
	}
	return strings.TrimSpace(string(r.Password))
}

// TCPConfig is Xray's rawSettings/tcpSettings.
type TCPConfig struct {
	Header              *TCPHeader `json:"header"`
	AcceptProxyProtocol Bool       `json:"acceptProxyProtocol"`
}

// TCPHeader describes the optional HTTP masquerade over a raw TCP stream.
type TCPHeader struct {
	Type     String            `json:"type"`
	Request  *TCPHeaderRequest `json:"request"`
	Response json.RawMessage   `json:"response"`
}

// TCPHeaderRequest is the client half of the HTTP masquerade.
type TCPHeaderRequest struct {
	Version String                `json:"version"`
	Method  String                `json:"method"`
	Path    StringList            `json:"path"`
	Headers map[string]StringList `json:"headers"`
}

// KCPConfig is Xray's kcpSettings.
type KCPConfig struct {
	MTU              Int        `json:"mtu"`
	TTI              Int        `json:"tti"`
	UplinkCapacity   Int        `json:"uplinkCapacity"`
	DownlinkCapacity Int        `json:"downlinkCapacity"`
	Congestion       Bool       `json:"congestion"`
	ReadBufferSize   Int        `json:"readBufferSize"`
	WriteBufferSize  Int        `json:"writeBufferSize"`
	Header           *KCPHeader `json:"header"`
	Seed             String     `json:"seed"`
}

// KCPHeader selects the mKCP packet camouflage.
type KCPHeader struct {
	Type String `json:"type"`
}

// WSConfig is Xray's wsSettings.
type WSConfig struct {
	Path                String            `json:"path"`
	Host                String            `json:"host"`
	Headers             map[string]String `json:"headers"`
	AcceptProxyProtocol Bool              `json:"acceptProxyProtocol"`
	HeartbeatPeriod     Int               `json:"heartbeatPeriod"`
	MaxEarlyData        Int               `json:"maxEarlyData"`
	EarlyDataHeaderName String            `json:"earlyDataHeaderName"`
	UseBrowserForwarder Bool              `json:"useBrowserForwarding"`
}

// HTTPConfig is Xray's httpSettings (the HTTP/2 transport).
type HTTPConfig struct {
	Host               StringList        `json:"host"`
	Path               String            `json:"path"`
	Method             String            `json:"method"`
	Headers            map[string]String `json:"headers"`
	ReadIdleTimeout    Int               `json:"read_idle_timeout"`
	HealthCheckTimeout Int               `json:"health_check_timeout"`
}

// QUICConfig is Xray's quicSettings. Mihomo has no QUIC transport for the
// V2Ray-family protocols, so this exists only so the converter can report it.
type QUICConfig struct {
	Security String     `json:"security"`
	Key      String     `json:"key"`
	Header   *KCPHeader `json:"header"`
}

// GRPCConfig is Xray's grpcSettings.
type GRPCConfig struct {
	ServiceName         String `json:"serviceName"`
	Authority           String `json:"authority"`
	MultiMode           Bool   `json:"multiMode"`
	UserAgent           String `json:"user_agent"`
	IdleTimeout         Int    `json:"idle_timeout"`
	HealthCheckTimeout  Int    `json:"health_check_timeout"`
	PermitWithoutStream Bool   `json:"permit_without_stream"`
	InitialWindowsSize  Int    `json:"initial_windows_size"`
}

// HTTPUpgradeConfig is Xray's httpupgradeSettings.
type HTTPUpgradeConfig struct {
	Path                String            `json:"path"`
	Host                String            `json:"host"`
	Headers             map[string]String `json:"headers"`
	AcceptProxyProtocol Bool              `json:"acceptProxyProtocol"`
}

// HysteriaTransport is Xray's hysteriaSettings.
//
// Paired with the "hysteria" outbound protocol it describes a plain Hysteria2
// server: the outbound settings carry only the address and port, and every
// other parameter -- the password above all -- lives here.
type HysteriaTransport struct {
	Version        Int           `json:"version"`
	Auth           String        `json:"auth"`
	Congestion     String        `json:"congestion"`
	Up             String        `json:"up"`
	Down           String        `json:"down"`
	UdpHop         *UdpHopConfig `json:"udphop"`
	UdpIdleTimeout Int           `json:"udpIdleTimeout"`
}

// UdpHopConfig is Xray's port-hopping block.
type UdpHopConfig struct {
	Ports    PortList   `json:"ports"`
	Interval Int32Range `json:"interval"`
}

// FinalMaskConfig is Xray's finalmask block. Newer builds moved the QUIC
// parameters of a Hysteria connection here, and its UDP masks are where the
// Hysteria obfuscator is configured.
type FinalMaskConfig struct {
	TCP        []*Mask           `json:"tcp"`
	UDP        []*Mask           `json:"udp"`
	QuicParams *QuicParamsConfig `json:"quicParams"`
}

// Mask is one entry of finalmask.tcp or finalmask.udp.
type Mask struct {
	Type     String          `json:"type"`
	Settings json.RawMessage `json:"settings"`
}

// QuicParamsConfig is finalmask.quicParams.
type QuicParamsConfig struct {
	Congestion string        `json:"congestion"`
	BbrProfile String        `json:"bbrProfile"`
	BrutalUp   String        `json:"brutalUp"`
	BrutalDown String        `json:"brutalDown"`
	UdpHop     *UdpHopConfig `json:"udpHop"`

	InitStreamReceiveWindow     uint64 `json:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow      uint64 `json:"maxStreamReceiveWindow"`
	InitConnectionReceiveWindow uint64 `json:"initConnectionReceiveWindow"`
	MaxConnectionReceiveWindow  uint64 `json:"maxConnectionReceiveWindow"`
}

// SalamanderMask is the settings object of a "salamander" UDP mask, which is
// the Hysteria obfuscator. A packet size range selects the gecko variant.
type SalamanderMask struct {
	Password   String     `json:"password"`
	PacketSize Int32Range `json:"packetSize"`
}

// UDPMask returns the first finalmask UDP mask of the given type.
func (s *StreamSettings) UDPMask(maskType string) *Mask {
	if s == nil || s.FinalMask == nil {
		return nil
	}
	for _, m := range s.FinalMask.UDP {
		if m != nil && strings.EqualFold(strings.TrimSpace(string(m.Type)), maskType) {
			return m
		}
	}
	return nil
}

// QuicParams returns the finalmask QUIC parameters, if any.
func (s *StreamSettings) QuicParams() *QuicParamsConfig {
	if s == nil || s.FinalMask == nil {
		return nil
	}
	return s.FinalMask.QuicParams
}

// Sockopt is Xray's socket-level configuration.
type Sockopt struct {
	Mark           Int             `json:"mark"`
	TCPFastOpen    Bool            `json:"tcpFastOpen"`
	TCPMptcp       Bool            `json:"tcpMptcp"`
	Tproxy         String          `json:"tproxy"`
	DomainStrategy String          `json:"domainStrategy"`
	DialerProxy    String          `json:"dialerProxy"`
	Interface      String          `json:"interface"`
	TCPKeepAlive   Int             `json:"tcpKeepAliveIdle"`
	V6Only         Bool            `json:"V6Only"`
	HappyEyeballs  json.RawMessage `json:"happyEyeballs"`
}

// XHTTPConfig is Xray's xhttpSettings/splithttpSettings.
type XHTTPConfig struct {
	Host    String            `json:"host"`
	Path    String            `json:"path"`
	Mode    String            `json:"mode"`
	Headers map[string]String `json:"headers"`

	XPaddingBytes     Int32Range `json:"xPaddingBytes"`
	XPaddingObfsMode  Bool       `json:"xPaddingObfsMode"`
	XPaddingKey       String     `json:"xPaddingKey"`
	XPaddingHeader    String     `json:"xPaddingHeader"`
	XPaddingPlacement String     `json:"xPaddingPlacement"`
	XPaddingMethod    String     `json:"xPaddingMethod"`

	UplinkHTTPMethod    String     `json:"uplinkHTTPMethod"`
	SessionIDPlacement  String     `json:"sessionIDPlacement"`
	SessionIDKey        String     `json:"sessionIDKey"`
	SessionIDTable      String     `json:"sessionIDTable"`
	SessionIDLength     Int32Range `json:"sessionIDLength"`
	SeqPlacement        String     `json:"seqPlacement"`
	SeqKey              String     `json:"seqKey"`
	UplinkDataPlacement String     `json:"uplinkDataPlacement"`
	UplinkDataKey       String     `json:"uplinkDataKey"`
	UplinkChunkSize     Int32Range `json:"uplinkChunkSize"`

	NoGRPCHeader bool `json:"-"`
	NoSSEHeader  bool `json:"-"`
	// Kept as pointers so that "extra" can distinguish "absent" from "false".
	NoGRPCHeaderRaw *Bool `json:"noGRPCHeader"`
	NoSSEHeaderRaw  *Bool `json:"noSSEHeader"`

	ScMaxEachPostBytes   Int32Range `json:"scMaxEachPostBytes"`
	ScMinPostsIntervalMs Int32Range `json:"scMinPostsIntervalMs"`
	ScMaxBufferedPosts   Int        `json:"scMaxBufferedPosts"`
	ScStreamUpServerSecs Int32Range `json:"scStreamUpServerSecs"`

	Xmux             *XmuxConfig     `json:"xmux"`
	DownloadSettings *StreamConfig   `json:"downloadSettings"`
	Extra            json.RawMessage `json:"extra"`
}

// Resolved applies the "extra" object the way Xray does: everything comes
// from "extra", except host, path and mode which stay with the outer object.
//
// This matters, because a naive merge would keep outer values that Xray
// discards, producing a config that behaves differently from the source.
func (c *XHTTPConfig) Resolved() *XHTTPConfig {
	if c == nil {
		return nil
	}
	out := *c
	if len(c.Extra) > 0 && !isJSONNull(c.Extra) {
		var extra XHTTPConfig
		if err := json.Unmarshal(c.Extra, &extra); err == nil {
			host, path, mode := c.Host, c.Path, c.Mode
			out = extra
			out.Host, out.Path, out.Mode = host, path, mode
		}
	}
	out.Extra = nil
	if out.NoGRPCHeaderRaw != nil {
		out.NoGRPCHeader = out.NoGRPCHeaderRaw.Bool()
	}
	if out.NoSSEHeaderRaw != nil {
		out.NoSSEHeader = out.NoSSEHeaderRaw.Bool()
	}
	return &out
}

// XmuxConfig is Xray's xmux block, which mihomo calls "reuse-settings".
type XmuxConfig struct {
	MaxConcurrency   Int32Range `json:"maxConcurrency"`
	MaxConnections   Int32Range `json:"maxConnections"`
	CMaxReuseTimes   Int32Range `json:"cMaxReuseTimes"`
	CMaxLifetimeMs   Int32Range `json:"cMaxLifetimeMs"`
	HMaxRequestTimes Int32Range `json:"hMaxRequestTimes"`
	HMaxReusableSecs Int32Range `json:"hMaxReusableSecs"`
	HKeepAlivePeriod Int        `json:"hKeepAlivePeriod"`
}

// IsZero reports whether no xmux field was set.
func (x *XmuxConfig) IsZero() bool {
	if x == nil {
		return true
	}
	return !x.MaxConcurrency.Set && !x.MaxConnections.Set && !x.CMaxReuseTimes.Set &&
		!x.CMaxLifetimeMs.Set && !x.HMaxRequestTimes.Set && !x.HMaxReusableSecs.Set &&
		x.HKeepAlivePeriod == 0
}

// StreamConfig is an XHTTP downloadSettings block: a full stream
// configuration plus the address of the download endpoint.
type StreamConfig struct {
	Address String `json:"address"`
	Port    Int    `json:"port"`
	StreamSettings
}

// UnmarshalJSON decodes both the address/port pair and the embedded stream
// settings from the same JSON object.
func (s *StreamConfig) UnmarshalJSON(data []byte) error {
	type addr struct {
		Address String `json:"address"`
		Port    Int    `json:"port"`
	}
	var a addr
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	var ss StreamSettings
	if err := json.Unmarshal(data, &ss); err != nil {
		return err
	}
	s.Address, s.Port, s.StreamSettings = a.Address, a.Port, ss
	return nil
}

func isJSONNull(raw json.RawMessage) bool {
	return strings.TrimSpace(string(raw)) == "null"
}

// ParseConfigs reads the converter's input: a JSON array of Xray
// configurations. A single configuration object, a bare array of outbounds and
// a single outbound are all accepted too, because that is what tools in the
// wild produce.
func ParseConfigs(data []byte) ([]*Config, error) {
	data = StripJSONC(unwrapBase64(data))
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("input is empty")
	}

	if strings.HasPrefix(trimmed, "[") {
		var items []json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &items); err != nil {
			return nil, fmt.Errorf("parsing the top-level JSON array: %w", err)
		}
		configs := make([]*Config, 0, len(items))
		for i, item := range items {
			cfg, err := parseConfigItem(item)
			if err != nil {
				return nil, fmt.Errorf("entry %d: %w", i, err)
			}
			if cfg != nil {
				configs = append(configs, cfg)
			}
		}
		return configs, nil
	}

	cfg, err := parseConfigItem(json.RawMessage(trimmed))
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return []*Config{cfg}, nil
}

// parseConfigItem accepts either a full configuration or a single outbound.
func parseConfigItem(raw json.RawMessage) (*Config, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	if !strings.HasPrefix(trimmed, "{") {
		return nil, fmt.Errorf("expected a JSON object, got %s", preview(trimmed))
	}

	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	if cfg.Outbound != nil {
		cfg.Outbounds = append(cfg.Outbounds, cfg.Outbound)
		cfg.Outbound = nil
	}
	if len(cfg.Outbounds) > 0 {
		return &cfg, nil
	}

	// No "outbounds" key: this may be a bare outbound object.
	if hasKey(raw, "protocol") {
		var ob Outbound
		if err := json.Unmarshal(raw, &ob); err != nil {
			return nil, err
		}
		return &Config{Outbounds: []*Outbound{&ob}}, nil
	}
	return &cfg, nil
}

func preview(s string) string {
	const max = 40
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
