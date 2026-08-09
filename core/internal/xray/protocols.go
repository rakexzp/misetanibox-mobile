package xray

import (
	"encoding/json"
	"strings"
)

// The outbound "settings" object differs per protocol, and most protocols
// accept both a nested server list (vnext/servers) and a flat single-server
// form. The types below model both so the converter can treat them uniformly.

// VLESSSettings is the settings object of a vless outbound.
type VLESSSettings struct {
	// Nested form.
	Vnext []*VLESSVnext `json:"vnext"`

	// Flat form, used by current Xray builds.
	Address    String `json:"address"`
	Port       Int    `json:"port"`
	ID         String `json:"id"`
	Flow       String `json:"flow"`
	Encryption String `json:"encryption"`
	Seed       String `json:"seed"`
	Level      Int    `json:"level"`
}

// VLESSVnext is one entry of vless settings.vnext.
type VLESSVnext struct {
	Address String       `json:"address"`
	Port    Int          `json:"port"`
	Users   []*VLESSUser `json:"users"`
}

// VLESSUser is one entry of a vnext users list.
type VLESSUser struct {
	ID         String `json:"id"`
	Flow       String `json:"flow"`
	Encryption String `json:"encryption"`
	Level      Int    `json:"level"`
	Email      String `json:"email"`
}

// Endpoints flattens the settings into one entry per server/user pair.
func (s *VLESSSettings) Endpoints() []VLESSEndpoint {
	var out []VLESSEndpoint
	for _, v := range s.Vnext {
		if v == nil {
			continue
		}
		if len(v.Users) == 0 {
			out = append(out, VLESSEndpoint{Address: string(v.Address), Port: v.Port.Int()})
			continue
		}
		for _, u := range v.Users {
			if u == nil {
				continue
			}
			out = append(out, VLESSEndpoint{
				Address:    string(v.Address),
				Port:       v.Port.Int(),
				ID:         strings.TrimSpace(string(u.ID)),
				Flow:       strings.TrimSpace(string(u.Flow)),
				Encryption: strings.TrimSpace(string(u.Encryption)),
				Email:      string(u.Email),
			})
		}
	}
	if len(out) == 0 && (s.Address != "" || s.ID != "") {
		out = append(out, VLESSEndpoint{
			Address:    string(s.Address),
			Port:       s.Port.Int(),
			ID:         strings.TrimSpace(string(s.ID)),
			Flow:       strings.TrimSpace(string(s.Flow)),
			Encryption: strings.TrimSpace(string(s.Encryption)),
		})
	}
	// The flat "encryption"/"flow" keys act as defaults for users that do not
	// carry their own.
	for i := range out {
		if out[i].Encryption == "" {
			out[i].Encryption = strings.TrimSpace(string(s.Encryption))
		}
		if out[i].Flow == "" {
			out[i].Flow = strings.TrimSpace(string(s.Flow))
		}
	}
	return out
}

// VLESSEndpoint is a single vless server/user pair.
type VLESSEndpoint struct {
	Address    string
	Port       int
	ID         string
	Flow       string
	Encryption string
	Email      string
}

// VMessSettings is the settings object of a vmess outbound.
type VMessSettings struct {
	Vnext []*VMessVnext `json:"vnext"`

	Address  String `json:"address"`
	Port     Int    `json:"port"`
	ID       String `json:"id"`
	Security String `json:"security"`
	AlterID  Int    `json:"alterId"`
}

// VMessVnext is one entry of vmess settings.vnext.
type VMessVnext struct {
	Address String       `json:"address"`
	Port    Int          `json:"port"`
	Users   []*VMessUser `json:"users"`
}

// VMessUser is one entry of a vmess vnext users list.
type VMessUser struct {
	ID          String `json:"id"`
	AlterID     Int    `json:"alterId"`
	AlterIDAlt  Int    `json:"alterid"`
	Security    String `json:"security"`
	Level       Int    `json:"level"`
	Email       String `json:"email"`
	Experiments String `json:"experiments"`
}

// VMessEndpoint is a single vmess server/user pair.
type VMessEndpoint struct {
	Address     string
	Port        int
	ID          string
	AlterID     int
	Security    string
	Email       string
	Experiments string
}

// Endpoints flattens the settings into one entry per server/user pair.
func (s *VMessSettings) Endpoints() []VMessEndpoint {
	var out []VMessEndpoint
	for _, v := range s.Vnext {
		if v == nil {
			continue
		}
		for _, u := range v.Users {
			if u == nil {
				continue
			}
			alter := u.AlterID.Int()
			if alter == 0 {
				alter = u.AlterIDAlt.Int()
			}
			out = append(out, VMessEndpoint{
				Address:     string(v.Address),
				Port:        v.Port.Int(),
				ID:          strings.TrimSpace(string(u.ID)),
				AlterID:     alter,
				Security:    strings.ToLower(strings.TrimSpace(string(u.Security))),
				Email:       string(u.Email),
				Experiments: string(u.Experiments),
			})
		}
	}
	if len(out) == 0 && (s.Address != "" || s.ID != "") {
		out = append(out, VMessEndpoint{
			Address:  string(s.Address),
			Port:     s.Port.Int(),
			ID:       strings.TrimSpace(string(s.ID)),
			AlterID:  s.AlterID.Int(),
			Security: strings.ToLower(strings.TrimSpace(string(s.Security))),
		})
	}
	return out
}

// TrojanSettings is the settings object of a trojan outbound.
type TrojanSettings struct {
	Servers []*TrojanServer `json:"servers"`

	Address  String `json:"address"`
	Port     Int    `json:"port"`
	Password String `json:"password"`
	Flow     String `json:"flow"`
}

// TrojanServer is one entry of trojan settings.servers.
type TrojanServer struct {
	Address  String `json:"address"`
	Port     Int    `json:"port"`
	Password String `json:"password"`
	Flow     String `json:"flow"`
	Email    String `json:"email"`
}

// Endpoints returns the configured trojan servers.
func (s *TrojanSettings) Endpoints() []TrojanServer {
	var out []TrojanServer
	for _, sv := range s.Servers {
		if sv != nil {
			out = append(out, *sv)
		}
	}
	if len(out) == 0 && (s.Address != "" || s.Password != "") {
		out = append(out, TrojanServer{
			Address:  s.Address,
			Port:     s.Port,
			Password: s.Password,
			Flow:     s.Flow,
		})
	}
	return out
}

// ShadowsocksSettings is the settings object of a shadowsocks outbound.
type ShadowsocksSettings struct {
	Servers []*ShadowsocksServer `json:"servers"`

	Address  String `json:"address"`
	Port     Int    `json:"port"`
	Method   String `json:"method"`
	Password String `json:"password"`
	UoT      Bool   `json:"uot"`
	UoTVer   Int    `json:"UoTVersion"`
}

// ShadowsocksServer is one entry of shadowsocks settings.servers.
type ShadowsocksServer struct {
	Address  String `json:"address"`
	Port     Int    `json:"port"`
	Method   String `json:"method"`
	Password String `json:"password"`
	Email    String `json:"email"`
	UoT      Bool   `json:"uot"`
	UoTVer   Int    `json:"UoTVersion"`
	Level    Int    `json:"level"`
}

// Endpoints returns the configured shadowsocks servers.
func (s *ShadowsocksSettings) Endpoints() []ShadowsocksServer {
	var out []ShadowsocksServer
	for _, sv := range s.Servers {
		if sv != nil {
			out = append(out, *sv)
		}
	}
	if len(out) == 0 && (s.Address != "" || s.Password != "") {
		out = append(out, ShadowsocksServer{
			Address:  s.Address,
			Port:     s.Port,
			Method:   s.Method,
			Password: s.Password,
			UoT:      s.UoT,
			UoTVer:   s.UoTVer,
		})
	}
	return out
}

// ProxyAccount is a username/password pair, spelled the way socks and http
// outbounds spell it.
type ProxyAccount struct {
	User String `json:"user"`
	Pass String `json:"pass"`
	// Alternative spellings seen in generated configs.
	Username String `json:"username"`
	Password String `json:"password"`
}

// Credentials returns the account's username and password.
func (a *ProxyAccount) Credentials() (string, string) {
	if a == nil {
		return "", ""
	}
	user := strings.TrimSpace(string(a.User))
	if user == "" {
		user = strings.TrimSpace(string(a.Username))
	}
	pass := strings.TrimSpace(string(a.Pass))
	if pass == "" {
		pass = strings.TrimSpace(string(a.Password))
	}
	return user, pass
}

// ProxyServerSettings is the settings object of a socks or http outbound.
type ProxyServerSettings struct {
	Servers []*ProxyServer `json:"servers"`

	Address String `json:"address"`
	Port    Int    `json:"port"`
	User    String `json:"user"`
	Pass    String `json:"pass"`
}

// ProxyServer is one entry of socks/http settings.servers.
type ProxyServer struct {
	Address String            `json:"address"`
	Port    Int               `json:"port"`
	Users   []*ProxyAccount   `json:"users"`
	Headers map[string]String `json:"headers"`
}

// ProxyEndpoint is a resolved socks/http server with its credentials.
type ProxyEndpoint struct {
	Address string
	Port    int
	User    string
	Pass    string
	Headers map[string]String
}

// Endpoints returns the configured socks/http servers.
func (s *ProxyServerSettings) Endpoints() []ProxyEndpoint {
	var out []ProxyEndpoint
	for _, sv := range s.Servers {
		if sv == nil {
			continue
		}
		ep := ProxyEndpoint{
			Address: string(sv.Address),
			Port:    sv.Port.Int(),
			Headers: sv.Headers,
		}
		if len(sv.Users) > 0 {
			ep.User, ep.Pass = sv.Users[0].Credentials()
		}
		out = append(out, ep)
	}
	if len(out) == 0 && s.Address != "" {
		out = append(out, ProxyEndpoint{
			Address: string(s.Address),
			Port:    s.Port.Int(),
			User:    strings.TrimSpace(string(s.User)),
			Pass:    strings.TrimSpace(string(s.Pass)),
		})
	}
	return out
}

// WireGuardSettings is the settings object of a wireguard outbound.
type WireGuardSettings struct {
	SecretKey      String           `json:"secretKey"`
	Address        StringList       `json:"address"`
	Peers          []*WireGuardPeer `json:"peers"`
	MTU            Int              `json:"mtu"`
	Reserved       json.RawMessage  `json:"reserved"`
	Workers        Int              `json:"workers"`
	DomainStrategy String           `json:"domainStrategy"`
	NoKernelTun    Bool             `json:"noKernelTun"`
	KernelMode     Bool             `json:"kernelMode"`
}

// WireGuardPeer is one entry of wireguard settings.peers.
type WireGuardPeer struct {
	PublicKey    String     `json:"publicKey"`
	PreSharedKey String     `json:"preSharedKey"`
	Endpoint     String     `json:"endpoint"`
	KeepAlive    Int        `json:"keepAlive"`
	AllowedIPs   StringList `json:"allowedIPs"`
}

// HysteriaSettings covers standalone Hysteria/Hysteria2 outbounds.
//
// Xray Core has no Hysteria2 outbound protocol of its own, but configuration
// sets that mix protocols routinely carry hysteria2 nodes in the same array,
// spelled the way the Hysteria2 client or a sing-box style generator spells
// them. All of those spellings are accepted here.
type HysteriaSettings struct {
	Servers []*HysteriaServer `json:"servers"`

	// Flat form.
	Address String `json:"address"`
	Server  String `json:"server"`
	Port    Int    `json:"port"`
	Ports   String `json:"ports"`
	// The Hysteria2 client calls the credential "auth"; mihomo and most
	// generators call it "password".
	Password   String `json:"password"`
	Auth       String `json:"auth"`
	AuthStr    String `json:"auth_str"`
	AuthStrAlt String `json:"authStr"`

	Obfs         json.RawMessage `json:"obfs"`
	ObfsPassword String          `json:"obfsPassword"`
	ObfsParam    String          `json:"obfs-password"`

	Up        String `json:"up"`
	Down      String `json:"down"`
	UpMbps    Int    `json:"upMbps"`
	DownMbps  Int    `json:"downMbps"`
	Bandwidth *struct {
		Up   String `json:"up"`
		Down String `json:"down"`
	} `json:"bandwidth"`

	HopInterval    String `json:"hopInterval"`
	HopIntervalAlt Int    `json:"hop_interval"`
	CWND           Int    `json:"cwnd"`
	UDPMTU         Int    `json:"udpMTU"`
	Version        Int    `json:"version"`

	// Some generators nest the TLS parameters in the settings object instead
	// of using streamSettings.
	TLS *struct {
		SNI        String     `json:"sni"`
		ServerName String     `json:"serverName"`
		Insecure   Bool       `json:"insecure"`
		ALPN       StringList `json:"alpn"`
		CA         String     `json:"ca"`
		Pin        String     `json:"pinSHA256"`
	} `json:"tls"`

	SNI      String     `json:"sni"`
	Insecure Bool       `json:"insecure"`
	ALPN     StringList `json:"alpn"`
}

// HysteriaServer is one entry of a hysteria settings.servers list.
type HysteriaServer struct {
	Address  String `json:"address"`
	Server   String `json:"server"`
	Port     Int    `json:"port"`
	Ports    String `json:"ports"`
	Password String `json:"password"`
	Auth     String `json:"auth"`
	AuthStr  String `json:"auth_str"`
	Up       String `json:"up"`
	Down     String `json:"down"`
	UpMbps   Int    `json:"upMbps"`
	DownMbps Int    `json:"downMbps"`
	Email    String `json:"email"`
}

// HysteriaObfs is the object form of the "obfs" field.
type HysteriaObfs struct {
	Type       String `json:"type"`
	Password   String `json:"password"`
	Salamander *struct {
		Password String `json:"password"`
	} `json:"salamander"`
}

// ParsedObfs returns the obfuscation mode and password, accepting both the
// string form ("salamander") and the object form used by the Hysteria2
// client.
func (s *HysteriaSettings) ParsedObfs() (mode, password string) {
	password = firstNonEmpty(string(s.ObfsPassword), string(s.ObfsParam))
	if len(s.Obfs) == 0 || isJSONNull(s.Obfs) {
		return "", password
	}
	trimmed := strings.TrimSpace(string(s.Obfs))
	if strings.HasPrefix(trimmed, "{") {
		var o HysteriaObfs
		if err := json.Unmarshal(s.Obfs, &o); err == nil {
			mode = strings.TrimSpace(string(o.Type))
			if o.Salamander != nil && o.Salamander.Password != "" {
				password = string(o.Salamander.Password)
			} else if o.Password != "" {
				password = string(o.Password)
			}
		}
		return mode, password
	}
	var str String
	if err := json.Unmarshal(s.Obfs, &str); err == nil {
		mode = strings.TrimSpace(string(str))
	}
	return mode, password
}

// TUICSettings covers standalone TUIC outbounds, which appear in mixed
// configuration sets for the same reason Hysteria2 does.
type TUICSettings struct {
	Servers []*TUICServer `json:"servers"`

	Address  String     `json:"address"`
	Server   String     `json:"server"`
	Port     Int        `json:"port"`
	UUID     String     `json:"uuid"`
	Password String     `json:"password"`
	Token    String     `json:"token"`
	ALPN     StringList `json:"alpn"`
	SNI      String     `json:"sni"`
	Insecure Bool       `json:"insecure"`

	CongestionControl    String `json:"congestion_control"`
	CongestionControlAlt String `json:"congestionController"`
	UDPRelayMode         String `json:"udp_relay_mode"`
	UDPRelayModeAlt      String `json:"udpRelayMode"`
	ReduceRTT            Bool   `json:"reduce_rtt"`
	ReduceRTTAlt         Bool   `json:"reduceRtt"`
	HeartbeatInterval    Int    `json:"heartbeat_interval"`
	DisableSNI           Bool   `json:"disable_sni"`
}

// TUICServer is one entry of a tuic settings.servers list.
type TUICServer struct {
	Address  String `json:"address"`
	Server   String `json:"server"`
	Port     Int    `json:"port"`
	UUID     String `json:"uuid"`
	Password String `json:"password"`
	Token    String `json:"token"`
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// FirstNonEmpty returns the first non-blank value, or "".
func FirstNonEmpty(values ...string) string { return firstNonEmpty(values...) }
