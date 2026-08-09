package convert

import (
	"strings"
	"testing"

	"misetanibox/mobilecore/internal/xray"
	"misetanibox/mobilecore/internal/yamlx"
)

// convertJSON runs the whole pipeline over a JSON snippet.
func convertJSON(t *testing.T, jsonText string) *Result {
	t.Helper()
	configs, err := xray.ParseConfigs([]byte(jsonText))
	if err != nil {
		t.Fatalf("ParseConfigs: %v", err)
	}
	res, err := Convert(configs, DefaultOptions())
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	return res
}

// one converts a snippet that is expected to produce exactly one proxy.
func one(t *testing.T, jsonText string) *yamlx.Map {
	t.Helper()
	res := convertJSON(t, jsonText)
	if len(res.Proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d (diagnostics: %v)", len(res.Proxies), res.Diagnostics)
	}
	return res.Proxies[0]
}

// field looks a value up along a path of nested map keys.
func field(t *testing.T, m *yamlx.Map, path ...string) any {
	t.Helper()
	var cur any = m
	for i, key := range path {
		asMap, ok := cur.(*yamlx.Map)
		if !ok {
			t.Fatalf("%s is not a map", strings.Join(path[:i], "."))
		}
		v, found := asMap.Get(key)
		if !found {
			t.Fatalf("key %q not found (path %s)", key, strings.Join(path[:i+1], "."))
		}
		cur = v
	}
	return cur
}

func assertField(t *testing.T, m *yamlx.Map, want any, path ...string) {
	t.Helper()
	if got := field(t, m, path...); got != want {
		t.Errorf("%s = %v (%T), want %v (%T)", strings.Join(path, "."), got, got, want, want)
	}
}

func assertNoField(t *testing.T, m *yamlx.Map, key string) {
	t.Helper()
	if m.Has(key) {
		v, _ := m.Get(key)
		t.Errorf("expected no %q, got %v", key, v)
	}
}

// ------------------------------------------------------ VLESS encryption ---

func TestVLESSEncryptionPassesThroughValidValue(t *testing.T) {
	const enc = "mlkem768x25519plus.native.1rtt.100-111-1111.75-0-111.50-0-3333." +
		"RvI5xPRmxvhVMSxOsCUDIF1uu4sN0-1Z9RXTVIrGYFk"

	m := one(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"`+enc+`"}]}]},
		"streamSettings":{"network":"tcp","security":"tls"}}]}`)

	// mihomo parses this field with the same grammar Xray uses, so the value
	// must survive untouched.
	assertField(t, m, enc, "encryption")
}

func TestVLESSEncryptionNoneIsOmitted(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]}}]}`)
	assertNoField(t, m, "encryption")
}

func TestVLESSEncryptionRejectsInvalidValues(t *testing.T) {
	const key = "RvI5xPRmxvhVMSxOsCUDIF1uu4sN0-1Z9RXTVIrGYFk"
	tests := []struct {
		name string
		enc  string
		want string
	}{
		{
			name: "server side seconds in the client field",
			enc:  "mlkem768x25519plus.native.600s.100-111-1111." + key,
			want: "1rtt or 0rtt",
		},
		{
			name: "unknown mode",
			enc:  "mlkem768x25519plus.plain.1rtt.100-111-1111." + key,
			want: "native, xorpub or random",
		},
		{
			name: "unknown scheme",
			enc:  "aes-128-gcm.native.1rtt.100-111-1111." + key,
			want: "mlkem768x25519plus",
		},
		{
			name: "padding without three parts",
			enc:  "mlkem768x25519plus.native.1rtt.30-50." + key,
			want: "form a-b-c",
		},
		{
			name: "first padding below the minimum",
			enc:  "mlkem768x25519plus.native.1rtt.50-10-10." + key,
			want: "at least 100-35-35",
		},
		{
			name: "key of the wrong length",
			enc:  "mlkem768x25519plus.native.1rtt.100-111-1111.aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSBrZXk",
			want: "expected 32 or 1184",
		},
		{
			name: "no key at all",
			enc:  "mlkem768x25519plus.native.1rtt.100-111-1111.75-0-111",
			want: "no server key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := convertJSON(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{
				"address":"a.example.com","port":443,"users":[{
				"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"`+tc.enc+`"}]}]}}]}`)

			// An invalid value makes mihomo reject the whole file, so the node
			// must be dropped rather than emitted.
			if len(res.Proxies) != 0 {
				t.Fatalf("expected the node to be skipped, got %d proxies", len(res.Proxies))
			}
			if res.Skipped != 1 {
				t.Fatalf("expected 1 skipped outbound, got %d", res.Skipped)
			}
			msg := res.Diagnostics[0].Message
			if !strings.Contains(msg, tc.want) {
				t.Errorf("diagnostic %q does not mention %q", msg, tc.want)
			}
		})
	}
}

// ------------------------------------------------------------- XHTTP -------

func TestXHTTPExtraReplacesOuterSettings(t *testing.T) {
	// Xray applies "extra" by replacing the whole object and then restoring
	// host, path and mode from the outer one. A naive merge would keep the
	// outer headers and padding, which the source never asked for.
	m := one(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
		"streamSettings":{"network":"xhttp","security":"tls","xhttpSettings":{
			"host":"outer.example.com","path":"/outer","mode":"stream-up",
			"headers":{"X-Outer":"dropped"},
			"xPaddingBytes":"1-2",
			"extra":{"headers":{"X-Inner":"kept"},"xPaddingBytes":"100-1000","noGRPCHeader":true}
		}}}]}`)

	opts := field(t, m, "xhttp-opts").(*yamlx.Map)
	assertField(t, opts, "outer.example.com", "host")
	assertField(t, opts, "/outer", "path")
	assertField(t, opts, "stream-up", "mode")
	assertField(t, opts, "100-1000", "x-padding-bytes")
	assertField(t, opts, true, "no-grpc-header")
	assertField(t, opts, "kept", "headers", "X-Inner")

	headers := field(t, opts, "headers").(*yamlx.Map)
	if headers.Has("X-Outer") {
		t.Error("headers from outside \"extra\" must be replaced, not merged")
	}
}

func TestXHTTPXmuxMapsToReuseSettings(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
		"streamSettings":{"network":"xhttp","security":"tls","xhttpSettings":{
			"path":"/x","xmux":{"maxConcurrency":"16-32","maxConnections":0,
			"cMaxReuseTimes":"64-128","hMaxRequestTimes":"800-900",
			"hMaxReusableSecs":"1800-3000","hKeepAlivePeriod":45}}}}]}`)

	reuse := field(t, m, "xhttp-opts", "reuse-settings").(*yamlx.Map)
	assertField(t, reuse, "16-32", "max-concurrency")
	assertField(t, reuse, "64-128", "c-max-reuse-times")
	assertField(t, reuse, "800-900", "h-max-request-times")
	assertField(t, reuse, "1800-3000", "h-max-reusable-secs")
	assertField(t, reuse, 45, "h-keep-alive-period")

	// Xray reads 0 as "use the default", so it must not be passed on as "0".
	assertNoField(t, reuse, "max-connections")
}

func TestXHTTPDownloadSettings(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
		"streamSettings":{"network":"xhttp","security":"tls","xhttpSettings":{
			"path":"/up","mode":"packet-up",
			"downloadSettings":{"address":"dl.example.com","port":8443,"network":"xhttp",
				"security":"tls","tlsSettings":{"serverName":"dl.example.com","fingerprint":"firefox"},
				"xhttpSettings":{"path":"/down","host":"dl.example.com",
					"xmux":{"maxConcurrency":"8-16"}}}}}}]}`)

	dl := field(t, m, "xhttp-opts", "download-settings").(*yamlx.Map)
	assertField(t, dl, "dl.example.com", "server")
	assertField(t, dl, 8443, "port")
	assertField(t, dl, "/down", "path")
	assertField(t, dl, "dl.example.com", "host")
	assertField(t, dl, true, "tls")
	assertField(t, dl, "dl.example.com", "servername")
	assertField(t, dl, "firefox", "client-fingerprint")
	assertField(t, dl, "8-16", "reuse-settings", "max-concurrency")
}

func TestXHTTPRejectsInvalidCombinations(t *testing.T) {
	// GET uplink is only legal in packet-up mode; Xray refuses it elsewhere.
	res := convertJSON(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
		"streamSettings":{"network":"xhttp","security":"tls","xhttpSettings":{
			"mode":"stream-one","uplinkHTTPMethod":"GET"}}}]}`)

	if len(res.Proxies) != 0 {
		t.Fatalf("expected the node to be skipped, got %d proxies", len(res.Proxies))
	}
	if !strings.Contains(res.Diagnostics[0].Message, "packet-up") {
		t.Errorf("unexpected diagnostic: %s", res.Diagnostics[0].Message)
	}
}

func TestXHTTPModeDefaultsToAuto(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
		"streamSettings":{"network":"xhttp","security":"tls","xhttpSettings":{"path":"/x"}}}]}`)
	assertField(t, m, "auto", "xhttp-opts", "mode")
}

// --------------------------------------------------------- Transports ------

func TestWebsocketEarlyDataMovesOutOfPath(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":0}]}]},
		"streamSettings":{"network":"ws","security":"tls","wsSettings":{
			"path":"/ws?ed=2560","headers":{"Host":"cdn.example.com"}}}}]}`)

	ws := field(t, m, "ws-opts").(*yamlx.Map)
	assertField(t, ws, "/ws", "path")
	assertField(t, ws, 2560, "max-early-data")
	assertField(t, ws, "Sec-WebSocket-Protocol", "early-data-header-name")
	// A Host header becomes the transport host.
	assertField(t, ws, "cdn.example.com", "headers", "Host")
}

func TestHTTPUpgradeBecomesWebsocketWithFlag(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
		"streamSettings":{"network":"httpupgrade","security":"tls",
		"httpupgradeSettings":{"path":"/up","host":"hu.example.com"}}}]}`)

	assertField(t, m, "ws", "network")
	assertField(t, m, true, "ws-opts", "v2ray-http-upgrade")
	assertField(t, m, "/up", "ws-opts", "path")
	assertField(t, m, "hu.example.com", "ws-opts", "headers", "Host")
}

func TestRawHTTPHeaderBecomesHTTPNetwork(t *testing.T) {
	// Xray's raw transport with an HTTP header is mihomo's "http" network,
	// which is a different thing from mihomo's "h2".
	m := one(t, `{"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":"a.example.com",
		"port":80,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":0}]}]},
		"streamSettings":{"network":"tcp","tcpSettings":{"header":{"type":"http",
			"request":{"method":"GET","path":["/"],"headers":{"Host":["cdn.example.com"]}}}}}}]}`)

	assertField(t, m, "http", "network")
	assertField(t, m, "GET", "http-opts", "method")
}

func TestPlainTCPHasNoNetworkKey(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
		"streamSettings":{"network":"raw","security":"tls"}}]}`)
	// tcp is mihomo's default, so the key is left out entirely.
	assertNoField(t, m, "network")
}

func TestUnsupportedTransportsAreSkipped(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		mention string
	}{
		{
			name: "trojan over h2",
			json: `{"outbounds":[{"protocol":"trojan","settings":{"servers":[{"address":"a.example.com",
				"port":443,"password":"p"}]},"streamSettings":{"network":"http","security":"tls"}}]}`,
			mention: "h2 transport for trojan",
		},
		{
			name: "vless over mkcp",
			json: `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
				"streamSettings":{"network":"kcp"}}]}`,
			mention: "kcp transport for vless",
		},
		{
			name: "vmess over xhttp",
			json: `{"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":"a.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":0}]}]},
				"streamSettings":{"network":"xhttp"}}]}`,
			mention: "xhttp transport for vmess",
		},
		{
			name: "quic",
			json: `{"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":"a.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":0}]}]},
				"streamSettings":{"network":"quic"}}]}`,
			mention: "QUIC",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := convertJSON(t, tc.json)
			if len(res.Proxies) != 0 {
				t.Fatalf("expected the node to be skipped, got %d proxies", len(res.Proxies))
			}
			if !strings.Contains(res.Diagnostics[0].Message, tc.mention) {
				t.Errorf("diagnostic %q does not mention %q", res.Diagnostics[0].Message, tc.mention)
			}
		})
	}
}

func TestVMessOverMKCP(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":0}]}]},
		"streamSettings":{"network":"kcp","kcpSettings":{"mtu":1350,"tti":50,
			"uplinkCapacity":5,"downlinkCapacity":20,"congestion":true,
			"seed":"pepper","header":{"type":"wechat-video"}}}}]}`)

	assertField(t, m, "kcp", "network")
	assertField(t, m, 1350, "mkcp-opts", "mtu")
	assertField(t, m, true, "mkcp-opts", "congestion")
	assertField(t, m, "pepper", "mkcp-opts", "seed")
	assertField(t, m, "wechat-video", "mkcp-opts", "header")
}

// --------------------------------------------------------------- TLS -------

func TestRealityMapping(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]}]},
		"streamSettings":{"network":"raw","security":"reality","realitySettings":{
			"serverName":"www.microsoft.com","fingerprint":"chrome",
			"publicKey":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","shortId":"6ba85179e30d4fc2"}}}]}`)

	assertField(t, m, true, "tls")
	assertField(t, m, "www.microsoft.com", "servername")
	assertField(t, m, "chrome", "client-fingerprint")
	assertField(t, m, "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", "reality-opts", "public-key")
	assertField(t, m, "6ba85179e30d4fc2", "reality-opts", "short-id")
	assertField(t, m, "xtls-rprx-vision", "flow")
}

func TestRealityAcceptsServerNamesAndShortIdsLists(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
		"streamSettings":{"security":"reality","realitySettings":{
			"serverNames":["www.apple.com","www.icloud.com"],
			"publicKey":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
			"shortIds":["aabb","ccdd"]}}}]}`)

	assertField(t, m, "www.apple.com", "servername")
	assertField(t, m, "aabb", "reality-opts", "short-id")
}

func TestCertificatePinIsReEncodedAsHex(t *testing.T) {
	// Xray writes the pin in base64; mihomo expects hex.
	m := one(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
		"streamSettings":{"security":"tls","tlsSettings":{
			"pinnedPeerCertSha256":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}}}]}`)

	assertField(t, m, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "fingerprint")
}

func TestVisionUDP443FlowIsAccepted(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811",
		"flow":"xtls-rprx-vision-udp443"}]}]},"streamSettings":{"security":"tls"}}]}`)
	assertField(t, m, "xtls-rprx-vision", "flow")
}

func TestDeprecatedFlowIsRejected(t *testing.T) {
	res := convertJSON(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811",
		"flow":"xtls-rprx-origin"}]}]},"streamSettings":{"security":"tls"}}]}`)

	if len(res.Proxies) != 0 {
		t.Fatalf("expected the node to be skipped, got %d proxies", len(res.Proxies))
	}
	if !strings.Contains(res.Diagnostics[0].Message, "xtls-rprx-vision") {
		t.Errorf("unexpected diagnostic: %s", res.Diagnostics[0].Message)
	}
}

// ---------------------------------------------------------- Hysteria2 ------

func TestHysteria2ObjectObfsAndBandwidth(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"hysteria2","settings":{
		"address":"hy2.example.com","port":443,"ports":"20000-30000","hopInterval":"30s",
		"password":"secret","obfs":{"type":"salamander","password":"obfs-pw"},
		"bandwidth":{"up":"50 Mbps","down":"200 Mbps"},
		"tls":{"sni":"hy2.example.com","insecure":true,"alpn":["h3"]}}}]}`)

	assertField(t, m, "hysteria2", "type")
	assertField(t, m, "secret", "password")
	assertField(t, m, "salamander", "obfs")
	assertField(t, m, "obfs-pw", "obfs-password")
	assertField(t, m, "50 Mbps", "up")
	assertField(t, m, "200 Mbps", "down")
	assertField(t, m, "20000-30000", "ports")
	assertField(t, m, "30", "hop-interval")
	assertField(t, m, "hy2.example.com", "sni")
	assertField(t, m, true, "skip-cert-verify")
}

func TestHysteria2AlternativeSpellings(t *testing.T) {
	// The Hysteria2 client calls the credential "auth" and the rates "upMbps".
	m := one(t, `{"outbounds":[{"protocol":"hysteria2","settings":{
		"server":"hy2.example.com:8443","auth":"pw","obfs":"salamander",
		"obfsPassword":"o","upMbps":30,"downMbps":100,"sni":"example.org"}}]}`)

	assertField(t, m, "hy2.example.com", "server")
	assertField(t, m, 8443, "port")
	assertField(t, m, "pw", "password")
	assertField(t, m, "30 Mbps", "up")
	assertField(t, m, "100 Mbps", "down")
	assertField(t, m, "o", "obfs-password")
	assertField(t, m, "example.org", "sni")
}

func TestHysteria2BareNumberBandwidthGetsUnit(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"hysteria2","settings":{
		"address":"hy2.example.com","port":443,"password":"pw","up":"50","down":"200"}}]}`)
	assertField(t, m, "50 Mbps", "up")
	assertField(t, m, "200 Mbps", "down")
}

func TestHysteria2UsesStreamSettingsTLS(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"hysteria2","settings":{
		"address":"hy2.example.com","port":443,"password":"pw"},
		"streamSettings":{"security":"tls","tlsSettings":{"serverName":"sni.example.com",
		"allowInsecure":true,"alpn":["h3"]}}}]}`)

	assertField(t, m, "sni.example.com", "sni")
	assertField(t, m, true, "skip-cert-verify")
}

func TestHysteriaTransportIsReportedNotSilentlyWrong(t *testing.T) {
	// Xray can carry VLESS inside a Hysteria tunnel; mihomo cannot express
	// that, and quietly emitting a plain hysteria2 node would be wrong.
	res := convertJSON(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{
		"address":"a.example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
		"streamSettings":{"network":"hysteria","security":"tls",
		"hysteriaSettings":{"version":2,"auth":"pw"}}}]}`)

	if len(res.Proxies) != 0 {
		t.Fatalf("expected the node to be skipped, got %d proxies", len(res.Proxies))
	}
	if !strings.Contains(res.Diagnostics[0].Message, "Hysteria tunnel") {
		t.Errorf("unexpected diagnostic: %s", res.Diagnostics[0].Message)
	}
}

// ------------------------------------------------------- Other protocols ---

func TestWireGuardMapping(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"wireguard","settings":{
		"secretKey":"yGXpFcJUXqLL0hV8Cz1234567890abcdefghijklmnA=",
		"address":["172.16.0.2/32","fd00::2/128"],"mtu":1420,"reserved":[12,34,56],
		"peers":[{"publicKey":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		"endpoint":"wg.example.com:51820","allowedIPs":["0.0.0.0/0","::/0"],"keepAlive":25}]}}]}`)

	assertField(t, m, "wireguard", "type")
	assertField(t, m, "wg.example.com", "server")
	assertField(t, m, 51820, "port")
	// The interface addresses lose their prefix length.
	assertField(t, m, "172.16.0.2", "ip")
	assertField(t, m, "fd00::2", "ipv6")
	assertField(t, m, 1420, "mtu")
	assertField(t, m, 25, "persistent-keepalive")
}

func TestWireGuardReservedAsBase64(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"wireguard","settings":{
		"secretKey":"yGXpFcJUXqLL0hV8Cz1234567890abcdefghijklmnA=","address":["172.16.0.2/32"],
		"reserved":"DCI4","peers":[{"publicKey":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		"endpoint":"wg.example.com:51820"}]}}]}`)

	reserved, ok := field(t, m, "reserved").(yamlx.FlowSeq)
	if !ok || len(reserved) != 3 {
		t.Fatalf("reserved = %v, want three bytes", reserved)
	}
	if reserved[0] != 12 || reserved[1] != 34 || reserved[2] != 56 {
		t.Errorf("reserved = %v, want [12 34 56]", reserved)
	}
}

func TestShadowsocksMapping(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{
		"address":"ss.example.com","port":8388,"method":"2022-blake3-aes-128-gcm",
		"password":"OTk4NTY0MzIxMDk4NzY1NA==","uot":true}]}}]}`)

	assertField(t, m, "ss", "type")
	assertField(t, m, "2022-blake3-aes-128-gcm", "cipher")
	assertField(t, m, true, "udp-over-tcp")
}

func TestShadowsocksPlainCipherIsRenamed(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{
		"address":"ss.example.com","port":8388,"method":"plain","password":"p"}]}}]}`)
	assertField(t, m, "none", "cipher")
}

func TestSocksAndHTTPCredentials(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"socks","settings":{"servers":[{
		"address":"127.0.0.1","port":1080,"users":[{"user":"alice","pass":"s3cret"}]}]}}]}`)

	assertField(t, m, "socks5", "type")
	assertField(t, m, "alice", "username")
	assertField(t, m, "s3cret", "password")
}

func TestNonProxyOutboundsAreIgnored(t *testing.T) {
	res := convertJSON(t, `{"outbounds":[
		{"protocol":"freedom","tag":"direct"},
		{"protocol":"blackhole","tag":"block"},
		{"protocol":"dns","tag":"dns-out"},
		{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com","port":443,
			"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}]}`)

	if len(res.Proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(res.Proxies))
	}
	if res.Skipped != 0 {
		t.Errorf("local outbounds should not count as skipped, got %d", res.Skipped)
	}
}

// ------------------------------------------------------------- Naming ------

func TestNamingPrefersRemarksThenTagThenAddress(t *testing.T) {
	res := convertJSON(t, `[
		{"remarks":"Tokyo 01","outbounds":[{"protocol":"vless","tag":"proxy","settings":{
			"vnext":[{"address":"a.example.com","port":443,
			"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}]},
		{"outbounds":[{"protocol":"vless","tag":"Osaka","settings":{
			"vnext":[{"address":"b.example.com","port":443,
			"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}]},
		{"outbounds":[{"protocol":"vless","tag":"proxy","settings":{
			"vnext":[{"address":"c.example.com","port":8443,
			"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}]}]`)

	want := []string{"Tokyo 01", "Osaka", "vless-c.example.com:8443"}
	got := res.Names()
	if len(got) != len(want) {
		t.Fatalf("got %d names %v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("name[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDuplicateNamesAreMadeUnique(t *testing.T) {
	res := convertJSON(t, `[
		{"remarks":"Node","outbounds":[{"protocol":"vless","settings":{"vnext":[{
			"address":"a.example.com","port":443,
			"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}]},
		{"remarks":"Node","outbounds":[{"protocol":"vless","settings":{"vnext":[{
			"address":"b.example.com","port":443,
			"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}]},
		{"remarks":"Node","outbounds":[{"protocol":"vless","settings":{"vnext":[{
			"address":"c.example.com","port":443,
			"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}]}]`)

	// mihomo refuses a proxy list that repeats a name.
	seen := map[string]bool{}
	for _, n := range res.Names() {
		if seen[n] {
			t.Errorf("duplicate proxy name %q", n)
		}
		seen[n] = true
	}
	if len(seen) != 3 {
		t.Errorf("expected 3 distinct names, got %v", res.Names())
	}
}

func TestNamePrefixIsApplied(t *testing.T) {
	configs, err := xray.ParseConfigs([]byte(`{"remarks":"Node","outbounds":[{"protocol":"vless",
		"settings":{"vnext":[{"address":"a.example.com","port":443,
		"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	opts := DefaultOptions()
	opts.NamePrefix = "[JP] "
	res, err := Convert(configs, opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Names()[0]; got != "[JP] Node" {
		t.Errorf("name = %q, want %q", got, "[JP] Node")
	}
}

// -------------------------------------------------------------- Options ----

func TestStrictModeFailsInsteadOfSkipping(t *testing.T) {
	configs, err := xray.ParseConfigs([]byte(`{"outbounds":[{"protocol":"vmess",
		"settings":{"vnext":[{"address":"a.example.com","port":443,
		"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":0}]}]},
		"streamSettings":{"network":"quic"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	opts := DefaultOptions()
	opts.Strict = true
	if _, err := Convert(configs, opts); err == nil {
		t.Fatal("expected strict mode to fail on an unconvertible outbound")
	}
}

func TestSkipCertVerifyOptionForcesTheFlag(t *testing.T) {
	configs, err := xray.ParseConfigs([]byte(`{"outbounds":[{"protocol":"vless",
		"settings":{"vnext":[{"address":"a.example.com","port":443,
		"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
		"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	opts := DefaultOptions()
	opts.SkipCertVerify = true
	res, err := Convert(configs, opts)
	if err != nil {
		t.Fatal(err)
	}
	assertField(t, res.Proxies[0], true, "skip-cert-verify")
}

func TestNoUDPOptionOmitsTheFlag(t *testing.T) {
	configs, err := xray.ParseConfigs([]byte(`{"outbounds":[{"protocol":"vless",
		"settings":{"vnext":[{"address":"a.example.com","port":443,
		"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Convert(configs, Options{UDP: false})
	if err != nil {
		t.Fatal(err)
	}
	assertNoField(t, res.Proxies[0], "udp")
}

// -------------------------------------------------------------- Sockopt ----

func TestSockoptMapping(t *testing.T) {
	m := one(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
		"streamSettings":{"sockopt":{"tcpFastOpen":true,"tcpMptcp":true,
		"interface":"eth0","mark":255,"domainStrategy":"UseIPv4"}}}]}`)

	assertField(t, m, true, "tfo")
	assertField(t, m, true, "mptcp")
	assertField(t, m, "eth0", "interface-name")
	assertField(t, m, 255, "routing-mark")
	assertField(t, m, "ipv4", "ip-version")
}
