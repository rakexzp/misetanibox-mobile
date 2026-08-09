package convert

import (
	"strings"
	"testing"

	"misetanibox/mobilecore/internal/yamlx"
)

// Xray writes a plain Hysteria2 server with the "hysteria" outbound protocol,
// whose settings hold nothing but the address and port. The password and the
// rest live in streamSettings, and reading only the settings object left every
// such node rejected for having no password.

const xrayNativeHysteria2 = `[{
	"remarks": "Bulgaria",
	"outbounds": [{
		"tag": "proxy",
		"protocol": "hysteria",
		"settings": { "address": "hy2.example.com", "port": 30443, "version": 2 },
		"streamSettings": {
			"network": "hysteria",
			"hysteriaSettings": { "version": 2, "auth": "the-password" },
			"security": "tls",
			"tlsSettings": { "serverName": "sni.example.com", "alpn": ["h3"] }
		}
	}]
}]`

func TestXrayNativeHysteria2(t *testing.T) {
	m := one(t, xrayNativeHysteria2)

	assertField(t, m, "hysteria2", "type")
	assertField(t, m, "hy2.example.com", "server")
	assertField(t, m, 30443, "port")
	// The password comes from streamSettings, not from the outbound settings.
	assertField(t, m, "the-password", "password")
	assertField(t, m, "sni.example.com", "sni")
}

func TestHysteria2VersionFoundInStreamSettings(t *testing.T) {
	// Only hysteriaSettings states the version; the node is still Hysteria2
	// and must not fall through to the version 1 converter.
	m := one(t, `[{
		"outbounds": [{
			"protocol": "hysteria",
			"settings": { "address": "hy2.example.com", "port": 443 },
			"streamSettings": {
				"network": "hysteria",
				"hysteriaSettings": { "version": 2, "auth": "pw" },
				"security": "tls"
			}
		}]
	}]`)

	assertField(t, m, "hysteria2", "type")
	assertField(t, m, "pw", "password")
}

func TestHysteria2ImpliedByTheHysteriaTransport(t *testing.T) {
	// Xray's hysteria outbound only ever speaks version 2, so the transport
	// alone settles it.
	m := one(t, `[{
		"outbounds": [{
			"protocol": "hysteria",
			"settings": { "address": "hy2.example.com", "port": 443 },
			"streamSettings": {
				"network": "hysteria",
				"hysteriaSettings": { "auth": "pw" },
				"security": "tls"
			}
		}]
	}]`)

	assertField(t, m, "hysteria2", "type")
	assertField(t, m, "pw", "password")
}

func TestHysteria2ReadsFinalMaskQuicParams(t *testing.T) {
	// Newer Xray builds moved the bandwidth, port hopping and QUIC windows
	// out of hysteriaSettings and into finalmask.
	m := one(t, `[{
		"outbounds": [{
			"protocol": "hysteria",
			"settings": { "address": "hy2.example.com", "port": 443, "version": 2 },
			"streamSettings": {
				"network": "hysteria",
				"hysteriaSettings": { "version": 2, "auth": "pw" },
				"security": "tls",
				"finalmask": { "quicParams": {
					"congestion": "brutal",
					"bbrProfile": "normal",
					"brutalUp": "50 mbps",
					"brutalDown": "200 mbps",
					"udpHop": { "ports": "20000-30000", "interval": 30 },
					"initStreamReceiveWindow": 8388608,
					"maxStreamReceiveWindow": 16777216,
					"initConnectionReceiveWindow": 20971520,
					"maxConnectionReceiveWindow": 41943040
				}}
			}
		}]
	}]`)

	assertField(t, m, "50 mbps", "up")
	assertField(t, m, "200 mbps", "down")
	assertField(t, m, "20000-30000", "ports")
	assertField(t, m, "30", "hop-interval")
	assertField(t, m, "normal", "bbr-profile")
	assertField(t, m, uint64(8388608), "initial-stream-receive-window")
	assertField(t, m, uint64(16777216), "max-stream-receive-window")
	assertField(t, m, uint64(20971520), "initial-connection-receive-window")
	assertField(t, m, uint64(41943040), "max-connection-receive-window")
}

func TestHysteria2ReadsSalamanderMask(t *testing.T) {
	// The Hysteria obfuscator is a finalmask UDP mask in an Xray config.
	m := one(t, `[{
		"outbounds": [{
			"protocol": "hysteria",
			"settings": { "address": "hy2.example.com", "port": 443, "version": 2 },
			"streamSettings": {
				"network": "hysteria",
				"hysteriaSettings": { "version": 2, "auth": "pw" },
				"security": "tls",
				"finalmask": { "udp": [
					{ "type": "salamander", "settings": { "password": "obfs-secret" } }
				]}
			}
		}]
	}]`)

	assertField(t, m, "salamander", "obfs")
	assertField(t, m, "obfs-secret", "obfs-password")
}

func TestHysteria2SalamanderPacketSizeSelectsGecko(t *testing.T) {
	// A packet size range turns the mask into the gecko variant, which mihomo
	// spells as its own obfuscator with a size range.
	m := one(t, `[{
		"outbounds": [{
			"protocol": "hysteria",
			"settings": { "address": "hy2.example.com", "port": 443, "version": 2 },
			"streamSettings": {
				"network": "hysteria",
				"hysteriaSettings": { "version": 2, "auth": "pw" },
				"security": "tls",
				"finalmask": { "udp": [
					{ "type": "salamander", "settings": {
						"password": "obfs-secret", "packetSize": "100-1200" } }
				]}
			}
		}]
	}]`)

	assertField(t, m, "gecko", "obfs")
	assertField(t, m, "obfs-secret", "obfs-password")
	assertField(t, m, 100, "obfs-min-packet-size")
	assertField(t, m, 1200, "obfs-max-packet-size")
}

func TestHysteria2PortHoppingFromHysteriaSettings(t *testing.T) {
	m := one(t, `[{
		"outbounds": [{
			"protocol": "hysteria",
			"settings": { "address": "hy2.example.com", "port": 0, "version": 2 },
			"streamSettings": {
				"network": "hysteria",
				"hysteriaSettings": { "version": 2, "auth": "pw",
					"udphop": { "ports": [ "20000-30000" ], "interval": 20 } },
				"security": "tls"
			}
		}]
	}]`)

	assertField(t, m, "20000-30000", "ports")
	assertField(t, m, "20", "hop-interval")
	// Without a base port, the low end of the hopping range is dialled first.
	assertField(t, m, 20000, "port")
}

func TestHysteria2SettingsWinOverStreamSettings(t *testing.T) {
	// A generator that fills the settings object means those values.
	m := one(t, `[{
		"outbounds": [{
			"protocol": "hysteria2",
			"settings": { "address": "hy2.example.com", "port": 443,
				"password": "from-settings", "up": "10 mbps" },
			"streamSettings": {
				"network": "hysteria",
				"hysteriaSettings": { "version": 2, "auth": "from-stream", "up": "99 mbps" },
				"security": "tls"
			}
		}]
	}]`)

	assertField(t, m, "from-settings", "password")
	assertField(t, m, "10 mbps", "up")
}

func TestHysteria2ReportsAnInapplicableUTLSFingerprint(t *testing.T) {
	// Hysteria2 is QUIC: there is no TLS ClientHello for a uTLS profile to
	// shape, and mihomo has no field for one.
	res := convertJSON(t, `[{
		"outbounds": [{
			"protocol": "hysteria",
			"settings": { "address": "hy2.example.com", "port": 443, "version": 2 },
			"streamSettings": {
				"network": "hysteria",
				"hysteriaSettings": { "version": 2, "auth": "pw" },
				"security": "tls",
				"tlsSettings": { "serverName": "hy2.example.com", "fingerprint": "firefox" }
			}
		}]
	}]`)

	if len(res.Proxies) != 1 {
		t.Fatalf("expected the node to convert, got %d proxies", len(res.Proxies))
	}
	if res.Proxies[0].Has("client-fingerprint") {
		t.Error("a uTLS fingerprint must not reach a hysteria2 proxy")
	}
	if !hasDiagnostic(res, "uTLS fingerprint") {
		t.Errorf("the dropped fingerprint was not reported: %v", res.Diagnostics)
	}
}

func TestHysteria2ReportsAnUnknownCongestionController(t *testing.T) {
	res := convertJSON(t, `[{
		"outbounds": [{
			"protocol": "hysteria",
			"settings": { "address": "hy2.example.com", "port": 443, "version": 2 },
			"streamSettings": {
				"network": "hysteria",
				"hysteriaSettings": { "version": 2, "auth": "pw" },
				"security": "tls",
				"finalmask": { "quicParams": { "congestion": "cubic" } }
			}
		}]
	}]`)

	if len(res.Proxies) != 1 {
		t.Fatalf("expected the node to convert, got %d proxies", len(res.Proxies))
	}
	if !hasDiagnostic(res, "congestion") {
		t.Errorf("the unknown congestion controller was not reported: %v", res.Diagnostics)
	}
}

func TestHysteria2WithoutAPasswordSaysWhereToLook(t *testing.T) {
	res := convertJSON(t, `[{
		"outbounds": [{
			"protocol": "hysteria",
			"settings": { "address": "hy2.example.com", "port": 443, "version": 2 },
			"streamSettings": { "network": "hysteria", "security": "tls" }
		}]
	}]`)

	if len(res.Proxies) != 0 {
		t.Fatalf("expected the node to be skipped, got %d proxies", len(res.Proxies))
	}
	if !strings.Contains(res.Diagnostics[0].Message, "hysteriaSettings.auth") {
		t.Errorf("the message does not say where the password lives: %s", res.Diagnostics[0].Message)
	}
}

func TestOtherProtocolsOverTheHysteriaTransportAreStillRejected(t *testing.T) {
	// A VLESS outbound really is tunnelled inside Hysteria there, which mihomo
	// cannot express -- unlike the hysteria outbound, which is the plain
	// protocol.
	res := convertJSON(t, `[{
		"outbounds": [{
			"protocol": "vless",
			"settings": {"vnext":[{"address":"a.example.com","port":443,
				"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
			"streamSettings": {
				"network": "hysteria",
				"hysteriaSettings": { "version": 2, "auth": "pw" },
				"security": "tls"
			}
		}]
	}]`)

	if len(res.Proxies) != 0 {
		t.Fatalf("expected the node to be skipped, got %d proxies", len(res.Proxies))
	}
	if !strings.Contains(res.Diagnostics[0].Message, "Hysteria tunnel") {
		t.Errorf("unexpected diagnostic: %s", res.Diagnostics[0].Message)
	}
}

func TestHysteriaVersionOneStillConverts(t *testing.T) {
	// Version 1 nodes keep going to the hysteria converter.
	m := one(t, `[{
		"outbounds": [{
			"protocol": "hysteria",
			"settings": { "address": "hy1.example.com", "port": 443, "version": 1,
				"auth_str": "pw", "up": "50", "down": "200" }
		}]
	}]`)

	assertField(t, m, "hysteria", "type")
	assertField(t, m, "pw", "auth-str")
}

func TestHysteria2AlpnAndFlowSequence(t *testing.T) {
	m := one(t, xrayNativeHysteria2)
	alpn, ok := field(t, m, "alpn").(yamlx.FlowSeq)
	if !ok || len(alpn) != 1 || alpn[0] != "h3" {
		t.Errorf("alpn = %v, want [h3]", alpn)
	}
}
