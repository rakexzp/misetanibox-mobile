package xray

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestStripJSONC(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "line comment",
			in:   "{\n  // a comment\n  \"a\": 1\n}",
			want: "{\n  \n  \"a\": 1\n}",
		},
		{
			name: "block comment",
			in:   `{"a": /* inline */ 1}`,
			want: `{"a":  1}`,
		},
		{
			name: "trailing comma in object",
			in:   `{"a": 1,}`,
			want: `{"a": 1}`,
		},
		{
			name: "trailing comma in array",
			in:   `[1, 2, ]`,
			want: `[1, 2 ]`,
		},
		{
			name: "comment characters inside a string are kept",
			in:   `{"path": "/a//b", "url": "http://example.com/*x*/"}`,
			want: `{"path": "/a//b", "url": "http://example.com/*x*/"}`,
		},
		{
			name: "escaped quote does not end the string",
			in:   `{"a": "say \" // not a comment"}`,
			want: `{"a": "say \" // not a comment"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(StripJSONC([]byte(tc.in))); got != tc.want {
				t.Errorf("StripJSONC(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestStripJSONCKeepsCommentedInputValid(t *testing.T) {
	const in = `// leading comment
	[
	  {
	    "remarks": "node", // trailing comment
	    /* block */
	    "outbounds": [{"protocol": "freedom"}],
	  },
	]`
	var v []map[string]any
	if err := json.Unmarshal(StripJSONC([]byte(in)), &v); err != nil {
		t.Fatalf("stripped JSON is still invalid: %v", err)
	}
	if len(v) != 1 || v[0]["remarks"] != "node" {
		t.Errorf("unexpected result: %v", v)
	}
}

func TestFlexibleScalarTypes(t *testing.T) {
	var v struct {
		Port    Int    `json:"port"`
		Name    String `json:"name"`
		Enabled Bool   `json:"enabled"`
	}
	// Generators stringify values inconsistently; all of these must parse.
	if err := json.Unmarshal([]byte(`{"port":"443","name":8080,"enabled":"true"}`), &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if v.Port.Int() != 443 {
		t.Errorf("port = %d, want 443", v.Port.Int())
	}
	if v.Name.String() != "8080" {
		t.Errorf("name = %q, want \"8080\"", v.Name.String())
	}
	if !v.Enabled.Bool() {
		t.Error("enabled = false, want true")
	}
}

func TestStringListAcceptsBothForms(t *testing.T) {
	var v struct {
		A StringList `json:"a"`
		B StringList `json:"b"`
	}
	if err := json.Unmarshal([]byte(`{"a":["h2","http/1.1"],"b":"h2,http/1.1"}`), &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, got := range []StringList{v.A, v.B} {
		if len(got) != 2 || got[0] != "h2" || got[1] != "http/1.1" {
			t.Errorf("got %v, want [h2 http/1.1]", got)
		}
	}
}

func TestInt32Range(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{`100`, "100"},
		{`"100"`, "100"},
		{`"100-1000"`, "100-1000"},
		{`"1000-100"`, "100-1000"}, // ends are ordered
		{`"-5-5"`, "-5-5"},
		{`0`, "0"},
	}
	for _, tc := range tests {
		var v struct {
			R Int32Range `json:"r"`
		}
		if err := json.Unmarshal([]byte(`{"r":`+tc.in+`}`), &v); err != nil {
			t.Fatalf("Unmarshal(%s): %v", tc.in, err)
		}
		if got := v.R.String(); got != tc.want {
			t.Errorf("Int32Range(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}

	var unset struct {
		R Int32Range `json:"r"`
	}
	if err := json.Unmarshal([]byte(`{}`), &unset); err != nil {
		t.Fatal(err)
	}
	if got := unset.R.String(); got != "" {
		t.Errorf("an unset range renders as %q, want the empty string", got)
	}
}

func TestParseConfigsAcceptsEveryInputShape(t *testing.T) {
	const outbound = `{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}`

	tests := []struct {
		name string
		in   string
	}{
		{"array of configs", `[{"outbounds":[` + outbound + `]}]`},
		{"single config", `{"outbounds":[` + outbound + `]}`},
		{"array of outbounds", `[` + outbound + `]`},
		{"single outbound", outbound},
		{"config with a singular outbound key", `{"outbound":` + outbound + `}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configs, err := ParseConfigs([]byte(tc.in))
			if err != nil {
				t.Fatalf("ParseConfigs: %v", err)
			}
			total := 0
			for _, c := range configs {
				total += len(c.Outbounds)
			}
			if total != 1 {
				t.Fatalf("expected 1 outbound, got %d", total)
			}
		})
	}
}

func TestParseConfigsRejectsEmptyInput(t *testing.T) {
	if _, err := ParseConfigs([]byte("   \n")); err == nil {
		t.Fatal("expected an error for empty input")
	}
}

func TestParseConfigsUnwrapsBase64(t *testing.T) {
	const plain = `[{"remarks":"node","outbounds":[{"protocol":"vless","settings":{"vnext":[{
		"address":"a.example.com","port":443,
		"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}]}]`

	// Subscription endpoints commonly return the body base64-encoded, in any
	// of the four alphabets and sometimes wrapped across lines.
	encodings := map[string]func([]byte) string{
		"standard":     base64.StdEncoding.EncodeToString,
		"raw standard": base64.RawStdEncoding.EncodeToString,
		"url":          base64.URLEncoding.EncodeToString,
		"raw url":      base64.RawURLEncoding.EncodeToString,
	}
	for name, encode := range encodings {
		t.Run(name, func(t *testing.T) {
			configs, err := ParseConfigs([]byte(encode([]byte(plain))))
			if err != nil {
				t.Fatalf("ParseConfigs: %v", err)
			}
			if len(configs) != 1 || configs[0].Label() != "node" {
				t.Fatalf("unexpected result: %+v", configs)
			}
		})
	}

	t.Run("wrapped across lines", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(plain))
		var wrapped strings.Builder
		for i := 0; i < len(encoded); i += 64 {
			end := i + 64
			if end > len(encoded) {
				end = len(encoded)
			}
			wrapped.WriteString(encoded[i:end])
			wrapped.WriteByte('\n')
		}
		configs, err := ParseConfigs([]byte(wrapped.String()))
		if err != nil {
			t.Fatalf("ParseConfigs: %v", err)
		}
		if len(configs) != 1 {
			t.Fatalf("expected 1 config, got %d", len(configs))
		}
	})
}

func TestParseConfigsReportsBrokenInputAsItself(t *testing.T) {
	// Base64 unwrapping must not swallow the real error for a broken file.
	_, err := ParseConfigs([]byte("this is not a configuration at all"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(strings.ToLower(err.Error()), "base64") {
		t.Errorf("the error should describe the input, not base64: %v", err)
	}
}

func TestLabelPrefersRemarks(t *testing.T) {
	cfg := &Config{Remarks: "first", Name: "second", PS: "third"}
	if got := cfg.Label(); got != "first" {
		t.Errorf("Label() = %q, want \"first\"", got)
	}
	cfg = &Config{PS: "only"}
	if got := cfg.Label(); got != "only" {
		t.Errorf("Label() = %q, want \"only\"", got)
	}
}

func TestNetworkNameNormalisation(t *testing.T) {
	tests := map[string]string{
		"":            "tcp",
		"tcp":         "tcp",
		"raw":         "tcp",
		"websocket":   "ws",
		"ws":          "ws",
		"splithttp":   "xhttp",
		"xhttp":       "xhttp",
		"mkcp":        "kcp",
		"gun":         "grpc",
		"grpc":        "grpc",
		"http":        "h2", // Xray's "http" is the HTTP/2 transport
		"h2":          "h2",
		"httpupgrade": "httpupgrade",
	}
	for in, want := range tests {
		ss := &StreamSettings{Network: String(in)}
		if got := ss.NetworkName(); got != want {
			t.Errorf("NetworkName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestXHTTPExtraReplacesRatherThanMerges(t *testing.T) {
	var cfg XHTTPConfig
	const raw = `{"host":"outer","path":"/outer","mode":"packet-up",
		"headers":{"X-Outer":"1"},"xPaddingBytes":"1-2",
		"extra":{"headers":{"X-Inner":"1"},"scMaxEachPostBytes":"999"}}`
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	got := cfg.Resolved()

	// host, path and mode survive; everything else comes from "extra".
	if string(got.Host) != "outer" || string(got.Path) != "/outer" || string(got.Mode) != "packet-up" {
		t.Errorf("host/path/mode were not preserved: %q %q %q", got.Host, got.Path, got.Mode)
	}
	if _, ok := got.Headers["X-Outer"]; ok {
		t.Error("outer headers should have been replaced")
	}
	if _, ok := got.Headers["X-Inner"]; !ok {
		t.Error("headers from \"extra\" are missing")
	}
	if got.XPaddingBytes.Set {
		t.Error("xPaddingBytes from outside \"extra\" should have been replaced")
	}
	if got.ScMaxEachPostBytes.String() != "999" {
		t.Errorf("scMaxEachPostBytes = %q, want \"999\"", got.ScMaxEachPostBytes.String())
	}
}

func TestRealityAccessorsFallBack(t *testing.T) {
	r := &RealityConfig{ServerNames: StringList{"a.example.com"}, ShortIds: StringList{"aabb"},
		Password: "pw-as-public-key"}
	if got := r.SNI(); got != "a.example.com" {
		t.Errorf("SNI() = %q", got)
	}
	if got := r.ShortIDValue(); got != "aabb" {
		t.Errorf("ShortIDValue() = %q", got)
	}
	// Newer Xray builds call the client-side public key "password".
	if got := r.PublicKeyValue(); got != "pw-as-public-key" {
		t.Errorf("PublicKeyValue() = %q", got)
	}
}
