package yamlx

import (
	"strings"
	"testing"
)

func TestQuoteString(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain word", "vless", "vless"},
		{"hostname", "example.com", "example.com"},
		{"path", "/websocket", "/websocket"},
		{"uuid", "b831381d-6324-4d53-ad4f-8cda48b30811", "b831381d-6324-4d53-ad4f-8cda48b30811"},
		{"range", "100-1000", "100-1000"},
		{"base64 padding", "OTk4NTY0MzIxMDk4NzY1NA==", "OTk4NTY0MzIxMDk4NzY1NA=="},
		{"unicode name", "香港 01 · Premium", "香港 01 · Premium"},
		{"bandwidth", "50 Mbps", "50 Mbps"},

		// Values a YAML resolver would turn into something other than a string.
		{"empty", "", "''"},
		{"integer", "443", "'443'"},
		{"float", "1.5", "'1.5'"},
		{"true", "true", "'true'"},
		{"yes", "yes", "'yes'"},
		{"off", "off", "'off'"},
		{"null word", "null", "'null'"},
		{"tilde", "~", "'~'"},
		{"hex", "0x1f", "'0x1f'"},
		{"sexagesimal", "1:30", "'1:30'"},

		// Values that would change the document structure.
		{"leading dash", "-node", "'-node'"},
		{"leading brace", "{a}", "'{a}'"},
		{"leading hash", "#comment", "'#comment'"},
		{"leading star", "*anchor", "'*anchor'"},
		{"colon space", "key: value", "'key: value'"},
		{"space hash", "node # 1", "'node # 1'"},
		{"trailing colon", "name:", "'name:'"},
		{"leading space", " pad", "' pad'"},
		{"trailing space", "pad ", "'pad '"},
		{"ipv6 cidr", "::/0", "'::/0'"},
		// An apostrophe only starts a quoted scalar at the beginning.
		{"inner apostrophe", "it's", "it's"},
		{"leading apostrophe", "'quoted'", "'''quoted'''"},

		// Characters that force double quotes.
		{"newline", "a\nb", `"a\nb"`},
		{"tab", "a\tb", `"a\tb"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := quoteString(tc.in); got != tc.want {
				t.Errorf("quoteString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestEncodeNestedStructure(t *testing.T) {
	inner := NewMap()
	inner.Set("path", "/reliable")
	inner.Set("mode", "packet-up")

	proxy := NewMap()
	proxy.Set("name", "node")
	proxy.Set("port", 443)
	proxy.Set("tls", true)
	proxy.Set("alpn", FlowSeq{"h2", "http/1.1"})
	proxy.Set("xhttp-opts", inner)

	got, err := EncodeToString(Seq{proxy})
	if err != nil {
		t.Fatalf("EncodeToString: %v", err)
	}

	want := strings.Join([]string{
		"- name: node",
		"  port: 443",
		"  tls: true",
		"  alpn: [h2, http/1.1]",
		"  xhttp-opts:",
		"    path: /reliable",
		"    mode: packet-up",
		"",
	}, "\n")

	if got != want {
		t.Errorf("EncodeToString mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestMapSetSkipsEmptyValues(t *testing.T) {
	m := NewMap()
	m.Set("kept", "value")
	m.Set("nil-value", nil)
	m.SetStr("empty-string", "")
	m.SetInt("zero", 0)
	m.SetBoolTrue("false-flag", false)
	m.Set("empty-map", NewMap())
	m.Set("empty-seq", Seq{})

	if m.Len() != 1 {
		t.Fatalf("expected only the non-empty entry, got keys %v", m.Keys())
	}
	if v, _ := m.Get("kept"); v != "value" {
		t.Errorf("kept = %v, want \"value\"", v)
	}
}

func TestMapSetOverwritesInPlace(t *testing.T) {
	m := NewMap()
	m.Set("a", 1)
	m.Set("b", 2)
	m.Set("a", 3)

	keys := m.Keys()
	if len(keys) != 2 || keys[0] != "a" || keys[1] != "b" {
		t.Fatalf("key order changed after overwrite: %v", keys)
	}
	if v, _ := m.Get("a"); v != 3 {
		t.Errorf("a = %v, want 3", v)
	}
}

func TestEncodeSequenceOfSequences(t *testing.T) {
	got, err := EncodeToString(Seq{Seq{"a", "b"}})
	if err != nil {
		t.Fatalf("EncodeToString: %v", err)
	}
	want := "- - a\n  - b\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFlowSeqRejectsCollections(t *testing.T) {
	if _, err := EncodeToString(FlowSeq{NewMap()}); err == nil {
		t.Fatal("expected an error for a collection inside a FlowSeq")
	}
}

func TestCommentedSequenceItem(t *testing.T) {
	inner := NewMap()
	inner.Set("name", "Germany")
	inner.Set("type", "url-test")

	got, err := EncodeToString(Seq{
		Commented{Comment: `Xray balancer "balancer", strategy leastPing`, Value: inner},
		"plain",
	})
	if err != nil {
		t.Fatalf("EncodeToString: %v", err)
	}

	want := strings.Join([]string{
		`# Xray balancer "balancer", strategy leastPing`,
		"- name: Germany",
		"  type: url-test",
		"- plain",
		"",
	}, "\n")
	if got != want {
		t.Errorf("mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestCommentedItemIndentsWithTheSequence(t *testing.T) {
	m := NewMap()
	m.Set("groups", Seq{Commented{Comment: "note", Value: "value"}})

	got, err := EncodeToString(m)
	if err != nil {
		t.Fatalf("EncodeToString: %v", err)
	}
	want := "groups:\n  # note\n  - value\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMultiLineCommentGetsAHashPerLine(t *testing.T) {
	got, err := EncodeToString(Seq{Commented{Comment: "first\nsecond", Value: "v"}})
	if err != nil {
		t.Fatal(err)
	}
	if got != "# first\n# second\n- v\n" {
		t.Errorf("got %q", got)
	}
}
