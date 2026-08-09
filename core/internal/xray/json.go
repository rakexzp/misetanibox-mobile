package xray

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// StripJSONC removes // and /* */ comments and trailing commas from data.
//
// Xray accepts commented JSON, and hand-maintained configs use it heavily, so
// the converter has to as well. Comment characters inside string literals are
// left alone.
func StripJSONC(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false

	for i := 0; i < len(data); i++ {
		c := data[i]

		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}

		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			// Keep the newline so line numbers in error messages stay usable.
			if i < len(data) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				if data[i] == '\n' {
					out = append(out, '\n')
				}
				i++
			}
			i++ // land on '/', the loop increment moves past it
		default:
			out = append(out, c)
		}
	}
	return stripTrailingCommas(out)
}

// stripTrailingCommas removes commas that directly precede a closing brace or
// bracket, which JSON rejects but hand-written configs often contain.
func stripTrailingCommas(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false

	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue // drop the comma
			}
		}
		out = append(out, c)
	}
	return out
}

// unwrapBase64 decodes a body that a subscription endpoint returned as
// base64, which several panels do. It only replaces the input when the decoded
// bytes are themselves JSON, so a genuinely broken file still produces an
// error about the file rather than about base64.
func unwrapBase64(data []byte) []byte {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{") {
		return data
	}
	// Subscription payloads are often wrapped, so ignore any line breaks.
	compact := strings.NewReplacer("\n", "", "\r", "", " ", "\t").Replace(trimmed)
	compact = strings.ReplaceAll(compact, "\t", "")

	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		decoded, err := enc.DecodeString(compact)
		if err != nil {
			continue
		}
		head := strings.TrimSpace(string(decoded))
		if strings.HasPrefix(head, "[") || strings.HasPrefix(head, "{") {
			return decoded
		}
	}
	return data
}

// String is a string that also accepts numbers and booleans, so a config
// written as {"port": 443} or {"port": "443"} parses either way.
type String string

func (s *String) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		*s = ""
		return nil
	}
	if data[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		*s = String(str)
		return nil
	}
	*s = String(strings.Trim(string(data), `"`))
	return nil
}

func (s String) String() string { return string(s) }

// Int is an integer that also accepts a quoted number or a float, covering
// generators that stringify every value.
type Int int64

func (i *Int) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		*i = 0
		return nil
	}
	s := strings.Trim(string(data), `"`)
	if s == "" {
		*i = 0
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		*i = Int(n)
		return nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		*i = Int(int64(f))
		return nil
	}
	return fmt.Errorf("cannot parse %q as an integer", s)
}

func (i Int) Int() int { return int(i) }

// Bool is a boolean that also accepts "true"/"false" strings and 0/1.
type Bool bool

func (b *Bool) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		*b = false
		return nil
	}
	s := strings.ToLower(strings.Trim(string(data), `"`))
	switch s {
	case "true", "1", "yes", "on":
		*b = true
	case "false", "0", "no", "off", "":
		*b = false
	default:
		return fmt.Errorf("cannot parse %q as a boolean", s)
	}
	return nil
}

func (b Bool) Bool() bool { return bool(b) }

// StringList accepts either a JSON array of strings or a single
// comma-separated string, matching Xray's own StringList type.
type StringList []string

func (l *StringList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		*l = nil
		return nil
	}
	if data[0] == '[' {
		var arr []String
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		out := make(StringList, 0, len(arr))
		for _, s := range arr {
			if v := strings.TrimSpace(string(s)); v != "" {
				out = append(out, v)
			}
		}
		*l = out
		return nil
	}
	var s String
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	out := StringList{}
	for _, part := range strings.Split(string(s), ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	*l = out
	return nil
}

// Int32Range mirrors Xray's Int32Range: it deserialises from a plain number or
// from a "from-to" string. Mihomo takes the same information as a string, so
// String renders it back in the form mihomo expects.
type Int32Range struct {
	From int32
	To   int32
	Set  bool
}

func (r *Int32Range) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	s := strings.TrimSpace(strings.Trim(string(data), `"`))
	if s == "" {
		return nil
	}
	from, to, err := parseRangeString(s)
	if err != nil {
		return err
	}
	r.From, r.To, r.Set = int32(from), int32(to), true
	return nil
}

// String renders the range the way mihomo's xhttp options expect: a bare
// number when both ends match, "from-to" otherwise. An unset range renders as
// the empty string so callers can skip it.
func (r Int32Range) String() string {
	if !r.Set {
		return ""
	}
	if r.From == r.To {
		return strconv.Itoa(int(r.From))
	}
	return strconv.Itoa(int(r.From)) + "-" + strconv.Itoa(int(r.To))
}

// parseRangeString handles "114", "114-514" and negative bounds such as
// "-114-514", following Xray's parsing rules.
func parseRangeString(s string) (int, int, error) {
	if v, err := strconv.Atoi(s); err == nil {
		return v, v, nil
	}
	parts := splitFromSecondDash(s)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid range %q", s)
	}
	from, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid range %q", s)
	}
	to, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid range %q", s)
	}
	if from > to {
		from, to = to, from
	}
	return from, to, nil
}

// splitFromSecondDash splits "-114-514" into ["-114", "514"] so that negative
// lower bounds are not mistaken for a separator.
func splitFromSecondDash(s string) []string {
	parts := strings.SplitN(s, "-", 3)
	switch len(parts) {
	case 2:
		return []string{parts[0], parts[1]}
	case 3:
		if parts[0] == "" {
			// Leading '-' belongs to the first number.
			return []string{"-" + parts[1], parts[2]}
		}
		return []string{parts[0], parts[1] + "-" + parts[2]}
	default:
		return []string{s}
	}
}

// RawObject keeps the original JSON of a value so that alternative spellings
// can be probed without committing to one schema up front.
type RawObject = json.RawMessage

// hasKey reports whether raw is a JSON object containing key.
func hasKey(raw json.RawMessage, key string) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	_, ok := probe[key]
	return ok
}

// PortList accepts Xray's port list in any of its spellings: a single number,
// a "1000-2000" range, a comma-separated list of either, or a JSON array of
// those. It keeps the textual form, which is what mihomo's "ports" takes.
type PortList string

func (l *PortList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		*l = ""
		return nil
	}
	if data[0] == '[' {
		var items []String
		if err := json.Unmarshal(data, &items); err != nil {
			return err
		}
		parts := make([]string, 0, len(items))
		for _, item := range items {
			if v := strings.TrimSpace(string(item)); v != "" {
				parts = append(parts, v)
			}
		}
		*l = PortList(strings.Join(parts, ","))
		return nil
	}
	var s String
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*l = PortList(strings.TrimSpace(string(s)))
	return nil
}

func (l PortList) String() string { return string(l) }
