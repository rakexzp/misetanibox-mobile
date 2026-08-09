// Package yamlx implements a small, dependency-free YAML emitter that
// preserves key insertion order.
//
// Mihomo reads its configuration with gopkg.in/yaml.v3, so the output here
// only needs to cover the subset of YAML that a proxy configuration uses:
// ordered mappings, sequences, and scalars. Keeping our own emitter means the
// converter builds with nothing but the Go standard library, and it lets us
// control key ordering so the generated file reads the way a hand-written
// mihomo config does.
package yamlx

import (
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// Map is an ordered mapping. The zero value is ready to use.
type Map struct {
	keys []string
	vals []any
}

// NewMap returns an empty ordered mapping.
func NewMap() *Map { return &Map{} }

// Set appends key with the given value. A nil value is ignored, which lets
// callers chain optional fields without guarding every one of them.
//
// Setting a key that already exists overwrites it in place, keeping its
// original position.
func (m *Map) Set(key string, val any) *Map {
	if val == nil {
		return m
	}
	// Empty containers carry no information in a proxy config; drop them so we
	// do not emit "ws-opts: {}" style noise.
	switch v := val.(type) {
	case *Map:
		if v == nil || len(v.keys) == 0 {
			return m
		}
	case Seq:
		if len(v) == 0 {
			return m
		}
	case FlowSeq:
		if len(v) == 0 {
			return m
		}
	}
	for i, k := range m.keys {
		if k == key {
			m.vals[i] = val
			return m
		}
	}
	m.keys = append(m.keys, key)
	m.vals = append(m.vals, val)
	return m
}

// SetStr sets key unless the value is empty.
func (m *Map) SetStr(key, val string) *Map {
	if val == "" {
		return m
	}
	return m.Set(key, val)
}

// SetInt sets key unless the value is zero.
func (m *Map) SetInt(key string, val int) *Map {
	if val == 0 {
		return m
	}
	return m.Set(key, val)
}

// SetBoolTrue sets key only when val is true, mirroring the "omitempty"
// behaviour of mihomo's own option structs.
func (m *Map) SetBoolTrue(key string, val bool) *Map {
	if !val {
		return m
	}
	return m.Set(key, true)
}

// Get returns the value stored for key, if any.
func (m *Map) Get(key string) (any, bool) {
	for i, k := range m.keys {
		if k == key {
			return m.vals[i], true
		}
	}
	return nil, false
}

// Has reports whether key is present.
func (m *Map) Has(key string) bool {
	_, ok := m.Get(key)
	return ok
}

// Len returns the number of entries.
func (m *Map) Len() int { return len(m.keys) }

// Keys returns the keys in insertion order.
func (m *Map) Keys() []string { return append([]string(nil), m.keys...) }

// Seq is a sequence rendered in block style, one item per line.
type Seq []any

// FlowSeq is a sequence rendered inline as [a, b, c]. It is meant for short
// scalar lists such as alpn, where block style would be needlessly verbose.
type FlowSeq []any

// Raw is a scalar emitted verbatim, without quoting. Use it only for values
// that are known to be valid YAML scalars.
type Raw string

// Commented wraps a sequence item with a comment written above it. It is only
// honoured for items of a Seq, which is where the emitter has a whole line to
// itself to put the comment on.
type Commented struct {
	Comment string
	Value   any
}

// Encode writes v to w as a YAML document.
func Encode(w io.Writer, v any) error {
	var sb strings.Builder
	if err := encodeValue(&sb, v, 0, false); err != nil {
		return err
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// EncodeToString renders v as a YAML document.
func EncodeToString(v any) (string, error) {
	var sb strings.Builder
	if err := encodeValue(&sb, v, 0, false); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func indentOf(n int) string { return strings.Repeat(" ", n) }

// encodeValue writes v at the given indent level. When inline is true the
// caller has already written the indentation (and possibly a "- " or "key: "
// prefix) for the first line of v.
func encodeValue(sb *strings.Builder, v any, indent int, inline bool) error {
	switch val := v.(type) {
	case *Map:
		return encodeMap(sb, val, indent, inline)
	case Seq:
		return encodeSeq(sb, val, indent, inline)
	case FlowSeq:
		if !inline {
			sb.WriteString(indentOf(indent))
		}
		s, err := encodeFlowSeq(val)
		if err != nil {
			return err
		}
		sb.WriteString(s)
		sb.WriteByte('\n')
		return nil
	default:
		s, err := scalarString(v)
		if err != nil {
			return err
		}
		if !inline {
			sb.WriteString(indentOf(indent))
		}
		sb.WriteString(s)
		sb.WriteByte('\n')
		return nil
	}
}

func encodeMap(sb *strings.Builder, m *Map, indent int, inline bool) error {
	if m == nil || len(m.keys) == 0 {
		if !inline {
			sb.WriteString(indentOf(indent))
		}
		sb.WriteString("{}\n")
		return nil
	}
	for i, k := range m.keys {
		if i > 0 || !inline {
			sb.WriteString(indentOf(indent))
		}
		sb.WriteString(quoteKey(k))
		sb.WriteByte(':')

		switch child := m.vals[i].(type) {
		case *Map:
			if child == nil || len(child.keys) == 0 {
				sb.WriteString(" {}\n")
				continue
			}
			sb.WriteByte('\n')
			if err := encodeMap(sb, child, indent+2, false); err != nil {
				return err
			}
		case Seq:
			if len(child) == 0 {
				sb.WriteString(" []\n")
				continue
			}
			sb.WriteByte('\n')
			if err := encodeSeq(sb, child, indent+2, false); err != nil {
				return err
			}
		case FlowSeq:
			s, err := encodeFlowSeq(child)
			if err != nil {
				return err
			}
			sb.WriteByte(' ')
			sb.WriteString(s)
			sb.WriteByte('\n')
		default:
			s, err := scalarString(child)
			if err != nil {
				return err
			}
			sb.WriteByte(' ')
			sb.WriteString(s)
			sb.WriteByte('\n')
		}
	}
	return nil
}

func encodeSeq(sb *strings.Builder, s Seq, indent int, inline bool) error {
	for i, item := range s {
		if c, ok := item.(Commented); ok {
			// The comment needs a line of its own, so an inline first item has
			// to give up its position on the parent's line.
			if i > 0 || !inline {
				sb.WriteString(indentOf(indent))
			}
			writeComment(sb, c.Comment, indent)
			sb.WriteString(indentOf(indent))
			sb.WriteString("- ")
			if err := encodeValue(sb, c.Value, indent+2, true); err != nil {
				return err
			}
			continue
		}
		if i > 0 || !inline {
			sb.WriteString(indentOf(indent))
		}
		sb.WriteString("- ")
		// Nested collections continue on the same line, indented two further
		// columns so the "- " acts as the first two spaces of that indent.
		if err := encodeValue(sb, item, indent+2, true); err != nil {
			return err
		}
	}
	return nil
}

// writeComment emits a comment, one line per line of text. The caller has
// already written the indentation of the first line.
func writeComment(sb *strings.Builder, comment string, indent int) {
	lines := strings.Split(comment, "\n")
	for i, line := range lines {
		if i > 0 {
			sb.WriteString(indentOf(indent))
		}
		sb.WriteString("# ")
		sb.WriteString(strings.TrimRight(line, " \t"))
		sb.WriteByte('\n')
	}
}

func encodeFlowSeq(s FlowSeq) (string, error) {
	parts := make([]string, 0, len(s))
	for _, item := range s {
		switch item.(type) {
		case *Map, Seq, FlowSeq:
			return "", fmt.Errorf("yamlx: FlowSeq only supports scalar items, got %T", item)
		}
		str, err := scalarString(item)
		if err != nil {
			return "", err
		}
		parts = append(parts, str)
	}
	return "[" + strings.Join(parts, ", ") + "]", nil
}

func scalarString(v any) (string, error) {
	switch val := v.(type) {
	case nil:
		return "null", nil
	case Raw:
		return string(val), nil
	case string:
		return quoteString(val), nil
	case bool:
		return strconv.FormatBool(val), nil
	case int:
		return strconv.Itoa(val), nil
	case int8:
		return strconv.FormatInt(int64(val), 10), nil
	case int16:
		return strconv.FormatInt(int64(val), 10), nil
	case int32:
		return strconv.FormatInt(int64(val), 10), nil
	case int64:
		return strconv.FormatInt(val, 10), nil
	case uint:
		return strconv.FormatUint(uint64(val), 10), nil
	case uint8:
		return strconv.FormatUint(uint64(val), 10), nil
	case uint16:
		return strconv.FormatUint(uint64(val), 10), nil
	case uint32:
		return strconv.FormatUint(uint64(val), 10), nil
	case uint64:
		return strconv.FormatUint(val, 10), nil
	case float32:
		return formatFloat(float64(val)), nil
	case float64:
		return formatFloat(val), nil
	default:
		return "", fmt.Errorf("yamlx: unsupported scalar type %T", v)
	}
}

func formatFloat(f float64) string {
	if math.IsInf(f, 1) {
		return ".inf"
	}
	if math.IsInf(f, -1) {
		return "-.inf"
	}
	if math.IsNaN(f) {
		return ".nan"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func quoteKey(k string) string { return quoteString(k) }

// quoteString renders s as a YAML scalar, using a plain scalar when that is
// unambiguous and quoting otherwise.
func quoteString(s string) string {
	if !needsQuoting(s) {
		return s
	}
	if canSingleQuote(s) {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return doubleQuote(s)
}

// leadingIndicators are characters that start a YAML construct (sequence
// entry, mapping key, alias, tag, block scalar, flow collection, ...). A plain
// scalar may not begin with any of them.
const leadingIndicators = "-?:,[]{}#&*!|>'\"%@`"

func needsQuoting(s string) bool {
	if s == "" {
		return true
	}
	if strings.ContainsAny(s, "\x00\r\n\t") {
		return true
	}
	for _, r := range s {
		// Control characters and DEL cannot appear in a plain scalar.
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	if strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ") {
		return true
	}
	if strings.ContainsRune(leadingIndicators, rune(s[0])) {
		return true
	}
	// ": " ends a key, " #" starts a comment, and a trailing ":" reads as a key.
	if strings.Contains(s, ": ") || strings.Contains(s, " #") || strings.HasSuffix(s, ":") {
		return true
	}
	// Anything a YAML resolver would turn into a non-string type has to be
	// quoted to survive the round trip as a string.
	return looksLikeNonString(s)
}

// nonStringWords are scalars that YAML 1.1 and/or 1.2 implementations resolve
// to booleans or null. yaml.v3 only treats a subset of these as booleans, but
// quoting all of them costs nothing and keeps the output portable across the
// YAML parsers that different mihomo forks and editors use.
var nonStringWords = map[string]bool{
	"true": true, "false": true, "yes": true, "no": true,
	"on": true, "off": true, "y": true, "n": true,
	"null": true, "~": true, "nil": true,
}

func looksLikeNonString(s string) bool {
	if nonStringWords[strings.ToLower(s)] {
		return true
	}
	lower := strings.ToLower(s)
	if lower == ".inf" || lower == "-.inf" || lower == "+.inf" || lower == ".nan" {
		return true
	}
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		return true
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return true
	}
	// Alternative integer bases understood by YAML resolvers, e.g. "0x1f"
	// resolves to 31 rather than to the string.
	if len(s) > 2 {
		switch {
		case strings.HasPrefix(lower, "0x"), strings.HasPrefix(lower, "0o"), strings.HasPrefix(lower, "0b"):
			if _, err := strconv.ParseInt(s, 0, 64); err == nil {
				return true
			}
		}
	}
	// YAML 1.1 sexagesimals, e.g. "1:30" or "12:34:56".
	if strings.Contains(s, ":") && isSexagesimal(s) {
		return true
	}
	return false
}

func isSexagesimal(s string) bool {
	parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(s, "-"), "+"), ":")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func canSingleQuote(s string) bool {
	// Single-quoted scalars cannot carry escapes, so any character that must be
	// escaped forces double quotes.
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func doubleQuote(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		case 0:
			sb.WriteString(`\0`)
		default:
			if r < 0x20 || r == 0x7f {
				sb.WriteString(fmt.Sprintf(`\x%02x`, r))
				continue
			}
			sb.WriteRune(r)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}
