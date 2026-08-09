// Package mihomo assembles a complete mihomo (Clash Meta) configuration
// document around a set of converted proxies.
package mihomo

import (
	"fmt"
	"strings"

	"misetanibox/mobilecore/internal/yamlx"
)

// Group is a proxy group to emit ahead of the generated ones. It is how an
// Xray balancer is represented: the nodes it balances over become the members
// of a single group, and only that group is offered for selection.
type Group struct {
	// Name is the group's name, unique among proxies and groups alike.
	Name string
	// Type is a mihomo group type: url-test, load-balance, fallback, select.
	Type string
	// Members are the proxy or group names the group chooses between.
	Members []string
	// Strategy is the load-balance strategy, if the type needs one.
	Strategy string
	// Note describes where the group came from, for a comment in the output.
	Note string
}

// DocumentOptions controls the shape of the generated configuration.
type DocumentOptions struct {
	// ProxiesOnly emits just the "proxies:" block, which is the format a
	// proxy-provider file uses.
	ProxiesOnly bool
	// MixedPort is the local HTTP/SOCKS port.
	MixedPort int
	// AllowLAN opens the local listeners to the network.
	AllowLAN bool
	// LogLevel is mihomo's log level.
	LogLevel string
	// ExternalController is the API listen address; empty disables it.
	ExternalController string
	// SelectGroup and AutoGroup name the generated proxy groups.
	SelectGroup string
	AutoGroup   string
	// TestURL is the health-check URL of the automatic group.
	TestURL string
	// TestInterval is the health-check interval in seconds.
	TestInterval int
}

// DefaultDocumentOptions returns a sensible configuration skeleton.
func DefaultDocumentOptions() DocumentOptions {
	return DocumentOptions{
		MixedPort:          7890,
		LogLevel:           "info",
		ExternalController: "127.0.0.1:9090",
		SelectGroup:        "PROXY",
		AutoGroup:          "AUTO",
		TestURL:            "https://www.gstatic.com/generate_204",
		TestInterval:       300,
	}
}

// privateRanges are the address blocks routed directly, so that local
// services keep working without depending on downloaded GeoIP data.
var privateRanges = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"224.0.0.0/4",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

// Build assembles the configuration document.
//
// names are the entries offered for selection. When a balancer produced a
// group, that group's name appears there in place of the nodes it covers, so
// the individual members stay out of the user-facing lists.
func Build(proxies []*yamlx.Map, groups []Group, names []string, opts DocumentOptions) *yamlx.Map {
	doc := yamlx.NewMap()

	if !opts.ProxiesOnly {
		doc.Set("mixed-port", opts.MixedPort)
		doc.Set("allow-lan", opts.AllowLAN)
		doc.Set("mode", "rule")
		doc.Set("log-level", orDefault(opts.LogLevel, "info"))
		doc.Set("ipv6", true)
		if opts.ExternalController != "" {
			doc.Set("external-controller", opts.ExternalController)
		}
		doc.Set("dns", buildDNS())
	}

	seq := make(yamlx.Seq, 0, len(proxies))
	for _, p := range proxies {
		seq = append(seq, p)
	}
	doc.Set("proxies", seq)

	if opts.ProxiesOnly {
		return doc
	}

	doc.Set("proxy-groups", buildGroups(groups, names, opts))
	doc.Set("rules", buildRules(opts))
	return doc
}

// renderGroup turns a balancer group into its YAML mapping.
func renderGroup(g Group, opts DocumentOptions) *yamlx.Map {
	m := yamlx.NewMap()
	m.Set("name", g.Name)
	m.Set("type", g.Type)

	switch g.Type {
	case "url-test", "fallback", "load-balance":
		m.Set("url", orDefault(opts.TestURL, "https://www.gstatic.com/generate_204"))
		m.Set("interval", orDefaultInt(opts.TestInterval, 300))
	}
	if g.Type == "url-test" {
		m.Set("tolerance", 50)
	}
	if g.Type == "load-balance" && g.Strategy != "" {
		m.Set("strategy", g.Strategy)
	}

	members := make(yamlx.Seq, 0, len(g.Members))
	for _, n := range g.Members {
		members = append(members, n)
	}
	m.Set("proxies", members)
	return m
}

func buildDNS() *yamlx.Map {
	dns := yamlx.NewMap()
	dns.Set("enable", true)
	dns.Set("ipv6", true)
	dns.Set("enhanced-mode", "fake-ip")
	dns.Set("fake-ip-range", "198.18.0.1/16")
	dns.Set("nameserver", yamlx.FlowSeq{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"})
	return dns
}

func buildGroups(groups []Group, names []string, opts DocumentOptions) yamlx.Seq {
	selectName := orDefault(opts.SelectGroup, "PROXY")
	autoName := orDefault(opts.AutoGroup, "AUTO")

	if len(names) == 0 {
		// A group with no members makes mihomo refuse to start, so fall back
		// to the built-in DIRECT target.
		sel := yamlx.NewMap()
		sel.Set("name", selectName)
		sel.Set("type", "select")
		sel.Set("proxies", yamlx.FlowSeq{"DIRECT"})
		return yamlx.Seq{sel}
	}

	selectMembers := make(yamlx.Seq, 0, len(names)+2)
	selectMembers = append(selectMembers, autoName)
	for _, n := range names {
		selectMembers = append(selectMembers, n)
	}
	selectMembers = append(selectMembers, "DIRECT")

	sel := yamlx.NewMap()
	sel.Set("name", selectName)
	sel.Set("type", "select")
	sel.Set("proxies", selectMembers)

	autoMembers := make(yamlx.Seq, 0, len(names))
	for _, n := range names {
		autoMembers = append(autoMembers, n)
	}
	auto := yamlx.NewMap()
	auto.Set("name", autoName)
	auto.Set("type", "url-test")
	auto.Set("url", orDefault(opts.TestURL, "https://www.gstatic.com/generate_204"))
	auto.Set("interval", orDefaultInt(opts.TestInterval, 300))
	auto.Set("tolerance", 50)
	auto.Set("proxies", autoMembers)

	// The balancer groups come first: they are what the two generated groups
	// select between, and mihomo resolves references in any order.
	out := make(yamlx.Seq, 0, len(groups)+2)
	for _, g := range groups {
		rendered := renderGroup(g, opts)
		if g.Note != "" {
			// Saying where the group came from makes the file readable
			// without the Xray configuration next to it.
			out = append(out, yamlx.Commented{Comment: g.Note, Value: rendered})
			continue
		}
		out = append(out, rendered)
	}
	return append(out, sel, auto)
}

func buildRules(opts DocumentOptions) yamlx.Seq {
	selectName := orDefault(opts.SelectGroup, "PROXY")
	rules := make(yamlx.Seq, 0, len(privateRanges)+2)
	for _, cidr := range privateRanges {
		// no-resolve keeps mihomo from looking up a domain just to match a
		// local address range.
		rules = append(rules, fmt.Sprintf("IP-CIDR,%s,DIRECT,no-resolve", cidr))
	}
	rules = append(rules, "MATCH,"+selectName)
	return rules
}

// Render writes the document, prefixed by the given header comment lines.
func Render(doc *yamlx.Map, header []string) (string, error) {
	body, err := yamlx.EncodeToString(doc)
	if err != nil {
		return "", err
	}
	if len(header) == 0 {
		return body, nil
	}
	var sb strings.Builder
	for _, line := range header {
		sb.WriteString("# ")
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	sb.WriteByte('\n')
	sb.WriteString(body)
	return sb.String(), nil
}

// templatePlaceholders are the markers RenderTemplate replaces.
var templatePlaceholders = []string{"#{{proxies}}", "#{{proxy-names}}", "#{{proxy-groups}}"}

// RenderTemplate substitutes the generated blocks into a user-supplied
// template, so an existing mihomo configuration can keep its own rules.
//
// Three placeholders are recognised, each on its own line:
//
//	#{{proxies}}       the proxies list, indented to match the placeholder
//	#{{proxy-names}}   the selectable names, for use inside a group
//	#{{proxy-groups}}  the groups produced by Xray balancers
//
// The names are the selectable ones: where a balancer produced a group, that
// group stands in for the nodes it covers.
func RenderTemplate(template string, proxies []*yamlx.Map, groups []Group, names []string) (string, error) {
	var out strings.Builder
	found := false

	opts := DefaultDocumentOptions()

	for _, line := range strings.Split(template, "\n") {
		trimmed := strings.TrimSpace(line)
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]

		var seq yamlx.Seq
		switch trimmed {
		case "#{{proxies}}":
			for _, p := range proxies {
				seq = append(seq, p)
			}
		case "#{{proxy-names}}":
			for _, n := range names {
				seq = append(seq, n)
			}
		case "#{{proxy-groups}}":
			for _, g := range groups {
				seq = append(seq, renderGroup(g, opts))
			}
		default:
			out.WriteString(line)
			out.WriteByte('\n')
			continue
		}

		found = true
		if len(seq) == 0 {
			// An empty list would leave a dangling key, so drop the line.
			continue
		}
		block, err := yamlx.EncodeToString(seq)
		if err != nil {
			return "", err
		}
		out.WriteString(indentBlock(block, indent))
	}

	if !found {
		return "", fmt.Errorf("the template contains none of %s", strings.Join(templatePlaceholders, ", "))
	}
	return strings.TrimRight(out.String(), "\n") + "\n", nil
}

// indentBlock prefixes every non-empty line of block with indent.
func indentBlock(block, indent string) string {
	var sb strings.Builder
	for _, line := range strings.Split(strings.TrimRight(block, "\n"), "\n") {
		if line == "" {
			sb.WriteByte('\n')
			continue
		}
		sb.WriteString(indent)
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func orDefaultInt(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}
