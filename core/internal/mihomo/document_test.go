package mihomo

import (
	"strings"
	"testing"

	"misetanibox/mobilecore/internal/yamlx"
)

func sampleProxies() ([]*yamlx.Map, []string) {
	a := yamlx.NewMap()
	a.Set("name", "Node A")
	a.Set("type", "vless")
	b := yamlx.NewMap()
	b.Set("name", "Node B")
	b.Set("type", "trojan")
	return []*yamlx.Map{a, b}, []string{"Node A", "Node B"}
}

func TestBuildFullDocument(t *testing.T) {
	proxies, names := sampleProxies()
	doc := Build(proxies, nil, names, DefaultDocumentOptions())

	for _, key := range []string{"mixed-port", "mode", "dns", "proxies", "proxy-groups", "rules"} {
		if !doc.Has(key) {
			t.Errorf("the document is missing %q", key)
		}
	}

	out, err := yamlx.EncodeToString(doc)
	if err != nil {
		t.Fatalf("EncodeToString: %v", err)
	}
	for _, want := range []string{"Node A", "Node B", "MATCH,PROXY", "url-test"} {
		if !strings.Contains(out, want) {
			t.Errorf("the document does not contain %q", want)
		}
	}
}

func TestBuildProxiesOnlyOmitsEverythingElse(t *testing.T) {
	proxies, names := sampleProxies()
	opts := DefaultDocumentOptions()
	opts.ProxiesOnly = true
	doc := Build(proxies, nil, names, opts)

	if doc.Len() != 1 || !doc.Has("proxies") {
		t.Errorf("a provider file must hold only \"proxies\", got %v", doc.Keys())
	}
}

func TestGroupsWithoutProxiesFallBackToDirect(t *testing.T) {
	// A group with no members makes mihomo refuse to start.
	doc := Build(nil, nil, nil, DefaultDocumentOptions())
	out, err := yamlx.EncodeToString(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "DIRECT") {
		t.Error("expected the empty group to fall back to DIRECT")
	}
}

func TestCustomGroupNamesReachTheRules(t *testing.T) {
	proxies, names := sampleProxies()
	opts := DefaultDocumentOptions()
	opts.SelectGroup = "选择"
	opts.AutoGroup = "自动"
	doc := Build(proxies, nil, names, opts)

	out, err := yamlx.EncodeToString(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "MATCH,选择") {
		t.Error("the final rule does not point at the renamed select group")
	}
	if !strings.Contains(out, "自动") {
		t.Error("the renamed url-test group is missing")
	}
}

func TestRenderTemplateSubstitutesPlaceholders(t *testing.T) {
	proxies, names := sampleProxies()
	const template = `mixed-port: 7890
proxies:
  #{{proxies}}
proxy-groups:
  - name: MyGroup
    type: select
    proxies:
      #{{proxy-names}}
rules:
  - MATCH,MyGroup`

	out, err := RenderTemplate(template, proxies, nil, names)
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}

	// The blocks must be indented to the depth of the placeholder.
	if !strings.Contains(out, "  - name: Node A") {
		t.Errorf("proxies were not indented to the placeholder depth:\n%s", out)
	}
	if !strings.Contains(out, "      - Node A") {
		t.Errorf("proxy names were not indented to the placeholder depth:\n%s", out)
	}
	if !strings.Contains(out, "mixed-port: 7890") || !strings.Contains(out, "rules:") {
		t.Error("the surrounding template was not preserved")
	}
}

func TestRenderTemplateWithoutPlaceholderFails(t *testing.T) {
	proxies, names := sampleProxies()
	if _, err := RenderTemplate("mixed-port: 7890\n", proxies, nil, names); err == nil {
		t.Fatal("expected an error when the template has no placeholder")
	}
}

func TestRenderAddsHeaderComments(t *testing.T) {
	doc := yamlx.NewMap()
	doc.Set("a", 1)
	out, err := Render(doc, []string{"line one", "line two"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "# line one\n# line two\n") {
		t.Errorf("unexpected header:\n%s", out)
	}
}

func TestBuildEmitsBalancerGroups(t *testing.T) {
	proxies, _ := sampleProxies()
	groups := []Group{{
		Name:    "Germany",
		Type:    "url-test",
		Members: []string{"Node A", "Node B"},
	}}
	// A balancer stands in for its nodes, so only the group is selectable.
	doc := Build(proxies, groups, []string{"Germany"}, DefaultDocumentOptions())

	out, err := yamlx.EncodeToString(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"- name: Germany", "type: url-test", "- Node A", "- Node B"} {
		if !strings.Contains(out, want) {
			t.Errorf("the document is missing %q:\n%s", want, out)
		}
	}
	// The generated groups select the balancer group, not its members.
	if strings.Count(out, "- Node A") != 1 {
		t.Errorf("a balanced node leaked into another group:\n%s", out)
	}
}

func TestLoadBalanceGroupCarriesItsStrategy(t *testing.T) {
	groups := []Group{{
		Name:     "Pool",
		Type:     "load-balance",
		Members:  []string{"Node A"},
		Strategy: "round-robin",
	}}
	out, err := yamlx.EncodeToString(renderGroup(groups[0], DefaultDocumentOptions()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "strategy: round-robin") {
		t.Errorf("the strategy is missing:\n%s", out)
	}
	if strings.Contains(out, "tolerance:") {
		t.Errorf("tolerance belongs to url-test only:\n%s", out)
	}
}

func TestRenderTemplateSubstitutesBalancerGroups(t *testing.T) {
	proxies, _ := sampleProxies()
	groups := []Group{{Name: "Germany", Type: "url-test", Members: []string{"Node A", "Node B"}}}
	const template = `proxies:
  #{{proxies}}
proxy-groups:
  #{{proxy-groups}}
  - name: Manual
    type: select
    proxies:
      #{{proxy-names}}`

	out, err := RenderTemplate(template, proxies, groups, []string{"Germany"})
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	if !strings.Contains(out, "  - name: Germany") {
		t.Errorf("the balancer group was not substituted:\n%s", out)
	}
	if !strings.Contains(out, "      - Germany") {
		t.Errorf("the selectable names were not substituted:\n%s", out)
	}
}
