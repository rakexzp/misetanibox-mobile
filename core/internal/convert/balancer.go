package convert

import (
	"fmt"
	"sort"
	"strings"

	"misetanibox/mobilecore/internal/mihomo"
	"misetanibox/mobilecore/internal/xray"
)

// Xray's client-side load balancer spreads traffic over several outbounds and
// presents them as one routing target. Emitting those outbounds as separate
// nodes would throw that away and leave the user picking between servers the
// configuration never meant them to see individually.
//
// mihomo expresses the same idea as a proxy group: the balanced nodes become
// its members, and only the group is offered for selection.

// balancerGroupTypes are the mihomo group types a balancer may be mapped to.
var balancerGroupTypes = map[string]bool{
	"url-test": true, "load-balance": true, "fallback": true, "select": true,
}

// buildBalancers turns one configuration's balancers into proxy groups.
//
// tagNames maps an outbound tag to the proxy names it produced; it is built
// while the outbounds are converted. The returned set holds every proxy name
// that a balancer claimed, so the caller can keep those out of the top-level
// lists.
func (c *converter) buildBalancers(cfg *xray.Config, ci int, tagNames map[string][]string) map[string]bool {
	balancers := cfg.Balancers()
	if len(balancers) == 0 {
		return nil
	}

	claimed := map[string]bool{}
	label := cfg.Label()
	routed, hasRules := routedBalancerTags(cfg)

	for bi, b := range balancers {
		tag := strings.TrimSpace(string(b.Tag))
		c.src = fmt.Sprintf("config[%d].routing.balancers[%d] (%s)", ci, bi, tag)

		members := c.balancerMembers(b, tagNames)
		if len(members) == 0 {
			c.warn("the balancer %q selected no node that could be converted; it was dropped", tag)
			continue
		}

		name := c.groupName(b, label, len(balancers))
		groupType := c.groupTypeFor(b)

		group := mihomo.Group{
			Name:    name,
			Type:    groupType,
			Members: members,
			Note:    fmt.Sprintf("Xray balancer %q, strategy %s", tag, b.StrategyDisplay()),
		}
		if groupType == "load-balance" {
			group.Strategy = loadBalanceStrategy(b.StrategyName())
		}

		// A balancer that no rule routes to is inert in Xray. It still becomes
		// a group here, since the nodes have to go somewhere, but saying so
		// explains why the client shows a group the panel never uses. Only a
		// configuration that carries routing rules can be judged this way.
		if hasRules && !routed[tag] {
			c.warn("no routing rule uses the balancer %q; its nodes were grouped anyway", tag)
		}

		for _, m := range members {
			claimed[m] = true
		}
		c.res.Groups = append(c.res.Groups, group)

		// A fallbackTag names the outbound Xray uses when every balanced node
		// is down. mihomo has no such field, but a "fallback" group over
		// [balancer, spare] behaves the same way: it uses the first member
		// that passes its health check.
		c.applyFallbackTag(b, tagNames, claimed)
	}
	return claimed
}

// balancerMembers resolves the proxy names a balancer covers.
func (c *converter) balancerMembers(b *xray.BalancingRule, tagNames map[string][]string) []string {
	// Xray sorts the selected tags, so the member order is reproducible.
	tags := make([]string, 0, len(tagNames))
	for tag := range tagNames {
		if b.Selects(tag) {
			tags = append(tags, tag)
		}
	}
	sort.Strings(tags)

	var members []string
	for _, tag := range tags {
		members = append(members, tagNames[tag]...)
	}
	return members
}

// applyFallbackTag wraps the balancer group in a fallback group when the
// balancer names a spare outbound.
func (c *converter) applyFallbackTag(b *xray.BalancingRule, tagNames map[string][]string, claimed map[string]bool) {
	fallbackTag := strings.TrimSpace(string(b.FallbackTag))
	if fallbackTag == "" {
		return
	}
	spares := tagNames[fallbackTag]
	if len(spares) == 0 {
		c.warn("fallbackTag %q does not name a converted outbound; it was dropped", fallbackTag)
		return
	}

	// The balancer group was just appended, so it is the last one.
	inner := &c.res.Groups[len(c.res.Groups)-1]
	outerName := inner.Name
	// The two groups need distinct names; the outer one keeps the plain name
	// because that is what the user selects.
	inner.Name = c.uniqueName(outerName + " pool")

	outer := mihomo.Group{
		Name:    outerName,
		Type:    "fallback",
		Members: append([]string{inner.Name}, spares...),
		Note:    fmt.Sprintf("Xray balancer fallbackTag %q", fallbackTag),
	}
	c.res.Groups = append(c.res.Groups, outer)

	// The spare is reachable through the group, so it does not need its own
	// entry in the top-level lists either.
	for _, s := range spares {
		claimed[s] = true
	}
}

// groupName picks a name for the balancer's group.
//
// The name comes from the label of the configuration the balancer lives in --
// its "remarks" -- because that is what describes the location to a person.
// A balancer tag is an internal routing name such as "balancer" and says
// nothing useful, so it is only used when the configuration carries no label
// at all.
func (c *converter) groupName(b *xray.BalancingRule, label string, balancerCount int) string {
	tag := strings.TrimSpace(string(b.Tag))

	candidate := label
	switch {
	case candidate == "":
		candidate = tag
	case balancerCount > 1:
		// Several balancers share one label, so the tag tells them apart
		// while the label still leads the name.
		candidate = fmt.Sprintf("%s (%s)", label, tag)
	}

	if c.opts.NamePrefix != "" {
		candidate = c.opts.NamePrefix + candidate
	}
	return c.uniqueName(sanitizeName(candidate))
}

// uniqueName reserves a name against everything already handed out, because
// mihomo needs proxies and groups to be distinct from one another.
func (c *converter) uniqueName(candidate string) string {
	if n, seen := c.used[candidate]; seen {
		for {
			n++
			next := fmt.Sprintf("%s #%d", candidate, n)
			if _, taken := c.used[next]; !taken {
				c.used[candidate] = n
				c.used[next] = 1
				return next
			}
		}
	}
	c.used[candidate] = 1
	return candidate
}

// groupTypeFor decides which mihomo group type stands in for the balancer.
func (c *converter) groupTypeFor(b *xray.BalancingRule) string {
	requested := strings.ToLower(strings.TrimSpace(c.opts.BalancerGroupType))
	if requested == "" {
		requested = "url-test"
	}
	if requested == "auto" {
		return autoGroupType(b.StrategyName())
	}
	if !balancerGroupTypes[requested] {
		requested = "url-test"
	}

	// url-test picks the fastest node, which is what leastPing and leastLoad
	// ask for. random and roundRobin spread traffic instead, and mihomo can do
	// that with a load-balance group, so say so rather than silently changing
	// how the nodes are used.
	if requested == "url-test" {
		switch b.StrategyName() {
		case "random", "roundrobin":
			c.warn("the balancer uses the %s strategy, which spreads traffic; "+
				"it became a url-test group that picks the fastest node "+
				"(use -balancer-type load-balance to keep spreading it)", b.StrategyName())
		}
	}
	return requested
}

// autoGroupType picks the mihomo group that behaves the way the strategy does,
// instead of forcing every balancer into one type.
//
// leastPing and leastLoad send traffic to the best node, which is what a
// url-test group does. random and roundRobin spread it over all of them, which
// is what a load-balance group does -- turning those into url-test would quietly
// pin every connection to a single server.
func autoGroupType(strategy string) string {
	switch strategy {
	case "random", "roundrobin":
		return "load-balance"
	default:
		// leastping, leastload, and anything newer: the balancer exists to
		// avoid the bad nodes, and url-test is how mihomo does that.
		return "url-test"
	}
}

// loadBalanceStrategy maps an Xray strategy onto mihomo's load-balance ones.
func loadBalanceStrategy(strategy string) string {
	switch strategy {
	case "roundrobin":
		return "round-robin"
	default:
		// mihomo's default spreads by hashing the destination, which keeps a
		// connection on one node without pinning all traffic to it.
		return "consistent-hashing"
	}
}

// routedBalancerTags collects the balancer tags the routing rules point at.
// The second result reports whether the configuration has any routing rules,
// since a configuration without them says nothing about what is used.
func routedBalancerTags(cfg *xray.Config) (map[string]bool, bool) {
	if cfg.Routing == nil || len(cfg.Routing.Rules) == 0 {
		return nil, false
	}
	out := map[string]bool{}
	for _, r := range cfg.Routing.Rules {
		if r == nil {
			continue
		}
		if tag := strings.TrimSpace(string(r.BalancerTag)); tag != "" {
			out[tag] = true
		}
	}
	return out, true
}
