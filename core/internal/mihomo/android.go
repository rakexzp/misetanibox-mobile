package mihomo

import "misetanibox/mobilecore/internal/yamlx"

// The document Build produces is a desktop skeleton: system DNS servers, IPv6
// on, process matching left at its default. On Android those choices are wrong
// in ways that are hard to diagnose from the device, so the client generates
// its own.
//
// BuildAndroid keeps the same proxies, groups and rules and swaps the skeleton
// for the one MihomoVpnService has always used for subscriptions it assembles
// itself. Every deviation from the defaults below has a reason, and the
// reasons are the ones written down in the project README.

// androidNameservers are resolvers that answer from inside Russia as well as
// outside it, since the client is used on networks where 8.8.8.8 is filtered.
var androidNameservers = yamlx.FlowSeq{"77.88.8.8", "223.5.5.5"}

// BuildAndroid assembles the configuration the Android client feeds to the
// core, around proxies converted from a foreign subscription format.
//
// names are the entries offered for selection: where a balancer became a
// group, the group's name stands there in place of the nodes it covers.
func BuildAndroid(proxies []*yamlx.Map, groups []Group, names []string) *yamlx.Map {
	opts := DefaultDocumentOptions()

	doc := yamlx.NewMap()
	doc.Set("mixed-port", opts.MixedPort)
	doc.Set("mode", "rule")
	doc.Set("log-level", "warning")
	// The TUN interface carries no IPv6 address, so a node reached over IPv6
	// would answer into a route that does not exist.
	doc.Set("ipv6", false)
	doc.Set("unified-delay", true)
	// Finding the process behind a connection means scanning /proc for every
	// one of them. Split tunnelling is done by VpnService, so the answer is
	// never used and the scan is pure battery drain.
	doc.Set("find-process-mode", "off")

	profile := yamlx.NewMap()
	// Remember the selected server across restarts, so the user does not pick
	// one again after every reconnect.
	profile.Set("store-selected", true)
	doc.Set("profile", profile)

	// The UI talks to the running core over this address; Start overrides it
	// anyway, and stating it here keeps the generated file runnable as-is.
	doc.Set("external-controller", opts.ExternalController)
	doc.Set("dns", buildAndroidDNS())

	seq := make(yamlx.Seq, 0, len(proxies))
	for _, p := range proxies {
		seq = append(seq, p)
	}
	doc.Set("proxies", seq)
	doc.Set("proxy-groups", buildGroups(groups, names, opts))
	doc.Set("rules", buildRules(opts))
	return doc
}

func buildAndroidDNS() *yamlx.Map {
	dns := yamlx.NewMap()
	dns.Set("enable", true)
	dns.Set("listen", "0.0.0.0:1053")
	dns.Set("ipv6", false)
	// fake-ip answers instantly and keeps the destination domain attached to
	// the connection, which is what the domain rules match on.
	dns.Set("enhanced-mode", "fake-ip")
	dns.Set("fake-ip-range", "198.18.0.1/16")
	dns.Set("fake-ip-filter", yamlx.Seq{"*.lan", "*.local", "localhost.ptlogin2.qq.com"})
	dns.Set("default-nameserver", androidNameservers)
	dns.Set("nameserver", androidNameservers)
	// Resolving the proxy server's own address must not go through the proxy.
	dns.Set("proxy-server-nameserver", androidNameservers)
	return dns
}
