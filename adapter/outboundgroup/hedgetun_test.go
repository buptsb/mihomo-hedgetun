package outboundgroup

import (
	"context"
	"os"
	"regexp"
	"sort"
	"testing"

	"github.com/metacubex/mihomo/common/yaml"
)

// TestRelayIPsOverSubscription resolves a real subscription the way the
// group does and prints the machines behind its relays: a subscription
// usually gives many names to one box, and those are not separate paths —
// hedgeconn.Start dials the first of them (D60). Opt in with a Clash YAML
// in HEDGETUN_SUB, and the group's filter in HEDGETUN_SUB_FILTER:
//
//	HEDGETUN_SUB=$HOME/.config/mihomo-hedgetun/shutiao.yaml \
//	HEDGETUN_SUB_FILTER='香港|新加坡' \
//	    go test -v -run RelayIPs ./adapter/outboundgroup/
func TestRelayIPsOverSubscription(t *testing.T) {
	path := os.Getenv("HEDGETUN_SUB")
	if path == "" {
		t.Skip("set HEDGETUN_SUB to a Clash YAML to resolve a real subscription")
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Proxies []struct {
			Name   string `yaml:"name"`
			Server string `yaml:"server"`
		} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(buf, &raw); err != nil {
		t.Fatal(err)
	}
	filter := os.Getenv("HEDGETUN_SUB_FILTER")
	if filter == "" {
		filter = "."
	}
	incl := regexp.MustCompile(filter)

	// group[ip] are the relay names that resolved to that address; a name
	// with several addresses joins the group of the first one it shares.
	group := map[string][]string{}
	home := map[string]string{} // ip -> the group it belongs to
	relays, unresolved := 0, 0
	for _, p := range raw.Proxies {
		if p.Server == "" || !incl.MatchString(p.Name) {
			continue
		}
		relays++
		ips, err := relayIPs(context.Background(), p.Server)
		if err != nil || len(ips) == 0 {
			unresolved++
			t.Logf("unresolved, kept as its own relay: %s (%s): %v", p.Name, p.Server, err)
			continue
		}
		key := ""
		for _, ip := range ips {
			if k, ok := home[ip.String()]; ok {
				key = k
				break
			}
		}
		if key == "" {
			key = ips[0].String()
		}
		for _, ip := range ips {
			home[ip.String()] = key
		}
		group[key] = append(group[key], p.Name)
	}

	keys := make([]string, 0, len(group))
	for k := range group {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(group[keys[i]]) > len(group[keys[j]]) })
	for _, k := range keys {
		t.Logf("%-18s x%d  %v", k, len(group[k]), group[k])
	}
	t.Logf("%d relays matched, %d machines behind them, %d unresolved",
		relays, len(group), unresolved)
	if relays > 0 && len(group) == 0 {
		t.Fatal("nothing resolved: is DNS reachable from here?")
	}
}
