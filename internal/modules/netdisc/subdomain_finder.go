// Package netdisc contains network discovery modules (subdomain finder).
package netdisc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lab/wpforge/internal/module"
	"github.com/lab/wpforge/internal/registry"
	"github.com/lab/wpforge/internal/wordlist"
)

// orDefault returns v when non-blank, else def.
func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// SubdomainFinder enumerates subdomains via passive sources + active DNS.
type SubdomainFinder struct{}

func init() { registry.Register(SubdomainFinder{}) }

// Meta implements module.Module.
func (SubdomainFinder) Meta() module.Meta {
	return module.Meta{
		ID:        "disc-subdomain-finder",
		Name:      "Subdomain finder (passive + active)",
		Component: "network",
		Primitive: module.PrimitiveRecon,
		AuthLevel: module.AuthNone,
		Notes:     "crt.sh + AlienVault OTX + HackerTarget passive, then active DNS brute with wildcard filtering.",
	}
}

// Params implements module.Module.
func (SubdomainFinder) Params() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "domain", Label: "Root domain", Required: true, Default: "example.local"},
		{Name: "wordlist", Label: "Wordlist (preset/URL/file/inline)", Default: "seclists:subdomains-5000"},
		{Name: "resolver", Label: "DNS resolver (host:port)", Default: "8.8.8.8:53"},
		{Name: "concurrency", Label: "Concurrent DNS lookups", Default: "30"},
	}
}

type passiveResult struct {
	Source string
	Names  []string
}

// Run implements module.Module.
func (SubdomainFinder) Run(ctx context.Context, t *module.Target, params map[string]string, log module.Logger) *module.Result {
	res := &module.Result{Artifacts: map[string]string{}}
	domain := strings.TrimSpace(params["domain"])
	if domain == "" {
		res.Err = fmt.Errorf("domain param required")
		return res
	}
	log.Infof("subdomain enum for %s", domain)

	found := map[string]bool{}
	var mu sync.Mutex
	add := func(src, name string) {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if name == "" || !strings.HasSuffix(name, domain) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !found[name] {
			found[name] = true
			log.Successf("[%s] %s", src, name)
		}
	}

	// --- passive sources in parallel ---
	srcs := []func(context.Context, string, func(string, string)){
		queryCRTSH,
		queryOTX,
		queryHackerTarget,
	}
	var wg sync.WaitGroup
	for _, src := range srcs {
		wg.Add(1)
		go func(fn func(context.Context, string, func(string, string))) {
			defer wg.Done()
			fn(ctx, domain, add)
		}(src)
	}

	// --- active brute while passive runs ---
	wlRef := orDefault(params["wordlist"], "seclists:subdomains-5000")
	words, err := wordlist.Load(ctx, wlRef, 0)
	if err != nil {
		log.Warnf("wordlist load failed (%v) - falling back to inline defaults", err)
		words = []string{"www", "mail", "dev", "staging", "test", "admin", "portal", "api", "cms", "blog", "shop", "wp"}
	}
	log.Infof("active brute with %d words from %s", len(words), wlRef)
	resolver := orDefault(params["resolver"], "8.8.8.8:53")
	conc := 20
	fmt.Sscanf(params["concurrency"], "%d", &conc)
	if conc < 1 {
		conc = 20
	}

	// Wildcard baseline: resolve a random label; if it resolves, wildcard is on.
	base := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, resolver)
	}}
	wildcardIP := ""
	if ips, err := base.LookupHost(ctx, "wpforge-wildcard-check-"+fmt.Sprint(time.Now().UnixNano())+"."+domain); err == nil && len(ips) > 0 {
		wildcardIP = ips[0]
		log.Warnf("wildcard DNS detected (%s) - filtering matching IPs", wildcardIP)
	}

	sem := make(chan struct{}, conc)
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		wg.Add(1)
		go func(word string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			host := word + "." + domain
			cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			ips, err := base.LookupHost(cctx, host)
			if err != nil || len(ips) == 0 {
				return
			}
			if wildcardIP != "" && len(ips) > 0 && ips[0] == wildcardIP {
				return // wildcard noise
			}
			add("dns", host)
		}(w)
	}
	wg.Wait()

	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		res.Summary = "no subdomains found"
		log.Warnf("%s", res.Summary)
		return res
	}
	res.Success = true
	res.Summary = fmt.Sprintf("%d unique subdomains", len(names))
	res.Artifacts["subdomains"] = strings.Join(names, ",")
	log.Infof("total: %d unique subdomains", len(names))
	return res
}

var _ module.Module = SubdomainFinder{}

// queryCRTSH queries crt.sh JSON endpoint.
func queryCRTSH(ctx context.Context, domain string, add func(string, string)) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain), nil)
	if err != nil {
		return
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return
	}
	for _, e := range entries {
		for _, n := range strings.Split(e.NameValue, "\n") {
			add("crt.sh", n)
		}
	}
}

// queryOTX queries AlienVault OTX passive DNS.
func queryOTX(ctx context.Context, domain string, add func(string, string)) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain), nil)
	if err != nil {
		return
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	var data struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return
	}
	for _, r := range data.PassiveDNS {
		add("otx", r.Hostname)
	}
}

// queryHackerTarget queries the HackerTarget host search API.
func queryHackerTarget(ctx context.Context, domain string, add func(string, string)) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain), nil)
	if err != nil {
		return
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	raw := make([]byte, 1<<20)
	n, _ := resp.Body.Read(raw)
	for _, line := range strings.Split(string(raw[:n]), "\n") {
		if i := strings.Index(line, ","); i > 0 {
			add("hackertarget", line[:i])
		}
	}
}
