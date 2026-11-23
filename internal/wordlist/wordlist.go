// Package wordlist loads brute/enum wordlists from SecLists presets,
// raw URLs, local files, or inline comma-separated values.
// Presets point at danielmiessler/SecLists (raw.githubusercontent.com).
package wordlist

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Preset maps a shorthand name to a SecLists raw URL. Max caps entries.
type Preset struct {
	URL string
	Max int
}

const seclistsRaw = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"

// Presets are canonical SecLists wordlists useful for WordPress work.
var Presets = map[string]Preset{
	"seclists:subdomains-5000":    {seclistsRaw + "Discovery/DNS/subdomains-top1million-5000.txt", 5000},
	"seclists:subdomains-20000":   {seclistsRaw + "Discovery/DNS/subdomains-top1million-20000.txt", 20000},
	"seclists:subdomains-110000":  {seclistsRaw + "Discovery/DNS/subdomains-top1million-110000.txt", 110000},
	"seclists:dns-jhaddix":        {seclistsRaw + "Discovery/DNS/dns-Jhaddix.txt", 100000},
	"seclists:usernames-top100":   {seclistsRaw + "Usernames/top-usernames-shortlist.txt", 100},
	"seclists:usernames-names":    {seclistsRaw + "Usernames/Names/names.txt", 100000},
	"seclists:passwords-top500":   {seclistsRaw + "Passwords/Common-Credentials/10-million-password-list-top-500.txt", 500},
	"seclists:passwords-top1000":  {seclistsRaw + "Passwords/Common-Credentials/10-million-password-list-top-1000.txt", 1000},
	"seclists:passwords-top100k":  {seclistsRaw + "Passwords/Common-Credentials/10-million-password-list-top-100000.txt", 100000},
	"seclists:web-content-common": {seclistsRaw + "Discovery/Web-Content/common.txt", 5000},
	"seclists:wp-directories":     {seclistsRaw + "Discovery/Web-Content/CMS/wp-themes.txt", 500},
}

var (
	cacheMu sync.Mutex
	cache   = map[string][]string{}
)

// Load resolves ref to a wordlist: preset name, http(s) URL, local file
// path, or inline comma-separated values. Results are cached per ref.
// max caps the entry count (0 = preset default or unlimited).
func Load(ctx context.Context, ref string, max int) ([]string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("wordlist ref empty")
	}

	// Inline list (unless it's a URL/path that happens to contain a comma).
	if !strings.HasPrefix(ref, "http") && !strings.HasPrefix(ref, "seclists:") &&
		!strings.Contains(ref, "/") && strings.Contains(ref, ",") {
		return splitLines(strings.Split(ref, ",")), nil
	}

	cacheMu.Lock()
	defer cacheMu.Unlock()
	if c, ok := cache[ref+"\x00"+fmt.Sprint(max)]; ok {
		return c, nil
	}

	var raw string
	if p, ok := Presets[ref]; ok {
		if max == 0 {
			max = p.Max
		}
		data, err := fetchURL(ctx, p.URL)
		if err != nil {
			return nil, fmt.Errorf("preset %s: %w", ref, err)
		}
		raw = data
	} else if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		data, err := fetchURL(ctx, ref)
		if err != nil {
			return nil, err
		}
		raw = data
	} else {
		data, err := os.ReadFile(ref)
		if err != nil {
			return nil, err
		}
		raw = string(data)
	}

	lines := splitLines(strings.Split(raw, "\n"))
	if max > 0 && len(lines) > max {
		lines = lines[:max]
	}
	cache[ref+"\x00"+fmt.Sprint(max)] = lines
	return lines, nil
}

// PresetNames returns sorted preset names for UI hints.
func PresetNames() []string {
	out := make([]string, 0, len(Presets))
	for k := range Presets {
		out = append(out, k)
	}
	return out
}

func fetchURL(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func splitLines(in []string) []string {
	out := make([]string, 0, len(in))
	for _, l := range in {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}
