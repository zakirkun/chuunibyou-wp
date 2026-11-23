// Recon expansion: plugin/theme enumeration, debug.log and backup exposure,
// author enumeration via ?author=N. Read-only checks from the
// access-recon-persistence research notes.
package recon

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/lab/wpforge/internal/module"
	"github.com/lab/wpforge/internal/registry"
)

// PluginEnum module: passive plugin/theme asset discovery + active probing.
type PluginEnum struct{}

func init() { registry.Register(PluginEnum{}) }

// Meta implements module.Module.
func (PluginEnum) Meta() module.Meta {
	return module.Meta{
		ID:        "recon-plugin-enum",
		Name:      "Plugin & theme enumeration",
		Component: "core",
		Primitive: module.PrimitiveRecon,
		AuthLevel: module.AuthNone,
		Notes:     "Passive: scrape /wp-content/plugins|themes/<slug>/ from front page. Active: probe readme.txt of common plugins.",
	}
}

// Params implements module.Module.
func (PluginEnum) Params() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "probe", Label: "Comma-separated plugin slugs to probe", Default: "wp-file-manager,contact-form-7,elementor,litespeed-cache,really-simple-ssl,backup-backup,wp-automatic,essential-addons-for-elementor-lite"},
	}
}

// Run implements module.Module.
func (PluginEnum) Run(ctx context.Context, t *module.Target, params map[string]string, log module.Logger) *module.Result {
	res := &module.Result{Artifacts: map[string]string{}}
	seen := map[string]bool{}

	// Passive: scrape front page for plugin/theme asset paths.
	_, body, err := t.Client.Get(ctx, "/")
	if err == nil {
		re := regexp.MustCompile(`/wp-content/(plugins|themes)/([a-z0-9\-_]+)/`)
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			kind, slug := m[1], m[2]
			key := kind + ":" + slug
			if !seen[key] {
				seen[key] = true
				log.Successf("passive %s: %s", kind, slug)
			}
		}
	}

	// Active: probe readme.txt for requested slugs.
	for _, slug := range strings.Split(params["probe"], ",") {
		if ctx.Err() != nil {
			break
		}
		slug = strings.TrimSpace(slug)
		if slug == "" || seen["plugins:"+slug] {
			continue
		}
		code, body, err := t.Client.Get(ctx, "/wp-content/plugins/"+slug+"/readme.txt")
		if err == nil && code == 200 && strings.Contains(body, "== ") {
			seen["plugins:"+slug] = true
			if v := regexp.MustCompile(`Stable tag:\s*([0-9.]+)`).FindStringSubmatch(body); v != nil {
				log.Successf("active plugin: %s (stable tag %s)", slug, v[1])
			} else {
				log.Successf("active plugin: %s", slug)
			}
		}
	}
	if len(seen) == 0 {
		res.Summary = "no plugins/themes discovered"
		log.Warnf("%s", res.Summary)
		return res
	}
	res.Success = true
	res.Summary = fmt.Sprintf("%d plugins/themes discovered", len(seen))
	res.Artifacts["count"] = fmt.Sprintf("%d", len(seen))
	return res
}

var _ module.Module = PluginEnum{}

// Exposure module: debug.log, backups, author enumeration, rest_route fallback.
type Exposure struct{}

func init() { registry.Register(Exposure{}) }

// Meta implements module.Module.
func (Exposure) Meta() module.Meta {
	return module.Meta{
		ID:        "recon-exposure",
		Name:      "Exposure checks (debug.log, backups, authors)",
		Component: "core",
		Primitive: module.PrimitiveRecon,
		AuthLevel: module.AuthNone,
		Notes:     "GET-only checks: wp-content/debug.log, common backup paths, ?author=N redirect enumeration, ?rest_route= fallback for blocked /wp-json/.",
	}
}

// Params implements module.Module.
func (Exposure) Params() []module.ParamSpec { return []module.ParamSpec{} }

// Run implements module.Module.
func (Exposure) Run(ctx context.Context, t *module.Target, params map[string]string, log module.Logger) *module.Result {
	res := &module.Result{Artifacts: map[string]string{}}
	findings := 0

	// debug.log
	code, body, err := t.Client.Get(ctx, "/wp-content/debug.log")
	if err == nil && code == 200 && (strings.Contains(body, "PHP ") || strings.Contains(body, "WARNING") || strings.Contains(body, "[")) {
		log.Successf("EXPOSURE: wp-content/debug.log readable (%d bytes)", len(body))
		findings++
		res.Artifacts["debug_log"] = "readable"
	}

	// backups
	for _, p := range []string{"/wp-content/backup-db/", "/wp-content/backups/", "/backup/", "/db.sql", "/wp-content/uploads/db.sql"} {
		code, _, err := t.Client.Get(ctx, p)
		if err == nil && code == 200 {
			log.Successf("EXPOSURE: %s returned 200 - inspect manually", p)
			findings++
		}
	}

	// author enumeration via ?author=N
	for i := 1; i <= 3; i++ {
		var m []string
		code, body, err := t.Client.Get(ctx, fmt.Sprintf("/?author=%d", i))
		if err != nil {
			break
		}
		if code >= 301 && code <= 308 || strings.Contains(body, "author/") {
			m = regexp.MustCompile(`/author/([^/"']+)/?`).FindStringSubmatch(body)
			if m != nil || code >= 301 {
				log.Successf("author enum: /?author=%d redirects to author archive", i)
				findings++
				break
			}
		}
	}

	// rest_route fallback for blocked /wp-json/
	c2, b2, err2 := t.Client.Get(ctx, "/?rest_route=/wp/v2/users")
	if err2 == nil && c2 == 200 && strings.Contains(b2, `"slug"`) {
		log.Successf("user enum via ?rest_route= fallback works (wp-json blocked but query-param route open)")
		findings++
		res.Artifacts["rest_route_users"] = "open"
	}

	if findings == 0 {
		res.Summary = "no exposures found"
		log.Warnf("%s", res.Summary)
		return res
	}
	res.Success = true
	res.Summary = fmt.Sprintf("%d exposure findings", findings)
	return res
}

var _ module.Module = Exposure{}
