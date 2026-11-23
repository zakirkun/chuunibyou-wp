// Package recon contains fingerprinting / enumeration modules.
package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lab/wpforge/internal/engine"
	"github.com/lab/wpforge/internal/module"
	"github.com/lab/wpforge/internal/registry"
)

func init() { registry.Register(Fingerprint{}) }

// Fingerprint module: WP version, xmlrpc, REST, users endpoint enumeration.
type Fingerprint struct{}

// Meta implements module.Module.
func (Fingerprint) Meta() module.Meta {
	return module.Meta{
		ID:         "recon-fingerprint",
		Name:       "WP Fingerprint & User Enum",
		Component:  "core",
		Primitive:  module.PrimitiveRecon,
		AuthLevel:  module.AuthNone,
		References: []string{"https://developer.wordpress.org/rest-api/reference/users/"},
		Notes:      "Detects WP version, xmlrpc.php, REST API, and enumerates users via /wp-json/wp/v2/users.",
	}
}

// Params implements module.Module.
func (Fingerprint) Params() []module.ParamSpec {
	return []module.ParamSpec{}
}

// Run implements module.Module.
func (Fingerprint) Run(ctx context.Context, t *module.Target, params map[string]string, log module.Logger) *module.Result {
	res := &module.Result{Artifacts: map[string]string{}}
	log.Infof("fingerprinting %s", t.BaseURL)

	if v, ok := engine.DetectVersion(ctx, t.Client); ok {
		log.Successf("wordpress version: %s", v)
		res.Artifacts["wp_version"] = v
	} else {
		log.Warnf("version not disclosed (meta generator hidden)")
	}

	log.Infof("probing xmlrpc.php ...")
	if engine.HasXMLRPC(ctx, t.Client) {
		log.Successf("xmlrpc.php is ENABLED - multicall brute force possible")
		res.Artifacts["xmlrpc"] = "enabled"
	} else {
		log.Warnf("xmlrpc.php disabled or blocked")
	}

	log.Infof("probing REST API ...")
	if !engine.HasREST(ctx, t.Client) {
		log.Warnf("REST API not reachable at /wp-json/")
		// Fallback: ?rest_route= form.
		if code, body, err := t.Client.Get(ctx, "/?rest_route=/"); err == nil && code == 200 && strings.Contains(body, `"routes"`) {
			log.Successf("REST API reachable via ?rest_route= fallback")
			res.Artifacts["rest"] = "rest_route-fallback"
		}
		return res
	}
	log.Successf("REST API reachable at /wp-json/")
	res.Artifacts["rest"] = "enabled"

	log.Infof("enumerating users via /wp-json/wp/v2/users ...")
	code, body, err := t.Client.Get(ctx, "/wp-json/wp/v2/users")
	if err != nil {
		log.Errorf("user enum request failed: %v", err)
		return res
	}
	if code != 200 {
		log.Warnf("users endpoint returned %d (likely hardened)", code)
		// Fallback: query-param route.
		if c2, b2, err2 := t.Client.Get(ctx, "/?rest_route=/wp/v2/users"); err2 == nil && c2 == 200 && strings.Contains(b2, `"slug"`) {
			log.Successf("user enum works via ?rest_route= fallback")
			code, body = c2, b2
		} else {
			return res
		}
	}
	var users []struct {
		ID    int      `json:"id"`
		Name  string   `json:"name"`
		Slug  string   `json:"slug"`
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal([]byte(body), &users); err != nil {
		log.Warnf("could not parse users response: %v", err)
		return res
	}
	for _, u := range users {
		roles := strings.Join(u.Roles, ",")
		log.Successf("user #%d slug=%q name=%q roles=[%s]", u.ID, u.Slug, u.Name, roles)
	}
	res.Artifacts["users"] = fmt.Sprintf("%d enumerated", len(users))
	res.Success = true
	res.Summary = fmt.Sprintf("found %d users; see log", len(users))
	return res
}

var _ module.Module = Fingerprint{}
