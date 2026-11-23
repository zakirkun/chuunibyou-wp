// Package module defines the contract every wpforge module implements.
package module

import (
	"context"
	"time"

	"github.com/lab/wpforge/internal/engine"
)

// AuthLevel is the minimum WordPress privilege a module requires.
type AuthLevel int

const (
	AuthNone AuthLevel = iota // unauthenticated
	AuthSubscriber
	AuthAuthor
	AuthEditor
	AuthAdmin
)

func (a AuthLevel) String() string {
	switch a {
	case AuthNone:
		return "none"
	case AuthSubscriber:
		return "subscriber"
	case AuthAuthor:
		return "author"
	case AuthEditor:
		return "editor"
	case AuthAdmin:
		return "admin"
	default:
		return "unknown"
	}
}

// Primitive is the exploit class a module belongs to. Used for grouping
// and filtering in the module browser.
type Primitive string

const (
	PrimitiveRecon       Primitive = "recon"        // fingerprint, version, user enum
	PrimitiveAccess      Primitive = "access"       // brute force, auth bypass
	PrimitiveFileUpload  Primitive = "file-upload"  // arbitrary/shell upload
	PrimitivePathTravRCE Primitive = "ptrav-rce"    // path traversal leading to code exec
	PrimitiveDeser       Primitive = "deser"        // PHP object injection
	PrimitiveSQLi        Primitive = "sqli"         // SQL injection
	PrimitiveSSRF        Primitive = "ssrf"
	PrimitiveBackdoor    Primitive = "backdoor"     // persistence / shell management
	PrimitivePostEx      Primitive = "post-ex"      // post-exploitation helpers
)

// ParamSpec describes one module parameter for TUI form generation.
type ParamSpec struct {
	Name        string // form field name, e.g. "target"
	Label       string // human label shown in TUI
	Description string
	Required    bool
	Default     string
	Secret      bool // mask input (passwords, tokens)
}

// Target is the WordPress installation a module runs against.
type Target struct {
	BaseURL string        // e.g. http://lab.local/wordpress
	Client  *engine.Client // shared HTTP engine (cookies, UA, timeouts)
	Creds   Credentials   // known/working credentials (populated by access modules)
	Debug   bool
}

// Credentials carries auth state between modules (access -> exploit chaining).
type Credentials struct {
	Username    string
	Password    string
	Cookies     map[string]string // authenticated session cookies
	Nonce       string            // wp REST/admin nonce if known
	ApplicationPass string          // application password if created
}

// Result is what a module run reports back to the engine/TUI.
type Result struct {
	Success    bool
	Summary    string            // one-line outcome for the console
	Detail     []string          // log lines
	Artifacts  map[string]string // e.g. {"shell_url": "http://.../wp-content/uploads/shell.php"}
	Creds      *Credentials      // non-nil if the module produced credentials to chain
	Duration   time.Duration
	Err        error
}

// Module is the contract for every exploit/aux module.
type Module interface {
	// Meta returns static metadata for the browser UI.
	Meta() Meta
	// Params returns the parameter specs for TUI form generation.
	Params() []ParamSpec
	// Run executes the module. ctx is cancelled on user abort.
	Run(ctx context.Context, t *Target, params map[string]string, log Logger) *Result
}

// Meta is static module identity, rendered in the module browser.
type Meta struct {
	ID        string    // unique, e.g. "cve-2020-25213-wp-file-manager"
	CVE       string    // "CVE-2020-25213" or "" for aux modules
	Name      string    // short name
	Component string    // affected plugin/theme/core slug + version range
	Primitive Primitive
	AuthLevel AuthLevel
	References []string // EDB IDs, metasploit, vendor advisories
	Notes     string
}

// Logger receives streaming output during a run; the TUI wires this to the console pane.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
	Successf(format string, args ...any)
	Rawf(format string, args ...any) // verbatim (hex dumps, payloads)
}
