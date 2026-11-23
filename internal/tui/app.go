// Package tui implements the wpforge console, target prompt, and shell sessions.
package tui

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/lab/wpforge/internal/module"
	"github.com/lab/wpforge/internal/scan"
)

// App owns the tview application and all screens.
type App struct {
	app     *tview.Application
	pages   *tview.Pages
	console *tview.TextView
	status  *tview.TextView

	target     *module.Target
	sessionsUI *sessionsView

	logMu  sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
}

// New builds the full UI.
func New() *App {
	a := &App{
		app:   tview.NewApplication(),
		pages: tview.NewPages(),
		ctx:   context.Background(),
	}
	a.buildConsole()
	a.buildStatusBar()
	a.buildSessions()
	a.layout()
	a.bindKeys()
	return a
}

func (a *App) buildConsole() {
	a.console = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWordWrap(true).
		SetMaxLines(5000).
		SetChangedFunc(func() {
			a.console.ScrollToEnd()
			a.app.Draw() // documented safe from SetChangedFunc (runs off event loop)
		})
	a.console.SetBorder(true).SetTitle(" Console ")
	fmt.Fprintf(a.console, "[green]wpforge[white] — modular WordPress research framework (lab use only)\n")
}

func (a *App) buildStatusBar() {
	a.status = tview.NewTextView().SetDynamicColors(true)
	a.status.SetText("[gray]Ctrl+T target / start scan | Ctrl+S shells | Ctrl+C cancel / quit[white]")
}

func (a *App) layout() {
	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.console, 0, 1, true).
		AddItem(a.status, 1, 1, false)
	a.pages.AddPage("main", root, true, true)
	a.app.SetRoot(a.pages, true)
}

func (a *App) bindKeys() {
	a.app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyCtrlC:
			// First press cancels a running job; press again to quit.
			if a.cancel != nil {
				a.safeCancel()
				a.Logf("warn", "job cancelled - press Ctrl+C again to quit")
				return nil
			}
			a.app.Stop()
			return nil
		case tcell.KeyCtrlT:
			a.promptTarget()
			return nil
		case tcell.KeyCtrlS:
			a.sessionsUI.show()
			return nil
		}
		return ev
	})
}

// Logf is the thread-safe console writer handed to modules as Logger.
// Untrusted text is escaped so it cannot inject tview color markup.
func (a *App) Logf(level, format string, args ...any) {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	color := map[string]string{
		"info": "white", "warn": "yellow", "error": "red",
		"ok": "green", "raw": "aqua",
	}[level]
	if color == "" {
		color = "white"
	}
	fmt.Fprintf(a.console, "[%s]%s[white]\n", color, tview.Escape(fmt.Sprintf(format, args...)))
}

// consoleLogger adapts App to module.Logger.
type consoleLogger struct{ a *App }

func (l consoleLogger) Infof(f string, v ...any)    { l.a.Logf("info", f, v...) }
func (l consoleLogger) Warnf(f string, v ...any)    { l.a.Logf("warn", f, v...) }
func (l consoleLogger) Errorf(f string, v ...any)   { l.a.Logf("error", f, v...) }
func (l consoleLogger) Successf(f string, v ...any) { l.a.Logf("ok", f, v...) }
func (l consoleLogger) Rawf(f string, v ...any)     { l.a.Logf("raw", f, v...) }

// NewWithTarget builds the UI with a pre-seeded target (from CLI flags).
func NewWithTarget(targetURL, user, pass, timeoutSecs string) *App {
	a := New()
	if targetURL != "" {
		if timeoutSecs == "" {
			timeoutSecs = "15"
		}
		t, err := newTarget(targetURL, timeoutSecs)
		if err != nil {
			a.Logf("error", "invalid -target %q: %v", targetURL, err)
			return a
		}
		t.Creds = module.Credentials{Username: user, Password: pass}
		a.target = t
		a.Logf("ok", "target set from CLI: %s (creds: %s)", t.BaseURL, orEmpty(user))
		a.startMassScan()
	}
	return a
}

// Run starts the event loop (blocking).
func (a *App) Run() error { return a.app.Run() }

// promptTarget asks for the base URL and initializes the HTTP engine.
func (a *App) promptTarget() {
	form := tview.NewForm()
	urlField := "http://localhost:8080"
	userField, passField := "", ""
	if a.target != nil {
		urlField = a.target.BaseURL
		userField = a.target.Creds.Username
		passField = a.target.Creds.Password
	}
	timeoutField := "15"
	form.AddInputField("Base URL", urlField, 50, nil, func(s string) { urlField = s })
	form.AddInputField("Username (optional)", userField, 20, nil, func(s string) { userField = s })
	form.AddPasswordField("Password (optional)", passField, 20, '*', func(s string) { passField = s })
	form.AddInputField("Timeout (s)", timeoutField, 5, nil, func(s string) { timeoutField = s })
	form.AddButton("Save", func() {
		if a.cancel != nil {
			a.Logf("warn", "cannot change target while a scan is running; press Ctrl+C to cancel first")
			return
		}
		t, err := newTarget(urlField, timeoutField)
		if err != nil {
			a.Logf("error", "invalid target: %v", err)
			return
		}
		t.Creds = module.Credentials{Username: strings.TrimSpace(userField), Password: passField}
		a.target = t
		a.Logf("ok", "target set: %s (creds: %s)", t.BaseURL, orEmpty(t.Creds.Username))
		a.pages.RemovePage("target")
		a.pages.SwitchToPage("main")
		a.startMassScan()
	})
	form.AddButton("Cancel", func() { a.pages.RemovePage("target"); a.pages.SwitchToPage("main") })
	form.SetBorder(true).SetTitle(" Target ")
	a.pages.AddPage("target", form, true, false)
	a.pages.SwitchToPage("target")
	a.app.SetFocus(form)
}

func orEmpty(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// startMassScan runs the full pipeline: recon -> exploit checks -> backdoor.
func (a *App) startMassScan() {
	if a.target == nil {
		a.Logf("warn", "no target set - press Ctrl+T first")
		a.promptTarget()
		return
	}
	if a.cancel != nil {
		a.Logf("warn", "a job is already running - Ctrl+C cancels it")
		return
	}
	a.pages.SwitchToPage("main")
	ctx, cancel := context.WithCancel(a.ctx)
	a.cancel = cancel
	p := &scan.Pipeline{Target: a.target, Log: consoleLogger{a}}
	go func() {
		defer func() {
			cancel()
			a.app.QueueUpdateDraw(func() { a.cancel = nil })
		}()
		p.Run(ctx)
	}()
}

func (a *App) safeCancel() {
	if a.cancel != nil {
		a.cancel()
	}
}
